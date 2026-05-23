"""
IIFVDCAS — Phase 2 API Routes: Firmware Extraction
"""
import asyncio
import hashlib
import os
import queue
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse

from core.firmware_extraction.extractor import (
    analyze_firmware_file, run_extraction, cleanup_extraction,
    FirmwareFileInfo, ExtractionResult, ExtractionStatus, asdict
)

router = APIRouter(prefix="/api/v1/firmware", tags=["firmware"])

UPLOAD_DIR = Path("/tmp/iifvdcas_uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Persistent storage for extracted firmware .bin files
FIRMWARE_STORE = Path("/tmp/iifvdcas_firmware_store")
FIRMWARE_STORE.mkdir(parents=True, exist_ok=True)

# In-memory job store (replaced by DB in Phase 4)
extraction_jobs: dict[str, dict] = {}


# ─── Upload firmware file ─────────────────────────────────────────────────────

@router.post("/upload")
async def upload_firmware(file: UploadFile = File(...)):
    """Upload a firmware binary for analysis."""
    safe_name = Path(file.filename).name.replace(" ", "_")
    dest = UPLOAD_DIR / safe_name
    with open(dest, "wb") as f:
        content = await file.read()
        f.write(content)

    size = dest.stat().st_size
    return {
        "filename": safe_name,
        "path": str(dest),
        "size_bytes": size,
        "size_human": _human_size(size),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── Analyze (P02) without extracting ────────────────────────────────────────

@router.post("/analyze")
async def analyze_firmware(body: dict):
    """
    Run P02 file analysis only — no extraction.
    Accepts: {"path": "/tmp/iifvdcas_uploads/firmware.bin"}
    """
    fw_path = body.get("path") or body.get("device_path")
    if not fw_path:
        raise HTTPException(400, "Provide 'path' or 'device_path'")
    if not Path(fw_path).exists():
        raise HTTPException(404, f"File not found: {fw_path}")

    info = analyze_firmware_file(fw_path)
    return asdict(info)


# ─── Start extraction job (uploaded file) ────────────────────────────────────

@router.post("/extract")
async def start_extraction(body: dict, background_tasks: BackgroundTasks):
    """Start extraction on an uploaded firmware file."""
    fw_path = body.get("path") or body.get("device_path")
    if not fw_path:
        raise HTTPException(400, "Provide 'path' or 'device_path'")
    if not Path(fw_path).exists():
        raise HTTPException(404, f"File not found: {fw_path}")

    job_id = hashlib.md5(
        f"{fw_path}-{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]

    extraction_jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "fw_path": fw_path,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    background_tasks.add_task(_run_extraction_bg, fw_path, job_id)

    return {
        "job_id": job_id,
        "status": "started",
        "message": "Extraction started. Connect to /ws for live progress.",
        "fw_path": fw_path,
    }


# ─── Start extraction job by reading flash from a connected device ───────────

@router.post("/extract-device")
async def start_extraction_from_device(body: dict, background_tasks: BackgroundTasks):
    """
    Read flash from an Arduino device via avrdude, then run extraction pipeline.
    Accepts:
      {"device_port": "/dev/ttyACM0", "baudrate": 115200, "mcu": "m328p",
       "include_eeprom": false}
    """
    device_port = body.get("device_port")
    if not device_port:
        raise HTTPException(400, "Provide 'device_port'")
    if not Path(device_port).exists():
        raise HTTPException(404, f"Device not found: {device_port}")

    baudrate = int(body.get("baudrate", 115200))
    mcu = body.get("mcu", "m328p")
    include_eeprom = bool(body.get("include_eeprom", False))

    job_id = hashlib.md5(
        f"{device_port}-{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]

    extraction_jobs[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "device_port": device_port,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }

    background_tasks.add_task(
        _run_device_extraction_bg,
        device_port, job_id, baudrate, mcu, include_eeprom
    )

    return {
        "job_id": job_id,
        "status": "started",
        "message": "Flash read started. Connect to /ws for live progress.",
        "device_port": device_port,
    }


# ─── Background tasks ─────────────────────────────────────────────────────────

async def _run_extraction_bg(fw_path: str, job_id: str):
    """Background task: runs extraction on an uploaded file."""
    from main import broadcast

    progress_updates: list = []

    def sync_progress_cb(event: dict):
        progress_updates.append(event)

    async def flush():
        for event in progress_updates:
            await broadcast({**event, "phase": "phase2"})
        progress_updates.clear()

    await broadcast({"event": "extraction_started", "job_id": job_id, "phase": "phase2"})
    await broadcast({"event": "progress", "job_id": job_id, "phase": "phase2",
                     "percent": 5, "step": "Starting extraction pipeline"})

    loop = asyncio.get_event_loop()
    result: ExtractionResult = await loop.run_in_executor(
        None,
        lambda: run_extraction(fw_path, job_id, sync_progress_cb),
    )

    await flush()

    result_dict = asdict(result)
    extraction_jobs[job_id] = result_dict

    await broadcast({
        "event": "extraction_complete",
        "job_id": job_id,
        "phase": "phase2",
        "percent": 100,
        "status": result.status.value,
        "total_files": result.total_files,
        "linux_found": result.linux_found,
        "extractor_used": result.extractor_used,
        "result": result_dict,
    })


async def _run_device_extraction_bg(
    device_port: str,
    job_id: str,
    baudrate: int,
    mcu: str,
    include_eeprom: bool,
):
    """
    Background task: reads flash from device via avrdude (with live stderr
    progress), saves the .bin persistently, then runs extraction pipeline.
    """
    from main import broadcast

    # All progress/log events queued by threads and flushed from the async loop
    progress_updates: list = []

    def sync_extract_progress_cb(event: dict):
        progress_updates.append(event)

    async def flush():
        for event in progress_updates:
            await broadcast({**event, "phase": "phase2"})
        progress_updates.clear()

    async def emit(event: str, **kwargs):
        await broadcast({"event": event, "job_id": job_id, "phase": "phase2", **kwargs})

    await emit("extraction_started")
    await emit("progress", percent=2, step="Preparing directories")

    # ── Directories ───────────────────────────────────────────────────────────
    output_dir = Path("/tmp/iifvdcas_extractions") / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    store_name = f"flash_{mcu}_{ts}_{job_id}.bin"
    store_path = FIRMWARE_STORE / store_name
    flash_path = output_dir / "flash.bin"

    # ── avrdude flash read with live stderr streaming ─────────────────────────
    await emit("log", message=f"[avrdude] Reading flash from {device_port} (mcu={mcu}, baud={baudrate})…")
    await emit("progress", percent=5, step="avrdude: connecting to device…")

    loop = asyncio.get_event_loop()
    stderr_q: queue.Queue = queue.Queue()

    def _stream_avrdude():
        """Run avrdude in a thread; put stderr lines into queue for async relay."""
        cmd = [
            "avrdude",
            "-c", "arduino",
            "-p", mcu,
            "-P", device_port,
            "-b", str(baudrate),
            "-D",
            "-U", f"flash:r:{flash_path}:r",
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # avrdude writes progress '#' chars to stderr — stream line-by-line
            for line in proc.stderr:
                line = line.rstrip()
                if line:
                    stderr_q.put(("line", line))
            proc.wait(timeout=60)
            stderr_q.put(("done", proc.returncode))
        except FileNotFoundError:
            stderr_q.put(("error", "avrdude not found — install: sudo apt install avrdude"))
        except subprocess.TimeoutExpired:
            proc.kill()
            stderr_q.put(("error", "avrdude timed out after 60s"))
        except Exception as exc:
            stderr_q.put(("error", str(exc)))

    # Start avrdude in a thread; poll the queue from the async event loop
    thread = threading.Thread(target=_stream_avrdude, daemon=True)
    thread.start()

    flash_ok = False
    returncode = -1
    avrdude_pct = 5          # we'll animate from 5 → 20 while avrdude runs
    avrdude_lines: list[str] = []

    while True:
        try:
            kind, value = stderr_q.get(timeout=0.05)
        except queue.Empty:
            await asyncio.sleep(0.05)
            continue

        if kind == "line":
            avrdude_lines.append(value)
            # Crude progress: count '#' characters avrdude emits (32 per bank)
            hashes = value.count("#")
            if hashes:
                avrdude_pct = min(avrdude_pct + hashes * 0.4, 19)
                await emit("progress", percent=int(avrdude_pct),
                           step=f"avrdude: reading flash… {value.strip()}")
            await emit("log", message=f"[avrdude] {value}")

        elif kind == "done":
            returncode = value
            flash_ok = (returncode == 0)
            break

        elif kind == "error":
            await emit("log", message=f"[avrdude] ERROR: {value}")
            await emit("progress", percent=100, step="Flash read failed")
            _fail_job(job_id, value)
            await emit("extraction_complete", status=ExtractionStatus.FAILED.value,
                       error=value)
            return

    if not flash_ok:
        stderr_text = "\n".join(avrdude_lines[-10:])
        await emit("log", message=f"[avrdude] Failed (exit {returncode}): {stderr_text}")
        await emit("progress", percent=100, step="Flash read failed")
        _fail_job(job_id, f"avrdude exit {returncode}: {stderr_text}")
        await emit("extraction_complete", status=ExtractionStatus.FAILED.value,
                   error=stderr_text)
        return

    flash_size = flash_path.stat().st_size
    await emit("log", message=f"[avrdude] Flash read OK — {_human_size(flash_size)} ({flash_size} bytes)")
    await emit("progress", percent=20, step="Flash read complete")

    # ── Persist the .bin ──────────────────────────────────────────────────────
    shutil.copy2(str(flash_path), str(store_path))
    await emit("log", message=f"[store] Firmware saved → {store_path}")
    await emit("progress", percent=22, step=f"Saved .bin → {store_name}")
    await broadcast({
        "event": "firmware_saved",
        "job_id": job_id,
        "phase": "phase2",
        "bin_path": str(store_path),
        "bin_filename": store_name,
        "size_bytes": flash_size,
        "size_human": _human_size(flash_size),
    })

    # ── Optional EEPROM read ──────────────────────────────────────────────────
    eeprom_store_path: Optional[Path] = None
    if include_eeprom:
        eeprom_path = output_dir / "eeprom.bin"
        eeprom_store_name = f"eeprom_{mcu}_{ts}_{job_id}.bin"
        await emit("log", message=f"[avrdude] Reading EEPROM from {device_port}…")
        await emit("progress", percent=24, step="Reading EEPROM…")
        eeprom_ok, _, eeprom_err = await loop.run_in_executor(
            None,
            lambda: _run_avrdude_simple(
                device_port, baudrate, mcu, "eeprom", str(eeprom_path), timeout=30
            ),
        )
        if eeprom_ok:
            eeprom_store_path = FIRMWARE_STORE / eeprom_store_name
            shutil.copy2(str(eeprom_path), str(eeprom_store_path))
            await emit("log", message=f"[avrdude] EEPROM OK → {eeprom_store_path}")
        else:
            await emit("log", message=f"[avrdude] EEPROM failed (non-fatal): {eeprom_err}")

    # ── Extraction pipeline ───────────────────────────────────────────────────
    await emit("log", message="[extract] Running extraction pipeline on flash.bin…")
    await emit("progress", percent=25, step="Starting extraction pipeline")

    result: ExtractionResult = await loop.run_in_executor(
        None,
        lambda: run_extraction(str(flash_path), job_id, sync_extract_progress_cb),
    )

    await flush()

    result_dict = asdict(result)
    result_dict["flash_bin_path"]        = str(store_path)
    result_dict["flash_bin_filename"]    = store_name
    result_dict["flash_bin_size_bytes"]  = flash_size
    result_dict["flash_bin_size_human"]  = _human_size(flash_size)
    if eeprom_store_path:
        result_dict["eeprom_bin_path"] = str(eeprom_store_path)

    extraction_jobs[job_id] = result_dict

    await broadcast({
        "event": "extraction_complete",
        "job_id": job_id,
        "phase": "phase2",
        "percent": 100,
        "status": result.status.value,
        "total_files": result.total_files,
        "linux_found": result.linux_found,
        "extractor_used": result.extractor_used,
        "flash_bin_path": str(store_path),
        "flash_bin_filename": store_name,
        "flash_bin_size_human": _human_size(flash_size),
        "result": result_dict,
    })


# ─── avrdude helpers ──────────────────────────────────────────────────────────

def _run_avrdude_simple(
    device_port: str, baudrate: int, mcu: str,
    memtype: str, output_file: str, timeout: int = 60,
) -> Tuple[bool, str, str]:
    """Simple blocking avrdude call (used for EEPROM reads)."""
    cmd = [
        "avrdude", "-c", "arduino", "-p", mcu,
        "-P", device_port, "-b", str(baudrate), "-D",
        "-U", f"{memtype}:r:{output_file}:r",
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.returncode == 0, r.stdout, r.stderr)
    except subprocess.TimeoutExpired:
        return (False, "", f"Timeout after {timeout}s")
    except FileNotFoundError:
        return (False, "", "avrdude not found — install: sudo apt install avrdude")
    except Exception as e:
        return (False, "", str(e))


def _fail_job(job_id: str, error: str):
    """Mark a job as failed in the in-memory store."""
    prev = extraction_jobs.get(job_id, {})
    extraction_jobs[job_id] = {
        **prev,
        "job_id": job_id,
        "status": ExtractionStatus.FAILED.value,
        "error": error,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── List saved firmware binaries ─────────────────────────────────────────────

@router.get("/store")
async def list_firmware_store():
    """List all .bin files saved in the persistent firmware store."""
    files = []
    for p in sorted(FIRMWARE_STORE.iterdir()):
        if p.is_file():
            stat = p.stat()
            files.append({
                "filename": p.name,
                "path": str(p),
                "size_bytes": stat.st_size,
                "size_human": _human_size(stat.st_size),
                "created_at": datetime.fromtimestamp(
                    stat.st_ctime, tz=timezone.utc
                ).isoformat(),
            })
    return {"store_dir": str(FIRMWARE_STORE), "files": files}


# ─── Query endpoints ──────────────────────────────────────────────────────────

@router.get("/extract/{job_id}")
async def get_extraction_result(job_id: str):
    if job_id not in extraction_jobs:
        raise HTTPException(404, "Job not found")
    return extraction_jobs[job_id]


@router.get("/extract/{job_id}/tree")
async def get_file_tree(job_id: str):
    if job_id not in extraction_jobs:
        raise HTTPException(404, "Job not found")
    job = extraction_jobs[job_id]
    return {
        "job_id": job_id,
        "file_tree": job.get("file_tree", []),
        "total_files": job.get("total_files", 0),
        "total_dirs": job.get("total_dirs", 0),
        "linux_found": job.get("linux_found", False),
        "linux_paths": job.get("linux_paths", []),
        "flash_bin_path": job.get("flash_bin_path"),
        "flash_bin_filename": job.get("flash_bin_filename"),
        "flash_bin_size_human": job.get("flash_bin_size_human"),
    }


@router.delete("/extract/{job_id}")
async def delete_extraction(job_id: str):
    cleanup_extraction(job_id)
    extraction_jobs.pop(job_id, None)
    return {"deleted": job_id}


@router.get("/jobs")
async def list_jobs():
    return {
        "jobs": [
            {
                "job_id": j.get("job_id"),
                "status": j.get("status"),
                "fw_path": j.get("fw_path"),
                "device_port": j.get("device_port"),
                "total_files": j.get("total_files", 0),
                "extractor_used": j.get("extractor_used", ""),
                "flash_bin_path": j.get("flash_bin_path"),
                "flash_bin_size_human": j.get("flash_bin_size_human"),
                "started_at": j.get("started_at", ""),
                "completed_at": j.get("completed_at", ""),
            }
            for j in extraction_jobs.values()
        ]
    }


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
