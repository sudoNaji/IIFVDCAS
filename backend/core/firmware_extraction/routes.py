"""
IIFVDCAS — Phase 2 API Routes: Firmware Extraction

ESP32/ESP8266 extraction strategy (esptool):
  Pass 1 — with stub flasher, baud ladder  [460800 → 230400 → 115200]
  Pass 2 — --no-stub (ROM bootloader),     [115200 only, slow but reliable]

"Corrupt data, expected 0x1000 bytes" = USB serial dropout (baud too fast).
Remedy: step down baud, then fall back to --no-stub which never has this issue.
"""
import asyncio
import hashlib
import os
import queue
import re
import shutil
import subprocess
import sys
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

UPLOAD_DIR    = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/uploads");    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
FIRMWARE_STORE = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/firmware_store"); FIRMWARE_STORE.mkdir(parents=True, exist_ok=True)

extraction_jobs: dict[str, dict] = {}

# ─── ANSI / terminal-control scrubber ────────────────────────────────────────
# esptool emits colour codes (\x1b[...m) AND cursor-movement sequences
# (\x1b[K  \x1b[1A  \x1b[2K  etc.).  Strip both families completely.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\[[0-9]*[ABCDK]|\x1b\[[\d;]*m")

def _clean(line: str) -> str:
    return _ANSI_RE.sub("", line).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Upload / Analyze
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_firmware(file: UploadFile = File(...)):
    safe_name = Path(file.filename).name.replace(" ", "_")
    dest = UPLOAD_DIR / safe_name
    dest.write_bytes(await file.read())
    size = dest.stat().st_size
    return {"filename": safe_name, "path": str(dest),
            "size_bytes": size, "size_human": _human_size(size),
            "uploaded_at": datetime.now(timezone.utc).isoformat()}


@router.post("/analyze")
async def analyze_firmware(body: dict):
    fw_path = body.get("path") or body.get("device_path")
    if not fw_path:
        raise HTTPException(400, "Provide 'path' or 'device_path'")
    if not Path(fw_path).exists():
        raise HTTPException(404, f"File not found: {fw_path}")
    return asdict(analyze_firmware_file(fw_path))


# ─────────────────────────────────────────────────────────────────────────────
# Extraction from uploaded file
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/extract")
async def start_extraction(body: dict, background_tasks: BackgroundTasks):
    fw_path = body.get("path") or body.get("device_path")
    if not fw_path:
        raise HTTPException(400, "Provide 'path' or 'device_path'")
    if not Path(fw_path).exists():
        raise HTTPException(404, f"File not found: {fw_path}")

    job_id = _make_job_id(fw_path)
    extraction_jobs[job_id] = {"job_id": job_id, "status": "pending",
                                "fw_path": fw_path,
                                "started_at": datetime.now(timezone.utc).isoformat()}
    background_tasks.add_task(_run_extraction_bg, fw_path, job_id)
    return {"job_id": job_id, "status": "started",
            "message": "Extraction started.", "fw_path": fw_path}


# ─────────────────────────────────────────────────────────────────────────────
# Extraction from connected device (avrdude / esptool)
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/extract-device")
async def start_extraction_from_device(body: dict, background_tasks: BackgroundTasks):
    """
    Read flash from a connected IoT device.
    For ESP32/ESP8266 (tool=esptool): automatic baud-rate fallback + --no-stub fallback.
    For AVR (tool=avrdude): standard avrdude read.

    Body params:
      device_port:    "/dev/ttyUSB0"
      tool:           "esptool" | "avrdude"   (default: esptool)
      baudrate:       115200 | 230400 | 460800 (default: 460800 for esptool, 115200 for avrdude)
      mcu:            "m328p" etc (avrdude only)
      chip:           "esp32" | "esp8266" | "auto" (esptool only, default: auto)
      flash_size:     "4MB" | "8MB" | "16MB" | "detect" (esptool, default: detect)
      include_eeprom: false (avrdude only)
    """
    device_port = body.get("device_port")
    if not device_port:
        raise HTTPException(400, "Provide 'device_port'")
    if not Path(device_port).exists():
        raise HTTPException(404, f"Device not found: {device_port}")

    tool         = body.get("tool",         "esptool")
    chip         = body.get("chip",         "auto")
    flash_size   = body.get("flash_size",   "detect")
    mcu          = body.get("mcu",          "m328p")
    include_eeprom = bool(body.get("include_eeprom", False))

    # Default baud differs by tool
    default_baud = 460800 if tool == "esptool" else 115200
    baudrate     = int(body.get("baudrate", default_baud))

    job_id = _make_job_id(device_port)
    extraction_jobs[job_id] = {"job_id": job_id, "status": "pending",
                                "device_port": device_port, "tool": tool,
                                "started_at": datetime.now(timezone.utc).isoformat()}

    background_tasks.add_task(
        _run_device_extraction_bg,
        device_port, job_id, baudrate, mcu, include_eeprom, tool, chip, flash_size,
    )
    return {"job_id": job_id, "status": "started",
            "message": f"Flash read started via {tool}.",
            "device_port": device_port}


# ─────────────────────────────────────────────────────────────────────────────
# Background: uploaded-file extraction
# ─────────────────────────────────────────────────────────────────────────────

async def _run_extraction_bg(fw_path: str, job_id: str):
    from main import broadcast
    progress_updates: list = []

    def cb(event: dict): progress_updates.append(event)
    async def flush():
        for ev in progress_updates: await broadcast({**ev, "phase": "phase2"})
        progress_updates.clear()

    await broadcast({"event": "extraction_started", "job_id": job_id, "phase": "phase2"})
    await broadcast({"event": "progress", "job_id": job_id, "phase": "phase2",
                     "percent": 5, "step": "Starting extraction pipeline"})

    loop = asyncio.get_event_loop()
    result: ExtractionResult = await loop.run_in_executor(
        None, lambda: run_extraction(fw_path, job_id, cb))
    await flush()

    result_dict = asdict(result)
    extraction_jobs[job_id] = result_dict
    await broadcast({"event": "extraction_complete", "job_id": job_id, "phase": "phase2",
                     "percent": 100, "status": result.status.value,
                     "total_files": result.total_files, "linux_found": result.linux_found,
                     "extractor_used": result.extractor_used, "result": result_dict})


# ─────────────────────────────────────────────────────────────────────────────
# Background: device extraction  (avrdude / esptool)
# ─────────────────────────────────────────────────────────────────────────────

# Baud ladder for esptool (fastest → slowest)
_ESPTOOL_BAUD_LADDER = [460800, 230400, 115200]

# Flash-size string → byte count
_FLASH_SIZE_MAP = {
    "detect": None,   # let esptool discover it
    "256KB":  0x40000,
    "512KB":  0x80000,
    "1MB":    0x100000,
    "2MB":    0x200000,
    "4MB":    0x400000,
    "8MB":    0x800000,
    "16MB":   0x1000000,
}


def _esptool_read_cmd(
    device_port: str,
    baud:        int,
    chip:        str,
    flash_bytes: Optional[int],
    out_path:    str,
    no_stub:     bool = False,
) -> list[str]:
    """
    Build the correct esptool v5 read-flash command.

    Key fixes vs previous version:
      - 'read-flash' (hyphen), as required by esptool v5
      - Flash size is an explicit hex integer, NOT the string "ALL"
      - --before default-reset, --after hard-reset
      - --no-stub flag added when no_stub=True
    """
    size_arg = hex(flash_bytes) if flash_bytes else "0x400000"  # default 4 MB
    # Use the API process's interpreter so virtual-environment PATH handling
    # cannot make the installed esptool command disappear.
    cmd = [
        sys.executable,
        "-m", "esptool",
        "--port",   device_port,
        "--baud",   str(baud),
        "--chip",   chip,
        "--before", "default-reset",
        "--after",  "hard-reset",
    ]
    if no_stub:
        cmd.append("--no-stub")
    cmd += ["read-flash", "0x0", size_arg, out_path]
    return cmd


async def _run_device_extraction_bg(
    device_port:   str,
    job_id:        str,
    baudrate:      int,
    mcu:           str,
    include_eeprom: bool,
    tool:          str,
    chip:          str,
    flash_size:    str,
):
    from main import broadcast
    progress_updates: list = []

    def cb(event: dict): progress_updates.append(event)

    async def flush():
        for ev in progress_updates: await broadcast({**ev, "phase": "phase2"})
        progress_updates.clear()

    async def emit(event: str, **kwargs):
        await broadcast({"event": event, "job_id": job_id, "phase": "phase2", **kwargs})

    await emit("extraction_started")
    await emit("progress", percent=2, step="Preparing directories")

    output_dir = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/extractions") / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    chip_label  = chip if tool == "esptool" else mcu
    store_name  = f"flash_{chip_label}_{ts}_{job_id}.bin"
    store_path  = FIRMWARE_STORE / store_name
    flash_path  = output_dir / "flash.bin"

    flash_bytes = _FLASH_SIZE_MAP.get(flash_size)   # None = auto-detect

    flash_ok   = False
    last_error = "unknown error"
    loop       = asyncio.get_event_loop()

    # ── Build the list of (command, label) attempts ───────────────────────────
    if tool == "esptool":
        # Stub pass: walk the baud ladder (keep only bauds ≤ user's chosen rate)
        stub_bauds = [b for b in _ESPTOOL_BAUD_LADDER if b <= baudrate] or [115200]
        # If user requested a baud not in the ladder, prepend it
        if baudrate not in stub_bauds:
            stub_bauds.insert(0, baudrate)

        attempts = [
            (_esptool_read_cmd(device_port, b, chip, flash_bytes, str(flash_path), False),
             f"esptool stub  baud={b}")
            for b in stub_bauds
        ] + [
            # --no-stub fallback at 115200: uses ROM bootloader, immune to corrupt-data errors
            (_esptool_read_cmd(device_port, 115200, chip, flash_bytes, str(flash_path), True),
             "esptool --no-stub  baud=115200"),
        ]
    else:
        # avrdude: single attempt at the requested baud
        attempts = [(
            ["avrdude", "-c", "arduino", "-p", mcu, "-P", device_port,
             "-b", str(baudrate), "-D", f"-Uflash:r:{flash_path}:r"],
            f"avrdude baud={baudrate}",
        )]

    # ── Attempt loop ──────────────────────────────────────────────────────────
    for attempt_idx, (cmd, label) in enumerate(attempts):
        is_last    = (attempt_idx == len(attempts) - 1)
        is_no_stub = "--no-stub" in cmd

        await emit("log",      message=f"[{tool}] Attempt {attempt_idx+1}/{len(attempts)}: {label}")
        await emit("progress", percent=5, step=f"{tool}: connecting ({label})…")

        if flash_path.exists():
            flash_path.unlink()   # remove partial file from previous attempt

        _q: queue.Queue = queue.Queue()
        # Timeouts: stub = fast; no-stub is ~10× slower for a 4 MB flash
        timeout_s = 600 if is_no_stub else 180

        def _stream(cmd=cmd, timeout_s=timeout_s):
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )
                buf: list[str] = []
                last_cr = ""
                while True:
                    ch = proc.stdout.read(1)
                    if not ch:
                        break
                    if ch in ("\n", "\r"):
                        raw = "".join(buf)
                        clean = _clean(raw)
                        if clean and (ch == "\n" or clean != last_cr):
                            _q.put(("line", clean))
                            if ch == "\r":
                                last_cr = clean
                        buf = []
                        if ch == "\n":
                            last_cr = ""
                    else:
                        buf.append(ch)
                if buf:
                    clean = _clean("".join(buf))
                    if clean:
                        _q.put(("line", clean))
                proc.wait(timeout=timeout_s)
                _q.put(("done", proc.returncode))
            except FileNotFoundError:
                _q.put(("error", f"{tool} not found in PATH — install esptool: pip install esptool"))
            except subprocess.TimeoutExpired:
                proc.kill()
                _q.put(("error", f"{tool} timed out after {timeout_s}s"))
            except Exception as exc:
                _q.put(("error", str(exc)))

        thread = threading.Thread(target=_stream, daemon=True)
        thread.start()

        returncode    = -1
        attempt_ok    = False
        attempt_error = ""
        corrupt_data  = False
        detected_size = None
        last_read_pct = -1

        while True:
            try:
                kind, value = _q.get(timeout=0.05)
            except queue.Empty:
                await asyncio.sleep(0.05)
                continue

            if kind == "line":
                # Detect corrupt-data dropout
                if "corrupt data" in value.lower():
                    corrupt_data = True

                # Auto-detect flash size from esptool output
                m_size = re.search(r"Detected flash size:\s*(\d+\s*(?:MB|KB))", value, re.I)
                if m_size:
                    detected_size = m_size.group(1)
                    await emit("log", message=f"[esptool] {value}")
                    continue

                # Parse progress percentage
                m_pct = re.search(r"(\d+(?:\.\d+)?)%", value)
                if m_pct:
                    pct = int(float(m_pct.group(1)))
                    if pct == last_read_pct:
                        continue
                    last_read_pct = pct
                    stub_label = "(--no-stub)" if is_no_stub else ""
                    await emit("progress",
                               percent=5 + int(pct * 0.15),
                               step=f"esptool {stub_label}: reading flash… {pct}%")

                # Always log the cleaned line
                await emit("log", message=f"[{tool}] {value}")

            elif kind == "done":
                returncode = value
                attempt_ok = (returncode == 0) and flash_path.exists() and flash_path.stat().st_size > 0
                if not attempt_ok and not attempt_error:
                    attempt_error = f"exit code {returncode}"
                break

            elif kind == "error":
                attempt_error = value
                await emit("log", message=f"[{tool}] ERROR: {value}")
                break

        if attempt_ok:
            flash_ok = True
            break   # ✓ success — exit attempt loop

        last_error = attempt_error

        if corrupt_data:
            if not is_last:
                next_label = attempts[attempt_idx + 1][1]
                await emit("log", message=(
                    f"[esptool] ⚠ Corrupt data (USB packet dropout at high baud). "
                    f"Retrying with: {next_label}"
                ))
            else:
                await emit("log", message=(
                    "[esptool] ✗ All attempts failed — corrupt data even at "
                    "lowest baud with --no-stub. Check USB cable quality and 3.3V supply."
                ))
        else:
            await emit("log", message=f"[{tool}] Attempt failed: {attempt_error}")

    # ── Check success ─────────────────────────────────────────────────────────
    if not flash_ok:
        await emit("progress", percent=100, step="Flash read failed")
        _fail_job(job_id, last_error)
        await emit("extraction_complete",
                   status=ExtractionStatus.FAILED.value, error=last_error)
        return

    flash_size_bytes = flash_path.stat().st_size
    await emit("log",      message=f"[{tool}] Flash read OK — {_human_size(flash_size_bytes)}")
    await emit("progress", percent=20, step="Flash read complete")

    # ── Persist to firmware store ─────────────────────────────────────────────
    shutil.copy2(str(flash_path), str(store_path))
    await emit("log",      message=f"[store] Firmware saved → {store_path}")
    await emit("progress", percent=22, step=f"Saved → {store_name}")
    await broadcast({"event": "firmware_saved", "job_id": job_id, "phase": "phase2",
                     "bin_path": str(store_path), "bin_filename": store_name,
                     "size_bytes": flash_size_bytes,
                     "size_human": _human_size(flash_size_bytes)})

    # ── Optional EEPROM (avrdude only) ────────────────────────────────────────
    eeprom_store_path: Optional[Path] = None
    if include_eeprom and tool == "avrdude":
        eeprom_path      = output_dir / "eeprom.bin"
        eeprom_store_name = f"eeprom_{mcu}_{ts}_{job_id}.bin"
        await emit("log",      message=f"[avrdude] Reading EEPROM from {device_port}…")
        await emit("progress", percent=24, step="Reading EEPROM…")
        ok, _, err = await loop.run_in_executor(
            None,
            lambda: _run_avrdude_simple(device_port, baudrate, mcu, "eeprom",
                                        str(eeprom_path), timeout=30))
        if ok:
            eeprom_store_path = FIRMWARE_STORE / eeprom_store_name
            shutil.copy2(str(eeprom_path), str(eeprom_store_path))
            await emit("log", message=f"[avrdude] EEPROM OK → {eeprom_store_path}")
        else:
            await emit("log", message=f"[avrdude] EEPROM failed (non-fatal): {err}")

    # ── Extraction pipeline (binwalk / unblob / partitions) ───────────────────
    await emit("log",      message="[extract] Running extraction pipeline on flash.bin…")
    await emit("progress", percent=25, step="Starting extraction pipeline")

    result: ExtractionResult = await loop.run_in_executor(
        None,
        lambda: run_extraction(str(flash_path), job_id, cb))
    await flush()

    result_dict = asdict(result)
    result_dict.update({
        "flash_bin_path":       str(store_path),
        "flash_bin_filename":   store_name,
        "flash_bin_size_bytes": flash_size_bytes,
        "flash_bin_size_human": _human_size(flash_size_bytes),
        "detected_flash_size":  detected_size or flash_size,
    })
    if eeprom_store_path:
        result_dict["eeprom_bin_path"] = str(eeprom_store_path)

    extraction_jobs[job_id] = result_dict
    await broadcast({"event": "extraction_complete", "job_id": job_id, "phase": "phase2",
                     "percent": 100, "status": result.status.value,
                     "total_files": result.total_files, "linux_found": result.linux_found,
                     "extractor_used": result.extractor_used,
                     "flash_bin_path": str(store_path),
                     "flash_bin_filename": store_name,
                     "flash_bin_size_human": _human_size(flash_size_bytes),
                     "result": result_dict})


# ─── helpers ──────────────────────────────────────────────────────────────────

def _run_avrdude_simple(device_port, baudrate, mcu, memtype, output_file, timeout=60):
    cmd = ["avrdude", "-c", "arduino", "-p", mcu, "-P", device_port,
           "-b", str(baudrate), "-D", f"-U{memtype}:r:{output_file}:r"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return False, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return False, "", "avrdude not found"
    except Exception as e:
        return False, "", str(e)


def _fail_job(job_id: str, error: str):
    prev = extraction_jobs.get(job_id, {})
    extraction_jobs[job_id] = {**prev, "job_id": job_id,
                                "status": ExtractionStatus.FAILED.value,
                                "error": error,
                                "completed_at": datetime.now(timezone.utc).isoformat()}


def _make_job_id(seed: str) -> str:
    return hashlib.md5(
        f"{seed}-{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─── Query endpoints ──────────────────────────────────────────────────────────

@router.get("/store")
async def list_firmware_store():
    files = []
    for p in sorted(FIRMWARE_STORE.iterdir()):
        if p.is_file():
            stat = p.stat()
            files.append({"filename": p.name, "path": str(p),
                           "size_bytes": stat.st_size, "size_human": _human_size(stat.st_size),
                           "created_at": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()})
    return {"store_dir": str(FIRMWARE_STORE), "files": files}


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
    return {"job_id": job_id, "file_tree": job.get("file_tree", []),
            "total_files": job.get("total_files", 0), "total_dirs": job.get("total_dirs", 0),
            "linux_found": job.get("linux_found", False), "linux_paths": job.get("linux_paths", []),
            "flash_bin_path": job.get("flash_bin_path"),
            "flash_bin_filename": job.get("flash_bin_filename"),
            "flash_bin_size_human": job.get("flash_bin_size_human")}


@router.get("/extract/{job_id}/download")
async def download_firmware(job_id: str):
    if job_id not in extraction_jobs:
        raise HTTPException(404, "Job not found")
    job = extraction_jobs[job_id]
    path = job.get("flash_bin_path")
    filename = job.get("flash_bin_filename", "flash.bin")
    if not path or not Path(path).exists():
        raise HTTPException(404, "Firmware file not found")
    return FileResponse(path, media_type="application/octet-stream", filename=filename)

@router.delete("/extract/{job_id}")
async def delete_extraction(job_id: str):
    cleanup_extraction(job_id)
    extraction_jobs.pop(job_id, None)
    return {"deleted": job_id}


@router.get("/jobs")
async def list_jobs():
    return {"jobs": [{
        "job_id":           j.get("job_id"),
        "status":           j.get("status"),
        "fw_path":          j.get("fw_path"),
        "device_port":      j.get("device_port"),
        "total_files":      j.get("total_files", 0),
        "extractor_used":   j.get("extractor_used", ""),
        "flash_bin_path":   j.get("flash_bin_path"),
        "flash_bin_size_human": j.get("flash_bin_size_human"),
        "started_at":       j.get("started_at", ""),
        "completed_at":     j.get("completed_at", ""),
    } for j in extraction_jobs.values()]}
