"""
IIFVDCAS Phase 4 — SBOM API Routes
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

try:
    from .generator import run_sbom_generation
except ImportError:
    run_sbom_generation = None

# ─── Models ──────────────────────────────────────────────────────────────────

class SBOMGenerateRequest(BaseModel):
    extraction_job_id: Optional[str] = None
    analysis_job_id: Optional[str]   = None
    device_info: Optional[dict]       = None
    output_dir: Optional[str]         = None

class SBOMGenerateResponse(BaseModel):
    job_id: str
    status: str
    message: str

class SBOMComponentInfo(BaseModel):
    name: str
    version: str
    type: str
    cpe: Optional[str]  = None
    purl: Optional[str] = None
    license: Optional[str] = None
    source: Optional[str] = None

# ─── In-memory job store ──────────────────────────────────────────────────────

SBOM_JOBS: dict[str, dict] = {}

def _get_job(job_id: str) -> dict:
    return SBOM_JOBS.get(job_id)

def _create_job(request: SBOMGenerateRequest) -> str:
    job_id = str(uuid.uuid4())
    SBOM_JOBS[job_id] = {
        "job_id":             job_id,
        "extraction_job_id":  request.extraction_job_id,
        "analysis_job_id":    request.analysis_job_id,
        "device_info":        request.device_info or {},
        "status":             "pending",
        "progress":           0,
        "progress_step":      "",
        "created_at":         datetime.now(timezone.utc).isoformat(),
        "completed_at":       None,
        "error":              None,
        "sbom":               [],
        "hbom":               [],
        "cbom":               [],
        "license_summary":    {},
        "toolchain":          {},
    }
    return job_id

def _update_job(job_id: str, **kw):
    if job_id in SBOM_JOBS:
        SBOM_JOBS[job_id].update(kw)

# ─── Background task ──────────────────────────────────────────────────────────

async def _sbom_bg(job_id: str, target_dir: str, firmware_path: str, prior: dict):
    """
    Async background task — runs the blocking generator in an executor
    and relays every progress/log event to WebSocket clients.
    """
    from main import broadcast

    event_queue: list = []

    def progress_cb(event: dict):
        """Called from the sync generator thread — just buffer events."""
        event_queue.append(event)

    async def flush():
        for ev in event_queue:
            await broadcast({**ev, "phase": "phase4"})
        event_queue.clear()

    await broadcast({"event": "sbom_started", "job_id": job_id, "phase": "phase4"})
    await broadcast({"event": "progress", "job_id": job_id, "phase": "phase4",
                     "percent": 2, "step": "Preparing SBOM generation…"})
    _update_job(job_id, status="processing", progress=2)

    if not run_sbom_generation:
        err = "SBOM generator module not available"
        _update_job(job_id, status="failed", error=err,
                    completed_at=datetime.now(timezone.utc).isoformat())
        await broadcast({"event": "sbom_complete", "job_id": job_id, "phase": "phase4",
                         "status": "failed", "error": err})
        return

    loop = asyncio.get_event_loop()

    # Run blocking generator in thread pool; poll queue every 200 ms for live relay
    future = loop.run_in_executor(
        None,
        lambda: run_sbom_generation(
            target_dir=target_dir,
            job_id=job_id,
            firmware_path=firmware_path,
            prior_analysis=prior,
            progress_callback=progress_cb,
        ),
    )

    # Live relay loop — runs while generator is working
    while not future.done():
        await asyncio.sleep(0.2)
        if event_queue:
            # Mirror progress into job store
            for ev in event_queue:
                if ev.get("event") == "progress":
                    _update_job(job_id,
                                progress=ev.get("percent", 0),
                                progress_step=ev.get("step", ""))
            await flush()

    # Drain any remaining events
    await flush()

    try:
        result = future.result()
    except Exception as exc:
        logger.exception("run_sbom_generation raised")
        err = str(exc)
        _update_job(job_id, status="failed", error=err,
                    completed_at=datetime.now(timezone.utc).isoformat())
        await broadcast({"event": "sbom_complete", "job_id": job_id, "phase": "phase4",
                         "status": "failed", "error": err})
        return

    # Store result
    _update_job(
        job_id,
        status=result.status,
        progress=100,
        progress_step="Complete",
        sbom=result.sbom_components,
        hbom=result.hbom_components,
        cbom=result.cbom_components,
        license_summary=result.license_summary,
        toolchain=result.toolchain,
        cyclonedx_path=result.cyclonedx_json_path,
        hbom_path=result.hbom_json_path,
        cbom_path=result.cbom_json_path,
        completed_at=result.completed_at,
        error=result.error or None,
    )

    await broadcast({
        "event":   "sbom_complete",
        "job_id":  job_id,
        "phase":   "phase4",
        "percent": 100,
        "status":  result.status,
        "result": {
            "status":          result.status,
            "component_count": result.total_components,
            "hardware_count":  result.total_hw_components,
            "crypto_count":    result.total_crypto_components,
            "weak_crypto":     result.weak_crypto_count,
            "insecure_crypto": result.insecure_crypto_count,
            "cyclonedx_path":  result.cyclonedx_json_path,
            "hbom_path":       result.hbom_json_path,
            "cbom_path":       result.cbom_json_path,
        }
    })
    logger.info(f"[{job_id}] SBOM complete — {result.total_components} components")


# ─── Router ───────────────────────────────────────────────────────────────────

router = APIRouter(prefix="/api/v1/sbom", tags=["sbom"])


@router.post("/generate", response_model=SBOMGenerateResponse)
async def generate_sbom(request: SBOMGenerateRequest, background_tasks: BackgroundTasks):
    # Resolve target directory
    target_dir = request.output_dir

    if not target_dir and request.extraction_job_id:
        # Look it up from the firmware extraction job store
        try:
            from core.firmware_extraction.routes import extraction_jobs
            ex_job = extraction_jobs.get(request.extraction_job_id, {})
            target_dir = ex_job.get("output_dir") or f"/tmp/iifvdcas_extractions/{request.extraction_job_id}"
        except Exception:
            target_dir = f"/tmp/iifvdcas_extractions/{request.extraction_job_id}"

    if not target_dir:
        # Default: scan the firmware store
        target_dir = "/tmp/iifvdcas_firmware_store"

    if not Path(target_dir).exists():
        # Fallback: create an empty dir so generation can still run
        # (it will produce an HBOM/CBOM based on whatever bits are available)
        Path(target_dir).mkdir(parents=True, exist_ok=True)
        logger.warning(f"Target dir did not exist, created: {target_dir}")

    firmware_path = ""
    if request.extraction_job_id:
        try:
            from core.firmware_extraction.routes import extraction_jobs
            ex_job = extraction_jobs.get(request.extraction_job_id, {})
            firmware_path = ex_job.get("flash_bin_path", "")
        except Exception:
            pass

    job_id = _create_job(request)
    background_tasks.add_task(
        _sbom_bg, job_id, target_dir, firmware_path, request.device_info or {}
    )

    return SBOMGenerateResponse(
        job_id=job_id,
        status="pending",
        message=f"SBOM generation started (job {job_id})",
    )


@router.get("/{job_id}/status")
async def get_status(job_id: str):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return {
        "job_id":        job_id,
        "status":        job["status"],
        "progress":      job["progress"],
        "progress_step": job.get("progress_step", ""),
        "created_at":    job["created_at"],
        "completed_at":  job["completed_at"],
        "error":         job.get("error"),
    }


@router.get("/{job_id}")
async def get_sbom(job_id: str):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return {
        "job_id":           job_id,
        "status":           job["status"],
        "progress":         job["progress"],
        "progress_step":    job.get("progress_step", ""),
        "created_at":       job["created_at"],
        "completed_at":     job["completed_at"],
        "components":       job.get("sbom", []),
        "total_components": len(job.get("sbom", [])),
        "license_summary":  job.get("license_summary", {}),
        "toolchain":        job.get("toolchain", {}),
        "error":            job.get("error"),
    }


@router.get("/{job_id}/hbom")
async def get_hbom(job_id: str):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    return {
        "job_id":             job_id,
        "status":             job["status"],
        "hardware_components": job.get("hbom", []),
        "total_hw_components": len(job.get("hbom", [])),
    }


@router.get("/{job_id}/cbom")
async def get_cbom(job_id: str):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    comps = job.get("cbom", [])
    return {
        "job_id":            job_id,
        "status":            job["status"],
        "crypto_components": comps,
        "summary": {
            "total":      len(comps),
            "strong":     sum(1 for c in comps if c.get("strength") == "strong"),
            "acceptable": sum(1 for c in comps if c.get("strength") == "acceptable"),
            "weak":       sum(1 for c in comps if c.get("strength") == "weak"),
            "insecure":   sum(1 for c in comps if c.get("strength") == "insecure"),
        },
    }


@router.get("/{job_id}/components")
async def get_components(
    job_id: str,
    filter_type: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("name"),
):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")

    comps = job.get("sbom", [])
    if filter_type:
        comps = [c for c in comps if c.get("component_type") == filter_type]

    result = []
    for c in comps:
        result.append({
            "name":    c.get("name", "unknown"),
            "version": c.get("version", "unknown"),
            "type":    c.get("component_type", "unknown"),
            "cpe":     c.get("cpe", ""),
            "purl":    c.get("purl", ""),
            "license": c.get("license", "NOASSERTION"),
            "source":  c.get("source_path", ""),
        })

    key_map = {"name": "name", "version": "version", "type": "type"}
    k = key_map.get(sort_by, "name")
    result.sort(key=lambda x: x.get(k, ""))
    return result


@router.get("/{job_id}/download")
async def download_sbom(job_id: str, format: str = Query("cyclonedx")):
    job = _get_job(job_id)
    if not job:
        raise HTTPException(404, f"Job {job_id} not found")
    if job["status"] not in ("success",):
        raise HTTPException(400, f"Job {job_id} not complete yet (status={job['status']})")

    if format == "cyclonedx" and job.get("cyclonedx_path"):
        fp = Path(job["cyclonedx_path"])
        if fp.exists():
            return FileResponse(fp, media_type="application/json",
                                filename=f"sbom_cyclonedx_{job_id[:8]}.json")

    # Fallback: return components as JSON
    return JSONResponse({
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "components": job.get("sbom", []),
    })


@router.get("/jobs/list")
async def list_jobs():
    return {
        "jobs": [
            {
                "job_id":       j["job_id"],
                "status":       j["status"],
                "progress":     j["progress"],
                "created_at":   j["created_at"],
                "completed_at": j["completed_at"],
                "component_count": len(j.get("sbom", [])),
                "error":        j.get("error"),
            }
            for j in SBOM_JOBS.values()
        ]
    }
