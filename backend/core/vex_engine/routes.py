"""
Phase 6 VEX Risk Analysis — API Routes
"""
import asyncio
import hashlib
import time
import logging
from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path

from .analyzer import run_vex_analysis, VEXResult

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/vex", tags=["vex"])

# In-memory job store
vex_jobs: dict[str, dict] = {}


# ─── List jobs (must be before /{job_id}) ────────────────────────────────────

@router.get("/jobs/list")
async def list_vex_jobs():
    return {
        "jobs": [
            {
                "job_id":          j.get("job_id"),
                "status":          j.get("status"),
                "risk_score":      j.get("risk_score", 0.0),
                "risk_label":      j.get("risk_label", ""),
                "affected_count":  j.get("affected_count", 0),
                "total_cves":      j.get("total_cves_input", 0),
                "cve_job_id":      j.get("cve_job_id", ""),
                "started_at":      j.get("started_at", ""),
                "completed_at":    j.get("completed_at", ""),
            }
            for j in vex_jobs.values()
        ]
    }


# ─── Start VEX analysis ───────────────────────────────────────────────────────

@router.post("/analyze")
async def start_vex_analysis(body: dict, background_tasks: BackgroundTasks):
    """
    Start Phase 6 VEX analysis.
    Requires cve_job_id (Phase 5) and sbom_job_id (Phase 4).
    Optional: analysis_job_id (Phase 3), device_info dict.
    """
    cve_job_id      = body.get("cve_job_id")
    sbom_job_id     = body.get("sbom_job_id", "")
    analysis_job_id = body.get("analysis_job_id", "")
    device_info     = body.get("device_info") or {}

    if not cve_job_id:
        raise HTTPException(400, "Provide 'cve_job_id' from Phase 5 CVE mapping")

    job_id = "vex_" + hashlib.md5(
        f"{cve_job_id}{time.time()}".encode()
    ).hexdigest()[:10]

    vex_jobs[job_id] = {
        "job_id":      job_id,
        "cve_job_id":  cve_job_id,
        "sbom_job_id": sbom_job_id,
        "status":      "pending",
        "progress":    0,
        "started_at":  asyncio.get_event_loop().time(),
    }

    background_tasks.add_task(
        _vex_bg, job_id, cve_job_id, sbom_job_id, analysis_job_id, device_info
    )

    return {
        "job_id":      job_id,
        "status":      "started",
        "message":     "VEX analysis started. Connect to /ws for live progress.",
        "cve_job_id":  cve_job_id,
        "sbom_job_id": sbom_job_id,
    }


# ─── Background task ──────────────────────────────────────────────────────────

async def _vex_bg(
    job_id: str, cve_job_id: str, sbom_job_id: str,
    analysis_job_id: str, device_info: dict,
):
    from main import broadcast

    event_queue: list = []

    def progress_cb(event: dict):
        event_queue.append(event)

    async def flush():
        for ev in event_queue:
            await broadcast({**ev, "phase": "phase6"})
        event_queue.clear()

    async def emit(event: str, **kwargs):
        await broadcast({"event": event, "job_id": job_id,
                         "phase": "phase6", **kwargs})

    vex_jobs[job_id]["status"] = "processing"
    await emit("vex_started")
    await emit("progress", percent=2, step="Starting VEX analysis…")

    loop = asyncio.get_event_loop()

    # Run blocking analysis in executor — all NVD/disk I/O stays in one thread
    future = loop.run_in_executor(
        None,
        lambda: run_vex_analysis(
            cve_job_id      = cve_job_id,
            sbom_job_id     = sbom_job_id,
            analysis_job_id = analysis_job_id,
            job_id          = job_id,
            device_info     = device_info,
            progress_cb     = progress_cb,
        ),
    )

    while not future.done():
        await asyncio.sleep(0.25)
        if event_queue:
            for ev in event_queue:
                if ev.get("event") == "progress":
                    vex_jobs[job_id]["progress"] = ev.get("percent", 0)
            await flush()

    await flush()

    try:
        result: VEXResult = future.result()
    except Exception as exc:
        logger.exception(f"[VEX] background task failed for {job_id}")
        vex_jobs[job_id].update({"status": "failed", "error": str(exc)})
        await emit("vex_complete", status="failed", error=str(exc))
        return

    result_dict = asdict(result)
    vex_jobs[job_id] = result_dict

    await broadcast({
        "event":          "vex_complete",
        "job_id":         job_id,
        "phase":          "phase6",
        "percent":        100,
        "status":         result.status,
        "risk_score":     result.risk_score,
        "risk_label":     result.risk_label,
        "affected":       result.affected_count,
        "not_affected":   result.not_affected_count,
        "fixed":          result.fixed_count,
        "under_inv":      result.under_inv_count,
        "result": {
            "risk_score":     result.risk_score,
            "risk_label":     result.risk_label,
            "affected_count": result.affected_count,
        },
    })


# ─── Query endpoints ──────────────────────────────────────────────────────────

@router.get("/{job_id}/status")
async def get_status(job_id: str):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    return {
        "job_id":       job_id,
        "status":       job.get("status", "unknown"),
        "progress":     job.get("progress", 0),
        "risk_score":   job.get("risk_score", 0.0),
        "risk_label":   job.get("risk_label", ""),
        "affected":     job.get("affected_count", 0),
        "not_affected": job.get("not_affected_count", 0),
        "completed_at": job.get("completed_at", ""),
        "error":        job.get("error", ""),
    }


@router.get("/{job_id}/summary")
async def get_summary(job_id: str):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    return {
        "job_id":             job_id,
        "status":             job.get("status"),
        "risk_score":         job.get("risk_score", 0.0),
        "risk_label":         job.get("risk_label", ""),
        "total_cves_input":   job.get("total_cves_input", 0),
        "affected_count":     job.get("affected_count", 0),
        "not_affected_count": job.get("not_affected_count", 0),
        "fixed_count":        job.get("fixed_count", 0),
        "under_inv_count":    job.get("under_inv_count", 0),
        "top_risks":          job.get("top_risks", []),
        "firmware_context":   job.get("firmware_context", {}),
    }


@router.get("/{job_id}/triage")
async def get_triage(
    job_id:  str,
    status:  Optional[str] = None,
    limit:   int = 200,
    offset:  int = 0,
):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")

    findings = job.get("triage_results", [])
    if status:
        findings = [f for f in findings if f.get("vex_status") == status]

    return {
        "job_id":  job_id,
        "total":   len(findings),
        "limit":   limit,
        "offset":  offset,
        "findings": findings[offset: offset + limit],
    }


@router.get("/{job_id}/remediation")
async def get_remediation(job_id: str):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    return {
        "job_id":           job_id,
        "remediation_plan": job.get("remediation_plan", []),
        "component_summary": job.get("component_summary", []),
    }


@router.get("/{job_id}/download")
async def download_vex(job_id: str):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    vex_path = job.get("vex_doc_path", "")
    if not vex_path or not Path(vex_path).exists():
        raise HTTPException(404, "VEX document not generated yet")
    return FileResponse(
        vex_path,
        media_type="application/json",
        filename=f"vex_{job_id[:8]}.json",
    )


@router.get("/{job_id}")
async def get_full_result(job_id: str):
    job = vex_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    return job


@router.delete("/{job_id}")
async def delete_job(job_id: str):
    if job_id not in vex_jobs:
        raise HTTPException(404, f"VEX job not found: {job_id}")
    del vex_jobs[job_id]
    return {"deleted": job_id}
