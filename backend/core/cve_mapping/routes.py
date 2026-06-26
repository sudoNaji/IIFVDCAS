"""
API routes for Phase 5 CVE mapping.
"""
import asyncio
import logging
from dataclasses import asdict
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import JSONResponse

from .cve_aggregator import run_cve_mapping, CVEResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/cve", tags=["cve"])

cve_mapping_jobs: dict[str, dict] = {}


# ─── List all jobs — MUST be defined before /{job_id} routes ─────────────────

@router.get("/jobs/list")
async def list_cve_jobs():
    """List all CVE mapping jobs."""
    jobs = []
    for job_id, job in cve_mapping_jobs.items():
        jobs.append({
            "job_id":        job_id,
            "sbom_job_id":   job.get("sbom_job_id", ""),
            "status":        job.get("status", "unknown"),
            "total_cves":    job.get("total_cves", 0),
            "critical_count":job.get("critical_count", 0),
            "kev_count":     job.get("kev_count", 0),
            "started_at":    job.get("started_at", ""),
            "completed_at":  job.get("completed_at", ""),
        })
    return {"jobs": jobs}


# ─── Start scan ───────────────────────────────────────────────────────────────

@router.post("/scan")
async def start_cve_mapping(body: dict, background_tasks: BackgroundTasks):
    """
    Start CVE mapping job based on Phase 4 SBOM data.
    Accepts: {"sbom_job_id": "xxx"}
    """
    sbom_job_id = body.get("sbom_job_id")
    if not sbom_job_id:
        raise HTTPException(400, "Provide 'sbom_job_id' from Phase 4 SBOM generation")

    import hashlib, time
    job_id = "cve_" + hashlib.md5(f"{sbom_job_id}{time.time()}".encode()).hexdigest()[:10]

    cve_mapping_jobs[job_id] = {
        "job_id":      job_id,
        "sbom_job_id": sbom_job_id,
        "status":      "pending",
        "started_at":  asyncio.get_event_loop().time(),
    }

    background_tasks.add_task(_run_cve_mapping_bg, sbom_job_id, job_id)

    return {
        "job_id":      job_id,
        "status":      "started",
        "message":     "CVE mapping started. Connect to /ws for live progress.",
        "sbom_job_id": sbom_job_id,
    }


# ─── Background task ──────────────────────────────────────────────────────────

async def _run_cve_mapping_bg(sbom_job_id: str, job_id: str):
    from main import broadcast

    event_queue: list = []

    def sync_progress_cb(event: dict):
        event_queue.append(event)

    async def flush():
        for ev in event_queue:
            await broadcast({**ev, "phase": "phase5"})
        event_queue.clear()

    async def emit(event: str, **kwargs):
        await broadcast({"event": event, "job_id": job_id, "phase": "phase5", **kwargs})

    try:
        await emit("cve_mapping_started")
        await emit("progress", percent=2, step="Initializing CVE mapping…")
        cve_mapping_jobs[job_id]["status"] = "processing"

        loop = asyncio.get_event_loop()

        # Run blocking mapper in thread pool; poll queue every 300ms for live relay
        future = loop.run_in_executor(
            None,
            lambda: run_cve_mapping(sbom_job_id, job_id, sync_progress_cb),
        )

        while not future.done():
            await asyncio.sleep(0.3)
            if event_queue:
                for ev in event_queue:
                    if ev.get("event") == "progress":
                        cve_mapping_jobs[job_id]["progress"] = ev.get("percent", 0)
                await flush()

        await flush()
        result: CVEResult = future.result()

        result_dict = {
            "job_id":         result.job_id,
            "sbom_job_id":    result.sbom_job_id,
            "status":         "completed",
            "total_cves":     result.total_cves,
            "critical_count": result.critical_count,
            "high_count":     result.high_count,
            "medium_count":   result.medium_count,
            "low_count":      result.low_count,
            "kev_count":      result.kev_count,
            "findings":       [asdict(f) for f in result.findings],
            "top_10":         [asdict(f) for f in result.top_10],
            "generated_at":   result.generated_at,
            "completed_at":   asyncio.get_event_loop().time(),
        }
        cve_mapping_jobs[job_id] = result_dict

        await emit("progress", percent=100, step="CVE mapping complete!")
        await broadcast({
            "event":  "cve_mapping_result",
            "job_id": job_id,
            "phase":  "phase5",
            "result": {
                "total_cves":     result.total_cves,
                "critical_count": result.critical_count,
                "kev_count":      result.kev_count,
            },
        })

    except Exception as e:
        logger.exception(f"CVE mapping background task failed for job {job_id}")
        cve_mapping_jobs[job_id] = {
            "job_id":      job_id,
            "sbom_job_id": sbom_job_id,
            "status":      "failed",
            "error":       str(e),
            "completed_at": asyncio.get_event_loop().time(),
        }
        await emit("progress", percent=100, step=f"Failed: {e}")
        await emit("cve_mapping_failed", error=str(e))


# ─── Query endpoints ──────────────────────────────────────────────────────────

@router.get("/{job_id}/summary")
async def get_cve_summary(job_id: str):
    job = cve_mapping_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"CVE mapping job not found: {job_id}")
    return {
        "job_id":         job_id,
        "status":         job.get("status", "unknown"),
        "total_cves":     job.get("total_cves", 0),
        "critical_count": job.get("critical_count", 0),
        "high_count":     job.get("high_count", 0),
        "medium_count":   job.get("medium_count", 0),
        "low_count":      job.get("low_count", 0),
        "kev_count":      job.get("kev_count", 0),
        "generated_at":   job.get("generated_at", ""),
        "error":          job.get("error"),
    }


@router.get("/{job_id}/findings")
async def get_cve_findings(
    job_id: str,
    limit: int = 100,
    offset: int = 0,
    severity: Optional[str] = None,
    kev_only: bool = False,
):
    job = cve_mapping_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"CVE mapping job not found: {job_id}")

    findings = list(job.get("findings", []))

    if severity:
        findings = [f for f in findings if f.get("cvss_severity") == severity.upper()]
    if kev_only:
        findings = [f for f in findings if f.get("is_kev") is True]

    total = len(findings)
    return {
        "job_id":   job_id,
        "total":    total,
        "limit":    limit,
        "offset":   offset,
        "findings": findings[offset:offset + limit],
    }


@router.get("/{job_id}/critical")
async def get_critical_cves(job_id: str):
    return await get_cve_findings(job_id, severity="CRITICAL", limit=500)


@router.get("/{job_id}/kev")
async def get_kev_cves(job_id: str):
    return await get_cve_findings(job_id, kev_only=True, limit=500)


@router.get("/{job_id}")
async def get_cve_result(job_id: str):
    job = cve_mapping_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"CVE mapping job not found: {job_id}")
    return job


@router.delete("/{job_id}")
async def delete_cve_job(job_id: str):
    if job_id in cve_mapping_jobs:
        del cve_mapping_jobs[job_id]
        return {"deleted": job_id}
    raise HTTPException(404, f"CVE mapping job not found: {job_id}")
