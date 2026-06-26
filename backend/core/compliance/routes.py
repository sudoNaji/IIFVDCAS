"""
Phase 7 Compliance Report — API Routes
"""
import asyncio
import hashlib
import time
import logging
from dataclasses import asdict
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse

from .report_generator import run_compliance_report, ComplianceReport

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])

compliance_jobs: dict[str, dict] = {}


# ─── List jobs (before /{job_id}) ─────────────────────────────────────────────

@router.get("/jobs/list")
async def list_jobs():
    return {
        "jobs": [
            {
                "job_id":           j.get("job_id"),
                "status":           j.get("status"),
                "compliance_score": j.get("compliance_score", 0.0),
                "compliance_grade": j.get("compliance_grade", ""),
                "risk_score":       j.get("risk_score", 0.0),
                "risk_label":       j.get("risk_label", ""),
                "device_name":      j.get("device_name", ""),
                "controls_fail":    j.get("controls_fail", 0),
                "started_at":       j.get("started_at", ""),
                "completed_at":     j.get("completed_at", ""),
                "pdf_ready":        bool(j.get("pdf_path")),
            }
            for j in compliance_jobs.values()
        ]
    }


# ─── Start report ─────────────────────────────────────────────────────────────

@router.post("/generate")
async def generate_report(body: dict, background_tasks: BackgroundTasks):
    """
    Start Phase 7 compliance report generation.
    Requires vex_job_id (Phase 6).
    Optional: cve_job_id, sbom_job_id, analysis_job_id, device_info.
    """
    vex_job_id      = body.get("vex_job_id", "")
    cve_job_id      = body.get("cve_job_id", "")
    sbom_job_id     = body.get("sbom_job_id", "")
    analysis_job_id = body.get("analysis_job_id", "")
    device_info     = body.get("device_info") or {}

    if not vex_job_id and not cve_job_id:
        raise HTTPException(400, "Provide at least 'vex_job_id' (Phase 6) or 'cve_job_id' (Phase 5)")

    job_id = "rpt_" + hashlib.md5(
        f"{vex_job_id}{time.time()}".encode()
    ).hexdigest()[:10]

    compliance_jobs[job_id] = {
        "job_id":      job_id,
        "vex_job_id":  vex_job_id,
        "cve_job_id":  cve_job_id,
        "status":      "pending",
        "progress":    0,
        "started_at":  asyncio.get_event_loop().time(),
    }

    background_tasks.add_task(
        _compliance_bg,
        job_id, vex_job_id, cve_job_id,
        sbom_job_id, analysis_job_id, device_info,
    )

    return {
        "job_id":     job_id,
        "status":     "started",
        "message":    "Compliance report started. Connect to /ws for live progress.",
        "vex_job_id": vex_job_id,
    }


# ─── Background task ──────────────────────────────────────────────────────────

async def _compliance_bg(
    job_id: str, vex_job_id: str, cve_job_id: str,
    sbom_job_id: str, analysis_job_id: str, device_info: dict,
):
    from main import broadcast

    event_queue: list = []

    def progress_cb(event: dict):
        event_queue.append(event)

    async def flush():
        for ev in event_queue:
            await broadcast({**ev, "phase": "phase7"})
        event_queue.clear()

    async def emit(event: str, **kwargs):
        await broadcast({"event": event, "job_id": job_id,
                         "phase": "phase7", **kwargs})

    compliance_jobs[job_id]["status"] = "processing"
    await emit("compliance_started")
    await emit("progress", percent=2, step="Starting compliance report…")

    loop = asyncio.get_event_loop()

    future = loop.run_in_executor(
        None,
        lambda: run_compliance_report(
            vex_job_id      = vex_job_id,
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
                    compliance_jobs[job_id]["progress"] = ev.get("percent", 0)
            await flush()

    await flush()

    try:
        result: ComplianceReport = future.result()
    except Exception as exc:
        logger.exception(f"[P7] Background task failed for {job_id}")
        compliance_jobs[job_id].update({"status": "failed", "error": str(exc)})
        await emit("compliance_complete", status="failed", error=str(exc))
        return

    result_dict = asdict(result)
    result_dict.pop("log", None)
    compliance_jobs[job_id] = result_dict

    await broadcast({
        "event":            "compliance_complete",
        "job_id":           job_id,
        "phase":            "phase7",
        "percent":          100,
        "status":           result.status,
        "compliance_score": result.compliance_score,
        "compliance_grade": result.compliance_grade,
        "risk_score":       result.risk_score,
        "pdf_ready":        bool(result.pdf_path),
        "result": {
            "compliance_score": result.compliance_score,
            "compliance_grade": result.compliance_grade,
            "controls_fail":    result.controls_fail,
            "risk_label":       result.risk_label,
        },
    })


# ─── Query endpoints ──────────────────────────────────────────────────────────

@router.get("/{job_id}/status")
async def get_status(job_id: str):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    return {
        "job_id":           job_id,
        "status":           job.get("status", "unknown"),
        "progress":         job.get("progress", 0),
        "compliance_score": job.get("compliance_score", 0.0),
        "compliance_grade": job.get("compliance_grade", ""),
        "risk_score":       job.get("risk_score", 0.0),
        "pdf_ready":        bool(job.get("pdf_path")),
        "completed_at":     job.get("completed_at", ""),
        "error":            job.get("error", ""),
    }


@router.get("/{job_id}/summary")
async def get_summary(job_id: str):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    return {
        "job_id":           job_id,
        "status":           job.get("status"),
        "device_name":      job.get("device_name", ""),
        "firmware_version": job.get("firmware_version", ""),
        "architecture":     job.get("architecture", ""),
        "scan_date":        job.get("scan_date", ""),
        "risk_score":       job.get("risk_score", 0.0),
        "risk_label":       job.get("risk_label", ""),
        "compliance_score": job.get("compliance_score", 0.0),
        "compliance_grade": job.get("compliance_grade", ""),
        "controls_pass":    job.get("controls_pass", 0),
        "controls_fail":    job.get("controls_fail", 0),
        "controls_partial": job.get("controls_partial", 0),
        "controls_unknown": job.get("controls_unknown", 0),
        "controls_total":   job.get("controls_total", 0),
        "total_cves":       job.get("total_cves", 0),
        "critical_cves":    job.get("critical_cves", 0),
        "affected_count":   job.get("affected_count", 0),
        "sbom_count":       job.get("sbom_count", 0),
        "cbom_count":       job.get("cbom_count", 0),
        "insecure_crypto":  job.get("insecure_crypto", 0),
        "top_risks":        job.get("top_risks", []),
        "pdf_ready":        bool(job.get("pdf_path")),
    }


@router.get("/{job_id}/controls")
async def get_controls(
    job_id: str,
    standard: Optional[str] = None,
    status:   Optional[str] = None,
):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")

    controls = job.get("control_results", [])
    if standard:
        controls = [c for c in controls if c.get("standard") == standard]
    if status:
        controls = [c for c in controls if c.get("status") == status]

    return {"job_id": job_id, "total": len(controls), "controls": controls}


@router.get("/{job_id}/download/pdf")
async def download_pdf(job_id: str):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    pdf_path = job.get("pdf_path", "")
    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(404, "PDF not ready yet — re-check status")
    device  = (job.get("device_name","device") or "device").replace(" ", "_")[:20]
    date    = (job.get("scan_date","") or "")[:10].replace("-","")
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"IIFVDCAS_Report_{device}_{date}.pdf",
    )


@router.get("/{job_id}/download/json")
async def download_json(job_id: str):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    json_path = job.get("json_path", "")
    if not json_path or not Path(json_path).exists():
        raise HTTPException(404, "JSON report not ready yet")
    device = (job.get("device_name","device") or "device").replace(" ", "_")[:20]
    return FileResponse(
        json_path,
        media_type="application/json",
        filename=f"IIFVDCAS_Report_{device}.json",
    )


@router.get("/{job_id}")
async def get_full_report(job_id: str):
    job = compliance_jobs.get(job_id)
    if not job:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    return job


@router.delete("/{job_id}")
async def delete_job(job_id: str):
    if job_id not in compliance_jobs:
        raise HTTPException(404, f"Compliance job not found: {job_id}")
    del compliance_jobs[job_id]
    return {"deleted": job_id}
