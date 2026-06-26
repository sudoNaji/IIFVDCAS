"""
IIFVDCAS — Phase 3 API Routes: Static Analysis
"""
import asyncio, hashlib, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from core.static_analysis.analyzer import (
    run_static_analysis, StaticAnalysisResult, asdict
)

router = APIRouter(prefix="/api/v1/analysis", tags=["static_analysis"])
analysis_jobs: dict[str, dict] = {}


def _make_job_id(target: str) -> str:
    return hashlib.md5(
        f"{target}-{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:12]


@router.post("/start")
async def start_analysis(body: dict, background_tasks: BackgroundTasks):
    from core.firmware_extraction.extractor import EXTRACT_BASE

    target_dir = body.get("target_dir")
    extraction_job_id = body.get("extraction_job_id")

    if not target_dir and extraction_job_id:
        target_dir = str(EXTRACT_BASE / extraction_job_id)

    if not target_dir:
        raise HTTPException(400, "Provide 'target_dir' or 'extraction_job_id'")
    if not Path(target_dir).is_dir():
        raise HTTPException(404, f"Target directory not found: {target_dir}")

    job_id = _make_job_id(target_dir)
    analysis_jobs[job_id] = {
        "job_id": job_id, "status": "pending",
        "target_dir": target_dir,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "progress": 0,
    }

    background_tasks.add_task(_run_analysis_bg, target_dir, job_id)
    return {
        "job_id": job_id, "status": "started",
        "target_dir": target_dir,
        "message": "Static analysis started. Connect to /ws for live progress.",
    }


async def _run_analysis_bg(target_dir: str, job_id: str):
    """
    Run analysis in thread executor.
    Use loop.call_soon_threadsafe to safely send WS events from the worker thread
    — fixes 'RuntimeError: no running event loop' from asyncio.create_task inside thread.
    """
    from main import broadcast

    loop = asyncio.get_event_loop()

    def sync_cb(event: dict):
        """Called from worker thread — schedule coroutine safely on the event loop."""
        async def _emit():
            await broadcast({**event, "phase": "phase3"})
        loop.call_soon_threadsafe(asyncio.ensure_future, _emit())

    await broadcast({"event": "analysis_started", "job_id": job_id, "phase": "phase3"})

    result: StaticAnalysisResult = await loop.run_in_executor(
        None,
        lambda: run_static_analysis(target_dir, job_id, sync_cb),
    )

    result_dict = asdict(result)
    analysis_jobs[job_id] = result_dict

    await broadcast({
        "event": "analysis_complete",
        "job_id": job_id,
        "phase": "phase3",
        "status": result.status,
        "risk_score": result.risk_score,
        "risk_label": result.risk_label,
        "total_binaries": result.total_binaries,
        "total_weak_funcs": result.total_weak_funcs,
        "total_passwords": result.total_passwords,
        "total_expired_certs": result.total_expired_certs,
        "total_ssh_issues": result.total_ssh_issues,
        "total_embedded_findings": result.total_embedded_findings,
        "total_embedded_critical": result.total_embedded_critical,
        "total_avr_findings": result.total_avr_findings,
        "total_avr_critical": result.total_avr_critical,
        "result": result_dict,
    })


@router.get("/jobs")
async def list_jobs():
    return {
        "jobs": [
            {k: v for k, v in j.items()
             if k not in ("binary_protections","weak_functions","password_findings",
                          "cert_findings","script_findings","ssh_findings",
                          "embedded_string_findings","avr_findings","avr_disassembly","log")}
            for j in analysis_jobs.values()
        ]
    }


@router.get("/{job_id}")
async def get_result(job_id: str):
    if job_id not in analysis_jobs:
        raise HTTPException(404, "Analysis job not found")
    return analysis_jobs[job_id]


@router.get("/{job_id}/summary")
async def get_summary(job_id: str):
    if job_id not in analysis_jobs:
        raise HTTPException(404, "Analysis job not found")
    j = analysis_jobs[job_id]
    return {
        "job_id": job_id, "status": j.get("status"),
        "risk_score": j.get("risk_score", 0),
        "risk_label": j.get("risk_label", "unknown"),
        "total_binaries": j.get("total_binaries", 0),
        "binaries_no_nx": j.get("binaries_no_nx", 0),
        "binaries_no_pie": j.get("binaries_no_pie", 0),
        "binaries_no_canary": j.get("binaries_no_canary", 0),
        "total_weak_funcs": j.get("total_weak_funcs", 0),
        "total_passwords": j.get("total_passwords", 0),
        "total_expired_certs": j.get("total_expired_certs", 0),
        "total_script_issues": j.get("total_script_issues", 0),
        "total_ssh_issues": j.get("total_ssh_issues", 0),
        "total_embedded_findings": j.get("total_embedded_findings", 0),
        "total_embedded_critical": j.get("total_embedded_critical", 0),
        "total_avr_findings": j.get("total_avr_findings", 0),
        "total_avr_critical": j.get("total_avr_critical", 0),
    }


@router.get("/{job_id}/binaries")
async def get_binaries(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"binaries": analysis_jobs[job_id].get("binary_protections", [])}


@router.get("/{job_id}/weak-functions")
async def get_weak_functions(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"weak_functions": analysis_jobs[job_id].get("weak_functions", [])}


@router.get("/{job_id}/passwords")
async def get_passwords(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"password_findings": analysis_jobs[job_id].get("password_findings", [])}


@router.get("/{job_id}/certs")
async def get_certs(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"cert_findings": analysis_jobs[job_id].get("cert_findings", [])}


@router.get("/{job_id}/ssh")
async def get_ssh(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"ssh_findings": analysis_jobs[job_id].get("ssh_findings", [])}

@router.get("/{job_id}/embedded")
async def get_embedded_findings(job_id: str):
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    return {"embedded_string_findings": analysis_jobs[job_id].get("embedded_string_findings", [])}

@router.get("/{job_id}/avr")
async def get_avr_analysis(job_id: str):
    """Get AVR disassembly and security findings for a job."""
    if job_id not in analysis_jobs: raise HTTPException(404, "Job not found")
    j = analysis_jobs[job_id]
    return {
        "avr_findings": j.get("avr_findings", []),
        "avr_disassembly": j.get("avr_disassembly", {}),
        "total_avr_findings": j.get("total_avr_findings", 0),
        "total_avr_critical": j.get("total_avr_critical", 0),
    }
