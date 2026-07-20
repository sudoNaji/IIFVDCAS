"""
Phase 7 — Report Generator (orchestrator)

Pulls data from all previous phases, runs the gap checker,
builds the JSON report, and triggers the PDF builder.
"""

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .gap_checker import check_all_controls, compliance_score, ControlResult

logger = logging.getLogger(__name__)

OUTPUT_BASE = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/compliance")


@dataclass
class ComplianceReport:
    job_id:             str
    status:             str = "pending"
    started_at:         str = ""
    completed_at:       str = ""
    error:              str = ""

    # Meta
    device_name:        str   = ""
    firmware_version:   str   = ""
    architecture:       str   = ""
    scan_date:          str   = ""

    # Scores
    risk_score:         float = 0.0
    risk_label:         str   = ""
    compliance_score:   float = 0.0
    compliance_grade:   str   = ""

    # Counts
    total_cves:         int = 0
    critical_cves:      int = 0
    kev_count:          int = 0
    affected_count:     int = 0
    sbom_count:         int = 0
    hbom_count:         int = 0
    cbom_count:         int = 0
    insecure_crypto:    int = 0

    # Controls
    controls_pass:      int = 0
    controls_fail:      int = 0
    controls_partial:   int = 0
    controls_unknown:   int = 0
    controls_total:     int = 0

    # Full data
    control_results:    List[Dict] = field(default_factory=list)
    top_risks:          List[Dict] = field(default_factory=list)
    remediation_plan:   List[Dict] = field(default_factory=list)
    cbom_components:    List[Dict] = field(default_factory=list)
    cve_findings:       List[Dict] = field(default_factory=list)

    # Output paths
    pdf_path:           str = ""
    json_path:          str = ""

    log: List[str] = field(default_factory=list)


# ─── Data loaders ─────────────────────────────────────────────────────────────

def _load_vex(vex_job_id: str) -> Dict:
    try:
        from core.vex_engine.routes import vex_jobs
        return vex_jobs.get(vex_job_id, {})
    except Exception:
        return {}


def _load_cve(cve_job_id: str) -> Dict:
    try:
        from core.cve_mapping.routes import cve_mapping_jobs
        return cve_mapping_jobs.get(cve_job_id, {})
    except Exception:
        return {}


def _load_sbom(sbom_job_id: str) -> Dict:
    try:
        from core.sbom.routes import SBOM_JOBS
        job = SBOM_JOBS.get(sbom_job_id, {})
        if job:
            return job
    except Exception:
        pass
    # Disk fallback
    base = Path(f"/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/sbom/{sbom_job_id}")
    result = {}
    for fname, key in [("cyclonedx_sbom.json","sbom"),
                       ("hbom.json","hbom"), ("cbom.json","cbom")]:
        fp = base / fname
        if fp.exists():
            try:
                data = json.loads(fp.read_text())
                result[key] = data.get("components", [])
            except Exception:
                pass
    return result


def _load_static(analysis_job_id: str) -> Dict:
    try:
        from core.static_analysis.routes import analysis_jobs
        return analysis_jobs.get(analysis_job_id, {})
    except Exception:
        return {}


# ─── Main runner ──────────────────────────────────────────────────────────────

def run_compliance_report(
    vex_job_id:      str,
    cve_job_id:      str,
    sbom_job_id:     str,
    analysis_job_id: str,
    job_id:          str,
    device_info:     Dict           = None,
    progress_cb:     Optional[Callable] = None,
) -> ComplianceReport:
    """
    Synchronous compliance report generator — called from async route's thread pool.
    """
    def emit(pct: int, step: str):
        if progress_cb:
            progress_cb({"event": "progress", "job_id": job_id,
                         "percent": pct, "step": step})

    def log(msg: str):
        logger.info(msg)
        report.log.append(msg)

    report = ComplianceReport(
        job_id=job_id,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )

    output_dir = OUTPUT_BASE / job_id
    output_dir.mkdir(parents=True, exist_ok=True)

    emit(2, "Loading phase data…")

    # ── Load all phases ───────────────────────────────────────────────────────
    device_info  = device_info or {}
    vex_data     = _load_vex(vex_job_id)
    cve_data     = _load_cve(cve_job_id)
    sbom_data    = _load_sbom(sbom_job_id)
    static_data  = _load_static(analysis_job_id)

    log(f"[P7] VEX findings: {len(vex_data.get('triage_results',[]))}")
    log(f"[P7] CVE findings: {cve_data.get('total_cves',0)}")
    log(f"[P7] SBOM comps:   {len(sbom_data.get('sbom',[]))}")
    log(f"[P7] Static:       {static_data.get('risk_score','?')}/100")

    if not vex_data and not cve_data:
        report.status = "failed"
        report.error  = "No VEX or CVE data found. Run Phase 5 and Phase 6 first."
        emit(100, f"Failed: {report.error}")
        return report

    emit(12, "Extracting metadata…")

    # ── Populate report metadata ───────────────────────────────────────────────
    fw_context   = vex_data.get("firmware_context", {})
    toolchain    = sbom_data.get("toolchain", {})

    report.device_name      = (
        device_info.get("name") or
        toolchain.get("architecture", "Unknown Device")
    )
    report.firmware_version = device_info.get("version", "unknown")
    report.architecture     = (
        fw_context.get("architecture") or
        toolchain.get("architecture", "unknown")
    )
    report.risk_score       = vex_data.get("risk_score",   0.0)
    report.risk_label       = vex_data.get("risk_label",   "UNKNOWN")
    report.total_cves       = cve_data.get("total_cves",   0)
    report.critical_cves    = cve_data.get("critical_count", 0)
    report.kev_count        = cve_data.get("kev_count",    0)
    report.affected_count   = vex_data.get("affected_count", 0)

    sbom_comps              = sbom_data.get("sbom", sbom_data.get("sbom_components", []))
    hbom_comps              = sbom_data.get("hbom", sbom_data.get("hbom_components", []))
    cbom_comps              = sbom_data.get("cbom", sbom_data.get("cbom_components", []))
    report.sbom_count       = len(sbom_comps)
    report.hbom_count       = len(hbom_comps)
    report.cbom_count       = len(cbom_comps)
    report.insecure_crypto  = sum(
        1 for c in cbom_comps
        if c.get("strength") in ("insecure", "weak")
    )
    report.cbom_components  = list(cbom_comps)
    report.top_risks        = vex_data.get("top_risks", [])
    report.remediation_plan = vex_data.get("remediation_plan", [])

    # Merge CVE findings with VEX status for the PDF table
    triage_by_cve = {
        t.get("cve_id"): t.get("vex_status", "")
        for t in vex_data.get("triage_results", [])
    }
    report.cve_findings = []
    for f in (cve_data.get("findings", []) or [])[:200]:
        enriched = dict(f)
        enriched["vex_status"] = triage_by_cve.get(f.get("cve_id",""), "unknown")
        report.cve_findings.append(enriched)

    emit(25, "Running compliance gap checks…")

    # ── Compliance gap analysis ───────────────────────────────────────────────
    control_results: List[ControlResult] = check_all_controls(
        static_job  = static_data,
        sbom_job    = sbom_data,
        cve_job     = cve_data,
        vex_job     = vex_data,
        device_info = device_info,
    )

    report.compliance_score = compliance_score(control_results)
    report.compliance_grade = _grade(report.compliance_score)
    report.controls_pass    = sum(1 for r in control_results if r.status == "pass")
    report.controls_fail    = sum(1 for r in control_results if r.status == "fail")
    report.controls_partial = sum(1 for r in control_results if r.status == "partial")
    report.controls_unknown = sum(1 for r in control_results if r.status == "unknown")
    report.controls_total   = len(control_results)
    report.control_results  = [asdict(r) for r in control_results]

    log(f"[P7] Compliance score: {report.compliance_score}/100 ({report.compliance_grade})")
    log(f"[P7] Controls: PASS={report.controls_pass} FAIL={report.controls_fail} "
        f"PARTIAL={report.controls_partial} UNKNOWN={report.controls_unknown}")

    emit(55, f"Compliance: {report.compliance_score:.0f}/100 — writing JSON…")

    # ── JSON report ───────────────────────────────────────────────────────────
    json_path = str(output_dir / "compliance_report.json")
    try:
        report_dict = asdict(report)
        report_dict.pop("log", None)       # keep JSON lean
        Path(json_path).write_text(
            json.dumps(report_dict, indent=2, default=str)
        )
        report.json_path = json_path
        log(f"[P7] JSON written: {json_path}")
    except Exception as e:
        log(f"[P7] JSON write failed: {e}")

    emit(65, "Building PDF report…")

    # ── PDF report ────────────────────────────────────────────────────────────
    pdf_path = str(output_dir / "compliance_report.pdf")
    try:
        from .pdf_builder import build_pdf
        report_meta = {
            "device_name":      report.device_name,
            "firmware_version": report.firmware_version,
            "architecture":     report.architecture,
            "risk_score":       report.risk_score,
            "risk_label":       report.risk_label,
            "compliance_score": report.compliance_score,
            "compliance_grade": report.compliance_grade,
            "total_cves":       report.total_cves,
            "critical_cves":    report.critical_cves,
            "affected_count":   report.affected_count,
            "sbom_count":       report.sbom_count,
            "generated_at":     report.scan_date,
        }
        build_pdf(
            output_path        = pdf_path,
            report_meta        = report_meta,
            top_risks          = report.top_risks,
            cve_findings       = report.cve_findings,
            compliance_results = control_results,
            cbom_comps         = cbom_comps,
            remediation_plan   = report.remediation_plan,
        )
        report.pdf_path = pdf_path
        log(f"[P7] PDF written: {pdf_path}")
    except Exception as e:
        log(f"[P7] PDF build failed: {e}")
        logger.exception("PDF build error")

    emit(95, "Finalising…")

    report.status       = "success"
    report.completed_at = datetime.now(timezone.utc).isoformat()

    emit(100,
         f"Done — score {report.compliance_score:.0f}/100 ({report.compliance_grade}) "
         f"| PDF ready")
    return report


def _grade(score: float) -> str:
    if score >= 85: return "A"
    if score >= 70: return "B"
    if score >= 55: return "C"
    if score >= 40: return "D"
    return "F"
