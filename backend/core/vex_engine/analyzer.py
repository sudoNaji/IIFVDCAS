"""
VEX Analyzer — Phase 6 main orchestrator.

Consumes Phase 4 (SBOM/HBOM/CBOM) + Phase 5 (CVE findings) + Phase 3 (static analysis)
and produces:
  - Per-CVE VEX triage results
  - Aggregate firmware risk score
  - CycloneDX 1.5 VEX document
  - Prioritised remediation plan
"""

import json
import logging
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .triage_engine import (
    FirmwareContext, TriageResult, triage_cve,
    AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION,
)
from .risk_scorer import RiskScore, calculate_risk_score
from .vex_document import generate_cyclonedx_vex

logger = logging.getLogger(__name__)


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class VEXResult:
    job_id:             str
    cve_job_id:         str
    sbom_job_id:        str
    status:             str           # running / success / failed
    started_at:         str
    completed_at:       str = ""
    error:              str = ""

    # Counts
    total_cves_input:   int = 0
    affected_count:     int = 0
    not_affected_count: int = 0
    fixed_count:        int = 0
    under_inv_count:    int = 0

    # Risk score
    risk_score:         float = 0.0
    risk_label:         str   = "MINIMAL"

    # Full triage list (serialised dicts)
    triage_results:     List[Dict] = field(default_factory=list)

    # Top 5 most critical findings
    top_risks:          List[Dict] = field(default_factory=list)

    # Remediation plan
    remediation_plan:   List[Dict] = field(default_factory=list)

    # CycloneDX VEX document path
    vex_doc_path:       str  = ""

    # Firmware context used for triage
    firmware_context:   Dict = field(default_factory=dict)

    # Per-component summary
    component_summary:  List[Dict] = field(default_factory=list)

    log: List[str] = field(default_factory=list)


# ─── Data loaders ─────────────────────────────────────────────────────────────

def _load_cve_findings(cve_job_id: str) -> List[Dict]:
    """Load CVE findings from Phase 5 in-memory store or disk."""
    try:
        from core.cve_mapping.routes import cve_mapping_jobs
        job = cve_mapping_jobs.get(cve_job_id, {})
        findings = job.get("findings", [])
        if findings:
            logger.info(f"[VEX] {len(findings)} CVE findings from memory")
            return findings
    except Exception as e:
        logger.debug(f"[VEX] memory CVE load: {e}")
    return []


def _load_sbom_data(sbom_job_id: str) -> Dict:
    """Load SBOM/HBOM/CBOM from Phase 4 in-memory store or disk."""
    try:
        from core.sbom.routes import SBOM_JOBS
        job = SBOM_JOBS.get(sbom_job_id, {})
        if job:
            return job
    except Exception as e:
        logger.debug(f"[VEX] memory SBOM load: {e}")

    # Disk fallback
    base = Path(f"/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/sbom/{sbom_job_id}")
    result = {}
    for name, key in [
        ("cyclonedx_sbom.json", "sbom"),
        ("hbom.json",           "hbom"),
        ("cbom.json",           "cbom"),
    ]:
        fp = base / name
        if fp.exists():
            try:
                data = json.loads(fp.read_text())
                result[key] = data.get("components", [])
            except Exception:
                pass
    return result


def _load_static_findings(analysis_job_id: str) -> List[Dict]:
    """Load Phase 3 static analysis findings."""
    try:
        from core.static_analysis.routes import analysis_jobs
        job = analysis_jobs.get(analysis_job_id, {})
        findings = []
        findings.extend(job.get("embedded_findings", []))
        findings.extend(job.get("avr_findings",      []))
        findings.extend(job.get("password_findings",  []))
        return findings
    except Exception as e:
        logger.debug(f"[VEX] static findings load: {e}")
    return []


# ─── Firmware context builder ─────────────────────────────────────────────────

def _build_firmware_context(
    sbom_data:      Dict,
    static_findings: List[Dict],
    device_info:    Dict,
) -> FirmwareContext:
    toolchain = sbom_data.get("toolchain", {})
    arch = (
        toolchain.get("architecture")
        or device_info.get("architecture")
        or "unknown"
    )
    hbom  = sbom_data.get("hbom",  sbom_data.get("hbom_components",  []))
    cbom  = sbom_data.get("cbom",  sbom_data.get("cbom_components",  []))

    cbom_algos = [
        c.get("algorithm", "") for c in cbom
        if isinstance(c, dict)
    ]

    return FirmwareContext(
        architecture      = arch,
        has_os            = False,
        has_network_stack = False,
        cbom_algorithms   = cbom_algos,
        static_findings   = static_findings,
        hbom_components   = hbom,
        device_info       = device_info,
    )


# ─── Remediation plan builder ─────────────────────────────────────────────────

def _build_remediation_plan(triage_results: List[TriageResult]) -> List[Dict]:
    """
    Produce a prioritised, de-duplicated remediation plan.
    Groups by component and picks the worst CVE to drive priority.
    """
    # Group by component
    by_component: Dict[str, List[TriageResult]] = {}
    for r in triage_results:
        if r.vex_status not in (AFFECTED, UNDER_INVESTIGATION):
            continue
        by_component.setdefault(r.component, []).append(r)

    plan = []
    for component, results in by_component.items():
        # Worst CVE drives the priority
        worst = max(
            results,
            key=lambda r: (
                r.exploitability == "critical",
                r.exploitability == "high",
                r.confidence,
            ),
        )
        versions = list({r.version for r in results})
        cve_ids  = [r.cve_id for r in results]

        plan.append({
            "component":     component,
            "versions":      versions,
            "priority":      worst.exploitability.upper() if worst.exploitability != "none" else "LOW",
            "affected_cves": len(cve_ids),
            "cve_ids":       cve_ids[:10],
            "action":        worst.remediation,
            "confidence":    round(worst.confidence, 2),
        })

    # Sort by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    plan.sort(key=lambda p: priority_order.get(p["priority"], 4))
    return plan


# ─── Component summary ────────────────────────────────────────────────────────

def _build_component_summary(triage_results: List[TriageResult]) -> List[Dict]:
    by_comp: Dict[str, Dict] = {}
    for r in triage_results:
        if r.component not in by_comp:
            by_comp[r.component] = {
                "component": r.component,
                "version":   r.version,
                "total":     0,
                "affected":  0,
                "not_affected": 0,
                "fixed":     0,
                "under_inv": 0,
                "worst_cvss": "unknown",
            }
        c = by_comp[r.component]
        c["total"] += 1
        if r.vex_status == AFFECTED:
            c["affected"] += 1
            if c["worst_cvss"] == "unknown" or _expl_rank(r.exploitability) > _expl_rank(c["worst_cvss"]):
                c["worst_cvss"] = r.exploitability
        elif r.vex_status == NOT_AFFECTED:
            c["not_affected"] += 1
        elif r.vex_status == FIXED:
            c["fixed"] += 1
        else:
            c["under_inv"] += 1

    result = sorted(
        by_comp.values(),
        key=lambda c: (_expl_rank(c["worst_cvss"]), c["affected"]),
        reverse=True,
    )
    return result


def _expl_rank(e: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "unknown": 0}.get(e, 0)


# ─── Main runner ──────────────────────────────────────────────────────────────

def run_vex_analysis(
    cve_job_id:      str,
    sbom_job_id:     str,
    analysis_job_id: str,
    job_id:          str,
    device_info:     Dict                  = None,
    progress_cb:     Optional[Callable]    = None,
) -> VEXResult:
    """
    Synchronous VEX analysis — called from the async route's thread pool.
    """

    def emit(pct: int, step: str):
        if progress_cb:
            progress_cb({"event": "progress", "job_id": job_id,
                         "percent": pct, "step": step})

    def log(msg: str):
        logger.info(msg)
        result.log.append(msg)

    result = VEXResult(
        job_id=job_id,
        cve_job_id=cve_job_id,
        sbom_job_id=sbom_job_id,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    emit(2, "Loading Phase 4/5 data…")

    # ── Load inputs ───────────────────────────────────────────────────────────
    cve_findings     = _load_cve_findings(cve_job_id)
    sbom_data        = _load_sbom_data(sbom_job_id)
    static_findings  = _load_static_findings(analysis_job_id)
    device_info_dict = device_info or {}

    if not cve_findings:
        result.status = "no_findings"
        result.risk_label = "UNKNOWN"
        result.error = (
            "Phase 5 found no CVE matches. This is not evidence that the "
            "firmware has no vulnerabilities; identifiable component versions "
            "are required for VEX triage."
        )
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[VEX] {result.error}")
        emit(100, "No CVE findings to triage - assessment is inconclusive")
        return result

    log(f"[VEX] {len(cve_findings)} CVE findings loaded")
    log(f"[VEX] SBOM: {len(sbom_data.get('sbom', []))} components")
    log(f"[VEX] Static findings: {len(static_findings)}")

    result.total_cves_input = len(cve_findings)
    emit(10, f"Building firmware context ({len(cve_findings)} CVEs)…")

    # ── Build firmware context ─────────────────────────────────────────────────
    ctx = _build_firmware_context(sbom_data, static_findings, device_info_dict)
    result.firmware_context = {
        "architecture":      ctx.architecture,
        "is_avr":            ctx.is_avr,
        "is_bare_metal":     ctx.is_bare_metal,
        "has_network_stack": ctx.has_network_stack,
        "cbom_algorithms":   list(ctx.cbom_algorithms),
    }
    log(f"[VEX] Context: arch={ctx.architecture} is_avr={ctx.is_avr} "
        f"net={ctx.has_network_stack} cbom_algos={len(ctx.cbom_algorithms)}")
    emit(18, f"Context: {ctx.architecture} bare_metal={ctx.is_bare_metal}")

    # ── Triage each CVE ────────────────────────────────────────────────────────
    emit(22, f"Triaging {len(cve_findings)} CVEs…")
    triage_list: List[TriageResult] = []
    total = len(cve_findings)

    for i, finding in enumerate(cve_findings):
        pct = 22 + int(i / total * 55)
        emit(pct, f"[{i+1}/{total}] {finding.get('cve_id', '?')}")

        try:
            tr = triage_cve(
                cve_id      = finding.get("cve_id",        ""),
                component   = finding.get("component",     ""),
                version     = finding.get("version",       "unknown"),
                cpe         = finding.get("cpe",           ""),
                cvss_score  = finding.get("cvss_score"),
                cvss_vector = finding.get("cvss_vector",   ""),
                epss_score  = finding.get("epss_score",    0.0) or 0.0,
                is_kev      = bool(finding.get("is_kev",   False)),
                cwe_ids     = finding.get("cwe_ids",       []) or [],
                description = finding.get("description",   ""),
                ctx         = ctx,
            )
            triage_list.append(tr)
        except Exception as e:
            logger.warning(f"[VEX] triage failed for {finding.get('cve_id','?')}: {e}")

    log(f"[VEX] Triage complete: {len(triage_list)} results")
    emit(80, "Calculating risk score…")

    # ── Risk score ─────────────────────────────────────────────────────────────
    risk: RiskScore = calculate_risk_score(triage_list, total_cves=len(cve_findings))
    result.risk_score         = risk.score
    result.risk_label         = risk.label
    result.affected_count     = risk.affected_count
    result.not_affected_count = risk.not_affected_count
    result.fixed_count        = risk.fixed_count
    result.under_inv_count    = risk.under_inv_count
    result.top_risks          = risk.top_risks

    log(f"[VEX] Risk score: {risk.score}/100 ({risk.label})")
    log(f"[VEX] affected={risk.affected_count} "
        f"not_affected={risk.not_affected_count} "
        f"fixed={risk.fixed_count} "
        f"under_inv={risk.under_inv_count}")
    emit(87, f"Risk: {risk.score}/100 ({risk.label})")

    # ── Remediation plan ───────────────────────────────────────────────────────
    result.remediation_plan   = _build_remediation_plan(triage_list)
    result.component_summary  = _build_component_summary(triage_list)

    # ── Serialise triage results ───────────────────────────────────────────────
    result.triage_results = [asdict(r) for r in triage_list]

    emit(92, "Generating CycloneDX VEX document…")

    # ── CycloneDX VEX document ─────────────────────────────────────────────────
    output_dir = Path(f"/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/vex/{job_id}")
    output_dir.mkdir(parents=True, exist_ok=True)
    vex_path   = str(output_dir / "vex_document.json")

    fw_name    = (
        device_info_dict.get("name")
        or sbom_data.get("toolchain", {}).get("architecture", "")
        or "unknown-firmware"
    )
    fw_version = device_info_dict.get("version", "unknown")

    try:
        generate_cyclonedx_vex(
            triage_results   = triage_list,
            firmware_name    = fw_name,
            firmware_version = fw_version,
            job_id           = job_id,
            output_path      = vex_path,
        )
        result.vex_doc_path = vex_path
        log(f"[VEX] CycloneDX VEX document written: {vex_path}")
    except Exception as e:
        log(f"[VEX] VEX document write failed: {e}")

    result.status       = "success"
    result.completed_at = datetime.now(timezone.utc).isoformat()
    emit(100, f"VEX complete — {risk.score}/100 {risk.label} | "
              f"{risk.affected_count} affected / {risk.not_affected_count} not_affected")

    return result
