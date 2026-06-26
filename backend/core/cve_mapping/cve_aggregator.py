"""
CVE Aggregator — Phase 5 orchestrator.

Data source priority (fastest first):
  1. Local SQLite NVD index (~5ms/lookup, 186k CVEs, CPE-matched)
  2. OSV batch API         (~1 HTTP call for all remaining packages)
  3. NVD REST API          (per-component fallback for anything still missing)

All SQLite lookups run in a single executor thread to keep the connection warm.
"""
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from .nvd_lookup import (
    lookup_cve_by_cpe, lookup_cve_by_product,
    lookup_osv_batch, get_epss_from_db,
    _get_conn, DB_PATH,
)
from .epss_scorer import get_epss_score
from .kev_checker import is_kev

logger = logging.getLogger(__name__)

# ─── Skip lists ───────────────────────────────────────────────────────────────

# Security markers — go to SBOM/P3 findings but never to NVD lookup
_SECURITY_MARKERS: Set[str] = {
    "debug-uart", "secure-boot-off", "sig-verify-off",
    "cert-pin-off", "custom-avr-firmware",
}

# Firmware identity strings — skip NVD product lookup (too generic = false positives)
_FIRMWARE_ID_SOURCES = {"avr-firmware-id"}

# Hardware-only components — sensors/chips with no software CVEs in NVD.
# Skipping NVD/REST API calls for these avoids 429 rate-limit errors.
# They appear in HBOM and are triaged separately in Phase 6 (hardware CVEs).
_HARDWARE_NO_CVE: Set[str] = {
    "nrf24l01", "mpu-6050", "mpu6050", "at24c", "at24c32",
    "enc28j60", "w5100", "bme280", "ds18b20", "cc2500",
    "atmega328p", "atmega2560", "attiny85",
}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class CVEFinding:
    cve_id:        str
    component:     str
    version:       str
    cpe:           str
    cvss_score:    Optional[float]
    cvss_severity: Optional[str]
    cvss_vector:   Optional[str]
    epss_score:    float
    is_kev:        bool
    cwe_ids:       List[str]
    published:     str
    description:   str
    source:        str = "NVD-local"
    exploitdb_id:  Optional[str] = None


@dataclass
class CVEResult:
    job_id:         str
    sbom_job_id:    str
    total_cves:     int
    critical_count: int
    high_count:     int
    medium_count:   int
    low_count:      int
    kev_count:      int
    findings:       List[CVEFinding]
    top_10:         List[CVEFinding]
    generated_at:   str
    error:          Optional[str] = None


def _count_sev(findings: List[CVEFinding], sev: str) -> int:
    return sum(1 for f in findings if (f.cvss_severity or "").upper() == sev)


def _empty(job_id: str, sbom_job_id: str, error: str = "") -> CVEResult:
    return CVEResult(
        job_id=job_id, sbom_job_id=sbom_job_id,
        total_cves=0, critical_count=0, high_count=0,
        medium_count=0, low_count=0, kev_count=0,
        findings=[], top_10=[],
        generated_at=datetime.now(timezone.utc).isoformat(),
        error=error,
    )


# ─── SBOM loader ──────────────────────────────────────────────────────────────

def _load_components(sbom_job_id: str) -> List[Dict]:
    try:
        from core.sbom.routes import SBOM_JOBS
        comps = (SBOM_JOBS.get(sbom_job_id) or {}).get("sbom") or []
        if comps:
            logger.info(f"[CVE] {len(comps)} components from memory")
            return comps
    except Exception as e:
        logger.debug(f"[CVE] memory lookup: {e}")

    base = Path(f"/tmp/iifvdcas_sbom/{sbom_job_id}")
    for name in ("cyclonedx_sbom.json", "sbom.json", "components.json", "bom.json"):
        fp = base / name
        if not fp.exists():
            continue
        try:
            data  = json.loads(fp.read_text())
            comps = data.get("components") or data.get("sbom_components") or []
            if comps:
                logger.info(f"[CVE] {len(comps)} components from {fp.name}")
                return comps
        except Exception as e:
            logger.warning(f"[CVE] parse {fp}: {e}")

    logger.error(f"[CVE] no SBOM data for job {sbom_job_id}")
    return []


# ─── Finding builder ──────────────────────────────────────────────────────────

def _make_finding(raw: Dict, name: str, version: str, cpe: str) -> CVEFinding:
    cve_id = raw.get("cve_id", "")
    return CVEFinding(
        cve_id        = cve_id,
        component     = name,
        version       = version,
        cpe           = cpe,
        cvss_score    = raw.get("cvss_score"),
        cvss_severity = (raw.get("cvss_severity") or "UNKNOWN").upper(),
        cvss_vector   = raw.get("cvss_vector", ""),
        epss_score    = get_epss_score(cve_id),
        is_kev        = is_kev(cve_id),
        cwe_ids       = raw.get("cwe_ids", []),
        published     = raw.get("published", ""),
        description   = (raw.get("description") or "")[:300],
        source        = raw.get("source", "NVD-local"),
    )


def _is_real_package(comp: Dict) -> bool:
    """Return True only if this component should be looked up in NVD."""
    name   = (comp.get("name")        or "").lower().strip()
    source = (comp.get("source_path") or "").lower()
    vendor = (comp.get("vendor")      or "").strip()
    cpe    = (comp.get("cpe")         or "").strip()

    if name in _SECURITY_MARKERS:
        return False
    if name in _HARDWARE_NO_CVE:
        return False  # hardware sensors — no NVD software CVEs
    if source in _FIRMWARE_ID_SOURCES and not vendor and not cpe:
        return False
    if name in {"unknown", "firmware", "avr", "mcu", "device"}:
        return False
    return True


def _should_do_product_lookup(comp: Dict) -> bool:
    """Return True if a name-based NVD product lookup is appropriate."""
    vendor = (comp.get("vendor")      or "").strip()
    source = (comp.get("source_path") or "").lower()
    if source in _FIRMWARE_ID_SOURCES:
        return False
    return bool(vendor)


# ─── Core mapping (single thread) ────────────────────────────────────────────

def _map_all(
    components: List[Dict],
    emit:       Callable,
    job_id:     str,
) -> List[CVEFinding]:
    """Map all components to CVEs in one thread (warm SQLite connection)."""
    _get_conn()   # pre-warm

    findings: List[CVEFinding] = []
    seen_ids: Set[str]         = set()
    no_local: List[Dict]       = []

    real_comps = [c for c in components if _is_real_package(c)]
    total      = len(real_comps)
    skipped    = len(components) - total

    if skipped:
        logger.info(f"[CVE] Skipped {skipped} markers/hardware — mapping {total} packages")

    emit(10, f"Pass 1/2 — NVD local index ({total} packages)")

    for i, comp in enumerate(real_comps):
        name    = (comp.get("name")    or "").strip()
        version = (comp.get("version") or "").strip()
        cpe     = (comp.get("cpe")     or "").strip()
        vendor  = (comp.get("vendor")  or "").strip()

        pct = 10 + int(i / max(total, 1) * 55)
        emit(pct, f"[{i+1}/{total}] {name}")

        raw_cves: List[Dict] = []

        if cpe and cpe.startswith("cpe:"):
            raw_cves = lookup_cve_by_cpe(cpe)

        if not raw_cves and _should_do_product_lookup(comp):
            raw_cves = lookup_cve_by_product(name, version)

        if raw_cves:
            logger.info(f"[CVE] {name} → {len(raw_cves)} CVEs (NVD-local)")
            for r in raw_cves:
                cid = r.get("cve_id", "")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    findings.append(_make_finding(r, name, version, cpe))
        else:
            if vendor:
                no_local.append(comp)

    # ── Pass 2: OSV batch ─────────────────────────────────────────────────────
    if no_local:
        emit(67, f"Pass 2/2 — OSV API ({len(no_local)} packages not in NVD local)")
        try:
            osv_results = lookup_osv_batch(no_local)
            for comp_name, raw_list in osv_results.items():
                comp    = next((c for c in no_local if c.get("name") == comp_name), {})
                version = comp.get("version", "")
                cpe     = comp.get("cpe", "")
                for r in raw_list:
                    cid = r.get("cve_id", "")
                    if cid and cid not in seen_ids:
                        seen_ids.add(cid)
                        findings.append(_make_finding(r, comp_name, version, cpe))
                if raw_list:
                    logger.info(f"[CVE] {comp_name} → {len(raw_list)} CVEs (OSV)")
        except Exception as e:
            logger.warning(f"[CVE] OSV batch: {e}")
    else:
        emit(67, "Pass 2/2 — all packages covered by NVD local index")

    emit(92, f"Enriching {len(findings)} CVEs with EPSS + KEV…")
    return findings


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_cve_mapping(
    sbom_job_id:  str,
    job_id:       str,
    progress_cb:  Optional[Callable[[Dict[str, Any]], None]] = None,
    sbom_data:    Optional[Dict[str, Any]] = None,
) -> CVEResult:
    """Synchronous CVE mapping — called from the async route's thread pool."""

    def emit(pct: int, step: str):
        if progress_cb:
            progress_cb({"event": "progress", "job_id": job_id,
                         "percent": pct, "step": step})

    emit(2, "Initialising CVE mapping…")

    if not DB_PATH.exists():
        emit(3, "⚠️  NVD index missing — using OSV + REST API only (slower)")

    components = (
        sbom_data.get("components", []) if sbom_data is not None
        else _load_components(sbom_job_id)
    )

    if not components:
        msg = f"No SBOM components for job {sbom_job_id}"
        logger.warning(f"[CVE] {msg}")
        emit(100, f"⚠️  {msg}")
        return _empty(job_id, sbom_job_id, msg)

    emit(8, f"Loaded {len(components)} components")

    all_findings = _map_all(components, emit, job_id)

    all_findings.sort(key=lambda f: (
        not f.is_kev,
        -(f.cvss_score  or 0.0),
        -(f.epss_score  or 0.0),
    ))

    result = CVEResult(
        job_id         = job_id,
        sbom_job_id    = sbom_job_id,
        total_cves     = len(all_findings),
        critical_count = _count_sev(all_findings, "CRITICAL"),
        high_count     = _count_sev(all_findings, "HIGH"),
        medium_count   = _count_sev(all_findings, "MEDIUM"),
        low_count      = _count_sev(all_findings, "LOW"),
        kev_count      = sum(1 for f in all_findings if f.is_kev),
        findings       = all_findings,
        top_10         = all_findings[:10],
        generated_at   = datetime.now(timezone.utc).isoformat(),
    )

    emit(100,
         f"✅  {result.total_cves} CVEs | "
         f"{result.critical_count} CRITICAL | "
         f"{result.high_count} HIGH | "
         f"{result.kev_count} KEV")

    return result
