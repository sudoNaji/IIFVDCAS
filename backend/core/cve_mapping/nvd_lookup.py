"""
NVD lookup — Phase 5 CVE data source layer.

Priority order (fastest first):
  1. Local SQLite index  (~5ms/lookup when built, 186k CVEs, 3.1M CPE rows)
  2. NVD REST API v2     (fallback when DB is building or missing)
  3. OSV batch API       (supplement for packages NVD misses)
"""
import re
import sqlite3
import threading
import requests
from pathlib import Path
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

DB_PATH     = Path("/mnt/d/Uni Work/FYP 2 IOT/IIFVDCAS-main/IIFVDCAS-main/data/nvd.db")
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BATCH   = "https://api.osv.dev/v1/querybatch"

_local = threading.local()
_MMAP  = 1 * 1024 * 1024 * 1024   # 1 GB
_db_ready: Optional[bool] = None   # None=unchecked, True=ready, False=empty/building


# ─── SQLite connection ────────────────────────────────────────────────────────

def _check_db_ready() -> bool:
    """Return True only if DB file exists AND has the cpe table with data."""
    global _db_ready
    if _db_ready is True:
        return True
    if not DB_PATH.exists():
        _db_ready = False
        return False
    try:
        c = sqlite3.connect(str(DB_PATH), timeout=3)
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        if "cpe" not in tables or "cve" not in tables:
            c.close()
            logger.warning("[NVD] DB exists but tables not ready yet — using REST API fallback")
            _db_ready = False
            return False
        count = c.execute("SELECT count(*) FROM cpe").fetchone()[0]
        c.close()
        if count < 1000:
            logger.warning(f"[NVD] DB has only {count} CPE rows — still building, using REST API")
            _db_ready = False
            return False
        _db_ready = True
        logger.info(f"[NVD] DB ready with {count} CPE rows")
        return True
    except Exception as e:
        logger.warning(f"[NVD] DB check failed: {e}")
        _db_ready = False
        return False


def _get_conn() -> Optional[sqlite3.Connection]:
    """Return a per-thread SQLite connection. Returns None if DB not ready."""
    # Re-check every call so we switch to SQLite as soon as build finishes
    global _db_ready
    if _db_ready is False:
        # Re-probe every ~50 calls in case build just finished
        if not hasattr(_local, "_miss_count"):
            _local._miss_count = 0
        _local._miss_count += 1
        if _local._miss_count % 50 != 1:
            return None
        _db_ready = None  # force re-check

    if not _check_db_ready():
        return None

    conn = getattr(_local, "conn", None)
    if conn is not None:
        return conn
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA mmap_size={_MMAP}")
        conn.execute("PRAGMA cache_size=-65536")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("SELECT count(*) FROM cpe WHERE product='openssl'").fetchone()
        _local.conn = conn
        logger.info(f"[NVD] SQLite connected ({DB_PATH.stat().st_size//1024//1024} MB)")
        return conn
    except Exception as e:
        logger.error(f"[NVD] connect failed: {e}")
        _db_ready = False
        return None


# ─── Version helpers ──────────────────────────────────────────────────────────

def _parse_ver(v: str) -> tuple:
    if not v:
        return ()
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", v) if x.isdigit())
    except Exception:
        return ()


def _version_in_range(version: str, row) -> bool:
    vsi = row["ver_start_inc"] or ""
    vse = row["ver_start_exc"] or ""
    vei = row["ver_end_inc"]   or ""
    vee = row["ver_end_exc"]   or ""

    if not any([vsi, vse, vei, vee]):
        crit    = row["cpe_str"] or ""
        parts   = crit.split(":")
        cpe_ver = parts[5] if len(parts) > 5 else "*"
        if cpe_ver in ("*", "-", ""):
            return True
        return (not version) or (version == cpe_ver)

    if not version:
        return True

    v = _parse_ver(version)
    if vsi  and v < _parse_ver(vsi):  return False
    if vse  and v <= _parse_ver(vse): return False
    if vei  and v > _parse_ver(vei):  return False
    if vee  and v >= _parse_ver(vee): return False
    return True


def _row_to_dict(row) -> Dict:
    return {
        "cve_id":        row["id"],
        "description":   row["description"] or "",
        "cvss_score":    row["cvss_score"],
        "cvss_severity": (row["cvss_severity"] or "UNKNOWN").upper(),
        "cvss_vector":   row["cvss_vector"]   or "",
        "cwe_ids":       [x for x in (row["cwe_ids"] or "").split("|") if x],
        "published":     row["published"]     or "",
        "source":        "NVD-local",
    }


# ─── SQLite CPE lookup ────────────────────────────────────────────────────────

def _sqlite_lookup(product: str, vendor: str, version: str) -> List[Dict]:
    conn = _get_conn()
    if conn is None:
        return []
    try:
        seen = set(); results = []
        if vendor:
            rows = conn.execute(
                "SELECT c.*, v.* FROM cpe c JOIN cve v ON c.cve_id=v.id "
                "WHERE c.product=? AND c.vendor=? LIMIT 300",
                (product, vendor),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT c.*, v.* FROM cpe c JOIN cve v ON c.cve_id=v.id "
                "WHERE c.product=? LIMIT 300",
                (product,),
            ).fetchall()
        for row in rows:
            cid = row["id"]
            if cid in seen: continue
            if version and not _version_in_range(version, row): continue
            seen.add(cid); results.append(_row_to_dict(row))

        if not results and len(product) >= 4:
            rows = conn.execute(
                "SELECT c.*, v.* FROM cpe c JOIN cve v ON c.cve_id=v.id "
                "WHERE c.product LIKE ? LIMIT 100",
                (f"{product}%",),
            ).fetchall()
            for row in rows:
                cid = row["id"]
                if cid in seen: continue
                if version and not _version_in_range(version, row): continue
                seen.add(cid); results.append(_row_to_dict(row))
        return results
    except Exception as e:
        logger.error(f"[NVD-SQLite] {e}")
        return []


# ─── Public: CPE lookup ───────────────────────────────────────────────────────

def lookup_cve_by_cpe(cpe: str) -> List[Dict]:
    if not cpe or not cpe.startswith("cpe:"):
        return []
    parts   = cpe.split(":")
    if len(parts) < 5: return []
    vendor  = parts[3].lower() if parts[3] not in ("*","-","") else ""
    product = parts[4].lower() if parts[4] not in ("*","-","") else ""
    version = parts[5]         if len(parts) > 5 and parts[5] not in ("*","-","") else ""
    if not product: return []

    # Try SQLite first
    results = _sqlite_lookup(product, vendor, version)
    if results:
        logger.info(f"[NVD] CPE '{cpe}': {len(results)} CVEs (SQLite)")
        return results

    # Fall back to REST API
    return _nvd_api_by_cpe(cpe)


# ─── Public: product name lookup ─────────────────────────────────────────────

def lookup_cve_by_product(name: str, version: str) -> List[Dict]:
    if not name: return []
    product = name.lower().strip()

    results = _sqlite_lookup(product, "", version)
    if results:
        logger.info(f"[NVD] Product '{name}': {len(results)} CVEs (SQLite)")
        return results

    return _nvd_api_fallback(f"{name} {version}".strip())


# ─── NVD REST API — CPE-based (accurate) ─────────────────────────────────────

def _nvd_api_by_cpe(cpe: str) -> List[Dict]:
    """Query NVD API by exact CPE — most accurate fallback."""
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cpeName": cpe, "resultsPerPage": 100},
            timeout=15,
        )
        resp.raise_for_status()
        results = [_parse_nvd_api_vuln(v) for v in resp.json().get("vulnerabilities", [])]
        results = [r for r in results if r]
        logger.info(f"[NVD-API-CPE] '{cpe}': {len(results)} CVEs")
        return results
    except Exception as e:
        logger.warning(f"[NVD-API-CPE] '{cpe}': {e}")
        # Last resort: keyword search
        parts = cpe.split(":")
        if len(parts) >= 5:
            keyword = f"{parts[4]} {parts[5] if len(parts) > 5 else ''}".strip()
            return _nvd_api_fallback(keyword)
        return []


# ─── NVD REST API — keyword fallback ─────────────────────────────────────────

def _nvd_api_fallback(keyword: str) -> List[Dict]:
    if not keyword or keyword == "unknown":
        return []
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 50},
            timeout=15,
        )
        resp.raise_for_status()
        results = [_parse_nvd_api_vuln(v) for v in resp.json().get("vulnerabilities", [])]
        results = [r for r in results if r]
        logger.info(f"[NVD-API] '{keyword}': {len(results)} CVEs")
        return results
    except Exception as e:
        logger.warning(f"[NVD-API] '{keyword}': {e}")
        return []


def _parse_nvd_api_vuln(vuln: Dict) -> Optional[Dict]:
    d = vuln.get("cve", vuln)
    try:
        cve_id = d.get("id", "")
        desc   = next(
            (x["value"] for x in d.get("descriptions", []) if x.get("lang") == "en"), ""
        )
        metrics = d.get("metrics", {})
        score = sev = vec = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cd = entries[0].get("cvssData", {})
                score = cd.get("baseScore")
                sev   = cd.get("baseSeverity")
                vec   = cd.get("vectorString")
                break
        if not score:
            entries = metrics.get("cvssMetricV2", [])
            if entries:
                cd    = entries[0].get("cvssData", {})
                score = cd.get("baseScore")
                sev   = entries[0].get("baseSeverity") or cd.get("severity")
                vec   = cd.get("vectorString")
        cwes = [
            x["value"] for w in d.get("weaknesses", [])
            for x in w.get("description", [])
            if x.get("lang") == "en" and x.get("value", "").startswith("CWE-")
        ]
        return {
            "cve_id":        cve_id,
            "description":   desc[:300],
            "cvss_score":    score,
            "cvss_severity": (sev or "UNKNOWN").upper(),
            "cvss_vector":   vec or "",
            "cwe_ids":       cwes,
            "published":     d.get("published", "")[:10],
            "source":        "NVD-API",
        }
    except Exception:
        return None


# ─── OSV batch ────────────────────────────────────────────────────────────────

_OSV_ECOSYSTEMS = ["OSS-Fuzz", "Debian", "Alpine", "Ubuntu"]


def lookup_osv_batch(components: List[Dict]) -> Dict[str, List[Dict]]:
    """Batch-query OSV for components with osv_package/osv_ecosystem set."""
    queries = []
    index   = []

    for comp in components:
        name    = comp.get("name", "")
        version = comp.get("version", "") or ""
        osv_pkg = comp.get("osv_package")
        osv_eco = comp.get("osv_ecosystem")

        if osv_pkg and osv_eco:
            q: Dict = {"package": {"name": osv_pkg, "ecosystem": osv_eco}}
            if version and version not in ("unknown", "*"):
                q["version"] = version
            queries.append(q)
            index.append((name, osv_pkg, osv_eco, version))

    if not queries:
        return {}

    results: Dict[str, List[Dict]] = {}
    try:
        resp = requests.post(OSV_BATCH, json={"queries": queries}, timeout=20)
        resp.raise_for_status()
        for i, res in enumerate(resp.json().get("results", [])):
            if i >= len(index): break
            comp_name, pkg, eco, ver = index[i]
            vulns = res.get("vulns", [])
            if not vulns: continue
            parsed = [_parse_osv(v, comp_name) for v in vulns]
            parsed = [p for p in parsed if p]
            if parsed:
                results.setdefault(comp_name, []).extend(parsed)
        total = sum(len(v) for v in results.values())
        logger.info(f"[OSV] {total} CVEs across {len(results)} components")
    except Exception as e:
        logger.warning(f"[OSV] batch failed: {e}")
    return results


def _parse_osv(vuln: Dict, component: str) -> Optional[Dict]:
    try:
        vid     = vuln.get("id", "")
        summary = (vuln.get("summary") or vuln.get("details") or "")[:300]
        score   = sev = vec = None
        for s in vuln.get("severity", []):
            if "CVSS_V3" in s.get("type", ""):
                vec   = s.get("score", "")
                score, sev = _infer_score(vec)
                break
        db = vuln.get("database_specific", {})
        if score is None and isinstance(db.get("cvss"), dict):
            score = db["cvss"].get("score")
            sev   = _score_to_sev(score) if score else None
        return {
            "cve_id":        vid,
            "description":   summary,
            "cvss_score":    float(score) if score else None,
            "cvss_severity": (sev or "UNKNOWN").upper(),
            "cvss_vector":   vec or "",
            "cwe_ids":       [],
            "published":     vuln.get("published", "")[:10],
            "source":        "OSV",
        }
    except Exception:
        return None


def _infer_score(vec: str):
    v = (vec or "").upper()
    if "AV:N" in v and "AC:L" in v and "PR:N" in v:
        return 9.8, "CRITICAL"
    if "CRITICAL" in v: return 9.5, "CRITICAL"
    if "HIGH"     in v: return 7.5, "HIGH"
    if "MEDIUM"   in v: return 5.5, "MEDIUM"
    if "LOW"      in v: return 2.5, "LOW"
    return None, None


def _score_to_sev(score) -> str:
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL"
        if s >= 7.0: return "HIGH"
        if s >= 4.0: return "MEDIUM"
        return "LOW"
    except Exception:
        return "UNKNOWN"


# ─── EPSS ────────────────────────────────────────────────────────────────────

def get_epss_from_db(cve_id: str) -> float:
    conn = _get_conn()
    if conn is None:
        return 0.0
    try:
        row = conn.execute(
            "SELECT score FROM epss WHERE cve_id=?", (cve_id.upper(),)
        ).fetchone()
        return float(row["score"]) if row else 0.0
    except Exception:
        return 0.0


def clear_cache():
    global _db_ready
    _db_ready = None
    conn = getattr(_local, "conn", None)
    if conn:
        try: conn.close()
        except Exception: pass
    _local.conn = None
    if hasattr(_local, "_miss_count"):
        _local._miss_count = 0
