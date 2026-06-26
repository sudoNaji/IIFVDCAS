"""
EPSS scorer — queries SQLite DB only (built by build_nvd_index.py).
CSV fallback is disabled by default because loading 333k entries from
year-by-year CSV files takes ~20s and the DB already contains them all.
"""
from pathlib import Path
from typing import Dict
import logging

logger = logging.getLogger(__name__)

DB_PATH  = Path("/tmp/iifvdcas_nvd.db")
EPSS_DIR = Path.home() / "emba" / "external" / "EPSS-data" / "EPSS_CVE_data"

_csv_cache: Dict[str, float] = {}
_csv_loaded = False


def get_epss_score(cve_id: str) -> float:
    """Return EPSS score (0.0–1.0) for a CVE."""
    if not cve_id:
        return 0.0
    cve_id = cve_id.strip().upper()

    # ── SQLite DB (fast — already has 333k EPSS scores) ──────────────────
    if DB_PATH.exists():
        try:
            from core.cve_mapping.nvd_lookup import get_epss_from_db
            return get_epss_from_db(cve_id)
        except Exception:
            pass

    # ── CSV fallback only if DB missing ──────────────────────────────────
    _ensure_csv_loaded()
    return _csv_cache.get(cve_id, 0.0)


def _ensure_csv_loaded():
    """Load EPSS from CSV files — only called when SQLite DB is missing."""
    global _csv_loaded
    if _csv_loaded:
        return
    if not EPSS_DIR.exists():
        _csv_loaded = True
        return
    logger.info("EPSS DB not found — loading from CSV files (one-time, slow)…")
    total = 0
    for csv_file in sorted(EPSS_DIR.glob("CVE_*_EPSS.csv")):
        try:
            with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    sep   = ";" if ";" in line else ","
                    parts = line.split(sep)
                    if len(parts) < 2:
                        continue
                    cid = parts[0].strip().upper()
                    if not cid.startswith("CVE-"):
                        continue
                    try:
                        _csv_cache[cid] = float(parts[1])
                        total += 1
                    except ValueError:
                        pass
        except Exception as e:
            logger.warning(f"Failed to read {csv_file}: {e}")
    _csv_loaded = True
    logger.info(f"EPSS CSV loaded {total} scores")


def clear_cache():
    global _csv_cache, _csv_loaded
    _csv_cache.clear()
    _csv_loaded = False
