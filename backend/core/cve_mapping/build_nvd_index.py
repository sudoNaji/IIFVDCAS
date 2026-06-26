#!/usr/bin/env python3
"""
Build a SQLite index of the local NVD per-CVE JSON feed.
Run once: python3 build_nvd_index.py
Output:  /tmp/iifvdcas_nvd.db  (~50–80 MB)

Schema:
  cve(id, published, cvss_score, cvss_severity, cvss_vector, description, cwe_ids, path)
  cpe(product, vendor, cpe_str, version_start_inc, version_start_exc,
      version_end_inc, version_end_exc, cve_id)
  epss(cve_id, score)
"""
import json, sqlite3, sys, os, re
from pathlib import Path
from datetime import datetime

NVD_ROOT  = Path.home() / "emba" / "external" / "nvd-json-data-feeds"
EPSS_DIR  = Path.home() / "emba" / "external" / "EPSS-data" / "EPSS_CVE_data"
DB_PATH   = Path("/tmp/iifvdcas_nvd.db")
STATE_CSV = NVD_ROOT / "_state.csv"

def get_cve_path(cve_id: str) -> Path:
    # CVE-2024-12345 → CVE-2024/CVE-2024-123xx/CVE-2024-12345.json
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    if not m:
        return None
    year, num = m.group(1), m.group(2)
    padded = num.zfill(5)
    range_dir = padded[:-2] + "xx"
    return NVD_ROOT / f"CVE-{year}" / f"CVE-{year}-{range_dir}" / f"{cve_id}.json"

def iter_nodes(configurations):
    for cfg in (configurations or []):
        for node in cfg.get("nodes", []):
            yield node
            for child in node.get("children", []):
                yield child

def parse_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cd = entries[0].get("cvssData", {})
            return cd.get("baseScore"), cd.get("baseSeverity"), cd.get("vectorString")
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        cd = entries[0].get("cvssData", {})
        return cd.get("baseScore"), entries[0].get("baseSeverity") or cd.get("severity"), cd.get("vectorString")
    return None, None, None

def build():
    if not NVD_ROOT.exists():
        print(f"ERROR: NVD path not found: {NVD_ROOT}")
        sys.exit(1)

    print(f"Building NVD SQLite index → {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-64000")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cve (
            id           TEXT PRIMARY KEY,
            published    TEXT,
            cvss_score   REAL,
            cvss_severity TEXT,
            cvss_vector  TEXT,
            description  TEXT,
            cwe_ids      TEXT,
            path         TEXT
        );
        CREATE TABLE IF NOT EXISTS cpe (
            product       TEXT,
            vendor        TEXT,
            cpe_str       TEXT,
            ver_start_inc TEXT,
            ver_start_exc TEXT,
            ver_end_inc   TEXT,
            ver_end_exc   TEXT,
            cve_id        TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cpe_product ON cpe(product);
        CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe(vendor, product);
        CREATE TABLE IF NOT EXISTS epss (
            cve_id TEXT PRIMARY KEY,
            score  REAL
        );
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
    """)
    conn.commit()

    # Read all CVE IDs from state CSV (fast)
    cve_ids = []
    with open(STATE_CSV, "r") as f:
        for i, line in enumerate(f):
            if i == 0:
                continue
            cve_id = line.split(",")[0].strip()
            if cve_id.startswith("CVE-"):
                cve_ids.append(cve_id)

    total = len(cve_ids)
    print(f"Found {total} CVE IDs in _state.csv")

    cve_rows = []
    cpe_rows = []
    inserted = 0
    skipped  = 0

    for i, cve_id in enumerate(cve_ids):
        if i % 10000 == 0:
            pct = i * 100 // total
            print(f"  [{pct:3d}%] {i}/{total} processed, {inserted} indexed, {skipped} missing", flush=True)
            if cve_rows:
                conn.executemany(
                    "INSERT OR IGNORE INTO cve VALUES (?,?,?,?,?,?,?,?)", cve_rows)
                conn.executemany(
                    "INSERT INTO cpe VALUES (?,?,?,?,?,?,?,?)", cpe_rows)
                conn.commit()
                cve_rows.clear()
                cpe_rows.clear()

        path = get_cve_path(cve_id)
        if not path or not path.exists():
            skipped += 1
            continue

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except Exception:
            skipped += 1
            continue

        desc = next(
            (d["value"] for d in data.get("descriptions", []) if d.get("lang") == "en"), ""
        )[:512]

        score, severity, vector = parse_cvss(data.get("metrics", {}))

        cwes = "|".join(
            d["value"]
            for w in data.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-")
        )

        cve_rows.append((
            cve_id,
            data.get("published", "")[:10],
            score, severity, vector,
            desc, cwes,
            str(path),
        ))

        for node in iter_nodes(data.get("configurations", [])):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable", True):
                    continue
                crit   = cm.get("criteria", "")
                parts  = crit.split(":")
                if len(parts) < 5:
                    continue
                vendor  = parts[3].lower() if parts[3] not in ("*","-","") else ""
                product = parts[4].lower() if parts[4] not in ("*","-","") else ""
                if not product:
                    continue
                cpe_rows.append((
                    product, vendor, crit,
                    cm.get("versionStartIncluding", ""),
                    cm.get("versionStartExcluding", ""),
                    cm.get("versionEndIncluding", ""),
                    cm.get("versionEndExcluding", ""),
                    cve_id,
                ))

        inserted += 1

    # Final flush
    if cve_rows:
        conn.executemany("INSERT OR IGNORE INTO cve VALUES (?,?,?,?,?,?,?,?)", cve_rows)
        conn.executemany("INSERT INTO cpe VALUES (?,?,?,?,?,?,?,?)", cpe_rows)
        conn.commit()

    print(f"\nCVE rows indexed: {inserted}")

    # ── Load EPSS ─────────────────────────────────────────────────────────
    if EPSS_DIR.exists():
        print("Loading EPSS scores…")
        epss_rows = []
        for csv_file in sorted(EPSS_DIR.glob("CVE_*_EPSS.csv")):
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
                        epss_rows.append((cid, float(parts[1])))
                    except ValueError:
                        pass
            if len(epss_rows) > 50000:
                conn.executemany("INSERT OR REPLACE INTO epss VALUES (?,?)", epss_rows)
                conn.commit()
                epss_rows.clear()

        if epss_rows:
            conn.executemany("INSERT OR REPLACE INTO epss VALUES (?,?)", epss_rows)
            conn.commit()
        print(f"EPSS scores loaded")

    conn.execute("INSERT OR REPLACE INTO meta VALUES ('built_at', ?)",
                 (datetime.utcnow().isoformat(),))
    conn.execute("ANALYZE")
    conn.commit()
    conn.close()
    print(f"\nDone! DB at {DB_PATH}  size={DB_PATH.stat().st_size // 1024 // 1024} MB")

if __name__ == "__main__":
    build()
