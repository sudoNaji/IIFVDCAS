"""
IIFVDCAS — Phase 3: Static Analysis Engine
Mirrors EMBA logic from:
  S12_binary_protection.sh   → checksec (RELRO, NX, PIE, canary, RPATH)
  S13_weak_func_check.sh     → objdump/readelf weak C functions
  S20_shell_check.sh         → shellcheck on .sh scripts
  S45_pass_file_check.sh     → password/hash file scanning
  S60_cert_file_check.sh     → SSL certificate expiry
  S85_ssh_check.sh           → SSH key/config checks
  S107_deep_password_search  → regex-based password hash hunting
  S108_stacs                 → STACS credential pattern scan
"""

import subprocess, os, re, json, hashlib, logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# AVR module imported lazily inside run_static_analysis to avoid circular

# ─── Severity levels (matches EMBA colouring) ────────────────────────────────
CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

# ─── Weak C functions EMBA tracks (functions.cfg equivalent) ─────────────────
WEAK_FUNCTIONS = [
    "strcpy","strcat","sprintf","vsprintf","gets","scanf",
    "fscanf","sscanf","vfscanf","vsscanf","strtok","strtok_r",
    "system","popen","exec","execl","execle","execlp","execv",
    "execve","execvp","execvpe","__isoc99_scanf","__isoc99_sscanf",
    "memcpy","memmove","memset","strncpy","strncat","snprintf",
    "vsnprintf","getenv","putenv","setenv","unsetenv",
]

# ─── Password hash regexes (S107 password_regex.cfg equivalent) ──────────────
PW_HASH_PATTERNS = [
    r'\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}',      # MD5-crypt
    r'\$2[aby]\$[0-9]{2}\$[a-zA-Z0-9./]{53}',           # bcrypt
    r'\$5\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{43}',    # SHA-256-crypt
    r'\$6\$[a-zA-Z0-9./]{8,16}\$[a-zA-Z0-9./]{86}',    # SHA-512-crypt
    r'[a-zA-Z0-9+/]{86}==',                              # base64 ~64 byte key
    r'[0-9a-f]{32}',                                      # MD5 hex
    r'[0-9a-f]{40}',                                      # SHA1 hex
    r'[0-9a-f]{64}',                                      # SHA256 hex
]

# ─── SSH / private key patterns ───────────────────────────────────────────────
SSH_PRIVKEY_PATTERNS = [
    r'-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----',
    r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
    r'PuTTY-User-Key-File',
]

# ─── Certificate file extensions ─────────────────────────────────────────────
CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx"}


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class BinaryProtection:
    """S12 result for a single binary"""
    path: str
    relro: str = "No"        # No / Partial / Full
    canary: str = "No"       # No / Yes
    nx: str = "No"           # No / Yes
    pie: str = "No"          # No / PIE / DSO / REL
    rpath: str = "No"
    runpath: str = "No"
    symbols: str = "No"
    fortify: str = "No"
    risk_score: int = 0      # 0-10, higher = worse
    architecture: str = ""
    file_type: str = ""


@dataclass
class WeakFunction:
    """S13 result — weak/dangerous function usage"""
    binary: str
    function: str
    count: int
    severity: str = HIGH


@dataclass
class PasswordFinding:
    """S45/S107 result — password or hash found"""
    file_path: str
    finding_type: str     # hash | plaintext | shadow_entry | private_key
    value: str            # the actual hash/password (truncated for safety)
    line_number: int = 0
    severity: str = CRITICAL
    hash_type: str = ""   # md5 | sha1 | sha256 | bcrypt | sha512crypt | unknown


@dataclass
class CertFinding:
    """S60 result — certificate issue"""
    file_path: str
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    is_expired: bool = False
    days_until_expiry: int = 0
    severity: str = INFO


@dataclass
class ScriptFinding:
    """S20 result — shell/python/PHP script issue"""
    file_path: str
    tool: str             # shellcheck | bandit | semgrep
    issue_code: str
    message: str
    line: int = 0
    severity: str = MEDIUM


@dataclass
class SSHFinding:
    """S85 result — SSH key or config issue"""
    file_path: str
    finding_type: str     # private_key | weak_config | known_vuln
    detail: str
    severity: str = CRITICAL


@dataclass
class StaticAnalysisResult:
    """Complete Phase 3 result"""
    job_id: str
    target_dir: str
    started_at: str
    completed_at: str = ""
    status: str = "pending"   # pending|running|success|failed
    progress: int = 0

    # Module results
    binary_protections: list = field(default_factory=list)   # S12
    weak_functions: list = field(default_factory=list)        # S13
    password_findings: list = field(default_factory=list)     # S45/S107
    cert_findings: list = field(default_factory=list)         # S60
    script_findings: list = field(default_factory=list)       # S20
    ssh_findings: list = field(default_factory=list)
    embedded_string_findings: list = field(default_factory=list)   # S108
    avr_findings: list = field(default_factory=list)                  # AVR          # S85

    # Summary counts
    total_binaries: int = 0
    binaries_no_nx: int = 0
    binaries_no_pie: int = 0
    binaries_no_canary: int = 0
    total_weak_funcs: int = 0
    total_passwords: int = 0
    total_expired_certs: int = 0
    total_script_issues: int = 0
    total_ssh_issues: int = 0
    total_embedded_findings: int = 0
    total_embedded_critical: int = 0
    total_avr_findings: int = 0
    total_avr_critical: int = 0
    avr_disassembly: dict = field(default_factory=dict)

    # Risk score 0-100
    risk_score: int = 0
    risk_label: str = "unknown"

    log: list = field(default_factory=list)
    error: str = ""


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, cwd: str = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, env={**os.environ, "LANG": "C", "LC_ALL": "C"})
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        return "", str(e), -99


def _find_files(base_dir: str, extensions: set = None, names: list = None,
                is_elf: bool = False) -> list[str]:
    """Find files matching criteria in extracted firmware tree."""
    results = []
    base = Path(base_dir)
    for root, dirs, files in os.walk(base_dir):
        # Skip obvious non-firmware dirs
        for skip in [".git", "node_modules", "__pycache__"]:
            if skip in dirs:
                dirs.remove(skip)
        for fname in files:
            fp = Path(root) / fname
            if not fp.is_file() or fp.is_symlink():
                continue
            if extensions and fp.suffix.lower() not in extensions:
                continue
            if names and fname not in names:
                continue
            if is_elf:
                try:
                    with open(fp, "rb") as f:
                        magic = f.read(4)
                    if magic != b"\x7fELF":
                        continue
                except:
                    continue
            results.append(str(fp))
    return results


# ─── S12: Binary protection check (checksec) ─────────────────────────────────

def run_s12_binary_protection(target_dir: str, log_cb) -> list[BinaryProtection]:
    """
    Mirrors EMBA S12_binary_protection.sh.
    Runs checksec --format=csv on every ELF binary in the extracted tree.
    """
    log_cb("[S12] Starting binary protection check (checksec)")
    results = []

    if not os.path.isdir(target_dir):
        log_cb(f"[S12] Target dir not found: {target_dir}")
        return results

    # Find all ELF binaries
    elf_files = _find_files(target_dir, is_elf=True)
    log_cb(f"[S12] Found {len(elf_files)} ELF binaries to check")

    if not elf_files:
        log_cb("[S12] No ELF binaries found in extraction")
        return results

    for elf_path in elf_files[:200]:  # cap at 200 like EMBA's thread limit
        out, err, rc = _run(["checksec", "--format=csv", f"--file={elf_path}"], timeout=15)
        if not out or rc != 0:
            continue

        # Parse checksec CSV: RELRO,STACK CANARY,NX,PIE,RPATH,RUNPATH,Symbols,FORTIFY,Fortified,Fortifiable,FILE
        lines = [l for l in out.splitlines() if l and not l.startswith("RELRO")]
        for line in lines:
            parts = line.split(",")
            if len(parts) < 8:
                continue
            bp = BinaryProtection(
                path=str(Path(elf_path).relative_to(target_dir)),
                relro=parts[0].strip(),
                canary=parts[1].strip(),
                nx=parts[2].strip(),
                pie=parts[3].strip(),
                rpath=parts[4].strip(),
                runpath=parts[5].strip(),
                symbols=parts[6].strip() if len(parts) > 6 else "No",
                fortify=parts[7].strip() if len(parts) > 7 else "No",
            )
            # Risk scoring (mirrors EMBA's negative flags)
            score = 0
            if "No" in bp.relro:         score += 2
            if bp.canary == "No":        score += 2
            if bp.nx == "No":            score += 3
            if "No" in bp.pie:           score += 2
            if "Yes" in bp.rpath:        score += 1
            bp.risk_score = min(score, 10)

            # Get architecture from file command
            f_out, _, _ = _run(["file", "-b", elf_path], timeout=5)
            bp.file_type = f_out[:80]
            for arch in ["ARM", "MIPS", "x86-64", "80386", "PowerPC", "SPARC", "AVR"]:
                if arch.lower() in f_out.lower():
                    bp.architecture = arch
                    break

            results.append(bp)

    log_cb(f"[S12] Checked {len(results)} binaries")
    return results


# ─── S13: Weak function check (objdump) ──────────────────────────────────────

def run_s13_weak_func_check(target_dir: str, log_cb) -> list[WeakFunction]:
    """
    Mirrors EMBA S13_weak_func_check.sh.
    Uses objdump to find dangerous C function calls in ELF binaries.
    """
    log_cb("[S13] Starting weak function check (objdump)")
    results = []

    elf_files = _find_files(target_dir, is_elf=True)
    log_cb(f"[S13] Scanning {len(elf_files)} ELF binaries for weak functions")

    for elf_path in elf_files[:200]:
        try:
            out, _, rc = _run(["objdump", "-T", elf_path], timeout=20)
            if rc != 0:
                # Try readelf as fallback (EMBA does this for static binaries)
                out, _, rc = _run(["readelf", "-s", elf_path], timeout=20)

            for func in WEAK_FUNCTIONS:
                # Count occurrences (EMBA counts per-function per binary)
                pattern = r'\b' + re.escape(func) + r'\b'
                matches = re.findall(pattern, out)
                if matches:
                    count = len(matches)
                    sev = CRITICAL if func in ("gets", "system", "popen") else HIGH
                    results.append(WeakFunction(
                        binary=str(Path(elf_path).relative_to(target_dir)),
                        function=func,
                        count=count,
                        severity=sev,
                    ))
        except Exception as e:
            logger.debug(f"[S13] Error on {elf_path}: {e}")

    log_cb(f"[S13] Found {len(results)} weak function usages")
    return results


# ─── S20: Shell script check (shellcheck) ────────────────────────────────────

def run_s20_shell_check(target_dir: str, log_cb) -> list[ScriptFinding]:
    """
    Mirrors EMBA S20_shell_check.sh — runs shellcheck on .sh scripts.
    Also runs bandit on .py files.
    """
    log_cb("[S20] Starting script analysis (shellcheck + bandit)")
    results = []

    # Shell scripts
    sh_files = _find_files(target_dir, extensions={".sh", ".bash"})
    log_cb(f"[S20] Found {len(sh_files)} shell scripts")
    for sh in sh_files[:100]:
        out, err, rc = _run(
            ["shellcheck", "--format=json", "--severity=warning", sh], timeout=30
        )
        if out:
            try:
                issues = json.loads(out)
                for issue in issues:
                    results.append(ScriptFinding(
                        file_path=str(Path(sh).relative_to(target_dir)),
                        tool="shellcheck",
                        issue_code=f"SC{issue.get('code',0)}",
                        message=issue.get("message", ""),
                        line=issue.get("line", 0),
                        severity=_sc_level_to_severity(issue.get("level", "warning")),
                    ))
            except json.JSONDecodeError:
                pass

    # Python scripts
    py_files = _find_files(target_dir, extensions={".py"})
    log_cb(f"[S20] Found {len(py_files)} Python scripts")
    for py in py_files[:100]:
        out, err, rc = _run(
            ["bandit", "-f", "json", "-q", py], timeout=30
        )
        if out:
            try:
                data = json.loads(out)
                for issue in data.get("results", []):
                    results.append(ScriptFinding(
                        file_path=str(Path(py).relative_to(target_dir)),
                        tool="bandit",
                        issue_code=issue.get("test_id", ""),
                        message=issue.get("issue_text", ""),
                        line=issue.get("line_number", 0),
                        severity=_bandit_level_to_severity(issue.get("issue_severity", "LOW")),
                    ))
            except json.JSONDecodeError:
                pass

    log_cb(f"[S20] Found {len(results)} script issues")
    return results


def _sc_level_to_severity(level: str) -> str:
    return {"error": CRITICAL, "warning": HIGH, "info": INFO, "style": LOW}.get(level.lower(), MEDIUM)

def _bandit_level_to_severity(level: str) -> str:
    return {"HIGH": CRITICAL, "MEDIUM": HIGH, "LOW": MEDIUM}.get(level.upper(), INFO)


# ─── S45 + S107: Password / hash scanning ────────────────────────────────────

def run_s45_password_check(target_dir: str, log_cb) -> list[PasswordFinding]:
    """
    Mirrors EMBA S45_pass_file_check.sh + S107_deep_password_search.sh.
    Scans for:
      - /etc/passwd, /etc/shadow, /etc/shadow- entries with hashes
      - Private SSH/SSL keys
      - Hash patterns in any binary/text file
    """
    log_cb("[S45] Starting password & credential scan")
    results = []

    # ── Check passwd/shadow files ─────────────────────────────────────────────
    passwd_names = {"passwd", "shadow", "shadow-", "group", "gshadow", ".htpasswd"}
    for root, _, files in os.walk(target_dir):
        for fname in files:
            if fname.lower() not in passwd_names:
                continue
            fpath = Path(root) / fname
            if not fpath.is_file():
                continue
            rel = str(fpath.relative_to(target_dir))
            try:
                lines = fpath.read_text(errors="replace").splitlines()
                for i, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 2:
                        pw_field = parts[1]
                        if pw_field not in ("x", "*", "!", "!!", "", "NP", "LK"):
                            # Actual hash or plaintext
                            ht = _identify_hash_type(pw_field)
                            results.append(PasswordFinding(
                                file_path=rel,
                                finding_type="shadow_entry" if "shadow" in fname else "passwd_hash",
                                value=pw_field[:60] + ("..." if len(pw_field) > 60 else ""),
                                line_number=i,
                                severity=CRITICAL,
                                hash_type=ht,
                            ))
            except Exception as e:
                logger.debug(f"[S45] Error reading {fpath}: {e}")

    # ── SSH private key scan (S106 equivalent) ────────────────────────────────
    for root, _, files in os.walk(target_dir):
        for fname in files:
            fpath = Path(root) / fname
            if not fpath.is_file() or fpath.stat().st_size > 10 * 1024:
                continue
            try:
                content = fpath.read_text(errors="replace")
                for pattern in SSH_PRIVKEY_PATTERNS:
                    if re.search(pattern, content):
                        rel = str(fpath.relative_to(target_dir))
                        results.append(PasswordFinding(
                            file_path=rel,
                            finding_type="private_key",
                            value=f"Private key found: {fname}",
                            severity=CRITICAL,
                            hash_type="private_key",
                        ))
                        break
            except Exception:
                pass

    # ── Deep hash scan (S107) — grep all text files ───────────────────────────
    log_cb(f"[S107] Deep password hash scan starting...")
    combined_pattern = "|".join(PW_HASH_PATTERNS)
    all_files = list(Path(target_dir).rglob("*"))
    text_files = [f for f in all_files if f.is_file() and not f.is_symlink()
                  and f.stat().st_size < 512 * 1024]  # max 512KB per file

    deep_count = 0
    for fpath in text_files[:500]:  # cap like EMBA
        try:
            content = fpath.read_text(errors="replace")
            for i, line in enumerate(content.splitlines(), 1):
                if re.search(combined_pattern, line):
                    # Don't double-report already found passwd files
                    if fpath.name.lower() not in passwd_names:
                        rel = str(fpath.relative_to(target_dir))
                        match = re.search(combined_pattern, line)
                        val = match.group(0)[:60] if match else line[:60]
                        ht = _identify_hash_type(val)
                        results.append(PasswordFinding(
                            file_path=rel,
                            finding_type="hash",
                            value=val,
                            line_number=i,
                            severity=HIGH,
                            hash_type=ht,
                        ))
                        deep_count += 1
                        if deep_count > 100:  # cap total deep finds
                            break
        except Exception:
            pass
        if deep_count > 100:
            break

    log_cb(f"[S45/S107] Found {len(results)} password/credential findings")
    return results


def _identify_hash_type(value: str) -> str:
    if value.startswith("$1$"):  return "md5crypt"
    if value.startswith("$2"):   return "bcrypt"
    if value.startswith("$5$"):  return "sha256crypt"
    if value.startswith("$6$"):  return "sha512crypt"
    if value.startswith("$y$"):  return "yescrypt"
    if re.match(r'^[0-9a-f]{32}$', value, re.I): return "md5"
    if re.match(r'^[0-9a-f]{40}$', value, re.I): return "sha1"
    if re.match(r'^[0-9a-f]{64}$', value, re.I): return "sha256"
    if re.match(r'^[0-9a-f]{128}$',value, re.I): return "sha512"
    return "unknown"


# ─── S60: Certificate check (openssl) ────────────────────────────────────────

def run_s60_cert_check(target_dir: str, log_cb) -> list[CertFinding]:
    """
    Mirrors EMBA S60_cert_file_check.sh.
    Scans for SSL/TLS certificate files and checks expiry.
    """
    log_cb("[S60] Starting certificate check (openssl)")
    results = []
    now_ts = datetime.now(timezone.utc).timestamp()

    cert_files = _find_files(target_dir, extensions=CERT_EXTENSIONS)
    log_cb(f"[S60] Found {len(cert_files)} certificate files")

    for cert_path in cert_files[:100]:
        rel = str(Path(cert_path).relative_to(target_dir))
        # Try openssl x509
        out, err, rc = _run(
            ["openssl", "x509", "-noout", "-subject", "-issuer",
             "-startdate", "-enddate", "-in", cert_path], timeout=10
        )
        if rc != 0:
            # Try DER format
            out, err, rc = _run(
                ["openssl", "x509", "-noout", "-subject", "-issuer",
                 "-startdate", "-enddate", "-inform", "DER", "-in", cert_path], timeout=10
            )

        if rc != 0 or not out:
            continue

        cf = CertFinding(file_path=rel)
        for line in out.splitlines():
            if line.startswith("subject="):
                cf.subject = line.replace("subject=", "").strip()
            elif line.startswith("issuer="):
                cf.issuer = line.replace("issuer=", "").strip()
            elif line.startswith("notBefore="):
                cf.not_before = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                cf.not_after = line.replace("notAfter=", "").strip()
                # Parse expiry
                try:
                    from email.utils import parsedate_to_datetime
                    exp_dt = datetime.strptime(cf.not_after, "%b %d %H:%M:%S %Y %Z")
                    exp_ts = exp_dt.replace(tzinfo=timezone.utc).timestamp()
                    days_left = int((exp_ts - now_ts) / 86400)
                    cf.days_until_expiry = days_left
                    if days_left < 0:
                        cf.is_expired = True
                        cf.severity = CRITICAL
                    elif days_left < 30:
                        cf.severity = HIGH
                    elif days_left < 90:
                        cf.severity = MEDIUM
                    else:
                        cf.severity = INFO
                except Exception:
                    pass

        results.append(cf)

    log_cb(f"[S60] Checked {len(results)} certificates")
    return results


# ─── S85: SSH check ───────────────────────────────────────────────────────────

def run_s85_ssh_check(target_dir: str, log_cb) -> list[SSHFinding]:
    """
    Mirrors EMBA S85_ssh_check.sh.
    Looks for SSH private keys, weak SSH configs, and known vulnerabilities.
    """
    log_cb("[S85] Starting SSH/config check")
    results = []

    # Weak SSH config patterns
    WEAK_SSH_CONFIGS = [
        ("PermitRootLogin yes",          CRITICAL, "Root login via SSH permitted"),
        ("PasswordAuthentication yes",   HIGH,     "SSH password auth enabled"),
        ("PermitEmptyPasswords yes",     CRITICAL, "Empty passwords permitted via SSH"),
        ("Protocol 1",                   CRITICAL, "Insecure SSH Protocol v1"),
        ("StrictModes no",               HIGH,     "SSH StrictModes disabled"),
        ("UsePAM no",                    MEDIUM,   "PAM disabled for SSH"),
        ("AllowAgentForwarding yes",     MEDIUM,   "SSH agent forwarding enabled"),
        ("X11Forwarding yes",            LOW,      "X11 forwarding enabled"),
        ("RSAAuthentication yes",        MEDIUM,   "RSA auth (legacy)"),
    ]

    # Scan SSH config files
    ssh_config_names = {"sshd_config", "ssh_config", "authorized_keys", "known_hosts"}
    for root, _, files in os.walk(target_dir):
        for fname in files:
            fpath = Path(root) / fname
            if not fpath.is_file():
                continue
            rel = str(fpath.relative_to(target_dir))

            # Config file check
            if fname.lower() in ssh_config_names:
                try:
                    content = fpath.read_text(errors="replace")
                    for pattern, sev, desc in WEAK_SSH_CONFIGS:
                        if pattern.lower() in content.lower():
                            results.append(SSHFinding(
                                file_path=rel,
                                finding_type="weak_config",
                                detail=f"{desc} ({pattern})",
                                severity=sev,
                            ))
                except Exception:
                    pass

            # Private key files
            if fpath.stat().st_size < 16 * 1024:
                try:
                    content = fpath.read_text(errors="replace")
                    for pattern in SSH_PRIVKEY_PATTERNS:
                        if re.search(pattern, content):
                            results.append(SSHFinding(
                                file_path=rel,
                                finding_type="private_key",
                                detail=f"SSH/SSL private key found in: {fname}",
                                severity=CRITICAL,
                            ))
                            break
                except Exception:
                    pass

    log_cb(f"[S85] Found {len(results)} SSH findings")
    return results


# ─── Risk Score Calculator ────────────────────────────────────────────────────

def _calculate_risk_score(result: StaticAnalysisResult) -> tuple[int, str]:
    """
    Calculate overall firmware risk score (0-100).
    Mirrors EMBA's aggregation logic from F50_base_aggregator.sh.
    """
    score = 0

    # Binary protections (S12)
    if result.total_binaries > 0:
        nx_pct  = result.binaries_no_nx     / result.total_binaries
        pie_pct = result.binaries_no_pie    / result.total_binaries
        can_pct = result.binaries_no_canary / result.total_binaries
        score += int(nx_pct  * 20)
        score += int(pie_pct * 15)
        score += int(can_pct * 10)

    # Critical findings
    critical_pws = sum(1 for p in result.password_findings if p.get("severity") == CRITICAL)
    score += min(critical_pws * 5, 20)

    # Weak functions
    score += min(len(result.weak_functions) // 5, 15)

    # Expired certs
    score += min(result.total_expired_certs * 3, 10)

    # SSH critical issues
    ssh_critical = sum(1 for s in result.ssh_findings if s.get("severity") == CRITICAL)
    score += min(ssh_critical * 5, 10)

    # Embedded strings (S108) — hardcoded creds, backdoors
    emb_critical = sum(1 for e in result.embedded_string_findings if e.get("severity") == CRITICAL)
    emb_high     = sum(1 for e in result.embedded_string_findings if e.get("severity") == HIGH)
    score += min(emb_critical * 8, 25)
    score += min(emb_high * 3, 10)

    # AVR embedded firmware findings
    avr_critical = sum(1 for e in result.avr_findings if e.get("severity") == CRITICAL)
    avr_high     = sum(1 for e in result.avr_findings if e.get("severity") == HIGH)
    score += min(avr_critical * 8, 25)
    score += min(avr_high * 3, 10)

    score = min(score, 100)

    if score >= 70:   label = "critical"
    elif score >= 50: label = "high"
    elif score >= 30: label = "medium"
    elif score >= 10: label = "low"
    else:             label = "minimal"

    return score, label


# ─── Master runner ────────────────────────────────────────────────────────────

def run_static_analysis(
    target_dir: str,
    job_id: str,
    progress_callback=None,
) -> StaticAnalysisResult:
    """
    Master static analysis function.
    Runs all S-modules in sequence: S12 → S13 → S20 → S45/S107 → S60 → S85
    """
    def log(msg: str):
        logger.info(msg)
        result.log.append({"ts": datetime.now(timezone.utc).isoformat(), "msg": msg})
        if progress_callback:
            progress_callback({"event": "log", "job_id": job_id, "message": msg})

    def progress(pct: int, step: str):
        result.progress = pct
        if progress_callback:
            progress_callback({"event": "progress", "job_id": job_id,
                               "percent": pct, "step": step})

    result = StaticAnalysisResult(
        job_id=job_id,
        target_dir=target_dir,
        started_at=datetime.now(timezone.utc).isoformat(),
        status="running",
    )

    if not os.path.isdir(target_dir):
        result.status = "failed"
        result.error = f"Target directory not found: {target_dir}"
        return result

    try:
        # ── S12: Binary protection ────────────────────────────────────────
        progress(5, "S12: Checking binary protections")
        bps = run_s12_binary_protection(target_dir, log)
        result.binary_protections = [asdict(b) for b in bps]
        result.total_binaries    = len(bps)
        result.binaries_no_nx    = sum(1 for b in bps if b.nx == "No")
        result.binaries_no_pie   = sum(1 for b in bps if "No" in b.pie)
        result.binaries_no_canary= sum(1 for b in bps if b.canary == "No")
        progress(20, f"S12: Done — {len(bps)} binaries checked")

        # ── S13: Weak functions ───────────────────────────────────────────
        progress(22, "S13: Checking weak/dangerous functions")
        wfs = run_s13_weak_func_check(target_dir, log)
        result.weak_functions = [asdict(w) for w in wfs]
        result.total_weak_funcs = len(wfs)
        progress(38, f"S13: Done — {len(wfs)} weak function usages found")

        # ── S20: Script analysis ──────────────────────────────────────────
        progress(40, "S20: Checking shell/Python scripts")
        sfs = run_s20_shell_check(target_dir, log)
        result.script_findings = [asdict(s) for s in sfs]
        result.total_script_issues = len(sfs)
        progress(55, f"S20: Done — {len(sfs)} script issues")

        # ── S45 + S107: Password scan ─────────────────────────────────────
        progress(57, "S45/S107: Scanning for passwords and credentials")
        pfs = run_s45_password_check(target_dir, log)
        result.password_findings = [asdict(p) for p in pfs]
        result.total_passwords = len(pfs)
        progress(72, f"S45: Done — {len(pfs)} credential findings")

        # ── S60: Certificate check ────────────────────────────────────────
        progress(74, "S60: Checking SSL/TLS certificates")
        cfs = run_s60_cert_check(target_dir, log)
        result.cert_findings = [asdict(c) for c in cfs]
        result.total_expired_certs = sum(1 for c in cfs if c.is_expired)
        progress(86, f"S60: Done — {len(cfs)} certs, {result.total_expired_certs} expired")

        # ── S85: SSH check ────────────────────────────────────────────────
        progress(88, "S85: Checking SSH keys and configs")
        ssh = run_s85_ssh_check(target_dir, log)
        result.ssh_findings = [asdict(s) for s in ssh]
        result.total_ssh_issues = len(ssh)
        progress(90, f"S85: Done — {len(ssh)} SSH findings")

        # ── S108: Embedded binary string analysis (raw firmware/AVR/MCU) ────
        progress(92, "S108: Analyzing embedded firmware strings")
        esf = run_s108_embedded_string_analysis(target_dir, log)
        result.embedded_string_findings = [asdict(e) for e in esf]
        result.total_embedded_findings = len(esf)
        result.total_embedded_critical = sum(1 for e in esf if e.severity == CRITICAL)
        progress(94, f"S108: Done — {len(esf)} embedded findings "
                 f"({result.total_embedded_critical} critical)")

        # ── AVR Analysis: Detect and analyze AVR binaries ────────────────────
        progress(95, "AVR: Detecting and analyzing AVR firmware binaries")
        try:
            from core.static_analysis.avr_analyzer import (
                detect_avr_binaries, run_avr_analysis
            )
            avr_bins = detect_avr_binaries(target_dir)
            if avr_bins:
                log(f"[AVR] Found {len(avr_bins)} AVR binary(ies)")
                for avr_bin in avr_bins[:5]:  # Limit to 5 binaries to avoid timeout
                    log(f"[AVR] Analyzing: {Path(avr_bin).name}")
                    avr_result = run_avr_analysis(avr_bin, log)
                    # security_findings already converted to dicts in run_avr_analysis
                    result.avr_findings.extend(avr_result.security_findings)
                    # Store sample disassembly
                    if avr_result.disassembly:
                        result.avr_disassembly[Path(avr_bin).name] = avr_result.disassembly
                result.total_avr_findings = len(result.avr_findings)
                result.total_avr_critical = sum(1 for f in result.avr_findings
                                                if f.get("severity") == CRITICAL)
                log(f"[AVR] Analysis complete: {result.total_avr_findings} findings "
                    f"({result.total_avr_critical} critical)")
            else:
                log("[AVR] No AVR binaries detected in extracted firmware")
        except ImportError as ie:
            log(f"[AVR] Import error (avr_analyzer): {ie}")
        except Exception as ae:
            log(f"[AVR] Analysis error: {ae}")

        # ── Risk score ────────────────────────────────────────────────────
        progress(97, "Calculating risk score")
        result.risk_score, result.risk_label = _calculate_risk_score(result)
        log(f"[DONE] Risk score: {result.risk_score}/100 ({result.risk_label})")

        result.status = "success"
        result.completed_at = datetime.now(timezone.utc).isoformat()
        progress(100, "Static analysis complete")

    except Exception as e:
        logger.exception("Static analysis failed")
        result.status = "failed"
        result.error = str(e)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[ERROR] {e}")

    return result


# ─── S108: Embedded Binary String Analysis (AVR/MCU/IoT raw firmware) ────────
# Mirrors EMBA S107/S108 logic for non-Linux firmware (raw .bin files)
# Detects: hardcoded passwords, WiFi credentials, debug backdoors,
#          insecure URLs, private keys, debug menus, OTA without signature

EMBEDDED_CREDENTIAL_PATTERNS = [
    # Passwords / secrets
    (r'(?i)(password|passwd|pass|pwd|secret|key)\s*[=:]\s*["\']?([^\s"\',;]{4,})',
     CRITICAL, "hardcoded_password"),
    # WiFi credentials
    (r'(?i)(ssid|wifi_ssid|wifi_pass|wifi_password|wpa_psk)\s*[=:\"\']\s*([^\s"\',;]{2,})',
     CRITICAL, "wifi_credential"),
    # Bare password-like strings (SuperSecretPass pattern)
    (r'\b([A-Z][a-z]+[A-Z][a-zA-Z0-9!@#$%]{6,})\b',
     HIGH, "hardcoded_secret_candidate"),
    # IP addresses embedded in firmware
    (r'\b((?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3})\b',
     MEDIUM, "hardcoded_ip_address"),
    # HTTP (not HTTPS) update URLs
    (r'http://[^\s"\']{5,}',
     HIGH, "insecure_http_url"),
    # Tokens / API keys
    (r'(?i)(token|api_key|apikey|auth_token|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{8,})',
     CRITICAL, "hardcoded_token"),
    # Private key headers
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) PRIVATE KEY-----',
     CRITICAL, "embedded_private_key"),
    # Default/test credentials
    (r'(?i)(admin|root|test|guest|default)\s*[:/]\s*(admin|password|1234|test|root)',
     CRITICAL, "default_credential"),
]

EMBEDDED_BACKDOOR_PATTERNS = [
    (r'(?i)debug\s*(menu|mode|console|uart|enabled|active)',
     HIGH, "debug_interface_enabled"),
    (r'(?i)(dump|leak|print)\s*(wifi|cred|token|password|secret|config)',
     CRITICAL, "credential_dump_function"),
    (r'(?i)secure[\s_-]?boot\s*(disabled?|off|false|0)',
     CRITICAL, "secure_boot_disabled"),
    (r'(?i)signature\s*verif\w*\s*(disabled?|off|false|skip)',
     CRITICAL, "signature_verification_disabled"),
    (r'(?i)(ota|update|firmware)\s*(warning|skip|no.?verif)',
     HIGH, "ota_security_bypass"),
    (r'(?i)backdoor|killswitch|kill.switch|master.?pass',
     CRITICAL, "backdoor_indicator"),
    (r'(?i)(uart|serial|console)\s*(debug|enabled|active|open)',
     MEDIUM, "debug_console_active"),
]

INSECURE_PROTOCOL_PATTERNS = [
    (r'(?i)telnet://[^\s]+',         HIGH,   "telnet_url"),
    (r'(?i)ftp://[^\s]+',            MEDIUM, "ftp_url"),
    (r'(?i)mqtt://[^\s]+',           MEDIUM, "unencrypted_mqtt"),
    (r'(?i)(TLS|SSL)\s*(disabled?|off|none|skip)',  HIGH, "tls_disabled"),
    (r'(?i)verify\s*(peer|host)\s*=\s*(false|0|no)', HIGH, "tls_peer_verify_off"),
]


@dataclass
class EmbeddedStringFinding:
    """Finding from raw binary string analysis"""
    file_path: str
    finding_type: str
    pattern_match: str
    context: str = ""
    severity: str = HIGH
    category: str = ""  # credential | backdoor | insecure_protocol | debug


def run_s108_embedded_string_analysis(
    target_dir: str, log_cb
) -> list[EmbeddedStringFinding]:
    """
    Scan raw firmware binaries (AVR, ARM, MIPS, ESP etc.) for embedded
    credentials, backdoors, debug interfaces, and insecure patterns.
    Mirrors EMBA S107/S108 deep string scan + firmware-specific checks.
    Handles: .bin, .hex, .fw, .rom, .img, .elf — anything with strings output.
    """
    log_cb("[S108] Starting embedded binary string analysis (IoT/MCU firmware)")
    results = []

    # Find all candidate firmware files (not just ELF — raw AVR bins too)
    FW_EXTENSIONS = {
        ".bin", ".hex", ".fw", ".rom", ".img", ".elf",
        ".bin.bak", ".firmware", ""  # also scan extensionless files
    }
    candidate_files = []
    for root, dirs, files in os.walk(target_dir):
        for skip in [".git", "node_modules", "__pycache__"]:
            if skip in dirs: dirs.remove(skip)
        for fname in files:
            fp = Path(root) / fname
            if not fp.is_file() or fp.is_symlink():
                continue
            if fp.stat().st_size < 64:  # skip tiny files
                continue
            if fp.stat().st_size > 32 * 1024 * 1024:  # skip >32MB
                continue
            if fp.suffix.lower() in FW_EXTENSIONS or fp.suffix == "":
                candidate_files.append(fp)

    # Also explicitly add extracted_partitions and raw_binary directory files
    from pathlib import Path as _Path
    for subdir in ["extracted_partitions", "raw_binary"]:
        scan_dir = _Path(target_dir) / subdir
        if scan_dir.exists():
            for pf in scan_dir.iterdir():
                if pf.is_file() and pf.stat().st_size > 64 and pf not in candidate_files:
                    candidate_files.append(pf)
                    log_cb(f"[S108] Added {subdir} file: {pf.name} ({pf.stat().st_size // 1024}KB)")

    log_cb(f"[S108] Scanning {len(candidate_files)} binary/firmware files for embedded strings")

    for fp in candidate_files:
        rel = str(fp.relative_to(target_dir))
        log_cb(f"[S108] Analyzing: {rel} ({fp.stat().st_size // 1024}KB)")

        # Run strings (like EMBA does) — min length 4 chars
        out, err, rc = _run(["strings", "-n", "4", str(fp)], timeout=30)
        if not out:
            continue

        lines = out.splitlines()
        log_cb(f"[S108] {rel}: {len(lines)} printable strings extracted")

        # ── Credential patterns ────────────────────────────────────────────
        for pattern, severity, finding_type in EMBEDDED_CREDENTIAL_PATTERNS:
            for i, line in enumerate(lines):
                m = re.search(pattern, line)
                if m:
                    matched_val = m.group(0)
                    # Get context (surrounding lines)
                    ctx_start = max(0, i - 1)
                    ctx_end   = min(len(lines), i + 2)
                    context = " | ".join(lines[ctx_start:ctx_end])
                    results.append(EmbeddedStringFinding(
                        file_path=rel,
                        finding_type=finding_type,
                        pattern_match=matched_val[:100],
                        context=context[:200],
                        severity=severity,
                        category="credential",
                    ))
                    break  # one finding per pattern per file

        # ── Backdoor / debug patterns ──────────────────────────────────────
        for pattern, severity, finding_type in EMBEDDED_BACKDOOR_PATTERNS:
            for i, line in enumerate(lines):
                m = re.search(pattern, line)
                if m:
                    ctx_start = max(0, i - 1)
                    ctx_end   = min(len(lines), i + 2)
                    context = " | ".join(lines[ctx_start:ctx_end])
                    results.append(EmbeddedStringFinding(
                        file_path=rel,
                        finding_type=finding_type,
                        pattern_match=m.group(0)[:100],
                        context=context[:200],
                        severity=severity,
                        category="backdoor",
                    ))
                    break

        # ── Insecure protocol patterns ─────────────────────────────────────
        for pattern, severity, finding_type in INSECURE_PROTOCOL_PATTERNS:
            for i, line in enumerate(lines):
                m = re.search(pattern, line)
                if m:
                    ctx_start = max(0, i - 1)
                    ctx_end   = min(len(lines), i + 2)
                    context = " | ".join(lines[ctx_start:ctx_end])
                    results.append(EmbeddedStringFinding(
                        file_path=rel,
                        finding_type=finding_type,
                        pattern_match=m.group(0)[:100],
                        context=context[:200],
                        severity=severity,
                        category="insecure_protocol",
                    ))
                    break

    critical_count = sum(1 for r in results if r.severity == CRITICAL)
    high_count     = sum(1 for r in results if r.severity == HIGH)
    log_cb(f"[S108] Done — {len(results)} findings "
           f"({critical_count} critical, {high_count} high)")
    return results
