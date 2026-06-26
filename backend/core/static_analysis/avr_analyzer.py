"""
IIFVDCAS — Phase 3 Extension: AVR Binary Analysis
Tools integrated (only those installable and usable headlessly):
  - avr-objcopy  : convert raw .bin → Intel HEX
  - avr-objdump  : disassemble AVR binary, extract interrupt vector table
  - avr-nm       : list symbols from AVR binary  
  - avr-readelf  : read ELF sections (if ELF format)
  - avr-strings  : extract strings (AVR-aware variant)
  - strings      : generic string extraction (already in S108)
  - r2pipe       : radare2 Python API for AVR disassembly / analysis
  
NOT integrated: Ghidra headless (requires Ghidra install + JVM overhead),
                simulavr/avr-gdb (dynamic — Phase 8), AVRS (research-grade)
"""

import subprocess, os, re, json, hashlib, logging, tempfile, shutil
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class AVRInterruptVector:
    """Entry in the AVR interrupt vector table"""
    index: int
    address: str
    target: str
    name: str = ""          # RESET, INT0, INT1, TIMER0_OVF, etc.


@dataclass
class AVRFunction:
    """Function detected via avr-objdump / r2"""
    address: str
    name: str
    size_bytes: int = 0
    call_count: int = 0


@dataclass
class AVRDisassemblyInfo:
    """Complete AVR disassembly metadata"""
    binary_path: str
    architecture: str = "AVR"
    device_hint: str = ""       # e.g. ATmega328P
    flash_size_bytes: int = 0
    entry_point: str = ""
    interrupt_vectors: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    total_instructions: int = 0
    raw_disasm_excerpt: str = ""   # first 100 instructions for display
    hex_path: str = ""


@dataclass
class AVRSecurityFinding:
    """Security finding from AVR analysis"""
    file_path: str
    finding_type: str
    detail: str
    severity: str = HIGH
    address: str = ""
    context: str = ""
    category: str = ""   # insecure_call | debug_symbol | crypto | config


@dataclass
class AVRAnalysisResult:
    """Complete AVR analysis result"""
    binary_path: str
    started_at: str
    completed_at: str = ""
    status: str = "pending"

    disassembly: Optional[AVRDisassemblyInfo] = None
    security_findings: list = field(default_factory=list)

    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    strings_extracted: int = 0

    log: list = field(default_factory=list)
    error: str = ""


# ─── AVR-specific dangerous call patterns (mirrors EMBA S13 for AVR ISA) ─────

AVR_DANGEROUS_PATTERNS = [
    # Hardcoded credential strings in disassembly data sections
    (r'\.string\s+"([^"]{4,})"',                      CRITICAL, "embedded_string",      "config"),
    # Calls to known unsafe sprintf equivalents in AVR libc
    (r'\bcall\b.*\bsprintf\b',                         HIGH,     "unsafe_sprintf_call",   "insecure_call"),
    (r'\bcall\b.*\bstrcpy\b',                          HIGH,     "unsafe_strcpy_call",    "insecure_call"),
    (r'\bcall\b.*\bgets\b',                            CRITICAL, "unsafe_gets_call",      "insecure_call"),
    # WDT disable — disabling watchdog timer is a security risk on MCUs
    (r'(?i)wdt_disable|WDTCSR|wdt\.h',                HIGH,     "watchdog_disabled",     "insecure_call"),
    # UART/Serial debug output left enabled
    (r'(?i)(Serial\.print|uart_puts|uart_send|USART)',  MEDIUM,   "uart_debug_output",     "debug_symbol"),
    # Insecure random (millis-based, not TRNG)
    (r'(?i)\brandom\b|\brand\b',                        MEDIUM,   "weak_rng",              "crypto"),
    # Hardcoded WiFi / MQTT / HTTP in data sections
    (r'(?i)(ssid|password|mqtt|http://)',               CRITICAL, "hardcoded_credential",  "config"),
    # Boot/secure flags
    (r'(?i)BOOT|FUSE|LOCKBIT',                         MEDIUM,   "boot_fuse_reference",   "config"),
    # EEPROM direct write (can leak secrets)
    (r'(?i)eeprom_write|EEAR|EEDR',                    LOW,      "eeprom_write",          "config"),
]

# Known AVR interrupt vector names for ATmega328P
ATMEGA328P_VECTORS = [
    "RESET", "INT0", "INT1", "PCINT0", "PCINT1", "PCINT2",
    "WDT", "TIMER2_COMPA", "TIMER2_COMPB", "TIMER2_OVF",
    "TIMER1_CAPT", "TIMER1_COMPA", "TIMER1_COMPB", "TIMER1_OVF",
    "TIMER0_COMPA", "TIMER0_COMPB", "TIMER0_OVF",
    "SPI_STC", "USART_RX", "USART_UDRE", "USART_TX",
    "ADC", "EE_READY", "ANALOG_COMP", "TWI", "SPM_READY",
]


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 60, cwd: str = None) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd,
                           env={**os.environ, "LANG": "C", "LC_ALL": "C"})
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError:
        return "", f"Not found: {cmd[0]}", -2
    except Exception as e:
        return "", str(e), -99


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─── Step 1: Convert .bin → .hex (avr-objcopy) ───────────────────────────────

def convert_bin_to_hex(bin_path: str, log_cb) -> Optional[str]:
    """
    Convert raw AVR .bin to Intel HEX format.
    Required by avr-objdump for proper disassembly.
    avr-objcopy -I binary -O ihex flash.bin flash.hex
    """
    hex_path = bin_path.replace(".bin", ".hex")
    if not hex_path.endswith(".hex"):
        hex_path = bin_path + ".hex"

    log_cb(f"[avr-objcopy] Converting {Path(bin_path).name} → {Path(hex_path).name}")
    out, err, rc = _run(
        ["avr-objcopy", "-I", "binary", "-O", "ihex", bin_path, hex_path],
        timeout=30
    )
    if rc == 0 and Path(hex_path).exists():
        log_cb(f"[avr-objcopy] ✅ HEX created: {hex_path} ({_human_size(Path(hex_path).stat().st_size)})")
        return hex_path
    else:
        log_cb(f"[avr-objcopy] ❌ Conversion failed: {err}")
        return None


# ─── Step 2: Disassemble with avr-objdump ────────────────────────────────────

def disassemble_with_avr_objdump(bin_path: str, hex_path: str, log_cb) -> AVRDisassemblyInfo:
    """
    Full AVR disassembly using avr-objdump.
    Command: avr-objdump -m avr5 -D flash.hex
    (avr5 = ATmega328P compatible instruction set)
    """
    info = AVRDisassemblyInfo(
        binary_path=bin_path,
        hex_path=hex_path or bin_path,
        flash_size_bytes=Path(bin_path).stat().st_size,
    )

    log_cb(f"[avr-objdump] Disassembling {Path(bin_path).name} (avr5 ISA)")

    target = hex_path if hex_path else bin_path
    input_flag = ["-m", "avr5"] if not hex_path else ["-m", "avr5"]

    out, err, rc = _run(
        ["avr-objdump", "-m", "avr5", "-D", target],
        timeout=60
    )

    if not out:
        # fallback: try avr:6 or plain avr
        out, err, rc = _run(
            ["avr-objdump", "-m", "avr", "-D", target], timeout=60
        )

    if not out:
        log_cb(f"[avr-objdump] ❌ Disassembly failed: {err[:100]}")
        return info

    lines = out.splitlines()
    log_cb(f"[avr-objdump] ✅ Disassembly: {len(lines)} lines")

    info.total_instructions = sum(1 for l in lines if re.match(r'\s+[0-9a-f]+:', l))

    # ── Extract interrupt vector table (first 26 entries for ATmega328P) ──
    vectors = []
    in_vectors = False
    for line in lines[:200]:
        # Interrupt vectors start at address 0x0000
        vec_match = re.match(r'\s+([0-9a-f]+):\s+([0-9a-f ]+)\s+.*?(jmp|rjmp)\s+0x([0-9a-f]+)', line, re.I)
        if vec_match:
            addr   = vec_match.group(1)
            target = vec_match.group(4)
            idx    = len(vectors)
            name   = ATMEGA328P_VECTORS[idx] if idx < len(ATMEGA328P_VECTORS) else f"VEC_{idx}"
            vectors.append(AVRInterruptVector(
                index=idx, address=f"0x{addr}", target=f"0x{target}", name=name
            ))
            if idx == 0:
                info.entry_point = f"0x{target}"
                log_cb(f"[avr-objdump] Entry point (RESET): 0x{target}")
            if idx >= 25:
                break

    info.interrupt_vectors = [asdict(v) for v in vectors]
    if vectors:
        log_cb(f"[avr-objdump] Found {len(vectors)} interrupt vectors")

    # ── Extract function symbols via avr-nm ────────────────────────────────
    nm_out, _, nm_rc = _run(["avr-nm", "-n", "--defined-only", target], timeout=20)
    if nm_rc == 0 and nm_out:
        funcs = []
        for line in nm_out.splitlines():
            m = re.match(r'([0-9a-f]+)\s+([tTW])\s+(\S+)', line)
            if m:
                funcs.append(AVRFunction(
                    address=f"0x{m.group(1)}",
                    name=m.group(3),
                ))
        info.functions = [asdict(f) for f in funcs]
        log_cb(f"[avr-nm] Found {len(funcs)} symbols/functions")

    # ── Device hint from disassembly patterns ─────────────────────────────
    # ATmega328P has 32KB flash, specific register layout
    if info.flash_size_bytes <= 32768:
        info.device_hint = "ATmega328P (32KB flash)"
    elif info.flash_size_bytes <= 65536:
        info.device_hint = "ATmega2560 / ATmega1280 (64KB flash)"
    else:
        info.device_hint = "Unknown AVR device"

    # ── First 100 instructions for UI display ─────────────────────────────
    disasm_lines = [l for l in lines if l.strip()]
    info.raw_disasm_excerpt = "\n".join(disasm_lines[:100])

    return info


# ─── Step 3: Security scan on disassembly ────────────────────────────────────

def scan_disassembly_for_security(
    disasm_text: str, bin_path: str, log_cb
) -> list[AVRSecurityFinding]:
    """
    Scan avr-objdump output for dangerous patterns.
    Mirrors EMBA S13 weak function logic adapted for AVR ISA.
    """
    findings = []
    rel = Path(bin_path).name

    for pattern, severity, finding_type, category in AVR_DANGEROUS_PATTERNS:
        for i, line in enumerate(disasm_text.splitlines()):
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                # Get address if present
                addr_m = re.match(r'\s+([0-9a-f]+):', line)
                addr = f"0x{addr_m.group(1)}" if addr_m else ""
                ctx_lines = disasm_text.splitlines()
                ctx = " | ".join(ctx_lines[max(0,i-1):min(len(ctx_lines),i+2)])
                findings.append(AVRSecurityFinding(
                    file_path=rel,
                    finding_type=finding_type,
                    detail=m.group(0)[:100],
                    severity=severity,
                    address=addr,
                    context=ctx[:200],
                    category=category,
                ))
                break  # one per pattern

    log_cb(f"[avr-security] Found {len(findings)} security issues in disassembly")
    return findings


# ─── Step 4: avr-strings scan ────────────────────────────────────────────────

def run_avr_strings(bin_path: str, log_cb) -> tuple[list[str], list[AVRSecurityFinding]]:
    """
    Run avr-strings (AVR-aware string extraction) on the binary.
    More accurate than generic `strings` for AVR binaries.
    """
    log_cb(f"[avr-strings] Extracting strings from {Path(bin_path).name}")
    findings = []
    extracted = []

    out, err, rc = _run(["avr-strings", "-n", "4", bin_path], timeout=30)
    if not out:
        # fallback to generic strings
        out, err, rc = _run(["strings", "-n", "4", bin_path], timeout=30)

    if out:
        extracted = [l.strip() for l in out.splitlines() if l.strip()]
        log_cb(f"[avr-strings] Extracted {len(extracted)} strings")

        # Security patterns on extracted strings
        CRED_PATTERNS = [
            (r'(?i)(password|pass|pwd|secret)\s*[=:]?\s*(\S{4,})', CRITICAL, "hardcoded_password"),
            (r'(?i)(ssid|wifi)\s*[=:]?\s*(\S{2,})',                 CRITICAL, "wifi_ssid"),
            (r'http://\S+',                                          HIGH,     "insecure_http_url"),
            (r'\b(\d{1,3}\.){3}\d{1,3}\b',                          MEDIUM,   "hardcoded_ip"),
            (r'(?i)(debug|backdoor|test_mode)',                      HIGH,     "debug_string"),
            (r'(?i)(secure.?boot.?dis|signature.?verif.?dis)',       CRITICAL, "security_bypass"),
            (r'(?i)(dump.?wifi|dump.?cred|dump.?token)',             CRITICAL, "credential_dump"),
        ]
        rel = Path(bin_path).name
        for pattern, sev, ftype in CRED_PATTERNS:
            for s in extracted:
                m = re.search(pattern, s)
                if m:
                    findings.append(AVRSecurityFinding(
                        file_path=rel,
                        finding_type=ftype,
                        detail=s[:100],
                        severity=sev,
                        category="credential" if "password" in ftype or "cred" in ftype or "wifi" in ftype
                                 else "debug_symbol" if "debug" in ftype
                                 else "insecure_protocol" if "http" in ftype
                                 else "config",
                    ))
                    break

    return extracted, findings


# ─── Step 5: r2pipe analysis (if radare2 available) ──────────────────────────

def run_r2pipe_analysis(bin_path: str, log_cb) -> list[AVRSecurityFinding]:
    """
    radare2 AVR analysis via r2pipe Python API.
    If radare2 binary not installed, uses r2pipe subprocess mode.
    """
    findings = []
    try:
        import r2pipe
        log_cb(f"[r2pipe] Opening {Path(bin_path).name} with arch=avr")
        r2 = r2pipe.open(bin_path, flags=["-2"])  # -2 = no stderr
        r2.cmd("e anal.arch=avr")
        r2.cmd("e anal.bits=8")
        r2.cmd("aaa")  # analyze all

        # Get function list
        funcs = r2.cmdj("aflj") or []
        log_cb(f"[r2pipe] Analyzed {len(funcs)} functions")

        # Get strings
        strings_raw = r2.cmdj("izj") or []
        log_cb(f"[r2pipe] Found {len(strings_raw)} strings")
        rel = Path(bin_path).name

        for s in strings_raw:
            val = s.get("string", "")
            # Flag dangerous strings
            for pattern, sev, ftype in [
                (r'(?i)(password|secret|wifi|ssid)', CRITICAL, "hardcoded_credential"),
                (r'http://',                          HIGH,     "insecure_http"),
                (r'(?i)(debug|test.mode|backdoor)',   HIGH,     "debug_string"),
            ]:
                if re.search(pattern, val):
                    findings.append(AVRSecurityFinding(
                        file_path=rel,
                        finding_type=ftype,
                        detail=val[:100],
                        severity=sev,
                        address=hex(s.get("vaddr", 0)),
                        category="credential" if "credential" in ftype else "debug_symbol",
                    ))
                    break

        r2.quit()
        log_cb(f"[r2pipe] Found {len(findings)} security issues")

    except ImportError:
        log_cb("[r2pipe] r2pipe not available — skipping radare2 analysis")
    except Exception as e:
        log_cb(f"[r2pipe] Error: {e}")

    return findings


# ─── Master AVR Analysis Runner ───────────────────────────────────────────────

def run_avr_analysis(bin_path: str, log_cb=None) -> AVRAnalysisResult:
    """
    Complete AVR binary analysis pipeline:
      1. avr-objcopy: .bin → .hex conversion
      2. avr-objdump: disassembly + IVT + symbols
      3. Security scan on disassembly
      4. avr-strings: string extraction + credential scan
      5. r2pipe: radare2 supplementary analysis (if available)
    """
    if log_cb is None:
        log_cb = lambda m: logger.info(m)

    result = AVRAnalysisResult(
        binary_path=bin_path,
        started_at=datetime.now(timezone.utc).isoformat(),
        status="running",
    )

    def log(msg):
        logger.info(msg)
        result.log.append({"ts": datetime.now(timezone.utc).isoformat(), "msg": msg})
        log_cb(msg)

    try:
        # ── 1. Convert bin → hex ──────────────────────────────────────────
        log(f"[AVR] Starting AVR binary analysis: {Path(bin_path).name}")
        log(f"[AVR] Binary size: {_human_size(Path(bin_path).stat().st_size)}")
        hex_path = convert_bin_to_hex(bin_path, log)

        # ── 2. Disassemble ────────────────────────────────────────────────
        log("[AVR] Running avr-objdump disassembly...")
        disasm = disassemble_with_avr_objdump(bin_path, hex_path, log)
        result.disassembly = asdict(disasm)
        log(f"[AVR] Disassembly: {disasm.total_instructions} instructions, "
            f"{len(disasm.interrupt_vectors)} vectors, {len(disasm.functions)} symbols")
        log(f"[AVR] Device hint: {disasm.device_hint}")
        if disasm.entry_point:
            log(f"[AVR] Entry point (RESET vector): {disasm.entry_point}")

        # ── 3. Security scan on disassembly ──────────────────────────────
        log("[AVR] Scanning disassembly for security issues...")
        sec_findings = scan_disassembly_for_security(
            disasm.raw_disasm_excerpt, bin_path, log
        )
        result.security_findings.extend([asdict(f) for f in sec_findings])

        # ── 4. avr-strings scan ───────────────────────────────────────────
        log("[AVR] Running avr-strings scan...")
        extracted_strings, str_findings = run_avr_strings(bin_path, log)
        result.strings_extracted = len(extracted_strings)
        result.security_findings.extend([asdict(f) for f in str_findings])

        # ── 5. r2pipe (optional) ──────────────────────────────────────────
        log("[AVR] Running r2pipe supplementary analysis...")
        r2_findings = run_r2pipe_analysis(bin_path, log)
        result.security_findings.extend([asdict(f) for f in r2_findings])

        # ── Deduplicate findings by type+detail ───────────────────────────
        seen = set()
        deduped = []
        for f in result.security_findings:
            key = f"{f['finding_type']}:{f['detail'][:40]}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        result.security_findings = deduped

        # ── Summary ───────────────────────────────────────────────────────
        result.total_findings  = len(result.security_findings)
        result.critical_count  = sum(1 for f in result.security_findings if f["severity"] == CRITICAL)
        result.high_count      = sum(1 for f in result.security_findings if f["severity"] == HIGH)

        log(f"[AVR] ✅ Analysis complete: {result.total_findings} findings "
            f"({result.critical_count} critical, {result.high_count} high)")

        result.status = "success"
        result.completed_at = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        logger.exception("AVR analysis failed")
        result.status = "failed"
        result.error = str(e)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[AVR] ❌ Error: {e}")

    return result


def detect_avr_binaries(target_dir: str) -> list[str]:
    """
    Detect AVR firmware binaries in extracted directory.
    Looks for: raw .bin files identified as AVR by `file` command,
    Intel HEX files, and binaries with AVR magic patterns.
    """
    avr_files = []
    for root, dirs, files in os.walk(target_dir):
        for skip in [".git", "node_modules", "__pycache__"]:
            if skip in dirs: dirs.remove(skip)
        for fname in files:
            fp = Path(root) / fname
            if not fp.is_file() or fp.is_symlink():
                continue
            size = fp.stat().st_size
            if size < 64 or size > 256 * 1024:  # AVR max 256KB flash
                continue
            ext = fp.suffix.lower()
            # Check by extension
            if ext in (".bin", ".hex", ".fw", ".rom"):
                avr_files.append(str(fp))
                continue
            # Check by file command output
            out, _, rc = _run(["file", "-b", str(fp)], timeout=5)
            if rc == 0 and any(k in out.upper() for k in ["AVR", "ATMEL", "INTEL HEX"]):
                avr_files.append(str(fp))
    return avr_files
