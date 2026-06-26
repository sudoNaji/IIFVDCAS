"""
IIFVDCAS — Phase 4: SBOM / HBOM / CBOM Generator
Mirrors EMBA logic from:
  F02_toolchain.sh      → toolchain/compiler detection
  F10_license_summary.sh → license inventory
  F15_cyclonedx_sbom.sh  → CycloneDX 1.5 JSON SBOM
  F50_base_aggregator.sh → risk aggregation summary

Generates three BOM types:
  SBOM  — Software Bill of Materials   (CycloneDX 1.5)
  HBOM  — Hardware Bill of Materials   (component metadata)
  CBOM  — Cryptography Bill of Materials (keys, certs, algorithms)
"""

import subprocess, os, re, json, hashlib, uuid, logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ─── Known license map ────────────────────────────────────────────────────────
LICENSE_MAP = {
    "busybox": "GPL-2.0-only", "openssl": "Apache-2.0",
    "dropbear": "MIT", "openssh": "BSD-2-Clause",
    "curl": "MIT", "wget": "GPL-3.0-or-later",
    "iptables": "GPL-2.0-only", "dnsmasq": "GPL-2.0-or-later",
    "lighttpd": "BSD-3-Clause", "nginx": "BSD-2-Clause",
    "mosquitto": "EPL-2.0", "avahi": "LGPL-2.1-or-later",
    "libssl": "Apache-2.0", "libcrypto": "Apache-2.0",
    "libc": "LGPL-2.1-or-later", "uclibc": "LGPL-2.1-or-later",
    "musl": "MIT", "glibc": "LGPL-2.1-or-later",
    "avr-libc": "BSD-2-Clause", "pubsubclient": "MIT",
    "arduinojson": "MIT", "wifinina": "LGPL-2.1-or-later",
}

# ─── Crypto algorithm patterns (CBOM) ────────────────────────────────────────
CRYPTO_PATTERNS = [
    (r'\bAES[-_]?(128|192|256)\b',   "AES",        "symmetric",    "strong"),
    (r'\bRSA[-_]?(1024|2048|4096)\b',"RSA",        "asymmetric",   "check_keysize"),
    (r'\bECDSA\b',                   "ECDSA",       "asymmetric",   "strong"),
    (r'\bECDH\b',                    "ECDH",        "key-exchange", "strong"),
    (r'\bSHA[-_]?(256|384|512)\b',   "SHA-2",       "hash",         "strong"),
    (r'\bSHA[-_]?1\b',               "SHA-1",       "hash",         "weak"),
    (r'\bMD5\b',                     "MD5",         "hash",         "weak"),
    (r'\bRC4\b',                     "RC4",         "symmetric",    "insecure"),
    (r'\bDES\b(?!_)',                "DES",         "symmetric",    "insecure"),
    (r'\b3DES\b|TRIPLE[-_]DES',     "3DES",        "symmetric",    "weak"),
    (r'\bTLS[-_]?(1\.0|1\.1)\b',    "TLS 1.0/1.1", "protocol",     "insecure"),
    (r'\bTLS[-_]?1\.2\b',           "TLS 1.2",     "protocol",     "acceptable"),
    (r'\bTLS[-_]?1\.3\b',           "TLS 1.3",     "protocol",     "strong"),
    (r'\bSSL[-_]?[23]\b',           "SSLv2/3",     "protocol",     "insecure"),
    (r'\bblowfish\b',               "Blowfish",    "symmetric",    "weak"),
    (r'\bchacha20\b',               "ChaCha20",    "symmetric",    "strong"),
    (r'\bpoly1305\b',               "Poly1305",    "mac",          "strong"),
]

# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class SBOMComponent:
    """CycloneDX component"""
    bom_ref: str
    component_type: str
    name: str
    version: str = "unknown"
    supplier: str = ""
    license: str = "NOASSERTION"
    cpe: str = ""
    purl: str = ""
    description: str = ""
    hashes: dict = field(default_factory=dict)
    source_path: str = ""
    architecture: str = ""

@dataclass
class HBOMComponent:
    """Hardware component"""
    bom_ref: str
    component_type: str
    name: str
    manufacturer: str = ""
    model: str = ""
    version: str = ""
    description: str = ""
    source: str = ""

@dataclass
class CBOMComponent:
    """Cryptographic algorithm/asset"""
    bom_ref: str
    algorithm: str
    category: str
    strength: str
    source_file: str = ""
    context: str = ""
    primitive: str = ""

@dataclass
class SBOMResult:
    """Full Phase 4 result"""
    job_id: str
    target_dir: str
    started_at: str
    completed_at: str = ""
    status: str = "pending"
    progress: int = 0
    sbom_components: list = field(default_factory=list)
    hbom_components: list = field(default_factory=list)
    cbom_components: list = field(default_factory=list)
    toolchain: dict = field(default_factory=dict)
    license_summary: dict = field(default_factory=dict)
    total_components: int = 0
    total_hw_components: int = 0
    total_crypto_components: int = 0
    weak_crypto_count: int = 0
    insecure_crypto_count: int = 0
    cyclonedx_json_path: str = ""
    hbom_json_path: str = ""
    cbom_json_path: str = ""
    log: list = field(default_factory=list)
    error: str = ""


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 30) -> tuple:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "LANG": "C", "LC_ALL": "C"})
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1

def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def _md5(path: str) -> str:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def _find_elf(base: str) -> list:
    results = []
    for root, dirs, files in os.walk(base):
        for skip in [".git", "__pycache__"]:
            if skip in dirs: dirs.remove(skip)
        for f in files:
            fp = Path(root) / f
            if not fp.is_file() or fp.is_symlink(): continue
            try:
                with open(fp, "rb") as fh:
                    if fh.read(4) == b"\x7fELF":
                        results.append(str(fp))
            except: pass
    return results


# ─── F02: Toolchain detection ─────────────────────────────────────────────────

def run_f02_toolchain(target_dir: str, log_cb) -> dict:
    log_cb("[F02] Toolchain detection starting")
    toolchain = {
        "architecture": "unknown", "endianness": "unknown",
        "libc_type": "unknown", "compiler_hint": "unknown",
        "kernel_version": "unknown", "gcc_version": "unknown",
        "build_system": "unknown", "cpu_arch": [],
    }
    elf_files = _find_elf(target_dir)
    log_cb(f"[F02] Found {len(elf_files)} ELF binaries for toolchain analysis")
    arch_votes = {}
    libc_hints = set()
    compiler_hints = set()
    gcc_versions = set()
    for elf in elf_files[:50]:
        out, _, rc = _run(["file", "-b", elf], timeout=5)
        if rc != 0: continue
        for arch in ["ARM", "MIPS", "x86-64", "80386", "PowerPC", "SPARC", "AVR", "RISC-V", "AArch64"]:
            if arch.lower() in out.lower():
                arch_votes[arch] = arch_votes.get(arch, 0) + 1
        if "LSB" in out: toolchain["endianness"] = "little-endian"
        elif "MSB" in out: toolchain["endianness"] = "big-endian"
        str_out, _, _ = _run(["strings", "-n", "6", elf], timeout=10)
        for line in str_out.splitlines():
            if "GCC" in line:
                m = re.search(r'GCC[:\s]+(\d+\.\d+[\.\d]*)', line)
                if m:
                    gcc_versions.add(m.group(1))
                    compiler_hints.add("GCC")
            if "Buildroot" in line:
                compiler_hints.add("Buildroot")
                toolchain["build_system"] = "Buildroot"
            if "OpenWrt" in line: toolchain["build_system"] = "OpenWrt"
            if "uclibc" in line.lower(): libc_hints.add("uClibc")
            if "musl" in line.lower(): libc_hints.add("musl")
            if "glibc" in line.lower() or "gnu libc" in line.lower(): libc_hints.add("glibc")
    if arch_votes:
        toolchain["architecture"] = max(arch_votes, key=arch_votes.get)
        toolchain["cpu_arch"] = list(arch_votes.keys())
    if libc_hints: toolchain["libc_type"] = " / ".join(sorted(libc_hints))
    if compiler_hints: toolchain["compiler_hint"] = " / ".join(sorted(compiler_hints))
    if gcc_versions: toolchain["gcc_version"] = ", ".join(sorted(gcc_versions))
    # ── ESP32/ESP8266 (Xtensa/RISC-V) special case — MUST run before the
    bin_files = list(Path(target_dir).rglob("*.bin"))
    for bf in bin_files[:3]:
        str_out, _, _ = _run(["strings", "-n", "4", str(bf)], timeout=10)
        if "avr-gcc" in str_out.lower() or "avr" in str_out.lower():
            toolchain["architecture"] = "AVR (ATmega)"
            toolchain["compiler_hint"] = "avr-gcc"
            toolchain["libc_type"] = "avr-libc"
            break
    # If still unknown and .bin/.hex files present → AVR
    if toolchain["architecture"] == "unknown":
        if any(Path(target_dir).rglob("*.bin")) or any(Path(target_dir).rglob("*.hex")):
            toolchain["architecture"] = "AVR (ATmega)"
            toolchain["libc_type"] = "avr-libc"
    log_cb(f"[F02] Arch: {toolchain['architecture']} | libc: {toolchain['libc_type']} | compiler: {toolchain['compiler_hint']}")
    return toolchain


# ─── SBOM component discovery ─────────────────────────────────────────────────

def _detect_elf_components(target_dir: str, log_cb) -> list:
    log_cb("[F15] Scanning ELF binaries for software components")
    components = []
    seen = set()
    elf_files = _find_elf(target_dir)
    ver_patterns = [
        r'(?:version|ver|v)\s*:?\s*(\d+\.\d+[\.\d\-\w]*)',
        r'(\d+\.\d+\.\d+[\-\w]*)',
    ]
    for elf in elf_files[:200]:
        name = Path(elf).stem.lower()
        if name in seen: continue
        seen.add(name)
        str_out, _, _ = _run(["strings", "-n", "4", elf], timeout=10)
        version = "unknown"
        for pattern in ver_patterns:
            m = re.search(pattern, str_out, re.IGNORECASE)
            if m:
                version = m.group(1)
                break
        file_out, _, _ = _run(["file", "-b", elf], timeout=5)
        arch = "unknown"
        for a in ["ARM", "MIPS", "x86-64", "80386", "PowerPC", "AVR", "AArch64"]:
            if a.lower() in file_out.lower():
                arch = a
                break
        license_name = LICENSE_MAP.get(name, "NOASSERTION")
        rel = str(Path(elf).relative_to(target_dir))
        comp = SBOMComponent(
            bom_ref=str(uuid.uuid4()),
            component_type="application" if rel.startswith(("bin/", "sbin/", "usr/")) else "library",
            name=name, version=version, license=license_name,
            hashes={"SHA-256": _sha256(elf), "MD5": _md5(elf)},
            source_path=rel, architecture=arch,
        )
        comp.purl = f"pkg:generic/{name}@{version}"
        components.append(comp)
    return components


def _detect_config_components(target_dir: str, log_cb) -> list:
    log_cb("[F15] Scanning config/package files")
    components = []
    seen_names = set()
    pkg_patterns = {
        "opkg_status": r'Package:\s*(.+)\nVersion:\s*(.+)',
        "dpkg_status": r'Package:\s*(.+)\nVersion:\s*(.+)',
    }
    for root, dirs, files in os.walk(target_dir):
        for fname in files:
            if fname.lower() not in {"status", "installed", "packages", "package.info"}:
                continue
            fpath = Path(root) / fname
            try:
                content = fpath.read_text(errors="replace")
                for pattern in pkg_patterns.values():
                    for m in re.finditer(pattern, content, re.MULTILINE):
                        pkg_name = m.group(1).strip()
                        pkg_ver = m.group(2).strip()
                        if pkg_name in seen_names: continue
                        seen_names.add(pkg_name)
                        components.append(SBOMComponent(
                            bom_ref=str(uuid.uuid4()),
                            component_type="library",
                            name=pkg_name, version=pkg_ver,
                            license=LICENSE_MAP.get(pkg_name.lower(), "NOASSERTION"),
                            source_path=str(fpath.relative_to(target_dir)),
                            purl=f"pkg:generic/{pkg_name}@{pkg_ver}",
                        ))
            except: pass
    # AVR firmware name from strings
    for bf in Path(target_dir).rglob("*.bin"):
        str_out, _, _ = _run(["strings", "-n", "4", str(bf)], timeout=10)
        fw_ver_match = re.search(r'FW[-_]?(\d+\.\d+[\.\d\-\w]*)', str_out, re.IGNORECASE)
        fw_name_match = re.search(r'([A-Za-z][A-Za-z0-9\-]{3,30})(?:\s+)?(?:IoT|Firmware|Controller)', str_out)
        if fw_ver_match:
            name = fw_name_match.group(1) if fw_name_match else Path(bf.stem).name
            if name not in seen_names:
                seen_names.add(name)
                components.append(SBOMComponent(
                    bom_ref=str(uuid.uuid4()),
                    component_type="firmware",
                    name=name, version=fw_ver_match.group(1),
                    license="NOASSERTION",
                    source_path=str(bf.relative_to(target_dir)),
                    description="Detected from embedded firmware strings",
                    purl=f"pkg:generic/{name}@{fw_ver_match.group(1)}",
                ))
        break
    log_cb(f"[F15] Config scan found {len(components)} package components")
    return components


# ─── HBOM: Hardware Bill of Materials ────────────────────────────────────────

def run_hbom_detection(target_dir: str, analysis_result: dict, log_cb) -> list:
    log_cb("[HBOM] Hardware component detection starting")
    components = []
    seen = set()

    CHIP_PATTERNS = [
        (r'\bATmega328P?\b',    "ATmega328P",  "Atmel/Microchip", "Microcontroller"),
        (r'\bATmega2560\b',     "ATmega2560",  "Atmel/Microchip", "Microcontroller"),
        (r'\bATtiny85\b',       "ATtiny85",    "Atmel/Microchip", "Microcontroller"),
        (r'\bESP8266\b',        "ESP8266",     "Espressif",       "WiFi SoC"),
        (r'\bESP32\b',          "ESP32",       "Espressif",       "WiFi/BT SoC"),
        (r'\bMPU.?6050\b',      "MPU-6050",    "InvenSense",      "Sensor/IMU"),
        (r'\bBME280\b',         "BME280",      "Bosch",           "Sensor/Env"),
        (r'\bDS18B20\b',        "DS18B20",     "Dallas/Maxim",    "Sensor/Temp"),
        (r'\bNRF24\b',          "NRF24L01",    "Nordic Semi",     "Radio/RF"),
        (r'\bCC2500\b',         "CC2500",      "Texas Instruments","Radio/RF"),
        (r'\bW5100\b',          "W5100",       "WIZnet",          "Ethernet"),
        (r'\bENC28J60\b',       "ENC28J60",    "Microchip",       "Ethernet"),
    ]

    # Scan binary/hex files for chip signatures
    bin_files = (
        list(Path(target_dir).rglob("*.bin")) +
        list(Path(target_dir).rglob("*.hex"))
    )
    all_strings = ""
    for bf in bin_files[:4]:
        out, _, _ = _run(["strings", "-n", "4", str(bf)], timeout=10)
        all_strings += out + "\n"

    for pattern, name, mfr, ctype in CHIP_PATTERNS:
        if re.search(pattern, all_strings, re.IGNORECASE) and name not in seen:
            seen.add(name)
            components.append(HBOMComponent(
                bom_ref=str(uuid.uuid4()),
                component_type=ctype,
                name=name, manufacturer=mfr,
                description=f"Detected via string pattern in {', '.join(str(p.name) for p in bin_files[:2])}",
                source="string_scan:" + (str(bin_files[0].name) if bin_files else ""),
            ))

    # Add from prior_analysis device_info
    device = analysis_result.get("device_info") or analysis_result
    mcu = (device.get("mcu") or device.get("chipset") or "")
    if mcu and mcu not in seen:
        seen.add(mcu)
        components.append(HBOMComponent(
            bom_ref=str(uuid.uuid4()),
            component_type="Microcontroller",
            name=mcu, manufacturer="Atmel/Microchip",
            source="device_detection",
        ))

    log_cb(f"[HBOM] Detected {len(components)} hardware components")
    return components


# ─── CBOM: Crypto Bill of Materials ──────────────────────────────────────────

def run_cbom_detection(target_dir: str, log_cb) -> list:
    log_cb("[CBOM] Cryptographic asset detection starting")
    components = []
    seen_algos = set()

    text_extensions = {".c", ".cpp", ".h", ".py", ".js", ".sh", ".conf",
                       ".txt", ".ini", ".cfg", ".bin", ".hex"}

    for root, dirs, files in os.walk(target_dir):
        for skip in [".git", "__pycache__"]: 
            if skip in dirs: dirs.remove(skip)
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in text_extensions: continue
            try:
                if fpath.suffix.lower() in {".bin", ".hex"}:
                    out, _, _ = _run(["strings", "-n", "4", str(fpath)], timeout=10)
                    content = out
                else:
                    content = fpath.read_text(errors="replace")

                for pattern, algo, category, strength in CRYPTO_PATTERNS:
                    if algo in seen_algos: continue
                    m = re.search(pattern, content, re.IGNORECASE)
                    if m:
                        seen_algos.add(algo)
                        # Key-size check for RSA
                        if strength == "check_keysize":
                            key_size = int(m.group(1)) if m.lastindex else 0
                            strength = "strong" if key_size >= 2048 else "weak"
                        rel = str(fpath.relative_to(target_dir))
                        # Get some context
                        lines = content.splitlines()
                        match_line = next((l.strip() for l in lines if re.search(pattern, l, re.IGNORECASE)), "")
                        components.append(CBOMComponent(
                            bom_ref=str(uuid.uuid4()),
                            algorithm=algo, category=category, strength=strength,
                            source_file=rel, context=match_line[:120],
                        ))
            except: pass

    log_cb(f"[CBOM] Detected {len(components)} cryptographic assets")
    return components


# ─── F10: License summary ──────────────────────────────────────────────────────

def build_license_summary(components: list) -> dict:
    summary = {}
    for comp in components:
        if hasattr(comp, 'license'):
            lic = comp.license or "NOASSERTION"
        else:
            lic = comp.get("license", "NOASSERTION")
        summary[lic] = summary.get(lic, 0) + 1
    return summary


# ─── CycloneDX 1.5 builder ────────────────────────────────────────────────────

def build_cyclonedx_json(result: "SBOMResult", firmware_path: str, toolchain: dict) -> dict:
    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "IIFVDCAS", "name": "Phase4-SBOM", "version": "1.0"}],
            "component": {
                "type": "firmware",
                "name": Path(firmware_path).name if firmware_path else "unknown",
                "version": "unknown",
                "description": f"Arch: {toolchain.get('architecture','?')} | libc: {toolchain.get('libc_type','?')}",
            },
        },
        "components": [],
    }
    for comp in result.sbom_components:
        c = {
            "type": comp.get("component_type", "library"),
            "bom-ref": comp.get("bom_ref", str(uuid.uuid4())),
            "name": comp.get("name", ""),
            "version": comp.get("version", "unknown"),
            "licenses": [{"license": {"id": comp.get("license", "NOASSERTION")}}],
        }
        if comp.get("cpe"):  c["cpe"] = comp["cpe"]
        if comp.get("purl"): c["purl"] = comp["purl"]
        if comp.get("hashes"):
            c["hashes"] = [
                {"alg": alg, "content": val}
                for alg, val in comp["hashes"].items() if val
            ]
        cdx["components"].append(c)
    return cdx


# ─── JSON writer ──────────────────────────────────────────────────────────────

def _write_json(data: dict, path: str) -> bool:
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(data, indent=2, default=str))
        return True
    except Exception as e:
        logger.error(f"Failed to write {path}: {e}")
        return False


# ─── Master runner ────────────────────────────────────────────────────────────

def run_sbom_generation(
    target_dir: str,
    job_id: str,
    firmware_path: str = "",
    prior_analysis: dict = None,
    progress_callback=None,
) -> SBOMResult:
    """Master Phase 4 runner. Generates SBOM + HBOM + CBOM."""

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

    result = SBOMResult(
        job_id=job_id, target_dir=target_dir,
        started_at=datetime.now(timezone.utc).isoformat(),
        status="running",
    )
    prior = prior_analysis or {}
    output_dir = Path(f"/tmp/iifvdcas_sbom/{job_id}")
    output_dir.mkdir(parents=True, exist_ok=True)

    if not os.path.isdir(target_dir):
        result.status = "failed"
        result.error = f"Target directory not found: {target_dir}"
        return result

    try:
        # ── F02: Toolchain ────────────────────────────────────────────────
        progress(5, "F02: Toolchain detection")
        result.toolchain = run_f02_toolchain(target_dir, log)
        progress(15, f"F02: Arch={result.toolchain['architecture']}")

        # ── F15: SBOM — ELF + config scan ────────────────────────────────
        progress(18, "F15: SBOM — scanning ELF binaries")
        elf_comps = _detect_elf_components(target_dir, log)
        progress(35, "F15: SBOM — scanning config/package files")
        cfg_comps = _detect_config_components(target_dir, log)
        all_comps = elf_comps + cfg_comps

        # ── AVR/MCU: Embedded library detection ──────────────────────────
        # For raw AVR firmware (no ELF/package managers), scan binary
        # strings for known Arduino/embedded library signatures with CPEs.
        is_avr = (
            result.toolchain.get("architecture", "").upper().startswith("AVR")
            or not elf_comps
        )
        if is_avr:
            progress(38, "AVR: Detecting embedded library components")
            try:
                from core.sbom.avr_component_extractor import detect_avr_components
                bin_files = [
                    str(p) for p in Path(target_dir).rglob("*.bin")
                    if p.stat().st_size < 2 * 1024 * 1024
                ] + [
                    str(p) for p in Path(target_dir).rglob("*.hex")
                    if p.stat().st_size < 4 * 1024 * 1024
                ]
                hbom_prior = prior.get("hbom_components", [])
                avr_comps_raw = detect_avr_components(
                    binary_paths=bin_files[:4],
                    hbom_components=hbom_prior,
                    log_cb=log,
                )
                seen_avr = {c.name for c in all_comps}
                for ac in avr_comps_raw:
                    if ac["name"] not in seen_avr:
                        all_comps.append(SBOMComponent(
                            bom_ref=str(uuid.uuid4()),
                            component_type=ac.get("component_type", "library"),
                            name=ac["name"],
                            version=ac.get("version", "unknown"),
                            supplier=ac.get("vendor", ""),
                            license=LICENSE_MAP.get(ac["name"].lower(),
                                    ac.get("license", "NOASSERTION")),
                            cpe=ac.get("cpe", ""),
                            purl=ac.get("purl", ""),
                            source_path=ac.get("source_path", "avr-scan"),
                        ))
                        seen_avr.add(ac["name"])
                log(f"[AVR-SBOM] Added {len(avr_comps_raw)} AVR library components")
            except Exception as e:
                log(f"[AVR-SBOM] AVR component extraction error: {e}")

        result.sbom_components = [asdict(c) for c in all_comps]
        result.total_components = len(all_comps)
        progress(45, f"F15: {result.total_components} components identified")

        # ── F10: License summary ──────────────────────────────────────────
        progress(47, "F10: Building license inventory")
        result.license_summary = build_license_summary(all_comps)
        log(f"[F10] {len(result.license_summary)} distinct licenses found")
        progress(50, "F10: License inventory complete")

        # ── HBOM: Hardware detection ──────────────────────────────────────
        progress(52, "HBOM: Hardware component detection")
        hw_comps = run_hbom_detection(target_dir, prior, log)
        result.hbom_components = [asdict(h) for h in hw_comps]
        result.total_hw_components = len(hw_comps)
        progress(65, f"HBOM: {result.total_hw_components} hardware components")

        # ── CBOM: Crypto detection ────────────────────────────────────────
        progress(67, "CBOM: Cryptographic asset detection")
        crypto_comps = run_cbom_detection(target_dir, log)
        result.cbom_components = [asdict(c) for c in crypto_comps]
        result.total_crypto_components = len(crypto_comps)
        result.weak_crypto_count = sum(1 for c in crypto_comps if c.strength == "weak")
        result.insecure_crypto_count = sum(1 for c in crypto_comps if c.strength == "insecure")
        progress(80, f"CBOM: {result.total_crypto_components} crypto assets ({result.insecure_crypto_count} insecure)")

        # ── Write CycloneDX JSON ──────────────────────────────────────────
        progress(82, "Writing CycloneDX 1.5 SBOM JSON")
        cdx = build_cyclonedx_json(result, firmware_path, result.toolchain)
        cdx_path = str(output_dir / "cyclonedx_sbom.json")
        if _write_json(cdx, cdx_path):
            result.cyclonedx_json_path = cdx_path
            log(f"[F15] CycloneDX SBOM written: {cdx_path}")
        progress(88, "CycloneDX SBOM written")

        # ── Write HBOM JSON ───────────────────────────────────────────────
        hbom_path = str(output_dir / "hbom.json")
        if _write_json({
            "format": "IIFVDCAS-HBOM", "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "components": result.hbom_components,
        }, hbom_path):
            result.hbom_json_path = hbom_path
        progress(92, "HBOM JSON written")

        # ── Write CBOM JSON ───────────────────────────────────────────────
        cbom_path = str(output_dir / "cbom.json")
        if _write_json({
            "format": "IIFVDCAS-CBOM", "version": "1.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": result.total_crypto_components,
                "strong": sum(1 for c in crypto_comps if c.strength == "strong"),
                "acceptable": sum(1 for c in crypto_comps if c.strength == "acceptable"),
                "weak": result.weak_crypto_count,
                "insecure": result.insecure_crypto_count,
            },
            "components": result.cbom_components,
        }, cbom_path):
            result.cbom_json_path = cbom_path
        progress(96, "CBOM JSON written")

        result.status = "success"
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[DONE] SBOM={result.total_components} HBOM={result.total_hw_components} CBOM={result.total_crypto_components}")
        progress(100, "Phase 4 complete")

    except Exception as e:
        logger.exception("SBOM generation failed")
        result.status = "failed"
        result.error = str(e)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[ERROR] {e}")

    return result
