"""
IIFVDCAS — Phase 2: Firmware Extraction Engine
Mirrors EMBA logic from:
  - P02_firmware_bin_file_check.sh  (fw_bin_detector, file type detection)
  - P50_binwalk_extractor.sh        (binwalk matryoshka extraction)
  - P55_unblob_extractor.sh         (unblob extraction - primary)
  - P60_deep_extractor.sh           (recursive deep extraction)
  - P14_ext_mounter.sh              (ext2/3/4 mounting)
  - P15_ubi_extractor.sh            (UBI image extraction)
  - P65_package_extractor.sh        (deb/rpm/ipk)
"""

import subprocess
import os
import re
import hashlib
import shutil
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)

EXTRACT_BASE = Path("/tmp/iifvdcas_extractions")


# ─── Enums matching EMBA detection logic ─────────────────────────────────────

class FirmwareType(str, Enum):
    UNKNOWN       = "unknown"
    LINUX_FS      = "linux_filesystem"
    SQUASHFS      = "squashfs"
    CRAMFS        = "cramfs"
    JFFS2         = "jffs2"
    YAFFS         = "yaffs"
    UBI           = "ubi_image"
    EXT2          = "ext2_filesystem"
    EXT3          = "ext3_filesystem"
    EXT4          = "ext4_filesystem"
    VMDK          = "vmdk"
    UEFI          = "uefi_bios"
    ELF           = "elf_binary"
    ARCHIVE       = "archive_zip_tar_gz"
    DEB           = "debian_package"
    RPM           = "rpm_package"
    UBOOT         = "uboot_image"
    KERNEL_CONFIG = "kernel_config"
    ANDROID_OTA   = "android_ota"
    CPIO          = "cpio_archive"
    RAW_BINARY    = "raw_binary"

class ExtractionStatus(str, Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    SUCCESS    = "success"
    PARTIAL    = "partial"
    FAILED     = "failed"


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class FirmwareFileInfo:
    """P02 equivalent — file details before extraction"""
    path: str
    size_bytes: int = 0
    size_human: str = ""
    sha512: str = ""
    sha1: str = ""
    md5: str = ""
    entropy: float = 0.0
    entropy_label: str = ""       # low / normal / high / encrypted
    file_type: str = ""           # raw `file` command output
    mime_type: str = ""
    firmware_type: FirmwareType = FirmwareType.UNKNOWN
    is_encrypted: bool = False
    is_compressed: bool = False
    architecture_hint: str = ""   # ARM / MIPS / x86 / AVR etc.
    endianness: str = ""          # little / big
    raw_binwalk_scan: str = ""


@dataclass
class ExtractedItem:
    """Single item inside extracted firmware"""
    path: str
    rel_path: str
    size_bytes: int
    file_type: str
    is_executable: bool = False
    is_symlink: bool = False
    link_target: str = ""


@dataclass
class ExtractionResult:
    """Complete result of a Phase 2 extraction run"""
    job_id: str
    started_at: str
    completed_at: str = ""
    status: ExtractionStatus = ExtractionStatus.PENDING
    firmware_info: Optional[FirmwareFileInfo] = None
    extractor_used: str = ""       # binwalk | unblob | manual | dd
    output_dir: str = ""
    total_files: int = 0
    total_dirs: int = 0
    total_size_bytes: int = 0
    linux_found: bool = False
    linux_paths: list = field(default_factory=list)
    filesystem_type: str = ""
    progress: int = 0
    log: list = field(default_factory=list)
    error: str = ""
    file_tree: list = field(default_factory=list)   # top-level tree for UI


# ─── Helper: run subprocess ──────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 120, cwd: str = None) -> tuple[str, str, int]:
    """Run command → (stdout, stderr, returncode). Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
            env={**os.environ, "LANG": "C", "LC_ALL": "C"}
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", f"Timeout after {timeout}s", -1
    except FileNotFoundError as e:
        return "", f"Command not found: {cmd[0]}", -2
    except Exception as e:
        return "", str(e), -99


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─── Phase P02: File analysis (mirrors fw_bin_detector + get_fw_file_details) ─

def analyze_firmware_file(fw_path: str) -> FirmwareFileInfo:
    """
    Mirrors EMBA P02_firmware_bin_file_check.sh:
      - Computes hashes (sha512, sha1, md5)
      - Calculates Shannon entropy via `ent`
      - Runs `file` for MIME/type detection
      - Runs binwalk scan for type fingerprinting
      - Detects: squashfs, cramfs, jffs2, ubi, ext2/3/4, vmdk, uefi,
                 elf, tar/gz/zip, deb, rpm, uboot, kernel config, android OTA
    """
    p = Path(fw_path)
    info = FirmwareFileInfo(path=str(p))

    if not p.exists():
        return info

    info.size_bytes = p.stat().st_size
    info.size_human = _human_size(info.size_bytes)

    # --- Hashes ---
    sha512 = hashlib.sha512()
    sha1   = hashlib.sha1()
    md5    = hashlib.md5()
    with open(fw_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha512.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    info.sha512 = sha512.hexdigest()
    info.sha1   = sha1.hexdigest()
    info.md5    = md5.hexdigest()

    # --- Entropy via `ent` (mirrors EMBA P02 entropy check) ---
    ent_out, _, _ = _run(["ent", fw_path], timeout=30)
    entropy_match = re.search(r"Entropy\s*=\s*([\d.]+)", ent_out)
    if entropy_match:
        info.entropy = float(entropy_match.group(1))
    else:
        # Fallback: calculate entropy in Python
        import math, collections
        data = p.read_bytes()
        freq = collections.Counter(data)
        total = len(data)
        if total > 0:
            entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
            info.entropy = round(entropy, 4)

    # Entropy label (EMBA heuristic)
    if info.entropy < 1.0:
        info.entropy_label = "very_low"
    elif info.entropy < 5.0:
        info.entropy_label = "low"
    elif info.entropy < 7.0:
        info.entropy_label = "normal"
    elif info.entropy < 7.9:
        info.entropy_label = "high"
    else:
        info.entropy_label = "encrypted_or_compressed"

    # --- file command (EMBA: lFILE_BIN_OUT=$(file "${lCHECK_FILE}")) ---
    file_out, _, _ = _run(["file", "-b", fw_path])
    info.file_type = file_out

    # MIME type
    mime_out, _, _ = _run(["file", "-b", "--mime-type", fw_path])
    info.mime_type = mime_out

    # --- binwalk scan (EMBA P02: binwalk "${lCHECK_FILE}") ---
    bw_out, _, bw_rc = _run(["binwalk", fw_path], timeout=60)
    info.raw_binwalk_scan = bw_out

    # --- Firmware type detection (mirrors fw_bin_detector logic exactly) ---
    f = info.file_type.upper()
    bw = (bw_out + info.raw_binwalk_scan).upper()

    # EMBA checks in order — mirrors the if/elif chain in fw_bin_detector
    if any(k in f for k in ["SQUASHFS", "SQUASH"]):
        info.firmware_type = FirmwareType.SQUASHFS
        info.is_compressed = True
    elif "CRAMFS" in f or "CRAMFS" in bw:
        info.firmware_type = FirmwareType.CRAMFS
        info.is_compressed = True
    elif "JFFS2" in f or "JFFS2" in bw:
        info.firmware_type = FirmwareType.JFFS2
        info.is_compressed = True
    elif "UBI IMAGE" in f or "UBI" in bw:
        info.firmware_type = FirmwareType.UBI
    elif "EXT2" in f or "EXT2 FILESYSTEM" in bw:
        info.firmware_type = FirmwareType.EXT2
    elif "EXT3" in f or "EXT3 FILESYSTEM" in bw:
        info.firmware_type = FirmwareType.EXT3
    elif "EXT4" in f or "EXT4 FILESYSTEM" in bw:
        info.firmware_type = FirmwareType.EXT4
    elif "VMDK" in f or "VMDK" in bw:
        info.firmware_type = FirmwareType.VMDK
    elif "UEFI" in f or "UEFI" in bw or "BIOS" in bw:
        info.firmware_type = FirmwareType.UEFI
    elif any(k in f for k in ["ELF 32", "ELF 64", "ELF,"]):
        info.firmware_type = FirmwareType.ELF
    elif "ANDROID SPARSE IMAGE" in f or "ANDROID OTA" in bw:
        info.firmware_type = FirmwareType.ANDROID_OTA
    elif "DEBIAN BINARY PACKAGE" in f or "DEB" in mime_out.upper():
        info.firmware_type = FirmwareType.DEB
    elif "RPM PACKAGE" in f:
        info.firmware_type = FirmwareType.RPM
    elif "U-BOOT" in f or "UBOOT" in bw:
        info.firmware_type = FirmwareType.UBOOT
    elif "CPIO ARCHIVE" in f:
        info.firmware_type = FirmwareType.CPIO
    elif any(k in f for k in ["GZIP", "ZIP", "XZ", "BZIP2", "7-ZIP", "TAR", "ISO 9660"]):
        info.firmware_type = FirmwareType.ARCHIVE
        info.is_compressed = True
    elif "LINUX KERNEL VERSION" in bw:
        info.firmware_type = FirmwareType.KERNEL_CONFIG
    elif info.entropy > 7.5:
        info.firmware_type = FirmwareType.RAW_BINARY
        info.is_encrypted = True
    else:
        info.firmware_type = FirmwareType.RAW_BINARY

    # --- Architecture hint (EMBA S02 style) ---
    arch_patterns = [
        (r"ARM", "ARM"), (r"MIPS", "MIPS"), (r"x86-64|x86_64|AMD64", "x86_64"),
        (r"x86|80386|i386|i686", "x86"), (r"PowerPC|PPC", "PowerPC"),
        (r"SPARC", "SPARC"), (r"AVR", "AVR"), (r"Xtensa", "Xtensa"),
    ]
    combined = info.file_type + " " + bw_out
    for pattern, arch in arch_patterns:
        if re.search(pattern, combined, re.IGNORECASE):
            info.architecture_hint = arch
            break

    # Endianness
    if "LSB" in info.file_type or "little endian" in info.file_type.lower():
        info.endianness = "little"
    elif "MSB" in info.file_type or "big endian" in info.file_type.lower():
        info.endianness = "big"

    return info


# ─── Phase P50/P55: Extraction engines ───────────────────────────────────────

def _extract_with_binwalk(fw_path: str, output_dir: str, log_cb) -> tuple[bool, str]:
    """
    Mirrors EMBA P50_binwalk_extractor.sh binwalker_matryoshka logic.
    Uses binwalk --extract --matryoshka for recursive extraction.
    """
    log_cb(f"[binwalk] Starting extraction of {Path(fw_path).name}")
    os.makedirs(output_dir, exist_ok=True)

    out, err, rc = _run(
        ["binwalk", "--extract", "--matryoshka", "--directory", output_dir,
         "--quiet", fw_path],
        timeout=300
    )
    log_cb(f"[binwalk] Exit code: {rc}")
    if out:
        log_cb(f"[binwalk] {out[:500]}")
    if err and rc != 0:
        log_cb(f"[binwalk] stderr: {err[:300]}")

    # Check if extraction produced files
    extracted = list(Path(output_dir).rglob("*"))
    files = [f for f in extracted if f.is_file()]
    log_cb(f"[binwalk] Extracted {len(files)} files")
    return len(files) > 0, out


def _extract_with_unblob(fw_path: str, output_dir: str, log_cb) -> tuple[bool, str]:
    """
    Mirrors EMBA P55_unblob_extractor.sh.
    unblob is EMBA's primary extractor (more reliable than binwalk for modern firmware).
    """
    log_cb(f"[unblob] Starting extraction of {Path(fw_path).name}")
    os.makedirs(output_dir, exist_ok=True)

    out, err, rc = _run(
        ["unblob", "--extract-dir", output_dir, fw_path],
        timeout=300
    )
    log_cb(f"[unblob] Exit code: {rc}")
    if out:
        log_cb(f"[unblob] {out[:500]}")

    files = [f for f in Path(output_dir).rglob("*") if f.is_file()]
    log_cb(f"[unblob] Extracted {len(files)} files")
    return len(files) > 0, out


def _extract_archive(fw_path: str, output_dir: str, fw_type: FirmwareType, log_cb) -> bool:
    """
    Handle common archives: tar, gz, zip, 7z, xz, bz2, cpio.
    Mirrors EMBA P65 package extractor and P02 archive handling.
    """
    os.makedirs(output_dir, exist_ok=True)
    p = Path(fw_path)
    log_cb(f"[archive] Extracting {fw_type.value}: {p.name}")

    if fw_type == FirmwareType.DEB:
        out, err, rc = _run(["dpkg-deb", "--extract", fw_path, output_dir])
    elif fw_type == FirmwareType.RPM:
        out, err, rc = _run(["sh", "-c", f"cd {output_dir} && rpm2cpio {fw_path} | cpio -idmv"])
    elif fw_type == FirmwareType.CPIO:
        out, err, rc = _run(["sh", "-c", f"cd {output_dir} && cpio -idmv < {fw_path}"])
    else:
        # Use 7z for everything else (tar, gz, zip, xz, bz2) — mirrors EMBA approach
        out, err, rc = _run(["7z", "x", "-y", f"-o{output_dir}", fw_path], timeout=120)
        if rc != 0:
            # fallback to tar
            out, err, rc = _run(["tar", "-xf", fw_path, "-C", output_dir], timeout=60)

    files = [f for f in Path(output_dir).rglob("*") if f.is_file()]
    log_cb(f"[archive] Extracted {len(files)} files, rc={rc}")
    return len(files) > 0


def _detect_linux_filesystem(extract_dir: str) -> tuple[bool, list]:
    """
    Mirrors EMBA linux_basic_identification() — checks for typical Linux FS indicators.
    Looks for: /bin, /etc, /lib, /usr, /var, /proc, /sbin
    Returns (found, [paths_where_found])
    """
    linux_indicators = {"bin", "etc", "lib", "usr", "var", "sbin", "proc", "dev"}
    linux_paths = []
    extract_path = Path(extract_dir)

    # Walk the extraction tree
    for root, dirs, files in os.walk(extract_dir):
        rel = Path(root).relative_to(extract_path)
        dir_names = {d.lower() for d in dirs}
        if len(dir_names & linux_indicators) >= 3:
            linux_paths.append(str(rel) or "/")
            if len(linux_paths) >= 5:
                break

    # Also check if passwd/shadow/inittab exist
    for probe_file in ["etc/passwd", "etc/shadow", "etc/hostname", "bin/sh", "bin/busybox"]:
        for match in extract_path.rglob(probe_file):
            if match.exists():
                linux_paths.append(str(match.relative_to(extract_path)))

    return len(linux_paths) > 0, list(set(linux_paths))[:10]


def _build_file_tree(extract_dir: str, max_depth: int = 3) -> list:
    """
    Build a JSON-serializable tree for the frontend UI.
    Only goes max_depth levels deep to keep it manageable.
    """
    extract_path = Path(extract_dir)

    def _node(p: Path, depth: int) -> dict:
        node = {
            "name": p.name or str(p),
            "path": str(p.relative_to(extract_path)),
            "type": "dir" if p.is_dir() else "file",
        }
        if p.is_file():
            node["size"] = p.stat().st_size
            node["size_human"] = _human_size(p.stat().st_size)
        if p.is_dir() and depth < max_depth:
            children = []
            try:
                items = sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name))
                for child in items[:50]:  # limit children per dir
                    children.append(_node(child, depth + 1))
                if len(list(p.iterdir())) > 50:
                    children.append({"name": f"... and more", "type": "ellipsis"})
            except PermissionError:
                pass
            node["children"] = children
        return node

    root = extract_path
    if not root.exists():
        return []

    tree = []
    try:
        items = sorted(root.iterdir(), key=lambda x: (x.is_file(), x.name))
        for item in items[:30]:
            tree.append(_node(item, 1))
    except Exception:
        pass
    return tree


# ─── Master Extraction Engine ─────────────────────────────────────────────────

def run_extraction(
    fw_path: str,
    job_id: str,
    progress_callback=None,
) -> ExtractionResult:
    """
    Master extraction function — called by FastAPI endpoint.
    Mirrors EMBA's full P02 → P50/P55 → P60 pipeline:
      1. Analyze file (P02)
      2. Try unblob first (P55 — EMBA primary)
      3. Fall back to binwalk (P50 — EMBA secondary)
      4. Handle special types: deb, rpm, cpio, archives (P65)
      5. Detect Linux filesystem (P99 linux_basic_identification)
      6. Build file tree for UI
    """
    def log(msg: str):
        logger.info(msg)
        if result.log is not None:
            result.log.append({"ts": datetime.now(timezone.utc).isoformat(), "msg": msg})
        if progress_callback:
            progress_callback({"event": "log", "job_id": job_id, "message": msg})

    def progress(pct: int, step: str):
        result.progress = pct
        if progress_callback:
            progress_callback({"event": "progress", "job_id": job_id, "percent": pct, "step": step})

    result = ExtractionResult(
        job_id=job_id,
        started_at=datetime.now(timezone.utc).isoformat(),
        status=ExtractionStatus.RUNNING,
    )

    # Output dir: /tmp/iifvdcas_extractions/<job_id>/
    output_dir = str(EXTRACT_BASE / job_id)
    os.makedirs(output_dir, exist_ok=True)
    result.output_dir = output_dir

    try:
        # ── Step 1: Analyze file (P02) ────────────────────────────────────
        progress(5, "Analyzing firmware file")
        log(f"[P02] Analyzing firmware: {fw_path}")
        info = analyze_firmware_file(fw_path)
        result.firmware_info = info
        log(f"[P02] Type: {info.firmware_type.value} | Entropy: {info.entropy:.3f} ({info.entropy_label})")
        log(f"[P02] File: {info.file_type[:100]}")
        log(f"[P02] Size: {info.size_human} | MD5: {info.md5[:16]}...")
        progress(15, "File analysis complete")

        # ── Step 2: Choose extractor (EMBA priority order) ────────────────
        extracted = False
        fw_type = info.firmware_type

        if fw_type in (FirmwareType.DEB, FirmwareType.RPM, FirmwareType.CPIO):
            # Package extractor (P65)
            progress(20, f"Extracting {fw_type.value}")
            log(f"[P65] Using package extractor for {fw_type.value}")
            pkg_dir = os.path.join(output_dir, "package_extracted")
            extracted = _extract_archive(fw_path, pkg_dir, fw_type, log)
            result.extractor_used = "package_extractor"

        elif fw_type == FirmwareType.ARCHIVE:
            # Archive extractor
            progress(20, "Extracting archive")
            log("[P02] Archive detected — using 7z/tar extractor")
            arc_dir = os.path.join(output_dir, "archive_extracted")
            extracted = _extract_archive(fw_path, arc_dir, fw_type, log)
            result.extractor_used = "archive_7z"

        elif fw_type in (FirmwareType.EXT2, FirmwareType.EXT3, FirmwareType.EXT4):
            # EXT filesystem mounter (P14)
            progress(20, f"Mounting {fw_type.value}")
            log(f"[P14] EXT filesystem — using dd + debugfs")
            ext_dir = os.path.join(output_dir, "ext_extracted")
            os.makedirs(ext_dir, exist_ok=True)
            out, err, rc = _run(
                ["debugfs", "-R", f"rdump / {ext_dir}", fw_path], timeout=60
            )
            if rc == 0:
                extracted = True
                result.extractor_used = "debugfs"
                log(f"[P14] debugfs extraction done")
            else:
                log(f"[P14] debugfs failed, falling back to unblob")
                extracted, _ = _extract_with_unblob(fw_path, ext_dir, log)
                result.extractor_used = "unblob_fallback"

        else:
            # Primary: unblob (P55 — EMBA's preferred extractor)
            progress(20, "Extracting with unblob (primary)")
            unblob_dir = os.path.join(output_dir, "unblob_extracted")
            log("[P55] Trying unblob (EMBA primary extractor)")
            unblob_ok, _ = _extract_with_unblob(fw_path, unblob_dir, log)

            if unblob_ok:
                extracted = True
                result.extractor_used = "unblob"
                log("[P55] unblob extraction succeeded")
                progress(50, "unblob extraction complete")
            else:
                # Fallback: binwalk (P50 — EMBA secondary)
                log("[P55] unblob found nothing — trying binwalk (P50 fallback)")
                progress(35, "Fallback: extracting with binwalk")
                binwalk_dir = os.path.join(output_dir, "binwalk_extracted")
                bw_ok, _ = _extract_with_binwalk(fw_path, binwalk_dir, log)

                if bw_ok:
                    extracted = True
                    result.extractor_used = "binwalk"
                    log("[P50] binwalk extraction succeeded")
                    progress(50, "binwalk extraction complete")
                else:
                    log("[P60] Both unblob and binwalk found nothing — firmware may be raw binary")
                    result.extractor_used = "none"
                    result.status = ExtractionStatus.PARTIAL
                    progress(50, "No extractor succeeded")

        # ── Step 3: Count extracted files ─────────────────────────────────
        progress(60, "Counting extracted files")
        all_files = list(Path(output_dir).rglob("*"))
        result.total_files = sum(1 for f in all_files if f.is_file())
        result.total_dirs  = sum(1 for f in all_files if f.is_dir())
        result.total_size_bytes = sum(
            f.stat().st_size for f in all_files if f.is_file() and not f.is_symlink()
        )
        log(f"[P99] Total: {result.total_files} files, {result.total_dirs} dirs, {_human_size(result.total_size_bytes)}")

        # ── Step 4: Linux filesystem detection (P99 linux_basic_identification) ─
        progress(75, "Detecting Linux filesystem structure")
        linux_found, linux_paths = _detect_linux_filesystem(output_dir)
        result.linux_found = linux_found
        result.linux_paths = linux_paths
        if linux_found:
            result.filesystem_type = "linux"
            log(f"[P99] ✅ Linux filesystem detected at: {linux_paths[:3]}")
        else:
            log("[P99] No Linux filesystem structure detected")

        # ── Step 5: Build file tree for UI ────────────────────────────────
        progress(85, "Building file tree")
        result.file_tree = _build_file_tree(output_dir)
        log(f"[UI] File tree built: {len(result.file_tree)} top-level entries")

        # ── Step 6: Finalize ──────────────────────────────────────────────
        progress(100, "Extraction complete")
        result.status = ExtractionStatus.SUCCESS if extracted else ExtractionStatus.PARTIAL
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[DONE] Status: {result.status.value} | Extractor: {result.extractor_used}")

    except Exception as e:
        logger.exception("Extraction failed")
        result.status = ExtractionStatus.FAILED
        result.error = str(e)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        log(f"[ERROR] {e}")

    return result


def cleanup_extraction(job_id: str):
    """Remove extracted files for a job."""
    job_dir = EXTRACT_BASE / job_id
    if job_dir.exists():
        shutil.rmtree(str(job_dir), ignore_errors=True)
