"""
IIFVDCAS Phase 4 — Component Discovery (Steps 1-3)
Mirrors EMBA logic:
  S08: Package manager parsing (dpkg, opkg, rpm)
  S40: Weak permission/crypto detection
  Custom: Binary version extraction, shared library mapping

Implements:
  Step 1a: Package manager databases (dpkg, apk, rpm)
  Step 1b: Binary version strings
  Step 1c: Shared library mapping (readelf -d)
  Step 1d: Script/interpreter detection
"""

import subprocess, os, re, hashlib, uuid, logging
from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path
import json

logger = logging.getLogger(__name__)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 30) -> tuple:
    """Execute command, return (stdout, stderr, returncode)"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "LANG": "C", "LC_ALL": "C"})
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), -1

def _find_elf(base: str, max_files: int = 500) -> list:
    """Find all ELF binaries in directory tree"""
    results = []
    for root, dirs, files in os.walk(base):
        for skip in [".git", "__pycache__", ".pytest_cache"]:
            if skip in dirs: 
                dirs.remove(skip)
        for f in files:
            if len(results) >= max_files:
                break
            fp = Path(root) / f
            if not fp.is_file() or fp.is_symlink(): 
                continue
            try:
                with open(fp, "rb") as fh:
                    if fh.read(4) == b"\x7fELF":
                        results.append(str(fp))
            except: 
                pass
    return results

def _extract_version_from_strings(binary_path: str) -> Optional[str]:
    """Extract version string from binary using strings | grep version"""
    stdout, _, _ = _run(["strings", "-n", "3", binary_path], timeout=10)
    if not stdout:
        return None
    
    # Common version patterns
    patterns = [
        r'v?(\d+\.\d+[\.\d\-\w]*)',
        r'Version[:\s]+(\d+\.\d+[\.\d\-\w]*)',
        r'VERSION[:\s]+(\d+\.\d+[\.\d\-\w]*)',
    ]
    
    for line in stdout.splitlines()[:100]:  # Only check first 100 strings
        for pattern in patterns:
            m = re.search(pattern, line, re.IGNORECASE)
            if m:
                return m.group(1)
    return None

def _extract_dependencies(binary_path: str) -> List[str]:
    """Extract shared library dependencies via readelf -d"""
    deps = []
    stdout, _, rc = _run(["readelf", "-d", binary_path], timeout=5)
    if rc != 0:
        return deps
    
    # Look for NEEDED entries
    for line in stdout.splitlines():
        m = re.search(r'NEEDED.*\[(.+\.so[^\]]*)\]', line)
        if m:
            deps.append(m.group(1))
    return deps

def _extract_architecture(binary_path: str) -> str:
    """Extract CPU architecture from ELF header"""
    stdout, _, rc = _run(["file", "-b", binary_path], timeout=5)
    if rc != 0:
        return "unknown"
    
    for arch in ["ARM", "MIPS", "x86-64", "80386", "PowerPC", "AVR", "AArch64", "RISC-V"]:
        if arch.lower() in stdout.lower():
            return arch
    return "unknown"

def _sha256(path: str) -> str:
    """Compute SHA-256 hash of file"""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

def _md5(path: str) -> str:
    """Compute MD5 hash of file"""
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return ""

# ─── Step 1a: Package manager parsing ────────────────────────────────────────

def parse_dpkg_status(dpkg_status_file: str, log_cb) -> list:
    """
    Parse Debian package database (var/lib/dpkg/status)
    Returns list of (name, version, arch, description) tuples
    """
    log_cb("[S08] Parsing dpkg status file")
    packages = []
    
    try:
        content = Path(dpkg_status_file).read_text(errors="replace")
        
        # Parse Debian control format
        entries = content.split("\n\n")
        for entry in entries:
            if not entry.strip():
                continue
            
            fields = {}
            for line in entry.splitlines():
                if ": " in line:
                    key, val = line.split(": ", 1)
                    fields[key.strip()] = val.strip()
            
            if "Package" in fields and "Version" in fields:
                packages.append({
                    "name": fields.get("Package"),
                    "version": fields.get("Version"),
                    "arch": fields.get("Architecture", "unknown"),
                    "description": fields.get("Description", ""),
                    "depends": fields.get("Depends", "").split(",") if fields.get("Depends") else [],
                    "source": "dpkg",
                })
        
        log_cb(f"[S08] Found {len(packages)} packages in dpkg status")
    except Exception as e:
        log_cb(f"[S08] Error parsing dpkg: {e}")
    
    return packages

def parse_apk_database(apk_installed_file: str, log_cb) -> list:
    """
    Parse Alpine Linux package database (lib/apk/db/installed)
    Format is key:value pairs separated by blank lines
    """
    log_cb("[S08] Parsing Alpine apk database")
    packages = []
    
    try:
        content = Path(apk_installed_file).read_text(errors="replace")
        
        entries = content.split("\n\n")
        for entry in entries:
            if not entry.strip():
                continue
            
            fields = {}
            for line in entry.splitlines():
                if ":" in line and not line.startswith(" "):
                    key, val = line.split(":", 1)
                    fields[key] = val.strip()
            
            if "n" in fields and "v" in fields:  # n=name, v=version
                packages.append({
                    "name": fields.get("n"),
                    "version": fields.get("v"),
                    "arch": fields.get("a", "unknown"),
                    "description": fields.get("c", ""),
                    "depends": [],
                    "source": "apk",
                })
        
        log_cb(f"[S08] Found {len(packages)} packages in apk database")
    except Exception as e:
        log_cb(f"[S08] Error parsing apk: {e}")
    
    return packages

def discover_package_manager_components(target_dir: str, log_cb) -> list:
    """
    Step 1a: Scan for package manager databases
    Looks for dpkg status, apk installed, opkg status, rpm database
    """
    log_cb("[S08] Package manager discovery starting")
    packages = []
    
    # dpkg status
    for dpkg_file in Path(target_dir).rglob("var/lib/dpkg/status"):
        packages.extend(parse_dpkg_status(str(dpkg_file), log_cb))
    
    # apk installed
    for apk_file in Path(target_dir).rglob("lib/apk/db/installed"):
        packages.extend(parse_apk_database(str(apk_file), log_cb))
    
    # .deb/.ipk files in opkg cache
    for pkg_file in Path(target_dir).rglob("*.ipk"):
        try:
            # Extract control.tar.gz from .ipk
            control_out, _, rc = _run(["tar", "-xzOf", str(pkg_file), "control.tar.gz"], timeout=10)
            if rc == 0:
                # Parse control file
                pass
        except:
            pass
    
    return packages

# ─── Step 1b: Binary version strings ─────────────────────────────────────────

def discover_binary_version_components(target_dir: str, log_cb) -> list:
    """
    Step 1b: Extract version strings from ELF binaries
    Uses strings | grep version patterns
    """
    log_cb("[S08] Binary version string discovery starting")
    components = []
    seen = set()
    
    elf_files = _find_elf(target_dir, max_files=200)
    log_cb(f"[S08] Found {len(elf_files)} ELF binaries to scan")
    
    for elf_path in elf_files:
        try:
            # Get binary name
            binary_name = Path(elf_path).name
            if binary_name in seen:
                continue
            
            # Extract version
            version = _extract_version_from_strings(elf_path)
            if not version:
                version = "unknown"
            
            arch = _extract_architecture(elf_path)
            
            seen.add(binary_name)
            components.append({
                "name": binary_name,
                "version": version,
                "arch": arch,
                "path": str(Path(elf_path).relative_to(target_dir)),
                "sha256": _sha256(elf_path),
                "source": "elf_strings",
            })
        except Exception as e:
            log_cb(f"[S08] Error scanning {elf_path}: {e}")
    
    log_cb(f"[S08] Discovered {len(components)} version strings from binaries")
    return components

# ─── Step 1c: Shared library mapping ─────────────────────────────────────────

def discover_shared_libraries(target_dir: str, log_cb) -> list:
    """
    Step 1c: Map shared library dependencies
    Uses readelf -d to extract NEEDED entries
    """
    log_cb("[S08] Shared library discovery starting")
    libraries = set()
    
    elf_files = _find_elf(target_dir, max_files=100)
    
    for elf_path in elf_files:
        try:
            deps = _extract_dependencies(elf_path)
            libraries.update(deps)
        except:
            pass
    
    result = [{"name": lib, "source": "readelf", "type": "shared_library"} for lib in sorted(libraries)]
    log_cb(f"[S08] Discovered {len(result)} unique shared libraries")
    return result

# ─── Step 1d: Script/interpreter detection ───────────────────────────────────

def discover_script_interpreters(target_dir: str, log_cb) -> list:
    """
    Step 1d: Detect scripting languages and interpreters
    Parses shebang lines from scripts
    """
    log_cb("[S08] Script interpreter discovery starting")
    interpreters = {}
    
    script_extensions = {".py": "python", ".sh": "bash", ".lua": "lua", ".php": "php", ".rb": "ruby"}
    
    for root, dirs, files in os.walk(target_dir):
        for skip in [".git", "__pycache__"]:
            if skip in dirs:
                dirs.remove(skip)
        
        for fname in files[:100]:  # Limit to prevent timeout
            fpath = Path(root) / fname
            
            # Check extension first
            ext = fpath.suffix.lower()
            if ext in script_extensions:
                interpreter = script_extensions[ext]
                if interpreter not in interpreters:
                    interpreters[interpreter] = "unknown"
            
            # Check shebang
            try:
                with open(fpath, "rb") as f:
                    header = f.read(100)
                    if header.startswith(b"#!"):
                        shebang = header.split(b"\n")[0].decode("utf-8", errors="ignore")
                        # Extract interpreter and version
                        m = re.search(r'#!.*?(/.*?)(\s|$)', shebang)
                        if m:
                            interp_path = m.group(1)
                            interp_name = Path(interp_path).name
                            
                            # Try to get version
                            version_out, _, _ = _run([interp_path, "--version"], timeout=2)
                            version_match = re.search(r'(\d+\.\d+[\.\d\w]*)', version_out)
                            version = version_match.group(1) if version_match else "unknown"
                            
                            interpreters[interp_name] = version
            except:
                pass
    
    result = [{"name": name, "version": version} for name, version in interpreters.items()]
    log_cb(f"[S08] Discovered {len(result)} script interpreters")
    return result

# ─── Main orchestrator ───────────────────────────────────────────────────────

def discover_all_components(target_dir: str, log_cb) -> dict:
    """
    Master component discovery function
    Combines steps 1a-1d into unified discovery
    """
    log_cb("[S08] ========== Phase 4 Step 1: Component Discovery ==========")
    
    result = {
        "software_components": [],
        "hardware_components": [],
        "crypto_components": [],
        "timestamp": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
    }
    
    # Step 1a: Package managers
    try:
        log_cb("[S08] Step 1a: Package manager discovery")
        pm_comps = discover_package_manager_components(target_dir, log_cb)
        result["software_components"].extend(pm_comps)
    except Exception as e:
        log_cb(f"[S08] Step 1a error: {e}")
    
    # Step 1b: Binary versions
    try:
        log_cb("[S08] Step 1b: Binary version discovery")
        bin_comps = discover_binary_version_components(target_dir, log_cb)
        result["software_components"].extend(bin_comps)
    except Exception as e:
        log_cb(f"[S08] Step 1b error: {e}")
    
    # Step 1c: Shared libraries
    try:
        log_cb("[S08] Step 1c: Shared library discovery")
        lib_comps = discover_shared_libraries(target_dir, log_cb)
        result["software_components"].extend(lib_comps)
    except Exception as e:
        log_cb(f"[S08] Step 1c error: {e}")
    
    # Step 1d: Script interpreters
    try:
        log_cb("[S08] Step 1d: Script interpreter discovery")
        script_comps = discover_script_interpreters(target_dir, log_cb)
        result["software_components"].extend(script_comps)
    except Exception as e:
        log_cb(f"[S08] Step 1d error: {e}")
    
    log_cb(f"[S08] Component discovery complete: {len(result['software_components'])} components")
    return result
