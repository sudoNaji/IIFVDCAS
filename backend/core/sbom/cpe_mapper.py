"""
IIFVDCAS Phase 4 — CPE/PURL Identifier Generation (Step 4)
Generates Common Platform Enumeration (CPE) 2.3 and Package URL (PURL) identifiers
for CVE mapping in Phase 5.

References:
  CPE 2.3: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-188.pdf
  PURL:    https://github.com/package-url/purl-spec
"""

import re
from typing import Optional, Tuple
from urllib.parse import quote

# ─── CPE 2.3 URI Format Binding ──────────────────────────────────────────────
# cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

# Known vendor/product mappings
VENDOR_MAPPINGS = {
    "busybox": ("busybox", "busybox"),
    "openssl": ("openssl", "openssl"),
    "openssh": ("openssh", "openssh"),
    "dropbear": ("matt_johnston", "dropbear"),
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "httpd"),
    "curl": ("curl", "curl"),
    "wget": ("gnu", "wget"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "mosquitto": ("eclipse", "mosquitto"),
    "avahi": ("avahi_project", "avahi"),
    "python": ("python", "python"),
    "perl": ("perl", "perl"),
    "ruby": ("ruby_lang", "ruby"),
    "node": ("nodejs", "node.js"),
    "lua": ("lua", "lua"),
    "php": ("php", "php"),
    "bash": ("gnu", "bash"),
    "sqlite": ("sqlite", "sqlite"),
    "libcrypto": ("openssl", "openssl"),
    "libssl": ("openssl", "openssl"),
    "libc": ("gnu", "libc"),
    "uclibc": ("uclibc_ng", "uclibc"),
    "musl": ("musl_libc", "musl"),
    "glibc": ("gnu", "glibc"),
    "atmel": ("atmel", None),
    "espressif": ("espressif", None),
    "stmicroelectronics": ("stmicroelectronics", None),
}

# Package manager to ecosystem mapping
ECOSYSTEM_MAPPING = {
    "dpkg": "deb",
    "apk": "apk",
    "rpm": "rpm",
    "opkg": "ipk",
    "pacman": "pacman",
    "elf_strings": "generic",
    "avr": "generic",
    "unknown": "generic",
}

# ─── CPE Generation ─────────────────────────────────────────────────────────

def normalize_cpe_value(value: str) -> str:
    """
    Normalize value for CPE 2.3 binding.
    Removes special characters, lowercases, handles wildcards.
    """
    if not value or value == "*" or value.lower() == "unknown":
        return "*"
    
    # Lowercase
    value = value.lower()
    
    # Remove problematic characters
    value = re.sub(r'[^a-z0-9\.\-_]', '_', value)
    
    # Remove trailing dots
    value = value.rstrip(".")
    
    return value if value else "*"

def generate_cpe(
    part: str,
    vendor: str,
    product: str,
    version: str = "*",
    update: str = "*",
    edition: str = "*",
    language: str = "*",
    sw_edition: str = "*",
    target_sw: str = "*",
    target_hw: str = "*",
    other: str = "*"
) -> str:
    """
    Generate CPE 2.3 URI binding.
    part: "a" (application), "h" (hardware), "o" (operating system)
    """
    parts = [
        normalize_cpe_value(p) for p in [
            part, vendor, product, version, update, edition, language,
            sw_edition, target_sw, target_hw, other
        ]
    ]
    
    return "cpe:2.3:" + ":".join(parts)

def infer_cpe_from_name_version(name: str, version: str = "*", source: str = "generic") -> Tuple[str, str, str]:
    """
    Attempt to infer vendor and product from component name.
    Returns (vendor, product, confidence)
    """
    name_lower = name.lower().strip()
    
    # Direct lookups
    if name_lower in VENDOR_MAPPINGS:
        vendor, product = VENDOR_MAPPINGS[name_lower]
        return vendor or name_lower, product or name_lower, "high"
    
    # Prefix matches
    for key, (vendor, product) in VENDOR_MAPPINGS.items():
        if name_lower.startswith(key):
            return vendor, product or name_lower, "medium"
    
    # Common patterns
    patterns = [
        (r'^(lib)(.+)', r'\2'),  # libfoo -> foo
        (r'^(python|py)(.+)', r'\2'),  # pyfoo -> foo
        (r'^(ruby|rb)(.+)', r'\2'),  # rbfoo -> foo
    ]
    
    for pattern, replacement in patterns:
        m = re.match(pattern, name_lower)
        if m:
            product = re.sub(pattern, replacement, name_lower)
            return name_lower, product, "low"
    
    # Fallback
    return name_lower, name_lower, "low"

def generate_cpe_for_component(component: dict, source_type: str = "generic") -> dict:
    """
    Generate CPE 2.3 URI for a component.
    component: {name, version, arch, ...}
    """
    name = component.get("name", "unknown")
    version = component.get("version", "*")
    
    # Infer vendor/product
    vendor, product, conf = infer_cpe_from_name_version(name, version)
    
    # Determine part (default: application)
    part = "a"  # application
    if component.get("source") in ("hardware", "avr", "device"):
        part = "h"  # hardware
    
    # Generate CPE
    cpe = generate_cpe(
        part=part,
        vendor=vendor,
        product=product,
        version=normalize_cpe_value(version),
        language="*",
    )
    
    return {
        **component,
        "cpe": cpe,
        "cpe_confidence": conf,
    }

# ─── PURL Generation ────────────────────────────────────────────────────────

def generate_purl(
    ecosystem: str,
    name: str,
    version: str = None,
    namespace: str = None,
    qualifiers: dict = None,
    subpath: str = None
) -> str:
    """
    Generate Package URL (PURL) identifier.
    Format: pkg:ecosystem/namespace/name@version?key=value#subpath
    """
    if not ecosystem or not name:
        return ""
    
    # Normalize ecosystem
    ecosystem = ecosystem.lower().strip()
    
    # Build PURL
    purl = f"pkg:{ecosystem}"
    
    if namespace:
        purl += f"/{quote(namespace)}"
    
    purl += f"/{quote(name)}"
    
    if version:
        purl += f"@{quote(version)}"
    
    if qualifiers:
        qs = "&".join(f"{k}={quote(str(v))}" for k, v in sorted(qualifiers.items()))
        purl += f"?{qs}"
    
    if subpath:
        purl += f"#{quote(subpath)}"
    
    return purl

def generate_purl_for_component(component: dict, package_manager: str = "generic") -> dict:
    """
    Generate PURL for a component.
    component: {name, version, arch, source, ...}
    """
    name = component.get("name", "unknown")
    version = component.get("version")
    ecosystem = ECOSYSTEM_MAPPING.get(package_manager, "generic")
    
    # Build qualifiers
    qualifiers = {}
    if component.get("arch") and component.get("arch") != "unknown":
        qualifiers["arch"] = component.get("arch")
    
    # Generate PURL
    purl = generate_purl(
        ecosystem=ecosystem,
        name=name,
        version=version,
        qualifiers=qualifiers if qualifiers else None,
    )
    
    return {
        **component,
        "purl": purl,
    }

# ─── Main orchestrator ───────────────────────────────────────────────────────

def generate_identifiers(component: dict, package_manager: str = "generic") -> dict:
    """
    Generate both CPE and PURL identifiers for a component.
    This is Step 4 of Phase 4.
    """
    result = component.copy()
    
    # Generate CPE
    cpe_result = generate_cpe_for_component(component)
    result["cpe"] = cpe_result.get("cpe")
    result["cpe_confidence"] = cpe_result.get("cpe_confidence")
    
    # Generate PURL
    purl_result = generate_purl_for_component(component, package_manager)
    result["purl"] = purl_result.get("purl")
    
    return result

def generate_identifiers_batch(components: list, package_manager: str = "generic", log_cb=None) -> list:
    """
    Generate CPE/PURL for batch of components.
    """
    if log_cb:
        log_cb(f"[CPE/PURL] Generating identifiers for {len(components)} components")
    
    result = []
    for comp in components:
        try:
            comp_with_ids = generate_identifiers(comp, package_manager)
            result.append(comp_with_ids)
        except Exception as e:
            if log_cb:
                log_cb(f"[CPE/PURL] Error processing {comp.get('name')}: {e}")
            result.append(comp)  # Add original if processing fails
    
    return result

# ─── Utility functions ──────────────────────────────────────────────────────

def extract_cve_search_terms(component: dict) -> list:
    """
    Extract search terms for CVE mapping.
    Returns list of (cpe, purl, vendor:product:version) tuples to search Phase 5.
    """
    terms = []
    
    if component.get("cpe"):
        terms.append(("cpe", component["cpe"]))
    
    if component.get("purl"):
        terms.append(("purl", component["purl"]))
    
    # Direct vendor:product:version
    vendor = component.get("vendor", component.get("name", ""))
    product = component.get("product", component.get("name", ""))
    version = component.get("version", "*")
    terms.append(("versionless", f"{vendor}:{product}:{version}"))
    
    return terms

def parse_cpe(cpe_string: str) -> dict:
    """Parse CPE string back into components."""
    if not cpe_string.startswith("cpe:2.3:"):
        return {}
    
    parts = cpe_string.split(":")
    if len(parts) < 11:
        return {}
    
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5] if len(parts) > 5 else "*",
        "update": parts[6] if len(parts) > 6 else "*",
    }

def parse_purl(purl_string: str) -> dict:
    """Parse PURL string back into components."""
    if not purl_string.startswith("pkg:"):
        return {}
    
    m = re.match(r'pkg:([^/]+)(?:/([^/]+))?/([^@#?]+)(?:@([^#?]+))?(?:\?([^#]+))?(?:#(.+))?', purl_string)
    if not m:
        return {}
    
    return {
        "ecosystem": m.group(1),
        "namespace": m.group(2),
        "name": m.group(3),
        "version": m.group(4),
        "qualifiers": m.group(5),
        "subpath": m.group(6),
    }
