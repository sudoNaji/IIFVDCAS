"""
IIFVDCAS Phase 4 — CycloneDX/HBOM/CBOM JSON Generation (Steps 5-7)
Generates standardized BOMs in CycloneDX 1.5 and SPDX 2.3 formats

Steps:
  Step 5: build_sbom_json() - Generate CycloneDX 1.5 Software BOM
  Step 6: build_hbom_json() - Generate Hardware BOM
  Step 7: build_cbom_json() - Generate Cryptography BOM
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from pathlib import Path

# ─── CycloneDX 1.5 SBOM Generation (Step 5) ────────────────────────────────

def build_sbom_json(
    components: List[dict],
    metadata: Optional[dict] = None,
    firmware_path: str = "",
    toolchain: Optional[dict] = None,
    license_summary: Optional[dict] = None,
) -> dict:
    """
    Step 5: Generate CycloneDX 1.5 Software Bill of Materials
    
    Returns complete CycloneDX structure with:
      - bomFormat, specVersion, $schema, serialNumber
      - metadata (component, tools, timestamp)
      - components array with all software packages
      - hashes, CPE, PURL for all components
    """
    
    # Build component objects for CycloneDX
    cyclonedx_components = []
    for comp in components:
        bom_ref = comp.get("bom_ref") or f"pkg-{uuid.uuid4()}"
        
        cdx_comp = {
            "bom-ref": bom_ref,
            "type": comp.get("type", "library"),
            "name": comp.get("name", "unknown"),
        }
        
        if comp.get("version"):
            cdx_comp["version"] = comp.get("version")
        
        # Supplier
        if comp.get("supplier") or comp.get("vendor"):
            cdx_comp["supplier"] = {
                "name": comp.get("supplier") or comp.get("vendor", "Unknown"),
            }
        
        # Licenses
        if comp.get("license"):
            cdx_comp["licenses"] = [
                {"license": {"name": comp.get("license")}}
            ]
        
        # Hashes (SHA-256 primary, MD5 secondary)
        hashes = []
        if comp.get("sha256"):
            hashes.append({
                "alg": "SHA-256",
                "content": comp.get("sha256"),
            })
        if comp.get("md5"):
            hashes.append({
                "alg": "MD5",
                "content": comp.get("md5"),
            })
        if hashes:
            cdx_comp["hashes"] = hashes
        
        # CPE
        if comp.get("cpe"):
            cdx_comp["cpe"] = comp.get("cpe")
        
        # PURL
        if comp.get("purl"):
            cdx_comp["purl"] = comp.get("purl")
        
        # Description/source
        if comp.get("description"):
            cdx_comp["description"] = comp.get("description")
        
        # Properties (custom data)
        properties = []
        if comp.get("source_path"):
            properties.append({
                "name": "source_path",
                "value": comp.get("source_path"),
            })
        if comp.get("architecture"):
            properties.append({
                "name": "architecture",
                "value": comp.get("architecture"),
            })
        if comp.get("cpe_confidence"):
            properties.append({
                "name": "cpe_confidence",
                "value": comp.get("cpe_confidence"),
            })
        if properties:
            cdx_comp["properties"] = properties
        
        cyclonedx_components.append(cdx_comp)
    
    # Build metadata
    cdx_metadata = {
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "component": {
            "bom-ref": "root",
            "type": "device",
            "name": Path(firmware_path).name if firmware_path else "Firmware",
            "description": "Firmware device analysis",
        },
    }
    
    # Add tools info
    tools = [
        {
            "vendor": "IIFVDCAS",
            "name": "Phase 4 - SBOM Generator",
            "version": "1.0.0",
        }
    ]
    if toolchain and toolchain.get("gcc_version"):
        tools.append({
            "vendor": "GNU",
            "name": "GCC",
            "version": toolchain.get("gcc_version"),
        })
    if toolchain:
        cdx_metadata["tools"] = tools
    
    # License summary as metadata properties
    if license_summary:
        properties = []
        for lic_name, count in license_summary.items():
            properties.append({
                "name": f"license_{lic_name}",
                "value": str(count),
            })
        if properties:
            cdx_metadata["properties"] = properties
    
    # Build full CycloneDX document
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": cdx_metadata,
        "components": cyclonedx_components,
    }
    
    return sbom

# ─── Hardware BOM Generation (Step 6) ──────────────────────────────────────

def build_hbom_json(hw_components: List[dict]) -> dict:
    """
    Step 6: Generate Hardware Bill of Materials
    
    Hardware component properties:
      - component_type: microcontroller, sensor, radio, memory, SoC, etc.
      - flash_size_kb, ram_size_kb
      - architecture, bit_width
      - manufacturer, model, datasheet
    """
    
    hbom_components = []
    for hw in hw_components:
        bom_ref = hw.get("bom_ref") or f"hw-{uuid.uuid4()}"
        
        hbom_comp = {
            "bom-ref": bom_ref,
            "type": "hardware",
            "name": hw.get("name", "unknown"),
            "manufacturer": hw.get("manufacturer", "Unknown"),
        }
        
        if hw.get("model"):
            hbom_comp["model"] = hw.get("model")
        
        if hw.get("version"):
            hbom_comp["version"] = hw.get("version")
        
        if hw.get("description"):
            hbom_comp["description"] = hw.get("description")
        
        # Properties for hardware-specific data
        properties = []
        
        hw_type = hw.get("component_type", "unknown")
        properties.append({"name": "type", "value": hw_type})
        
        if hw.get("flash_size_kb"):
            properties.append({
                "name": "flash_size_kb",
                "value": str(hw.get("flash_size_kb")),
            })
        
        if hw.get("ram_size_kb"):
            properties.append({
                "name": "ram_size_kb",
                "value": str(hw.get("ram_size_kb")),
            })
        
        if hw.get("architecture"):
            properties.append({
                "name": "architecture",
                "value": hw.get("architecture"),
            })
        
        if hw.get("bit_width"):
            properties.append({
                "name": "bit_width",
                "value": str(hw.get("bit_width")),
            })
        
        if hw.get("datasheet_url"):
            properties.append({
                "name": "datasheet_url",
                "value": hw.get("datasheet_url"),
            })
        
        if hw.get("pin_count"):
            properties.append({
                "name": "pin_count",
                "value": str(hw.get("pin_count")),
            })
        
        if hw.get("operating_voltage"):
            properties.append({
                "name": "operating_voltage",
                "value": hw.get("operating_voltage"),
            })
        
        if properties:
            hbom_comp["properties"] = properties
        
        hbom_components.append(hbom_comp)
    
    # Build HBOM structure
    hbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "component": {
                "type": "device",
                "name": "Hardware Components",
                "description": "Hardware Bill of Materials",
            },
            "tools": [
                {
                    "vendor": "IIFVDCAS",
                    "name": "Hardware BOM Generator",
                    "version": "1.0.0",
                }
            ],
        },
        "components": hbom_components,
    }
    
    return hbom

# ─── Cryptography BOM Generation (Step 7) ─────────────────────────────────

def build_cbom_json(crypto_components: List[dict]) -> dict:
    """
    Step 7: Generate Cryptography Bill of Materials
    
    Strength classifications:
      - strong: AES-256, TLS 1.3, ChaCha20, RSA-4096
      - acceptable: AES-128/192, TLS 1.2, RSA-2048, SHA-256, SHA-512
      - weak: SHA-1, 3DES, TLS 1.1
      - insecure: DES, RC4, MD5, SSL, TLS 1.0
    """
    
    cbom_components = []
    weakness_summary = {"strong": 0, "acceptable": 0, "weak": 0, "insecure": 0}
    
    for crypto in crypto_components:
        bom_ref = crypto.get("bom_ref") or f"crypto-{uuid.uuid4()}"
        
        cbom_comp = {
            "bom-ref": bom_ref,
            "type": "cryptographic-asset",
            "name": crypto.get("algorithm", "unknown"),
        }
        
        # Category (e.g., "cipher", "hash", "key-agreement", "signature")
        category = crypto.get("category", "unknown")
        if category:
            cbom_comp["classification"] = category
        
        # Strength classification
        strength = crypto.get("strength", "unknown")
        cbom_comp["strength"] = strength
        weakness_summary[strength] = weakness_summary.get(strength, 0) + 1
        
        if crypto.get("description"):
            cbom_comp["description"] = crypto.get("description")
        
        # Properties
        properties = []
        
        if crypto.get("key_size"):
            properties.append({
                "name": "key_size_bits",
                "value": str(crypto.get("key_size")),
            })
        
        if crypto.get("source_file"):
            properties.append({
                "name": "source_file",
                "value": crypto.get("source_file"),
            })
        
        if crypto.get("context"):
            properties.append({
                "name": "context",
                "value": crypto.get("context"),
            })
        
        # Flags for weak/insecure
        if strength == "weak":
            properties.append({
                "name": "warning",
                "value": "Weak algorithm - consider replacement",
            })
        elif strength == "insecure":
            properties.append({
                "name": "critical",
                "value": "Insecure algorithm - immediate replacement required",
            })
        
        if properties:
            cbom_comp["properties"] = properties
        
        cbom_components.append(cbom_comp)
    
    # Build CBOM structure with summary
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "component": {
                "type": "device",
                "name": "Cryptographic Assets",
                "description": "Cryptography Bill of Materials",
            },
            "tools": [
                {
                    "vendor": "IIFVDCAS",
                    "name": "Crypto BOM Generator",
                    "version": "1.0.0",
                }
            ],
            "properties": [
                {"name": "strength_summary_strong", "value": str(weakness_summary["strong"])},
                {"name": "strength_summary_acceptable", "value": str(weakness_summary["acceptable"])},
                {"name": "strength_summary_weak", "value": str(weakness_summary["weak"])},
                {"name": "strength_summary_insecure", "value": str(weakness_summary["insecure"])},
            ],
        },
        "components": cbom_components,
    }
    
    return cbom

# ─── SPDX 2.3 Export (Alternative Format) ──────────────────────────────────

def export_spdx_json(
    sbom_result: dict,
    document_name: str = "Firmware-SBOM",
) -> dict:
    """
    Export SBOM data in SPDX 2.3 JSON format.
    SPDX provides an alternative interchange format to CycloneDX.
    """
    
    packages = []
    for comp in sbom_result.get("components", []):
        pkg = {
            "SPDXID": f"SPDXRef-{comp.get('name', 'unknown').replace(' ', '_')}",
            "name": comp.get("name", "unknown"),
            "version": comp.get("version"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }
        
        # CPE and PURL
        if comp.get("cpe"):
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": comp.get("cpe"),
                }
            ]
        
        if comp.get("license"):
            pkg["licenseConcluded"] = comp.get("license")
            pkg["licenseDeclared"] = comp.get("license")
        
        packages.append(pkg)
    
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": f"https://example.com/iifvdcas/{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat() + "Z",
            "creators": ["Tool: IIFVDCAS-Phase4"],
        },
        "packages": packages,
    }
    
    return spdx_doc

# ─── File I/O ──────────────────────────────────────────────────────────────

def write_json_file(data: dict, output_path: str, indent: int = 2) -> bool:
    """Write JSON data to file with error handling"""
    try:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(data, f, indent=indent)
        return True
    except Exception as e:
        print(f"Error writing JSON to {output_path}: {e}")
        return False

# ─── Main orchestrator (wraps Steps 5-7) ───────────────────────────────────

def generate_sbom_outputs(
    sbom_components: List[dict],
    hbom_components: List[dict],
    cbom_components: List[dict],
    output_dir: str = "/tmp/sbom",
    firmware_path: str = "",
    toolchain: Optional[dict] = None,
    license_summary: Optional[dict] = None,
    log_cb=None,
) -> dict:
    """
    Generate all BOM outputs (Steps 5-7)
    Returns dict with paths to generated files
    """
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    
    # Step 5: CycloneDX SBOM
    if log_cb:
        log_cb("[SBOM Generator] Generating CycloneDX SBOM (Step 5)")
    
    sbom_data = build_sbom_json(
        components=sbom_components,
        firmware_path=firmware_path,
        toolchain=toolchain,
        license_summary=license_summary,
    )
    
    sbom_path = output_dir / "sbom_cyclonedx.json"
    if write_json_file(sbom_data, str(sbom_path)):
        results["sbom"] = sbom_data
        results["sbom_path"] = str(sbom_path)
        if log_cb:
            log_cb(f"✓ CycloneDX SBOM written to {sbom_path}")
    else:
        if log_cb:
            log_cb(f"✗ Failed to write CycloneDX SBOM")
    
    # Step 6: Hardware BOM
    if log_cb:
        log_cb("[SBOM Generator] Generating Hardware BOM (Step 6)")
    
    hbom_data = build_hbom_json(hw_components=hbom_components)
    
    hbom_path = output_dir / "sbom_hbom.json"
    if write_json_file(hbom_data, str(hbom_path)):
        results["hbom"] = hbom_data
        results["hbom_path"] = str(hbom_path)
        if log_cb:
            log_cb(f"✓ Hardware BOM written to {hbom_path}")
    else:
        if log_cb:
            log_cb(f"✗ Failed to write Hardware BOM")
    
    # Step 7: Cryptography BOM
    if log_cb:
        log_cb("[SBOM Generator] Generating Cryptography BOM (Step 7)")
    
    cbom_data = build_cbom_json(crypto_components=cbom_components)
    
    cbom_path = output_dir / "sbom_cbom.json"
    if write_json_file(cbom_data, str(cbom_path)):
        results["cbom"] = cbom_data
        results["cbom_path"] = str(cbom_path)
        if log_cb:
            log_cb(f"✓ Cryptography BOM written to {cbom_path}")
    else:
        if log_cb:
            log_cb(f"✗ Failed to write Cryptography BOM")
    
    # Alternative format: SPDX 2.3
    if log_cb:
        log_cb("[SBOM Generator] Generating SPDX 2.3 alternate format")
    
    spdx_data = export_spdx_json(sbom_data)
    spdx_path = output_dir / "sbom_spdx.json"
    if write_json_file(spdx_data, str(spdx_path)):
        results["spdx"] = spdx_data
        results["spdx_path"] = str(spdx_path)
        if log_cb:
            log_cb(f"✓ SPDX 2.3 format written to {spdx_path}")
    else:
        if log_cb:
            log_cb(f"✗ Failed to write SPDX format")
    
    if log_cb:
        log_cb(f"[SBOM Generator] All BOMs generated successfully")
    
    return results
