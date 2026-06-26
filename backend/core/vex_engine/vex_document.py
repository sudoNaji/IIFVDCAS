"""
CycloneDX VEX 1.5 Document Generator — Phase 6

Produces a standards-compliant VEX document from triage results.
CycloneDX VEX is the industry standard adopted by CISA, NTIA, and EU CRA.
"""

import uuid
import json
from datetime import datetime, timezone
from typing import List, Dict, Optional
from pathlib import Path

from .triage_engine import TriageResult, AFFECTED, NOT_AFFECTED, FIXED, UNDER_INVESTIGATION


# CycloneDX VEX status → spec value
_VEX_STATUS_MAP = {
    AFFECTED:            "affected",
    NOT_AFFECTED:        "not_affected",
    FIXED:               "fixed",
    UNDER_INVESTIGATION: "under_investigation",
}

# CycloneDX justification codes
_JUSTIFICATION_MAP = {
    "vulnerable_code_not_in_execute_path": "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present":         "vulnerable_code_not_present",
    "inline_mitigations_already_exist":    "inline_mitigations_already_exist",
    "component_not_present":               "component_not_present",
    "patched_version_installed":           "protected_by_mitigating_control",
}


def generate_cyclonedx_vex(
    triage_results:  List[TriageResult],
    firmware_name:   str,
    firmware_version: str,
    job_id:          str,
    output_path:     Optional[str] = None,
) -> Dict:
    """Generate a CycloneDX 1.5 VEX document from triage results."""

    doc = {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version":     1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "IIFVDCAS",
                    "name":   "Phase6-VEX-Engine",
                    "version":"1.0",
                }
            ],
            "component": {
                "type":    "firmware",
                "name":    firmware_name or "unknown-firmware",
                "version": firmware_version or "unknown",
                "bom-ref": str(uuid.uuid4()),
            },
        },
        "vulnerabilities": [],
    }

    for r in triage_results:
        vuln: Dict = {
            "id":     r.cve_id,
            "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{r.cve_id}"},
            "analysis": {
                "state":         _VEX_STATUS_MAP.get(r.vex_status, "under_investigation"),
                "justification": _map_justification(r.justification_code),
                "detail":        r.justification,
                "response":      _response_actions(r),
                "firstIssued":   datetime.now(timezone.utc).isoformat(),
                "lastUpdated":   datetime.now(timezone.utc).isoformat(),
            },
            "affects": [
                {
                    "ref":     r.cve_id,
                    "versions":[{"version": r.version or "unknown"}],
                }
            ],
            "ratings": [
                {
                    "source": {"name": "IIFVDCAS-VEX"},
                    "score":  None,
                    "severity": r.exploitability if r.exploitability != "none" else "none",
                    "method": "CVSSv3",
                }
            ],
            "recommendation": r.remediation or "",
        }
        doc["vulnerabilities"].append(vuln)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(doc, indent=2, default=str))

    return doc


def _map_justification(code: str) -> str:
    return _JUSTIFICATION_MAP.get(code, "")


def _response_actions(r: TriageResult) -> List[str]:
    if r.vex_status == NOT_AFFECTED:
        return ["will_not_fix"]
    if r.vex_status == FIXED:
        return ["update"]
    if r.vex_status == AFFECTED:
        if "P0" in r.remediation or "IMMEDIATE" in r.remediation:
            return ["update", "workaround_available"]
        return ["update"]
    return ["investigating"]
