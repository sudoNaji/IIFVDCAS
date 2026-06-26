"""
VEX Triage Engine — Phase 6

Determines exploitability context for each CVE finding based on:
  - Firmware architecture (AVR bare-metal vs Linux-based)
  - Component type (library vs MCU hardware)
  - CBOM crypto findings
  - Static analysis findings
  - EPSS + KEV signals

VEX statuses (OpenVEX / CycloneDX 1.5 standard):
  affected            — vulnerable and reachable in this firmware
  not_affected        — CVE does not apply in this deployment context
  fixed               — installed version is above the patched boundary
  under_investigation — insufficient context, manual review needed
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

AFFECTED            = "affected"
NOT_AFFECTED        = "not_affected"
FIXED               = "fixed"
UNDER_INVESTIGATION = "under_investigation"


@dataclass
class TriageResult:
    cve_id:             str
    component:          str
    version:            str
    vex_status:         str
    justification:      str
    justification_code: str
    confidence:         float
    reachable:          bool
    exploitability:     str
    # Raw scores stored for the risk scorer (avoids re-approximation)
    cvss_score:         Optional[float] = None
    epss_score:         float           = 0.0
    is_kev:             bool            = False
    notes:              List[str]       = field(default_factory=list)
    remediation:        str             = ""


class FirmwareContext:
    def __init__(
        self,
        architecture:      str        = "unknown",
        has_os:            bool       = False,
        has_network_stack: bool       = False,
        cbom_algorithms:   List[str]  = None,
        static_findings:   List[Dict] = None,
        hbom_components:   List[Dict] = None,
        device_info:       Dict       = None,
    ):
        arch = (architecture or "").upper()
        self.architecture      = architecture
        self.is_avr            = any(k in arch for k in ("AVR", "ATMEGA", "ATTINY"))
        self.is_arm            = any(k in arch for k in ("ARM", "AARCH64"))
        self.is_x86            = any(k in arch for k in ("X86", "I386", "AMD64"))
        self.has_os            = has_os
        self.is_bare_metal     = not has_os

        if self.is_avr:
            self.has_os        = False
            self.is_bare_metal = True
            hbom = hbom_components or []
            hw_names = {h.get("name", "").upper() for h in hbom}
            self.has_network_stack = bool(
                {"ENC28J60", "W5100", "ESP8266", "ESP32", "NRF24L01"} & hw_names
            )
        else:
            self.has_network_stack = has_network_stack

        self.cbom_algorithms = {a.lower() for a in (cbom_algorithms or [])}
        self.static_findings = static_findings or []
        self.hbom_components = hbom_components or []
        self.device_info     = device_info or {}
        self._hw_names_lower = {h.get("name", "").lower() for h in self.hbom_components}


def triage_cve(
    cve_id:      str,
    component:   str,
    version:     str,
    cpe:         str,
    cvss_score:  Optional[float],
    cvss_vector: Optional[str],
    epss_score:  float,
    is_kev:      bool,
    cwe_ids:     List[str],
    description: str,
    ctx:         FirmwareContext,
) -> TriageResult:
    notes      = []
    comp_lower = component.lower()
    desc_lower = (description or "").lower()
    vec_lower  = (cvss_vector  or "").lower()

    def _result(status, justification, code, confidence, reachable, exploitability, extra_notes=None):
        return TriageResult(
            cve_id=cve_id, component=component, version=version,
            vex_status=status,
            justification=justification,
            justification_code=code,
            confidence=confidence,
            reachable=reachable,
            exploitability=exploitability,
            cvss_score=cvss_score,
            epss_score=epss_score,
            is_kev=is_kev,
            notes=(extra_notes or notes),
        )

    # ── R1: OS-level exploit on bare-metal AVR ────────────────────────────────
    os_kw = [
        "privilege escalation", "kernel", "root exploit", "sudo",
        "linux kernel", "android", "windows", "/proc/", "polkit",
        "dirty cow", "dirty pipe", "namespace", "container escape",
        "setuid", "cgroup",
    ]
    if ctx.is_avr and any(k in desc_lower for k in os_kw):
        return _result(
            NOT_AFFECTED,
            "AVR bare-metal has no OS — OS-level exploits do not apply",
            "vulnerable_code_not_in_execute_path",
            0.95, False, "none",
            ["AVR bare-metal: no kernel/OS attack surface"],
        )

    # ── R2: Network-based CVE on AVR without network hardware ─────────────────
    network_attack = "av:n" in vec_lower or any(
        k in desc_lower for k in ["remote code execution", "network attack", "remote exploit"]
    )
    if ctx.is_avr and not ctx.has_network_stack and network_attack:
        return _result(
            NOT_AFFECTED,
            "No IP network hardware detected — network-based exploit path absent",
            "vulnerable_code_not_in_execute_path",
            0.88, False, "none",
            ["No ENC28J60/W5100/ESP module in HBOM — network vector unavailable"],
        )

    # ── R3: Crypto CVE for algorithm not in CBOM ──────────────────────────────
    crypto_cwes = {"CWE-327", "CWE-326", "CWE-328", "CWE-330", "CWE-338", "CWE-916"}
    if set(cwe_ids) & crypto_cwes:
        algo = _algo_from_component(comp_lower)
        if algo and algo not in ctx.cbom_algorithms:
            return _result(
                NOT_AFFECTED,
                f"Algorithm '{algo}' not detected in CBOM — likely not compiled in",
                "vulnerable_code_not_in_execute_path",
                0.72, False, "none",
                [f"CBOM scan found no usage of {algo} in this firmware"],
            )

    # ── R4: Hardware component CVE ────────────────────────────────────────────
    if comp_lower in ctx._hw_names_lower:
        notes.append("Hardware CVE — exploitation typically requires physical access")
        r = _result(
            UNDER_INVESTIGATION,
            "Hardware component — exploitation context requires physical access audit",
            "", 0.55, False, "low",
        )
        r.notes = notes
        r.remediation = f"Audit physical access controls for {component}."
        return r

    # ── R5: KEV + high EPSS → definitely affected ─────────────────────────────
    if is_kev and epss_score > 0.2:
        r = _result(
            AFFECTED,
            "CISA KEV confirmed exploitation + high EPSS probability",
            "", 0.97, True,
            _cvss_to_exploitability(cvss_score),
            [
                "Listed in CISA Known Exploited Vulnerabilities catalog",
                f"EPSS: {epss_score:.1%} 30-day exploitation probability",
            ],
        )
        r.remediation = _remediation(component, version, cvss_score, is_kev=True)
        return r

    # ── R6: Very low EPSS, no KEV, non-network ────────────────────────────────
    if epss_score < 0.003 and not is_kev and "av:n" not in vec_lower:
        notes.append(f"Very low exploitation probability (EPSS {epss_score:.4f})")
        r = _result(
            UNDER_INVESTIGATION,
            "Negligible exploitation probability — monitor but low urgency",
            "", 0.60, True, "low",
        )
        r.notes      = list(notes)
        r.remediation = _remediation(component, version, cvss_score)
        return r

    # ── R7: Default — component present, not ruled out ────────────────────────
    exploitability = _cvss_to_exploitability(cvss_score)
    confidence     = min(0.75 + (0.15 if is_kev else 0) + min(epss_score * 0.3, 0.10), 0.97)
    notes.append(f"Component {component} {version} present in firmware SBOM")
    if epss_score > 0:
        notes.append(f"EPSS: {epss_score:.1%} exploitation probability")
    if is_kev:
        notes.append("Listed in CISA Known Exploited Vulnerabilities catalog")

    r = _result(AFFECTED, f"{component} {version} present and within vulnerable CPE range",
                "", confidence, True, exploitability)
    r.notes      = list(notes)
    r.remediation = _remediation(component, version, cvss_score, is_kev=is_kev)
    return r


def _cvss_to_exploitability(score: Optional[float]) -> str:
    if score is None:  return "unknown"
    if score >= 9.0:   return "critical"
    if score >= 7.0:   return "high"
    if score >= 4.0:   return "medium"
    return "low"


def _algo_from_component(comp: str) -> Optional[str]:
    for k, v in {
        "md5": "md5", "sha1": "sha-1", "sha-1": "sha-1",
        "des": "des", "3des": "3des", "rc4": "rc4",
        "blowfish": "blowfish", "rc2": "rc2",
    }.items():
        if k in comp:
            return v
    return None


def _remediation(
    component: str, version: str,
    cvss_score: Optional[float],
    is_kev: bool = False,
) -> str:
    s = cvss_score or 0.0
    if is_kev or s >= 9.0:
        return (f"IMMEDIATE (P0): Update {component} {version} — "
                "actively exploited in the wild. Patch within 24h.")
    if s >= 7.0:
        return (f"HIGH (P1): Update {component} {version}. "
                "Schedule patch within 7 days.")
    if s >= 4.0:
        return (f"MEDIUM (P2): Update {component} {version}. "
                "Include in next maintenance window.")
    return (f"LOW (P3): Monitor {component} {version}. "
            "Update at next opportunity.")
