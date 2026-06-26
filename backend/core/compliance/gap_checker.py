"""
Phase 7 — Compliance Gap Checker

Maps findings from Phases 3-6 to controls in:
  - ETSI EN 303 645 v2.1.1  (13 provisions, IoT baseline)
  - EU Cyber Resilience Act 2024  (Annex I essential requirements)
  - OWASP IoT Top 10  (attack surface checklist)
  - IEC 62443-4-2  (component security level, light mapping)

Each control gets one of:
  PASS    — evidence shows the requirement is met
  FAIL    — evidence shows the requirement is not met
  PARTIAL — partially met, gaps identified
  NA      — not applicable to this device type
  UNKNOWN — insufficient data to assess
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─── Status constants ─────────────────────────────────────────────────────────
PASS    = "pass"
FAIL    = "fail"
PARTIAL = "partial"
NA      = "na"
UNKNOWN = "unknown"


@dataclass
class ControlResult:
    control_id:   str
    standard:     str
    title:        str
    description:  str
    status:       str            # pass / fail / partial / na / unknown
    severity:     str            # critical / high / medium / low / info
    weight:       float          # for overall score calculation
    evidence:     List[str]      # what data drove this result
    gaps:         List[str]      # specific gaps found
    remediation:  str = ""       # what to fix


# ─── ETSI EN 303 645 provision definitions ────────────────────────────────────
ETSI_PROVISIONS = [
    ("5.1",  "No universal default passwords",          "critical", 1.5),
    ("5.2",  "Vulnerability disclosure policy",         "medium",   0.8),
    ("5.3",  "Keep software updated",                   "high",     1.2),
    ("5.4",  "Secure storage of sensitive data",        "high",     1.2),
    ("5.5",  "Communicate securely",                    "high",     1.2),
    ("5.6",  "Minimise exposed attack surfaces",        "high",     1.0),
    ("5.7",  "Ensure software integrity",               "critical", 1.5),
    ("5.8",  "Ensure personal data security",           "medium",   0.8),
    ("5.9",  "Make systems resilient to outages",       "low",      0.6),
    ("5.10", "Monitor system telemetry data",           "low",      0.5),
    ("5.11", "Make it easy to delete user data",        "low",      0.5),
    ("5.12", "Make installation and maintenance easy",  "low",      0.4),
    ("5.13", "Validate input data",                     "medium",   0.9),
]

# EU CRA Annex I requirements (simplified mapping)
EU_CRA_REQUIREMENTS = [
    ("CRA-1",  "No known exploitable vulnerabilities at launch", "critical", 1.5),
    ("CRA-2",  "Secure by default configuration",               "high",     1.2),
    ("CRA-3",  "Access control and authentication",             "high",     1.2),
    ("CRA-4",  "Data protection and encryption",                "high",     1.1),
    ("CRA-5",  "Secure update mechanism",                       "critical", 1.5),
    ("CRA-6",  "Vulnerability disclosure and patching",         "high",     1.0),
    ("CRA-7",  "Attack surface minimisation",                   "medium",   0.9),
    ("CRA-8",  "Network traffic security",                      "high",     1.1),
    ("CRA-9",  "Software bill of materials available",          "medium",   0.8),
    ("CRA-10", "Integrity and authenticity of updates",         "critical", 1.5),
]

# OWASP IoT Top 10
OWASP_IOT_CONTROLS = [
    ("OW-1",  "Weak/guessable/hardcoded passwords",    "critical", 1.5),
    ("OW-2",  "Insecure network services",             "high",     1.2),
    ("OW-3",  "Insecure ecosystem interfaces",         "high",     1.0),
    ("OW-4",  "Lack of secure update mechanism",       "critical", 1.4),
    ("OW-5",  "Use of insecure/outdated components",   "high",     1.3),
    ("OW-6",  "Insufficient privacy protection",       "medium",   0.7),
    ("OW-7",  "Insecure data transfer and storage",    "high",     1.1),
    ("OW-8",  "Lack of device management",             "medium",   0.7),
    ("OW-9",  "Insecure default settings",             "high",     1.0),
    ("OW-10", "Lack of physical hardening",            "medium",   0.8),
]


def check_all_controls(
    static_job:    Dict,
    sbom_job:      Dict,
    cve_job:       Dict,
    vex_job:       Dict,
    device_info:   Dict,
) -> List[ControlResult]:
    """
    Run all compliance checks and return a flat list of ControlResults.
    Each check is a small function that reads from the phase outputs.
    """
    results: List[ControlResult] = []
    ctx = _BuildContext(static_job, sbom_job, cve_job, vex_job, device_info)

    # ETSI EN 303 645
    results += _check_etsi(ctx)
    # EU CRA
    results += _check_eu_cra(ctx)
    # OWASP IoT
    results += _check_owasp(ctx)

    return results


# ─── Build context (pre-extracts all needed values once) ──────────────────────

class _BuildContext:
    def __init__(self, static_job, sbom_job, cve_job, vex_job, device_info):
        self.static     = static_job  or {}
        self.sbom       = sbom_job    or {}
        self.cve        = cve_job     or {}
        self.vex        = vex_job     or {}
        self.device     = device_info or {}

        # Static analysis extracts
        self.password_findings  = self.static.get("password_findings",        []) or []
        self.embedded_findings  = self.static.get("embedded_string_findings",  []) or []
        self.avr_findings       = self.static.get("avr_findings",              []) or []
        self.cert_findings      = self.static.get("cert_findings",             []) or []
        self.ssh_findings       = self.static.get("ssh_findings",              []) or []
        self.weak_funcs         = self.static.get("weak_functions",            []) or []

        # SBOM extracts
        self.sbom_comps         = self.sbom.get("sbom",                        []) or []
        self.hbom_comps         = self.sbom.get("hbom",    self.sbom.get("hbom_components", [])) or []
        self.cbom_comps         = self.sbom.get("cbom",    self.sbom.get("cbom_components", [])) or []
        self.toolchain          = self.sbom.get("toolchain",                   {}) or {}

        # CVE extracts
        self.total_cves         = self.cve.get("total_cves",                   0)
        self.critical_cves      = self.cve.get("critical_count",               0)
        self.kev_count          = self.cve.get("kev_count",                    0)
        self.cve_findings       = self.cve.get("findings",                     []) or []

        # VEX extracts
        self.risk_score         = self.vex.get("risk_score",                   0.0)
        self.risk_label         = self.vex.get("risk_label",                   "UNKNOWN")
        self.affected_count     = self.vex.get("affected_count",               0)
        self.triage             = self.vex.get("triage_results",               []) or []
        self.remediation_plan   = self.vex.get("remediation_plan",             []) or []
        self.fw_context         = self.vex.get("firmware_context",             {}) or {}

        # Helpers
        self.hardcoded_creds    = [
            f for f in self.embedded_findings + self.password_findings
            if any(k in str(f.get("finding_type","")).lower()
                   for k in ["credential","password","hardcoded","hash"])
        ]
        self.insecure_crypto    = [
            c for c in self.cbom_comps
            if c.get("strength") in ("insecure", "weak")
        ]
        self.secure_boot_off    = any(
            "secure boot" in str(f.get("detail","")).lower() or
            "secure boot" in str(f.get("description","")).lower()
            for f in self.embedded_findings + self.avr_findings
        )
        self.sig_verify_off     = any(
            "signature verification" in str(f.get("detail","")).lower() or
            "signature" in str(f.get("description","")).lower()
            for f in self.embedded_findings + self.avr_findings
        )
        self.http_urls          = [
            f for f in self.embedded_findings
            if "http://" in str(f.get("detail","")).lower()
               and "https://" not in str(f.get("detail","")).lower()
        ]
        self.debug_backdoors    = [
            f for f in self.embedded_findings + self.avr_findings
            if any(k in str(f.get("finding_type","")).lower()
                   for k in ["backdoor","debug","uart"])
        ]


# ─── ETSI EN 303 645 checks ──────────────────────────────────────────────────

def _check_etsi(ctx: _BuildContext) -> List[ControlResult]:
    results = []

    # 5.1 — No universal default passwords
    if ctx.hardcoded_creds:
        gaps = [f"Hardcoded credential: {c.get('detail','')[:60]}"
                for c in ctx.hardcoded_creds[:3]]
        results.append(ControlResult(
            control_id="5.1", standard="ETSI EN 303 645",
            title="No universal default passwords",
            description="Shall not use universal default passwords",
            status=FAIL, severity="critical", weight=1.5,
            evidence=[f"{len(ctx.hardcoded_creds)} hardcoded credentials found by S45/S107"],
            gaps=gaps,
            remediation="Remove all hardcoded credentials. Use provisioning-time unique credentials or certificate-based auth.",
        ))
    else:
        results.append(_pass("5.1", "ETSI EN 303 645", "No universal default passwords",
                             "No hardcoded credentials detected", weight=1.5))

    # 5.3 — Keep software updated (OTA mechanism)
    if ctx.http_urls or ctx.sig_verify_off:
        gaps = []
        if ctx.http_urls:   gaps.append("OTA update over plain HTTP (not HTTPS)")
        if ctx.sig_verify_off: gaps.append("Signature verification disabled for updates")
        results.append(ControlResult(
            control_id="5.3", standard="ETSI EN 303 645",
            title="Keep software updated",
            description="Shall support secure software updates",
            status=FAIL, severity="critical", weight=1.2,
            evidence=["OTA URL detected: " + str(ctx.http_urls[0].get("detail",""))[:60]] if ctx.http_urls else ["Sig verify disabled"],
            gaps=gaps,
            remediation="Use HTTPS for OTA. Enforce cryptographic signature verification before applying updates.",
        ))
    else:
        results.append(_pass("5.3", "ETSI EN 303 645", "Keep software updated",
                             "No insecure OTA patterns detected", weight=1.2))

    # 5.4 — Secure storage of sensitive data
    weak_crypto_names = [c.get("algorithm","") for c in ctx.insecure_crypto]
    if ctx.insecure_crypto or ctx.hardcoded_creds:
        gaps = []
        if ctx.insecure_crypto: gaps.append(f"Insecure crypto in CBOM: {', '.join(weak_crypto_names[:4])}")
        if ctx.hardcoded_creds: gaps.append("Credentials stored in plaintext in flash")
        results.append(ControlResult(
            control_id="5.4", standard="ETSI EN 303 645",
            title="Secure storage of sensitive data",
            description="Sensitive data shall be stored securely",
            status=FAIL, severity="high", weight=1.2,
            evidence=[f"{len(ctx.insecure_crypto)} insecure/weak crypto assets in CBOM"],
            gaps=gaps,
            remediation="Replace MD5/DES/RC4/SSLv3 with AES-256/SHA-256/TLS 1.2+. Do not store credentials in firmware flash.",
        ))
    else:
        results.append(_pass("5.4", "ETSI EN 303 645", "Secure storage of sensitive data",
                             "No insecure crypto or plaintext credentials found", weight=1.2))

    # 5.5 — Communicate securely
    if ctx.http_urls or any(
        c.get("algorithm","") in ("SSLv3","TLS 1.0","RC4","DES","3DES")
        for c in ctx.cbom_comps
    ):
        gaps = []
        if ctx.http_urls: gaps.append(f"{len(ctx.http_urls)} HTTP (non-TLS) URLs in firmware")
        insec_proto = [c.get("algorithm","") for c in ctx.cbom_comps
                       if c.get("algorithm","") in ("SSLv3","TLS 1.0")]
        if insec_proto: gaps.append(f"Insecure protocol versions: {', '.join(insec_proto)}")
        results.append(ControlResult(
            control_id="5.5", standard="ETSI EN 303 645",
            title="Communicate securely",
            description="Shall use best-practice cryptography for communication",
            status=FAIL, severity="high", weight=1.2,
            evidence=[f"HTTP URLs: {len(ctx.http_urls)}, insecure TLS: {len(insec_proto)}"],
            gaps=gaps,
            remediation="Use TLS 1.2+ for all network communication. Disable SSLv3, TLS 1.0/1.1.",
        ))
    else:
        results.append(_pass("5.5", "ETSI EN 303 645", "Communicate securely",
                             "No insecure protocols detected", weight=1.2))

    # 5.6 — Minimise exposed attack surfaces
    if ctx.debug_backdoors:
        gaps = [f"Debug interface: {f.get('detail','')[:60]}" for f in ctx.debug_backdoors[:3]]
        results.append(ControlResult(
            control_id="5.6", standard="ETSI EN 303 645",
            title="Minimise exposed attack surfaces",
            description="Unused interfaces shall be disabled",
            status=FAIL, severity="high", weight=1.0,
            evidence=[f"{len(ctx.debug_backdoors)} debug/backdoor interfaces found by S108"],
            gaps=gaps,
            remediation="Disable UART debug console in production builds. Remove debug menu code or gate behind compile-time flag.",
        ))
    else:
        results.append(_pass("5.6", "ETSI EN 303 645", "Minimise exposed attack surfaces",
                             "No debug interfaces detected", weight=1.0))

    # 5.7 — Ensure software integrity
    status = FAIL if ctx.secure_boot_off or ctx.sig_verify_off else PASS
    gaps = []
    if ctx.secure_boot_off:   gaps.append("Secure boot is explicitly disabled")
    if ctx.sig_verify_off:    gaps.append("Signature verification is disabled")
    if gaps:
        results.append(ControlResult(
            control_id="5.7", standard="ETSI EN 303 645",
            title="Ensure software integrity",
            description="Shall verify software using secure boot",
            status=FAIL, severity="critical", weight=1.5,
            evidence=["Static analysis: 'Secure boot DISABLED' and/or 'Signature verification disabled' strings found"],
            gaps=gaps,
            remediation="Enable secure boot. Enforce signature verification for all firmware updates. Use hardware root of trust (e.g. ATmega LOCK bits).",
        ))
    else:
        results.append(_pass("5.7", "ETSI EN 303 645", "Ensure software integrity",
                             "No secure boot bypass detected", weight=1.5))

    # 5.13 — Validate input data (weak functions = strcpy/gets/sprintf)
    if ctx.weak_funcs:
        results.append(ControlResult(
            control_id="5.13", standard="ETSI EN 303 645",
            title="Validate input data",
            description="Software shall validate all input",
            status=PARTIAL, severity="medium", weight=0.9,
            evidence=[f"{len(ctx.weak_funcs)} unsafe string functions found (S13)"],
            gaps=["Unsafe functions: " + ", ".join(
                f.get("function_name","?") for f in ctx.weak_funcs[:5]
            )],
            remediation="Replace strcpy/gets/sprintf with bounded equivalents. Add input length validation.",
        ))
    else:
        results.append(_pass("5.13", "ETSI EN 303 645", "Validate input data",
                             "No unsafe string functions detected", weight=0.9))

    # Remaining provisions: assessed from available data
    _add_unknown(results, [("5.2","Vulnerability disclosure policy",0.8),
                            ("5.8","Personal data security",0.8),
                            ("5.9","Resilience to outages",0.6),
                            ("5.10","System telemetry monitoring",0.5),
                            ("5.11","User data deletion",0.5),
                            ("5.12","Easy installation",0.4)],
                 "ETSI EN 303 645")
    return results


# ─── EU CRA checks ───────────────────────────────────────────────────────────

def _check_eu_cra(ctx: _BuildContext) -> List[ControlResult]:
    results = []

    # CRA-1: No known exploitable vulnerabilities at launch
    crit_affected = [t for t in ctx.triage
                     if t.get("vex_status") == "affected"
                     and t.get("exploitability") == "critical"]
    if crit_affected:
        results.append(ControlResult(
            control_id="CRA-1", standard="EU CRA 2024",
            title="No known exploitable vulnerabilities at launch",
            description="Products shall be placed on market without known exploitable vulnerabilities",
            status=FAIL, severity="critical", weight=1.5,
            evidence=[f"{len(crit_affected)} CRITICAL CVEs with VEX status=affected"],
            gaps=[f"CVE {t['cve_id']} ({t['component']}) CVSS={t.get('cvss_score','?')}"
                  for t in crit_affected[:5]],
            remediation="Update all components with CRITICAL CVEs before release.",
        ))
    elif ctx.affected_count > 0:
        results.append(ControlResult(
            control_id="CRA-1", standard="EU CRA 2024",
            title="No known exploitable vulnerabilities at launch",
            description="Products shall be placed on market without known exploitable vulnerabilities",
            status=PARTIAL, severity="high", weight=1.5,
            evidence=[f"{ctx.affected_count} CVEs with VEX status=affected (no CRITICAL)"],
            gaps=[f"{ctx.affected_count} affected CVEs need remediation"],
            remediation="Review and patch all affected vulnerabilities before release.",
        ))
    else:
        results.append(_pass("CRA-1", "EU CRA 2024",
                             "No known exploitable vulnerabilities at launch",
                             "No affected CVEs detected", weight=1.5))

    # CRA-2: Secure by default
    if ctx.hardcoded_creds or ctx.debug_backdoors or ctx.secure_boot_off:
        gaps = []
        if ctx.hardcoded_creds: gaps.append("Default credentials in firmware")
        if ctx.debug_backdoors: gaps.append("Debug interfaces enabled by default")
        if ctx.secure_boot_off: gaps.append("Secure boot disabled by default")
        results.append(ControlResult(
            control_id="CRA-2", standard="EU CRA 2024",
            title="Secure by default configuration",
            description="Products shall be secure by default",
            status=FAIL, severity="high", weight=1.2,
            evidence=["Multiple insecure-by-default indicators found"],
            gaps=gaps,
            remediation="Ship with secure boot enabled, no debug interfaces, and unique credentials.",
        ))
    else:
        results.append(_pass("CRA-2", "EU CRA 2024", "Secure by default",
                             "No insecure default indicators found", weight=1.2))

    # CRA-5: Secure update mechanism
    if ctx.http_urls or ctx.sig_verify_off:
        gaps = []
        if ctx.http_urls:      gaps.append("Update fetched over HTTP")
        if ctx.sig_verify_off: gaps.append("Update signature verification disabled")
        results.append(ControlResult(
            control_id="CRA-5", standard="EU CRA 2024",
            title="Secure update mechanism",
            description="Shall support secure and authenticated updates",
            status=FAIL, severity="critical", weight=1.5,
            evidence=["OTA over HTTP and/or signature verification disabled"],
            gaps=gaps,
            remediation="Use HTTPS + cryptographic signature verification for all updates.",
        ))
    else:
        results.append(_pass("CRA-5", "EU CRA 2024", "Secure update mechanism",
                             "No insecure update patterns detected", weight=1.5))

    # CRA-9: SBOM available
    sbom_count = len(ctx.sbom_comps)
    if sbom_count > 0:
        results.append(ControlResult(
            control_id="CRA-9", standard="EU CRA 2024",
            title="Software bill of materials available",
            description="Shall maintain and provide SBOM",
            status=PASS, severity="medium", weight=0.8,
            evidence=[f"SBOM generated with {sbom_count} components (Phase 4)"],
            gaps=[],
            remediation="",
        ))
    else:
        results.append(ControlResult(
            control_id="CRA-9", standard="EU CRA 2024",
            title="Software bill of materials available",
            description="Shall maintain and provide SBOM",
            status=FAIL, severity="medium", weight=0.8,
            evidence=["No SBOM components found"],
            gaps=["SBOM not generated or empty"],
            remediation="Run Phase 4 SBOM generation and provide CycloneDX 1.5 SBOM with product.",
        ))

    # CRA-10: Integrity and authenticity
    results.append(ControlResult(
        control_id="CRA-10", standard="EU CRA 2024",
        title="Integrity and authenticity of updates",
        description="Updates shall be authenticated and integrity-protected",
        status=FAIL if ctx.sig_verify_off else (PARTIAL if not ctx.secure_boot_off else UNKNOWN),
        severity="critical", weight=1.5,
        evidence=["Signature verification disabled" if ctx.sig_verify_off else "Secure boot status unknown"],
        gaps=["Signature verification disabled"] if ctx.sig_verify_off else [],
        remediation="Implement firmware signing (e.g. Ed25519) and verify signature before boot.",
    ))

    _add_unknown(results, [("CRA-3","Access control and auth",1.2),
                            ("CRA-4","Data protection",1.1),
                            ("CRA-6","Vulnerability disclosure",1.0),
                            ("CRA-7","Attack surface minimisation",0.9),
                            ("CRA-8","Network traffic security",1.1)],
                 "EU CRA 2024")
    return results


# ─── OWASP IoT Top 10 checks ─────────────────────────────────────────────────

def _check_owasp(ctx: _BuildContext) -> List[ControlResult]:
    results = []

    # OW-1: Weak/hardcoded passwords
    if ctx.hardcoded_creds:
        results.append(ControlResult(
            control_id="OW-1", standard="OWASP IoT Top 10",
            title="Weak/guessable/hardcoded passwords",
            description="No hardcoded or guessable credentials",
            status=FAIL, severity="critical", weight=1.5,
            evidence=[f"{len(ctx.hardcoded_creds)} hardcoded credentials in flash"],
            gaps=[f"Hardcoded credential: {c.get('detail','')[:50]}"
                  for c in ctx.hardcoded_creds[:3]],
            remediation="Remove all hardcoded credentials from firmware. Use runtime provisioning.",
        ))
    else:
        results.append(_pass("OW-1", "OWASP IoT Top 10",
                             "No hardcoded passwords", "No hardcoded credentials", weight=1.5))

    # OW-4: Insecure update mechanism
    if ctx.http_urls or ctx.sig_verify_off:
        results.append(ControlResult(
            control_id="OW-4", standard="OWASP IoT Top 10",
            title="Lack of secure update mechanism",
            description="Updates must be authenticated over TLS",
            status=FAIL, severity="critical", weight=1.4,
            evidence=["HTTP OTA URL detected" if ctx.http_urls else "Sig verify disabled"],
            gaps=["OTA over plain HTTP" if ctx.http_urls else "No signature check"],
            remediation="HTTPS + signed updates mandatory.",
        ))
    else:
        results.append(_pass("OW-4", "OWASP IoT Top 10",
                             "Secure update mechanism", "No insecure update patterns", weight=1.4))

    # OW-5: Outdated/vulnerable components
    if ctx.affected_count > 10 or ctx.critical_cves > 0:
        results.append(ControlResult(
            control_id="OW-5", standard="OWASP IoT Top 10",
            title="Use of insecure/outdated components",
            description="Components must be free of known vulnerabilities",
            status=FAIL, severity="high", weight=1.3,
            evidence=[f"{ctx.total_cves} CVEs in {len(ctx.sbom_comps)} components; {ctx.critical_cves} CRITICAL"],
            gaps=[f"Component {p['component']} has {p['affected_cves']} CVEs"
                  for p in ctx.remediation_plan[:3]],
            remediation="Update all vulnerable components. Prioritise CRITICAL CVEs first.",
        ))
    elif ctx.affected_count > 0:
        results.append(ControlResult(
            control_id="OW-5", standard="OWASP IoT Top 10",
            title="Use of insecure/outdated components",
            description="Components must be free of known vulnerabilities",
            status=PARTIAL, severity="high", weight=1.3,
            evidence=[f"{ctx.total_cves} CVEs found, {ctx.affected_count} affected"],
            gaps=["Non-critical CVEs present — review and update"],
            remediation="Schedule updates for all affected components.",
        ))
    else:
        results.append(_pass("OW-5", "OWASP IoT Top 10",
                             "No outdated/insecure components", "No affected CVEs", weight=1.3))

    # OW-7: Insecure data transfer
    if ctx.http_urls or ctx.insecure_crypto:
        results.append(ControlResult(
            control_id="OW-7", standard="OWASP IoT Top 10",
            title="Insecure data transfer and storage",
            description="All data transfer must be encrypted",
            status=FAIL, severity="high", weight=1.1,
            evidence=[f"HTTP URLs: {len(ctx.http_urls)}, Insecure crypto: {len(ctx.insecure_crypto)}"],
            gaps=["Cleartext HTTP transmission" if ctx.http_urls else "",
                  "Weak crypto in CBOM" if ctx.insecure_crypto else ""],
            remediation="Encrypt all data in transit (TLS 1.2+) and at rest (AES-256).",
        ))
    else:
        results.append(_pass("OW-7", "OWASP IoT Top 10",
                             "Secure data transfer", "No insecure transfer patterns", weight=1.1))

    # OW-9: Insecure default settings
    if ctx.debug_backdoors or ctx.secure_boot_off:
        results.append(ControlResult(
            control_id="OW-9", standard="OWASP IoT Top 10",
            title="Insecure default settings",
            description="Device must ship with secure defaults",
            status=FAIL, severity="high", weight=1.0,
            evidence=["Debug interfaces active, secure boot disabled"],
            gaps=["Debug UART console enabled by default",
                  "Secure boot disabled in production build"],
            remediation="Disable all debug interfaces in release builds. Enable secure boot.",
        ))
    else:
        results.append(_pass("OW-9", "OWASP IoT Top 10",
                             "Secure defaults", "No insecure defaults detected", weight=1.0))

    _add_unknown(results, [("OW-2","Insecure network services",1.2),
                            ("OW-3","Insecure ecosystem interfaces",1.0),
                            ("OW-6","Insufficient privacy",0.7),
                            ("OW-8","Lack of device management",0.7),
                            ("OW-10","Lack of physical hardening",0.8)],
                 "OWASP IoT Top 10")
    return results


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _pass(ctrl_id, standard, title, evidence_str, weight=1.0) -> ControlResult:
    return ControlResult(
        control_id=ctrl_id, standard=standard, title=title,
        description="", status=PASS, severity="info", weight=weight,
        evidence=[evidence_str], gaps=[], remediation="",
    )


def _add_unknown(results, items, standard):
    for ctrl_id, title, weight in items:
        results.append(ControlResult(
            control_id=ctrl_id, standard=standard, title=title,
            description="",
            status=UNKNOWN, severity="info", weight=weight,
            evidence=["Insufficient data from current scan phases"],
            gaps=["Manual assessment required"],
            remediation="Perform manual review against the full standard.",
        ))


def compliance_score(results: List[ControlResult]) -> float:
    """
    Weighted compliance score 0-100.
    PASS=1.0, PARTIAL=0.5, UNKNOWN=0.3, NA=1.0(excluded), FAIL=0.0
    """
    weights = {PASS: 1.0, PARTIAL: 0.5, UNKNOWN: 0.3, NA: None, FAIL: 0.0}
    total_w = 0.0
    earned_w = 0.0
    for r in results:
        w = r.weight
        score = weights.get(r.status)
        if score is None:   # NA — skip
            continue
        total_w  += w
        earned_w += w * score
    if total_w == 0:
        return 0.0
    return round((earned_w / total_w) * 100, 1)
