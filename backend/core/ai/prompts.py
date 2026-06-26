"""
Prompt templates for all IIFVDCAS AI features.

Each function returns a list[dict] ready to pass to AIProvider.complete().
"""

from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Feature 1 — CVE Impact Analyst (Phase 5)
# ─────────────────────────────────────────────────────────────────────────────
def explain_cve_messages(
    cve_id: str,
    description: str,
    firmware_context: Dict[str, Any],
) -> List[Dict]:
    fw = firmware_context or {}
    return [
        {
            "role": "system",
            "content": (
                "You are a senior firmware security analyst. "
                "You write for IoT product developers and product managers — "
                "not academic researchers. Be direct, concrete, and jargon-free. "
                "Never copy-paste the raw CVE description. Always translate it."
            ),
        },
        {
            "role": "user",
            "content": (
                f"CVE ID: {cve_id}\n"
                f"Official description: {description or 'Not available.'}\n\n"
                f"Firmware context:\n"
                f"  Architecture:     {fw.get('architecture', 'unknown')}\n"
                f"  Bare-metal:       {fw.get('is_bare_metal', True)}\n"
                f"  Has network stack:{fw.get('has_network_stack', False)}\n"
                f"  Crypto algorithms:{fw.get('cbom_algorithms', [])}\n"
                f"  Components:       {fw.get('components', [])}\n\n"
                "Answer in exactly 3 short paragraphs:\n"
                "1. What this vulnerability actually does technically (1-2 sentences, plain English)\n"
                "2. Whether it is realistically exploitable in THIS specific firmware — "
                "explain why or why not based on the context above\n"
                "3. The single most important action the developer should take\n\n"
                "Use plain English. No bullet lists. No CVSS jargon."
            ),
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Feature 2 — VEX Justification Generator (Phase 6)
# ─────────────────────────────────────────────────────────────────────────────
def vex_justification_messages(
    triage_finding: Dict[str, Any],
    firmware_context: Dict[str, Any],
) -> List[Dict]:
    fw = triage_finding or {}
    fwc = firmware_context or {}
    return [
        {
            "role": "system",
            "content": (
                "You are a security compliance engineer writing VEX (Vulnerability Exploitability eXchange) "
                "documents in CycloneDX 1.5 format. Your justifications must be:\n"
                "- Technically precise\n"
                "- Written in the formal language used by notified bodies and regulators\n"
                "- Based strictly on the provided firmware evidence\n"
                "- A single paragraph of 3-5 sentences"
            ),
        },
        {
            "role": "user",
            "content": (
                f"Write a CycloneDX-compliant VEX justification for this finding:\n\n"
                f"CVE ID:         {fw.get('cve_id', 'Unknown')}\n"
                f"Component:      {fw.get('component', 'Unknown')}\n"
                f"Version:        {fw.get('version', 'Unknown')}\n"
                f"VEX Status:     {fw.get('vex_status', 'not_affected')}\n"
                f"Engine reason:  {fw.get('justification', '')}\n"
                f"Exploitability: {fw.get('exploitability', 'unknown')}\n"
                f"Notes:          {'; '.join(fw.get('notes', []))}\n\n"
                f"Firmware context:\n"
                f"  Architecture: {fwc.get('architecture', 'unknown')}\n"
                f"  Bare-metal:   {fwc.get('is_bare_metal', True)}\n"
                f"  Network:      {fwc.get('has_network_stack', False)}\n"
                f"  OS present:   {fwc.get('has_os', False)}\n\n"
                "Write one formal justification paragraph suitable for inclusion in "
                "a CycloneDX VEX document submitted to a customer or regulator. "
                "Do not include headers, bullet points, or markdown."
            ),
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Feature 3 — Compliance Formal Write-up (Phase 7)
# ─────────────────────────────────────────────────────────────────────────────
def compliance_writeup_messages(
    control: Dict[str, Any],
    firmware_context: Dict[str, Any],
) -> List[Dict]:
    c = control or {}
    fwc = firmware_context or {}
    gaps_text = "\n".join(f"  - {g}" for g in c.get("gaps", [])) or "  (none documented)"
    evidence_text = "\n".join(f"  - {e}" for e in c.get("evidence", [])) or "  (none documented)"
    return [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity compliance auditor writing formal non-conformance statements "
                "for IoT product manufacturers seeking ETSI EN 303 645, EU CRA, or IEC 62443 certification. "
                "Your writing is used directly in conformance dossiers submitted to notified bodies. "
                "Write in the style of a formal audit report."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Write a formal non-conformance statement for this compliance gap:\n\n"
                f"Standard:    {c.get('standard', 'Unknown')}\n"
                f"Control ID:  {c.get('control_id', 'Unknown')}\n"
                f"Title:       {c.get('title', 'Unknown')}\n"
                f"Status:      {c.get('status', 'fail').upper()}\n"
                f"Severity:    {c.get('severity', 'high').upper()}\n"
                f"Remediation: {c.get('remediation', '')}\n\n"
                f"Identified gaps:\n{gaps_text}\n\n"
                f"Evidence:\n{evidence_text}\n\n"
                f"Device context:\n"
                f"  Architecture: {fwc.get('architecture', 'unknown')}\n"
                f"  Device:       {fwc.get('device_name', 'unknown')}\n"
                f"  Firmware:     {fwc.get('firmware_version', 'unknown')}\n\n"
                "Write 2-3 formal paragraphs:\n"
                "1. State of non-conformance (what requirement was violated)\n"
                "2. Specific technical evidence found\n"
                "3. Required corrective action with timeline urgency\n\n"
                "Write in formal audit English. No bullet points. No markdown headers."
            ),
        },
    ]


def compliance_executive_summary_messages(
    summary: Dict[str, Any],
    failed_controls: List[Dict],
    firmware_context: Dict[str, Any],
) -> List[Dict]:
    s = summary or {}
    fwc = firmware_context or {}
    top_failures = [
        f"{c.get('standard')} {c.get('control_id')}: {c.get('title')}"
        for c in (failed_controls or [])[:5]
    ]
    return [
        {
            "role": "system",
            "content": (
                "You are a cybersecurity compliance consultant writing executive summaries "
                "for IoT product audit reports. Your audience is senior management and "
                "legal/compliance teams, not engineers."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Write an executive summary for this firmware compliance audit:\n\n"
                f"Device:           {fwc.get('device_name', 'IoT Device')}\n"
                f"Compliance grade: {s.get('compliance_grade', 'F')}\n"
                f"Score:            {s.get('compliance_score', 0):.1f}%\n"
                f"Risk label:       {s.get('risk_label', 'CRITICAL')}\n"
                f"Total controls:   {s.get('controls_total', 0)}\n"
                f"Passed:           {s.get('controls_pass', 0)}\n"
                f"Failed:           {s.get('controls_fail', 0)}\n"
                f"Total CVEs:       {s.get('total_cves', 0)} "
                f"({s.get('critical_cves', 0)} critical)\n\n"
                f"Top failed controls:\n"
                + "\n".join(f"  - {f}" for f in top_failures) + "\n\n"
                "Write a 2-paragraph executive summary suitable as the cover letter "
                "section of a formal audit report. Paragraph 1: overall security posture. "
                "Paragraph 2: key risks and recommended priority actions. "
                "Write for a non-technical executive. No markdown, no bullet points."
            ),
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Feature 4 — Static Analysis Finding Explainer (Phase 3)
# ─────────────────────────────────────────────────────────────────────────────
def explain_finding_messages(
    finding: Dict[str, Any],
    firmware_context: Dict[str, Any],
) -> List[Dict]:
    f = finding or {}
    fwc = firmware_context or {}
    # Build detail string from whatever fields exist
    details = []
    for k in ("type", "description", "detail", "value", "path", "function", "offset", "cwe"):
        v = f.get(k)
        if v:
            details.append(f"  {k}: {v}")
    detail_str = "\n".join(details) or "  (no additional detail)"

    return [
        {
            "role": "system",
            "content": (
                "You are a firmware security engineer helping developers understand "
                "static analysis findings. Be practical and direct. "
                "Explain what the finding means and exactly what the developer should do."
            ),
        },
        {
            "role": "user",
            "content": (
                f"Explain this static analysis finding:\n\n"
                f"Severity: {f.get('severity', 'unknown').upper()}\n"
                f"Title:    {f.get('name') or f.get('type') or f.get('title', 'Unknown finding')}\n"
                f"Details:\n{detail_str}\n\n"
                f"Firmware context:\n"
                f"  Architecture: {fwc.get('architecture', 'unknown')}\n"
                f"  Bare-metal:   {fwc.get('is_bare_metal', True)}\n\n"
                "Answer in 3 parts (no headers, just flowing text):\n"
                "1. What this finding means in plain English\n"
                "2. Why it is a security problem in this specific firmware context\n"
                "3. Exact fix — what the developer should change in their code or build config\n\n"
                "Keep it under 150 words total. Be concrete."
            ),
        },
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Feature 5 — AI Security Assistant Chat (cross-cutting)
# ─────────────────────────────────────────────────────────────────────────────
def chat_messages(
    user_message: str,
    scan_context: Dict[str, Any],
    history: Optional[List[Dict]] = None,
) -> List[Dict]:
    ctx = scan_context or {}

    # Build context summary
    context_lines = []
    if ctx.get("device"):
        context_lines.append(f"Device: {ctx['device']}")
    if ctx.get("architecture"):
        context_lines.append(f"Architecture: {ctx['architecture']}")
    if ctx.get("is_bare_metal") is not None:
        context_lines.append(f"Bare-metal: {ctx['is_bare_metal']}")
    if ctx.get("total_cves") is not None:
        context_lines.append(
            f"CVEs: {ctx['total_cves']} total "
            f"({ctx.get('critical_cves', 0)} critical, "
            f"{ctx.get('high_cves', 0)} high)"
        )
    if ctx.get("risk_score") is not None:
        context_lines.append(
            f"Risk score: {ctx['risk_score']}/100 ({ctx.get('risk_label', '')})"
        )
    if ctx.get("compliance_grade"):
        context_lines.append(
            f"Compliance: grade {ctx['compliance_grade']} "
            f"({ctx.get('compliance_score', 0):.0f}%)"
        )
    if ctx.get("kev_count"):
        context_lines.append(f"CISA KEV hits: {ctx['kev_count']}")
    if ctx.get("affected_count"):
        context_lines.append(f"Confirmed affected CVEs: {ctx['affected_count']}")

    context_block = "\n".join(context_lines) if context_lines else "No scan data loaded yet."

    system = (
        "You are an expert IoT firmware security analyst embedded in the IIFVDCAS platform. "
        "You have access to the user's current scan results shown below. "
        "Answer questions about their firmware's security posture, vulnerabilities, "
        "compliance status, and remediation priorities. Be concise and practical.\n\n"
        f"Current scan context:\n{context_block}"
    )

    messages: List[Dict] = [{"role": "system", "content": system}]

    # Add chat history (last 10 turns max to avoid token bloat)
    for turn in (history or [])[-10:]:
        messages.append(turn)

    messages.append({"role": "user", "content": user_message})
    return messages
