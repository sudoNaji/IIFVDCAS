"""
Phase 7 — PDF Report Builder (ReportLab A4)

Generates a professional A4 PDF security assessment report from all phase outputs.
Cover page is drawn directly via canvas for pixel-perfect layout.
Inner pages use Platypus platypus flowables.
"""

import io
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle,
    Spacer, HRFlowable, KeepTogether, PageBreak,
)

from .gap_checker import ControlResult, PASS, FAIL, PARTIAL, UNKNOWN, NA

logger = logging.getLogger(__name__)

# ─── Colour palette ───────────────────────────────────────────────────────────
C_DARK_BG    = colors.HexColor("#1a1a2e")
C_ACCENT     = colors.HexColor("#4f46e5")
C_RED        = colors.HexColor("#dc2626")
C_ORANGE     = colors.HexColor("#ea580c")
C_AMBER      = colors.HexColor("#d97706")
C_GREEN      = colors.HexColor("#16a34a")
C_BLUE       = colors.HexColor("#2563eb")
C_GRAY       = colors.HexColor("#6b7280")
C_LIGHT_GRAY = colors.HexColor("#f3f4f6")
C_MED_GRAY   = colors.HexColor("#e5e7eb")
C_WHITE      = colors.white
C_BLACK      = colors.HexColor("#111827")
C_INDIGO_LT  = colors.HexColor("#a5b4fc")

STATUS_COLORS = {
    PASS:    C_GREEN,
    FAIL:    C_RED,
    PARTIAL: C_AMBER,
    UNKNOWN: C_GRAY,
    NA:      C_GRAY,
}

SEV_COLORS = {
    "critical": C_RED,
    "high":     C_ORANGE,
    "medium":   C_AMBER,
    "low":      C_BLUE,
    "info":     C_GRAY,
}

RISK_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_AMBER,
    "LOW":      C_BLUE,
    "MINIMAL":  C_GREEN,
}


# ─── Style setup ──────────────────────────────────────────────────────────────

def _make_styles():
    base   = getSampleStyleSheet()
    styles = {}

    styles["section_header"] = ParagraphStyle(
        "section_header", parent=base["Heading1"],
        fontSize=14, textColor=C_ACCENT, fontName="Helvetica-Bold",
        spaceBefore=16, spaceAfter=6,
    )
    styles["subsection"] = ParagraphStyle(
        "subsection", parent=base["Heading2"],
        fontSize=11, textColor=C_BLACK, fontName="Helvetica-Bold",
        spaceBefore=10, spaceAfter=4,
    )
    styles["body"] = ParagraphStyle(
        "body", parent=base["Normal"],
        fontSize=9, textColor=C_BLACK, fontName="Helvetica",
        spaceAfter=4, leading=13,
    )
    styles["body_small"] = ParagraphStyle(
        "body_small", parent=base["Normal"],
        fontSize=8, textColor=C_GRAY, fontName="Helvetica",
        spaceAfter=2, leading=11,
    )
    styles["table_header"] = ParagraphStyle(
        "table_header", parent=base["Normal"],
        fontSize=8, textColor=C_WHITE, fontName="Helvetica-Bold",
        alignment=TA_LEFT,
    )
    styles["table_cell"] = ParagraphStyle(
        "table_cell", parent=base["Normal"],
        fontSize=8, textColor=C_BLACK, fontName="Helvetica",
        leading=10,
    )
    styles["table_cell_mono"] = ParagraphStyle(
        "table_cell_mono", parent=base["Normal"],
        fontSize=7.5, textColor=C_BLACK, fontName="Courier",
        leading=10,
    )
    styles["footer"] = ParagraphStyle(
        "footer", parent=base["Normal"],
        fontSize=7, textColor=C_GRAY, fontName="Helvetica",
        alignment=TA_CENTER,
    )
    return styles


# ─── Cover page — drawn directly on canvas for precise layout ─────────────────

def _draw_cover(canvas, doc, meta: Dict):
    """Draw the entire cover page using canvas primitives."""
    w, h = A4
    cx   = w / 2     # horizontal centre

    # ── Dark background ───────────────────────────────────────────────────────
    canvas.setFillColor(C_DARK_BG)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    # ── Accent stripe across middle ───────────────────────────────────────────
    canvas.setFillColor(C_ACCENT)
    canvas.rect(0, h * 0.38, w, 3, fill=1, stroke=0)

    # ── Title block (top third) ───────────────────────────────────────────────
    y = h - 4.5 * cm
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 28)
    canvas.drawCentredString(cx, y, "IIFVDCAS")

    y -= 0.7 * cm
    canvas.setFillColor(C_INDIGO_LT)
    canvas.setFont("Helvetica", 13)
    canvas.drawCentredString(cx, y, "IoT Firmware Security Assessment Report")

    # ── Device name ───────────────────────────────────────────────────────────
    y -= 1.6 * cm
    canvas.setFillColor(C_WHITE)
    canvas.setFont("Helvetica-Bold", 20)
    canvas.drawCentredString(cx, y, meta.get("device_name", "Unknown Device"))

    y -= 0.6 * cm
    canvas.setFillColor(C_INDIGO_LT)
    canvas.setFont("Helvetica", 11)
    fw   = meta.get("firmware_version", "unknown")
    arch = meta.get("architecture",     "unknown")
    canvas.drawCentredString(cx, y, f"Firmware: {fw}   |   Arch: {arch}")

    # ── Risk score block ──────────────────────────────────────────────────────
    risk_score = meta.get("risk_score", 0.0)
    risk_label = meta.get("risk_label", "UNKNOWN")
    risk_color = RISK_COLORS.get(risk_label, C_GRAY)

    # Score number — large, centred
    y -= 2.5 * cm
    canvas.setFillColor(risk_color)
    canvas.setFont("Helvetica-Bold", 52)
    canvas.drawCentredString(cx, y, f"{risk_score:.0f}")

    # "/100" — smaller, right of centre, same baseline
    score_str  = f"{risk_score:.0f}"
    score_w    = canvas.stringWidth(score_str, "Helvetica-Bold", 52)
    canvas.setFillColor(C_INDIGO_LT)
    canvas.setFont("Helvetica", 16)
    canvas.drawString(cx + score_w / 2 + 4, y + 4, " / 100")

    # Risk label — below the number
    y -= 0.9 * cm
    canvas.setFillColor(risk_color)
    canvas.setFont("Helvetica-Bold", 16)
    canvas.drawCentredString(cx, y, risk_label)

    # "Overall firmware risk" caption
    y -= 0.55 * cm
    canvas.setFillColor(C_INDIGO_LT)
    canvas.setFont("Helvetica", 10)
    canvas.drawCentredString(cx, y, "Overall firmware risk")

    # ── Meta table (bottom third) ─────────────────────────────────────────────
    scan_date    = (meta.get("generated_at") or "")[:10]
    comp_score   = meta.get("compliance_score", 0)
    total_cves   = meta.get("total_cves",       0)
    crit_cves    = meta.get("critical_cves",    0)
    affected     = meta.get("affected_count",   0)
    sbom_count   = meta.get("sbom_count",       0)

    rows = [
        ("Scan date:",          scan_date),
        ("Compliance score:",   f"{comp_score:.1f} / 100"),
        ("Total CVEs:",         str(total_cves)),
        ("CRITICAL CVEs:",      str(crit_cves)),
        ("Affected components:", str(affected)),
        ("SBOM components:",    str(sbom_count)),
    ]

    # Table positioned in the lower quarter
    table_top  = h * 0.34   # just above the accent stripe
    row_h      = 0.55 * cm
    col1_x     = cx - 5.5 * cm
    col2_x     = cx + 0.5 * cm
    y_row      = table_top

    # Separator line above table
    canvas.setStrokeColor(C_ACCENT)
    canvas.setLineWidth(0.5)
    canvas.line(col1_x - 0.2 * cm, y_row + 0.3 * cm,
                col2_x + 5 * cm,   y_row + 0.3 * cm)

    for label, value in rows:
        y_row -= row_h
        canvas.setFillColor(C_INDIGO_LT)
        canvas.setFont("Helvetica", 10)
        canvas.drawString(col1_x, y_row, label)

        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(col2_x, y_row, value)

    # Bottom separator
    canvas.setStrokeColor(C_ACCENT)
    canvas.line(col1_x - 0.2 * cm, y_row - 0.25 * cm,
                col2_x + 5 * cm,   y_row - 0.25 * cm)

    # ── Footer ────────────────────────────────────────────────────────────────
    canvas.setFillColor(C_GRAY)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(cx, 1.2 * cm, "Confidential — IIFVDCAS Security Assessment Platform")


# ─── Header/footer for inner pages ────────────────────────────────────────────

def _on_page(canvas, doc, report_meta: Dict):
    canvas.saveState()
    w, h = A4

    if doc.page == 1:
        # Cover page drawn entirely by _draw_cover (called separately)
        pass
    else:
        # Header bar
        canvas.setFillColor(C_ACCENT)
        canvas.rect(0, h - 26, w, 26, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(1.5 * cm, h - 17, "IIFVDCAS Security Assessment Report")
        device = report_meta.get("device_name", "Unknown Device")
        canvas.drawRightString(w - 1.5 * cm, h - 17, device)

        # Footer
        canvas.setFillColor(C_LIGHT_GRAY)
        canvas.rect(0, 0, w, 20, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_GRAY)
        canvas.drawString(1.5 * cm, 7,
                          f"Confidential — Generated {report_meta.get('generated_at','')}")
        canvas.drawCentredString(w / 2, 7, f"Page {doc.page}")
        canvas.drawRightString(w - 1.5 * cm, 7, "IIFVDCAS v1.0")

    canvas.restoreState()


# ─── Section builders ─────────────────────────────────────────────────────────

def _cover_page_flowable() -> List:
    """Return an empty page-break so Platypus reserves page 1 for the canvas cover."""
    return [PageBreak()]


def _executive_summary(styles, meta: Dict, top_risks: List, compliance_results: List) -> List:
    elems = []
    elems.append(Paragraph("Executive Summary", styles["section_header"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    risk_label = meta.get("risk_label", "UNKNOWN")
    risk_score = meta.get("risk_score", 0.0)
    comp_score = meta.get("compliance_score", 0.0)
    risk_color = RISK_COLORS.get(risk_label, C_GRAY)

    stat_data = [[
        Paragraph(f"<font size=18 color='#{_hex(risk_color)}'><b>{risk_score:.0f}</b></font><br/>"
                  f"<font size=8 color='gray'>Risk score</font>", styles["body"]),
        Paragraph(f"<font size=18><b>{meta.get('total_cves',0)}</b></font><br/>"
                  f"<font size=8 color='gray'>Total CVEs</font>", styles["body"]),
        Paragraph(f"<font size=18 color='#{_hex(C_RED)}'><b>{meta.get('critical_cves',0)}</b></font><br/>"
                  f"<font size=8 color='gray'>Critical CVEs</font>", styles["body"]),
        Paragraph(f"<font size=18><b>{comp_score:.0f}%</b></font><br/>"
                  f"<font size=8 color='gray'>Compliance</font>", styles["body"]),
    ]]
    st = Table(stat_data, colWidths=[4 * cm] * 4)
    st.setStyle(TableStyle([
        ("BOX",          (0, 0), (-1, -1), 0.5, C_MED_GRAY),
        ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_MED_GRAY),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [C_WHITE]),
    ]))
    elems.append(st)
    elems.append(Spacer(1, 10))

    if top_risks:
        elems.append(Paragraph("Top critical findings", styles["subsection"]))
        risk_rows = [[
            Paragraph("CVE ID",        styles["table_header"]),
            Paragraph("Component",     styles["table_header"]),
            Paragraph("CVSS",          styles["table_header"]),
            Paragraph("Severity",      styles["table_header"]),
            Paragraph("Action required", styles["table_header"]),
        ]]
        for r in top_risks[:5]:
            sev   = r.get("exploitability", "unknown")
            sev_c = SEV_COLORS.get(sev, C_GRAY)
            action = r.get("remediation", "")
            risk_rows.append([
                Paragraph(r.get("cve_id", "?"), styles["table_cell_mono"]),
                Paragraph(r.get("component", "?"), styles["table_cell"]),
                Paragraph(str(r.get("cvss_score", "?")), styles["table_cell"]),
                Paragraph(f"<font color='#{_hex(sev_c)}'><b>{sev.upper()}</b></font>",
                          styles["table_cell"]),
                Paragraph((action[:80] + "…") if len(action) > 80 else action,
                          styles["body_small"]),
            ])
        rt = Table(risk_rows, colWidths=[3.2*cm, 2.8*cm, 1.2*cm, 1.8*cm, 7*cm])
        _apply_table_style(rt)
        elems.append(rt)

    elems.append(Spacer(1, 8))

    pass_count    = sum(1 for r in compliance_results if r.status == PASS)
    fail_count    = sum(1 for r in compliance_results if r.status == FAIL)
    partial_count = sum(1 for r in compliance_results if r.status == PARTIAL)
    unknown_count = sum(1 for r in compliance_results if r.status == UNKNOWN)
    total_count   = len(compliance_results)

    elems.append(Paragraph("Compliance overview", styles["subsection"]))
    comp_row = [
        [Paragraph("Pass",    styles["table_header"]),
         Paragraph("Fail",    styles["table_header"]),
         Paragraph("Partial", styles["table_header"]),
         Paragraph("Unknown", styles["table_header"]),
         Paragraph("Total",   styles["table_header"])],
        [Paragraph(f"<font color='#{_hex(C_GREEN)}'><b>{pass_count}</b></font>",    styles["table_cell"]),
         Paragraph(f"<font color='#{_hex(C_RED)}'><b>{fail_count}</b></font>",      styles["table_cell"]),
         Paragraph(f"<font color='#{_hex(C_AMBER)}'><b>{partial_count}</b></font>", styles["table_cell"]),
         Paragraph(str(unknown_count), styles["table_cell"]),
         Paragraph(str(total_count),   styles["table_cell"])],
    ]
    ct = Table(comp_row, colWidths=[3.2*cm]*5)
    ct.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), C_ACCENT),
        ("TEXTCOLOR",    (0, 0), (-1, 0), C_WHITE),
        ("BOX",          (0, 0), (-1, -1), 0.5, C_MED_GRAY),
        ("INNERGRID",    (0, 0), (-1, -1), 0.5, C_MED_GRAY),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ]))
    elems.append(ct)
    return elems


def _vulnerability_section(styles, cve_findings: List) -> List:
    elems = [PageBreak()]
    elems.append(Paragraph("Vulnerability Findings", styles["section_header"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    if not cve_findings:
        elems.append(Paragraph("No CVE findings.", styles["body"]))
        return elems

    shown = sorted(cve_findings, key=lambda f: -(f.get("cvss_score") or 0))[:40]

    rows = [[
        Paragraph("CVE ID",    styles["table_header"]),
        Paragraph("Component", styles["table_header"]),
        Paragraph("Ver",       styles["table_header"]),
        Paragraph("CVSS",      styles["table_header"]),
        Paragraph("Severity",  styles["table_header"]),
        Paragraph("EPSS",      styles["table_header"]),
        Paragraph("KEV",       styles["table_header"]),
        Paragraph("VEX",       styles["table_header"]),
    ]]
    for f in shown:
        sev   = (f.get("cvss_severity") or "").upper()
        sev_c = {"CRITICAL":C_RED,"HIGH":C_ORANGE,"MEDIUM":C_AMBER,"LOW":C_BLUE}.get(sev, C_GRAY)
        vex   = f.get("vex_status", "")
        vex_c = {"affected":C_RED,"not_affected":C_GREEN,
                 "fixed":C_BLUE,"under_investigation":C_AMBER}.get(vex, C_GRAY)
        epss  = f.get("epss_score", 0) or 0
        rows.append([
            Paragraph(f.get("cve_id","?"),            styles["table_cell_mono"]),
            Paragraph(f.get("component","?"),          styles["table_cell"]),
            Paragraph((f.get("version","?") or "")[:10], styles["table_cell"]),
            Paragraph(str(f.get("cvss_score","?")),    styles["table_cell"]),
            Paragraph(f"<font color='#{_hex(sev_c)}'><b>{sev}</b></font>", styles["table_cell"]),
            Paragraph(f"{epss:.1%}",                   styles["table_cell"]),
            Paragraph("YES" if f.get("is_kev") else "—", styles["table_cell"]),
            Paragraph(f"<font color='#{_hex(vex_c)}'>{vex[:12]}</font>", styles["table_cell"]),
        ])

    t = Table(rows, colWidths=[3.0*cm,2.6*cm,1.6*cm,1.0*cm,1.8*cm,1.2*cm,0.8*cm,2.0*cm])
    _apply_table_style(t)
    elems.append(t)

    if len(cve_findings) > 40:
        elems.append(Paragraph(
            f"Showing top 40 of {len(cve_findings)} CVEs by CVSS score.",
            styles["body_small"],
        ))
    return elems


def _compliance_section(styles, results) -> List:
    elems = [PageBreak()]
    elems.append(Paragraph("Compliance Gap Analysis", styles["section_header"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    by_standard: Dict[str, list] = {}
    for r in results:
        # Support both ControlResult dataclass and plain dict (from asdict())
        std = r.get("standard") if isinstance(r, dict) else r.standard
        by_standard.setdefault(std, []).append(r)

    for standard, ctrl_list in by_standard.items():
        elems.append(Paragraph(standard, styles["subsection"]))
        rows = [[
            Paragraph("Control",        styles["table_header"]),
            Paragraph("Title",          styles["table_header"]),
            Paragraph("Status",         styles["table_header"]),
            Paragraph("Severity",       styles["table_header"]),
            Paragraph("Gap / Evidence", styles["table_header"]),
        ]]
        for r in ctrl_list:
            # Normalise to dict access
            if isinstance(r, dict):
                ctrl_id  = r.get("control_id", "?")
                title    = r.get("title",      "?")
                status   = r.get("status",     "unknown")
                severity = r.get("severity",   "info")
                gaps     = r.get("gaps",       []) or []
                evidence = r.get("evidence",   []) or []
            else:
                ctrl_id  = r.control_id
                title    = r.title
                status   = r.status
                severity = r.severity
                gaps     = r.gaps    or []
                evidence = r.evidence or []

            status_c = STATUS_COLORS.get(status,   C_GRAY)
            sev_c    = SEV_COLORS.get(severity, C_GRAY)
            gap_text = (
                (gaps[0][:80] + "…") if gaps and len(gaps[0]) > 80
                else (gaps[0] if gaps
                      else (evidence[0][:80] if evidence else "—"))
            )
            rows.append([
                Paragraph(ctrl_id,  styles["table_cell_mono"]),
                Paragraph(title,    styles["table_cell"]),
                Paragraph(f"<font color='#{_hex(status_c)}'><b>{status.upper()}</b></font>",
                          styles["table_cell"]),
                Paragraph(f"<font color='#{_hex(sev_c)}'>{severity}</font>",
                          styles["table_cell"]),
                Paragraph(gap_text, styles["body_small"]),
            ])
        t = Table(rows, colWidths=[1.8*cm, 4.5*cm, 1.6*cm, 1.6*cm, 6.5*cm])
        _apply_table_style(t)
        elems.append(t)
        elems.append(Spacer(1, 6))
    return elems


def _crypto_section(styles, cbom_comps: List) -> List:
    elems = []
    elems.append(Paragraph("Cryptographic Posture (CBOM)", styles["section_header"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))

    if not cbom_comps:
        elems.append(Paragraph("No cryptographic assets detected.", styles["body"]))
        return elems

    rows = [[
        Paragraph("Algorithm", styles["table_header"]),
        Paragraph("Category",  styles["table_header"]),
        Paragraph("Strength",  styles["table_header"]),
        Paragraph("Context",   styles["table_header"]),
    ]]
    for c in cbom_comps:
        strength = c.get("strength", "unknown")
        str_c    = {"strong":"green","acceptable":"blue",
                    "weak":"orange","insecure":"red"}.get(strength, "gray")
        rows.append([
            Paragraph(c.get("algorithm","?"), styles["table_cell"]),
            Paragraph(c.get("category","?"),  styles["table_cell"]),
            Paragraph(f"<font color='{str_c}'><b>{strength}</b></font>",
                      styles["table_cell"]),
            Paragraph((c.get("context","") or "—")[:80], styles["body_small"]),
        ])
    t = Table(rows, colWidths=[3*cm, 3*cm, 2.5*cm, 7.5*cm])
    _apply_table_style(t)
    elems.append(t)
    return elems


def _remediation_section(styles, remediation_plan: List) -> List:
    elems = [PageBreak()]
    elems.append(Paragraph("Remediation Plan", styles["section_header"]))
    elems.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT, spaceAfter=8))
    elems.append(Paragraph(
        "Actions ordered by priority. Address P0 items within 24 hours, P1 within 7 days.",
        styles["body"],
    ))
    elems.append(Spacer(1, 6))

    if not remediation_plan:
        elems.append(Paragraph("No remediation actions required.", styles["body"]))
        return elems

    rows = [[
        Paragraph("Priority",  styles["table_header"]),
        Paragraph("Component", styles["table_header"]),
        Paragraph("CVEs",      styles["table_header"]),
        Paragraph("Action",    styles["table_header"]),
    ]]
    for item in remediation_plan:
        pri   = item.get("priority", "?")
        pri_c = {"CRITICAL":C_RED,"HIGH":C_ORANGE,
                 "MEDIUM":C_AMBER,"LOW":C_BLUE}.get(pri, C_GRAY)
        action = item.get("action", "")
        rows.append([
            Paragraph(f"<font color='#{_hex(pri_c)}'><b>{pri}</b></font>",
                      styles["table_cell"]),
            Paragraph(item.get("component","?"), styles["table_cell"]),
            Paragraph(str(item.get("affected_cves", 0)), styles["table_cell"]),
            Paragraph((action[:120] + "…") if len(action) > 120 else action,
                      styles["body_small"]),
        ])
    t = Table(rows, colWidths=[2.2*cm, 3*cm, 1.2*cm, 9.6*cm])
    _apply_table_style(t)
    elems.append(t)
    return elems


# ─── Main builder ─────────────────────────────────────────────────────────────

def build_pdf(
    output_path:        str,
    report_meta:        Dict,
    top_risks:          List,
    cve_findings:       List,
    compliance_results: List[ControlResult],
    cbom_comps:         List,
    remediation_plan:   List,
) -> str:
    styles = _make_styles()

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=1.5*cm, leftMargin=1.5*cm,
        topMargin=1.8*cm,   bottomMargin=1.5*cm,
        title=f"IIFVDCAS — {report_meta.get('device_name','?')}",
        author="IIFVDCAS",
    )

    story = []

    # Page 1: cover — drawn via canvas in onFirstPage callback
    # We push a blank PageBreak so Platypus reserves page 1
    story.append(PageBreak())

    # Pages 2+: content
    story += _executive_summary(styles, report_meta, top_risks, compliance_results)
    story += _vulnerability_section(styles, cve_findings)
    story += _compliance_section(styles, compliance_results)
    story.append(Spacer(1, 10))
    story += _crypto_section(styles, cbom_comps)
    story += _remediation_section(styles, remediation_plan)

    def on_first_page(canvas, doc):
        # Draw pixel-perfect cover on page 1
        canvas.saveState()
        _draw_cover(canvas, doc, report_meta)
        canvas.restoreState()

    def on_later_pages(canvas, doc):
        _on_page(canvas, doc, report_meta)

    doc.build(story, onFirstPage=on_first_page, onLaterPages=on_later_pages)
    logger.info(f"[PDF] Written: {output_path}")
    return output_path


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _apply_table_style(t: Table):
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_ACCENT),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_LIGHT_GRAY]),
        ("BOX",           (0, 0), (-1,-1), 0.5, C_MED_GRAY),
        ("INNERGRID",     (0, 0), (-1,-1), 0.3, C_MED_GRAY),
        ("TOPPADDING",    (0, 0), (-1,-1), 3),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 3),
        ("LEFTPADDING",   (0, 0), (-1,-1), 4),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
    ]))


def _hex(color) -> str:
    try:
        r = int(color.red   * 255)
        g = int(color.green * 255)
        b = int(color.blue  * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "888888"
