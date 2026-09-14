"""
Generates the investigator-facing PDF dossier from orchestrator.investigate() output.
NETRA — Cyber Crime Investigation Dossier
Structure: Executive Summary -> Findings by category (grouped, confidence-sorted)
-> Cross-linkage -> Full source citation appendix.
"""
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
)
from risk_gauge import compute_risk_score, render_gauge

TIER_COLORS = {"HIGH": colors.HexColor("#1a7f37"), "MED": colors.HexColor("#9a6700"), "LOW": colors.HexColor("#828282")}


def _tier(confidence: float) -> str:
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.5:
        return "MED"
    return "LOW"


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="DossierTitle", fontSize=20, leading=24, spaceAfter=6, textColor=colors.HexColor("#1a1a1a")))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=14, leading=18, spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#1a1a1a")))
    styles.add(ParagraphStyle(name="Meta", fontSize=9, textColor=colors.HexColor("#555555")))
    styles.add(ParagraphStyle(name="FindingText", fontSize=10, leading=14))
    return styles


def _findings_table(findings, styles):
    if not findings:
        return Paragraph("No findings in this category.", styles["Meta"])

    rows = [["Tier", "Confidence", "Source", "Finding"]]
    for f in sorted(findings, key=lambda x: -x.confidence):
        tier = _tier(f.confidence)
        rows.append([tier, f"{f.confidence:.2f}", f.source, Paragraph(f.fact, styles["FindingText"])])

    table = Table(rows, colWidths=[0.55*inch, 0.7*inch, 1.3*inch, 3.7*inch], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2b2b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
    ]
    for i, f in enumerate(sorted(findings, key=lambda x: -x.confidence), start=1):
        style_cmds.append(("TEXTCOLOR", (0, i), (0, i), TIER_COLORS[_tier(f.confidence)]))
        style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style_cmds))
    return table


def _summary_counts(all_findings):
    high = sum(1 for f in all_findings if _tier(f.confidence) == "HIGH")
    med = sum(1 for f in all_findings if _tier(f.confidence) == "MED")
    low = sum(1 for f in all_findings if _tier(f.confidence) == "LOW")
    flags = sum(1 for f in all_findings if "FLAG" in f.fact)
    return high, med, low, flags


def generate_pdf(result: dict, phone: str | None, email: str | None, output_path: str = "netra_report.pdf"):
    styles = _styles()
    story = []

    story.append(Paragraph("NETRA — Cyber Crime Investigation Dossier", styles["DossierTitle"]))
    story.append(Paragraph("Jaipur Police Cyber Crime Dept | Project Netra — Rohit Khatana", styles["Meta"]))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; "
        f"Subject phone: {phone or 'N/A'} &nbsp;|&nbsp; Subject email: {email or 'N/A'}",
        styles["Meta"],
    ))
    story.append(Spacer(1, 12))

    all_findings = result["phone_findings"] + result["email_findings"] + result["linkage_findings"]
    high, med, low, flags = _summary_counts(all_findings)

    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.append(Paragraph(
        f"{len(all_findings)} total findings across all intelligence sources — "
        f"{high} high-confidence, {med} medium-confidence, {low} low-confidence. "
        f"{flags} risk flag(s) raised. Every finding below is traceable to its originating "
        "source via the reference column; this report is an investigative aid, not a "
        "standalone determination of guilt or fraud.",
        styles["FindingText"],
    ))

    risk_score = compute_risk_score(all_findings)
    gauge_path = render_gauge(risk_score, output_path=output_path.replace(".pdf", "_gauge.png"))
    story.append(Spacer(1, 6))
    story.append(Image(gauge_path, width=3.0 * inch, height=1.85 * inch, hAlign="CENTER"))
    story.append(Spacer(1, 6))

    if result["phone_findings"]:
        story.append(Paragraph("Phone Number Findings", styles["SectionHeading"]))
        story.append(_findings_table(result["phone_findings"], styles))

    if result["email_findings"]:
        story.append(Paragraph("Email Findings", styles["SectionHeading"]))
        story.append(_findings_table(result["email_findings"], styles))

    if result["linkage_findings"]:
        story.append(Paragraph("Cross-Identifier Linkage", styles["SectionHeading"]))
        story.append(_findings_table(result["linkage_findings"], styles))

    story.append(PageBreak())
    story.append(Paragraph("Appendix: Full Source Citation Log", styles["SectionHeading"]))
    story.append(Paragraph(
        "Raw reference for every finding above, for verification and chain-of-evidence purposes.",
        styles["Meta"],
    ))
    story.append(Spacer(1, 8))
    appendix_rows = [["Source", "Finding", "Raw Reference"]]
    for f in all_findings:
        appendix_rows.append([f.source, Paragraph(f.fact, styles["FindingText"]), Paragraph(str(f.raw_reference)[:200], styles["Meta"])])
    appendix_table = Table(appendix_rows, colWidths=[1.1*inch, 2.9*inch, 2.3*inch], repeatRows=1)
    appendix_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b2b2b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
    ]))
    story.append(appendix_table)

    doc = SimpleDocTemplate(output_path, pagesize=letter, title="NETRA — Cyber Crime Investigation Dossier")
    doc.build(story)

    import os
    if os.path.exists(gauge_path):
        os.remove(gauge_path)  # intermediate artifact, only the PDF needs to remain

    return output_path
