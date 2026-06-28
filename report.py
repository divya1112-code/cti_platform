from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from datetime import datetime

def generate_report(ioc, ioc_type, vt_score, abuse_score, otx_score, final_score, verdict):

    filename = f"report_{ioc.replace('.', '_')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#00d4ff'),
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#7b2ff7'),
        spaceAfter=5
    )

    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=5
    )

    story.append(Paragraph("CTI Threat Intelligence Platform", title_style))
    story.append(Paragraph("Threat Investigation Report", styles['Heading2']))
    story.append(Spacer(1, 0.3*inch))

    story.append(Paragraph("IOC Information", heading_style))
    ioc_data = [
        ["Field", "Value"],
        ["IOC", ioc],
        ["Type", ioc_type.upper()],
        ["Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]

    ioc_table = Table(ioc_data, colWidths=[2*inch, 4*inch])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#00d4ff')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f0f0')]),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(ioc_table)
    story.append(Spacer(1, 0.3*inch))

    story.append(Paragraph("Threat Intelligence Scores", heading_style))
    score_data = [
        ["Source", "Score", "Weight"],
        ["VirusTotal", f"{vt_score}/100", "40%"],
        ["AbuseIPDB", f"{abuse_score}/100", "30%"],
        ["AlienVault OTX", f"{otx_score}/100", "30%"],
        ["FINAL SCORE", f"{final_score}/100", "100%"],
    ]

    score_table = Table(score_data, colWidths=[2*inch, 2*inch, 2*inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#7b2ff7')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 11),
        ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#00d4ff')),
        ('ROWBACKGROUNDS', (0,1), (-1,-2), [colors.white, colors.HexColor('#f0f0f0')]),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.3*inch))

    story.append(Paragraph("Verdict", heading_style))

    if final_score >= 71:
        verdict_color = colors.HexColor('#dc3545')
        recommendation = "This IOC is highly dangerous. Block immediately and investigate all systems that may have interacted with it."
    elif final_score >= 31:
        verdict_color = colors.HexColor('#ffc107')
        recommendation = "This IOC shows suspicious activity. Monitor closely and proceed with extreme caution."
    else:
        verdict_color = colors.HexColor('#28a745')
        recommendation = "This IOC appears to be safe based on current threat intelligence data."

    verdict_style = ParagraphStyle(
        'VerdictStyle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=verdict_color,
        spaceAfter=10
    )

    story.append(Paragraph(verdict, verdict_style))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("Recommendation", heading_style))
    story.append(Paragraph(recommendation, normal_style))
    story.append(Spacer(1, 0.3*inch))

    story.append(Paragraph("Disclaimer", heading_style))
    story.append(Paragraph(
        "This report was generated automatically by CTI Threat Intelligence Platform. "
        "Results are based on data from VirusTotal, AbuseIPDB, and AlienVault OTX. "
        "Always verify findings with additional investigation before taking action.",
        normal_style
    ))

    doc.build(story)
    return filename
