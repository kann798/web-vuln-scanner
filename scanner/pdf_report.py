"""
PDF Report Generator using ReportLab.
Generates professional security assessment reports.
"""

import io
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfgen import canvas


# ─────────────────────────────────────────────
# Color palette
# ─────────────────────────────────────────────
DARK_BG       = colors.HexColor("#FFFFFF")
CARD_BG       = colors.HexColor("#FFFFFF")
ACCENT        = colors.HexColor("#000000")
ACCENT_BLUE   = colors.HexColor("#181E20")
TEXT_PRIMARY  = colors.HexColor("#3689D2")
TEXT_SECONDARY= colors.HexColor("#000000")
BORDER        = colors.HexColor("#131518")

CRITICAL_COLOR= colors.HexColor("#A0A89E")
HIGH_COLOR    = colors.HexColor("#98A098")
MEDIUM_COLOR  = colors.HexColor("#438952")
LOW_COLOR     = colors.HexColor('#00AA00')
INFO_COLOR    = colors.HexColor("#1A1F22")


SEVERITY_COLORS = {
    'critical': CRITICAL_COLOR,
    'high': HIGH_COLOR,
    'medium': MEDIUM_COLOR,
    'low': LOW_COLOR,
    'info': INFO_COLOR,
}

RISK_COLORS = {
    'critical': CRITICAL_COLOR,
    'high': HIGH_COLOR,
    'medium': MEDIUM_COLOR,
    'low': LOW_COLOR,
    'info': INFO_COLOR,
}


def get_styles():
    styles = getSampleStyleSheet()
    
    custom = {
        'Title': ParagraphStyle(
            'CustomTitle',
            fontName='Helvetica-Bold',
            fontSize=28,
            leading=36,
            textColor=TEXT_PRIMARY,
            spaceBefore=0,
            spaceAfter=10,
            alignment=TA_CENTER,
        ),
        'Subtitle': ParagraphStyle(
            'Subtitle',
            fontName='Helvetica',
            fontSize=12,
            leading=18,
            textColor=TEXT_SECONDARY,
            spaceBefore=0,
            spaceAfter=10,
            alignment=TA_CENTER,
        ),
        'SectionHeader': ParagraphStyle(
            'SectionHeader',
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=ACCENT,
            spaceBefore=14,
            spaceAfter=6,
        ),
        'VulnTitle': ParagraphStyle(
            'VulnTitle',
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=TEXT_PRIMARY,
            spaceBefore=8,
            spaceAfter=4,
        ),
        'Body': ParagraphStyle(
            'Body',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_SECONDARY,
            spaceAfter=4,
            leading=14,
            alignment=TA_JUSTIFY,
        ),
        'BulletItem': ParagraphStyle(
            'BulletItem',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_SECONDARY,
            leftIndent=12,
            spaceAfter=3,
            leading=13,
        ),
        'Code': ParagraphStyle(
            'Code',
            fontName='Courier',
            fontSize=8,
            textColor=ACCENT,
            backColor=CARD_BG,
            spaceBefore=4,
            spaceAfter=4,
            leftIndent=8,
        ),
        'MetaLabel': ParagraphStyle(
            'MetaLabel',
            fontName='Helvetica-Bold',
            fontSize=8,
            textColor=TEXT_SECONDARY,
            spaceAfter=2,
        ),
        'MetaValue': ParagraphStyle(
            'MetaValue',
            fontName='Helvetica',
            fontSize=9,
            textColor=TEXT_PRIMARY,
            spaceAfter=4,
        ),
    }
    return custom


def draw_page_background(canvas_obj, doc):
    """Draw dark background and header/footer on every page."""
    width, height = A4
    
    # Dark background
    canvas_obj.saveState()
    canvas_obj.setFillColor(DARK_BG)
    canvas_obj.rect(0, 0, width, height, fill=1, stroke=0)
    
    # Top accent line
    canvas_obj.setFillColor(ACCENT)
    canvas_obj.rect(0, height - 3, width, 3, fill=1, stroke=0)
    
    # Bottom footer
    canvas_obj.setFillColor(CARD_BG)
    canvas_obj.rect(0, 0, width, 20 * mm, fill=1, stroke=0)
    
    canvas_obj.setFillColor(BORDER)
    canvas_obj.rect(0, 20 * mm, width, 0.5, fill=1, stroke=0)
    
    # Footer text
    canvas_obj.setFont('Helvetica', 8)
    canvas_obj.setFillColor(TEXT_SECONDARY)
    canvas_obj.drawString(20 * mm, 12 * mm, 'AI-Based Web Vulnerability Scanner')
    canvas_obj.drawRightString(width - 20 * mm, 12 * mm, f'Page {doc.page}')
    canvas_obj.drawCentredString(width / 2, 12 * mm, f'CONFIDENTIAL — Security Assessment Report')
    
    canvas_obj.restoreState()


def generate_pdf_report(scan_result_obj):
    """
    Generate PDF report from a ScanResult model instance.
    Returns BytesIO buffer.
    """
    buffer = io.BytesIO()
    
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=25 * mm,
        bottomMargin=28 * mm,
        title=f'Security Report — {scan_result_obj.url}',
    )
    
    styles = get_styles()
    story = []
    width = A4[0] - 40 * mm  # usable width
    
    # ── COVER PAGE ──────────────────────────────────────────
    story.append(Spacer(1, 30 * mm))

    # Title block — separated clearly
    story.append(Paragraph('SECURITY ASSESSMENT', styles['Title']))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph('AI-Powered Web Vulnerability Report', styles['Subtitle']))
    story.append(Spacer(1, 10 * mm))
    
    # Horizontal rule
    story.append(HRFlowable(width=width, thickness=1, color=ACCENT, spaceAfter=8 * mm))
    
    # Target URL box
    url_table_data = [[
        Paragraph('TARGET URL', styles['MetaLabel']),
    ], [
        Paragraph(f'<font color="#00B4FF">{scan_result_obj.url}</font>', styles['MetaValue']),
    ]]
    url_table = Table(url_table_data, colWidths=[width])
    url_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
        ('ROUNDEDCORNERS', [4, 4, 4, 4]),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('BOX', (0, 0), (-1, -1), 1, BORDER),
    ]))
    story.append(url_table)
    story.append(Spacer(1, 6 * mm))
    
    # Metadata grid
    scan_date_str = scan_result_obj.scan_date.strftime('%B %d, %Y at %H:%M UTC')
    meta_data = [
        ['SCAN DATE', 'DURATION', 'RESPONSE CODE', 'SERVER'],
        [
            scan_date_str,
            f'{scan_result_obj.scan_duration:.1f}s',
            str(scan_result_obj.risk_score),  # reuse field for display
            'Web Server',
        ],
    ]
    meta_table = Table(meta_data, colWidths=[width/4]*4)
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), CARD_BG),
        ('BACKGROUND', (0, 1), (-1, 1), DARK_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), TEXT_SECONDARY),
        ('TEXTCOLOR', (0, 1), (-1, 1), TEXT_PRIMARY),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, 0), 7),
        ('FONTSIZE', (0, 1), (-1, 1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10 * mm))
    
    # Risk Score — big display
    risk_color = RISK_COLORS.get(scan_result_obj.risk_level, INFO_COLOR)
    risk_hex = risk_color.hexval() if hasattr(risk_color, 'hexval') else '#888888'
    
    score_data = [[
        Paragraph(f'<font size="52" color="{risk_hex}"><b>{scan_result_obj.risk_score}</b></font>', 
                  ParagraphStyle('score', alignment=TA_CENTER)),
        Paragraph(f'<font size="11" color="{TEXT_SECONDARY.hexval() if hasattr(TEXT_SECONDARY,"hexval") else "#8B949E"}">RISK SCORE<br/><br/></font>'
                  f'<font size="18" color="{risk_hex}"><b>{scan_result_obj.risk_level.upper()}</b></font><br/>'
                  f'<font size="9" color="#8B949E">{scan_result_obj.vulnerabilities_found} vulnerabilities found</font>',
                  ParagraphStyle('riskLabel', alignment=TA_CENTER, leading=20)),
    ]]
    score_table = Table(score_data, colWidths=[width*0.5, width*0.5])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 14),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 14),
        ('BOX', (0, 0), (-1, -1), 2, risk_color),
        ('LINEAFTER', (0, 0), (0, 0), 0.5, BORDER),
    ]))
    story.append(score_table)
    
    story.append(PageBreak())
    
    # ── EXECUTIVE SUMMARY ────────────────────────────────────
    story.append(Paragraph('Executive Summary', styles['SectionHeader']))
    story.append(HRFlowable(width=width, thickness=0.5, color=BORDER, spaceAfter=6))
    
    vulns = scan_result_obj.vulnerabilities
    vuln_count = len(vulns)
    total_issues = sum(len(v.get('issues', [])) for v in vulns)
    
    summary_text = (
        f"This automated security assessment was conducted on <b><font color='#00B4FF'>{scan_result_obj.url}</font></b> "
        f"on {scan_date_str}. The scan completed in <b>{scan_result_obj.scan_duration:.1f} seconds</b> using an "
        f"AI-powered Random Forest classification engine combined with rule-based detection logic. "
        f"A total of <b><font color='{risk_hex}'>{vuln_count} vulnerability categories</font></b> were identified "
        f"encompassing <b>{total_issues} specific issues</b>. "
        f"The overall risk score of <b><font color='{risk_hex}'>{scan_result_obj.risk_score}/100</font></b> "
        f"places this target in the <b><font color='{risk_hex}'>{scan_result_obj.risk_level.upper()}</font></b> risk tier. "
        f"Immediate remediation action is {'strongly recommended' if scan_result_obj.risk_score >= 50 else 'advisable'}."
    )
    story.append(Paragraph(summary_text, styles['Body']))
    story.append(Spacer(1, 5 * mm))
    
    # Vulnerability summary table
    if vulns:
        story.append(Paragraph('Vulnerability Summary', styles['SectionHeader']))
        
        table_data = [['Type', 'Severity', 'Issues Found', 'Status']]
        for v in vulns:
            sev = v.get('severity', 'medium')
            sev_color = SEVERITY_COLORS.get(sev, MEDIUM_COLOR)
            sev_hex = sev_color.hexval() if hasattr(sev_color, 'hexval') else '#FFAA00'
            table_data.append([
                Paragraph(f'<b>{v["type"]}</b>', ParagraphStyle('tvt', fontName='Helvetica-Bold', fontSize=9, textColor=TEXT_PRIMARY)),
                Paragraph(f'<font color="{sev_hex}">⬤</font> {sev.upper()}', ParagraphStyle('tvs', fontName='Helvetica-Bold', fontSize=8, textColor=sev_color)),
                Paragraph(str(len(v.get('issues', []))), ParagraphStyle('tvc', fontName='Helvetica', fontSize=9, textColor=TEXT_PRIMARY, alignment=TA_CENTER)),
                Paragraph('DETECTED', ParagraphStyle('tvst', fontName='Helvetica-Bold', fontSize=8, textColor=CRITICAL_COLOR)),
            ])
        
        col_widths = [width*0.4, width*0.2, width*0.2, width*0.2]
        summary_table = Table(table_data, colWidths=col_widths)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), CARD_BG),
            ('BACKGROUND', (0, 1), (-1, -1), DARK_BG),
            ('TEXTCOLOR', (0, 0), (-1, 0), ACCENT),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('ALIGN', (2, 0), (3, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, BORDER),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [DARK_BG, CARD_BG]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 5 * mm))
    
    # ── DETAILED FINDINGS ────────────────────────────────────
    if vulns:
        story.append(Paragraph('Detailed Findings', styles['SectionHeader']))
        story.append(HRFlowable(width=width, thickness=0.5, color=BORDER, spaceAfter=8))
        
        for i, vuln in enumerate(vulns):
            sev = vuln.get('severity', 'medium')
            sev_color = SEVERITY_COLORS.get(sev, MEDIUM_COLOR)
            sev_hex = sev_color.hexval() if hasattr(sev_color, 'hexval') else '#FFAA00'
            
            elements = []
            
            # Vuln header
            header_data = [[
                Paragraph(f'<b>#{i+1} — {vuln["type"]}</b>', 
                          ParagraphStyle('vh', fontName='Helvetica-Bold', fontSize=13, textColor=TEXT_PRIMARY)),
                Paragraph(f'<font color="{sev_hex}"><b>{sev.upper()}</b></font>',
                          ParagraphStyle('vs', fontName='Helvetica-Bold', fontSize=10, textColor=sev_color, alignment=TA_RIGHT)),
            ]]
            header_table = Table(header_data, colWidths=[width*0.75, width*0.25])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
                ('LEFTPADDING', (0, 0), (0, 0), 12),
                ('RIGHTPADDING', (-1, 0), (-1, 0), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LINEBELOW', (0, 0), (-1, 0), 2, sev_color),
            ]))
            elements.append(header_table)
            
            # Description
            elements.append(Spacer(1, 3 * mm))
            elements.append(Paragraph('<b>Description</b>', 
                                       ParagraphStyle('dl', fontName='Helvetica-Bold', fontSize=9, textColor=ACCENT_BLUE, spaceAfter=3)))
            elements.append(Paragraph(vuln.get('description', ''), styles['Body']))
            
            # Issues found
            issues = vuln.get('issues', [])
            if issues:
                elements.append(Paragraph(f'<b>Issues Found ({len(issues)})</b>',
                                          ParagraphStyle('il', fontName='Helvetica-Bold', fontSize=9, textColor=ACCENT_BLUE, spaceBefore=6, spaceAfter=3)))
                for issue in issues:
                    elements.append(Paragraph(f'→  {issue}', styles['BulletItem']))
            
            # Remediation
            elements.append(Paragraph('<b>Remediation</b>',
                                       ParagraphStyle('rl', fontName='Helvetica-Bold', fontSize=9, textColor=ACCENT_BLUE, spaceBefore=6, spaceAfter=3)))
            elements.append(Paragraph(vuln.get('remediation', ''), styles['Body']))
            elements.append(Spacer(1, 5 * mm))
            
            story.append(KeepTogether(elements))
    
    else:
        story.append(Spacer(1, 10 * mm))
        clean_data = [[
            Paragraph('✅  No Critical Vulnerabilities Detected',
                      ParagraphStyle('clean', fontName='Helvetica-Bold', fontSize=14, textColor=LOW_COLOR, alignment=TA_CENTER)),
        ]]
        clean_table = Table(clean_data, colWidths=[width])
        clean_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
            ('TOPPADDING', (0, 0), (-1, -1), 20),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
            ('BOX', (0, 0), (-1, -1), 1, LOW_COLOR),
        ]))
        story.append(clean_table)
    
    # ── RECOMMENDATIONS ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph('General Recommendations', styles['SectionHeader']))
    story.append(HRFlowable(width=width, thickness=0.5, color=BORDER, spaceAfter=6))
    
    recs = [
        ('Implement Security Headers', 'Add X-Frame-Options, Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and Referrer-Policy headers to all responses.'),
        ('Use HTTPS Everywhere', 'Enforce HTTPS across all pages, implement HSTS, and use modern TLS configurations to protect data in transit.'),
        ('Input Validation & Sanitization', 'Validate and sanitize all user inputs on both client and server side. Use allowlists rather than denylists.'),
        ('Implement CSRF Protection', 'Add CSRF tokens to all state-changing forms and verify them server-side. Use SameSite cookie attribute.'),
        ('Regular Security Audits', 'Conduct regular automated and manual penetration tests. Keep all dependencies updated and monitor for CVEs.'),
        ('Principle of Least Privilege', 'Database users, file system permissions, and API keys should have only the minimum permissions required.'),
        ('Error Handling', 'Implement generic error messages for users. Log detailed errors server-side only. Never expose stack traces or DB queries.'),
        ('Dependency Management', 'Regularly audit and update third-party libraries. Use tools like pip-audit or OWASP Dependency Check.'),
    ]
    
    for title, detail in recs:
        rec_data = [[
            Paragraph(f'<b>{title}</b>', ParagraphStyle('rt', fontName='Helvetica-Bold', fontSize=9, textColor=ACCENT)),
            Paragraph(detail, styles['Body']),
        ]]
        rec_table = Table(rec_data, colWidths=[width*0.3, width*0.7])
        rec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), CARD_BG),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, BORDER),
            ('LINEBEFORE', (0, 0), (0, -1), 2, ACCENT),
        ]))
        story.append(rec_table)
        story.append(Spacer(1, 2 * mm))
    
    # ── DISCLAIMER ───────────────────────────────────────────
    story.append(Spacer(1, 8 * mm))
    story.append(HRFlowable(width=width, thickness=0.5, color=BORDER, spaceAfter=6))
    disclaimer = (
        "<b>Disclaimer:</b> This report was generated by an automated AI-powered scanning tool. "
        "Results should be validated by a qualified security professional before remediation. "
        "This tool is intended for authorized testing only. Unauthorized scanning of systems "
        "you do not own or have explicit permission to test is illegal. The authors assume no "
        "liability for misuse of this tool or its reports."
    )
    story.append(Paragraph(disclaimer, ParagraphStyle(
        'disc', fontName='Helvetica', fontSize=8, textColor=TEXT_SECONDARY,
        leading=12, alignment=TA_JUSTIFY
    )))
    
    # Build PDF
    doc.build(story, onFirstPage=draw_page_background, onLaterPages=draw_page_background)
    
    buffer.seek(0)
    return buffer