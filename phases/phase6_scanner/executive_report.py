"""
Enigma pqc-scanner v3: Executive PDF Report for CISOs.

Generates a professional Bifrost-themed PDF with:
  - Executive summary with risk score
  - Compliance dashboard (CNSA 2.0, NIST IR 8547, PCI DSS 4.0)
  - Top findings with remediation priorities
  - Migration roadmap with timeline
  - Dependency analysis
  - Cost/effort estimates
"""

from __future__ import annotations
import os
from datetime import datetime
from typing import Dict, List

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from pqc_scanner import ScanResult, Severity
from compliance import analyze_compliance, ComplianceStatus

# Enigma theme
NAV = HexColor('#0A0E1A')
PANEL = HexColor('#111827')
HDR = HexColor('#1C2333')
GOLD = HexColor('#D4AF37')
ICE = HexColor('#7EB8DA')
FG = HexColor('#E2E8F0')
FG2 = HexColor('#8892A8')
RED = HexColor('#DC4A4A')
GREEN = HexColor('#48BB78')
ORANGE = HexColor('#E8853D')


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle('ExTitle', parent=s['Title'], fontSize=26, textColor=GOLD, alignment=TA_CENTER, spaceAfter=4))
    s.add(ParagraphStyle('ExSub', parent=s['Normal'], fontSize=12, textColor=ICE, alignment=TA_CENTER, spaceAfter=16))
    s.add(ParagraphStyle('ExH1', parent=s['Heading1'], fontSize=16, textColor=GOLD, spaceAfter=8, spaceBefore=14))
    s.add(ParagraphStyle('ExH2', parent=s['Heading2'], fontSize=13, textColor=ICE, spaceAfter=6, spaceBefore=10))
    s.add(ParagraphStyle('ExBody', parent=s['Normal'], fontSize=10, textColor=FG, spaceAfter=6, leading=14))
    s.add(ParagraphStyle('ExSmall', parent=s['Normal'], fontSize=8, textColor=FG2, spaceAfter=4))
    s.add(ParagraphStyle('ExBig', parent=s['Normal'], fontSize=20, textColor=GOLD, alignment=TA_CENTER))
    return s


def _bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAV)
    canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
    canvas.setFillColor(FG2)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(inch, 0.35*inch, f'CONFIDENTIAL // PQC Assessment Report // Page {doc.page}')
    canvas.drawRightString(letter[0]-inch, 0.35*inch, datetime.now().strftime('%Y-%m-%d'))
    canvas.restoreState()


def _table(data, widths=None):
    t = Table(data, colWidths=widths)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), HDR),
        ('TEXTCOLOR', (0, 0), (-1, 0), GOLD),
        ('TEXTCOLOR', (0, 1), (-1, -1), FG),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#2A3040')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(('BACKGROUND', (0, i), (-1, i), HexColor('#0F1525')))
    t.setStyle(TableStyle(style))
    return t


def generate_executive_report(result: ScanResult, org_name: str = "Organization",
                               output_path: str = None) -> str:
    """Generate executive PDF report from scan results."""
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), '..', '..', 'PQC_Executive_Report.pdf')

    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.6*inch)

    story = []
    result.compute_summary()
    compliance = analyze_compliance(result)

    # ---- TITLE PAGE ----
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("POST-QUANTUM CRYPTOGRAPHY", styles['ExTitle']))
    story.append(Paragraph("Assessment Report", styles['ExSub']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(org_name, styles['ExH2']))
    story.append(Spacer(1, 0.4*inch))

    score = result.risk_score
    score_color = 'red' if score > 50 else ('orange' if score > 20 else 'green')
    stats = [
        [str(score), str(len(result.findings)), str(result.files_scanned)],
        ['Risk Score', 'Findings', 'Files Scanned'],
    ]
    st = Table(stats, colWidths=[2*inch]*3)
    st.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, 0), GOLD),
        ('TEXTCOLOR', (0, 1), (-1, 1), FG2),
        ('FONTSIZE', (0, 0), (-1, 0), 28),
        ('FONTSIZE', (0, 1), (-1, 1), 10),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(st)
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"Scan date: {result.scan_date[:10]}", styles['ExSmall']))
    story.append(Paragraph("CONFIDENTIAL", styles['ExSmall']))
    story.append(PageBreak())

    # ---- EXECUTIVE SUMMARY ----
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles['ExH1']))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))

    crit = result.summary.get('CRITICAL', 0)
    high = result.summary.get('HIGH', 0)

    if crit > 0:
        story.append(Paragraph(
            f"<b>IMMEDIATE ACTION REQUIRED.</b> This assessment found <b>{crit} CRITICAL</b> "
            f"and <b>{high} HIGH</b> severity quantum-vulnerable cryptographic implementations. "
            f"These algorithms will be broken by Shor's algorithm when cryptographically relevant "
            f"quantum computers (CRQC) become available, estimated between 2030-2040.",
            styles['ExBody']))
    else:
        story.append(Paragraph(
            f"This assessment found <b>{len(result.findings)} findings</b> across "
            f"{result.files_scanned} files. No CRITICAL quantum vulnerabilities were detected.",
            styles['ExBody']))

    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The primary threat is <b>Harvest Now, Decrypt Later (HNDL)</b>: adversaries "
        "can intercept and store encrypted data today, then decrypt it once quantum "
        "computers are available. This makes key exchange migration (RSA, ECDH, DH) "
        "urgent even before CRQC exists.",
        styles['ExBody']))
    story.append(PageBreak())

    # ---- COMPLIANCE DASHBOARD ----
    story.append(Paragraph("2. COMPLIANCE STATUS", styles['ExH1']))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))

    for fw_name, findings in compliance.items():
        nc = sum(1 for f in findings if f.status == ComplianceStatus.NON_COMPLIANT)
        dep = sum(1 for f in findings if f.status == ComplianceStatus.DEPRECATED)
        if nc > 0:
            verdict = "NON-COMPLIANT"
        elif dep > 0:
            verdict = "AT RISK"
        else:
            verdict = "COMPLIANT"

        story.append(Paragraph(f"{fw_name}: <b>{verdict}</b>", styles['ExH2']))
        rows = [['Algorithm', 'Status', 'Deadline', 'Findings', 'Action']]
        for f in findings:
            rows.append([f.algorithm, f.status, f.deadline or '-',
                        str(f.finding_count), (f.replacement or '-')[:40]])
        story.append(_table(rows, [1.1*inch, 1.2*inch, 0.7*inch, 0.7*inch, 2.5*inch]))
        story.append(Spacer(1, 10))

    story.append(PageBreak())

    # ---- TOP FINDINGS ----
    story.append(Paragraph("3. TOP FINDINGS", styles['ExH1']))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))

    sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
    for sev in sev_order:
        sev_findings = [f for f in result.findings if f.severity == sev]
        if not sev_findings:
            continue
        story.append(Paragraph(f"{sev.value} ({len(sev_findings)} findings)", styles['ExH2']))
        rows = [['ID', 'Algorithm', 'File', 'Line', 'Replacement']]
        for f in sev_findings[:10]:
            rel = os.path.basename(f.file)
            rows.append([f.id, f.algorithm, rel[:25], str(f.line), f.pqc_replacement[:30]])
        story.append(_table(rows, [0.7*inch, 0.8*inch, 1.8*inch, 0.5*inch, 2.4*inch]))
        if len(sev_findings) > 10:
            story.append(Paragraph(f"  ... and {len(sev_findings)-10} more {sev.value} findings", styles['ExSmall']))
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ---- MIGRATION ROADMAP ----
    story.append(Paragraph("4. RECOMMENDED MIGRATION ROADMAP", styles['ExH1']))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))

    phases = [
        ("Phase 1: Immediate (0-3 months)", "CRITICAL", [
            "Replace all RSA/DH key exchange with ML-KEM-768 hybrid (X25519+ML-KEM)",
            "Enable PQC key exchange in TLS 1.3 (Chrome/Cloudflare already support this)",
            "Upgrade AES-128 to AES-256 across all systems",
            "Remove MD5, SHA-1, DES, 3DES, RC4 from all codepaths",
        ]),
        ("Phase 2: Short-term (3-12 months)", "HIGH", [
            "Migrate RSA/ECDSA code signing to ML-DSA-65 (FIPS 204)",
            "Update SSH key exchange to sntrup761+x25519 (OpenSSH 9.0+)",
            "Replace ECDSA/Ed25519 certificates with ML-DSA when CA supports it",
            "Audit all JWT/JOSE signing for PQC compatibility",
        ]),
        ("Phase 3: Medium-term (12-24 months)", "MEDIUM", [
            "Complete certificate infrastructure migration to PQC",
            "Deploy PQC-enabled VPN (IPsec with ML-KEM via RFC 9370)",
            "Update S/MIME email encryption to PQC",
            "Migrate all code signing and firmware signing",
        ]),
        ("Phase 4: Validation (Ongoing)", "", [
            "Continuous PQC compliance monitoring via CI/CD (pqc-scanner)",
            "Regular certificate chain audits",
            "Track NIST algorithm health (monitor for cryptanalytic advances)",
            "Performance benchmarking of PQC vs classical implementations",
        ]),
    ]

    for title, sev, items in phases:
        story.append(Paragraph(title, styles['ExH2']))
        for item in items:
            story.append(Paragraph(f"  - {item}", styles['ExBody']))
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # ---- COST ESTIMATES ----
    story.append(Paragraph("5. EFFORT & COST ESTIMATES", styles['ExH1']))
    story.append(HRFlowable(width="100%", thickness=1, color=GOLD, spaceAfter=8))

    cost_data = [
        ['Phase', 'Effort', 'Cost Range', 'Risk if Delayed'],
        ['Key exchange (TLS/SSH)', '2-4 weeks', '$15K-40K', 'HNDL attack exposure NOW'],
        ['Certificate migration', '4-8 weeks', '$30K-80K', 'Non-compliance by 2030'],
        ['Code signing', '2-4 weeks', '$10K-30K', 'Supply chain risk'],
        ['Symmetric upgrade (AES)', '1-2 weeks', '$5K-15K', 'Reduced security margin'],
        ['CI/CD integration', '1 week', '$5K-10K', 'Regression risk'],
        ['Full validation', '2-4 weeks', '$15K-40K', 'Audit failure risk'],
        ['TOTAL', '12-24 weeks', '$80K-215K', ''],
    ]
    story.append(_table(cost_data, [1.8*inch, 0.9*inch, 1*inch, 2.5*inch]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Cost estimates assume a mid-size enterprise (50-200 developers, 10-50 services). "
        "Actual costs depend on codebase size, language diversity, and deployment complexity.",
        styles['ExSmall']))

    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("CONFIDENTIAL // Generated by Enigma pqc-scanner", styles['ExSmall']))

    doc.build(story, onFirstPage=_bg, onLaterPages=_bg)
    return output_path
