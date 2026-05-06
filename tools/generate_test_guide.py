"""
Enigma — pqc-scanner Test Guide PDF Generator.

Step-by-step walkthrough for testing pqc-scanner on a real project.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Preformatted,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from datetime import datetime
import os

BG_DARK = HexColor('#0D0D1A')
PURPLE = HexColor('#9B59B6')
CYAN = HexColor('#00D4AA')
GOLD = HexColor('#F1C40F')
WHITE = HexColor('#E8E8E8')
LIGHT_GRAY = HexColor('#AAAAAA')
HEADER_BG = HexColor('#16213E')
CODE_BG = HexColor('#1A1A2E')
RED = HexColor('#E74C3C')
GREEN = HexColor('#2ECC71')

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'PQC_Scanner_Test_Guide.pdf')


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('Title2', parent=styles['Title'],
        fontSize=24, textColor=CYAN, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle('Sub', parent=styles['Normal'],
        fontSize=12, textColor=PURPLE, alignment=TA_CENTER, spaceAfter=20))
    styles.add(ParagraphStyle('H1', parent=styles['Heading1'],
        fontSize=16, textColor=CYAN, spaceAfter=8, spaceBefore=14))
    styles.add(ParagraphStyle('H2', parent=styles['Heading2'],
        fontSize=13, textColor=PURPLE, spaceAfter=6, spaceBefore=10))
    styles.add(ParagraphStyle('H3', parent=styles['Heading3'],
        fontSize=11, textColor=GOLD, spaceAfter=4, spaceBefore=6))
    styles.add(ParagraphStyle('Body', parent=styles['Normal'],
        fontSize=10, textColor=WHITE, spaceAfter=6, leading=14))
    styles.add(ParagraphStyle('Small', parent=styles['Normal'],
        fontSize=8, textColor=LIGHT_GRAY, spaceAfter=4))
    styles.add(ParagraphStyle('CodeBlock', parent=styles['Normal'],
        fontSize=8, textColor=CYAN, fontName='Courier', spaceAfter=4,
        leftIndent=16, rightIndent=16, leading=11,
        backColor=CODE_BG, borderPadding=6))
    styles.add(ParagraphStyle('Step', parent=styles['Normal'],
        fontSize=11, textColor=GOLD, spaceAfter=2, spaceBefore=8,
        fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle('Result', parent=styles['Normal'],
        fontSize=9, textColor=GREEN, spaceAfter=6, leftIndent=16))
    return styles


def bg(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
    canvas.setFillColor(LIGHT_GRAY)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(inch, 0.4 * inch, f'pqc-scanner Test Guide // Page {doc.page}')
    canvas.restoreState()


def hr():
    return HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=8, spaceBefore=8)


def generate():
    styles = build_styles()
    doc = SimpleDocTemplate(OUTPUT_PATH, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch)

    story = []

    # TITLE
    story.append(Spacer(1, inch))
    story.append(Paragraph("pqc-scanner", styles['Title2']))
    story.append(Paragraph("Step-by-Step Test Guide", styles['Sub']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(
        "This guide walks you through testing the Enigma pqc-scanner on a sample "
        "multi-language project. You will scan Python, Java, Go, JavaScript, and "
        "nginx config files for quantum-vulnerable cryptography.",
        styles['Body']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d')}", styles['Small']))
    story.append(PageBreak())

    # PREREQUISITES
    story.append(Paragraph("PREREQUISITES", styles['H1']))
    story.append(hr())
    story.append(Paragraph("You need:", styles['Body']))
    story.append(Paragraph("  - Python 3.10+ installed", styles['Body']))
    story.append(Paragraph("  - The Enigma project at C:\\Users\\jbro1\\Desktop\\Enigma", styles['Body']))
    story.append(Paragraph("  - pip install cryptography (for certificate scanning)", styles['Body']))
    story.append(Spacer(1, 10))
    story.append(Paragraph("The demo project is already created at:", styles['Body']))
    story.append(Paragraph("demo/sample_vulnerable_project/", styles['CodeBlock']))
    story.append(Paragraph(
        "It contains intentionally vulnerable code across 6 files and 4 languages.",
        styles['Body']))
    story.append(PageBreak())

    # STEP 1
    story.append(Paragraph("STEP 1: Run a Basic Text Scan", styles['H1']))
    story.append(hr())
    story.append(Paragraph("Step 1.1 - Open a terminal in the Enigma directory", styles['Step']))
    story.append(Paragraph("cd C:\\Users\\jbro1\\Desktop\\Enigma", styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 1.2 - Run the scanner on the demo project", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan demo/sample_vulnerable_project",
        styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Expected output:", styles['H3']))
    story.append(Paragraph("  - Files Scanned: 6", styles['Result']))
    story.append(Paragraph("  - Total Findings: 29", styles['Result']))
    story.append(Paragraph("  - Risk Score: 100/100", styles['Result']))
    story.append(Paragraph("  - Severity: 16 CRITICAL, 9 HIGH, 4 MEDIUM", styles['Result']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("What to look for:", styles['H3']))
    story.append(Paragraph(
        "Each finding shows the file, line number, code snippet, what's wrong, "
        "and what to replace it with. CRITICAL means Shor's algorithm breaks it. "
        "HIGH means deprecated or broken. MEDIUM means Grover-weakened.",
        styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Exit codes:", styles['H3']))
    story.append(Paragraph("  - Exit 0: No findings (quantum-safe!)", styles['Body']))
    story.append(Paragraph("  - Exit 1: Findings found (non-critical)", styles['Body']))
    story.append(Paragraph("  - Exit 2: CRITICAL findings found", styles['Body']))
    story.append(PageBreak())

    # STEP 2
    story.append(Paragraph("STEP 2: Generate an HTML Report", styles['H1']))
    story.append(hr())
    story.append(Paragraph("Step 2.1 - Generate the visual report", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan demo/sample_vulnerable_project "
        "--format html --output demo/scan_report.html",
        styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 2.2 - Open it in your browser", styles['Step']))
    story.append(Paragraph("start demo\\scan_report.html", styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("What you'll see:", styles['H3']))
    story.append(Paragraph(
        "A dark-themed dashboard with a large risk score (100), total findings count, "
        "files scanned, and a color-coded table of every finding. CRITICAL findings are "
        "red, HIGH are orange, MEDIUM are yellow. Each row shows the algorithm, code "
        "snippet, file location, and PQC replacement.",
        styles['Body']))
    story.append(PageBreak())

    # STEP 3
    story.append(Paragraph("STEP 3: Generate SARIF for CI/CD", styles['H1']))
    story.append(hr())
    story.append(Paragraph(
        "SARIF (Static Analysis Results Interchange Format) is the standard way to feed "
        "scanner results into GitHub Code Scanning and Azure DevOps.",
        styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 3.1 - Generate SARIF output", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan demo/sample_vulnerable_project "
        "--format sarif --output demo/scan_report.sarif",
        styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 3.2 - Inspect the SARIF file", styles['Step']))
    story.append(Paragraph(
        "Open demo/scan_report.sarif in any text editor. You'll see JSON with:",
        styles['Body']))
    story.append(Paragraph("  - version: '2.1.0' (SARIF standard version)", styles['Body']))
    story.append(Paragraph("  - runs[0].tool.driver.rules[] (17 quantum-vuln rules)", styles['Body']))
    story.append(Paragraph("  - runs[0].results[] (29 findings with locations)", styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 3.3 - Use in GitHub Actions (example workflow)", styles['Step']))
    story.append(Paragraph(
        "name: PQC Scan\n"
        "on: push\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: python pqc_scanner.py scan . --format sarif -o results.sarif\n"
        "      - uses: github/codeql-action/upload-sarif@v3\n"
        "        with:\n"
        "          sarif_file: results.sarif",
        styles['CodeBlock']))
    story.append(PageBreak())

    # STEP 4
    story.append(Paragraph("STEP 4: Scan Certificates", styles['H1']))
    story.append(hr())
    story.append(Paragraph(
        "The scanner can also analyze X.509 certificates for quantum-vulnerable algorithms.",
        styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 4.1 - Scan a live TLS endpoint", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan-tls google.com",
        styles['CodeBlock']))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Expected:", styles['H3']))
    story.append(Paragraph(
        "  [CRITICAL] ECDSA-256: CN=*.google.com\n"
        "    ECDSA P-256 certificate -- broken by Shor's algorithm\n"
        "    Fix: Replace with ML-DSA certificate (FIPS 204)",
        styles['Result']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 4.2 - Scan certificate files", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan-certs /path/to/certs/",
        styles['CodeBlock']))
    story.append(Paragraph(
        "Scans all .pem, .crt, .cer, .der files in the directory recursively.",
        styles['Body']))
    story.append(PageBreak())

    # STEP 5
    story.append(Paragraph("STEP 5: Scan Your Own Code", styles['H1']))
    story.append(hr())
    story.append(Paragraph(
        "Now try it on a real project. Point the scanner at any codebase:",
        styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 5.1 - Scan any directory", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan C:\\path\\to\\your\\project",
        styles['CodeBlock']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 5.2 - Filter by severity", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan . --severity critical",
        styles['CodeBlock']))
    story.append(Paragraph("Only shows CRITICAL findings (Shor-vulnerable key exchange).", styles['Body']))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Step 5.3 - Try scanning Enigma itself", styles['Step']))
    story.append(Paragraph(
        "python phases/phase6_scanner/pqc_scanner.py scan phases/phase2_classical",
        styles['CodeBlock']))
    story.append(Paragraph(
        "This scans our own crypto code. Expected: 150+ findings (we built RSA, AES, "
        "ECDSA etc. from scratch, so the scanner correctly flags them all).",
        styles['Body']))
    story.append(PageBreak())

    # INTERPRETING RESULTS
    story.append(Paragraph("INTERPRETING RESULTS", styles['H1']))
    story.append(hr())

    interp_data = [
        ['Severity', 'Meaning', 'Action', 'Timeline'],
        ['CRITICAL', 'Broken by Shor (RSA, ECDH, DH)', 'Replace with ML-KEM/ML-DSA', 'IMMEDIATE'],
        ['HIGH', 'Deprecated or broken (3DES, MD5, RC4)', 'Upgrade algorithm', '1-3 months'],
        ['MEDIUM', 'Grover-weakened (AES-128, SHA-1)', 'Upgrade key size', '3-6 months'],
        ['LOW', 'Suboptimal but not broken', 'Review and plan', '6-12 months'],
        ['INFO', 'Informational (crypto lib detected)', 'Audit usage', 'Ongoing'],
    ]
    t = Table(interp_data, colWidths=[0.8*inch, 2*inch, 2*inch, 1*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, -1), WHITE),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#333344')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 15))

    story.append(Paragraph("Risk Score Interpretation:", styles['H3']))
    story.append(Paragraph("  0-20: Low exposure (mostly quantum-safe)", styles['Body']))
    story.append(Paragraph("  21-50: Moderate (some key exchange needs migration)", styles['Body']))
    story.append(Paragraph("  51-80: High (significant quantum-vulnerable surface)", styles['Body']))
    story.append(Paragraph("  81-100: Critical (urgent migration needed)", styles['Body']))
    story.append(Spacer(1, 15))

    story.append(Paragraph("PQC Replacement Quick Reference:", styles['H3']))
    replacements = [
        ['Vulnerable', 'Replace With', 'NIST Standard'],
        ['RSA (key exchange)', 'ML-KEM-768', 'FIPS 203'],
        ['RSA (signatures)', 'ML-DSA-65', 'FIPS 204'],
        ['ECDH / DH', 'X25519 + ML-KEM-768 hybrid', 'FIPS 203'],
        ['ECDSA / Ed25519', 'ML-DSA-44 or ML-DSA-65', 'FIPS 204'],
        ['AES-128', 'AES-256', 'Same standard, bigger key'],
        ['SHA-1 / MD5', 'SHA-256 or SHA-3', 'FIPS 180-4 / FIPS 202'],
    ]
    t2 = Table(replacements, colWidths=[1.5*inch, 2.2*inch, 1.8*inch])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, -1), WHITE),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#333344')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t2)

    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("CONFIDENTIAL // Enigma Project // Ribbz", styles['Small']))

    doc.build(story, onFirstPage=bg, onLaterPages=bg)
    return OUTPUT_PATH


if __name__ == '__main__':
    path = generate()
    print(f"Test guide generated: {path}")
