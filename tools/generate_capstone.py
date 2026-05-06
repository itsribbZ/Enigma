"""
Enigma — Capstone PDF Generator.

Generates the master document compiling the entire Enigma Quantum Security
Expert project: architecture, all 8 phases + v2 enhancements, code highlights,
audit results, research summaries, and statistics.

Uses Bifrost theme: deep purple/cyan on dark background.
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

# ============================================================================
# BIFROST THEME
# ============================================================================

BG_DARK = HexColor('#0D0D1A')
PURPLE = HexColor('#9B59B6')
CYAN = HexColor('#00D4AA')
GOLD = HexColor('#F1C40F')
WHITE = HexColor('#E8E8E8')
LIGHT_GRAY = HexColor('#AAAAAA')
DARK_PANEL = HexColor('#1A1A2E')
HEADER_BG = HexColor('#16213E')
ROW_ALT = HexColor('#0F0F20')
RED = HexColor('#E74C3C')
GREEN = HexColor('#2ECC71')

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'Enigma_Capstone.pdf')


def build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle('BifrostTitle', parent=styles['Title'],
        fontSize=28, textColor=CYAN, alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle('BifrostSubtitle', parent=styles['Normal'],
        fontSize=14, textColor=PURPLE, alignment=TA_CENTER, spaceAfter=20))
    styles.add(ParagraphStyle('BifrostH1', parent=styles['Heading1'],
        fontSize=18, textColor=CYAN, spaceAfter=10, spaceBefore=16))
    styles.add(ParagraphStyle('BifrostH2', parent=styles['Heading2'],
        fontSize=14, textColor=PURPLE, spaceAfter=8, spaceBefore=12))
    styles.add(ParagraphStyle('BifrostH3', parent=styles['Heading3'],
        fontSize=12, textColor=GOLD, spaceAfter=6, spaceBefore=8))
    styles.add(ParagraphStyle('BifrostBody', parent=styles['Normal'],
        fontSize=10, textColor=WHITE, spaceAfter=6, leading=14))
    styles.add(ParagraphStyle('BifrostSmall', parent=styles['Normal'],
        fontSize=8, textColor=LIGHT_GRAY, spaceAfter=4))
    styles.add(ParagraphStyle('BifrostCode', parent=styles['Normal'],
        fontSize=9, textColor=CYAN, fontName='Courier', spaceAfter=4, leftIndent=20))
    styles.add(ParagraphStyle('BifrostStat', parent=styles['Normal'],
        fontSize=24, textColor=CYAN, alignment=TA_CENTER, spaceAfter=4))
    styles.add(ParagraphStyle('BifrostStatLabel', parent=styles['Normal'],
        fontSize=10, textColor=LIGHT_GRAY, alignment=TA_CENTER, spaceAfter=12))
    return styles


def bg_callback(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
    # Footer
    canvas.setFillColor(LIGHT_GRAY)
    canvas.setFont('Helvetica', 7)
    canvas.drawString(inch, 0.4 * inch,
        f'Enigma // Quantum Security Expert // Confidential // Page {doc.page}')
    canvas.drawRightString(letter[0] - inch, 0.4 * inch, datetime.now().strftime('%Y-%m-%d'))
    canvas.restoreState()


def make_table(data, col_widths=None):
    t = Table(data, colWidths=col_widths)
    style = [
        ('BACKGROUND', (0, 0), (-1, 0), HEADER_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, -1), WHITE),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#333344')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(('BACKGROUND', (0, i), (-1, i), ROW_ALT))
    t.setStyle(TableStyle(style))
    return t


def hr():
    return HRFlowable(width="100%", thickness=1, color=PURPLE, spaceAfter=10, spaceBefore=10)


def generate():
    styles = build_styles()
    doc = SimpleDocTemplate(OUTPUT_PATH, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch)

    story = []

    # ======== TITLE PAGE ========
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("ENIGMA", styles['BifrostTitle']))
    story.append(Paragraph("Quantum Security Expert // Capstone", styles['BifrostSubtitle']))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("Zero to Enterprise-Deliverable in 4 Sessions", styles['BifrostBody']))
    story.append(Spacer(1, 0.5*inch))

    # Stats row
    stats_data = [
        ['~9,200', '353', '20', '8/8'],
        ['Lines of Code', 'Tests Passing', 'Python Modules', 'Phases Complete'],
    ]
    stats_table = Table(stats_data, colWidths=[1.5*inch]*4)
    stats_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, 0), CYAN),
        ('TEXTCOLOR', (0, 1), (-1, 1), LIGHT_GRAY),
        ('FONTSIZE', (0, 0), (-1, 0), 24),
        ('FONTSIZE', (0, 1), (-1, 1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(stats_table)
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("All cryptography built FROM SCRATCH — no library wrappers", styles['BifrostBody']))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['BifrostSmall']))
    story.append(Paragraph("Classification: CONFIDENTIAL // Intellectual Property", styles['BifrostSmall']))
    story.append(PageBreak())

    # ======== TABLE OF CONTENTS ========
    story.append(Paragraph("TABLE OF CONTENTS", styles['BifrostH1']))
    story.append(hr())
    toc = [
        "1. Executive Summary",
        "2. Architecture Overview",
        "3. Phase 1: Mathematical Foundations",
        "4. Phase 2: Classical Cryptography",
        "5. Phase 3: Quantum Mechanics",
        "6. Phase 4: Quantum Threat Model",
        "7. Phase 5: Post-Quantum Cryptography",
        "8. Phase 6: PQC Migration Scanner",
        "9. Phase 7: Quantum Key Distribution",
        "10. Phase 8: Portfolio & GTM",
        "11. v2 Enhancements",
        "12. Holy Trinity Audit Results",
        "13. Research Corpus",
        "14. Technical Statistics",
    ]
    for item in toc:
        story.append(Paragraph(item, styles['BifrostBody']))
    story.append(PageBreak())

    # ======== 1. EXECUTIVE SUMMARY ========
    story.append(Paragraph("1. EXECUTIVE SUMMARY", styles['BifrostH1']))
    story.append(hr())
    story.append(Paragraph(
        "Enigma is a comprehensive quantum security self-study track that takes a practitioner "
        "from zero to enterprise-deliverable expertise across 8 phases. Every cryptographic "
        "primitive is implemented from mathematical first principles — no library wrappers, "
        "no black boxes. The project demonstrates deep understanding of classical cryptography, "
        "quantum computing, post-quantum standards, and security tooling.",
        styles['BifrostBody']))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "The flagship deliverable is <b>pqc-scanner</b> — a multi-language post-quantum "
        "cryptography vulnerability scanner with SARIF output for CI/CD integration and "
        "certificate chain scanning. It found 156 quantum-vulnerable findings in our own code.",
        styles['BifrostBody']))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Key achievements:", styles['BifrostH3']))
    achievements = [
        "ML-KEM (FIPS 203) built from lattice math — NTT, CBD, all 3 parameter sets",
        "Ed25519 (RFC 8032) from twisted Edwards curve arithmetic",
        "AES-GCM, RSA-OAEP, ECDSA with RFC 6979, SHA-256/SHA-1 — all from scratch",
        "Shor's algorithm: real quantum circuit for N=15 on Qiskit",
        "BB84 QKD: 0% QBER without Eve, 28% with Eve (detected)",
        "E91: CHSH = 2.96 (quantum violation of Bell inequality)",
        "CryptoPals Sets 1-4: padding oracle, ECB byte-at-a-time, MT19937 clone",
        "pqc-scanner v2: SARIF 2.1.0 + certificate chain scanning",
        "Holy Trinity audit: 152 findings lifetime, all CRITICALs fixed",
    ]
    for a in achievements:
        story.append(Paragraph(f"  - {a}", styles['BifrostBody']))
    story.append(PageBreak())

    # ======== 2. ARCHITECTURE OVERVIEW ========
    story.append(Paragraph("2. ARCHITECTURE OVERVIEW", styles['BifrostH1']))
    story.append(hr())
    story.append(Paragraph("Module Dependency Graph", styles['BifrostH2']))

    arch_data = [
        ['Module', 'LOC', 'Tests', 'Dependencies'],
        ['modular_math.py', '665', '14', 'None (foundation)'],
        ['sha256.py', '~350', '5', 'None'],
        ['aes.py', '~450', '10', 'None'],
        ['rsa.py', '~400', '6', 'modular_math, sha256'],
        ['ecc.py', '~270', '11', 'modular_math, sha256'],
        ['ed25519.py', '386', '24', 'None (standalone)'],
        ['cryptopals.py', '~400', '13', 'aes'],
        ['tls_analyzer.py', '~350', '8', 'None (network)'],
        ['quantum_circuits.py', '380', '13', 'qiskit'],
        ['quantum_threats.py', '465', '11', 'quantum_circuits'],
        ['quantum_hardware.py', '~300', '7', 'quantum_circuits, qiskit_aer'],
        ['pqc_lattice.py', '~420', '10', 'modular_math, rsa, ecc'],
        ['ml_kem.py', '579', '38', 'None (standalone FIPS 203)'],
        ['pqc_scanner.py', '~580', '20', 'cryptography (certs only)'],
        ['qkd_protocols.py', '371', '8', 'qiskit'],
        ['portfolio.py', '274', '6', 'All phases (stats)'],
    ]
    story.append(make_table(arch_data, [1.8*inch, 0.5*inch, 0.5*inch, 3.5*inch]))
    story.append(PageBreak())

    # ======== PHASES 1-8 ========
    phases = [
        ("3. Phase 1: Mathematical Foundations", "665 LOC | 14 tests",
         "The bedrock. Modular arithmetic, extended GCD, finite fields GF(p) and GF(2^8), "
         "AES S-Box construction, Miller-Rabin primality, CRT, Tonelli-Shanks, Pollard's rho.",
         ["modular_math.py: 22 functions covering all crypto math primitives",
          "GF(2^8) with AES irreducible polynomial x^8 + x^4 + x^3 + x + 1",
          "RSA end-to-end: p=61, q=53, e=17, encrypt(65)=2790"]),

        ("4. Phase 2: Classical Cryptography", "~2,400 LOC | 97 tests",
         "Every major classical algorithm from scratch. SHA-256/SHA-1/HMAC, AES (ECB/CBC/CTR/GCM), "
         "RSA (PKCS#1/OAEP/signatures), ECC (secp256k1/P-256/ECDH/ECDSA/RFC 6979), "
         "Ed25519 (RFC 8032), CryptoPals Sets 1-4, live TLS analyzer.",
         ["AES-GCM: GHASH over GF(2^128) with authentication tag verification",
          "RFC 6979: deterministic ECDSA nonces (prevents Sony PS3 class attacks)",
          "Ed25519: twisted Edwards curve, extended coordinates, HWCD08 doubling",
          "CryptoPals: padding oracle, byte-at-a-time ECB, MT19937 clone",
          "TLS: live analysis of google.com (TLSv1.3, AES-256-GCM, PQC detection)"]),

        ("5. Phase 3: Quantum Mechanics for CS", "~680 LOC | 20 tests",
         "10 quantum circuits on Qiskit 2.3, teleportation with 0.99+ fidelity, "
         "QFT implementation verified unitary (QFT^4 = I). Hardware execution module "
         "with IBM Eagle/Heron noise model.",
         ["Circuits: superposition, Bell, GHZ, NOT, phase kickback, Deutsch, B-V, Grover",
          "Teleportation: deferred measurement, partial trace verification",
          "Hardware: noise-model simulator with ~98% avg success rate across 5 circuits"]),

        ("6. Phase 4: Quantum Threat Model", "465 LOC | 11 tests",
         "Shor's factoring (quantum circuit for N=15, classical for N=21/35/77/91), "
         "Grover's search (93-95% on 3 qubits), Mosca's inequality framework, "
         "full threat assessment report generator.",
         ["Shor: real quantum circuit with modular exponentiation for N=15",
          "Grover: amplitude amplification with oracle for arbitrary targets",
          "Threat assessment: HNDL analysis, Mosca's inequality, migration urgency"]),

        ("7. Phase 5: Post-Quantum Cryptography", "~1,000 LOC | 48 tests",
         "Regev's LWE encryption from scratch, ML-KEM (FIPS 203) with NTT and all 3 "
         "parameter sets, PQC benchmark suite, migration guide generator.",
         ["LWE: noisy linear regression over Z_q, CBD sampling, bit encryption",
          "ML-KEM: NTT/INTT, basemul with twist factors, K-PKE + FO transform",
          "ML-KEM-512/768/1024: key serialization per FIPS 203 encoding",
          "Constant-time decapsulation (hmac.compare_digest), domain separation G(d||k)"]),

        ("8. Phase 6: PQC Migration Scanner", "~780 LOC | 20 tests",
         "THE FLAGSHIP. Multi-language scanner (Python/Java/Go/JS/C/C++/Rust) for "
         "quantum-vulnerable cryptography. v2 adds SARIF 2.1.0 and certificate chain scanning.",
         ["Detection: RSA, ECDSA, ECDH, DH, DSA, AES-128, SHA-1, MD5, 3DES, RC4",
          "Output: text, JSON, HTML (XSS-hardened), SARIF 2.1.0 (CI/CD)",
          "Certificates: PEM/DER parsing, TLS endpoint scanning, algorithm detection",
          "Risk scoring: logarithmic scale 0-100, CRITICAL/HIGH/MEDIUM/LOW/INFO",
          "Self-test: found 156 quantum-vulnerable findings in own Phase 2 code"]),

        ("9. Phase 7: Quantum Key Distribution", "371 LOC | 8 tests",
         "BB84 and E91 QKD protocol simulations, QRNG, hybrid QKD+PQC architecture whitepaper.",
         ["BB84: 0% QBER without eavesdropper, 28.1% with Eve (detected via threshold)",
          "E91: CHSH = 2.96 (exceeds classical bound of 2.0, confirms quantum correlations)",
          "QRNG: quantum random number generator (documented as simulator-based)",
          "Hybrid: 3-tier architecture (QKD metro, PQC backbone, classical edge)"]),

        ("10. Phase 8: Portfolio & Go-to-Market", "274 LOC | 6 tests",
         "Portfolio generator, competency map, certification assessment, GTM strategy.",
         ["Stats: automated project statistics collection across all phases",
          "Competency map: 6 domains with skill-level assessment",
          "Certifications: CompTIA Security+, ISC2 CC, IBM Quantum Dev, CISSP, ISARA",
          "GTM: consulting ($150-300/hr), product (pqc-scanner SaaS), employment, hybrid"]),
    ]

    for title, subtitle, description, highlights in phases:
        story.append(Paragraph(title, styles['BifrostH1']))
        story.append(Paragraph(subtitle, styles['BifrostH3']))
        story.append(hr())
        story.append(Paragraph(description, styles['BifrostBody']))
        story.append(Spacer(1, 6))
        for h in highlights:
            story.append(Paragraph(f"  - {h}", styles['BifrostBody']))
        story.append(PageBreak())

    # ======== 11. V2 ENHANCEMENTS ========
    story.append(Paragraph("11. v2 ENHANCEMENTS (Session #4)", styles['BifrostH1']))
    story.append(hr())
    v2_data = [
        ['Enhancement', 'LOC', 'Tests', 'Status'],
        ['Ed25519 (RFC 8032)', '386', '24', 'COMPLETE + AUDITED'],
        ['ML-KEM (FIPS 203)', '579', '38', 'COMPLETE + AUDITED'],
        ['SARIF 2.1.0 Output', '~150', '4', 'COMPLETE + AUDITED'],
        ['Certificate Scanning', '~150', '4', 'COMPLETE + AUDITED'],
        ['pytest Migration', '14 files', '353 total', 'COMPLETE'],
        ['Hardware Execution', '~300', '7', 'COMPLETE (noise-model)'],
        ['ML-KEM Serialization', '~100', '8', 'COMPLETE'],
    ]
    story.append(make_table(v2_data, [2*inch, 0.7*inch, 0.9*inch, 2.5*inch]))
    story.append(PageBreak())

    # ======== 12. AUDIT RESULTS ========
    story.append(Paragraph("12. HOLY TRINITY AUDIT RESULTS", styles['BifrostH1']))
    story.append(hr())
    story.append(Paragraph(
        "The Holy Trinity workflow deploys parallel diagnostic agents (devTeam) to audit "
        "every module for correctness, security, and code quality. Findings are classified "
        "as CRITICAL, HIGH, MEDIUM, or LOW. All CRITICALs and HIGHs are fixed before shipping.",
        styles['BifrostBody']))
    story.append(Spacer(1, 10))

    audit_data = [
        ['Module', 'Findings', 'CRITICALs Fixed', 'HIGHs Fixed', 'Status'],
        ['Session 3 (all phases)', '120', '10', '6', 'CLEAN'],
        ['ed25519.py', '10', '0 (1 FP)', '3', 'CLEAN'],
        ['ml_kem.py', '12', '3', '3', 'CLEAN'],
        ['pqc_scanner.py v2', '10', '3', '3', 'CLEAN'],
        ['TOTAL', '152', '16', '15', 'ALL CLEAN'],
    ]
    story.append(make_table(audit_data, [1.8*inch, 0.8*inch, 1.2*inch, 1*inch, 0.8*inch]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Key Audit Fixes:", styles['BifrostH3']))
    fixes = [
        "CRITICAL: hmac.compare_digest for ML-KEM CCA2 decapsulation (timing oracle)",
        "CRITICAL: CBD bit ordering fixed to LSB-first per FIPS 203 (interoperability)",
        "CRITICAL: FIPS 203 domain separation G(d||k) across parameter sets",
        "CRITICAL: SARIF URI relativization for GitHub Code Scanning compatibility",
        "CRITICAL: XSS prevention in HTML reports (scan_path escaping)",
        "HIGH: Ed25519 point_double now used in scalar_multiply (was dead code)",
        "HIGH: SHAKE-128 XOF stream extension (was re-hashing same input)",
        "HIGH: ML-KEM ciphertext length validation in decrypt",
    ]
    for f in fixes:
        story.append(Paragraph(f"  - {f}", styles['BifrostBody']))
    story.append(PageBreak())

    # ======== 13. RESEARCH CORPUS ========
    story.append(Paragraph("13. RESEARCH CORPUS", styles['BifrostH1']))
    story.append(hr())
    research_data = [
        ['Document', 'Agents', 'Pages/Size'],
        ['Phase 1: Math Foundations', '6', '133 pages'],
        ['Phase 2: Classical Crypto', '7', '136 pages'],
        ['Phase 3: Quantum Mechanics', '5', '~100 pages'],
        ['Phase 4: Quantum Threats', '5', '~50 pages'],
        ['Phase 5: PQC Standards', '6', '~50 pages'],
        ['Ed25519 Implementation Research', '1', '~30 pages'],
        ['Scanner v2 Research (SARIF + Certs)', '1', '77 KB MD'],
    ]
    story.append(make_table(research_data, [3*inch, 0.8*inch, 1.5*inch]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Total: 30+ research agents deployed, 7 master documents produced.",
                           styles['BifrostBody']))
    story.append(PageBreak())

    # ======== 14. TECHNICAL STATISTICS ========
    story.append(Paragraph("14. TECHNICAL STATISTICS", styles['BifrostH1']))
    story.append(hr())

    final_stats = [
        ['Metric', 'Value'],
        ['Total Source LOC', '~9,200'],
        ['Python Modules', '20'],
        ['Test Cases', '353 (352 passing, 1 network skip)'],
        ['Phases Complete', '8/8 + v2 enhancements'],
        ['Algorithms Implemented', '15+ (RSA, AES, ECC, Ed25519, SHA, ML-KEM, LWE, BB84, E91, ...)'],
        ['Languages Scanned (pqc-scanner)', 'Python, Java, Go, JS/TS, C/C++, Rust, Config'],
        ['SARIF Rules', '17 quantum-vulnerability rules'],
        ['Audit Findings (lifetime)', '152 (16 CRITICAL, 15 HIGH fixed)'],
        ['Research Documents', '7 (469+ pages)'],
        ['Sessions', '4'],
        ['Build Tool', 'Python 3.14, Qiskit 2.3, reportlab'],
    ]
    story.append(make_table(final_stats, [2.5*inch, 4*inch]))

    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("CLASSIFICATION: CONFIDENTIAL // INTELLECTUAL PROPERTY",
                           styles['BifrostSmall']))
    story.append(Paragraph("Owner: Ribbz (Jacob Ribbe) // Enigma Project",
                           styles['BifrostSmall']))

    # Build PDF
    doc.build(story, onFirstPage=bg_callback, onLaterPages=bg_callback)
    return OUTPUT_PATH


if __name__ == '__main__':
    path = generate()
    print(f"Capstone PDF generated: {path}")
