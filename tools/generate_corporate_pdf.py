"""
Enigma pqc-scanner: Corporate Product Overview PDF.
Professional enterprise-grade document for CISO/CTO audiences.
"""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phases', 'phase6_scanner'))

from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor, white
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus.flowables import Flowable
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics import renderPDF


# ============================================================================
# BRANDING
# ============================================================================
NAVY = HexColor('#0B1120')
DARK_BLUE = HexColor('#121D33')
GOLD = HexColor('#C9A84C')
LIGHT_GOLD = HexColor('#E8D48B')
STEEL = HexColor('#4A5568')
LIGHT_GRAY = HexColor('#F7F8FA')
MID_GRAY = HexColor('#E2E4E8')
DARK_TEXT = HexColor('#1A202C')
BODY_TEXT = HexColor('#2D3748')
ACCENT_GREEN = HexColor('#38A169')
ACCENT_RED = HexColor('#E53E3E')
ACCENT_ORANGE = HexColor('#DD6B20')
MUTED = HexColor('#718096')


class EnigmaLogo(Flowable):
    """Draw the Enigma 'E' logo."""
    def __init__(self, size=60):
        Flowable.__init__(self)
        self.size = size
        self.width = size
        self.height = size

    def draw(self):
        s = self.size
        c = self.canv
        # Outer circle
        c.setStrokeColor(GOLD)
        c.setLineWidth(3)
        c.setFillColor(NAVY)
        c.circle(s/2, s/2, s/2 - 2, stroke=1, fill=1)
        # Inner E
        c.setFont('Helvetica-Bold', int(s * 0.55))
        c.setFillColor(GOLD)
        c.drawCentredString(s/2, s/2 - s*0.18, 'E')


def build_corporate_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6*inch, bottomMargin=0.6*inch,
        leftMargin=0.8*inch, rightMargin=0.8*inch,
    )

    styles = getSampleStyleSheet()

    # ── Custom Styles ──
    s_title = ParagraphStyle('CTitle', fontSize=36, textColor=NAVY,
        fontName='Helvetica-Bold', alignment=TA_CENTER, spaceAfter=4, leading=42)
    s_subtitle = ParagraphStyle('CSub', fontSize=14, textColor=STEEL,
        alignment=TA_CENTER, spaceAfter=16, leading=18)
    s_h1 = ParagraphStyle('CH1', fontSize=20, textColor=NAVY,
        fontName='Helvetica-Bold', spaceBefore=20, spaceAfter=10, leading=24)
    s_h2 = ParagraphStyle('CH2', fontSize=14, textColor=GOLD,
        fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6, leading=18,
        textTransform='uppercase')
    s_body = ParagraphStyle('CBody', fontSize=10.5, textColor=BODY_TEXT,
        spaceAfter=8, leading=15)
    s_body_b = ParagraphStyle('CBodyB', parent=s_body, fontName='Helvetica-Bold')
    s_bullet = ParagraphStyle('CBullet', parent=s_body, leftIndent=18,
        bulletIndent=6, spaceBefore=2, spaceAfter=3)
    s_stat_num = ParagraphStyle('CStatNum', fontSize=26, textColor=NAVY,
        fontName='Helvetica-Bold', alignment=TA_CENTER, leading=28)
    s_stat_lbl = ParagraphStyle('CStatLbl', fontSize=8, textColor=MUTED,
        alignment=TA_CENTER, leading=10)
    s_footer = ParagraphStyle('CFoot', fontSize=8, textColor=MUTED,
        alignment=TA_CENTER)
    s_callout = ParagraphStyle('CCallout', fontSize=11, textColor=NAVY,
        fontName='Helvetica-Bold', spaceBefore=6, spaceAfter=6,
        leftIndent=12, borderPadding=8)

    def tbl_style(has_header=True):
        """Standard table styling."""
        ts = [
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('TEXTCOLOR', (0, 0), (-1, -1), BODY_TEXT),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('TOPPADDING', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 0.5, MID_GRAY),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [white, LIGHT_GRAY]),
        ]
        if has_header:
            ts.extend([
                ('BACKGROUND', (0, 0), (-1, 0), NAVY),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ])
        return TableStyle(ts)

    E = []  # elements

    # ══════════════════════════════════════════════════════════════
    # TITLE PAGE
    # ══════════════════════════════════════════════════════════════
    E.append(Spacer(1, 1.8*inch))
    # Center the logo using a table
    logo_table = Table([[EnigmaLogo(80)]], colWidths=[6*inch])
    logo_table.setStyle(TableStyle([('ALIGN', (0,0), (0,0), 'CENTER')]))
    E.append(logo_table)
    E.append(Spacer(1, 0.25*inch))
    E.append(Paragraph('ENIGMA', s_title))
    E.append(Paragraph('pqc-scanner', ParagraphStyle('pname', fontSize=16,
        textColor=GOLD, alignment=TA_CENTER, fontName='Helvetica')))
    E.append(Spacer(1, 0.3*inch))
    E.append(HRFlowable(width='30%', thickness=1.5, color=GOLD, spaceAfter=16))
    E.append(Paragraph('Post-Quantum Cryptography Migration Scanner', s_subtitle))
    E.append(Paragraph('Enterprise Product Overview', ParagraphStyle('epo',
        fontSize=11, textColor=MUTED, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.15*inch))
    E.append(Paragraph(f'Version 4.0 &mdash; {datetime.now().strftime("%B %Y")}',
        ParagraphStyle('ver', fontSize=10, textColor=MUTED, alignment=TA_CENTER)))
    E.append(Spacer(1, 2*inch))
    E.append(Paragraph('CONFIDENTIAL &mdash; FOR AUTHORIZED RECIPIENTS ONLY',
        ParagraphStyle('conf', fontSize=9, textColor=ACCENT_RED,
                       alignment=TA_CENTER, fontName='Helvetica-Bold')))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # TABLE OF CONTENTS
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('Table of Contents', s_h1))
    E.append(Spacer(1, 0.1*inch))
    toc = [
        ('1', 'Executive Summary', '3'),
        ('2', 'The Quantum Threat Landscape', '4'),
        ('3', 'Regulatory & Compliance Deadlines', '5'),
        ('4', 'Product Capabilities', '6'),
        ('5', 'Detection Engine', '8'),
        ('6', 'Risk Intelligence & Grading', '9'),
        ('7', 'Competitive Analysis', '10'),
        ('8', 'Performance & Accuracy', '11'),
        ('9', 'Migration Support', '12'),
        ('10', 'Deployment Options', '13'),
        ('11', 'Contact & Next Steps', '14'),
    ]
    toc_data = [[Paragraph(f'<b>{n}.</b>', s_body), Paragraph(t, s_body),
                 Paragraph(p, ParagraphStyle('p', parent=s_body, alignment=TA_RIGHT))]
                for n, t, p in toc]
    E.append(Table(toc_data, colWidths=[0.4*inch, 4.8*inch, 0.6*inch],
                   style=TableStyle([
                       ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                       ('LINEBELOW', (0,0), (-1,-1), 0.4, MID_GRAY),
                   ])))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 1. EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('1. Executive Summary', s_h1))
    E.append(Paragraph(
        'Quantum computers capable of breaking RSA, ECDSA, and ECDH are projected to arrive '
        'between 2030 and 2040. NIST has finalized three post-quantum cryptographic standards '
        '(FIPS 203, 204, 205) and set a deadline of 2035 for full migration. The NSA&rsquo;s CNSA 2.0 '
        'mandates even earlier deadlines beginning in 2025.', s_body))
    E.append(Paragraph(
        '<b>Enigma pqc-scanner</b> is the most comprehensive post-quantum cryptography migration '
        'scanner available. It identifies quantum-vulnerable cryptography across 16 languages and '
        'configuration formats, maps findings to compliance frameworks, assigns readiness grades, '
        'and generates actionable migration guidance &mdash; all in under 30 seconds for enterprise-scale '
        'codebases.', s_body))
    E.append(Spacer(1, 0.15*inch))

    # Key metrics
    metrics = [
        [Paragraph('96.2%', s_stat_num), Paragraph('100%', s_stat_num),
         Paragraph('98.0%', s_stat_num), Paragraph('&lt;30s', s_stat_num)],
        [Paragraph('Precision', s_stat_lbl), Paragraph('Recall', s_stat_lbl),
         Paragraph('F1 Score', s_stat_lbl), Paragraph('Enterprise Scan', s_stat_lbl)],
    ]
    E.append(Table(metrics, colWidths=[1.5*inch]*4, rowHeights=[42, 22],
        style=TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,0), 'BOTTOM'),
        ('VALIGN', (0,1), (-1,1), 'TOP'),
        ('BOX', (0,0), (-1,-1), 1, MID_GRAY),
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_GRAY),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('TOPPADDING', (0,0), (-1,0), 8),
    ])))

    E.append(Spacer(1, 0.15*inch))
    E.append(Paragraph(
        '<b>Market context:</b> The post-quantum cryptography market is projected to reach '
        '$7.82 billion by 2030 (37.6% CAGR). Organizations that inventory and migrate their '
        'cryptographic assets now will avoid compliance penalties, reduce risk exposure, and '
        'gain competitive advantage.', s_body))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 2. QUANTUM THREAT
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('2. The Quantum Threat Landscape', s_h1))
    E.append(Paragraph(
        'Shor&rsquo;s algorithm (1994) enables quantum computers to break all public-key '
        'cryptography based on integer factorization (RSA) and discrete logarithms (ECDSA, '
        'ECDH, DH, DSA). Grover&rsquo;s algorithm halves the effective security of symmetric '
        'ciphers, requiring key size upgrades.', s_body))

    E.append(Paragraph('Quantum Vulnerability Classification', s_h2))
    threat = [
        ['Algorithm', 'Attack Vector', 'Business Impact', 'Urgency'],
        ['RSA (all key sizes)', "Shor's algorithm", 'TLS, certificates, code signing broken', 'CRITICAL'],
        ['ECDSA / ECDH / Ed25519', "Shor's algorithm", 'All elliptic curve operations broken', 'CRITICAL'],
        ['DH / DSA', "Shor's algorithm", 'Key exchange, legacy signatures broken', 'CRITICAL'],
        ['AES-128', "Grover's algorithm", 'Effective security reduced to 64-bit', 'HIGH'],
        ['SHA-1 / MD5', 'Classically broken', 'Collision attacks trivial today', 'IMMEDIATE'],
        ['3DES / RC4 / Blowfish', 'Classically broken', 'Exploitable without quantum computers', 'IMMEDIATE'],
    ]
    E.append(Table(threat, colWidths=[1.5*inch, 1.1*inch, 2.1*inch, 1.1*inch],
                   style=tbl_style()))

    E.append(Spacer(1, 0.15*inch))
    E.append(Paragraph('Harvest Now, Decrypt Later (HNDL)', s_h2))
    E.append(Paragraph(
        'Nation-state adversaries are actively collecting encrypted communications and stored '
        'data today with the intent to decrypt it when quantum computers become available. '
        'Any data that must remain confidential beyond 2035 &mdash; healthcare records, financial '
        'transactions, intellectual property, government communications &mdash; is at risk '
        '<i>right now</i>.', s_body))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 3. COMPLIANCE
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('3. Regulatory & Compliance Deadlines', s_h1))

    comp = [
        ['Framework', 'Governing Body', 'Key Deadlines', 'Applicability'],
        ['CNSA 2.0', 'NSA / DoD',
         'Software signing: 2025\nWeb services: 2026\nNetworking: 2030\nAll NSS: 2033',
         'National Security\nSystems (mandatory)'],
        ['NIST IR 8547', 'NIST',
         'Deprecation: 2030\nFull removal: 2035',
         'Federal agencies +\nindustry guidance'],
        ['PCI DSS 4.0', 'PCI SSC',
         'Strong crypto required\nPQC recommended',
         'Payment card\nprocessing (mandatory)'],
        ['OMB M-23-02', 'White House OMB',
         'Crypto inventory: Immediate\nMigration plans: Required',
         'All federal agencies\n(mandatory)'],
    ]
    E.append(Table(comp, colWidths=[1.1*inch, 1*inch, 1.9*inch, 1.6*inch],
                   style=tbl_style()))

    E.append(Spacer(1, 0.15*inch))
    E.append(Paragraph(
        '<b>Enigma pqc-scanner maps every finding to these frameworks automatically</b>, '
        'including per-algorithm deadline countdowns showing exactly how many days remain '
        'before each algorithm becomes non-compliant under CNSA 2.0.', s_body))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 4. PRODUCT CAPABILITIES
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('4. Product Capabilities', s_h1))

    # Stats row
    stats2 = [
        [Paragraph('16', s_stat_num), Paragraph('50+', s_stat_num),
         Paragraph('6', s_stat_num), Paragraph('30', s_stat_num)],
        [Paragraph('Languages &\nConfig Formats', s_stat_lbl),
         Paragraph('Crypto API\nPatterns', s_stat_lbl),
         Paragraph('Output\nFormats', s_stat_lbl),
         Paragraph('Unique\nFeatures', s_stat_lbl)],
    ]
    E.append(Table(stats2, colWidths=[1.5*inch]*4, style=TableStyle([
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 1, GOLD),
        ('BACKGROUND', (0,0), (-1,-1), LIGHT_GRAY),
        ('BOTTOMPADDING', (0,0), (-1,0), 2),
        ('TOPPADDING', (0,0), (-1,0), 10),
    ])))
    E.append(Spacer(1, 0.15*inch))

    caps = [
        ('<b>Deep AST Analysis</b> &mdash; Tree-sitter powered parsing across 13 programming '
         'languages. Real abstract syntax tree analysis with import resolution, key size '
         'extraction, cipher mode detection, and backward slicing for parameter resolution.'),
        ('<b>PQC Readiness Grade</b> &mdash; SSL Labs-style A+ through F assessment based on '
         'three weighted categories: Algorithm Security (40%), Key Management (30%), '
         'and Compliance Posture (30%).'),
        ('<b>Quality Gates</b> &mdash; CI/CD pass/fail enforcement. Four built-in presets: '
         '<i>pqc-ready</i>, <i>no-critical</i>, <i>cnsa-compliant</i>, <i>migration-safe</i>. '
         'Returns distinct exit codes for pipeline automation.'),
        ('<b>Reachability Analysis</b> &mdash; Verifies whether crypto dependencies are actually '
         'called in source code. Classifies as CONFIRMED, REACHABLE, or AVAILABLE with '
         'confidence scoring.'),
        ('<b>Auto-Fix Engine</b> &mdash; Generates code transformation suggestions as unified '
         'diffs. Tier 1 transforms (MD5 to SHA-256, DES to AES-GCM) are deterministic and '
         'safe to auto-apply. Tier 2 provides template migrations for RSA to ML-KEM.'),
        ('<b>CycloneDX CBOM 1.7</b> &mdash; Cryptographic Bill of Materials output for '
         'integration with enterprise SBOM toolchains. Standards-compliant format adopted '
         'by IBM, OWASP, and CycloneDX community.'),
        ('<b>Migration Cost Estimator</b> &mdash; Per-finding effort estimates (hours and cost) '
         'based on algorithm complexity classification. Includes overhead for testing (30%), '
         'integration (20%), and documentation (10%).'),
        ('<b>CNSA 2.0 Deadline Countdown</b> &mdash; Per-algorithm deadline tracking with '
         'urgency classification: OVERDUE, URGENT, APPROACHING, DISTANT. No other scanner '
         'provides this level of compliance granularity.'),
    ]
    for c in caps:
        E.append(Paragraph(f'&bull; {c}', s_bullet))
    E.append(PageBreak())

    # Feature matrix
    E.append(Paragraph('Complete Feature Matrix', s_h2))
    categories = [
        ('DETECTION ENGINE', [
            'Tree-sitter AST analysis (13 languages)',
            'Regex pattern matching (fallback)',
            'Python-specific AST deep analysis',
            'Key size extraction from source code',
            'Algorithm mode detection (ECB/CBC/GCM)',
            'Backward slicing for parameter resolution',
            'Custom YAML rule engine',
            'Built-in extended rules (JWT, SSH, hardcoded keys)',
            'Comment stripping (false positive reduction)',
            'IaC scanning (Terraform, YAML, Dockerfile)',
        ]),
        ('RISK INTELLIGENCE', [
            'PQC Readiness Grade (A+ through F)',
            'QARS quantum-adjusted risk scoring (0-100)',
            "Mosca's inequality urgency factor",
            'CNSA 2.0 per-algorithm deadline countdown',
            'Quality gates for CI/CD pipelines (4 presets)',
            'Reachability analysis (CONFIRMED/REACHABLE/AVAILABLE)',
            'Migration effort and cost estimator',
            'PQC performance impact comparison',
            'Historical scan trend tracking',
        ]),
        ('COMPLIANCE FRAMEWORKS', [
            'CNSA 2.0 (NSA) with category-specific deadlines',
            'NIST IR 8547 transition guidance',
            'PCI DSS 4.0 payment card requirements',
            'OMB M-23-02 federal inventory mandate',
        ]),
        ('OUTPUT & INTEGRATION', [
            'Text, JSON, HTML report formats',
            'SARIF 2.1.0 (GitHub Code Scanning, Azure DevOps)',
            'CycloneDX CBOM 1.7 (enterprise SBOM integration)',
            'Interactive SVG dashboard (self-contained HTML)',
            'PDF executive reports',
            'VS Code extension (scan on save, inline diagnostics)',
            'GitHub Action with SARIF auto-upload',
            'Baseline diffing (incremental CI/CD scanning)',
            '.pqcignore suppression system',
        ]),
        ('DEPENDENCY ANALYSIS', [
            '6 manifest parsers (pip, npm, Maven, Go, Cargo, Gradle)',
            '6 lock file parsers (Pipfile.lock, package-lock.json, etc.)',
            'Transitive dependency detection',
            '60+ known crypto packages across 6 ecosystems',
            'Certificate scanning (PEM, DER, TLS endpoint)',
            'Reachability verification (import + call analysis)',
        ]),
        ('REMEDIATION', [
            'Tier 1: Deterministic auto-fix (25+ transforms)',
            'Tier 2: Template migrations (RSA to ML-KEM, ECDSA to ML-DSA)',
            'Unified diff output (compatible with git apply)',
            'Per-finding PQC replacement recommendations',
        ]),
    ]

    feat_rows = []
    for cat_name, features in categories:
        feat_rows.append([Paragraph(f'<b>{cat_name}</b>', s_body_b), ''])
        for feat in features:
            feat_rows.append([
                Paragraph(feat, s_body),
                Paragraph('<font color="#38A169"><b>YES</b></font>',
                         ParagraphStyle('y', parent=s_body, alignment=TA_CENTER)),
            ])

    E.append(Table(feat_rows, colWidths=[5.2*inch, 0.7*inch], style=TableStyle([
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('LINEBELOW', (0,0), (-1,-1), 0.3, MID_GRAY),
    ])))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 5. DETECTION ENGINE
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('5. Detection Engine', s_h1))
    E.append(Paragraph(
        'Enigma employs a three-layer detection architecture. Tree-sitter provides deep AST '
        'parsing for 13 compiled grammars. Regex pattern matching serves as a high-speed '
        'fallback. Python-specific AST analysis handles import aliasing and dynamic dispatch.', s_body))

    E.append(Paragraph('Supported Languages & Crypto APIs', s_h2))
    lang_data = [
        ['Language', 'Crypto APIs Detected', 'Analysis Depth'],
        ['Python', 'cryptography, PyCryptodome, hashlib,\nssl, paramiko',
         'AST: import alias resolution,\nkey_size kwarg extraction,\nbackward slicing'],
        ['Java / Kotlin / Scala', 'JCA: Cipher, KeyPairGenerator,\nMessageDigest, Signature, KeyAgreement',
         'AST: getInstance() string parsing,\nmode detection (ECB/GCM)'],
        ['Go', 'crypto/rsa, crypto/ecdsa, crypto/des,\ncrypto/sha1, x/crypto',
         'AST: import path tracking,\nGenerateKey size extraction'],
        ['JavaScript / TypeScript', 'crypto.createSign, generateKeyPair,\ncreateECDH, createDiffieHellman',
         'AST: require() resolution,\nalgorithm string detection'],
        ['Rust', 'rsa, p256, k256, sha1, md5,\nring, rustls crates',
         'AST: use declaration tracking,\ncrate function detection'],
        ['C / C++', 'OpenSSL EVP_*, RSA_*, EC_KEY_*,\nDH_*, SHA1_*, MD5_*',
         'AST: function call matching,\nkey size parameter extraction'],
        ['C#', 'System.Security.Cryptography:\nRSA, ECDsa, TripleDES, MD5, SHA1',
         'AST: Create() pattern matching'],
        ['Ruby', 'OpenSSL::PKey, Digest::MD5/SHA1', 'AST: module reference tracking'],
        ['PHP', 'openssl_pkey_new, openssl_sign,\nmd5(), sha1(), mcrypt',
         'AST: function call detection'],
        ['Swift', 'CryptoKit (P256, Curve25519),\nCommonCrypto (CC_MD5, CC_SHA1)',
         'AST: framework import tracking'],
        ['Terraform / YAML', 'tls_private_key, algorithm,\nmin_tls_version, cipher_suites',
         'Pattern: IaC config scanning'],
        ['Dockerfile', 'ENV/ARG crypto configuration', 'Pattern: build config scanning'],
    ]
    E.append(Table(lang_data, colWidths=[1.3*inch, 2.2*inch, 2.2*inch], style=tbl_style()))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 6. RISK INTELLIGENCE
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('6. Risk Intelligence & Grading', s_h1))

    E.append(Paragraph('PQC Readiness Grade', s_h2))
    E.append(Paragraph(
        'Inspired by Qualys SSL Labs, the Readiness Grade provides an instant, universally '
        'understood assessment of quantum preparedness:', s_body))

    grade_data = [
        ['Grade', 'Score', 'Assessment', 'Action Required'],
        ['A+ / A', '85 - 100', 'Quantum-ready', 'Maintain current posture'],
        ['B', '75 - 84', 'Good posture', 'Address minor gaps'],
        ['C', '60 - 74', 'Moderate risk', 'Plan migration roadmap'],
        ['D', '40 - 59', 'High risk', 'Begin active migration'],
        ['F', '0 - 39', 'Critical risk', 'Immediate action required'],
    ]
    E.append(Table(grade_data, colWidths=[0.7*inch, 0.8*inch, 1.5*inch, 2.5*inch],
                   style=tbl_style()))

    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph('QARS &mdash; Quantum-Adjusted Risk Score', s_h2))
    E.append(Paragraph(
        'Multi-factor scoring model incorporating five dimensions: algorithm vulnerability '
        '(Shor/Grover susceptibility), key size analysis, Mosca&rsquo;s inequality urgency '
        'factor, data sensitivity classification, and network exposure level. Enables '
        'data-driven prioritization of migration efforts across large portfolios.', s_body))

    E.append(Paragraph('Quality Gates for CI/CD', s_h2))
    gates = [
        ['Gate Preset', 'Conditions', 'Use Case'],
        ['pqc-ready', 'No Shor-vulnerable algorithms,\ngrade C+, no overdue CNSA deadlines',
         'Production release gates'],
        ['no-critical', 'Zero CRITICAL severity findings', 'Standard build pipeline'],
        ['cnsa-compliant', 'No overdue CNSA 2.0 deadlines,\nno non-compliant algorithms',
         'Government / defense contracts'],
        ['migration-safe', 'Not grade F, QARS below 80', 'Incremental migration\n(gates new risk only)'],
    ]
    E.append(Table(gates, colWidths=[1.3*inch, 2.4*inch, 1.8*inch], style=tbl_style()))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 7. COMPETITIVE ANALYSIS
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('7. Competitive Analysis', s_h1))
    E.append(Paragraph(
        'Based on analysis of 30 tools across PQC-specific scanners, general SAST platforms, '
        'and network scanning tools:', s_body))

    comp_data = [
        ['Capability', 'Enigma', 'IBM\nCBOMkit', 'CSNP\nCryptoScan', 'Semgrep', 'Snyk'],
        ['AST-based detection', '13 langs', '3 langs', 'No', '30+ langs', '30+ langs'],
        ['PQC awareness', 'YES', 'Partial', 'YES', 'No', 'No'],
        ['CBOM output', 'YES', 'YES', 'YES', 'No', 'No'],
        ['Readiness grade (A+-F)', 'YES', 'No', 'No', 'No', 'No'],
        ['Quality gates', 'YES', 'No', 'No', 'No', 'No'],
        ['CNSA 2.0 deadlines', 'YES', 'No', 'No', 'No', 'No'],
        ['Auto-fix code diffs', 'YES', 'No', 'No', 'YES', 'YES'],
        ['Reachability analysis', 'YES', 'No', 'Go only', 'No', 'YES'],
        ['Backward slicing', 'YES', 'No', 'No', 'No', 'No'],
        ['Risk scoring', 'QARS', 'No', 'Basic', 'No', 'CVSS'],
        ['Dependency scanning', '12 formats', 'No', '4 ecosys', 'YES', 'YES'],
        ['Certificate scanning', 'YES', 'No', 'Partial', 'No', 'No'],
        ['Custom rule engine', 'YAML', 'Yes', 'No', 'YAML', 'Partial'],
        ['Migration estimator', 'YES', 'No', 'No', 'No', 'No'],
        ['Trend tracking', 'YES', 'Partial', 'Partial', 'YES', 'YES'],
    ]
    ct = Table(comp_data, colWidths=[1.4*inch, 0.8*inch, 0.7*inch, 0.7*inch, 0.8*inch, 0.7*inch])
    ct.setStyle(tbl_style())
    ct.setStyle(TableStyle([
        ('BACKGROUND', (1, 0), (1, -1), HexColor('#F0F7F0')),
        ('FONTNAME', (1, 1), (1, -1), 'Helvetica-Bold'),
    ]))
    E.append(ct)
    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph(
        '<i>Enigma provides 30 PQC-specific features. The closest competitor (CSNP CryptoScan) '
        'provides 10. No existing tool combines AST-based PQC detection with CBOM output, '
        'compliance mapping, and automated remediation in a single CLI.</i>', s_footer))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 8. PERFORMANCE
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('8. Performance & Accuracy', s_h1))

    E.append(Paragraph('Benchmark Results', s_h2))
    E.append(Paragraph(
        'Measured against a controlled test suite of 22 known crypto patterns across '
        '8 languages and 8 verified clean files:', s_body))

    bench = [
        ['Metric', 'Result', 'Description'],
        ['Precision', '96.2%', 'Of findings flagged, 96.2% are true crypto usage'],
        ['Recall', '100.0%', 'Of known crypto patterns, 100% were detected'],
        ['F1 Score', '98.0%', 'Harmonic mean of precision and recall'],
        ['False positive source', '3.8%', 'Algorithm names in string literals (regex layer)'],
    ]
    E.append(Table(bench, colWidths=[1.2*inch, 0.8*inch, 3.5*inch], style=tbl_style()))

    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph('Scale Testing', s_h2))
    scale = [
        ['Project', 'Files', 'Scan Time', 'Findings', 'Memory'],
        ['Django (full repo)', '7,056', '12.1 seconds', '139', '32 MB'],
        ['Flask', '84', '0.95 seconds', '16', '<10 MB'],
        ['requests', '37', '0.71 seconds', '55', '<10 MB'],
    ]
    E.append(Table(scale, colWidths=[1.4*inch, 0.8*inch, 1*inch, 0.8*inch, 0.8*inch],
                   style=tbl_style()))

    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph('Error Resilience', s_h2))
    E.append(Paragraph(
        'Validated against 10 edge-case scenarios: binary files, empty files, 100K-character '
        'lines, mixed encoding, 10K-line files, comment-only files, syntax errors, nonexistent '
        'paths, empty directories, and permission restrictions. <b>All handled gracefully with '
        'zero crashes.</b>', s_body))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 9. MIGRATION SUPPORT
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('9. Migration Support', s_h1))

    E.append(Paragraph('Effort Classification', s_h2))
    effort = [
        ['Complexity', 'Examples', 'Hours / Instance', 'Approach'],
        ['DROP-IN', 'MD5 to SHA-256\nSHA-1 to SHA-256', '0.5 - 1.0',
         'Direct function rename.\nDeterministic, automatable.'],
        ['API CHANGE', '3DES to AES-256-GCM\nRC4 to ChaCha20', '2.0 - 3.0',
         'Cipher + key size change.\nModerate testing required.'],
        ['ARCHITECTURAL', 'RSA to ML-KEM\nECDSA to ML-DSA', '5.0 - 8.0',
         'Full scheme replacement.\nLibrary, protocol, and interop\ntesting required.'],
    ]
    E.append(Table(effort, colWidths=[1.2*inch, 1.3*inch, 1.1*inch, 2.1*inch],
                   style=tbl_style()))

    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph('PQC Algorithm Performance', s_h2))
    E.append(Paragraph(
        'PQC algorithms have larger keys but are often computationally faster:', s_body))
    perf = [
        ['Algorithm', 'Type', 'Public Key', 'Sig / CT', 'Ops/sec', 'Standard'],
        ['RSA-2048', 'Classical', '256 B', '256 B', '1,000', 'PKCS#1'],
        ['X25519', 'Classical', '32 B', '32 B', '20,000', 'RFC 7748'],
        ['ML-KEM-768', 'PQC', '1,184 B', '1,088 B', '35,000', 'FIPS 203'],
        ['ML-DSA-65', 'PQC', '1,952 B', '3,293 B', '10,000', 'FIPS 204'],
    ]
    E.append(Table(perf, colWidths=[1.1*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.9*inch],
                   style=tbl_style()))
    E.append(Paragraph(
        '<b>Key insight:</b> ML-KEM-768 is 1.75x <i>faster</i> than X25519 in operations/second. '
        'The migration cost is primarily bandwidth (larger keys/signatures), not compute.', s_body))
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 10. DEPLOYMENT
    # ══════════════════════════════════════════════════════════════
    E.append(Paragraph('10. Deployment Options', s_h1))

    deploy = [
        ['Method', 'Setup', 'Use Case'],
        ['CLI', 'pqc-scanner scan /path --grade --fix', 'Developer workstation,\nautomated scripts'],
        ['CI/CD Pipeline', 'pqc-scanner scan . --gate pqc-ready\n--format sarif -o results.sarif',
         'Build pipeline quality\ngate enforcement'],
        ['GitHub Action', 'uses: enigma/pqc-scanner@v4\nwith: { format: sarif }',
         'GitHub Code Scanning\nSARIF integration'],
        ['VS Code Extension', 'Install from marketplace.\nAuto-scans on file save.',
         'Real-time inline warnings\nwith quick-fix actions'],
        ['Executive Dashboard', 'pqc-scanner scan . --format dashboard\n-o report.html',
         'CISO/board reporting,\nstakeholder presentations'],
        ['CBOM Export', 'pqc-scanner scan . --format cbom\n-o cbom.json',
         'Enterprise SBOM toolchain\nand compliance audit'],
        ['Consulting Assessment', 'Full scan + compliance report +\nmigration estimate',
         'Professional services\nengagement deliverable'],
    ]
    dt = Table(deploy, colWidths=[1.3*inch, 2.5*inch, 1.9*inch])
    dt.setStyle(tbl_style())
    dt.setStyle(TableStyle([
        ('FONTNAME', (1, 1), (1, -1), 'Courier'),
        ('FONTSIZE', (1, 1), (1, -1), 8),
    ]))
    E.append(dt)
    E.append(PageBreak())

    # ══════════════════════════════════════════════════════════════
    # 11. CLOSING
    # ══════════════════════════════════════════════════════════════
    E.append(Spacer(1, 0.5*inch))
    closing_logo = Table([[EnigmaLogo(60)]], colWidths=[6*inch])
    closing_logo.setStyle(TableStyle([('ALIGN', (0,0), (0,0), 'CENTER')]))
    E.append(closing_logo)
    E.append(Spacer(1, 0.2*inch))
    E.append(Paragraph('Ready to Assess Your Quantum Risk?',
        ParagraphStyle('closeh1', parent=s_h1, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph(
        'The NIST deadline is 2035. CNSA 2.0 deadlines have already begun. '
        'Every day without a cryptographic inventory is a day of unquantified risk.', s_body))
    E.append(Spacer(1, 0.1*inch))
    E.append(Paragraph(
        'Enigma pqc-scanner provides the most comprehensive quantum vulnerability assessment '
        'available &mdash; across more languages, with deeper analysis, and more actionable '
        'output than any competing solution.', s_body))

    E.append(Spacer(1, 0.3*inch))
    E.append(HRFlowable(width='40%', thickness=1.5, color=GOLD, spaceAfter=16))
    E.append(Spacer(1, 0.3*inch))

    E.append(Paragraph(
        '<b>ENIGMA</b> pqc-scanner',
        ParagraphStyle('end1', fontSize=14, textColor=NAVY,
                       alignment=TA_CENTER, fontName='Helvetica-Bold')))
    E.append(Paragraph(
        f'Version 4.0 &mdash; {datetime.now().strftime("%B %Y")}',
        ParagraphStyle('end2', fontSize=10, textColor=MUTED, alignment=TA_CENTER)))
    E.append(Spacer(1, 0.5*inch))
    E.append(Paragraph('CONFIDENTIAL', ParagraphStyle('endc', fontSize=9,
        textColor=ACCENT_RED, alignment=TA_CENTER, fontName='Helvetica-Bold')))

    # ── Build ──
    doc.build(E)
    return output_path


if __name__ == '__main__':
    out = os.path.join(os.path.dirname(__file__), '..',
                       'Enigma_PQC_Scanner_Corporate_Overview.pdf')
    path = build_corporate_pdf(out)
    print(f'Generated: {os.path.abspath(path)}')
