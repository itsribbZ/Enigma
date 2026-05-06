"""
Enigma pqc-scanner v4.0: Compliance Framework Mapping + QARS Risk Scoring.

Maps scanner findings to three major PQC compliance frameworks:
  - CNSA 2.0 (NSA Commercial National Security Algorithm Suite)
  - NIST IR 8547 (Transition to Post-Quantum Cryptography)
  - PCI DSS 4.0 (Payment Card Industry Data Security Standard)

v4.0 adds:
  - CNSA 2.0 deadline countdown (days remaining per algorithm)
  - QARS multi-factor quantum risk scoring
  - Urgency classification (OVERDUE / URGENT / APPROACHING / DISTANT)
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, date
from typing import Dict, List, Optional
from pqc_scanner import ScanResult, Finding, Severity


# ============================================================================
# COMPLIANCE STATUS
# ============================================================================

class ComplianceStatus:
    COMPLIANT = 'COMPLIANT'
    DEPRECATED = 'DEPRECATED'
    NON_COMPLIANT = 'NON-COMPLIANT'
    NOT_APPLICABLE = 'N/A'


# ============================================================================
# CNSA 2.0 (NSA, September 2022) — with granular deadlines
# ============================================================================

# CNSA 2.0 has CATEGORY-SPECIFIC deadlines (NSA CSA CNSA 2.0, published 2022, updated 2024)
# Dates below are EXCLUSIVE-USE deadlines (when legacy algorithms must be fully retired).
# "Support and prefer" milestones are earlier; these are the hard compliance deadlines.
CNSA2_DEADLINES = {
    'software_signing': date(2030, 12, 31),   # Software/firmware signing exclusive use
    'web_services': date(2033, 12, 31),       # Web servers, cloud, browsers exclusive use
    'networking': date(2030, 12, 31),         # Networking equipment, IKE/IPsec
    'all_nss': date(2033, 12, 31),            # All remaining National Security Systems
}

CNSA2_ALGORITHM_MAP = {
    # Algorithm → (status, deadline_key, replacement, notes)
    # Per NSA SP 800-208: firmware/software signing MUST use LMS or XMSS (stateful hash sigs).
    # ML-DSA is for general signatures; ML-KEM is for key establishment.
    'RSA': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
            'LMS or XMSS (firmware/code signing, per NIST SP 800-208), ML-KEM-1024 (key exchange), ML-DSA-87 (general signatures)',
            'Software/firmware signing: LMS/XMSS by 2030. Web services: 2033. Networking: 2030.'),
    'ECDSA': (ComplianceStatus.NON_COMPLIANT, 'all_nss',
              'ML-DSA-87',
              'ECDSA P-384 allowed until 2033. Transition to ML-DSA.'),
    'ECDH': (ComplianceStatus.NON_COMPLIANT, 'networking',
             'ML-KEM-1024',
             'ECDH deprecated for key exchange. Replace by 2030.'),
    'Ed25519': (ComplianceStatus.NON_COMPLIANT, 'all_nss',
                'ML-DSA-65 or ML-DSA-87',
                'All ECC-based signatures must transition to ML-DSA.'),
    'DH': (ComplianceStatus.NON_COMPLIANT, 'networking',
            'ML-KEM-1024',
            'Finite-field DH deprecated. Replace immediately.'),
    'DSA': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
            'ML-DSA-87',
            'DSA already deprecated. Replace immediately.'),
    'AES-128': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
                'AES-256',
                'CNSA 2.0 requires AES-256 minimum across ALL NSS categories. AES-128 is non-compliant immediately.'),
    'AES-256': (ComplianceStatus.COMPLIANT, None, None,
                'AES-256 is CNSA 2.0 compliant.'),
    'SHA-1': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
              'SHA-384 or SHA-512',
              'SHA-1 prohibited. CNSA 2.0 requires SHA-384+.'),
    'SHA-256': (ComplianceStatus.DEPRECATED, 'all_nss',
                'SHA-384',
                'CNSA 2.0 prefers SHA-384. SHA-256 acceptable transitionally.'),
    'MD5': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
            'SHA-384', 'MD5 prohibited.'),
    '3DES': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
             'AES-256', '3DES prohibited.'),
    'RC4': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
            'AES-256-GCM', 'RC4 prohibited.'),
    'Blowfish': (ComplianceStatus.NON_COMPLIANT, 'software_signing',
                 'AES-256', 'Blowfish not approved.'),
}

# ============================================================================
# NIST IR 8547 (November 2024)
# ============================================================================

NIST_IR8547_MAP = {
    'RSA': (ComplianceStatus.DEPRECATED, '2030',
            'ML-KEM (FIPS 203) / ML-DSA (FIPS 204)',
            'NIST recommends completing PQC transition by 2035. RSA disallowed after 2030.'),
    'ECDSA': (ComplianceStatus.DEPRECATED, '2030',
              'ML-DSA (FIPS 204)',
              'ECDSA P-256 (128-bit classical sec) deprecated after 2030, disallowed after 2035. ECDSA P-384+ disallowed after 2035.'),
    'ECDH': (ComplianceStatus.DEPRECATED, '2030',
             'ML-KEM (FIPS 203)',
             'Key exchange must transition first (HNDL threat).'),
    'Ed25519': (ComplianceStatus.DEPRECATED, '2035',
                'ML-DSA (FIPS 204)',
                'All ECC-based signatures deprecated by 2035.'),
    'DH': (ComplianceStatus.DEPRECATED, '2030',
            'ML-KEM (FIPS 203)', 'DH deprecated for key exchange.'),
    'DSA': (ComplianceStatus.NON_COMPLIANT, '2023',
            'ML-DSA (FIPS 204)', 'DSA already disallowed in FIPS 186-5.'),
    'AES-128': (ComplianceStatus.DEPRECATED, '2035',
                'AES-256', 'AES-128 has 64-bit quantum security. NIST IR 8547 does not impose a specific 2030 deadline on AES-128 (that applies to 112-bit classical algorithms). Transition to AES-256 recommended by 2035.'),
    'AES-256': (ComplianceStatus.COMPLIANT, None, None,
                'AES-256 remains secure (128-bit quantum security).'),
    'SHA-1': (ComplianceStatus.NON_COMPLIANT, '2023',
              'SHA-256 or SHA-3', 'SHA-1 disallowed since FIPS 186-5.'),
    'SHA-256': (ComplianceStatus.COMPLIANT, None, None,
                'SHA-256 provides 128-bit quantum security via Grover.'),
    'MD5': (ComplianceStatus.NON_COMPLIANT, '2010', 'SHA-256', 'MD5 broken and prohibited.'),
    '3DES': (ComplianceStatus.NON_COMPLIANT, '2023', 'AES-256', '3DES disallowed after 2023.'),
    'RC4': (ComplianceStatus.NON_COMPLIANT, '2015', 'AES-256-GCM', 'RC4 prohibited.'),
    'Blowfish': (ComplianceStatus.NON_COMPLIANT, '2023', 'AES-256', 'Not NIST-approved.'),
}

# ============================================================================
# PCI DSS 4.0
# ============================================================================

PCI_DSS4_MAP = {
    'RSA': (ComplianceStatus.DEPRECATED, '2030', 'ML-KEM + ML-DSA',
            'PCI DSS 4.0 Req 4: strong cryptography. RSA >=2048 accepted but PQC migration recommended.'),
    'ECDSA': (ComplianceStatus.COMPLIANT, None, None,
              'ECDSA accepted for PCI DSS 4.0 with approved curves (P-256+).'),
    'ECDH': (ComplianceStatus.COMPLIANT, None, None,
             'ECDH accepted for PCI DSS 4.0 key exchange.'),
    'Ed25519': (ComplianceStatus.COMPLIANT, None, None, 'Ed25519 accepted.'),
    'DH': (ComplianceStatus.DEPRECATED, '2025', 'ECDH or ML-KEM',
            'DH >=2048 accepted but ECDH preferred.'),
    'DSA': (ComplianceStatus.NON_COMPLIANT, '2023', 'ECDSA or ML-DSA',
            'DSA not recommended for new deployments.'),
    'AES-128': (ComplianceStatus.COMPLIANT, None, None, 'AES-128 accepted (Req 3.5.1).'),
    'AES-256': (ComplianceStatus.COMPLIANT, None, None, 'AES-256 preferred.'),
    'SHA-1': (ComplianceStatus.NON_COMPLIANT, '2023', 'SHA-256', 'SHA-1 not accepted.'),
    'SHA-256': (ComplianceStatus.COMPLIANT, None, None, 'SHA-256 accepted.'),
    'MD5': (ComplianceStatus.NON_COMPLIANT, '2010', 'SHA-256', 'MD5 prohibited.'),
    '3DES': (ComplianceStatus.NON_COMPLIANT, '2023', 'AES-128 or AES-256', '3DES disallowed.'),
    'RC4': (ComplianceStatus.NON_COMPLIANT, '2015', 'AES-GCM', 'RC4 prohibited.'),
    'Blowfish': (ComplianceStatus.NON_COMPLIANT, '2023', 'AES-256', 'Not approved.'),
}

FRAMEWORKS = {
    'CNSA 2.0': CNSA2_ALGORITHM_MAP,
    'NIST IR 8547': NIST_IR8547_MAP,
    'PCI DSS 4.0': PCI_DSS4_MAP,
}


# ============================================================================
# CNSA 2.0 DEADLINE COUNTDOWN
# ============================================================================

@dataclass
class DeadlineInfo:
    """CNSA 2.0 deadline details for an algorithm."""
    algorithm: str
    deadline_category: str     # software_signing, web_services, networking, all_nss
    deadline_date: date
    days_remaining: int
    urgency: str              # OVERDUE, URGENT (<365 days), APPROACHING (<1095), DISTANT
    status: str


def get_cnsa2_deadline(algorithm: str, reference_date: Optional[date] = None) -> Optional[DeadlineInfo]:
    """Get CNSA 2.0 deadline details for an algorithm with countdown."""
    if algorithm not in CNSA2_ALGORITHM_MAP:
        return None

    status, deadline_key, replacement, notes = CNSA2_ALGORITHM_MAP[algorithm]
    if deadline_key is None:
        return None  # Compliant — no deadline

    deadline_date = CNSA2_DEADLINES[deadline_key]
    ref = reference_date or date.today()
    days = (deadline_date - ref).days

    if days < 0:
        urgency = 'OVERDUE'
    elif days < 365:
        urgency = 'URGENT'
    elif days < 1095:  # ~3 years
        urgency = 'APPROACHING'
    else:
        urgency = 'DISTANT'

    return DeadlineInfo(
        algorithm=algorithm,
        deadline_category=deadline_key,
        deadline_date=deadline_date,
        days_remaining=days,
        urgency=urgency,
        status=status,
    )


def get_all_deadlines(algorithms: List[str],
                      reference_date: Optional[date] = None) -> List[DeadlineInfo]:
    """Get CNSA 2.0 deadline info for a list of algorithms, sorted by urgency."""
    deadlines = []
    seen = set()
    for algo in algorithms:
        if algo in seen:
            continue
        seen.add(algo)
        info = get_cnsa2_deadline(algo, reference_date)
        if info:
            deadlines.append(info)
    return sorted(deadlines, key=lambda d: d.days_remaining)


# ============================================================================
# QARS — Quantum-Adjusted Risk Score
# ============================================================================

# Algorithm risk factors (probability of quantum break, 0.0-1.0)
# Calibrated against NIST Post-Quantum Cryptography project assessments,
# ETSI Quantum Safe Cryptography white papers (TR 103 619), and
# BSI Technical Guideline TR-02102-1 (2024 edition).
#
# Methodology:
#   Shor-vulnerable (public-key): 0.85-0.95 — Shor's algorithm provides
#     exponential speedup. RSA/DH/DSA require ~2n qubits for n-bit keys.
#     ECDSA/ECDH require ~6n qubits for n-bit curves. RSA is rated highest
#     because its keys are typically smaller relative to security level.
#   Grover-vulnerable (symmetric/hash): 0.20-0.50 — Grover provides only
#     quadratic speedup. AES-256 retains 128-bit post-quantum security.
#     Broken algorithms (MD5, RC4) get higher scores due to classical+quantum.
#   Classically broken: 0.50-0.80 — already exploitable, quantum makes worse.
_ALGO_RISK = {
    # Shor-vulnerable (asymmetric) — NIST categorizes as "not quantum-resistant"
    'RSA': 0.95,      # Shor's: 2048-bit RSA needs ~4,099 logical qubits (Gidney & Ekera 2021)
    'DH': 0.95,       # Shor's on DLP: same resource requirements as RSA factoring
    'DSA': 0.93,      # Shor's on DLP: same as DH but less commonly used (smaller attack surface)
    'ECDSA': 0.90,    # Shor's on ECDLP: P-256 needs ~2,330 logical qubits (Roetteler et al.)
    'ECDH': 0.90,     # Same ECDLP vulnerability as ECDSA
    'Ed25519': 0.88,  # Curve25519 ECDLP: similar qubit count to P-256, slightly smaller field
    'Ed448': 0.88,    # Larger curve but same class of vulnerability
    'X25519': 0.88,   # ECDH on Curve25519 — same as Ed25519
    'X448': 0.88,     # ECDH on Curve448
    # Grover-vulnerable (symmetric) — NIST: "double key length for post-quantum security"
    'AES-128': 0.25,  # Grover reduces to 64-bit: borderline. AES-256 recommended.
    'AES-256': 0.05,  # Grover reduces to 128-bit: still secure. CNSA 2.0 compliant.
    # Classically broken + quantum acceleration
    'SHA-1': 0.45,    # Collision-broken 2017 (SHAttered). Grover speeds preimage by sqrt.
    'MD5': 0.55,      # Collision-broken 2004. Trivially exploitable classically.
    'MD4': 0.60,      # Severely broken since 1995.
    '3DES': 0.65,     # 64-bit block → Sweet32 attack. Grover halves keyspace.
    'RC4': 0.75,      # Broken classically (biases). IETF RFC 7465 prohibits in TLS.
    'Blowfish': 0.55, # 64-bit block → Sweet32. Key schedule limits effective strength.
    'IDEA': 0.50,     # 64-bit block, 128-bit key. Grover reduces to 64-bit.
    'CAST5': 0.50,    # 64-bit block, up to 128-bit key. Same class as IDEA.
    'DES': 0.80,      # 56-bit key: trivially breakable even classically.
}

# Key size risk (inverse security margin against quantum)
# Based on NIST SP 800-57 Part 1 Rev 5 security strength estimates,
# adjusted for Shor/Grover quantum impact.
_KEY_SIZE_RISK = {
    # RSA/DH/DSA key sizes (Shor's: effectively 0-bit post-quantum security)
    512: 1.0,    # Factorable in hours on classical hardware
    768: 0.98,   # Factorable with effort classically
    1024: 0.95,  # ~80-bit classical, 0-bit post-quantum
    2048: 0.80,  # ~112-bit classical, 0-bit post-quantum
    3072: 0.70,  # ~128-bit classical, 0-bit post-quantum
    4096: 0.60,  # ~152-bit classical, 0-bit post-quantum
    8192: 0.40,  # Larger but still Shor-vulnerable
    # ECC key sizes (Shor's: effectively 0-bit post-quantum)
    224: 0.85,   # P-224: ~112-bit classical
    256: 0.80,   # P-256: ~128-bit classical
    384: 0.70,   # P-384: ~192-bit classical
    521: 0.60,   # P-521: ~256-bit classical
    # Symmetric key sizes (Grover: halves effective strength)
    128: 0.25,   # Post-quantum: 64-bit (borderline)
    192: 0.10,   # Post-quantum: 96-bit (adequate)
    256: 0.05,   # Post-quantum: 128-bit (secure)
}

# Data sensitivity levels
SENSITIVITY_LEVELS = {
    'public': 0.1,
    'internal': 0.4,
    'confidential': 0.7,
    'restricted': 1.0,
}

# Exposure levels
EXPOSURE_LEVELS = {
    'isolated': 0.1,
    'internal': 0.3,
    'internet': 0.8,
    'critical_infra': 1.0,
}


@dataclass
class QARSScore:
    """Quantum-Adjusted Risk Score for a scan result."""
    overall_score: float          # 0.0-100.0
    grade: str                    # A-F
    algorithm_risk: float         # Weighted average algorithm risk
    mosca_urgency: float          # Mosca's inequality urgency factor
    highest_risk_algo: str        # Most vulnerable algorithm found
    highest_risk_value: float
    findings_by_risk: Dict[str, float]  # algo → risk value


def compute_qars(result: ScanResult,
                 sensitivity: str = 'internal',
                 exposure: str = 'internet',
                 data_shelf_life_years: int = 10,
                 migration_time_years: int = 3,
                 quantum_threat_years: int = 10) -> QARSScore:
    """Compute QARS (Quantum-Adjusted Risk Score) for a scan result.

    Incorporates:
    - Algorithm vulnerability (Shor/Grover susceptibility)
    - Key size analysis
    - Mosca's inequality urgency
    - Data sensitivity and exposure weighting

    Args:
        result: Scan result with findings
        sensitivity: Data sensitivity level (public/internal/confidential/restricted)
        exposure: Network exposure level (isolated/internal/internet/critical_infra)
        data_shelf_life_years: How long data must remain secure
        migration_time_years: Estimated time to complete PQC migration
        quantum_threat_years: Estimated years until CRQC (cryptographically relevant quantum computer)
    """
    if not result.findings:
        return QARSScore(0.0, 'A', 0.0, 0.0, 'None', 0.0, {})

    sensitivity_w = SENSITIVITY_LEVELS.get(sensitivity, 0.4)
    exposure_w = EXPOSURE_LEVELS.get(exposure, 0.8)

    # Mosca urgency: if shelf_life + migration_time > quantum_threat, urgent
    mosca_margin = (data_shelf_life_years + migration_time_years) - quantum_threat_years
    mosca_urgency = max(0.0, min(1.0, mosca_margin / 10.0))  # Normalize to 0-1

    # Per-algorithm risk
    algo_risks: Dict[str, float] = {}
    for f in result.findings:
        algo = f.algorithm
        if algo in algo_risks:
            continue
        base_risk = _ALGO_RISK.get(algo, 0.5)

        # Key size adjustment (from tree-sitter findings with key_size in description)
        key_size_factor = 0.7  # default
        if hasattr(f, 'description') and 'key_size=' in f.description:
            try:
                ks = int(f.description.split('key_size=')[1].split(')')[0].split(' ')[0])
                key_size_factor = _KEY_SIZE_RISK.get(ks, 0.5)
            except (ValueError, IndexError):
                pass

        # Combined risk per algorithm
        algo_risk = base_risk * 0.5 + key_size_factor * 0.2 + sensitivity_w * 0.15 + exposure_w * 0.15
        algo_risks[algo] = min(1.0, algo_risk)

    # Overall score: weighted by finding count
    algo_counts = {}
    for f in result.findings:
        algo_counts[f.algorithm] = algo_counts.get(f.algorithm, 0) + 1

    total_weighted = 0.0
    total_count = 0
    for algo, risk in algo_risks.items():
        count = algo_counts.get(algo, 1)
        total_weighted += risk * count
        total_count += count

    avg_risk = total_weighted / max(total_count, 1)

    # Apply Mosca urgency multiplier
    urgency_multiplier = 1.0 + mosca_urgency * 0.5  # Up to 1.5x for urgent
    overall = min(100.0, avg_risk * urgency_multiplier * 100)

    # Grade
    if overall >= 80:
        grade = 'F'
    elif overall >= 60:
        grade = 'D'
    elif overall >= 40:
        grade = 'C'
    elif overall >= 20:
        grade = 'B'
    else:
        grade = 'A'

    highest_algo = max(algo_risks, key=algo_risks.get) if algo_risks else 'None'

    return QARSScore(
        overall_score=round(overall, 1),
        grade=grade,
        algorithm_risk=round(avg_risk, 3),
        mosca_urgency=round(mosca_urgency, 3),
        highest_risk_algo=highest_algo,
        highest_risk_value=round(algo_risks.get(highest_algo, 0), 3),
        findings_by_risk=algo_risks,
    )


# ============================================================================
# COMPLIANCE ANALYSIS
# ============================================================================

@dataclass
class ComplianceFinding:
    framework: str
    algorithm: str
    status: str
    deadline: Optional[str]
    replacement: Optional[str]
    notes: str
    finding_count: int
    days_remaining: Optional[int] = None
    urgency: Optional[str] = None


def analyze_compliance(result: ScanResult) -> Dict[str, List[ComplianceFinding]]:
    """Map scan findings to compliance framework violations."""
    result.compute_summary()
    report = {}

    algo_counts: Dict[str, int] = {}
    for f in result.findings:
        algo_counts[f.algorithm] = algo_counts.get(f.algorithm, 0) + 1

    for fw_name, fw_map in FRAMEWORKS.items():
        findings = []
        for algo, count in algo_counts.items():
            if algo in fw_map:
                entry = fw_map[algo]
                status = entry[0]
                deadline_key_or_year = entry[1]
                replacement = entry[2]
                notes = entry[3]

                # CNSA 2.0: resolve deadline from key
                days = None
                urgency = None
                if fw_name == 'CNSA 2.0' and deadline_key_or_year is not None:
                    info = get_cnsa2_deadline(algo)
                    if info:
                        days = info.days_remaining
                        urgency = info.urgency
                        deadline_str = f'{info.deadline_date.isoformat()} ({info.deadline_category})'
                    else:
                        deadline_str = str(deadline_key_or_year)
                else:
                    deadline_str = str(deadline_key_or_year) if deadline_key_or_year else None

                findings.append(ComplianceFinding(
                    framework=fw_name,
                    algorithm=algo,
                    status=status,
                    deadline=deadline_str,
                    replacement=replacement,
                    notes=notes,
                    finding_count=count,
                    days_remaining=days,
                    urgency=urgency,
                ))
        report[fw_name] = sorted(findings, key=lambda f: (
            0 if f.status == ComplianceStatus.NON_COMPLIANT else
            1 if f.status == ComplianceStatus.DEPRECATED else 2
        ))

    return report


def format_compliance_report(compliance: Dict[str, List[ComplianceFinding]]) -> str:
    """Format compliance analysis as text report with deadline countdown."""
    lines = [
        "=" * 70,
        "  COMPLIANCE ANALYSIS — Post-Quantum Cryptography Frameworks",
        "=" * 70,
        "",
    ]

    for fw_name, findings in compliance.items():
        non_compliant = sum(1 for f in findings if f.status == ComplianceStatus.NON_COMPLIANT)
        deprecated = sum(1 for f in findings if f.status == ComplianceStatus.DEPRECATED)

        if non_compliant > 0:
            verdict, verdict_char = "FAIL", "X"
        elif deprecated > 0:
            verdict, verdict_char = "WARN", "!"
        else:
            verdict, verdict_char = "PASS", "+"

        lines.append(f"  [{verdict_char}] {fw_name}: {verdict}")
        lines.append(f"      Non-compliant: {non_compliant} | Deprecated: {deprecated}")
        lines.append("")

        for f in findings:
            icon = "X" if f.status == ComplianceStatus.NON_COMPLIANT else (
                "!" if f.status == ComplianceStatus.DEPRECATED else "+")
            lines.append(f"      [{icon}] {f.algorithm} ({f.finding_count} findings) — {f.status}")
            if f.deadline:
                deadline_line = f"          Deadline: {f.deadline}"
                if f.days_remaining is not None:
                    if f.days_remaining < 0:
                        deadline_line += f" — OVERDUE by {abs(f.days_remaining)} days"
                    else:
                        deadline_line += f" — {f.days_remaining} days remaining"
                if f.urgency:
                    deadline_line += f" [{f.urgency}]"
                lines.append(deadline_line)
            if f.replacement:
                lines.append(f"          Replace:  {f.replacement}")
            lines.append(f"          {f.notes}")
            lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_qars_report(qars: QARSScore) -> str:
    """Format QARS score as text report."""
    lines = [
        "=" * 70,
        "  QARS — Quantum-Adjusted Risk Score",
        "=" * 70,
        "",
        f"  Overall Score: {qars.overall_score}/100 (Grade: {qars.grade})",
        f"  Algorithm Risk: {qars.algorithm_risk:.1%}",
        f"  Mosca Urgency:  {qars.mosca_urgency:.1%}",
        f"  Highest Risk:   {qars.highest_risk_algo} ({qars.highest_risk_value:.1%})",
        "",
        "  Per-Algorithm Risk:",
    ]

    for algo, risk in sorted(qars.findings_by_risk.items(), key=lambda x: -x[1]):
        bar = "#" * int(risk * 30)
        lines.append(f"    {algo:15s} [{bar:<30s}] {risk:.1%}")

    lines.extend(["", "=" * 70])
    return "\n".join(lines)
