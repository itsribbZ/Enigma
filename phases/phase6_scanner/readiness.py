"""
Enigma pqc-scanner v4.0: PQC Readiness Grade + Quality Gates.

SSL Labs-style grading (A+ through F) for quantum readiness.
SonarQube-style quality gates for CI/CD pass/fail decisions.

Grading Methodology:
  Algorithm Security  (40%) — Are quantum-vulnerable algorithms present?
  Key Management      (30%) — Key sizes, modes, certificate readiness
  Compliance Posture  (30%) — CNSA 2.0 / NIST IR 8547 alignment

Quality Gates:
  Define pass/fail conditions for CI/CD pipelines.
  Built-in gates: "pqc-ready", "no-critical", "cnsa-compliant"
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List, Optional, Tuple

from pqc_scanner import ScanResult, Finding, Severity, Category
from compliance import (
    get_all_deadlines, analyze_compliance, compute_qars,
    ComplianceStatus, CNSA2_ALGORITHM_MAP,
)


# ============================================================================
# PQC READINESS GRADE
# ============================================================================

@dataclass
class ReadinessGrade:
    """PQC Readiness assessment with SSL Labs-style grading."""
    grade: str                          # A+, A, B, C, D, F
    score: float                        # 0-100
    algorithm_score: float              # 0-100 (40% weight)
    key_management_score: float         # 0-100 (30% weight)
    compliance_score: float             # 0-100 (30% weight)
    summary: str                        # One-line summary
    details: Dict[str, str] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


# Shor-vulnerable algorithms (direct quantum break)
_SHOR_VULNERABLE = {'RSA', 'ECDSA', 'ECDH', 'Ed25519', 'DH', 'DSA',
                    'RSA/ECDSA', 'ECDH/DH', 'ECDSA/DSA', 'DH/ECDH'}

# Grover-weakened algorithms
_GROVER_WEAKENED = {'AES-128', 'SHA-1', 'MD5', '3DES', 'RC4', 'Blowfish',
                    'SHA-1/MD5', 'Weak cipher', 'Old TLS'}


def compute_readiness_grade(result: ScanResult,
                            sensitivity: str = 'internal',
                            exposure: str = 'internet') -> ReadinessGrade:
    """Compute PQC readiness grade (A+ through F).

    Methodology inspired by SSL Labs:
    - Algorithm Security (40%): presence and count of quantum-vulnerable crypto
    - Key Management (30%): key sizes, cipher modes, certificate posture
    - Compliance Posture (30%): CNSA 2.0 deadline status, framework alignment
    """
    if not result.findings:
        return ReadinessGrade(
            grade='A+', score=100.0,
            algorithm_score=100.0, key_management_score=100.0, compliance_score=100.0,
            summary='No quantum-vulnerable cryptography detected. Quantum-ready!',
            recommendations=['Maintain current posture', 'Monitor for new PQC standards'],
        )

    result.compute_summary()
    algos_found = set(f.algorithm for f in result.findings)

    # ── Algorithm Security (40%) ──
    shor_count = sum(1 for f in result.findings if f.algorithm in _SHOR_VULNERABLE)
    grover_count = sum(1 for f in result.findings if f.algorithm in _GROVER_WEAKENED)
    total = len(result.findings)

    if shor_count == 0 and grover_count == 0:
        algo_score = 100.0
    elif shor_count == 0:
        # Only Grover-weakened — not great but not catastrophic
        algo_score = max(0, 70 - grover_count * 3)
    else:
        # Shor-vulnerable present — significant deduction
        shor_ratio = shor_count / max(total, 1)
        algo_score = max(0, 40 - shor_ratio * 40 - grover_count * 2)

    # ── Key Management (30%) ──
    key_score = 100.0
    has_weak_keys = False
    has_ecb = False

    for f in result.findings:
        # Check for weak key sizes in description
        if 'key_size=' in f.description:
            try:
                ks = int(f.description.split('key_size=')[1].split(')')[0].split(' ')[0])
                if f.algorithm == 'RSA' and ks < 2048:
                    key_score -= 30
                    has_weak_keys = True
                elif f.algorithm == 'RSA' and ks < 4096:
                    key_score -= 10
            except (ValueError, IndexError):
                pass
        # Check for ECB mode
        if 'ECB' in f.description.upper() or 'mode=ecb' in f.description.lower():
            key_score -= 15
            has_ecb = True
        # Certificate findings
        if f.category == Category.CERTIFICATE:
            key_score -= 5

    # Deduct for broken algorithms
    if 'MD5' in algos_found:
        key_score -= 20
    if 'RC4' in algos_found:
        key_score -= 20
    if '3DES' in algos_found:
        key_score -= 10

    key_score = max(0, key_score)

    # ── Compliance Posture (30%) ──
    compliance_score = 100.0
    deadlines = get_all_deadlines(list(algos_found))
    overdue = [d for d in deadlines if d.days_remaining < 0]
    urgent = [d for d in deadlines if 0 <= d.days_remaining < 365]

    if overdue:
        compliance_score -= len(overdue) * 20
    if urgent:
        compliance_score -= len(urgent) * 10

    # CNSA 2.0 non-compliant count
    cnsa_violations = 0
    for algo in algos_found:
        if algo in CNSA2_ALGORITHM_MAP:
            status = CNSA2_ALGORITHM_MAP[algo][0]
            if status == ComplianceStatus.NON_COMPLIANT:
                cnsa_violations += 1
    compliance_score -= cnsa_violations * 5
    compliance_score = max(0, compliance_score)

    # ── Combined Score ──
    score = (algo_score * 0.4 + key_score * 0.3 + compliance_score * 0.3)

    # ── Grade Assignment ──
    # Automatic caps (SSL Labs style). Grade bands below: A+ ≥95, A ≥85, B ≥75, C ≥60, D ≥40, F <40.
    # Caps must land INSIDE the intended grade band, not below it.
    if shor_count > 0:
        score = min(score, 74)  # Cap at C (max) — Shor-vulnerable should not earn B
    if overdue:
        score = min(score, 59)  # Cap at D (max) — CNSA-overdue should not earn C
    if 'MD5' in algos_found or 'RC4' in algos_found:
        score = min(score, 74)  # Cap at C (max) — broken classical crypto should not earn B

    if score >= 95:
        grade = 'A+'
    elif score >= 85:
        grade = 'A'
    elif score >= 75:
        grade = 'B'
    elif score >= 60:
        grade = 'C'
    elif score >= 40:
        grade = 'D'
    else:
        grade = 'F'

    # ── Summary ──
    if grade in ('A+', 'A'):
        summary = 'Quantum-ready. No significant vulnerabilities.'
    elif grade == 'B':
        summary = 'Good posture. Minor improvements needed.'
    elif grade == 'C':
        summary = 'Moderate risk. Quantum-vulnerable crypto present.'
    elif grade == 'D':
        summary = 'High risk. Significant quantum vulnerabilities. Migration needed.'
    else:
        summary = 'Critical risk. Immediate PQC migration required.'

    # ── Recommendations ──
    recommendations = []
    if shor_count > 0:
        shor_algos = sorted(algos_found & _SHOR_VULNERABLE)
        recommendations.append(
            f'CRITICAL: Replace Shor-vulnerable algorithms ({", ".join(shor_algos)}) '
            f'with NIST PQC standards (ML-KEM, ML-DSA, SLH-DSA)')
    if overdue:
        recommendations.append(
            f'OVERDUE: {len(overdue)} algorithm(s) past CNSA 2.0 deadline — '
            f'immediate action required')
    if 'MD5' in algos_found:
        recommendations.append('Replace MD5 with SHA-256 (deterministic fix available)')
    if 'SHA-1' in algos_found:
        recommendations.append('Replace SHA-1 with SHA-256 (deterministic fix available)')
    if '3DES' in algos_found or 'RC4' in algos_found or 'Blowfish' in algos_found:
        recommendations.append('Replace deprecated ciphers with AES-256-GCM')
    if has_ecb:
        recommendations.append('Replace ECB mode with GCM for authenticated encryption')
    if not recommendations:
        recommendations.append('Monitor NIST PQC standard updates')

    return ReadinessGrade(
        grade=grade,
        score=round(score, 1),
        algorithm_score=round(algo_score, 1),
        key_management_score=round(key_score, 1),
        compliance_score=round(compliance_score, 1),
        summary=summary,
        details={
            'shor_vulnerable_count': str(shor_count),
            'grover_weakened_count': str(grover_count),
            'total_findings': str(total),
            'cnsa_overdue': str(len(overdue)),
            'cnsa_urgent': str(len(urgent)),
        },
        recommendations=recommendations,
    )


def format_readiness_report(grade: ReadinessGrade) -> str:
    """Format readiness grade as text report."""
    grade_bar = {
        'A+': '[##########] A+', 'A': '[######### ] A ',
        'B': '[#######   ] B ', 'C': '[#####     ] C ',
        'D': '[###       ] D ', 'F': '[#         ] F ',
    }
    bar = grade_bar.get(grade.grade, '[          ] ? ')

    lines = [
        "=" * 70,
        "  PQC READINESS GRADE",
        "=" * 70,
        "",
        f"  {bar}   {grade.score}/100",
        "",
        f"  {grade.summary}",
        "",
        f"  Algorithm Security:  {grade.algorithm_score:5.1f}/100  (40% weight)",
        f"  Key Management:      {grade.key_management_score:5.1f}/100  (30% weight)",
        f"  Compliance Posture:  {grade.compliance_score:5.1f}/100  (30% weight)",
        "",
        "  Recommendations:",
    ]
    for i, rec in enumerate(grade.recommendations, 1):
        lines.append(f"    {i}. {rec}")

    lines.extend(["", "=" * 70])
    return "\n".join(lines)


# ============================================================================
# QUALITY GATES
# ============================================================================

@dataclass
class GateCondition:
    """A single quality gate condition."""
    name: str
    description: str
    check: str             # 'no_critical', 'qars_below', 'grade_above', 'no_overdue', etc.
    threshold: str         # The value to compare against
    passed: bool = False
    actual_value: str = ''


@dataclass
class GateResult:
    """Result of evaluating a quality gate."""
    gate_name: str
    passed: bool
    conditions: List[GateCondition]

    @property
    def failed_conditions(self) -> List[GateCondition]:
        return [c for c in self.conditions if not c.passed]


# Built-in gate presets
BUILTIN_GATES = {
    'pqc-ready': {
        'description': 'Full PQC readiness — no quantum-vulnerable crypto',
        'conditions': [
            ('no_shor', 'No Shor-vulnerable algorithms', 'count_shor', '0'),
            ('grade_c', 'Readiness grade C or above', 'grade_above', 'D'),
            ('no_overdue', 'No overdue CNSA deadlines', 'cnsa_overdue', '0'),
        ],
    },
    'no-critical': {
        'description': 'No CRITICAL severity findings',
        'conditions': [
            ('no_crit', 'No CRITICAL findings', 'severity_count', 'CRITICAL:0'),
        ],
    },
    'cnsa-compliant': {
        'description': 'CNSA 2.0 compliance gate',
        'conditions': [
            ('no_overdue', 'No overdue CNSA deadlines', 'cnsa_overdue', '0'),
            ('no_non_compliant', 'No CNSA non-compliant algorithms', 'cnsa_violations', '0'),
        ],
    },
    'migration-safe': {
        'description': 'Safe for incremental migration — allow existing but no new critical',
        'conditions': [
            ('grade_f', 'Not grade F', 'grade_above', 'F'),
            ('qars_80', 'QARS score below 80', 'qars_below', '80'),
        ],
    },
}


def evaluate_gate(gate_name: str, result: ScanResult,
                  grade: Optional[ReadinessGrade] = None,
                  sensitivity: str = 'internal',
                  exposure: str = 'internet') -> GateResult:
    """Evaluate a quality gate against scan results."""
    if gate_name not in BUILTIN_GATES:
        return GateResult(gate_name, False, [
            GateCondition('unknown', f'Unknown gate: {gate_name}', 'error', '', False, 'N/A')
        ])

    gate_def = BUILTIN_GATES[gate_name]
    if grade is None:
        grade = compute_readiness_grade(result, sensitivity, exposure)

    result.compute_summary()
    qars = compute_qars(result, sensitivity, exposure)
    algos = set(f.algorithm for f in result.findings)
    deadlines = get_all_deadlines(list(algos))
    overdue = [d for d in deadlines if d.days_remaining < 0]
    shor_count = sum(1 for f in result.findings if f.algorithm in _SHOR_VULNERABLE)

    conditions = []
    for cond_name, desc, check, threshold in gate_def['conditions']:
        passed = False
        actual = ''

        if check == 'count_shor':
            actual = str(shor_count)
            passed = shor_count <= int(threshold)
        elif check == 'grade_above':
            grade_order = ['F', 'D', 'C', 'B', 'A', 'A+']
            actual = grade.grade
            passed = grade_order.index(grade.grade) > grade_order.index(threshold)
        elif check == 'cnsa_overdue':
            actual = str(len(overdue))
            passed = len(overdue) <= int(threshold)
        elif check == 'cnsa_violations':
            violations = sum(1 for a in algos if a in CNSA2_ALGORITHM_MAP and
                           CNSA2_ALGORITHM_MAP[a][0] == ComplianceStatus.NON_COMPLIANT)
            actual = str(violations)
            passed = violations <= int(threshold)
        elif check == 'severity_count':
            sev_name, max_count = threshold.split(':')
            count = result.summary.get(sev_name, 0)
            actual = str(count)
            passed = count <= int(max_count)
        elif check == 'qars_below':
            actual = str(qars.overall_score)
            passed = qars.overall_score < float(threshold)

        conditions.append(GateCondition(cond_name, desc, check, threshold, passed, actual))

    all_passed = all(c.passed for c in conditions)
    return GateResult(gate_name, all_passed, conditions)


def format_gate_result(result: GateResult) -> str:
    """Format quality gate result."""
    gate_def = BUILTIN_GATES.get(result.gate_name, {})
    desc = gate_def.get('description', result.gate_name)
    status = "PASSED" if result.passed else "FAILED"
    icon = "+" if result.passed else "X"

    lines = [
        f"  [{icon}] Quality Gate: {result.gate_name} — {status}",
        f"      {desc}",
    ]

    for c in result.conditions:
        c_icon = "+" if c.passed else "X"
        lines.append(f"      [{c_icon}] {c.description}: {c.actual_value} (threshold: {c.threshold})")

    if not result.passed:
        lines.append(f"      ACTION REQUIRED: {len(result.failed_conditions)} condition(s) failed")

    return "\n".join(lines)
