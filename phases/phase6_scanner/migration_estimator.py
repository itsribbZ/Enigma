"""
Enigma pqc-scanner v4.0: Migration Effort & Performance Impact Estimator.

Provides CISOs with:
  - Hours/cost estimates per finding for PQC migration
  - PQC performance impact data (key sizes, bandwidth, latency)
  - Migration complexity classification per algorithm
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional

from pqc_scanner import ScanResult, Finding


# ============================================================================
# MIGRATION EFFORT
# ============================================================================

@dataclass
class MigrationEstimate:
    """Migration effort estimate for a single algorithm."""
    algorithm: str
    complexity: str          # DROP_IN, API_CHANGE, ARCHITECTURAL
    hours_per_instance: float
    description: str
    pqc_target: str
    prerequisites: List[str]


# Per-algorithm migration complexity and effort
MIGRATION_EFFORT = {
    'MD5': MigrationEstimate('MD5', 'DROP_IN', 0.5,
        'Direct function rename (hashlib.md5 → hashlib.sha256)',
        'SHA-256', ['None — deterministic transform']),
    'SHA-1': MigrationEstimate('SHA-1', 'DROP_IN', 0.5,
        'Direct function rename',
        'SHA-256', ['None — deterministic transform']),
    '3DES': MigrationEstimate('3DES', 'API_CHANGE', 2.0,
        'Replace cipher + adjust key generation (24-byte → 32-byte keys)',
        'AES-256-GCM', ['Key rotation plan', 'Data re-encryption strategy']),
    'RC4': MigrationEstimate('RC4', 'API_CHANGE', 2.0,
        'Replace stream cipher with authenticated encryption',
        'AES-256-GCM or ChaCha20-Poly1305', ['Protocol update if custom protocol']),
    'Blowfish': MigrationEstimate('Blowfish', 'API_CHANGE', 2.0,
        'Replace cipher + adjust key handling',
        'AES-256-GCM', ['Key rotation plan']),
    'AES-128': MigrationEstimate('AES-128', 'DROP_IN', 1.0,
        'Increase key size from 128 to 256 bits',
        'AES-256', ['Key derivation update', 'Performance validation']),
    'RSA': MigrationEstimate('RSA', 'ARCHITECTURAL', 8.0,
        'Replace entire key exchange or signature scheme. Requires library change, '
        'key format migration, protocol updates, and interoperability testing.',
        'ML-KEM-768 (key exchange) / ML-DSA-65 (signatures)',
        ['PQC library integration (liboqs/oqs-provider)',
         'Key format migration plan',
         'Certificate reissuance (if PKI)',
         'Interoperability testing with partners',
         'Hybrid mode during transition']),
    'ECDSA': MigrationEstimate('ECDSA', 'ARCHITECTURAL', 6.0,
        'Replace signature scheme. Similar to RSA but smaller key changes.',
        'ML-DSA-65 (FIPS 204)',
        ['PQC library integration',
         'Signature format changes',
         'Certificate reissuance']),
    'ECDH': MigrationEstimate('ECDH', 'ARCHITECTURAL', 6.0,
        'Replace key exchange. Higher priority due to HNDL threat.',
        'ML-KEM-768 (FIPS 203)',
        ['PQC library integration',
         'Protocol negotiation update',
         'Hybrid key exchange during transition']),
    'Ed25519': MigrationEstimate('Ed25519', 'ARCHITECTURAL', 5.0,
        'Replace signature scheme.',
        'ML-DSA-44 (FIPS 204)',
        ['PQC library integration',
         'Key format migration']),
    'DH': MigrationEstimate('DH', 'ARCHITECTURAL', 8.0,
        'Replace key exchange. Often embedded in protocol implementations.',
        'ML-KEM-768 (FIPS 203)',
        ['Protocol redesign',
         'PQC library integration',
         'Interoperability testing']),
    'DSA': MigrationEstimate('DSA', 'ARCHITECTURAL', 6.0,
        'Replace signature scheme. DSA is already deprecated classically.',
        'ML-DSA-65 (FIPS 204)',
        ['PQC library integration',
         'Already should have been replaced with ECDSA']),
}

# Hourly rate assumptions for cost estimation
DEFAULT_HOURLY_RATE = 150  # Senior security engineer


def estimate_migration(result: ScanResult,
                       hourly_rate: float = DEFAULT_HOURLY_RATE) -> dict:
    """Estimate total migration effort and cost.

    Returns dict with per-algorithm and total estimates.
    """
    result.compute_summary()
    algo_counts: Dict[str, int] = {}
    for f in result.findings:
        algo_counts[f.algorithm] = algo_counts.get(f.algorithm, 0) + 1

    estimates = []
    total_hours = 0.0
    for algo, count in algo_counts.items():
        est = MIGRATION_EFFORT.get(algo)
        if est is None:
            est = MigrationEstimate(algo, 'API_CHANGE', 3.0,
                'Review and migrate', 'Consult NIST PQC standards', [])
        hours = est.hours_per_instance * count
        total_hours += hours
        estimates.append({
            'algorithm': algo,
            'instances': count,
            'complexity': est.complexity,
            'hours_per_instance': est.hours_per_instance,
            'total_hours': hours,
            'total_cost': hours * hourly_rate,
            'pqc_target': est.pqc_target,
            'description': est.description,
            'prerequisites': est.prerequisites,
        })

    # Add overhead: testing (30%), integration (20%), documentation (10%)
    testing_hours = total_hours * 0.30
    integration_hours = total_hours * 0.20
    documentation_hours = total_hours * 0.10
    grand_total = total_hours + testing_hours + integration_hours + documentation_hours

    return {
        'estimates': sorted(estimates, key=lambda e: -e['total_hours']),
        'subtotal_hours': round(total_hours, 1),
        'testing_hours': round(testing_hours, 1),
        'integration_hours': round(integration_hours, 1),
        'documentation_hours': round(documentation_hours, 1),
        'grand_total_hours': round(grand_total, 1),
        'grand_total_cost': round(grand_total * hourly_rate, 0),
        'hourly_rate': hourly_rate,
    }


# ============================================================================
# PQC PERFORMANCE IMPACT
# ============================================================================

# Classical vs PQC key/signature/ciphertext sizes
PQC_PERFORMANCE = {
    'Key Exchange': {
        'RSA-2048': {'public_key': 256, 'private_key': 1232, 'ciphertext': 256,
                     'operations_sec': 1000, 'standard': 'PKCS#1'},
        'ECDH P-256': {'public_key': 64, 'private_key': 32, 'shared_secret': 32,
                       'operations_sec': 5000, 'standard': 'NIST SP 800-56A'},
        'X25519': {'public_key': 32, 'private_key': 32, 'shared_secret': 32,
                   'operations_sec': 20000, 'standard': 'RFC 7748'},
        'ML-KEM-512': {'public_key': 800, 'private_key': 1632, 'ciphertext': 768,
                       'operations_sec': 50000, 'standard': 'FIPS 203'},
        'ML-KEM-768': {'public_key': 1184, 'private_key': 2400, 'ciphertext': 1088,
                       'operations_sec': 35000, 'standard': 'FIPS 203'},
        'ML-KEM-1024': {'public_key': 1568, 'private_key': 3168, 'ciphertext': 1568,
                        'operations_sec': 25000, 'standard': 'FIPS 203'},
    },
    'Digital Signatures': {
        'RSA-2048': {'public_key': 256, 'signature': 256, 'sign_sec': 1000,
                     'verify_sec': 30000, 'standard': 'PKCS#1'},
        'ECDSA P-256': {'public_key': 64, 'signature': 64, 'sign_sec': 10000,
                        'verify_sec': 5000, 'standard': 'FIPS 186-5'},
        'Ed25519': {'public_key': 32, 'signature': 64, 'sign_sec': 20000,
                    'verify_sec': 8000, 'standard': 'RFC 8032'},
        'ML-DSA-44': {'public_key': 1312, 'signature': 2420, 'sign_sec': 15000,
                      'verify_sec': 50000, 'standard': 'FIPS 204'},
        'ML-DSA-65': {'public_key': 1952, 'signature': 3293, 'sign_sec': 10000,
                      'verify_sec': 35000, 'standard': 'FIPS 204'},
        'ML-DSA-87': {'public_key': 2592, 'signature': 4595, 'sign_sec': 7000,
                      'verify_sec': 25000, 'standard': 'FIPS 204'},
        'SLH-DSA-128s': {'public_key': 32, 'signature': 7856, 'sign_sec': 50,
                         'verify_sec': 500, 'standard': 'FIPS 205'},
    },
}


def format_performance_table() -> str:
    """Format PQC performance impact as text."""
    lines = [
        "=" * 80,
        "  PQC PERFORMANCE IMPACT — Key/Signature Size Comparison",
        "=" * 80, "",
    ]

    for category, algos in PQC_PERFORMANCE.items():
        lines.append(f"  {category}:")
        lines.append(f"  {'Algorithm':<18} {'Pub Key':>9} {'Priv/Sig':>9} {'CT/SS':>9} {'Ops/sec':>9}  {'Standard'}")
        lines.append("  " + "-" * 72)
        for algo, data in algos.items():
            pk = f"{data.get('public_key', '-')}B"
            if 'signature' in data:
                sk = f"{data['signature']}B"
            elif 'private_key' in data:
                sk = f"{data['private_key']}B"
            else:
                sk = '-'
            ct = f"{data.get('ciphertext', data.get('shared_secret', '-'))}B"
            if isinstance(ct, str) and ct == '-B':
                ct = '-'
            ops = str(data.get('operations_sec', data.get('sign_sec', '-')))
            std = data.get('standard', '')
            quantum = ' [PQC]' if 'ML-' in algo or 'SLH-' in algo else ''
            lines.append(f"  {algo:<18} {pk:>9} {sk:>9} {ct:>9} {ops:>9}  {std}{quantum}")
        lines.append("")

    lines.extend([
        "  KEY TAKEAWAY:",
        "  ML-KEM-768 public keys are 18.5x larger than X25519 (1184B vs 32B)",
        "  ML-DSA-65 signatures are 51.5x larger than Ed25519 (3293B vs 64B)",
        "  But ML-KEM/ML-DSA are 2-5x FASTER in operations per second",
        "",
        "=" * 80,
    ])
    return "\n".join(lines)


def format_effort_report(estimation: dict) -> str:
    """Format migration effort estimate as text."""
    lines = [
        "=" * 80,
        "  MIGRATION EFFORT ESTIMATE",
        "=" * 80, "",
        f"  Hourly Rate: ${estimation['hourly_rate']}/hr (senior security engineer)",
        "",
        f"  {'Algorithm':<15} {'Count':>6} {'Complexity':<15} {'Hours':>7} {'Cost':>10}",
        "  " + "-" * 60,
    ]

    for e in estimation['estimates']:
        lines.append(
            f"  {e['algorithm']:<15} {e['instances']:>6} {e['complexity']:<15} "
            f"{e['total_hours']:>7.1f} ${e['total_cost']:>9,.0f}"
        )

    lines.extend([
        "  " + "-" * 60,
        f"  {'Code Changes':<15} {'':>6} {'':>15} {estimation['subtotal_hours']:>7.1f} "
        f"${estimation['subtotal_hours'] * estimation['hourly_rate']:>9,.0f}",
        f"  {'Testing (30%)':<15} {'':>6} {'':>15} {estimation['testing_hours']:>7.1f} "
        f"${estimation['testing_hours'] * estimation['hourly_rate']:>9,.0f}",
        f"  {'Integration (20%)':<17} {'':>4} {'':>15} {estimation['integration_hours']:>7.1f} "
        f"${estimation['integration_hours'] * estimation['hourly_rate']:>9,.0f}",
        f"  {'Documentation (10%)':<19} {'':>2} {'':>15} {estimation['documentation_hours']:>7.1f} "
        f"${estimation['documentation_hours'] * estimation['hourly_rate']:>9,.0f}",
        "  " + "=" * 60,
        f"  {'TOTAL':<15} {'':>6} {'':>15} {estimation['grand_total_hours']:>7.1f} "
        f"${estimation['grand_total_cost']:>9,.0f}",
        "", "=" * 80,
    ])
    return "\n".join(lines)
