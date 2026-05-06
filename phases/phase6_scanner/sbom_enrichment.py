"""
Enigma pqc-scanner v4.0: SBOM Enrichment with PQC Risk Annotations.

Consumes an existing CycloneDX SBOM (JSON) and enriches it with:
  - PQC risk annotations per component (quantum-safe status)
  - Crypto algorithm properties (from Enigma's detection)
  - Migration urgency based on CNSA 2.0 deadlines
  - QARS risk scores per component

Usage: pqc-scanner scan <path> --enrich-sbom <input.json> --output enriched.json
"""

from __future__ import annotations
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pqc_scanner import (
    PQCScanner, ScanResult, Finding, Severity, Category, REMEDIATION, __version__,
)


# ============================================================================
# CRYPTO PACKAGE DATABASE (maps package names to crypto algorithms)
# ============================================================================

_PACKAGE_CRYPTO_MAP = {
    # Python
    'cryptography': ['RSA', 'ECDSA', 'ECDH', 'Ed25519', 'AES', 'DH', 'DSA'],
    'pycryptodome': ['RSA', 'ECDSA', 'AES', 'DES', '3DES', 'Blowfish', 'RC4'],
    'pycryptodomex': ['RSA', 'ECDSA', 'AES', 'DES', '3DES', 'Blowfish', 'RC4'],
    'pyopenssl': ['RSA', 'ECDSA', 'DH'],
    'paramiko': ['RSA', 'ECDSA', 'Ed25519'],
    'pynacl': ['Ed25519', 'X25519'],
    'pyjwt': ['RSA', 'ECDSA'],
    'python-jose': ['RSA', 'ECDSA'],
    'rsa': ['RSA'],
    'ecdsa': ['ECDSA'],
    # JavaScript/Node
    'node-rsa': ['RSA'],
    'node-forge': ['RSA', 'ECDSA', 'AES', '3DES', 'DES'],
    'jsonwebtoken': ['RSA', 'ECDSA'],
    'jose': ['RSA', 'ECDSA'],
    'elliptic': ['ECDSA', 'ECDH'],
    'tweetnacl': ['Ed25519', 'X25519'],
    # Java
    'org.bouncycastle': ['RSA', 'ECDSA', 'DH', 'DSA', 'AES', '3DES'],
    'com.auth0:java-jwt': ['RSA', 'ECDSA'],
    # Go
    'golang.org/x/crypto': ['Ed25519', 'X25519', 'ECDSA'],
    # Rust
    'rsa': ['RSA'],
    'p256': ['ECDSA'],
    'ed25519-dalek': ['Ed25519'],
    'x25519-dalek': ['X25519'],
}

# Algorithms that are quantum-safe (don't flag these)
_QUANTUM_SAFE_ALGOS = {'AES-256', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-3',
                       'ML-KEM', 'ML-DSA', 'SLH-DSA', 'XMSS', 'LMS'}

# Algorithm to quantum-safe status
_ALGO_QUANTUM_STATUS = {
    'RSA': 'vulnerable',      # Shor's algorithm
    'ECDSA': 'vulnerable',    # Shor's on ECDLP
    'ECDH': 'vulnerable',     # Shor's on ECDLP
    'Ed25519': 'vulnerable',  # Shor's on ECDLP
    'Ed448': 'vulnerable',
    'X25519': 'vulnerable',
    'X448': 'vulnerable',
    'DH': 'vulnerable',       # Shor's on DLP
    'DSA': 'vulnerable',      # Shor's on DLP
    'AES-128': 'weakened',    # Grover halves to 64-bit
    'AES-256': 'safe',        # Grover halves to 128-bit
    'SHA-1': 'weakened',      # Classically broken + Grover
    'SHA-256': 'safe',        # Grover halves preimage to 128-bit
    'MD5': 'broken',          # Classically broken
    '3DES': 'broken',         # Short block, deprecated
    'RC4': 'broken',          # Classically broken
    'Blowfish': 'weakened',   # Short block
    'DES': 'broken',          # 56-bit key
}


# ============================================================================
# SBOM ENRICHMENT ENGINE
# ============================================================================

def enrich_sbom(sbom_path: str,
                scan_path: Optional[str] = None,
                output_path: Optional[str] = None) -> dict:
    """Enrich an existing CycloneDX SBOM with PQC risk annotations.

    Args:
        sbom_path: Path to input CycloneDX SBOM (JSON format)
        scan_path: Optional path to scan for source-level crypto findings
        output_path: Optional path to write enriched SBOM

    Returns:
        Enriched SBOM as a dict
    """
    # Load the input SBOM
    with open(sbom_path, 'r', encoding='utf-8') as f:
        sbom = json.load(f)

    # Validate it's a CycloneDX document.
    # CycloneDX documents have bomFormat='CycloneDX' and a specVersion string.
    bom_format = str(sbom.get('bomFormat', '')).lower()
    spec_version = str(sbom.get('specVersion') or '')
    has_components = 'components' in sbom
    if bom_format != 'cyclonedx' and not has_components:
        raise ValueError(f'Input does not appear to be a CycloneDX SBOM: {sbom_path}')
    # specVersion should be 1.0-1.7 — warn if unknown/unsupported.
    _SUPPORTED_SPEC_VERSIONS = {'1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7'}
    if spec_version and spec_version not in _SUPPORTED_SPEC_VERSIONS:
        import sys as _sys
        print(f'Warning: unsupported CycloneDX specVersion: {spec_version!r}', file=_sys.stderr)

    # Run source scan if path provided
    scan_findings: Dict[str, List[Finding]] = {}
    if scan_path and os.path.exists(scan_path):
        scanner = PQCScanner()
        result = scanner.scan(scan_path)
        for finding in result.findings:
            algo = finding.algorithm
            scan_findings.setdefault(algo, []).append(finding)

    # Enrich each component
    components = sbom.get('components', [])
    enriched_count = 0
    for component in components:
        name = component.get('name', '').lower().replace('-', '_').replace('.', '_')
        purl = component.get('purl', '')

        # Check against crypto package database
        crypto_algos = set()
        for pkg_pattern, algos in _PACKAGE_CRYPTO_MAP.items():
            pkg_normalized = pkg_pattern.lower().replace('-', '_').replace('.', '_')
            if name == pkg_normalized or name.endswith('_' + pkg_normalized):
                crypto_algos.update(algos)

        # Also check if source scan found crypto in this component
        for algo, findings in scan_findings.items():
            for f in findings:
                if name in f.file.lower().replace('-', '_').replace('.', '_'):
                    crypto_algos.add(algo)

        if not crypto_algos:
            continue

        # Add PQC risk properties
        enriched_count += 1
        properties = component.setdefault('properties', [])

        # Add quantum safety status
        vulnerable = [a for a in crypto_algos if _ALGO_QUANTUM_STATUS.get(a, 'unknown') == 'vulnerable']
        weakened = [a for a in crypto_algos if _ALGO_QUANTUM_STATUS.get(a, 'unknown') == 'weakened']
        broken = [a for a in crypto_algos if _ALGO_QUANTUM_STATUS.get(a, 'unknown') == 'broken']
        safe = [a for a in crypto_algos if _ALGO_QUANTUM_STATUS.get(a, 'unknown') == 'safe']

        if vulnerable:
            status = 'quantum-vulnerable'
        elif broken:
            status = 'classically-broken'
        elif weakened:
            status = 'quantum-weakened'
        else:
            status = 'quantum-safe'

        _set_property(properties, 'enigma:pqc:status', status)
        _set_property(properties, 'enigma:pqc:algorithms', ','.join(sorted(crypto_algos)))

        if vulnerable:
            _set_property(properties, 'enigma:pqc:vulnerable_algorithms', ','.join(sorted(vulnerable)))
            replacements = []
            for algo in vulnerable:
                rec, repl = REMEDIATION.get(algo, ('Review', 'Consult NIST'))
                replacements.append(f'{algo}->{repl}')
            _set_property(properties, 'enigma:pqc:replacements', '; '.join(replacements))

        if broken:
            _set_property(properties, 'enigma:pqc:broken_algorithms', ','.join(sorted(broken)))

        # Risk level
        if vulnerable or broken:
            risk = 'critical'
        elif weakened:
            risk = 'medium'
        else:
            risk = 'low'
        _set_property(properties, 'enigma:pqc:risk_level', risk)

    # Add Enigma tool metadata
    metadata = sbom.setdefault('metadata', {})
    tools = metadata.get('tools', [])
    # Handle both CycloneDX 1.4 (list of dicts) and 1.5+ (object with components)
    if isinstance(tools, list):
        tools.append({
            'vendor': 'Enigma',
            'name': 'pqc-scanner',
            'version': __version__,
        })
        metadata['tools'] = tools
    elif isinstance(tools, dict):
        tool_components = tools.setdefault('components', [])
        tool_components.append({
            'type': 'application',
            'name': 'enigma-pqc-scanner',
            'version': __version__,
            'publisher': 'Enigma',
        })

    # Add enrichment timestamp
    _set_property(
        metadata.setdefault('properties', []),
        'enigma:enrichment_date', datetime.now().isoformat()
    )
    _set_property(
        metadata.setdefault('properties', []),
        'enigma:components_enriched', str(enriched_count)
    )

    # Write output (atomic write to prevent corruption on interrupted process)
    if output_path:
        import tempfile as _tempfile
        out_dir = os.path.dirname(os.path.abspath(output_path)) or '.'
        fd, tmp = _tempfile.mkstemp(dir=out_dir, suffix='.sbom-tmp')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(sbom, f, indent=2)
            os.replace(tmp, output_path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    return sbom


def _set_property(properties: list, name: str, value: str):
    """Set a property in a CycloneDX properties list, updating if exists."""
    for prop in properties:
        if prop.get('name') == name:
            prop['value'] = value
            return
    properties.append({'name': name, 'value': value})


# ============================================================================
# REPORTING
# ============================================================================

def format_enrichment_report(sbom: dict) -> str:
    """Format a summary of SBOM enrichment results."""
    components = sbom.get('components', [])
    total = len(components)

    vulnerable = []
    broken = []
    weakened = []
    safe_count = 0

    for comp in components:
        props = {p['name']: p['value'] for p in comp.get('properties', []) if 'enigma:pqc' in p.get('name', '')}
        status = props.get('enigma:pqc:status', '')
        name = comp.get('name', 'unknown')
        version = comp.get('version', '')
        label = f'{name}@{version}' if version else name

        if status == 'quantum-vulnerable':
            algos = props.get('enigma:pqc:vulnerable_algorithms', '')
            vulnerable.append((label, algos))
        elif status == 'classically-broken':
            algos = props.get('enigma:pqc:broken_algorithms', '')
            broken.append((label, algos))
        elif status == 'quantum-weakened':
            weakened.append(label)
        elif status == 'quantum-safe':
            safe_count += 1

    enriched = len(vulnerable) + len(broken) + len(weakened) + safe_count

    lines = [
        "=" * 70,
        "  SBOM ENRICHMENT REPORT — PQC Risk Annotations",
        "=" * 70,
        "",
        f"  Total components:      {total}",
        f"  Enriched with crypto:  {enriched}",
        f"  Quantum-vulnerable:    {len(vulnerable)}",
        f"  Classically broken:    {len(broken)}",
        f"  Quantum-weakened:      {len(weakened)}",
        f"  Quantum-safe:          {safe_count}",
        "",
    ]

    if vulnerable:
        lines.append("  QUANTUM-VULNERABLE (Shor's algorithm — replace immediately):")
        lines.append("  " + "-" * 60)
        for label, algos in vulnerable:
            lines.append(f"    {label} — {algos}")
        lines.append("")

    if broken:
        lines.append("  CLASSICALLY BROKEN (already exploitable):")
        lines.append("  " + "-" * 60)
        for label, algos in broken:
            lines.append(f"    {label} — {algos}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
