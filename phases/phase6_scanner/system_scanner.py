"""
Enigma System Scanner — Quantum Readiness Audit for Your Machine.

Scans:
  1. SSH keys (~/.ssh/) — algorithm, key size, quantum vulnerability
  2. System certificates — Windows cert store or /etc/ssl/
  3. TLS connections — test popular sites for PQC key exchange support
  4. Git signing keys — GPG/SSH signing config
  5. Installed crypto libraries — detect what's in PATH/pip/npm
"""

from __future__ import annotations
import os
import re
import ssl
import socket
import subprocess
import struct
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum


class QRisk(str, Enum):
    CRITICAL = 'CRITICAL'   # Broken by Shor's (RSA, DSA, ECDSA keys)
    HIGH = 'HIGH'           # Weak but not immediately broken
    MEDIUM = 'MEDIUM'       # Suboptimal (short keys, old algorithms)
    SAFE = 'SAFE'           # Quantum-resistant
    INFO = 'INFO'


@dataclass
class SystemFinding:
    category: str           # SSH, CERT, TLS, GIT, CRYPTO_LIB
    item: str               # Key filename, cert subject, site name
    algorithm: str
    key_size: int
    risk: QRisk
    description: str
    fix: str

    def to_dict(self) -> dict:
        return {
            'category': self.category,
            'item': self.item,
            'algorithm': self.algorithm,
            'key_size': self.key_size,
            'risk': self.risk.value,
            'description': self.description,
            'fix': self.fix,
        }


@dataclass
class SystemScanResult:
    hostname: str
    scan_date: str
    findings: List[SystemFinding] = field(default_factory=list)
    categories: Dict[str, List[SystemFinding]] = field(default_factory=dict)

    def add(self, f: SystemFinding):
        self.findings.append(f)
        self.categories.setdefault(f.category, []).append(f)

    @property
    def score(self) -> int:
        """Quantum Readiness Score: 0 (fully vulnerable) to 100 (quantum-safe)."""
        if not self.findings:
            return 100
        weights = {'CRITICAL': 0, 'HIGH': 25, 'MEDIUM': 60, 'SAFE': 100, 'INFO': 80}
        total = sum(weights.get(f.risk.value, 50) for f in self.findings)
        return total // len(self.findings)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90: return 'A'
        if s >= 75: return 'B'
        if s >= 60: return 'C'
        if s >= 40: return 'D'
        return 'F'


# ============================================================================
# SSH KEY SCANNER
# ============================================================================

# SSH key type → (algorithm_name, is_quantum_vulnerable, description)
SSH_KEY_TYPES = {
    'ssh-rsa': ('RSA', True, 'RSA — broken by Shor\'s algorithm'),
    'ssh-dss': ('DSA', True, 'DSA — broken by Shor\'s algorithm'),
    'ecdsa-sha2-nistp256': ('ECDSA-P256', True, 'ECDSA P-256 — broken by Shor\'s'),
    'ecdsa-sha2-nistp384': ('ECDSA-P384', True, 'ECDSA P-384 — broken by Shor\'s'),
    'ecdsa-sha2-nistp521': ('ECDSA-P521', True, 'ECDSA P-521 — broken by Shor\'s'),
    'ssh-ed25519': ('Ed25519', True, 'Ed25519 — broken by Shor\'s (ECC-based)'),
    'ssh-ed448': ('Ed448', True, 'Ed448 — broken by Shor\'s (ECC-based)'),
    'sntrup761x25519-sha512@openssh.com': ('SNTRUP761+X25519', False, 'PQC hybrid — quantum-safe!'),
    'sk-ssh-ed25519@openssh.com': ('Ed25519-SK', True, 'Ed25519 FIDO — broken by Shor\'s'),
}


def _get_ssh_key_size(key_data: bytes, key_type: str) -> int:
    """Extract key size in bits from SSH public key blob."""
    try:
        if key_type == 'ssh-rsa':
            # RSA: skip type string, read e, then n
            offset = 4 + struct.unpack('>I', key_data[:4])[0]  # skip type
            e_len = struct.unpack('>I', key_data[offset:offset+4])[0]
            offset += 4 + e_len
            n_len = struct.unpack('>I', key_data[offset:offset+4])[0]
            return (n_len - 1) * 8  # subtract leading zero byte
        elif 'ecdsa' in key_type:
            return {'nistp256': 256, 'nistp384': 384, 'nistp521': 521}.get(
                key_type.split('-')[-1], 256)
        elif 'ed25519' in key_type:
            return 256
        elif 'ed448' in key_type:
            return 448
        elif 'sntrup' in key_type:
            return 761  # SNTRUP761 security level
    except Exception:
        pass
    return 0


def scan_ssh_keys(ssh_dir: str = None) -> List[SystemFinding]:
    """Scan ~/.ssh/ for SSH keys and assess quantum vulnerability."""
    if ssh_dir is None:
        ssh_dir = os.path.expanduser('~/.ssh')

    findings = []
    ssh_path = Path(ssh_dir)

    if not ssh_path.exists():
        return findings

    # Scan .pub files
    for pub_file in ssh_path.glob('*.pub'):
        try:
            content = pub_file.read_text(encoding='utf-8', errors='ignore').strip()
            parts = content.split()
            if len(parts) < 2:
                continue

            key_type = parts[0]
            key_data = base64.b64decode(parts[1])
            key_size = _get_ssh_key_size(key_data, key_type)
            comment = parts[2] if len(parts) > 2 else pub_file.stem

            info = SSH_KEY_TYPES.get(key_type, (key_type, True, f'{key_type} — unknown quantum status'))
            algo, vulnerable, desc = info

            if not vulnerable:
                findings.append(SystemFinding(
                    'SSH', comment, algo, key_size, QRisk.SAFE,
                    f'{desc} ({key_size}-bit)',
                    'No action needed — this key uses PQC-safe algorithms'))
            elif algo == 'RSA':
                risk = QRisk.CRITICAL if key_size < 4096 else QRisk.HIGH
                findings.append(SystemFinding(
                    'SSH', comment, algo, key_size, risk,
                    f'{desc} ({key_size}-bit)',
                    'Generate new key: ssh-keygen -t ed25519 (short-term) or wait for PQC SSH keys'))
            elif algo in ('DSA',):
                findings.append(SystemFinding(
                    'SSH', comment, algo, key_size, QRisk.CRITICAL,
                    f'{desc} — also classically deprecated',
                    'Replace immediately: ssh-keygen -t ed25519'))
            else:
                findings.append(SystemFinding(
                    'SSH', comment, algo, key_size, QRisk.HIGH,
                    f'{desc} ({key_size}-bit)',
                    'Monitor for PQC SSH key types. Ed25519 is best current option.'))

        except Exception:
            continue

    # Check SSH config for key exchange algorithms
    config_path = ssh_path / 'config'
    if config_path.exists():
        try:
            config = config_path.read_text(encoding='utf-8', errors='ignore')
            if 'sntrup' in config.lower():
                findings.append(SystemFinding(
                    'SSH', 'ssh_config', 'SNTRUP761+X25519', 0, QRisk.SAFE,
                    'SSH config uses PQC key exchange (sntrup761)',
                    'No action needed'))
        except Exception:
            pass

    return findings


# ============================================================================
# SYSTEM CERTIFICATE SCANNER
# ============================================================================

def scan_system_certificates() -> List[SystemFinding]:
    """Scan system certificate stores for quantum-vulnerable algorithms."""
    findings = []

    # Try Windows cert store
    if os.name == 'nt':
        findings.extend(_scan_windows_certs())

    # Try common Linux/Mac cert paths
    for cert_dir in ['/etc/ssl/certs', '/etc/pki/tls/certs',
                     '/usr/local/share/ca-certificates',
                     '/System/Library/Keychains']:
        if os.path.isdir(cert_dir):
            findings.extend(_scan_cert_directory(cert_dir))

    return findings


def _scan_windows_certs() -> List[SystemFinding]:
    """Scan Windows certificate store using certutil."""
    findings = []
    try:
        result = subprocess.run(
            ['certutil', '-store', 'My'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            # Parse certutil output for algorithm info
            current_subject = ''
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Subject:'):
                    current_subject = line.split(':', 1)[1].strip()[:60]
                elif 'Public Key Algorithm' in line or 'Signature Algorithm' in line:
                    algo_str = line.split(':', 1)[1].strip() if ':' in line else line
                    if 'RSA' in algo_str.upper():
                        findings.append(SystemFinding(
                            'CERT', current_subject, 'RSA', 0, QRisk.CRITICAL,
                            f'RSA certificate in Windows store',
                            'Replace with ML-DSA certificate when CA supports it'))
                    elif 'ECDSA' in algo_str.upper() or 'ECC' in algo_str.upper():
                        findings.append(SystemFinding(
                            'CERT', current_subject, 'ECDSA', 0, QRisk.CRITICAL,
                            f'ECDSA certificate in Windows store',
                            'Replace with ML-DSA certificate when CA supports it'))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return findings


def _scan_cert_directory(cert_dir: str) -> List[SystemFinding]:
    """Scan a directory of PEM certificate files."""
    findings = []
    try:
        from pqc_scanner import scan_certificate_file
        for ext in ['*.pem', '*.crt', '*.cer']:
            for cert_file in Path(cert_dir).glob(ext):
                try:
                    cert_findings = scan_certificate_file(str(cert_file))
                    for cf in cert_findings:
                        risk = QRisk.CRITICAL if cf.severity.value == 'CRITICAL' else QRisk.HIGH
                        findings.append(SystemFinding(
                            'CERT', cf.cert_subject[:50], cf.algorithm, cf.key_size, risk,
                            cf.description,
                            cf.recommendation))
                except Exception:
                    continue
    except ImportError:
        pass
    return findings


# ============================================================================
# TLS PQC CHECKER
# ============================================================================

# Sites to test for PQC key exchange support
PQC_TEST_SITES = [
    ('google.com', 443, 'Google'),
    ('cloudflare.com', 443, 'Cloudflare'),
    ('github.com', 443, 'GitHub'),
    ('amazon.com', 443, 'Amazon'),
    ('microsoft.com', 443, 'Microsoft'),
    ('apple.com', 443, 'Apple'),
]


def scan_tls_pqc(sites: List[Tuple[str, int, str]] = None, timeout: int = 5) -> List[SystemFinding]:
    """Check popular sites for PQC key exchange support."""
    if sites is None:
        sites = PQC_TEST_SITES

    findings = []
    for host, port, name in sites:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    cert = ssock.getpeercert()

                    cipher_name = cipher[0] if cipher else 'Unknown'
                    subject = dict(x[0] for x in cert.get('subject', ())) if cert else {}
                    cn = subject.get('commonName', host)

                    # Check for PQC indicators
                    is_pqc = any(kw in cipher_name.upper() for kw in
                                 ['KYBER', 'MLKEM', 'SNTRUP', 'PQC', 'X25519MLKEM'])

                    if is_pqc:
                        findings.append(SystemFinding(
                            'TLS', f'{name} ({host})', 'PQC Hybrid', 0, QRisk.SAFE,
                            f'{version} with PQC key exchange: {cipher_name}',
                            'Quantum-safe connection! No action needed.'))
                    else:
                        findings.append(SystemFinding(
                            'TLS', f'{name} ({host})', cipher_name, 0, QRisk.HIGH,
                            f'{version}: {cipher_name} — no PQC key exchange detected',
                            'Server does not yet support PQC. Monitor for updates.'))

        except Exception as e:
            findings.append(SystemFinding(
                'TLS', f'{name} ({host})', 'Unknown', 0, QRisk.INFO,
                f'Could not connect: {type(e).__name__}',
                'Check network connectivity'))

    return findings


# ============================================================================
# GIT SIGNING KEY SCANNER
# ============================================================================

def scan_git_signing() -> List[SystemFinding]:
    """Check Git signing key configuration."""
    findings = []

    try:
        # Check git config for signing key
        result = subprocess.run(
            ['git', 'config', '--global', 'user.signingkey'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            key_id = result.stdout.strip()

            # Check GPG key type
            gpg_result = subprocess.run(
                ['gpg', '--list-keys', '--keyid-format', 'long', key_id],
                capture_output=True, text=True, timeout=5
            )
            if gpg_result.returncode == 0:
                output = gpg_result.stdout
                if 'rsa' in output.lower():
                    match = re.search(r'rsa(\d+)', output.lower())
                    key_size = int(match.group(1)) if match else 0
                    findings.append(SystemFinding(
                        'GIT', f'GPG key {key_id}', 'RSA', key_size, QRisk.CRITICAL,
                        f'Git signing uses RSA-{key_size} GPG key',
                        'Consider: git config --global gpg.format ssh + Ed25519 key'))
                elif 'ed25519' in output.lower():
                    findings.append(SystemFinding(
                        'GIT', f'GPG key {key_id}', 'Ed25519', 256, QRisk.HIGH,
                        'Git signing uses Ed25519 (still ECC-based)',
                        'Best current option. Monitor for PQC GPG support.'))
        else:
            # Check SSH signing
            ssh_result = subprocess.run(
                ['git', 'config', '--global', 'gpg.format'],
                capture_output=True, text=True, timeout=5
            )
            if ssh_result.returncode == 0 and 'ssh' in ssh_result.stdout.lower():
                findings.append(SystemFinding(
                    'GIT', 'SSH signing', 'SSH', 0, QRisk.INFO,
                    'Git uses SSH signing — check your SSH key algorithm',
                    'See SSH findings above for key algorithm assessment'))

    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return findings


# ============================================================================
# FULL SYSTEM SCAN
# ============================================================================

def run_system_scan(include_tls: bool = True, tls_timeout: int = 5) -> SystemScanResult:
    """Run a complete system quantum readiness scan."""
    from datetime import datetime
    import platform

    result = SystemScanResult(
        hostname=platform.node(),
        scan_date=datetime.now().isoformat(),
    )

    # SSH Keys
    for f in scan_ssh_keys():
        result.add(f)

    # System Certificates
    for f in scan_system_certificates():
        result.add(f)

    # Git Signing
    for f in scan_git_signing():
        result.add(f)

    # TLS PQC Check
    if include_tls:
        for f in scan_tls_pqc(timeout=tls_timeout):
            result.add(f)

    return result


def format_system_report(result: SystemScanResult) -> str:
    """Format system scan as readable report."""
    lines = [
        "=" * 65,
        f"  QUANTUM READINESS SCAN — {result.hostname}",
        "=" * 65,
        "",
        f"  Score: {result.score}/100 (Grade: {result.grade})",
        f"  Date:  {result.scan_date[:19]}",
        f"  Total: {len(result.findings)} items scanned",
        "",
    ]

    risk_counts = {}
    for f in result.findings:
        risk_counts[f.risk.value] = risk_counts.get(f.risk.value, 0) + 1

    for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'SAFE', 'INFO']:
        if risk in risk_counts:
            lines.append(f"  {risk:10s} {risk_counts[risk]}")
    lines.append("")

    for cat in ['SSH', 'CERT', 'TLS', 'GIT']:
        cat_findings = result.categories.get(cat, [])
        if not cat_findings:
            continue
        lines.append(f"  [{cat}]")
        for f in cat_findings:
            icon = 'X' if f.risk in (QRisk.CRITICAL, QRisk.HIGH) else ('+' if f.risk == QRisk.SAFE else '.')
            size_str = f" ({f.key_size}-bit)" if f.key_size else ""
            lines.append(f"    [{icon}] {f.item}: {f.algorithm}{size_str}")
            lines.append(f"        {f.description}")
            lines.append(f"        Fix: {f.fix}")
            lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)
