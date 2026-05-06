"""
Enigma pqc-scanner v4.0: Dependency Tree Scanner.

Parses package manifests AND lock files, flags crypto libraries with
known quantum-vulnerable algorithm usage. Distinguishes direct vs
transitive dependencies.

v4.0 adds lock file support:
  - Pipfile.lock, poetry.lock (Python)
  - package-lock.json, yarn.lock (Node.js)
  - Cargo.lock (Rust)
  - go.sum (Go)
"""

from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from enum import Enum


class DepRisk(str, Enum):
    CRITICAL = 'CRITICAL'   # Package primarily provides quantum-vulnerable crypto
    HIGH = 'HIGH'           # Package uses quantum-vulnerable crypto internally
    MEDIUM = 'MEDIUM'       # Package has optional crypto that may be vulnerable
    INFO = 'INFO'           # Crypto-adjacent, audit recommended


@dataclass
class DepFinding:
    package: str
    version: Optional[str]
    ecosystem: str          # pip, npm, maven, go, cargo
    risk: DepRisk
    description: str
    recommendation: str
    manifest_file: str
    line: int = 0
    is_transitive: bool = False  # v4: True if from lock file (indirect dep)

    def to_dict(self) -> dict:
        return {
            'package': self.package,
            'version': self.version,
            'ecosystem': self.ecosystem,
            'risk': self.risk.value,
            'description': self.description,
            'recommendation': self.recommendation,
            'manifest_file': self.manifest_file,
            'line': self.line,
            'is_transitive': self.is_transitive,
        }


# ============================================================================
# KNOWN CRYPTO DEPENDENCY DATABASE
# ============================================================================

# Python packages
PYTHON_CRYPTO_DEPS = {
    'cryptography': (DepRisk.HIGH, 'Core crypto library — audit for RSA/ECC usage',
                     'Ensure PQC-safe algorithm configuration'),
    'pycryptodome': (DepRisk.HIGH, 'Crypto primitives — likely uses RSA/AES/DES',
                     'Audit all algorithm usage, migrate to PQC equivalents'),
    'pycryptodomex': (DepRisk.HIGH, 'Crypto primitives (standalone) — likely uses RSA/AES',
                      'Audit all algorithm usage'),
    'pyopenssl': (DepRisk.HIGH, 'TLS/SSL library — uses RSA/ECDSA certificates',
                  'Ensure TLS config supports PQC key exchange'),
    'paramiko': (DepRisk.HIGH, 'SSH library — uses RSA/ECDSA/DH key exchange',
                 'Upgrade to version with PQC support when available'),
    'pyca/bcrypt': (DepRisk.MEDIUM, 'Password hashing — not directly quantum-vulnerable',
                    'No PQC concern for password hashing'),
    'rsa': (DepRisk.CRITICAL, 'Pure RSA implementation — directly quantum-vulnerable',
            'Replace with ML-KEM (FIPS 203) or ML-DSA (FIPS 204)'),
    'ecdsa': (DepRisk.CRITICAL, 'Pure ECDSA implementation — broken by Shor',
              'Replace with ML-DSA (FIPS 204)'),
    'pynacl': (DepRisk.HIGH, 'NaCl/libsodium bindings — uses Curve25519/Ed25519',
               'Ed25519 is quantum-vulnerable; monitor for PQC updates'),
    'jwcrypto': (DepRisk.HIGH, 'JSON Web Crypto — uses RSA/ECDSA for JWT signing',
                 'Migrate JWT signing to PQC algorithms when supported'),
    'pyjwt': (DepRisk.HIGH, 'JWT library — typically uses RSA/ECDSA',
              'Audit JWT algorithm configuration'),
    'tls': (DepRisk.MEDIUM, 'TLS support — audit cipher suite configuration',
            'Ensure TLS 1.3 with PQC key exchange'),
    'certifi': (DepRisk.INFO, 'CA certificate bundle — contains RSA/ECDSA root certs',
                'Monitor for PQC CA certificate adoption'),
    'requests': (DepRisk.INFO, 'HTTP library — uses TLS via urllib3',
                 'Audit TLS configuration for PQC readiness'),
    'boto3': (DepRisk.MEDIUM, 'AWS SDK — uses SigV4 (HMAC-SHA256) + TLS',
              'AWS managing PQC transition; monitor SDK updates'),
    'azure-identity': (DepRisk.MEDIUM, 'Azure SDK — uses RSA/ECDSA for auth tokens',
                       'Monitor Azure PQC migration timeline'),
    'google-auth': (DepRisk.MEDIUM, 'Google SDK — uses RSA for service account auth',
                    'Monitor GCP PQC migration timeline'),
}

# Node.js packages
NPM_CRYPTO_DEPS = {
    'node-rsa': (DepRisk.CRITICAL, 'Pure RSA implementation — quantum-vulnerable',
                 'Replace with PQC key exchange'),
    'elliptic': (DepRisk.CRITICAL, 'ECC library — all curves broken by Shor',
                 'Replace with ML-DSA or hybrid signatures'),
    'node-forge': (DepRisk.HIGH, 'Crypto toolkit — RSA, AES, TLS implementations',
                   'Audit all algorithm usage'),
    'jsonwebtoken': (DepRisk.HIGH, 'JWT library — typically RSA/ECDSA signing',
                     'Audit JWT signing algorithm'),
    'jose': (DepRisk.HIGH, 'JOSE/JWT/JWE — uses RSA/ECDSA',
             'Migrate to PQC-compatible JOSE when available'),
    'bcrypt': (DepRisk.INFO, 'Password hashing — not quantum-vulnerable',
               'No PQC concern'),
    'crypto-js': (DepRisk.MEDIUM, 'Crypto utilities — check for weak algorithms',
                  'Audit for AES-128, DES, MD5 usage'),
    'ssh2': (DepRisk.HIGH, 'SSH library — uses RSA/ECDSA key exchange',
             'Monitor for PQC SSH support'),
    'tls': (DepRisk.MEDIUM, 'TLS — audit cipher configuration',
            'Ensure PQC cipher suites'),
}

# Maven/Gradle (Java) packages
MAVEN_CRYPTO_DEPS = {
    'org.bouncycastle': (DepRisk.HIGH, 'BouncyCastle — comprehensive crypto, likely uses RSA/ECDSA',
                         'BouncyCastle has PQC support — enable it'),
    'com.google.crypto.tink': (DepRisk.MEDIUM, 'Google Tink — crypto abstraction layer',
                               'Tink manages algorithm selection; check config'),
    'javax.crypto': (DepRisk.HIGH, 'JCE — standard Java crypto API',
                     'Audit all Cipher/KeyPairGenerator usage'),
    'io.jsonwebtoken': (DepRisk.HIGH, 'JJWT — JWT signing with RSA/ECDSA',
                        'Audit signing algorithm configuration'),
    'org.apache.shiro': (DepRisk.MEDIUM, 'Shiro security — uses crypto internally',
                         'Audit crypto configuration'),
    'com.nimbusds': (DepRisk.HIGH, 'Nimbus JOSE+JWT — RSA/EC for JWS/JWE',
                     'Migrate to PQC algorithms'),
}

# Go modules
GO_CRYPTO_DEPS = {
    'crypto/rsa': (DepRisk.CRITICAL, 'Go stdlib RSA — quantum-vulnerable',
                   'Replace with PQC'),
    'crypto/ecdsa': (DepRisk.CRITICAL, 'Go stdlib ECDSA — quantum-vulnerable',
                     'Replace with PQC signatures'),
    'crypto/elliptic': (DepRisk.CRITICAL, 'Go stdlib ECC — quantum-vulnerable',
                        'Replace with PQC key exchange'),
    'github.com/cloudflare/circl': (DepRisk.INFO, 'Cloudflare CIRCL — includes PQC implementations',
                                     'Good: PQC-ready library'),
    'golang.org/x/crypto': (DepRisk.HIGH, 'Extended crypto — may use RSA/ECDSA/Ed25519',
                             'Audit usage for quantum-vulnerable algorithms'),
}

# Rust crates
RUST_CRYPTO_DEPS = {
    'rsa': (DepRisk.CRITICAL, 'RSA crate — quantum-vulnerable',
            'Replace with PQC crate (pqcrypto)'),
    'p256': (DepRisk.CRITICAL, 'NIST P-256 ECC — quantum-vulnerable',
             'Replace with PQC signatures'),
    'k256': (DepRisk.CRITICAL, 'secp256k1 ECC — quantum-vulnerable',
             'Replace with PQC'),
    'ed25519-dalek': (DepRisk.HIGH, 'Ed25519 signatures — quantum-vulnerable',
                      'Replace with ML-DSA when available'),
    'ring': (DepRisk.HIGH, 'Crypto primitives — uses RSA/ECDSA/AES',
             'Audit algorithm configuration'),
    'rustls': (DepRisk.MEDIUM, 'TLS library — audit cipher suites',
               'Monitor for PQC TLS support'),
    'pqcrypto': (DepRisk.INFO, 'PQC implementations — quantum-safe!',
                 'Good: using PQC-ready crate'),
}


# ============================================================================
# MANIFEST PARSERS
# ============================================================================

def _parse_requirements_txt(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse requirements.txt → [(package, version, line_num)]."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            match = re.match(r'^([a-zA-Z0-9_.-]+)\s*(?:[><=!~]+\s*(.+))?', line)
            if match:
                pkg = match.group(1).lower().replace('-', '_').replace('.', '_')
                ver = match.group(2).strip() if match.group(2) else None
                results.append((pkg, ver, i))
    return results


def _parse_pyproject_toml(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse pyproject.toml dependencies."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        in_deps = False
        for i, line in enumerate(f, 1):
            if '[project.dependencies]' in line or '[tool.poetry.dependencies]' in line:
                in_deps = True
                continue
            if in_deps and line.strip().startswith('['):
                in_deps = False
            if in_deps:
                match = re.match(r'^"?([a-zA-Z0-9_.-]+)"?\s*', line.strip())
                if match:
                    pkg = match.group(1).lower().replace('-', '_')
                    results.append((pkg, None, i))
    return results


def _parse_package_json(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse package.json dependencies."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
        deps = data.get(dep_type, {})
        for pkg, ver in deps.items():
            results.append((pkg, ver, 0))
    return results


def _parse_pom_xml(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse pom.xml for Maven dependencies (simple regex, no XML parser needed)."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    # Find <groupId>...</groupId> <artifactId>...</artifactId>
    pattern = r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?'
    for match in re.finditer(pattern, content):
        group_id = match.group(1)
        artifact_id = match.group(2)
        version = match.group(3)
        results.append((f"{group_id}:{artifact_id}", version, 0))
    return results


def _parse_go_mod(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse go.mod for Go module dependencies."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line.startswith('require') or line.startswith(')') or line.startswith('module'):
                continue
            match = re.match(r'^([a-zA-Z0-9./_-]+)\s+v?(\S+)', line)
            if match:
                results.append((match.group(1), match.group(2), i))
    return results


def _parse_cargo_toml(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse Cargo.toml for Rust dependencies."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        in_deps = False
        for i, line in enumerate(f, 1):
            if '[dependencies]' in line or '[dev-dependencies]' in line:
                in_deps = True
                continue
            if in_deps and line.strip().startswith('[') and 'dependencies' not in line:
                in_deps = False
            if in_deps:
                match = re.match(r'^([a-zA-Z0-9_-]+)\s*=', line.strip())
                if match:
                    results.append((match.group(1), None, i))
    return results


# ============================================================================
# LOCK FILE PARSERS (v4.0 — transitive dependency detection)
# ============================================================================

def _parse_pipfile_lock(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse Pipfile.lock → [(package, version, 0)]."""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for section in ('default', 'develop'):
            for pkg, info in data.get(section, {}).items():
                ver = info.get('version', '').lstrip('=')
                results.append((pkg.lower().replace('-', '_'), ver or None, 0))
    except (json.JSONDecodeError, KeyError):
        pass
    return results


def _parse_poetry_lock(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse poetry.lock (TOML-like) → [(package, version, line)]."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        current_pkg = None
        current_ver = None
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line == '[[package]]':
                if current_pkg:
                    results.append((current_pkg, current_ver, i))
                current_pkg = None
                current_ver = None
            elif line.startswith('name = '):
                current_pkg = line.split('=', 1)[1].strip().strip('"').lower().replace('-', '_')
            elif line.startswith('version = '):
                current_ver = line.split('=', 1)[1].strip().strip('"')
        if current_pkg:
            results.append((current_pkg, current_ver, 0))
    return results


def _parse_package_lock_json(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse package-lock.json (v2/v3) → [(package, version, 0)]."""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # v2/v3 format: packages dict with node_modules/ paths
        packages = data.get('packages', {})
        for path, info in packages.items():
            if path == '':
                continue  # Root project entry
            pkg_name = path.split('node_modules/')[-1]
            ver = info.get('version')
            results.append((pkg_name, ver, 0))
        # v1 format fallback: dependencies dict
        if not packages:
            deps = data.get('dependencies', {})
            for pkg, info in deps.items():
                ver = info.get('version') if isinstance(info, dict) else None
                results.append((pkg, ver, 0))
    except (json.JSONDecodeError, KeyError):
        pass
    return results


def _parse_yarn_lock(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse yarn.lock → [(package, version, line)]."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        current_pkg = None
        for i, line in enumerate(f, 1):
            if not line.startswith(' ') and not line.startswith('#') and '@' in line or line.strip().endswith(':'):
                # Package header line like: "package-name@^1.0.0:"
                name = line.split('@')[0].strip().strip('"')
                if name:
                    current_pkg = name
            elif line.strip().startswith('version '):
                ver = line.split('"')[1] if '"' in line else line.split()[-1]
                if current_pkg:
                    results.append((current_pkg, ver, i))
                    current_pkg = None
    return results


def _parse_cargo_lock(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse Cargo.lock → [(package, version, line)]."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        current_pkg = None
        current_ver = None
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line == '[[package]]':
                if current_pkg:
                    results.append((current_pkg, current_ver, i))
                current_pkg = None
                current_ver = None
            elif line.startswith('name = '):
                current_pkg = line.split('=', 1)[1].strip().strip('"')
            elif line.startswith('version = '):
                current_ver = line.split('=', 1)[1].strip().strip('"')
        if current_pkg:
            results.append((current_pkg, current_ver, 0))
    return results


def _parse_go_sum(filepath: str) -> List[Tuple[str, Optional[str], int]]:
    """Parse go.sum → [(module, version, line)]. Deduplicated."""
    results = []
    seen = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f, 1):
            parts = line.strip().split()
            if len(parts) >= 2:
                module = parts[0]
                version = parts[1].split('/')[0].lstrip('v')
                key = (module, version)
                if key not in seen:
                    seen.add(key)
                    results.append((module, version, i))
    return results


# ============================================================================
# SCANNER ENGINE
# ============================================================================

# Manifest file → (parser_function, ecosystem, dep_database)
MANIFEST_MAP = {
    'requirements.txt': (_parse_requirements_txt, 'pip', PYTHON_CRYPTO_DEPS),
    'requirements-dev.txt': (_parse_requirements_txt, 'pip', PYTHON_CRYPTO_DEPS),
    'requirements_dev.txt': (_parse_requirements_txt, 'pip', PYTHON_CRYPTO_DEPS),
    'pyproject.toml': (_parse_pyproject_toml, 'pip', PYTHON_CRYPTO_DEPS),
    'Pipfile': (_parse_requirements_txt, 'pip', PYTHON_CRYPTO_DEPS),
    'package.json': (_parse_package_json, 'npm', NPM_CRYPTO_DEPS),
    'pom.xml': (_parse_pom_xml, 'maven', MAVEN_CRYPTO_DEPS),
    'go.mod': (_parse_go_mod, 'go', GO_CRYPTO_DEPS),
    'Cargo.toml': (_parse_cargo_toml, 'cargo', RUST_CRYPTO_DEPS),
}

# Lock files → (parser_function, ecosystem, dep_database)
LOCK_FILE_MAP = {
    'Pipfile.lock': (_parse_pipfile_lock, 'pip', PYTHON_CRYPTO_DEPS),
    'poetry.lock': (_parse_poetry_lock, 'pip', PYTHON_CRYPTO_DEPS),
    'package-lock.json': (_parse_package_lock_json, 'npm', NPM_CRYPTO_DEPS),
    'yarn.lock': (_parse_yarn_lock, 'npm', NPM_CRYPTO_DEPS),
    'Cargo.lock': (_parse_cargo_lock, 'cargo', RUST_CRYPTO_DEPS),
    'go.sum': (_parse_go_sum, 'go', GO_CRYPTO_DEPS),
}


def scan_dependencies(path: str) -> List[DepFinding]:
    """Scan a directory for dependency manifests and lock files.

    v4: Also scans lock files for transitive dependencies.
    """
    findings = []
    target = Path(path)

    if target.is_file():
        name = target.name
        if name in MANIFEST_MAP:
            parser, eco, db = MANIFEST_MAP[name]
            findings.extend(_scan_manifest(str(target), parser, eco, db))
        elif name in LOCK_FILE_MAP:
            parser, eco, db = LOCK_FILE_MAP[name]
            findings.extend(_scan_manifest(str(target), parser, eco, db,
                                           is_transitive=True))
        return findings

    # Walk directory for manifests and lock files
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            filepath = os.path.join(dirpath, fname)
            if fname in MANIFEST_MAP:
                parser, eco, db = MANIFEST_MAP[fname]
                findings.extend(_scan_manifest(filepath, parser, eco, db))
            elif fname in LOCK_FILE_MAP:
                parser, eco, db = LOCK_FILE_MAP[fname]
                findings.extend(_scan_manifest(filepath, parser, eco, db,
                                               is_transitive=True))

    return findings


def _scan_manifest(filepath: str, parser, ecosystem: str, db: dict,
                   is_transitive: bool = False) -> List[DepFinding]:
    """Scan a single manifest/lock file against the crypto dependency database."""
    findings = []
    try:
        deps = parser(filepath)
    except Exception:
        return findings

    for pkg_name, version, line in deps:
        normalized = pkg_name.lower().replace('-', '_').replace('.', '_')

        for db_key, (risk, desc, rec) in db.items():
            db_normalized = db_key.lower().replace('-', '_').replace('.', '_')
            if normalized == db_normalized or normalized.endswith('_' + db_normalized) or normalized.endswith('-' + db_normalized):
                ver_str = f" ({version})" if version else ""
                trans_tag = " [transitive]" if is_transitive else ""
                findings.append(DepFinding(
                    package=pkg_name,
                    version=version,
                    ecosystem=ecosystem,
                    risk=risk,
                    description=f"{desc}{ver_str}{trans_tag}",
                    recommendation=rec,
                    manifest_file=filepath,
                    line=line,
                    is_transitive=is_transitive,
                ))

    return findings


def format_dep_report(findings: List[DepFinding]) -> str:
    """Format dependency findings as text report."""
    if not findings:
        return "No crypto dependencies detected in manifest files."

    lines = [
        "=" * 65,
        "  DEPENDENCY SCAN — Quantum-Vulnerable Crypto Packages",
        "=" * 65,
        "",
        f"  Total findings: {len(findings)}",
        "",
    ]

    for risk in [DepRisk.CRITICAL, DepRisk.HIGH, DepRisk.MEDIUM, DepRisk.INFO]:
        risk_findings = [f for f in findings if f.risk == risk]
        if not risk_findings:
            continue
        lines.append(f"  [{risk.value}]")
        for f in risk_findings:
            lines.append(f"    {f.package} ({f.ecosystem})")
            lines.append(f"      {f.description}")
            lines.append(f"      Fix: {f.recommendation}")
            lines.append(f"      File: {os.path.basename(f.manifest_file)}:{f.line}")
            lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)
