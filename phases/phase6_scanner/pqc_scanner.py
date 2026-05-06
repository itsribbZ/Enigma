"""
Enigma pqc-scanner v4.0 — Post-Quantum Cryptography Migration Scanner.

THE MONEY DELIVERABLE. Scans codebases, certificates, and configs for
quantum-vulnerable cryptography. Outputs risk reports with remediation.

v4.0: Comment/string stripping, .pqcignore suppression, baseline diffing,
      CycloneDX CBOM output, unified scoring, PyPI packaging.

Usage:
    pqc-scanner scan <path>
    pqc-scanner scan <path> --format sarif
    pqc-scanner scan <path> --format cbom --output cbom.json
    pqc-scanner scan <path> --baseline previous.json
"""

from __future__ import annotations
import ast
import fnmatch
import json
import math
import os
import re
import sys
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime

__version__ = '4.0.0'


# ============================================================================
# DATA MODEL
# ============================================================================

class Severity(str, Enum):
    CRITICAL = 'CRITICAL'  # Shor-vulnerable key exchange (HNDL risk NOW)
    HIGH = 'HIGH'          # Shor-vulnerable signatures
    MEDIUM = 'MEDIUM'      # Grover-weakened symmetric (AES-128)
    LOW = 'LOW'            # Suboptimal but not broken
    INFO = 'INFO'          # Informational (quantum-safe already)


class Category(str, Enum):
    KEY_EXCHANGE = 'KEY_EXCHANGE'
    SIGNATURE = 'SIGNATURE'
    SYMMETRIC = 'SYMMETRIC'
    HASH = 'HASH'
    CERTIFICATE = 'CERTIFICATE'
    PROTOCOL = 'PROTOCOL'
    DEPENDENCY = 'DEPENDENCY'


@dataclass
class Finding:
    id: str
    severity: Severity
    category: Category
    algorithm: str
    file: str
    line: int
    code_snippet: str
    description: str
    recommendation: str
    pqc_replacement: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d['severity'] = self.severity.value
        d['category'] = self.category.value
        return d


@dataclass
class ScanResult:
    scan_path: str
    scan_date: str
    files_scanned: int
    findings: List[Finding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def compute_summary(self) -> None:
        self.summary = {s.value: 0 for s in Severity}
        for f in self.findings:
            self.summary[f.severity.value] += 1

    def to_dict(self) -> dict:
        self.compute_summary()
        return {
            'scan_path': self.scan_path,
            'scan_date': self.scan_date,
            'files_scanned': self.files_scanned,
            'total_findings': len(self.findings),
            'summary': self.summary,
            'findings': [f.to_dict() for f in self.findings],
        }

    @property
    def risk_score(self) -> int:
        """0-100 risk score. Higher = more vulnerable. Logarithmic scaling."""
        weights = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 3, 'LOW': 1, 'INFO': 0}
        self.compute_summary()
        raw = sum(self.summary.get(k, 0) * v for k, v in weights.items())
        if raw == 0:
            return 0
        return min(100, int(20 * math.log(raw + 1)))


def _safe_relpath(filepath: str, scan_root: str) -> str:
    """Compute relative path safely.

    os.path.relpath raises ValueError on Windows when paths are on different drives.
    This wrapper falls back to the absolute path on any failure.
    """
    try:
        return os.path.relpath(filepath, scan_root)
    except (ValueError, TypeError):
        return filepath


_RULES_SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv',
                    'venv', 'env', '.tox', 'dist', 'build', '.eggs'}


def _walk_source_files(root: str, extensions: tuple, max_files: int = 10000):
    """Yield source files under root, respecting skip dirs and a max file cap.

    Replaces naked rglob traversal in the CLI's rules-engine passes to avoid
    re-walking node_modules/.git/build on large monorepos.
    """
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _RULES_SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(extensions):
                if count >= max_files:
                    return
                count += 1
                yield Path(dirpath) / fn


# ============================================================================
# COMMENT & STRING STRIPPING (False Positive Elimination)
# ============================================================================

# Language-aware single-line comment patterns
_COMMENT_PATTERNS = {
    'Python': re.compile(r'#.*$'),
    'Java': re.compile(r'//.*$'),
    'Go': re.compile(r'//.*$'),
    'JavaScript': re.compile(r'//.*$'),
    'C/C++': re.compile(r'//.*$'),
    'Rust': re.compile(r'//.*$'),
    'C#': re.compile(r'//.*$'),
    'Ruby': re.compile(r'#.*$'),
    'PHP': re.compile(r'(?://.*$|#.*$)'),
    'Kotlin': re.compile(r'//.*$'),
    'Swift': re.compile(r'//.*$'),
    'Scala': re.compile(r'//.*$'),
    'Config': re.compile(r'#.*$'),
}

# Languages that use /* ... */ block comments
_BLOCK_COMMENT_LANGS = {
    'Java', 'Go', 'JavaScript', 'C/C++', 'Rust',
    'C#', 'Kotlin', 'Swift', 'Scala', 'PHP',
}

# String literal pattern: matches single-quoted, double-quoted, and backtick strings
_STRING_LITERAL_RE = re.compile(
    r'(?:'
    r"'''[\s\S]*?'''|"   # Python triple single-quote
    r'"""[\s\S]*?"""|'   # Python triple double-quote
    r"'(?:[^'\\]|\\.)*'|"  # Single-quoted
    r'"(?:[^"\\]|\\.)*"|'  # Double-quoted
    r'`(?:[^`\\]|\\.)*`'   # Backtick (JS template literals)
    r')'
)


def strip_comments(line: str, language: str) -> str:
    """Remove single-line comments from a line of code.

    Preserves the code portion so regex patterns only match active code.
    Does NOT strip comments inside string literals.
    """
    pattern = _COMMENT_PATTERNS.get(language)
    if pattern is None:
        return line
    # Protect string literals by replacing them with placeholders
    strings = []
    def _save_string(m):
        strings.append(m.group())
        return f'__STR{len(strings) - 1}__'
    protected = _STRING_LITERAL_RE.sub(_save_string, line)
    # Strip the comment
    stripped = pattern.sub('', protected)
    # Restore strings
    for i, s in enumerate(strings):
        stripped = stripped.replace(f'__STR{i}__', s)
    return stripped


def strip_string_literals(line: str) -> str:
    """Replace string literal contents with empty strings.

    This prevents regex from matching algorithm names inside
    error messages, log strings, or documentation.
    """
    def _empty(m):
        s = m.group()
        if s.startswith('"""') or s.startswith("'''"):
            return s[:3] + s[-3:]
        return s[0] + s[-1]
    return _STRING_LITERAL_RE.sub(_empty, line)


def strip_block_comments(content: str, language: str) -> str:
    """Remove multi-line block comments from source code.

    Handles:
      /* ... */    — C-family languages (Java, Go, JS, C/C++, Rust, C#, Kotlin, Swift, Scala, PHP)
      =begin...=end — Ruby
      <!-- ... --> — HTML/XML config files

    Preserves line count by replacing comment content with newlines,
    so line numbers in findings remain accurate.
    String literals are protected — block comments inside strings are NOT stripped.
    """
    if language in _BLOCK_COMMENT_LANGS:
        content = _strip_c_block_comments(content)
    elif language == 'Ruby':
        content = _strip_ruby_block_comments(content)
    elif language == 'Config':
        content = _strip_html_comments(content)
    elif language == 'Python':
        # Python multiline strings (docstrings) are syntactically strings, not comments,
        # but for PQC scanning purposes their content should be treated like comments —
        # algorithm names in docstrings would cause false positives otherwise.
        content = _strip_python_triple_strings(content)
    return content


_PYTHON_TRIPLE_STRING_RE = re.compile(
    r'''(?:[rRbBfFuU]{0,2})("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')''',
    re.MULTILINE,
)


def _strip_python_triple_strings(content: str) -> str:
    """Replace Python triple-quoted strings with blank content, preserving line count.

    Needed because per-line string stripping can't see multi-line strings.
    Without this, algorithm names inside docstrings generate false positives.
    """
    def _blank(match):
        s = match.group()
        return '\n' * s.count('\n')
    return _PYTHON_TRIPLE_STRING_RE.sub(_blank, content)


def _strip_c_block_comments(content: str) -> str:
    """Remove /* ... */ block comments, preserving line count.

    Protects string literals so that /* inside strings is not treated as a comment.
    """
    def _replace_keeping_newlines(match):
        return '\n' * match.group().count('\n')

    # Protect string literals, strip block comments, then restore
    strings = []

    def _save(m):
        strings.append(m.group())
        return f'__BLKSTR{len(strings) - 1}__'

    protected = _STRING_LITERAL_RE.sub(_save, content)
    stripped = re.sub(r'/\*[\s\S]*?\*/', _replace_keeping_newlines, protected)

    for i, s in enumerate(strings):
        stripped = stripped.replace(f'__BLKSTR{i}__', s)
    return stripped


def _strip_ruby_block_comments(content: str) -> str:
    """Remove =begin ... =end block comments, preserving line count."""
    def _replace_keeping_newlines(match):
        return '\n' * match.group().count('\n')

    return re.sub(r'^=begin\b.*?^=end\b[^\n]*',
                  _replace_keeping_newlines,
                  content, flags=re.MULTILINE | re.DOTALL)


def _strip_html_comments(content: str) -> str:
    """Remove <!-- ... --> comments, preserving line count."""
    def _replace_keeping_newlines(match):
        return '\n' * match.group().count('\n')

    return re.sub(r'<!--[\s\S]*?-->', _replace_keeping_newlines, content)


# ============================================================================
# SUPPRESSION SYSTEM (.pqcignore + inline # pqc-ignore)
# ============================================================================

def load_pqcignore(scan_path: str) -> List[str]:
    """Load .pqcignore file from the scan root directory.

    Returns a list of glob patterns for files/dirs to skip.
    Format is like .gitignore: one pattern per line, # for comments.
    """
    patterns = []
    ignore_file = Path(scan_path) / '.pqcignore'
    if ignore_file.is_file():
        for line in ignore_file.read_text(encoding='utf-8', errors='ignore').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    return patterns


def is_suppressed(filepath: str, scan_root: str, ignore_patterns: List[str]) -> bool:
    """Check if a file matches any .pqcignore pattern."""
    try:
        rel = os.path.relpath(filepath, scan_root).replace('\\', '/')
    except ValueError:
        rel = filepath
    for pattern in ignore_patterns:
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(os.path.basename(filepath), pattern):
            return True
    return False


def has_inline_suppression(line: str, algorithm: Optional[str] = None) -> bool:
    """Check if a line has an inline pqc-ignore suppression comment.

    Supports:
        # pqc-ignore          — suppress all findings on this line
        # pqc-ignore[RSA]     — suppress only RSA findings
        # pqc-ignore[RSA,DH]  — suppress RSA and DH findings
    """
    match = re.search(r'#\s*pqc-ignore(?:\[([^\]]+)\])?', line)
    if not match:
        return False
    algos_str = match.group(1)
    if algos_str is None:
        return True  # Blanket suppression
    if algorithm is None:
        return True
    suppressed_algos = {a.strip().upper() for a in algos_str.split(',')}
    return algorithm.upper() in suppressed_algos


# ============================================================================
# BASELINE DIFFING
# ============================================================================

def _finding_fingerprint(f: Finding, scan_root: str = '') -> str:
    """Create a stable fingerprint for a finding (file + line + algo + category).

    Uses the full canonical path relative to the scan root for collision resistance
    in monorepos. Falls back to last 3 path components when scan_root is unknown,
    which is more robust than 2-component truncation while still portable.
    """
    try:
        if scan_root:
            rel = os.path.relpath(f.file, scan_root).replace('\\', '/')
            if not rel.startswith('..'):
                return f'{rel}:{f.line}:{f.algorithm}:{f.category.value}'
    except (ValueError, OSError):
        pass
    # Fallback: last 3 path components (more collision-resistant than 2).
    parts = Path(f.file).parts
    n = min(3, len(parts))
    portable = '/'.join(parts[-n:]) if parts else f.file
    return f'{portable}:{f.line}:{f.algorithm}:{f.category.value}'


def _baseline_dict_fingerprint(bf_dict: dict, scan_root: str = '') -> str:
    """Fingerprint for a baseline JSON entry, matching _finding_fingerprint logic."""
    file_path = bf_dict.get('file', '')
    try:
        if scan_root and file_path:
            rel = os.path.relpath(file_path, scan_root).replace('\\', '/')
            if not rel.startswith('..'):
                return f"{rel}:{bf_dict.get('line', 0)}:{bf_dict.get('algorithm', '')}:{bf_dict.get('category', '')}"
    except (ValueError, OSError):
        pass
    parts = Path(file_path).parts
    n = min(3, len(parts))
    portable = '/'.join(parts[-n:]) if parts else file_path
    return f"{portable}:{bf_dict.get('line', 0)}:{bf_dict.get('algorithm', '')}:{bf_dict.get('category', '')}"


def diff_against_baseline(current: ScanResult, baseline_path: str) -> dict:
    """Compare current scan against a baseline JSON file.

    Returns dict with 'new', 'fixed', and 'existing' finding lists.
    """
    try:
        with open(baseline_path, 'r', encoding='utf-8') as bf:
            baseline_data = json.load(bf)
    except (OSError, json.JSONDecodeError):
        return {'new': current.findings, 'fixed': [], 'existing': []}

    scan_root = current.scan_path
    baseline_findings = baseline_data.get('findings', [])
    baseline_fps = set()
    for bf in baseline_findings:
        baseline_fps.add(_baseline_dict_fingerprint(bf, scan_root))

    current_fps = {}
    for f in current.findings:
        fp = _finding_fingerprint(f, scan_root)
        current_fps[fp] = f

    new_findings = []
    existing_findings = []
    for fp, f in current_fps.items():
        if fp in baseline_fps:
            existing_findings.append(f)
        else:
            new_findings.append(f)

    # Fixed = in baseline but not in current
    current_fp_set = set(current_fps.keys())
    fixed_findings = []
    for bf in baseline_findings:
        fp = _baseline_dict_fingerprint(bf, scan_root)
        if fp not in current_fp_set:
            fixed_findings.append(bf)

    return {
        'new': new_findings,
        'fixed': fixed_findings,
        'existing': existing_findings,
    }


# ============================================================================
# DETECTION PATTERNS
# ============================================================================

# Remediation mapping
REMEDIATION = {
    'RSA': ('ML-KEM (FIPS 203) for key exchange, ML-DSA (FIPS 204) for signatures',
            'ML-KEM-768 or ML-DSA-65'),
    'ECDSA': ('ML-DSA (FIPS 204) for signatures', 'ML-DSA-65'),
    'ECDH': ('X25519+ML-KEM-768 hybrid key exchange', 'ML-KEM-768'),
    'EdDSA': ('ML-DSA (FIPS 204) for signatures', 'ML-DSA-65'),
    'Ed25519': ('ML-DSA (FIPS 204) for signatures', 'ML-DSA-44'),
    'Ed448': ('ML-DSA (FIPS 204) for signatures', 'ML-DSA-65'),
    'X25519': ('ML-KEM (FIPS 203) for key exchange', 'ML-KEM-768'),
    'X448': ('ML-KEM (FIPS 203) for key exchange', 'ML-KEM-768'),
    'DH': ('ML-KEM (FIPS 203) for key exchange', 'ML-KEM-768'),
    'DSA': ('ML-DSA (FIPS 204) for signatures', 'ML-DSA-65'),
    'AES-128': ('Upgrade to AES-256 (128-bit post-quantum security)', 'AES-256'),
    'SHA-1': ('Upgrade to SHA-256 minimum', 'SHA-256 or SHA-3'),
    'MD5': ('Upgrade to SHA-256 minimum', 'SHA-256 or SHA-3'),
    '3DES': ('Upgrade to AES-256', 'AES-256-GCM'),
    'RC4': ('Upgrade to AES-256-GCM or ChaCha20-Poly1305', 'AES-256-GCM'),
    'Blowfish': ('Upgrade to AES-256', 'AES-256-GCM'),
}

# Python patterns
PYTHON_PATTERNS = [
    # RSA
    (r'rsa\.generate_private_key|RSA\.generate|PKCS1_v15|PKCS1_OAEP',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE,
     'RSA key generation or encryption detected'),
    (r'RSAPrivateKey|RSAPublicKey|rsa_private_key|rsa_public_key',
     'RSA', Severity.HIGH, Category.SIGNATURE,
     'RSA key usage detected'),
    # ECDSA/ECDH
    (r'ec\.generate_private_key|ECDSA|ec\.SECP256R1|ec\.SECP384R1',
     'ECDSA', Severity.CRITICAL, Category.SIGNATURE,
     'ECDSA/ECC key generation or signing detected'),
    (r'ECDH|ec\.ECDH|derive.*shared.*key',
     'ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE,
     'ECDH key exchange detected'),
    (r'ed25519|Ed25519',
     'Ed25519', Severity.HIGH, Category.SIGNATURE,
     'Ed25519 signature detected'),
    # DH
    (r'dh\.generate_parameters|DHParameters|DiffieHellman',
     'DH', Severity.CRITICAL, Category.KEY_EXCHANGE,
     'Diffie-Hellman key exchange detected'),
    # Weak symmetric
    (r'AES\.new\(.{0,30}16\)|algorithms\.AES\(.{0,30}16\)|aes[_-]128|AES128',
     'AES-128', Severity.MEDIUM, Category.SYMMETRIC,
     'AES-128 detected (64-bit post-quantum security)'),
    (r'\bDES\b|3DES|TripleDES|DES3',
     '3DES', Severity.HIGH, Category.SYMMETRIC,
     '3DES/DES detected — deprecated and quantum-vulnerable'),
    (r'Blowfish|blowfish|BF_',
     'Blowfish', Severity.HIGH, Category.SYMMETRIC,
     'Blowfish detected — deprecated'),
    (r'\bRC4\b|ARC4|rc4',
     'RC4', Severity.HIGH, Category.SYMMETRIC,
     'RC4 detected — broken, deprecated'),
    # Weak hash
    (r'hashlib\.sha1|SHA1|sha1\b',
     'SHA-1', Severity.MEDIUM, Category.HASH,
     'SHA-1 detected — collision-broken since 2017'),
    (r'hashlib\.md5|MD5|md5\b',
     'MD5', Severity.HIGH, Category.HASH,
     'MD5 detected — completely broken'),
]

# Java patterns
JAVA_PATTERNS = [
    (r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key generation'),
    (r'Cipher\.getInstance\s*\(\s*"RSA',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA encryption'),
    (r'Signature\.getInstance\s*\(.*(RSA|ECDSA|EdDSA|DSA)',
     'RSA/ECDSA', Severity.HIGH, Category.SIGNATURE, 'Digital signature usage'),
    (r'KeyAgreement\.getInstance\s*\(\s*"(ECDH|DH)"',
     'ECDH/DH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'Key agreement'),
    (r'KeyPairGenerator\.getInstance\s*\(\s*"(EC|DSA)"',
     'ECDSA/DSA', Severity.CRITICAL, Category.SIGNATURE, 'EC/DSA key generation'),
    (r'MessageDigest\.getInstance\s*\(\s*"(SHA-1|MD5)"',
     'SHA-1/MD5', Severity.MEDIUM, Category.HASH, 'Weak hash function'),
]

# Go patterns
GO_PATTERNS = [
    (r'crypto/rsa|rsa\.GenerateKey',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA usage'),
    (r'crypto/ecdsa|ecdsa\.GenerateKey|ecdsa\.Sign',
     'ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECDSA usage'),
    (r'crypto/elliptic|elliptic\.P256|elliptic\.P384',
     'ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'Elliptic curve usage'),
    (r'crypto/dsa',
     'DSA', Severity.CRITICAL, Category.SIGNATURE, 'DSA usage (deprecated)'),
    (r'crypto/des|des\.NewCipher',
     '3DES', Severity.HIGH, Category.SYMMETRIC, 'DES/3DES usage'),
]

# JavaScript/Node patterns
JS_PATTERNS = [
    (r'crypto\.createSign|crypto\.createVerify',
     'RSA/ECDSA', Severity.HIGH, Category.SIGNATURE, 'Digital signature'),
    (r'crypto\.generateKeyPair\s*\(\s*[\'"]rsa[\'"]',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key generation'),
    (r'crypto\.createDiffieHellman|crypto\.createECDH',
     'DH/ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'Key exchange'),
    (r'node-rsa|node-forge.*rsa',
     'RSA', Severity.CRITICAL, Category.DEPENDENCY, 'RSA library dependency'),
]

# Config file patterns (nginx, apache, haproxy)
CONFIG_PATTERNS = [
    (r'ssl_ciphers.*(?:RC4|DES|3DES|EXPORT)',
     'Weak cipher', Severity.HIGH, Category.PROTOCOL, 'Weak cipher suite in config'),
    (r'\bRC4\b',
     'RC4', Severity.HIGH, Category.SYMMETRIC, 'RC4 in config — broken cipher'),
    (r'SSLProtocol.*(?:SSLv3|TLSv1\b|TLSv1\.0|TLSv1\.1)',
     'Old TLS', Severity.HIGH, Category.PROTOCOL, 'Deprecated TLS version'),
    (r'ssl_protocols.*(?:TLSv1\b|TLSv1\.0|TLSv1\.1)',
     'Old TLS', Severity.HIGH, Category.PROTOCOL, 'Deprecated TLS version'),
]

# Dependency file patterns
DEPENDENCY_PATTERNS = {
    'requirements.txt': [
        (r'pycryptodome|pycryptodomex|PyCrypto', 'Crypto library', Severity.INFO,
         'PyCrypto dependency — audit for quantum-vulnerable algorithm usage'),
        (r'cryptography', 'Crypto library', Severity.INFO,
         'cryptography library — audit for RSA/ECC usage'),
        (r'paramiko', 'SSH library', Severity.INFO,
         'paramiko — check SSH key exchange configuration'),
        (r'pyOpenSSL', 'TLS library', Severity.INFO,
         'pyOpenSSL — audit TLS configuration'),
    ],
    'package.json': [
        (r'node-rsa', 'RSA library', Severity.HIGH,
         'node-rsa dependency — RSA is quantum-vulnerable'),
        (r'"elliptic"', 'ECC library', Severity.HIGH,
         'elliptic dependency — ECC is quantum-vulnerable'),
    ],
}

# C/C++ patterns
C_PATTERNS = [
    (r'RSA_generate_key|RSA_new|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'OpenSSL RSA usage'),
    (r'EC_KEY_new|EC_KEY_generate_key|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC',
     'ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'OpenSSL ECC usage'),
    (r'DH_generate_parameters|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_DH',
     'DH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'OpenSSL DH usage'),
    (r'EVP_des_|DES_set_key|DES_ecb_encrypt',
     '3DES', Severity.HIGH, Category.SYMMETRIC, 'OpenSSL DES/3DES usage'),
    (r'EVP_sha1\b|SHA1_Init|SHA1_Update',
     'SHA-1', Severity.MEDIUM, Category.HASH, 'OpenSSL SHA-1 usage'),
    (r'EVP_md5\b|MD5_Init|MD5_Update',
     'MD5', Severity.HIGH, Category.HASH, 'OpenSSL MD5 usage'),
    (r'EVP_aes_128_|AES_set_encrypt_key\(.{0,20}16\)',
     'AES-128', Severity.MEDIUM, Category.SYMMETRIC, 'OpenSSL AES-128'),
]

# Rust patterns
RUST_PATTERNS = [
    (r'use\s+rsa::|RsaPrivateKey|RsaPublicKey',
     'RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'Rust RSA crate'),
    (r'use\s+p256::|use\s+k256::|EcdsaSigningKey',
     'ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'Rust ECC crate'),
    (r'use\s+sha1::|Sha1::new',
     'SHA-1', Severity.MEDIUM, Category.HASH, 'Rust SHA-1'),
]

# File extension to language mapping
LANGUAGE_MAP = {
    '.py': ('Python', PYTHON_PATTERNS),
    '.java': ('Java', JAVA_PATTERNS),
    '.go': ('Go', GO_PATTERNS),
    '.js': ('JavaScript', JS_PATTERNS),
    '.ts': ('JavaScript', JS_PATTERNS),
    '.mjs': ('JavaScript', JS_PATTERNS),
    '.c': ('C/C++', C_PATTERNS),
    '.cpp': ('C/C++', C_PATTERNS),
    '.cc': ('C/C++', C_PATTERNS),
    '.h': ('C/C++', C_PATTERNS),
    '.hpp': ('C/C++', C_PATTERNS),
    '.rs': ('Rust', RUST_PATTERNS),
    '.conf': ('Config', CONFIG_PATTERNS),
    '.cfg': ('Config', CONFIG_PATTERNS),
}


# ============================================================================
# SCANNER ENGINE
# ============================================================================

class PQCScanner:
    """Post-Quantum Cryptography vulnerability scanner v4.0."""

    def __init__(self, strip_comments: bool = True, strip_strings: bool = False):
        self._finding_counter = 0
        self._skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv',
                           'venv', 'env', '.tox', 'dist', 'build', '.eggs'}
        self._strip_comments = strip_comments
        self._strip_strings = strip_strings
        self._ignore_patterns: List[str] = []
        self._scan_root: str = ''
        self._suppressed_count = 0

    def scan(self, path: str, max_files: int = 10000) -> ScanResult:
        """Scan a file or directory for quantum-vulnerable cryptography."""
        self._scan_root = os.path.abspath(path)
        result = ScanResult(
            scan_path=self._scan_root,
            scan_date=datetime.now().isoformat(),
            files_scanned=0,
        )

        target = Path(path)

        # Load .pqcignore
        if target.is_dir():
            self._ignore_patterns = load_pqcignore(str(target))
        else:
            self._ignore_patterns = load_pqcignore(str(target.parent))

        if target.is_file():
            self._scan_file(target, result)
        elif target.is_dir():
            for filepath in self._walk_files(target, max_files):
                self._scan_file(filepath, result)
        else:
            raise FileNotFoundError(f"Path not found: {path}")

        result.compute_summary()
        return result

    @property
    def suppressed_count(self) -> int:
        """Number of findings suppressed by .pqcignore or inline comments."""
        return self._suppressed_count

    def _walk_files(self, root: Path, max_files: int) -> List[Path]:
        """Walk directory tree, respecting skip dirs, max files, .pqcignore, and symlink safety."""
        files = []
        real_root = os.path.realpath(str(root))
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self._skip_dirs]
            for fname in filenames:
                if len(files) >= max_files:
                    return files
                fp = Path(dirpath) / fname
                # Symlink safety: reject files whose real path escapes the scan root.
                real_fp = os.path.realpath(str(fp))
                if not (real_fp.startswith(real_root + os.sep) or real_fp == real_root):
                    continue
                if not is_suppressed(str(fp), self._scan_root, self._ignore_patterns):
                    files.append(fp)
        return files

    def _scan_file(self, filepath: Path, result: ScanResult) -> None:
        """Scan a single file for findings."""
        ext = filepath.suffix.lower()
        name = filepath.name.lower()

        # Check dependency files
        if name in DEPENDENCY_PATTERNS:
            self._scan_dependency_file(filepath, name, result)
            result.files_scanned += 1
            return

        # Check source/config files
        if ext not in LANGUAGE_MAP:
            return

        language, patterns = LANGUAGE_MAP[ext]

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            return

        result.files_scanned += 1

        # Strip multi-line block comments before splitting into lines
        if self._strip_comments:
            content = strip_block_comments(content, language)

        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Pre-process line: strip comments and string literals
            check_line = line
            if self._strip_comments:
                check_line = strip_comments(check_line, language)
            if self._strip_strings:
                check_line = strip_string_literals(check_line)

            for pattern, algo, severity, category, desc in patterns:
                if re.search(pattern, check_line, re.IGNORECASE):
                    # Check inline suppression on the ORIGINAL line
                    if has_inline_suppression(line, algo):
                        self._suppressed_count += 1
                        continue

                    rec, replacement = REMEDIATION.get(algo, (
                        'Review and migrate to PQC equivalent', 'Consult NIST PQC standards'))
                    self._finding_counter += 1
                    result.add_finding(Finding(
                        id=f'PQC-{self._finding_counter:04d}',
                        severity=severity,
                        category=category,
                        algorithm=algo,
                        file=str(filepath),
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        description=f'{desc} ({language})',
                        recommendation=rec,
                        pqc_replacement=replacement,
                    ))

    def _scan_dependency_file(self, filepath: Path, name: str,
                               result: ScanResult) -> None:
        """Scan dependency files (requirements.txt, package.json)."""
        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
        except (OSError, PermissionError):
            return

        patterns = DEPENDENCY_PATTERNS.get(name, [])
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            for pattern, algo, severity, desc in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._finding_counter += 1
                    result.add_finding(Finding(
                        id=f'PQC-{self._finding_counter:04d}',
                        severity=severity,
                        category=Category.DEPENDENCY,
                        algorithm=algo,
                        file=str(filepath),
                        line=line_num,
                        code_snippet=line.strip()[:120],
                        description=desc,
                        recommendation='Audit usage for quantum-vulnerable algorithms',
                        pqc_replacement='NIST PQC standards (FIPS 203/204/205)',
                    ))


# ============================================================================
# REPORT GENERATION
# ============================================================================

def format_text_report(result: ScanResult) -> str:
    """Generate human-readable text report."""
    result.compute_summary()
    lines = [
        "=" * 70,
        "  PQC-SCANNER — Post-Quantum Cryptography Vulnerability Report",
        "=" * 70,
        "",
        f"  Scan Path:     {result.scan_path}",
        f"  Scan Date:     {result.scan_date}",
        f"  Files Scanned: {result.files_scanned}",
        f"  Total Findings: {len(result.findings)}",
        f"  Risk Score:    {result.risk_score}/100",
        "",
        "  SEVERITY BREAKDOWN:",
    ]

    severity_colors = {'CRITICAL': '!!!', 'HIGH': '!! ', 'MEDIUM': '!  ',
                       'LOW': '.  ', 'INFO': '   '}
    for sev, count in result.summary.items():
        if count > 0:
            lines.append(f"    [{severity_colors.get(sev, '   ')}] {sev:10s} {count}")

    if not result.findings:
        lines.extend(["", "  No quantum-vulnerable cryptography detected.",
                       "  Your codebase appears quantum-safe!"])
    else:
        lines.extend(["", "  FINDINGS:", "  " + "-" * 60])

        # Group by severity
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in result.findings if f.severity == sev]
            if not sev_findings:
                continue
            lines.append(f"\n  [{sev.value}]")
            for f in sev_findings:
                rel_path = _safe_relpath(f.file, result.scan_path)
                lines.extend([
                    f"    {f.id}: {f.algorithm} — {f.description}",
                    f"      File: {rel_path}:{f.line}",
                    f"      Code: {f.code_snippet}",
                    f"      Fix:  {f.recommendation}",
                    f"      Use:  {f.pqc_replacement}",
                    "",
                ])

    lines.extend([
        "  REMEDIATION SUMMARY:",
        "  " + "-" * 60,
        "  IMMEDIATE: Replace all RSA/ECDH key exchange with ML-KEM hybrid",
        "  SHORT-TERM: Migrate RSA/ECDSA signatures to ML-DSA",
        "  QUICK WIN: Upgrade AES-128 to AES-256, SHA-1/MD5 to SHA-256",
        "",
        "=" * 70,
    ])

    return "\n".join(lines)


def format_json_report(result: ScanResult) -> str:
    """Generate JSON report for CI/CD integration."""
    return json.dumps(result.to_dict(), indent=2)


def format_html_report(result: ScanResult) -> str:
    """Generate HTML report."""
    import html as html_mod
    result.compute_summary()
    severity_colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800',
                       'MEDIUM': '#ffcc00', 'LOW': '#44aaff', 'INFO': '#888888'}

    findings_html = ""
    for f in result.findings:
        color = severity_colors.get(f.severity.value, '#888')
        # html.escape() prevents XSS from scanned code containing <script> tags
        snippet = html_mod.escape(f.code_snippet[:80])
        algo = html_mod.escape(f.algorithm)
        replacement = html_mod.escape(f.pqc_replacement)
        findings_html += f"""
        <tr>
            <td style="color:{color};font-weight:bold">{f.severity.value}</td>
            <td>{f.id}</td>
            <td>{algo}</td>
            <td><code>{snippet}</code></td>
            <td>{html_mod.escape(os.path.basename(f.file))}:{f.line}</td>
            <td>{replacement}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>PQC Scanner Report</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 20px; }}
h1 {{ color: #bb86fc; }} h2 {{ color: #03dac6; }}
table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
th {{ background: #2d2d44; color: #bb86fc; padding: 10px; text-align: left; }}
td {{ padding: 8px; border-bottom: 1px solid #333; }}
code {{ background: #2d2d44; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
.score {{ font-size: 48px; color: {'#ff4444' if result.risk_score > 50 else '#03dac6'}; }}
.stat {{ display: inline-block; margin: 10px 20px; text-align: center; }}
.stat-num {{ font-size: 32px; color: #bb86fc; }}
</style></head><body>
<h1>PQC-SCANNER Report</h1>
<p>Scan: {html_mod.escape(result.scan_path)} | Date: {html_mod.escape(result.scan_date)}</p>
<div class="stat"><div class="score">{result.risk_score}</div><div>Risk Score</div></div>
<div class="stat"><div class="stat-num">{len(result.findings)}</div><div>Findings</div></div>
<div class="stat"><div class="stat-num">{result.files_scanned}</div><div>Files Scanned</div></div>
<div class="stat"><div class="stat-num">{result.summary.get('CRITICAL', 0)}</div><div>Critical</div></div>
<h2>Findings</h2>
<table><tr><th>Severity</th><th>ID</th><th>Algorithm</th><th>Code</th><th>Location</th><th>PQC Replacement</th></tr>
{findings_html}</table>
<h2>Remediation</h2>
<ul>
<li><strong>IMMEDIATE:</strong> Replace RSA/ECDH key exchange with ML-KEM (FIPS 203) hybrid</li>
<li><strong>SHORT-TERM:</strong> Migrate RSA/ECDSA signatures to ML-DSA (FIPS 204)</li>
<li><strong>QUICK WIN:</strong> Upgrade AES-128 to AES-256, SHA-1/MD5 to SHA-256</li>
</ul>
<p><em>Generated by Enigma pqc-scanner | CONFIDENTIAL</em></p>
</body></html>"""


# ============================================================================
# SARIF 2.1.0 OUTPUT (CI/CD integration — GitHub, Azure DevOps)
# ============================================================================

# Severity to SARIF level mapping
SARIF_LEVELS = {
    'CRITICAL': 'error',
    'HIGH': 'error',
    'MEDIUM': 'warning',
    'LOW': 'note',
    'INFO': 'none',
}

# Rule definitions for SARIF
SARIF_RULES = {
    'RSA': {'id': 'PQC001', 'name': 'QuantumVulnerableRSA',
            'short': 'RSA is broken by Shor\'s algorithm',
            'help': 'Replace with ML-KEM (FIPS 203) or ML-DSA (FIPS 204)'},
    'ECDSA': {'id': 'PQC002', 'name': 'QuantumVulnerableECDSA',
              'short': 'ECDSA is broken by Shor\'s algorithm',
              'help': 'Replace with ML-DSA (FIPS 204)'},
    'ECDH': {'id': 'PQC003', 'name': 'QuantumVulnerableECDH',
             'short': 'ECDH is broken by Shor\'s algorithm',
             'help': 'Replace with ML-KEM-768 hybrid key exchange'},
    'Ed25519': {'id': 'PQC004', 'name': 'QuantumVulnerableEd25519',
                'short': 'Ed25519 is broken by Shor\'s algorithm',
                'help': 'Replace with ML-DSA-44 (FIPS 204)'},
    'DH': {'id': 'PQC005', 'name': 'QuantumVulnerableDH',
            'short': 'Diffie-Hellman is broken by Shor\'s algorithm',
            'help': 'Replace with ML-KEM (FIPS 203)'},
    'DSA': {'id': 'PQC006', 'name': 'QuantumVulnerableDSA',
            'short': 'DSA is broken by Shor\'s algorithm',
            'help': 'Replace with ML-DSA (FIPS 204)'},
    'AES-128': {'id': 'PQC007', 'name': 'QuantumWeakenedAES128',
                'short': 'AES-128 weakened to 64-bit by Grover\'s algorithm',
                'help': 'Upgrade to AES-256 for 128-bit post-quantum security'},
    'SHA-1': {'id': 'PQC008', 'name': 'WeakHashSHA1',
              'short': 'SHA-1 is collision-broken (2017)',
              'help': 'Upgrade to SHA-256 or SHA-3'},
    'MD5': {'id': 'PQC009', 'name': 'WeakHashMD5',
            'short': 'MD5 is completely broken',
            'help': 'Upgrade to SHA-256 or SHA-3'},
    '3DES': {'id': 'PQC010', 'name': 'DeprecatedTripleDES',
             'short': '3DES is deprecated and quantum-vulnerable',
             'help': 'Upgrade to AES-256-GCM'},
    'RC4': {'id': 'PQC011', 'name': 'BrokenRC4',
            'short': 'RC4 is broken',
            'help': 'Upgrade to AES-256-GCM or ChaCha20-Poly1305'},
    'Blowfish': {'id': 'PQC012', 'name': 'DeprecatedBlowfish',
                 'short': 'Blowfish is deprecated',
                 'help': 'Upgrade to AES-256-GCM'},
    'RSA/ECDSA': {'id': 'PQC013', 'name': 'QuantumVulnerableSignature',
                  'short': 'Signature algorithm vulnerable to Shor\'s',
                  'help': 'Replace with ML-DSA (FIPS 204)'},
    'ECDH/DH': {'id': 'PQC014', 'name': 'QuantumVulnerableKeyExchange',
                'short': 'Key exchange vulnerable to Shor\'s',
                'help': 'Replace with ML-KEM (FIPS 203)'},
    'ECDSA/DSA': {'id': 'PQC015', 'name': 'QuantumVulnerableECDSADSA',
                  'short': 'EC/DSA vulnerable to Shor\'s',
                  'help': 'Replace with ML-DSA (FIPS 204)'},
    'SHA-1/MD5': {'id': 'PQC016', 'name': 'WeakHash',
                  'short': 'Weak hash function',
                  'help': 'Upgrade to SHA-256 or SHA-3'},
    'DH/ECDH': {'id': 'PQC017', 'name': 'QuantumVulnerableDHECDH',
                'short': 'Key exchange vulnerable to Shor\'s',
                'help': 'Replace with ML-KEM (FIPS 203)'},
}


def format_sarif_report(result: ScanResult) -> str:
    """Generate SARIF 2.1.0 report for CI/CD integration.

    Compatible with GitHub Code Scanning (upload-sarif action)
    and Azure DevOps SARIF Viewer.
    """
    # Build rules list (deduplicated by algorithm)
    seen_rules = {}
    rule_indices = {}
    rules = []
    for f in result.findings:
        algo = f.algorithm
        if algo not in seen_rules:
            safe_id = re.sub(r'[^A-Za-z0-9._/-]', '_', algo)
            rule_def = SARIF_RULES.get(algo, {
                'id': f'PQC-{safe_id}',
                'name': f'QuantumVulnerable{safe_id.replace("-", "").replace("/", "").replace("_", "")}',
                'short': f'{algo} may be quantum-vulnerable',
                'help': 'Consult NIST PQC standards (FIPS 203/204/205)',
            })
            rule_idx = len(rules)
            rules.append({
                'id': rule_def['id'],
                'name': rule_def['name'],
                'shortDescription': {'text': rule_def['short']},
                'fullDescription': {'text': f.description},
                'helpUri': 'https://csrc.nist.gov/projects/post-quantum-cryptography',
                'properties': {
                    'tags': ['security', 'quantum', 'cryptography'],
                    'precision': 'high',
                },
            })
            seen_rules[algo] = rule_def['id']
            rule_indices[algo] = rule_idx

    # Build results
    sarif_results = []
    for f in result.findings:
        sarif_results.append({
            'ruleId': seen_rules[f.algorithm],
            'ruleIndex': rule_indices[f.algorithm],
            'level': SARIF_LEVELS.get(f.severity.value, 'warning'),
            'message': {
                'text': f'{f.description}. Replace with {f.pqc_replacement}.',
            },
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {
                        'uri': _safe_relpath(f.file, result.scan_path).replace('\\', '/'),
                        'uriBaseId': '%SRCROOT%',
                    },
                    'region': {
                        'startLine': f.line,
                        'startColumn': 1,
                        'snippet': {'text': f.code_snippet},
                    },
                },
            }],
            'properties': {
                'recommendation': f.recommendation,
            },
        })

    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'pqc-scanner',
                    'version': __version__,
                    'semanticVersion': __version__,
                    'informationUri': 'https://github.com/enigma/pqc-scanner',
                    'rules': rules,
                },
            },
            'results': sarif_results,
            'invocations': [{
                'executionSuccessful': True,
                'commandLine': f'pqc-scanner scan {result.scan_path}',
            }],
        }],
    }

    return json.dumps(sarif, indent=2)


# ============================================================================
# CycloneDX CBOM 1.7 OUTPUT
# ============================================================================

# Map algorithms to CycloneDX crypto properties
_CBOM_ALGO_MAP = {
    'RSA': {'primitive': 'pke', 'family': 'RSA', 'quantumSafe': False},
    'ECDSA': {'primitive': 'signature', 'family': 'EC', 'quantumSafe': False},
    'ECDH': {'primitive': 'ke', 'family': 'EC', 'quantumSafe': False},
    'Ed25519': {'primitive': 'signature', 'family': 'EC', 'quantumSafe': False},
    'DH': {'primitive': 'ke', 'family': 'DH', 'quantumSafe': False},
    'DSA': {'primitive': 'signature', 'family': 'DSA', 'quantumSafe': False},
    'AES-128': {'primitive': 'blockcipher', 'family': 'AES', 'quantumSafe': False,
                'note': 'Grover halves effective key length to 64-bit'},
    'SHA-1': {'primitive': 'hash', 'family': 'SHA', 'quantumSafe': False},
    'MD5': {'primitive': 'hash', 'family': 'MD', 'quantumSafe': False},
    '3DES': {'primitive': 'blockcipher', 'family': 'DES', 'quantumSafe': False},
    'RC4': {'primitive': 'streamcipher', 'family': 'RC4', 'quantumSafe': False},
    'Blowfish': {'primitive': 'blockcipher', 'family': 'Blowfish', 'quantumSafe': False},
}


def format_cbom_report(result: ScanResult) -> str:
    """Generate CycloneDX 1.7 CBOM (Cryptographic Bill of Materials).

    Outputs a standards-compliant CBOM JSON that enterprises can ingest
    into their security toolchains alongside SBOMs.
    """
    result.compute_summary()

    # Deduplicate crypto assets by algorithm
    crypto_components = []
    seen_algos = set()

    for f in result.findings:
        algo = f.algorithm
        if algo in seen_algos:
            continue
        seen_algos.add(algo)

        props = _CBOM_ALGO_MAP.get(algo, {
            'primitive': 'unknown', 'family': algo, 'quantumSafe': False
        })

        component = {
            'type': 'cryptographic-asset',
            'name': algo,
            'bom-ref': f'crypto-{algo.lower().replace("/", "-").replace(" ", "-")}',
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': {
                    'primitive': props['primitive'],
                    'parameterSetIdentifier': algo,
                    'cryptoFunctions': ['keygen', 'encrypt', 'decrypt', 'sign', 'verify'],
                },
                'oid': '',
                'classicalSecurityLevel': _classical_security(algo),
                'nistQuantumSecurityLevel': 0,
            },
            'properties': [
                {'name': 'quantumSafe', 'value': str(props['quantumSafe']).lower()},
                {'name': 'algorithmFamily', 'value': props['family']},
                {'name': 'findingCount', 'value': str(sum(
                    1 for ff in result.findings if ff.algorithm == algo
                ))},
            ],
        }

        rec, replacement = REMEDIATION.get(algo, ('Review', 'Consult NIST PQC standards'))
        component['properties'].append(
            {'name': 'pqcReplacement', 'value': replacement}
        )

        crypto_components.append(component)

    # Build evidence: occurrences per finding
    occurrences = []
    for f in result.findings:
        occurrences.append({
            'bom-ref': f'occurrence-{f.id}',
            'location': _safe_relpath(f.file, result.scan_path).replace('\\', '/'),
            'line': f.line,
            'algorithm': f.algorithm,
            'severity': f.severity.value,
            'description': f.description,
        })

    cbom = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.7',
        'serialNumber': f'urn:uuid:{uuid.uuid4()}',
        'version': 1,
        'metadata': {
            'timestamp': result.scan_date,
            'tools': {
                'components': [{
                    'type': 'application',
                    'name': 'pqc-scanner',
                    'version': __version__,
                    'description': 'Enigma Post-Quantum Cryptography Migration Scanner',
                }],
            },
            'component': {
                'type': 'application',
                'name': os.path.basename(result.scan_path),
                'description': f'Scanned project at {result.scan_path}',
            },
            'properties': [
                {'name': 'pqc-scanner:filesScanned', 'value': str(result.files_scanned)},
                {'name': 'pqc-scanner:riskScore', 'value': str(result.risk_score)},
                {'name': 'pqc-scanner:totalFindings', 'value': str(len(result.findings))},
            ],
        },
        'components': crypto_components,
        'properties': [
            {'name': 'pqc-scanner:occurrences', 'value': json.dumps(occurrences)},
        ],
    }

    return json.dumps(cbom, indent=2)


def _classical_security(algo: str) -> int:
    """Estimated classical security level in bits."""
    levels = {
        'RSA': 112, 'ECDSA': 128, 'ECDH': 128, 'Ed25519': 128,
        'DH': 112, 'DSA': 112, 'AES-128': 128, 'SHA-1': 80,
        'MD5': 64, '3DES': 112, 'RC4': 0, 'Blowfish': 64,
    }
    return levels.get(algo, 0)


# ============================================================================
# CERTIFICATE CHAIN SCANNING
# ============================================================================

@dataclass
class CertFinding:
    """Finding from certificate analysis."""
    cert_subject: str
    cert_issuer: str
    algorithm: str
    key_size: int
    severity: Severity
    description: str
    recommendation: str
    not_after: Optional[str] = None
    host: Optional[str] = None


def scan_certificate_file(filepath: str) -> List[CertFinding]:
    """Scan a PEM/DER certificate file for quantum-vulnerable algorithms."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec, ed25519, dsa

    findings = []
    path = Path(filepath)

    try:
        data = path.read_bytes()
    except (OSError, PermissionError):
        return findings

    certs = []
    # Try PEM format
    if b'-----BEGIN CERTIFICATE-----' in data:
        import re as re_mod
        pem_certs = re_mod.findall(
            b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            data, re_mod.DOTALL
        )
        for pem in pem_certs:
            try:
                certs.append(x509.load_pem_x509_certificate(pem))
            except Exception:
                pass
    else:
        # Try DER format
        try:
            certs.append(x509.load_der_x509_certificate(data))
        except Exception:
            pass

    for cert in certs:
        findings.extend(_analyze_certificate(cert, str(filepath)))

    return findings


def scan_tls_endpoint(host: str, port: int = 443, timeout: int = 10) -> List[CertFinding]:
    """Connect to a TLS endpoint and analyze its certificate chain."""
    import ssl
    import socket

    findings = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                chain = ssock.getpeercert(binary_form=True)
                if chain:
                    from cryptography import x509
                    cert = x509.load_der_x509_certificate(chain)
                    for f in _analyze_certificate(cert, f'tls://{host}:{port}'):
                        f.host = host
                        findings.append(f)
    except Exception:
        pass

    return findings


def _analyze_certificate(cert, source: str) -> List[CertFinding]:
    """Analyze a single X.509 certificate for quantum vulnerabilities."""
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod, ec, ed25519 as ed_mod, dsa

    findings = []
    pub_key = cert.public_key()

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_after = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after)

    algo = 'Unknown'
    key_size = 0
    severity = Severity.HIGH

    if isinstance(pub_key, rsa_mod.RSAPublicKey):
        algo = 'RSA'
        key_size = pub_key.key_size
        severity = Severity.CRITICAL
        desc = f'RSA-{key_size} certificate — broken by Shor\'s algorithm'
        rec = 'Replace with ML-DSA certificate (FIPS 204)'
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        algo = 'ECDSA'
        key_size = pub_key.key_size
        severity = Severity.CRITICAL
        desc = f'ECDSA P-{key_size} certificate — broken by Shor\'s algorithm'
        rec = 'Replace with ML-DSA certificate (FIPS 204)'
    elif isinstance(pub_key, ed_mod.Ed25519PublicKey):
        algo = 'Ed25519'
        key_size = 256
        severity = Severity.HIGH
        desc = 'Ed25519 certificate — broken by Shor\'s algorithm'
        rec = 'Replace with ML-DSA-44 certificate (FIPS 204)'
    elif isinstance(pub_key, dsa.DSAPublicKey):
        algo = 'DSA'
        key_size = pub_key.key_size
        severity = Severity.CRITICAL
        desc = f'DSA-{key_size} certificate — broken by Shor\'s algorithm'
        rec = 'Replace with ML-DSA certificate (FIPS 204)'
    else:
        # Unknown algorithm — could be post-quantum (ML-DSA, SLH-DSA) or exotic classical.
        # Don't flag as HIGH/CRITICAL — that produces wrong guidance for already-migrated certs.
        algo = 'Unknown'
        severity = Severity.INFO
        desc = 'Unrecognized certificate algorithm — may be quantum-safe (e.g., ML-DSA). Manual review recommended.'
        rec = 'Verify algorithm identity. If PQC (ML-DSA, SLH-DSA, LMS), no action needed.'

    findings.append(CertFinding(
        cert_subject=subject,
        cert_issuer=issuer,
        algorithm=algo,
        key_size=key_size,
        severity=severity,
        description=desc,
        recommendation=rec,
        not_after=not_after,
    ))

    return findings


def scan_certificates_in_path(path: str) -> List[CertFinding]:
    """Find and scan all certificate files in a directory."""
    cert_extensions = {'.pem', '.crt', '.cer', '.der'}
    findings = []

    target = Path(path)
    if target.is_file():
        if target.suffix.lower() in cert_extensions:
            findings.extend(scan_certificate_file(str(target)))
    elif target.is_dir():
        cert_count = 0
        max_certs = 10000
        for cert_file in _walk_source_files(path, tuple(cert_extensions), max_files=max_certs):
            findings.extend(scan_certificate_file(str(cert_file)))
            cert_count += 1
            if cert_count >= max_certs:
                break

    return findings


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """CLI entry point for pqc-scanner v4."""
    import argparse

    parser = argparse.ArgumentParser(
        prog='pqc-scanner',
        description=f'pqc-scanner v{__version__} — Post-Quantum Cryptography Migration Scanner')
    parser.add_argument('command', choices=['scan', 'scan-certs', 'scan-tls'],
                        help='scan (code+deps), scan-certs (certificates), scan-tls (TLS endpoint)')
    parser.add_argument('path', help='Path to scan, or host:port for scan-tls')
    parser.add_argument('--format', choices=['text', 'json', 'html', 'sarif', 'cbom', 'dashboard'],
                        default='text', help='Output format (dashboard = interactive HTML)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low', 'info'],
                        default='low', help='Minimum severity to report')
    parser.add_argument('--baseline', help='Previous JSON scan for diff comparison')
    parser.add_argument('--no-strip-comments', action='store_true',
                        help='Disable comment stripping')
    parser.add_argument('--strip-strings', action='store_true',
                        help='Enable string literal stripping')
    # QARS flags
    parser.add_argument('--sensitivity',
                        choices=['public', 'internal', 'confidential', 'restricted'],
                        default='internal', help='Data sensitivity level for QARS scoring')
    parser.add_argument('--exposure',
                        choices=['isolated', 'internal', 'internet', 'critical_infra'],
                        default='internet', help='Network exposure level for QARS scoring')
    # Auto-fix
    parser.add_argument('--compliance-target',
                        choices=['general', 'cnsa-2.0'],
                        default='general',
                        help='PQC parameter strength target. "general" = NIST Cat 3 '
                             '(ML-KEM-768/ML-DSA-65, default); "cnsa-2.0" = NSA Cat 5 '
                             '(ML-KEM-1024/ML-DSA-87, required for NSS deployments).')
    parser.add_argument('--fix', action='store_true',
                        help='Generate auto-fix suggestions for findings')
    # Compliance
    parser.add_argument('--compliance', action='store_true',
                        help='Show compliance analysis (CNSA 2.0, NIST, PCI DSS)')
    # Dependencies
    parser.add_argument('--scan-deps', action='store_true',
                        help='Also scan dependency manifests and lock files')
    # Readiness grade
    parser.add_argument('--grade', action='store_true',
                        help='Show PQC readiness grade (A+ to F)')
    # Quality gate
    parser.add_argument('--gate', choices=['pqc-ready', 'no-critical',
                        'cnsa-compliant', 'migration-safe'],
                        help='Evaluate a quality gate (exit 1 if failed)')
    # Custom rules
    parser.add_argument('--rules', help='Path to custom .pqcrules.yml file')
    # History
    parser.add_argument('--history', action='store_true',
                        help='Show scan history and trends')
    parser.add_argument('--record', action='store_true',
                        help='Record this scan to history database')
    # Migration estimator
    parser.add_argument('--estimate', action='store_true',
                        help='Show migration effort/cost estimate')
    # Reachability analysis
    parser.add_argument('--reachability', action='store_true',
                        help='Verify if crypto dependencies are actually called in source')
    parser.add_argument('--hourly-rate', type=float, default=150,
                        help='Hourly rate for cost estimation (default: $150)')
    parser.add_argument('--performance', action='store_true',
                        help='Show PQC performance impact comparison')
    # Cutting-edge features
    parser.add_argument('--ai', action='store_true',
                        help='AI-powered finding triage + migration code (requires ANTHROPIC_API_KEY)')
    parser.add_argument('--api-key', help='Anthropic API key for --ai flag')
    parser.add_argument('--enrich-sbom', metavar='SBOM_PATH',
                        help='Enrich a CycloneDX SBOM with PQC risk annotations')
    parser.add_argument('--callgraph', action='store_true',
                        help='Cross-file call graph analysis (all languages via tree-sitter)')
    # Team dashboard
    parser.add_argument('--save-history', action='store_true',
                        help='Save scan results to history for team dashboard tracking')
    parser.add_argument('--history-file', default='.enigma_history.json',
                        help='Path to scan history file (default: .enigma_history.json)')
    parser.add_argument('--scanner-name', default='default',
                        help='Team member name for scan attribution')
    parser.add_argument('--team-dashboard', action='store_true',
                        help='Generate team dashboard from scan history')

    args = parser.parse_args()

    if args.command == 'scan':
        scanner = PQCScanner(
            strip_comments=not args.no_strip_comments,
            strip_strings=args.strip_strings,
        )
        result = scanner.scan(args.path)

        # Tree-sitter deep analysis (if available)
        try:
            from treesitter_scanner import ts_scan_directory, TREE_SITTER_AVAILABLE
            if TREE_SITTER_AVAILABLE:
                ts_findings = ts_scan_directory(args.path)
                existing = {(f.file, f.line, f.algorithm) for f in result.findings}
                added = 0
                for tf in ts_findings:
                    # Type guard: ts_scan_directory should return Finding objects,
                    # but defend against TSFinding leaks that would crash report generators.
                    if not isinstance(tf, Finding):
                        continue
                    if (tf.file, tf.line, tf.algorithm) not in existing:
                        result.findings.append(tf)
                        existing.add((tf.file, tf.line, tf.algorithm))
                        added += 1
                if added > 0:
                    print(f"Tree-sitter: +{added} deep findings across 7 languages")
        except ImportError:
            pass

        # AST scanner (Python-specific, catches what regex misses)
        try:
            from ast_scanner import ast_scan_directory
            ast_findings = ast_scan_directory(args.path)
            existing = {(f.file, f.line, f.algorithm) for f in result.findings}
            for af in ast_findings:
                if (af.file, af.line, af.algorithm) not in existing:
                    result.findings.append(af)
        except ImportError:
            pass

        # Dependency scanning
        if args.scan_deps:
            try:
                from dependency_scanner import scan_dependencies, format_dep_report
                dep_findings = scan_dependencies(args.path)
                if dep_findings:
                    print(f"\nDependencies: {len(dep_findings)} crypto packages found")
                    print(format_dep_report(dep_findings))
            except ImportError:
                pass

        # Filter by severity
        sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        min_idx = sev_order.index(args.severity.upper())
        result.findings = [f for f in result.findings if sev_order.index(f.severity.value) <= min_idx]
        result.compute_summary()

        # Baseline diff
        if args.baseline:
            diff = diff_against_baseline(result, args.baseline)
            print(f"Baseline: {len(diff['new'])} new, "
                  f"{len(diff['existing'])} existing, {len(diff['fixed'])} fixed")
            result.findings = diff['new']
            result.compute_summary()

        if scanner.suppressed_count > 0:
            print(f"Suppressed: {scanner.suppressed_count} findings")

        # Format and output report
        if args.format == 'dashboard':
            try:
                from dashboard import generate_dashboard
                from readiness import compute_readiness_grade
                from compliance import get_all_deadlines, compute_qars
                from autofix import generate_fixes

                rg = compute_readiness_grade(result, args.sensitivity, args.exposure)
                algos = list(set(f.algorithm for f in result.findings))
                dls = get_all_deadlines(algos)
                fixes = generate_fixes(result.findings, args.path,
                                       compliance_target=args.compliance_target)

                output = generate_dashboard(
                    result,
                    grade_info={'grade': rg.grade, 'score': rg.score,
                               'summary': rg.summary, 'recommendations': rg.recommendations},
                    deadline_info=[{'algorithm': d.algorithm, 'days_remaining': d.days_remaining,
                                    'deadline_date': str(d.deadline_date), 'urgency': d.urgency}
                                   for d in dls],
                    fix_info=[f.to_dict() for f in fixes[:10]],
                )
            except ImportError:
                output = format_html_report(result)
        else:
            formatters = {
                'text': format_text_report, 'json': format_json_report,
                'html': format_html_report, 'sarif': format_sarif_report,
                'cbom': format_cbom_report,
            }
            output = formatters[args.format](result)

        if args.output:
            # Atomic write: tempfile + os.replace prevents truncated/corrupt reports
            # if the process is interrupted (critical for CI gate behavior).
            import tempfile as _tempfile
            out_path = os.path.abspath(args.output)
            out_dir = os.path.dirname(out_path) or '.'
            os.makedirs(out_dir, exist_ok=True)
            fd, tmp = _tempfile.mkstemp(dir=out_dir, suffix='.pqc-out')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline='') as _f:
                    _f.write(output)
                os.replace(tmp, out_path)
                print(f"Report saved to {out_path}")
            except OSError as e:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                print(f"Failed to write report: {e}", file=sys.stderr)
        else:
            # Windows console (cp1252) cannot print Unicode arrows/bullets.
            # Fallback to ASCII-safe output on encoding failure.
            try:
                print(output)
            except UnicodeEncodeError:
                enc = (sys.stdout.encoding or 'ascii')
                sys.stdout.write(output.encode(enc, errors='replace').decode(enc, errors='replace'))
                sys.stdout.write('\n')
                sys.stdout.flush()

        # QARS scoring (always shown for text, opt-in for others)
        if result.findings:
            try:
                from compliance import compute_qars, format_qars_report
                qars = compute_qars(result,
                                    sensitivity=args.sensitivity,
                                    exposure=args.exposure)
                print(f"\nQARS Score: {qars.overall_score}/100 (Grade: {qars.grade})")
                print(f"  Highest risk: {qars.highest_risk_algo} ({qars.highest_risk_value:.0%})")
            except ImportError:
                pass

        # Compliance analysis
        if args.compliance and result.findings:
            try:
                from compliance import analyze_compliance, format_compliance_report
                compliance = analyze_compliance(result)
                print(format_compliance_report(compliance))
            except ImportError:
                pass

        # Custom rules
        if args.rules:
            try:
                from rules_engine import load_rules_from_yaml, scan_with_rules
                custom_rules = load_rules_from_yaml(args.rules)
                if custom_rules:
                    for filepath in _walk_source_files(
                            args.path,
                            ('.py', '.java', '.go', '.js', '.ts', '.rs', '.c', '.cpp')):
                        try:
                            content = filepath.read_text(encoding='utf-8', errors='ignore')
                            rule_findings = scan_with_rules(custom_rules, str(filepath), content)
                            result.findings.extend(rule_findings)
                        except OSError:
                            pass
                    result.compute_summary()
                    print(f"Custom rules: {len(custom_rules)} rules loaded")
            except ImportError:
                pass

        # Built-in extended rules (JWT, SSH, hardcoded keys)
        try:
            from rules_engine import BUILTIN_RULES, scan_with_rules
            existing = {(f.file, f.line, f.algorithm) for f in result.findings}
            for filepath in _walk_source_files(
                    args.path, ('.py', '.java', '.go', '.js', '.ts')):
                try:
                    content = filepath.read_text(encoding='utf-8', errors='ignore')
                    rule_findings = scan_with_rules(BUILTIN_RULES, str(filepath), content)
                    for rf in rule_findings:
                        if (rf.file, rf.line, rf.algorithm) not in existing:
                            result.findings.append(rf)
                            existing.add((rf.file, rf.line, rf.algorithm))
                except OSError:
                    pass
            result.compute_summary()
        except ImportError:
            pass

        # PQC Readiness Grade
        readiness_grade = None
        if args.grade or args.gate:
            try:
                from readiness import compute_readiness_grade, format_readiness_report
                readiness_grade = compute_readiness_grade(
                    result, sensitivity=args.sensitivity, exposure=args.exposure)
                if args.grade:
                    print(format_readiness_report(readiness_grade))
            except ImportError:
                pass

        # Quality Gate
        gate_failed = False
        if args.gate:
            try:
                from readiness import evaluate_gate, format_gate_result
                gate_result = evaluate_gate(
                    args.gate, result, readiness_grade,
                    sensitivity=args.sensitivity, exposure=args.exposure)
                print(format_gate_result(gate_result))
                if not gate_result.passed:
                    gate_failed = True
            except ImportError:
                pass

        # Auto-fix suggestions
        if args.fix and result.findings:
            try:
                from autofix import generate_fixes, format_fix_report
                fixes = generate_fixes(result.findings, args.path,
                                       compliance_target=args.compliance_target)
                print(format_fix_report(fixes))
            except ImportError:
                pass

        # Reachability analysis
        if args.reachability and args.scan_deps:
            try:
                from dependency_scanner import scan_dependencies
                from reachability import analyze_reachability, format_reachability_report
                dep_findings = scan_dependencies(args.path)
                dep_packages = list(set(d.package for d in dep_findings))
                if dep_packages:
                    reach_results = analyze_reachability(args.path, dep_packages)
                    print(format_reachability_report(reach_results))
            except ImportError:
                pass

        # Backward slicing to resolve crypto parameters
        try:
            from reachability import resolve_crypto_call_parameters
            # Pre-build index for O(1) lookup instead of O(n) list.index per finding.
            _finding_index = {id(f): i for i, f in enumerate(result.findings)}
            for fpath in _walk_source_files(args.path, ('.py',)):
                try:
                    src = fpath.read_text(encoding='utf-8', errors='ignore')
                    file_findings = [f for f in result.findings if f.file == str(fpath)]
                    if file_findings:
                        enhanced = resolve_crypto_call_parameters(src, file_findings, str(fpath))
                        for orig, enh in zip(file_findings, enhanced):
                            if enh.description != orig.description:
                                idx = _finding_index.get(id(orig))
                                if idx is not None:
                                    result.findings[idx] = enh
                except OSError:
                    pass
        except ImportError:
            pass

        # Migration effort estimate
        if args.estimate and result.findings:
            try:
                from migration_estimator import estimate_migration, format_effort_report
                estimation = estimate_migration(result, hourly_rate=args.hourly_rate)
                print(format_effort_report(estimation))
            except ImportError:
                pass

        # Performance impact comparison
        if args.performance:
            try:
                from migration_estimator import format_performance_table
                print(format_performance_table())
            except ImportError:
                pass

        # Record to history
        if args.record:
            try:
                from history import record_scan
                grade_val = readiness_grade.grade if readiness_grade else '?'
                qars_val = 0.0
                try:
                    from compliance import compute_qars
                    qars_val = compute_qars(result, args.sensitivity, args.exposure).overall_score
                except ImportError:
                    pass
                record_scan(result, grade=grade_val, qars_score=qars_val)
                print("Scan recorded to history.")
            except ImportError:
                pass

        # Show history
        if args.history:
            try:
                from history import format_history_report
                project = os.path.basename(os.path.abspath(args.path))
                print(format_history_report(project))
            except ImportError:
                pass

        # AI-powered triage
        if args.ai and result.findings:
            try:
                from ai_triage import triage_findings, format_triage_report, filter_false_positives
                print("\nRunning AI triage (Claude API)...")
                triage_results = triage_findings(result.findings, api_key=args.api_key)
                print(format_triage_report(triage_results))
                # Filter false positives from findings if confidence is high
                result.findings = filter_false_positives(result.findings, triage_results)
                result.compute_summary()
                print(f"After AI triage: {len(result.findings)} findings remaining")
            except (ImportError, ValueError) as e:
                print(f"AI triage unavailable: {e}")

        # SBOM enrichment
        if args.enrich_sbom:
            try:
                from sbom_enrichment import enrich_sbom, format_enrichment_report
                output = args.output or args.enrich_sbom.replace('.json', '_enriched.json')
                enriched = enrich_sbom(args.enrich_sbom, scan_path=args.path, output_path=output)
                print(format_enrichment_report(enriched))
                print(f"Enriched SBOM written to: {output}")
            except (ImportError, ValueError, OSError) as e:
                print(f"SBOM enrichment failed: {e}")

        # Cross-file call graph analysis
        if args.callgraph:
            try:
                from callgraph import analyze_callgraph, format_callgraph_report
                cg_result = analyze_callgraph(args.path, findings=result.findings)
                print(format_callgraph_report(cg_result))
            except ImportError as e:
                print(f"Call graph analysis unavailable: {e}")

        # Save scan to history (for team dashboard)
        if args.save_history:
            try:
                from dashboard import ScanHistoryEntry, save_scan_to_history
                grade_str = '?'
                pqc_pct = 0.0
                try:
                    from readiness import compute_readiness_grade
                    rg = compute_readiness_grade(result)
                    grade_str = rg.grade
                    pqc_pct = rg.score
                except ImportError:
                    pass
                entry = ScanHistoryEntry.from_scan_result(
                    result, scanner=args.scanner_name,
                    grade=grade_str, pqc_ready_pct=pqc_pct)
                save_scan_to_history(entry, args.history_file)
                print(f"Scan saved to history: {args.history_file}")
            except ImportError as e:
                print(f"History save unavailable: {e}")

        # Team dashboard
        if args.team_dashboard:
            try:
                from dashboard import load_scan_history, generate_team_dashboard
                history = load_scan_history(args.history_file)
                if history:
                    output_path = args.output or 'team_dashboard.html'
                    html_content = generate_team_dashboard(history)
                    import tempfile as _td_tmp
                    _td_dir = os.path.dirname(os.path.abspath(output_path)) or '.'
                    os.makedirs(_td_dir, exist_ok=True)
                    _td_fd, _td_tmp_path = _td_tmp.mkstemp(dir=_td_dir, suffix='.html')
                    try:
                        with os.fdopen(_td_fd, 'w', encoding='utf-8') as f:
                            f.write(html_content)
                        os.replace(_td_tmp_path, output_path)
                    except OSError:
                        try:
                            os.unlink(_td_tmp_path)
                        except OSError:
                            pass
                        raise
                    print(f"Team dashboard written to: {output_path}")
                else:
                    print("No scan history found. Run scans with --save-history first.")
            except ImportError as e:
                print(f"Team dashboard unavailable: {e}")

        # Exit codes: gate failure > critical findings > any findings
        if gate_failed:
            sys.exit(3)  # Quality gate failed
        if result.summary.get('CRITICAL', 0) > 0:
            sys.exit(2)
        elif len(result.findings) > 0:
            sys.exit(1)
        sys.exit(0)

    elif args.command == 'scan-certs':
        findings = scan_certificates_in_path(args.path)
        for f in findings:
            print(f"[{f.severity.value}] {f.algorithm}-{f.key_size}: {f.cert_subject}")
            print(f"  {f.description}")
            print(f"  Expires: {f.not_after}")
            print(f"  Fix: {f.recommendation}")
            print()
        if not findings:
            print("No certificates found.")

    elif args.command == 'scan-tls':
        host_port = args.path.split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443
        findings = scan_tls_endpoint(host, port)
        for f in findings:
            print(f"[{f.severity.value}] {f.algorithm}-{f.key_size}: {f.cert_subject}")
            print(f"  {f.description}")
            print(f"  Expires: {f.not_after}")
            print(f"  Fix: {f.recommendation}")
            print()
        if not findings:
            print(f"Could not retrieve certificate from {host}:{port}")


if __name__ == '__main__':
    try:
        main()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        sys.exit(130)
