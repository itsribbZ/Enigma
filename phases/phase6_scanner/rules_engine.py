"""
Enigma pqc-scanner v4.0: Custom YAML Rule Engine.

Semgrep-inspired rule format for defining custom crypto detection patterns.
Enterprises can define .pqcrules.yml files to enforce their own crypto policies.

Rule format:
  rules:
    - id: custom-rsa-ban
      severity: CRITICAL
      category: KEY_EXCHANGE
      algorithm: RSA
      message: "RSA usage violates internal crypto policy"
      pattern: "rsa\\.generate|RSA\\.generate|KeyPairGenerator.*RSA"
      languages: [python, java, go]
      fix: "Use ML-KEM-768 via oqs library"
      metadata:
        policy: "CRYPTO-001"
        owner: "security-team"
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from pqc_scanner import Finding, Severity, Category

# Try to import YAML parser
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


# ============================================================================
# RULE DATA MODEL
# ============================================================================

@dataclass
class CustomRule:
    """A custom detection rule."""
    id: str
    severity: Severity
    category: Category
    algorithm: str
    message: str
    pattern: str              # Regex pattern
    languages: List[str]      # Which languages to apply to
    fix: Optional[str] = None
    metadata: Dict[str, str] = field(default_factory=dict)
    _compiled: Optional[re.Pattern] = field(default=None, repr=False)

    def compile(self):
        """Pre-compile the regex pattern."""
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return self._compiled


# Extension → language name mapping
_EXT_LANG = {
    '.py': 'python', '.java': 'java', '.go': 'go',
    '.js': 'javascript', '.ts': 'typescript', '.mjs': 'javascript',
    '.rs': 'rust', '.c': 'c', '.cpp': 'c', '.h': 'c',
    '.conf': 'config', '.cfg': 'config', '.yml': 'yaml', '.yaml': 'yaml',
    '.cs': 'csharp', '.rb': 'ruby', '.php': 'php', '.swift': 'swift',
    '.kt': 'kotlin',
}


# ============================================================================
# RULE LOADING
# ============================================================================

def _parse_severity(s: str) -> Severity:
    """Parse severity string to enum."""
    mapping = {
        'critical': Severity.CRITICAL, 'high': Severity.HIGH,
        'medium': Severity.MEDIUM, 'low': Severity.LOW, 'info': Severity.INFO,
    }
    return mapping.get(s.lower(), Severity.MEDIUM)


def _parse_category(s: str) -> Category:
    """Parse category string to enum."""
    mapping = {
        'key_exchange': Category.KEY_EXCHANGE, 'signature': Category.SIGNATURE,
        'symmetric': Category.SYMMETRIC, 'hash': Category.HASH,
        'certificate': Category.CERTIFICATE, 'protocol': Category.PROTOCOL,
        'dependency': Category.DEPENDENCY,
    }
    return mapping.get(s.lower(), Category.SYMMETRIC)


def load_rules_from_yaml(filepath: str) -> List[CustomRule]:
    """Load custom rules from a YAML file."""
    if not YAML_AVAILABLE:
        return []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError):
        return []

    if not data or 'rules' not in data:
        return []

    rules = []
    for rule_data in data['rules']:
        try:
            rule = CustomRule(
                id=rule_data['id'],
                severity=_parse_severity(rule_data.get('severity', 'medium')),
                category=_parse_category(rule_data.get('category', 'symmetric')),
                algorithm=rule_data.get('algorithm', 'Custom'),
                message=rule_data.get('message', ''),
                pattern=rule_data['pattern'],
                languages=rule_data.get('languages', ['python', 'java', 'go',
                    'javascript', 'typescript', 'rust', 'c']),
                fix=rule_data.get('fix'),
                metadata=rule_data.get('metadata', {}),
            )
            rule.compile()  # Validate regex
            rules.append(rule)
        except (KeyError, re.error):
            continue

    return rules


def load_rules_from_directory(scan_path: str) -> List[CustomRule]:
    """Load rules from .pqcrules.yml files in the scan directory and parents."""
    rules = []
    rule_files = ['.pqcrules.yml', '.pqcrules.yaml', 'pqcrules.yml']

    target = Path(scan_path).resolve()
    search_dirs = [target]
    if target.is_file():
        search_dirs = [target.parent]

    # Also check parent directories (up to 3 levels)
    current = search_dirs[0]
    for _ in range(3):
        parent = current.parent
        if parent != current:
            search_dirs.append(parent)
            current = parent

    for directory in search_dirs:
        for filename in rule_files:
            rule_file = directory / filename
            if rule_file.is_file():
                rules.extend(load_rules_from_yaml(str(rule_file)))

    return rules


# ============================================================================
# RULE SCANNER
# ============================================================================

def scan_with_rules(rules: List[CustomRule], filepath: str,
                    content: str) -> List[Finding]:
    """Scan a file against custom rules."""
    if not rules:
        return []

    ext = Path(filepath).suffix.lower()
    lang = _EXT_LANG.get(ext, '')
    findings = []
    counter = 0

    # ReDoS protection: skip lines longer than this threshold. Real source code
    # rarely has lines > 2000 chars; pathological lines are usually minified/generated.
    _MAX_LINE_LEN = 2000

    lines = content.split('\n')
    for rule in rules:
        if lang not in rule.languages and 'all' not in rule.languages:
            continue

        compiled = rule.compile()
        for line_num, line in enumerate(lines, 1):
            if len(line) > _MAX_LINE_LEN:
                continue  # ReDoS guard: skip pathologically long lines
            if compiled.search(line):
                counter += 1
                rec = rule.fix or 'Review and remediate per custom policy'
                # ID includes rule.id + filepath hash + line for cross-file uniqueness.
                # Per-call counter alone produced RULE-0001 collisions across files in SARIF.
                import hashlib as _rl_hash
                _fhash = _rl_hash.md5(filepath.encode('utf-8', errors='replace')).hexdigest()[:6]
                findings.append(Finding(
                    id=f'RULE-{rule.id}-{_fhash}-L{line_num}',
                    severity=rule.severity,
                    category=rule.category,
                    algorithm=rule.algorithm,
                    file=filepath,
                    line=line_num,
                    code_snippet=line.strip()[:120],
                    description=f'{rule.message} [{rule.id}]',
                    recommendation=rec,
                    pqc_replacement=rule.fix or 'See custom rule policy',
                ))

    return findings


# ============================================================================
# BUILT-IN RULE PACKS
# ============================================================================

# These rules ship with the scanner — no YAML needed
BUILTIN_RULES = [
    CustomRule(
        id='pqc-jwt-rsa',
        severity=Severity.HIGH,
        category=Category.SIGNATURE,
        algorithm='RSA',
        message='JWT signed with RSA — quantum-vulnerable',
        pattern=r'["\']RS256["\']|["\']RS384["\']|["\']RS512["\']',
        languages=['python', 'java', 'javascript', 'typescript', 'go'],
        fix='Migrate JWT signing to ML-DSA when supported',
    ),
    CustomRule(
        id='pqc-jwt-ecdsa',
        severity=Severity.HIGH,
        category=Category.SIGNATURE,
        algorithm='ECDSA',
        message='JWT signed with ECDSA — quantum-vulnerable',
        pattern=r'["\']ES256["\']|["\']ES384["\']|["\']ES512["\']',
        languages=['python', 'java', 'javascript', 'typescript', 'go'],
        fix='Migrate JWT signing to ML-DSA when supported',
    ),
    CustomRule(
        id='pqc-ssh-rsa',
        severity=Severity.HIGH,
        category=Category.KEY_EXCHANGE,
        algorithm='RSA',
        message='SSH configured with RSA key — quantum-vulnerable',
        pattern=r'ssh-rsa|id_rsa',
        languages=['python', 'config', 'yaml'],
        fix='Migrate to Ed25519 (interim) then ML-DSA SSH keys',
    ),
    CustomRule(
        id='pqc-hardcoded-key',
        severity=Severity.CRITICAL,
        category=Category.KEY_EXCHANGE,
        algorithm='Hardcoded Key',
        message='Potential hardcoded cryptographic key detected',
        pattern=r'(?:private_key|secret_key|api_key)\s*=\s*["\'][A-Za-z0-9+/=]{20,}["\']',
        languages=['python', 'java', 'javascript', 'typescript', 'go', 'ruby'],
        fix='Use environment variables or a secrets manager',
    ),
]

# Pre-compile all built-in rules
for _rule in BUILTIN_RULES:
    _rule.compile()
