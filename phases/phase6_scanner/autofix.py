"""
Enigma pqc-scanner v4.0: Auto-Fix Engine.

Generates code transformation suggestions for migrating quantum-vulnerable
cryptography to post-quantum alternatives. Three confidence tiers:

  Tier 1 — Deterministic (safe to auto-apply):
    MD5/SHA-1 → SHA-256, DES/3DES → AES-256-GCM, TLS 1.0 → 1.3

  Tier 2 — Template (structurally sound, needs review):
    RSA keygen → hybrid ML-KEM, ECDSA → ML-DSA pattern

  Tier 3 — Advisory (complex, manual only):
    Architectural changes, protocol redesigns

Output: Unified diff format, compatible with `git apply`.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pqc_scanner import Finding, Severity


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass
class FixSuggestion:
    """A suggested code fix for a quantum-vulnerable finding."""
    finding_id: str
    file: str
    line: int
    tier: int               # 1=deterministic, 2=template, 3=advisory
    confidence: str         # HIGH, MEDIUM, LOW
    original: str           # Original line of code
    replacement: str        # Suggested replacement
    explanation: str        # Why this change is needed
    algorithm_before: str   # e.g., 'MD5'
    algorithm_after: str    # e.g., 'SHA-256'

    def to_diff(self) -> str:
        """Generate unified diff format for this fix.

        Handles both single-line (Tier 1) and multi-line (Tier 2) replacements.
        """
        rel_path = self.file.replace('\\', '/')
        fname = os.path.basename(rel_path)
        orig_lines = self.original.rstrip('\n').split('\n')
        repl_lines = self.replacement.rstrip('\n').split('\n')
        orig_count = len(orig_lines)
        repl_count = len(repl_lines)
        header = (
            f"--- a/{fname}\n"
            f"+++ b/{fname}\n"
            f"@@ -{self.line},{orig_count} +{self.line},{repl_count} @@\n"
        )
        diff_body = ''.join(f'-{line}\n' for line in orig_lines)
        diff_body += ''.join(f'+{line}\n' for line in repl_lines)
        return header + diff_body

    def to_dict(self) -> dict:
        return {
            'finding_id': self.finding_id,
            'file': self.file,
            'line': self.line,
            'tier': self.tier,
            'confidence': self.confidence,
            'original': self.original,
            'replacement': self.replacement,
            'explanation': self.explanation,
            'algorithm_before': self.algorithm_before,
            'algorithm_after': self.algorithm_after,
        }


# ============================================================================
# TIER 1 — DETERMINISTIC TRANSFORMS
# ============================================================================

# (regex_pattern, replacement_func, algorithm_before, algorithm_after, explanation)
TIER1_PYTHON = [
    # MD5 → SHA-256
    (r'hashlib\.md5\b', 'hashlib.sha256',
     'MD5', 'SHA-256', 'MD5 is completely broken. SHA-256 is the minimum secure hash.'),
    (r"hashlib\.new\(['\"]md5['\"]\)", "hashlib.new('sha256')",
     'MD5', 'SHA-256', 'MD5 is completely broken. SHA-256 is the minimum secure hash.'),
    # SHA-1 → SHA-256
    (r'hashlib\.sha1\b', 'hashlib.sha256',
     'SHA-1', 'SHA-256', 'SHA-1 is collision-broken since 2017. Upgrade to SHA-256.'),
    (r"hashlib\.new\(['\"]sha1['\"]\)", "hashlib.new('sha256')",
     'SHA-1', 'SHA-256', 'SHA-1 is collision-broken since 2017.'),
    # DES → AES-256
    (r'from Crypto\.Cipher import DES\b', 'from Crypto.Cipher import AES',
     '3DES', 'AES-256', 'DES is deprecated. Use AES-256-GCM.'),
    (r'from Crypto\.Cipher import DES3', 'from Crypto.Cipher import AES',
     '3DES', 'AES-256', '3DES is deprecated. Use AES-256-GCM.'),
    (r'DES\.new\(', 'AES.new(',
     '3DES', 'AES-256', 'Replace DES cipher with AES-256.'),
    (r'DES3\.new\(', 'AES.new(',
     '3DES', 'AES-256', 'Replace 3DES cipher with AES-256.'),
    # Blowfish → AES
    (r'from Crypto\.Cipher import Blowfish', 'from Crypto.Cipher import AES',
     'Blowfish', 'AES-256', 'Blowfish is deprecated. Use AES-256-GCM.'),
    (r'Blowfish\.new\(', 'AES.new(',
     'Blowfish', 'AES-256', 'Replace Blowfish with AES-256.'),
    # RC4 → AES
    (r'from Crypto\.Cipher import ARC4', 'from Crypto.Cipher import AES',
     'RC4', 'AES-256', 'RC4 is broken. Use AES-256-GCM.'),
]

TIER1_JAVA = [
    # MD5 → SHA-256
    (r'MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)',
     'MessageDigest.getInstance("SHA-256")',
     'MD5', 'SHA-256', 'MD5 is broken. Use SHA-256.'),
    # SHA-1 → SHA-256
    (r'MessageDigest\.getInstance\s*\(\s*"SHA-1"\s*\)',
     'MessageDigest.getInstance("SHA-256")',
     'SHA-1', 'SHA-256', 'SHA-1 is collision-broken. Use SHA-256.'),
    # DES → AES
    (r'Cipher\.getInstance\s*\(\s*"DES[^"]*"\s*\)',
     'Cipher.getInstance("AES/GCM/NoPadding")',
     '3DES', 'AES-256-GCM', 'DES/3DES deprecated. Use AES-256-GCM.'),
    (r'Cipher\.getInstance\s*\(\s*"DESede[^"]*"\s*\)',
     'Cipher.getInstance("AES/GCM/NoPadding")',
     '3DES', 'AES-256-GCM', '3DES deprecated. Use AES-256-GCM.'),
    # ECB → GCM
    (r'Cipher\.getInstance\s*\(\s*"AES/ECB/[^"]*"\s*\)',
     'Cipher.getInstance("AES/GCM/NoPadding")',
     'AES-ECB', 'AES-256-GCM', 'ECB mode leaks patterns. Use GCM for authenticated encryption.'),
]

TIER1_GO = [
    (r'crypto/des', 'crypto/aes',
     '3DES', 'AES-256', 'DES deprecated. Use AES.'),
    (r'des\.NewCipher', 'aes.NewCipher',
     '3DES', 'AES-256', 'Replace DES with AES.'),
    (r'crypto/md5', 'crypto/sha256',
     'MD5', 'SHA-256', 'MD5 broken. Use SHA-256.'),
    (r'md5\.New\(\)', 'sha256.New()',
     'MD5', 'SHA-256', 'MD5 broken. Use SHA-256.'),
    (r'crypto/sha1', 'crypto/sha256',
     'SHA-1', 'SHA-256', 'SHA-1 collision-broken. Use SHA-256.'),
    (r'sha1\.New\(\)', 'sha256.New()',
     'SHA-1', 'SHA-256', 'SHA-1 collision-broken. Use SHA-256.'),
]

TIER1_CONFIG = [
    # TLS version upgrades
    (r'ssl_protocols\s+.*TLSv1\b[^.23]',
     'ssl_protocols TLSv1.2 TLSv1.3;',
     'Old TLS', 'TLS 1.3', 'TLS 1.0 is deprecated. Use TLS 1.2+.'),
    (r'SSLProtocol\s+.*SSLv3',
     'SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1',
     'SSLv3', 'TLS 1.2+', 'SSLv3 is broken. Disable it.'),
    # Weak cipher suites
    (r'ssl_ciphers.*RC4',
     'ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;',
     'RC4', 'AES-256-GCM', 'RC4 is broken. Use modern cipher suites.'),
]

_TIER1_BY_EXT = {
    '.py': TIER1_PYTHON,
    '.java': TIER1_JAVA,
    '.go': TIER1_GO,
    '.conf': TIER1_CONFIG,
    '.cfg': TIER1_CONFIG,
}


# ============================================================================
# TIER 2 — TEMPLATE TRANSFORMS
# ============================================================================

TIER2_TRANSFORMS = {
    # ========== PYTHON ==========
    'RSA_KEYGEN_PYTHON': {
        'pattern': r'(\s*).*rsa\.generate_private_key\s*\(',
        'ext': '.py',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 (hybrid)',
        'explanation': (
            'RSA is broken by Shor\'s algorithm. Replaced with ML-KEM-768 '
            'key encapsulation via liboqs. REVIEW-REQUIRED: KEM API differs '
            'from RSA keypair — callers must adapt to encap/decap pattern.'
        ),
        'replacement': (
            '{indent}# REVIEW-REQUIRED: PQC migration — RSA → ML-KEM-768\n'
            '{indent}# Original: {original}\n'
            '{indent}from oqs import KeyEncapsulation  # pip install liboqs-python\n'
            '{indent}kem = KeyEncapsulation("ML-KEM-768")\n'
            '{indent}pqc_public_key = kem.generate_keypair()\n'
            '{indent}# Encapsulate: ciphertext, shared_secret = kem.encap_secret(peer_pk)\n'
            '{indent}# Decapsulate: shared_secret = kem.decap_secret(ciphertext)'
        ),
    },
    'ECDSA_SIGN_PYTHON': {
        'pattern': r'(\s*).*ec\.ECDSA\(',
        'ext': '.py',
        'algorithm_before': 'ECDSA',
        'algorithm_after': 'ML-DSA-65',
        'explanation': (
            'ECDSA is broken by Shor\'s algorithm. Replaced with ML-DSA-65 '
            '(FIPS 204) digital signatures via liboqs. REVIEW-REQUIRED: '
            'Signature format and key size differ from ECDSA.'
        ),
        'replacement': (
            '{indent}# REVIEW-REQUIRED: PQC migration — ECDSA → ML-DSA-65\n'
            '{indent}# Original: {original}\n'
            '{indent}from oqs import Signature  # pip install liboqs-python\n'
            '{indent}signer = Signature("ML-DSA-65")\n'
            '{indent}pqc_public_key = signer.generate_keypair()\n'
            '{indent}# Sign: signature = signer.sign(message)\n'
            '{indent}# Verify: is_valid = signer.verify(message, signature, pqc_public_key)'
        ),
    },
    'ECDH_PYTHON': {
        'pattern': r'(\s*).*ec\.ECDH\(',
        'ext': '.py',
        'algorithm_before': 'ECDH',
        'algorithm_after': 'ML-KEM-768',
        'explanation': (
            'ECDH key exchange is broken by Shor\'s algorithm. Replaced with '
            'ML-KEM-768 key encapsulation. REVIEW-REQUIRED: KEM is a different '
            'primitive than DH — one party encapsulates, the other decapsulates.'
        ),
        'replacement': (
            '{indent}# REVIEW-REQUIRED: PQC migration — ECDH → ML-KEM-768\n'
            '{indent}# Original: {original}\n'
            '{indent}from oqs import KeyEncapsulation  # pip install liboqs-python\n'
            '{indent}kem = KeyEncapsulation("ML-KEM-768")\n'
            '{indent}pqc_public_key = kem.generate_keypair()\n'
            '{indent}# Encapsulate: ciphertext, shared_secret = kem.encap_secret(peer_pk)'
        ),
    },
    'DSA_KEYGEN_PYTHON': {
        'pattern': r'(\s*).*dsa\.generate_private_key\s*\(',
        'ext': '.py',
        'algorithm_before': 'DSA',
        'algorithm_after': 'ML-DSA-65',
        'explanation': (
            'DSA is broken by Shor\'s algorithm. Replaced with ML-DSA-65 '
            '(FIPS 204) digital signatures.'
        ),
        'replacement': (
            '{indent}# REVIEW-REQUIRED: PQC migration — DSA → ML-DSA-65\n'
            '{indent}# Original: {original}\n'
            '{indent}from oqs import Signature  # pip install liboqs-python\n'
            '{indent}signer = Signature("ML-DSA-65")\n'
            '{indent}pqc_public_key = signer.generate_keypair()'
        ),
    },
    # ========== JAVA ==========
    'RSA_KEYGEN_JAVA': {
        'pattern': r'(\s*).*KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)',
        'ext': '.java',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 (BouncyCastle)',
        'explanation': (
            'RSA key generation replaced with ML-KEM-768 via BouncyCastle 1.78+. '
            'REVIEW-REQUIRED: ML-KEM is a KEM, not an asymmetric keypair — '
            'callers must use KEM encapsulation API.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — RSA → ML-KEM-768\n'
            '{indent}// Original: {original}\n'
            '{indent}Security.addProvider(new BouncyCastleProvider());\n'
            '{indent}KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");\n'
            '{indent}kpg.initialize(new MLKEMParameterSpec(MLKEMParameterSpec.ml_kem_768));\n'
            '{indent}KeyPair pqcKeyPair = kpg.generateKeyPair();'
        ),
    },
    'RSA_CIPHER_JAVA': {
        'pattern': r'(\s*).*Cipher\.getInstance\s*\(\s*"RSA[^"]*"\s*\)',
        'ext': '.java',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 + AES-GCM (hybrid)',
        'explanation': (
            'RSA encryption replaced with ML-KEM key encapsulation + AES-GCM '
            'for data encryption. REVIEW-REQUIRED: Two-step process — '
            'KEM generates shared secret, AES-GCM encrypts payload.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — RSA cipher → ML-KEM + AES-GCM\n'
            '{indent}// Original: {original}\n'
            '{indent}// Step 1: ML-KEM key encapsulation for shared secret\n'
            '{indent}KeyPairGenerator kemKpg = KeyPairGenerator.getInstance("ML-KEM", "BC");\n'
            '{indent}kemKpg.initialize(new MLKEMParameterSpec(MLKEMParameterSpec.ml_kem_768));\n'
            '{indent}// Step 2: Use shared secret with AES-GCM for data encryption\n'
            '{indent}Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");'
        ),
    },
    'ECDSA_JAVA': {
        'pattern': r'(\s*).*Signature\.getInstance\s*\(\s*".*EC[^"]*"\s*\)',
        'ext': '.java',
        'algorithm_before': 'ECDSA',
        'algorithm_after': 'ML-DSA-65 (BouncyCastle)',
        'explanation': (
            'ECDSA signature replaced with ML-DSA-65 (FIPS 204) via '
            'BouncyCastle. REVIEW-REQUIRED: Signature sizes differ — '
            'ML-DSA-65 signatures are ~3,300 bytes vs ECDSA ~72 bytes.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — ECDSA → ML-DSA-65\n'
            '{indent}// Original: {original}\n'
            '{indent}Security.addProvider(new BouncyCastleProvider());\n'
            '{indent}Signature sig = Signature.getInstance("ML-DSA", "BC");'
        ),
    },
    # ========== GO ==========
    'RSA_KEYGEN_GO': {
        'pattern': r'(\s*).*rsa\.GenerateKey\s*\(',
        'ext': '.go',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 (circl)',
        'explanation': (
            'RSA key generation replaced with ML-KEM-768 via Cloudflare circl. '
            'REVIEW-REQUIRED: KEM API differs from RSA keypair.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — RSA → ML-KEM-768\n'
            '{indent}// Original: {original}\n'
            '{indent}// import "github.com/cloudflare/circl/kem/mlkem/mlkem768"\n'
            '{indent}pqcPublicKey, pqcPrivateKey, err := mlkem768.GenerateKeyPair(rand.Reader)'
        ),
    },
    'ECDSA_KEYGEN_GO': {
        'pattern': r'(\s*).*ecdsa\.GenerateKey\s*\(',
        'ext': '.go',
        'algorithm_before': 'ECDSA',
        'algorithm_after': 'ML-DSA-65 (circl)',
        'explanation': (
            'ECDSA replaced with ML-DSA-65 via Cloudflare circl.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — ECDSA → ML-DSA-65\n'
            '{indent}// Original: {original}\n'
            '{indent}// import "github.com/cloudflare/circl/sign/mldsa/mldsa65"\n'
            '{indent}pqcPublicKey, pqcPrivateKey, err := mldsa65.GenerateKey(rand.Reader)'
        ),
    },
    # ========== C# ==========
    'RSA_CSHARP': {
        'pattern': r'(\s*).*RSA\.Create\s*\(',
        'ext': '.cs',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 (BouncyCastle)',
        'explanation': (
            'RSA replaced with ML-KEM-768. C# support via BouncyCastle.Cryptography NuGet.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — RSA → ML-KEM-768\n'
            '{indent}// Original: {original}\n'
            '{indent}// Install: dotnet add package BouncyCastle.Cryptography\n'
            '{indent}var kemGen = new MLKemKeyPairGenerator();\n'
            '{indent}kemGen.Init(new MLKemKeyGenerationParameters(new SecureRandom(), MLKemParameters.ml_kem_768));\n'
            '{indent}var pqcKeyPair = kemGen.GenerateKeyPair();'
        ),
    },
    # ========== KOTLIN ==========
    'RSA_KEYGEN_KOTLIN': {
        'pattern': r'(\s*).*KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)',
        'ext': '.kt',
        'algorithm_before': 'RSA',
        'algorithm_after': 'ML-KEM-768 (BouncyCastle)',
        'explanation': (
            'RSA replaced with ML-KEM-768 via BouncyCastle.'
        ),
        'replacement': (
            '{indent}// REVIEW-REQUIRED: PQC migration — RSA → ML-KEM-768\n'
            '{indent}// Original: {original}\n'
            '{indent}Security.addProvider(BouncyCastleProvider())\n'
            '{indent}val kpg = KeyPairGenerator.getInstance("ML-KEM", "BC")\n'
            '{indent}kpg.initialize(MLKEMParameterSpec(MLKEMParameterSpec.ml_kem_768))\n'
            '{indent}val pqcKeyPair = kpg.generateKeyPair()'
        ),
    },
}

# Backward compatibility alias
TIER2_TEMPLATES = {
    k: {**v, 'replacement_comment': v['replacement'].replace('{indent}', '').replace('{original}', '...')}
    for k, v in TIER2_TRANSFORMS.items()
}


# ============================================================================
# FIX ENGINE
# ============================================================================

def _upgrade_for_cnsa2(text: str) -> str:
    """
    Replace general-purpose PQC parameters with CNSA 2.0-grade ones.

    NSA CNSA 2.0 requires the highest NIST PQC parameter sets for NSS deployment:
      ML-KEM-1024  (Cat 5, defends 256-bit AES-equivalent)
      ML-DSA-87    (Cat 5)
      SLH-DSA-256s (Cat 5, when used)

    The default autofix output uses ML-KEM-768 / ML-DSA-65 (NIST Cat 3) which is
    the right choice for general PQC migration, but is NOT acceptable under
    CNSA 2.0 for National Security Systems.
    """
    return (
        text
        .replace("ML-KEM-768", "ML-KEM-1024")
        .replace('"ML-KEM-768"', '"ML-KEM-1024"')
        .replace("'ML-KEM-768'", "'ML-KEM-1024'")
        .replace("MLKEM768", "MLKEM1024")
        .replace("ML-DSA-65", "ML-DSA-87")
        .replace('"ML-DSA-65"', '"ML-DSA-87"')
        .replace("'ML-DSA-65'", "'ML-DSA-87'")
    )


def generate_fixes(findings: List[Finding],
                   scan_path: str,
                   compliance_target: str = "general") -> List[FixSuggestion]:
    """Generate fix suggestions for all findings.

    Args:
        findings: scanner findings to fix
        scan_path: scan root path (used for relative file paths in diffs)
        compliance_target: "general" (default, NIST Cat 3 / ML-KEM-768)
                           or "cnsa-2.0" (NSA Cat 5 / ML-KEM-1024 / ML-DSA-87)

    Returns suggestions sorted by tier (deterministic first) then by file.
    """
    cnsa = compliance_target.lower() in ("cnsa-2.0", "cnsa2", "cnsa", "nss")
    suggestions = []

    for f in findings:
        ext = os.path.splitext(f.file)[1].lower()

        # Try Tier 1 — deterministic
        tier1_rules = _TIER1_BY_EXT.get(ext, [])
        # Exact match on algorithm name, handling combined forms like "RSA/ECDSA".
        # Previous prefix matching caused SHA-1 rules to match SHA-256 findings (SHA-256.startswith("SHA")).
        finding_algos = {a.strip().upper() for a in f.algorithm.split('/')}
        for pattern, replacement, algo_before, algo_after, explanation in tier1_rules:
            if algo_before.upper() in finding_algos:
                if re.search(pattern, f.code_snippet, re.IGNORECASE):
                    fixed = re.sub(pattern, replacement, f.code_snippet)
                    if fixed != f.code_snippet:
                        suggestions.append(FixSuggestion(
                            finding_id=f.id, file=f.file, line=f.line,
                            tier=1, confidence='HIGH',
                            original=f.code_snippet, replacement=fixed,
                            explanation=explanation,
                            algorithm_before=algo_before,
                            algorithm_after=algo_after,
                        ))
                        break

        # Try Tier 2 — real code transforms with indent preservation
        for tname, tmpl in TIER2_TRANSFORMS.items():
            # Match by file extension if specified
            if 'ext' in tmpl and ext != tmpl['ext']:
                continue
            match = re.search(tmpl['pattern'], f.code_snippet, re.IGNORECASE)
            if match:
                # Extract indentation from the original line
                indent = ''
                if match.lastindex and match.lastindex >= 1:
                    indent = match.group(1) or ''
                if not indent:
                    indent_match = re.match(r'^(\s*)', f.code_snippet)
                    indent = indent_match.group(1) if indent_match else ''

                # Escape braces in code_snippet to prevent format string injection
                # (scanned code commonly contains {dict_literals} and f-strings)
                safe_original = f.code_snippet.strip().replace('{', '{{').replace('}', '}}')
                replacement = tmpl['replacement'].format(
                    indent=indent,
                    original=safe_original,
                )
                explanation = tmpl['explanation']
                algo_after = tmpl['algorithm_after']
                if cnsa:
                    replacement = _upgrade_for_cnsa2(replacement)
                    explanation = (
                        _upgrade_for_cnsa2(explanation)
                        + " (CNSA 2.0 compliance target: ML-KEM-1024 / ML-DSA-87 required for NSS.)"
                    )
                    algo_after = _upgrade_for_cnsa2(algo_after)
                suggestions.append(FixSuggestion(
                    finding_id=f.id, file=f.file, line=f.line,
                    tier=2, confidence='MEDIUM',
                    original=f.code_snippet,
                    replacement=replacement,
                    explanation=explanation,
                    algorithm_before=tmpl['algorithm_before'],
                    algorithm_after=algo_after,
                ))
                break

    return sorted(suggestions, key=lambda s: (s.tier, s.file, s.line))


def format_fix_report(suggestions: List[FixSuggestion]) -> str:
    """Format fix suggestions as a human-readable report."""
    if not suggestions:
        return "No auto-fix suggestions available for the current findings."

    lines = [
        "=" * 70,
        "  AUTO-FIX SUGGESTIONS — PQC Migration Transforms",
        "=" * 70,
        "",
        f"  Total suggestions: {len(suggestions)}",
        f"    Tier 1 (deterministic, safe to apply): "
        f"{sum(1 for s in suggestions if s.tier == 1)}",
        f"    Tier 2 (template, needs review):       "
        f"{sum(1 for s in suggestions if s.tier == 2)}",
        f"    Tier 3 (advisory, manual only):        "
        f"{sum(1 for s in suggestions if s.tier == 3)}",
        "",
    ]

    for tier in (1, 2, 3):
        tier_fixes = [s for s in suggestions if s.tier == tier]
        if not tier_fixes:
            continue

        tier_names = {1: 'DETERMINISTIC', 2: 'TEMPLATE', 3: 'ADVISORY'}
        conf_names = {1: 'HIGH', 2: 'MEDIUM', 3: 'LOW'}
        lines.append(f"  TIER {tier} — {tier_names[tier]} (confidence: {conf_names[tier]})")
        lines.append("  " + "-" * 60)

        for s in tier_fixes:
            rel_file = os.path.basename(s.file)
            lines.extend([
                f"    [{s.finding_id}] {rel_file}:{s.line}",
                f"      {s.algorithm_before} → {s.algorithm_after}",
                f"      {s.explanation.split(chr(10))[0]}",  # First line only
                "",
            ])
            if s.tier == 1:
                lines.extend([
                    f"      - {s.original.strip()}",
                    f"      + {s.replacement.strip()}",
                    "",
                ])
            elif s.tier == 2:
                for comment_line in s.replacement.strip().split('\n')[:3]:
                    lines.append(f"      {comment_line}")
                lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_unified_diff(suggestions: List[FixSuggestion]) -> str:
    """Generate a unified diff for all Tier 1 suggestions.

    This output is compatible with `git apply` for auto-patching.
    """
    diffs = []
    for s in suggestions:
        if s.tier == 1:
            diffs.append(s.to_diff())
    return "\n".join(diffs)


def apply_tier1_fixes(suggestions: List[FixSuggestion]) -> int:
    """Apply Tier 1 deterministic fixes directly to files.

    Returns count of successfully applied fixes.
    Enforces ENIGMA_ALLOWED_ROOT if set — refuses to write outside allowed scope.
    """
    applied = 0
    allowed_root = os.environ.get('ENIGMA_ALLOWED_ROOT', '')
    if allowed_root:
        allowed_root = os.path.abspath(allowed_root)

    # Group by file to minimize reads/writes
    by_file: Dict[str, List[FixSuggestion]] = {}
    for s in suggestions:
        if s.tier != 1:
            continue
        # Path security check: refuse to write outside allowed root
        if allowed_root:
            real_path = os.path.realpath(s.file)
            if not (real_path.startswith(allowed_root + os.sep) or real_path == allowed_root):
                continue  # silently skip — file is outside allowed scope
        by_file.setdefault(s.file, []).append(s)

    import tempfile
    import shutil
    for filepath, fixes in by_file.items():
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
            # Apply in reverse line order to preserve line numbers
            fix_count = 0
            for fix in sorted(fixes, key=lambda f: -f.line):
                idx = fix.line - 1
                if 0 <= idx < len(lines):
                    # Preserve the original line's leading whitespace. fix.replacement comes
                    # from code_snippet which is already stripped, so we must re-indent.
                    orig_line = lines[idx]
                    indent_len = len(orig_line) - len(orig_line.lstrip())
                    indent = orig_line[:indent_len]
                    lines[idx] = indent + fix.replacement.lstrip() + '\n'
                    fix_count += 1
            # Atomic write: write to temp file then rename (prevents corruption)
            dir_name = os.path.dirname(filepath) or '.'
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.pqc-fix')
            try:
                with os.fdopen(fd, 'w', encoding='utf-8', newline='') as tmp_f:
                    tmp_f.writelines(lines)
                shutil.move(tmp_path, filepath)
                applied += fix_count
            except OSError:
                os.unlink(tmp_path)
        except OSError:
            continue
    return applied
