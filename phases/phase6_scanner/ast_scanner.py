"""
Enigma pqc-scanner v3: AST-Based Python Crypto Detection.

Uses Python's ast module to parse source code into Abstract Syntax Trees
and detect cryptographic API usage through import resolution and call analysis.

This catches patterns that regex misses:
  - Aliased imports (from crypto import rsa as r)
  - Indirect calls through variables
  - Crypto in wrapper functions
  - String-based algorithm selection
"""

from __future__ import annotations
import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pqc_scanner import Finding, Severity, Category, REMEDIATION


# ============================================================================
# CRYPTO MODULE DATABASE
# ============================================================================

# Maps fully-qualified module paths to (algorithm, severity, category, description)
CRYPTO_MODULES = {
    # cryptography library
    'cryptography.hazmat.primitives.asymmetric.rsa': ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA module imported'),
    'cryptography.hazmat.primitives.asymmetric.ec': ('ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECC module imported'),
    'cryptography.hazmat.primitives.asymmetric.dsa': ('DSA', Severity.CRITICAL, Category.SIGNATURE, 'DSA module imported'),
    'cryptography.hazmat.primitives.asymmetric.dh': ('DH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'DH module imported'),
    'cryptography.hazmat.primitives.asymmetric.ed25519': ('Ed25519', Severity.HIGH, Category.SIGNATURE, 'Ed25519 module imported'),
    'cryptography.hazmat.primitives.asymmetric.ed448': ('Ed448', Severity.HIGH, Category.SIGNATURE, 'Ed448 module imported'),

    # PyCryptodome
    'Crypto.PublicKey.RSA': ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'PyCrypto RSA imported'),
    'Crypto.PublicKey.ECC': ('ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'PyCrypto ECC imported'),
    'Crypto.PublicKey.DSA': ('DSA', Severity.CRITICAL, Category.SIGNATURE, 'PyCrypto DSA imported'),
    'Crypto.Cipher.DES': ('3DES', Severity.HIGH, Category.SYMMETRIC, 'DES imported'),
    'Crypto.Cipher.DES3': ('3DES', Severity.HIGH, Category.SYMMETRIC, '3DES imported'),
    'Crypto.Cipher.Blowfish': ('Blowfish', Severity.HIGH, Category.SYMMETRIC, 'Blowfish imported'),
    'Crypto.Cipher.ARC4': ('RC4', Severity.HIGH, Category.SYMMETRIC, 'RC4 imported'),

    # Standard library
    'hashlib': (None, None, None, None),  # Handled per-function
}

# Maps function calls to findings
# (module_or_prefix, function_name) → (algorithm, severity, category, desc)
CRYPTO_CALLS = {
    ('rsa', 'generate_private_key'): ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key generation'),
    ('rsa', 'RSAPrivateKey'): ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA private key usage'),
    ('ec', 'generate_private_key'): ('ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECC key generation'),
    ('ec', 'ECDSA'): ('ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECDSA signing'),
    ('ec', 'ECDH'): ('ECDH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'ECDH key exchange'),
    ('dsa', 'generate_private_key'): ('DSA', Severity.CRITICAL, Category.SIGNATURE, 'DSA key generation'),
    ('dh', 'generate_parameters'): ('DH', Severity.CRITICAL, Category.KEY_EXCHANGE, 'DH parameter generation'),
    ('ed25519', 'Ed25519PrivateKey'): ('Ed25519', Severity.HIGH, Category.SIGNATURE, 'Ed25519 key usage'),
    ('RSA', 'generate'): ('RSA', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA key generation (PyCrypto)'),
    ('RSA', 'import_key'): ('RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'RSA key import (PyCrypto)'),
    ('ECC', 'generate'): ('ECDSA', Severity.CRITICAL, Category.SIGNATURE, 'ECC key generation (PyCrypto)'),
    ('DSA', 'generate'): ('DSA', Severity.CRITICAL, Category.SIGNATURE, 'DSA key generation (PyCrypto)'),
    ('DES', 'new'): ('3DES', Severity.HIGH, Category.SYMMETRIC, 'DES cipher instantiation'),
    ('DES3', 'new'): ('3DES', Severity.HIGH, Category.SYMMETRIC, '3DES cipher instantiation'),
    ('Blowfish', 'new'): ('Blowfish', Severity.HIGH, Category.SYMMETRIC, 'Blowfish cipher instantiation'),
    ('ARC4', 'new'): ('RC4', Severity.HIGH, Category.SYMMETRIC, 'RC4 cipher instantiation'),
}

# hashlib function → (algorithm, severity, category, description)
HASHLIB_CALLS = {
    'md5': ('MD5', Severity.HIGH, Category.HASH, 'MD5 hash — completely broken'),
    'sha1': ('SHA-1', Severity.MEDIUM, Category.HASH, 'SHA-1 hash — collision-broken since 2017'),
    'new': None,  # Check the algorithm argument
}

# String constants that indicate algorithm selection
ALGO_STRINGS = {
    'rsa': ('RSA', Severity.HIGH, Category.KEY_EXCHANGE, 'RSA algorithm string reference'),
    'dsa': ('DSA', Severity.HIGH, Category.SIGNATURE, 'DSA algorithm string reference'),
    'ecdsa': ('ECDSA', Severity.HIGH, Category.SIGNATURE, 'ECDSA algorithm string reference'),
    'des': ('3DES', Severity.HIGH, Category.SYMMETRIC, 'DES algorithm string reference'),
    '3des': ('3DES', Severity.HIGH, Category.SYMMETRIC, '3DES algorithm string reference'),
    'blowfish': ('Blowfish', Severity.HIGH, Category.SYMMETRIC, 'Blowfish algorithm string reference'),
    'rc4': ('RC4', Severity.HIGH, Category.SYMMETRIC, 'RC4 algorithm string reference'),
    'md5': ('MD5', Severity.HIGH, Category.HASH, 'MD5 algorithm string reference'),
    'sha-1': ('SHA-1', Severity.MEDIUM, Category.HASH, 'SHA-1 algorithm string reference'),
    'sha1': ('SHA-1', Severity.MEDIUM, Category.HASH, 'SHA-1 algorithm string reference'),
}


# ============================================================================
# AST VISITOR
# ============================================================================

class CryptoASTVisitor(ast.NodeVisitor):
    """Walk a Python AST and detect cryptographic API usage."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.findings: List[Finding] = []
        self._finding_counter = 0
        self._imports: Dict[str, str] = {}  # local_name → fully_qualified_module
        self._from_imports: Dict[str, str] = {}  # local_name → fully_qualified_name

    def _add_finding(self, algo: str, severity: Severity, category: Category,
                     desc: str, line: int, code: str = ''):
        self._finding_counter += 1
        rec, replacement = REMEDIATION.get(algo, (
            'Review and migrate to PQC equivalent', 'Consult NIST PQC standards'))
        self.findings.append(Finding(
            id=f'AST-{self._finding_counter:04d}',
            severity=severity,
            category=category,
            algorithm=algo,
            file=self.filepath,
            line=line,
            code_snippet=code[:120],
            description=f'{desc} (AST analysis)',
            recommendation=rec,
            pqc_replacement=replacement,
        ))

    def visit_Import(self, node: ast.Import):
        """Track `import X` and `import X as Y`.

        Imports are tracked for resolution only — findings are fired at actual
        call sites (visit_Call). Reporting both import and call line for the same
        usage inflates finding counts.
        """
        for alias in node.names:
            local = alias.asname or alias.name.split('.')[-1]
            self._imports[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Track `from X import Y` and `from X import Y as Z`.

        Imports are tracked for resolution only — findings are fired at actual
        call sites.
        """
        if node.module is None:
            return self.generic_visit(node)

        for alias in node.names:
            local = alias.asname or alias.name
            full = f'{node.module}.{alias.name}'
            self._from_imports[local] = full
            self._imports[local] = node.module

            # Imports tracked for resolution only — call-site visitor fires findings.
            # No findings are generated here to avoid duplicate reports.

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Detect crypto function calls."""
        # Handle: module.function() and module.Class.method()
        if isinstance(node.func, ast.Attribute):
            self._check_attribute_call(node)
        # Handle: function() where function was imported
        elif isinstance(node.func, ast.Name):
            self._check_name_call(node)

        # Check string arguments for algorithm names
        self._check_string_args(node)

        self.generic_visit(node)

    def _check_attribute_call(self, node: ast.Call):
        """Check calls like `rsa.generate_private_key()` or `hashlib.sha1()`."""
        attr = node.func
        if not isinstance(attr, ast.Attribute):
            return

        func_name = attr.attr

        # Get the object being called on
        obj_name = None
        if isinstance(attr.value, ast.Name):
            obj_name = attr.value.id
        elif isinstance(attr.value, ast.Attribute):
            # Handle chained: module.submodule.function()
            parts = []
            v = attr.value
            while isinstance(v, ast.Attribute):
                parts.append(v.attr)
                v = v.value
            if isinstance(v, ast.Name):
                parts.append(v.id)
            obj_name = '.'.join(reversed(parts))

        if obj_name is None:
            return

        # Check hashlib special cases
        resolved_module = self._imports.get(obj_name, obj_name)
        if resolved_module == 'hashlib' or obj_name == 'hashlib':
            if func_name in HASHLIB_CALLS:
                info = HASHLIB_CALLS[func_name]
                if info:
                    algo, sev, cat, desc = info
                    self._add_finding(algo, sev, cat, desc, node.lineno,
                                      f'hashlib.{func_name}()')
                elif func_name == 'new' and node.args:
                    # hashlib.new('sha1') — check first argument
                    if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        algo_name = node.args[0].value.lower()
                        if algo_name in ALGO_STRINGS:
                            a, s, c, d = ALGO_STRINGS[algo_name]
                            self._add_finding(a, s, c, f'hashlib.new("{algo_name}")',
                                              node.lineno, f'hashlib.new("{algo_name}")')
            return

        # Check crypto call database
        for (prefix, fname), info in CRYPTO_CALLS.items():
            if (obj_name == prefix or obj_name.endswith('.' + prefix)) and func_name == fname:
                algo, sev, cat, desc = info
                self._add_finding(algo, sev, cat, desc, node.lineno,
                                  f'{obj_name}.{func_name}()')
                return

        # Check resolved imports
        full_from = self._from_imports.get(obj_name, '')
        for (prefix, fname), info in CRYPTO_CALLS.items():
            if full_from.endswith(prefix) and func_name == fname:
                algo, sev, cat, desc = info
                self._add_finding(algo, sev, cat, desc, node.lineno,
                                  f'{obj_name}.{func_name}()')
                return

    def _check_name_call(self, node: ast.Call):
        """Check calls like `generate_private_key()` where the name was imported."""
        name = node.func.id
        full = self._from_imports.get(name, '')

        # Check if this name was imported from a crypto module
        for mod_path, info in CRYPTO_MODULES.items():
            if full.startswith(mod_path):
                algo, sev, cat, desc = info
                if algo:
                    self._add_finding(algo, sev, cat, f'{name}() call — imported from crypto module',
                                      node.lineno, f'{name}()')
                    return

    def _check_string_args(self, node: ast.Call):
        """Check string arguments for algorithm name references."""
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                val = arg.value.lower().strip()
                if val in ALGO_STRINGS:
                    algo, sev, cat, desc = ALGO_STRINGS[val]
                    self._add_finding(algo, sev, cat, desc, node.lineno,
                                      f'...("{arg.value}")')

        for kw in node.keywords:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                val = kw.value.value.lower().strip()
                if val in ALGO_STRINGS:
                    algo, sev, cat, desc = ALGO_STRINGS[val]
                    self._add_finding(algo, sev, cat, desc, node.lineno,
                                      f'...({kw.arg}="{kw.value.value}")')


# ============================================================================
# PUBLIC API
# ============================================================================

def ast_scan_file(filepath: str) -> List[Finding]:
    """Scan a single Python file using AST analysis."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return []  # Can't parse — skip

    visitor = CryptoASTVisitor(filepath)
    visitor.visit(tree)
    return visitor.findings


def ast_scan_directory(path: str) -> List[Finding]:
    """Scan all Python files in a directory using AST analysis."""
    findings = []
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}

    target = Path(path)
    if target.is_file() and target.suffix == '.py':
        return ast_scan_file(str(target))

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if fname.endswith('.py'):
                filepath = os.path.join(dirpath, fname)
                findings.extend(ast_scan_file(filepath))

    return findings
