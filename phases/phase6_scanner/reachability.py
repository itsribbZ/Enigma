"""
Enigma pqc-scanner v4.0: Reachability Analysis + Backward Slicing.

Two enterprise-grade analysis engines:

1. REACHABILITY ANALYSIS:
   Connects dependency scanning to source code analysis.
   For each crypto dependency, verifies if it's actually used.
   Classification: CONFIRMED → REACHABLE → AVAILABLE

2. BACKWARD SLICING:
   When a crypto API call uses variables instead of literals,
   traces backward through assignments to resolve actual values.
   Resolves: algorithm names, key sizes, cipher modes.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pqc_scanner import Finding, Severity, Category

try:
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

try:
    from treesitter_scanner import _get_parser, _EXT_TO_LANG
    _TS_SCANNER_AVAILABLE = True
except ImportError:
    _TS_SCANNER_AVAILABLE = False

# Tree-sitter node types for import statements per language
_IMPORT_TYPES = {
    'python': {'import_statement', 'import_from_statement'},
    'java': {'import_declaration'},
    'go': {'import_spec'},
    'javascript': {'import_statement'},
    'typescript': {'import_statement'},
    'rust': {'use_declaration', 'extern_crate_declaration'},
    'c': {'preproc_include'},
    'csharp': {'using_directive'},
    'ruby': set(),    # require() is a call, handled separately
    'php': {'use_declaration'},
    'kotlin': {'import_header'},
    'swift': {'import_declaration'},
    'scala': {'import_declaration'},
}

# Tree-sitter node types for function calls per language
_CALL_NODE_TYPES = {
    'python': {'call'},
    'java': {'method_invocation', 'object_creation_expression'},
    'go': {'call_expression'},
    'javascript': {'call_expression', 'new_expression'},
    'typescript': {'call_expression', 'new_expression'},
    'rust': {'call_expression', 'macro_invocation'},
    'c': {'call_expression'},
    'csharp': {'invocation_expression', 'object_creation_expression'},
    'ruby': {'call'},
    'php': {'function_call_expression', 'member_call_expression'},
    'kotlin': {'call_expression'},
    'swift': {'call_expression'},
    'scala': {'call_expression'},
}


# ============================================================================
# REACHABILITY ANALYSIS
# ============================================================================

class ReachabilityLevel:
    CONFIRMED = 'CONFIRMED'    # Source code directly calls crypto APIs from this package
    REACHABLE = 'REACHABLE'    # Source code imports the package (crypto usage possible)
    AVAILABLE = 'AVAILABLE'    # Package in deps but never imported in source
    UNKNOWN = 'UNKNOWN'


@dataclass
class ReachabilityResult:
    """Reachability analysis for a dependency."""
    package: str
    level: str                  # CONFIRMED / REACHABLE / AVAILABLE
    import_locations: List[Tuple[str, int]]   # (file, line) where imported
    call_locations: List[Tuple[str, int, str]]  # (file, line, function) where called
    confidence: float           # 0.0-1.0

    def to_dict(self) -> dict:
        return {
            'package': self.package,
            'level': self.level,
            'confidence': self.confidence,
            'import_count': len(self.import_locations),
            'call_count': len(self.call_locations),
            'imports': [{'file': f, 'line': l} for f, l in self.import_locations],
            'calls': [{'file': f, 'line': l, 'function': fn}
                      for f, l, fn in self.call_locations],
        }


# Map pip/npm package names → import names used in source code
_PACKAGE_TO_IMPORTS = {
    # Python
    'cryptography': ['cryptography', 'cryptography.hazmat', 'cryptography.fernet'],
    'pycryptodome': ['Crypto', 'Crypto.Cipher', 'Crypto.PublicKey', 'Crypto.Hash'],
    'pycryptodomex': ['Cryptodome', 'Cryptodome.Cipher', 'Cryptodome.PublicKey'],
    'pyopenssl': ['OpenSSL', 'OpenSSL.crypto', 'OpenSSL.SSL'],
    'paramiko': ['paramiko'],
    'pynacl': ['nacl', 'nacl.signing', 'nacl.public'],
    'rsa': ['rsa'],
    'ecdsa': ['ecdsa'],
    'jwcrypto': ['jwcrypto', 'jwcrypto.jwk', 'jwcrypto.jws'],
    'pyjwt': ['jwt'],
    'bcrypt': ['bcrypt'],
    'certifi': ['certifi'],
    'requests': ['requests'],
    'boto3': ['boto3'],
    'azure_identity': ['azure.identity'],
    'google_auth': ['google.auth'],
    # npm
    'node-rsa': ['node-rsa', 'NodeRSA'],
    'elliptic': ['elliptic'],
    'node-forge': ['node-forge', 'forge'],
    'jsonwebtoken': ['jsonwebtoken', 'jwt'],
    'crypto-js': ['crypto-js', 'CryptoJS'],
    'tweetnacl': ['tweetnacl'],
    # Go
    'crypto/rsa': ['crypto/rsa'],
    'crypto/ecdsa': ['crypto/ecdsa'],
    'crypto/elliptic': ['crypto/elliptic'],
    'golang.org/x/crypto': ['golang.org/x/crypto'],
    'github.com/cloudflare/circl': ['github.com/cloudflare/circl'],
    # Rust
    'rsa_crate': ['rsa'],
    'ring': ['ring'],
    'rustls': ['rustls'],
    'p256': ['p256'],
    'k256': ['k256'],
    'ed25519-dalek': ['ed25519_dalek', 'ed25519'],
}


def _analyze_file_treesitter(fpath: str, content: str,
                              import_names: List[str],
                              import_locs: List[Tuple[str, int]],
                              call_locs: List[Tuple[str, int, str]]) -> None:
    """Use tree-sitter AST to find imports and crypto calls in a source file.

    Provides accurate AST-based detection instead of regex, supporting all
    13 tree-sitter languages with proper syntax awareness.
    """
    if not _TS_SCANNER_AVAILABLE:
        return

    ext = Path(fpath).suffix.lower()
    lang = _EXT_TO_LANG.get(ext)
    if not lang or lang in ('terraform', 'yaml_config', 'docker'):
        return

    parser = _get_parser(lang)
    if not parser:
        return

    try:
        source_bytes = content.encode('utf-8')
        tree = parser.parse(source_bytes)
    except Exception:
        return

    import_types = _IMPORT_TYPES.get(lang, set())
    call_types = _CALL_NODE_TYPES.get(lang, set())
    lines = content.split('\n')

    def _walk_imports(node):
        """Find import statements and match against target packages."""
        if node.type in import_types:
            node_text = node.text.decode('utf-8')
            line_num = node.start_point[0] + 1
            for imp_name in import_names:
                if imp_name in node_text:
                    import_locs.append((fpath, line_num))
                    break
        # Ruby/JS require(): check call nodes for require('package')
        if lang in ('ruby', 'javascript', 'typescript') and node.type in ('call', 'call_expression'):
            node_text = node.text.decode('utf-8')
            if 'require' in node_text:
                for imp_name in import_names:
                    if imp_name in node_text:
                        import_locs.append((fpath, node.start_point[0] + 1))
                        break
        for child in node.children:
            _walk_imports(child)

    def _walk_calls(node):
        """Find crypto API calls in the AST."""
        if node.type in call_types:
            node_text = node.text.decode('utf-8')
            line_num = node.start_point[0] + 1
            # Match against crypto API patterns
            crypto_patterns = [
                'generate_private_key', 'generate_key', 'GenerateKey',
                'getInstance', 'encrypt', 'decrypt', 'sign', 'verify',
                'md5', 'sha1', 'sha256', 'MD5', 'SHA1', 'SHA256',
                'ECDSA', 'ECDH', 'RSA', 'DiffieHellman',
                'Cipher', 'KeyPairGenerator', 'MessageDigest', 'Signature',
                'PrivateKey', 'PublicKey', 'SecretKey',
                'generate_parameters', 'create_default_context', 'SSLContext',
            ]
            for pattern in crypto_patterns:
                if pattern in node_text:
                    # Extract function name from the call
                    func_name = _extract_ts_call_name(node)
                    call_locs.append((fpath, line_num, func_name or 'unknown'))
                    break
        for child in node.children:
            _walk_calls(child)

    _walk_imports(tree.root_node)
    if import_locs:  # Only look for crypto calls if imports found
        _walk_calls(tree.root_node)


def _extract_ts_call_name(node) -> Optional[str]:
    """Extract function name from a tree-sitter call node."""
    func_node = node.child_by_field_name('function')
    if func_node:
        # Simple identifier: foo()
        if func_node.type == 'identifier':
            return func_node.text.decode('utf-8')
        # Attribute access: obj.method()
        attr = func_node.child_by_field_name('attribute')
        if attr:
            return attr.text.decode('utf-8')
        # Return short text
        text = func_node.text.decode('utf-8')
        if len(text) < 60:
            return text
    # Java method_invocation: 'name' field
    name_node = node.child_by_field_name('name')
    if name_node:
        return name_node.text.decode('utf-8')
    # Fallback: first identifier child
    for child in node.children:
        if child.type == 'identifier':
            return child.text.decode('utf-8')
    return None


def analyze_reachability(scan_path: str,
                         dep_packages: List[str]) -> List[ReachabilityResult]:
    """Analyze reachability of crypto dependencies in source code.

    For each package in dep_packages, scans source files to determine
    if the package is imported and if its crypto APIs are called.
    """
    results = []
    target = Path(scan_path)
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}

    # Collect all source files (capped at 10K to prevent OOM on enterprise repos)
    source_files = []
    max_files = 10000
    if target.is_dir():
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in skip]
            for fname in filenames:
                if len(source_files) >= max_files:
                    break
                ext = Path(fname).suffix.lower()
                if ext in ('.py', '.java', '.go', '.js', '.ts', '.rs', '.c', '.cpp',
                           '.cs', '.rb', '.php', '.kt', '.swift', '.scala'):
                    source_files.append(os.path.join(dirpath, fname))

    # Read all source files once
    source_contents: Dict[str, str] = {}
    for fpath in source_files:
        try:
            source_contents[fpath] = Path(fpath).read_text(encoding='utf-8', errors='ignore')
        except OSError:
            pass

    # Analyze each package
    for pkg in dep_packages:
        pkg_normalized = pkg.lower().replace('-', '_').replace('.', '_')
        import_names = _PACKAGE_TO_IMPORTS.get(pkg_normalized, [pkg])

        import_locs: List[Tuple[str, int]] = []
        call_locs: List[Tuple[str, int, str]] = []

        for fpath, content in source_contents.items():
            # Try tree-sitter AST analysis first (accurate, multi-language)
            if _TS_SCANNER_AVAILABLE:
                _analyze_file_treesitter(fpath, content, import_names,
                                         import_locs, call_locs)
                continue

            # Fallback: regex-based detection
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Check imports
                for imp_name in import_names:
                    # Python: import X / from X import Y
                    if re.search(rf'\bimport\s+{re.escape(imp_name)}\b', line):
                        import_locs.append((fpath, line_num))
                    if re.search(rf'\bfrom\s+{re.escape(imp_name)}\b', line):
                        import_locs.append((fpath, line_num))
                    # JS: require('X')
                    if re.search(rf"require\s*\(\s*['\"].*{re.escape(imp_name)}.*['\"]\s*\)", line):
                        import_locs.append((fpath, line_num))
                    # Go: import "X"
                    if re.search(rf'"\s*{re.escape(imp_name)}\s*"', line):
                        import_locs.append((fpath, line_num))
                    # Rust: use X / extern crate X
                    if re.search(rf'\buse\s+{re.escape(imp_name)}', line):
                        import_locs.append((fpath, line_num))
                    # C#: using X
                    if re.search(rf'\busing\s+{re.escape(imp_name)}', line):
                        import_locs.append((fpath, line_num))

                # Check crypto API calls (if package is imported)
                if import_locs:
                    # Common crypto function patterns
                    crypto_calls = [
                        r'generate_private_key|generate_key|GenerateKey',
                        r'getInstance|Create\s*\(|new\s*\(',
                        r'encrypt|decrypt|sign|verify',
                        r'\.md5|\.sha1|\.sha256|MD5|SHA1|SHA256',
                        r'ECDSA|ECDH|RSA|DiffieHellman',
                        r'Cipher|KeyPairGenerator|MessageDigest|Signature',
                        r'PrivateKey|PublicKey|SecretKey',
                    ]
                    for call_pattern in crypto_calls:
                        if re.search(call_pattern, line, re.IGNORECASE):
                            # Extract function name
                            func_match = re.search(r'(\w+)\s*\(', line)
                            func_name = func_match.group(1) if func_match else 'unknown'
                            call_locs.append((fpath, line_num, func_name))
                            break

        # Deduplicate
        import_locs = list(set(import_locs))
        call_locs = list(set(call_locs))

        # Classify
        if call_locs:
            level = ReachabilityLevel.CONFIRMED
            confidence = min(1.0, 0.7 + len(call_locs) * 0.05)
        elif import_locs:
            level = ReachabilityLevel.REACHABLE
            confidence = min(0.7, 0.3 + len(import_locs) * 0.1)
        else:
            level = ReachabilityLevel.AVAILABLE
            confidence = 0.1

        results.append(ReachabilityResult(
            package=pkg,
            level=level,
            import_locations=import_locs,
            call_locations=call_locs,
            confidence=round(confidence, 2),
        ))

    return results


# ============================================================================
# BACKWARD SLICING — Crypto Parameter Resolution
# ============================================================================

@dataclass
class ResolvedParameter:
    """A resolved parameter value from backward slicing."""
    name: str                   # Variable name
    value: Optional[str]        # Resolved value (string/int) or None
    value_type: str             # 'string', 'integer', 'variable', 'unknown'
    source_line: int            # Where the value was assigned
    confidence: str             # HIGH (literal), MEDIUM (single assignment), LOW (complex)


def backward_slice_function(source: str, target_line: int,
                            target_var: str) -> Optional[ResolvedParameter]:
    """Trace a variable backward through assignments to resolve its value.

    Intraprocedural: only traces within the current function scope.
    Handles:
      - Direct string assignment: algo = "RSA"
      - Direct integer assignment: key_size = 2048
      - Dict/config access: algo = config["algorithm"]
      - Function default: def func(algo="RSA")
      - Chained assignment: x = y; y = "RSA"
    """
    lines = source.split('\n')
    if target_line < 1 or target_line > len(lines):
        return None

    # Search backward from target_line
    var_to_resolve = target_var.strip()
    visited_vars = {var_to_resolve}
    max_depth = 3  # Don't chase more than 3 levels of assignment chains

    for depth in range(max_depth):
        found = False
        for i in range(target_line - 2, max(-1, target_line - 50), -1):
            if i < 0:
                break
            line = lines[i].strip()

            # Pattern 1: Direct string assignment — var = "value"
            match = re.match(
                rf'{re.escape(var_to_resolve)}\s*=\s*["\']([^"\']+)["\']',
                line
            )
            if match:
                return ResolvedParameter(
                    name=target_var, value=match.group(1),
                    value_type='string', source_line=i + 1,
                    confidence='HIGH',
                )

            # Pattern 2: Direct integer assignment — var = 2048
            match = re.match(
                rf'{re.escape(var_to_resolve)}\s*=\s*(\d+)',
                line
            )
            if match:
                return ResolvedParameter(
                    name=target_var, value=match.group(1),
                    value_type='integer', source_line=i + 1,
                    confidence='HIGH',
                )

            # Pattern 3: Variable assignment — var = other_var
            match = re.match(
                rf'{re.escape(var_to_resolve)}\s*=\s*([a-zA-Z_]\w*)\s*$',
                line
            )
            if match:
                next_var = match.group(1)
                if next_var not in visited_vars:
                    visited_vars.add(next_var)
                    var_to_resolve = next_var
                    target_line = i + 1
                    found = True
                    break

            # Pattern 4: Dict/config access — var = config["key"]  or config.get("key", "default")
            match = re.match(
                rf'{re.escape(var_to_resolve)}\s*=\s*\w+\.get\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']\)',
                line
            )
            if match:
                return ResolvedParameter(
                    name=target_var, value=match.group(1),
                    value_type='string', source_line=i + 1,
                    confidence='MEDIUM',
                )

            # Pattern 5: Dict bracket access with default
            match = re.match(
                rf'{re.escape(var_to_resolve)}\s*=\s*\w+\[["\']([^"\']+)["\']\]',
                line
            )
            if match:
                return ResolvedParameter(
                    name=target_var, value=None,
                    value_type='variable', source_line=i + 1,
                    confidence='LOW',
                )

            # Pattern 6: Function default parameter — def func(var="RSA")
            match = re.search(
                rf'{re.escape(var_to_resolve)}\s*=\s*["\']([^"\']+)["\']',
                line
            )
            if match and ('def ' in line or 'function ' in line):
                return ResolvedParameter(
                    name=target_var, value=match.group(1),
                    value_type='string', source_line=i + 1,
                    confidence='MEDIUM',
                )

            # Pattern 7: Integer from function default — def func(key_size=2048)
            match = re.search(
                rf'{re.escape(var_to_resolve)}\s*=\s*(\d+)',
                line
            )
            if match and ('def ' in line or 'function ' in line):
                return ResolvedParameter(
                    name=target_var, value=match.group(1),
                    value_type='integer', source_line=i + 1,
                    confidence='MEDIUM',
                )

        if not found:
            break

    return None


def resolve_crypto_call_parameters(source: str, findings: List[Finding],
                                   filepath: str) -> List[Finding]:
    """Enhance findings by resolving variable parameters via backward slicing.

    For each finding where the code snippet contains a variable reference
    instead of a literal, attempts to resolve the actual value.
    """
    lines = source.split('\n')
    enhanced = []

    for f in findings:
        if f.file != filepath:
            enhanced.append(f)
            continue

        line_idx = f.line - 1
        if line_idx < 0 or line_idx >= len(lines):
            enhanced.append(f)
            continue

        line = lines[line_idx]

        # Look for variable arguments in crypto calls
        # Pattern: func(var_name) where var_name is not a string/number literal
        call_match = re.search(r'(\w+)\s*\(\s*([a-zA-Z_]\w*)\s*[,)]', line)
        if call_match:
            func_name = call_match.group(1)
            var_name = call_match.group(2)

            # Skip if it's a known literal/keyword
            if var_name in ('True', 'False', 'None', 'null', 'true', 'false',
                           'self', 'this', 'cls'):
                enhanced.append(f)
                continue

            resolved = backward_slice_function(source, f.line, var_name)
            if resolved and resolved.value:
                # Enhance the finding description
                new_desc = f.description
                if resolved.value_type == 'string':
                    new_desc += f' [resolved: {var_name}="{resolved.value}" from line {resolved.source_line}]'
                elif resolved.value_type == 'integer':
                    new_desc += f' [resolved: {var_name}={resolved.value} from line {resolved.source_line}]'

                enhanced.append(Finding(
                    id=f.id, severity=f.severity, category=f.category,
                    algorithm=f.algorithm, file=f.file, line=f.line,
                    code_snippet=f.code_snippet,
                    description=new_desc,
                    recommendation=f.recommendation,
                    pqc_replacement=f.pqc_replacement,
                ))
                continue

        # Check for keyword arguments: func(key_size=var)
        kw_match = re.search(r'(\w+)\s*=\s*([a-zA-Z_]\w*)\s*[,)]', line)
        if kw_match:
            kw_name = kw_match.group(1)
            var_name = kw_match.group(2)

            if kw_name in ('key_size', 'bits', 'size', 'length', 'algorithm',
                          'algo', 'cipher', 'hash_name', 'digest'):
                resolved = backward_slice_function(source, f.line, var_name)
                if resolved and resolved.value:
                    new_desc = f.description
                    new_desc += f' [resolved: {kw_name}={resolved.value} from line {resolved.source_line}]'
                    enhanced.append(Finding(
                        id=f.id, severity=f.severity, category=f.category,
                        algorithm=f.algorithm, file=f.file, line=f.line,
                        code_snippet=f.code_snippet,
                        description=new_desc,
                        recommendation=f.recommendation,
                        pqc_replacement=f.pqc_replacement,
                    ))
                    continue

        enhanced.append(f)

    return enhanced


# ============================================================================
# FORMATTING
# ============================================================================

def format_reachability_report(results: List[ReachabilityResult]) -> str:
    """Format reachability analysis as text report."""
    if not results:
        return "No dependency reachability data."

    lines = [
        "=" * 70,
        "  REACHABILITY ANALYSIS — Crypto Dependency Usage Verification",
        "=" * 70, "",
    ]

    confirmed = [r for r in results if r.level == ReachabilityLevel.CONFIRMED]
    reachable = [r for r in results if r.level == ReachabilityLevel.REACHABLE]
    available = [r for r in results if r.level == ReachabilityLevel.AVAILABLE]

    lines.append(f"  CONFIRMED: {len(confirmed)} packages (crypto APIs called in source)")
    lines.append(f"  REACHABLE: {len(reachable)} packages (imported but no direct crypto call)")
    lines.append(f"  AVAILABLE: {len(available)} packages (in deps, never imported)")
    lines.append("")

    for level_name, level_results, icon in [
        ('CONFIRMED', confirmed, '!'),
        ('REACHABLE', reachable, '?'),
        ('AVAILABLE', available, '.'),
    ]:
        if not level_results:
            continue
        lines.append(f"  [{icon}] {level_name}:")
        for r in level_results:
            lines.append(f"      {r.package} (confidence: {r.confidence:.0%})")
            if r.import_locations:
                imp_files = set(os.path.basename(f) for f, _ in r.import_locations)
                lines.append(f"        Imported in: {', '.join(sorted(imp_files))}")
            if r.call_locations:
                for f, l, fn in r.call_locations[:3]:
                    lines.append(f"        Call: {os.path.basename(f)}:{l} → {fn}()")
            if r.level == ReachabilityLevel.AVAILABLE:
                lines.append(f"        Not imported anywhere — may be unused or transitive")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
