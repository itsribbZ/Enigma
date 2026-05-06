"""
Enigma pqc-scanner v4.0: Cross-File Call Graph Analysis.

Uses pyan3 to build interprocedural call graphs for Python codebases,
then traces paths from entry points to crypto API calls. Upgrades
reachability confidence from REACHABLE to CONFIRMED when a full
call chain from a public entry point to a crypto sink is found.

Usage: pqc-scanner scan <path> --callgraph
"""

from __future__ import annotations
import os
import sys
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Tree-sitter support for multi-language call graph
try:
    from treesitter_scanner import _get_parser, _EXT_TO_LANG
    _TS_AVAILABLE = True
except ImportError:
    _TS_AVAILABLE = False

# All source extensions the call graph can analyze
_SUPPORTED_EXTS = {
    '.py', '.java', '.go', '.js', '.mjs', '.cjs', '.ts', '.tsx',
    '.rs', '.c', '.h', '.cpp', '.cc', '.hpp', '.cs', '.rb',
    '.php', '.kt', '.kts', '.swift', '.scala', '.sc',
}

# Tree-sitter node types for function/method definitions per language
_FUNC_DEF_TYPES = {
    'python': {'function_definition'},
    'java': {'method_declaration', 'constructor_declaration'},
    'go': {'function_declaration', 'method_declaration'},
    'javascript': {'function_declaration', 'method_definition'},
    'typescript': {'function_declaration', 'method_definition'},
    'rust': {'function_item'},
    'c': {'function_definition'},
    'csharp': {'method_declaration', 'constructor_declaration'},
    'ruby': {'method', 'singleton_method'},
    'php': {'function_definition', 'method_declaration'},
    'kotlin': {'function_declaration'},
    'swift': {'function_declaration'},
    'scala': {'function_definition'},
}

# Tree-sitter node types for function/method calls per language
_CALL_TYPES = {
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

# Identifier node types across languages
_NAME_TYPES = frozenset({
    'identifier', 'name', 'simple_identifier', 'property_identifier',
    'type_identifier', 'field_identifier',
})


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass
class CallChain:
    """A traced call chain from entry point to crypto API usage."""
    entry_point: str        # e.g., "main.handle_request"
    entry_file: str         # e.g., "main.py"
    crypto_call: str        # e.g., "rsa.generate_private_key"
    crypto_file: str        # e.g., "crypto_utils.py"
    crypto_line: int
    chain: List[str]        # ["main.handle_request", "auth.verify_user", "crypto.sign"]
    chain_length: int       # Number of hops
    algorithm: str          # Detected algorithm at the crypto call


@dataclass
class CallGraphResult:
    """Results from call graph analysis."""
    total_functions: int
    total_edges: int
    crypto_sinks: int       # Number of crypto API call sites found
    confirmed_chains: List[CallChain]
    orphan_crypto: List[str]  # Crypto calls with no traced entry point
    analysis_time_ms: float


# ============================================================================
# CRYPTO SINK PATTERNS (function names that indicate crypto usage)
# ============================================================================

_CRYPTO_SINKS = {
    # Asymmetric — Shor-vulnerable
    'generate_private_key': 'RSA/ECDSA',
    'generate_key': 'RSA/ECDSA',
    'RSA.generate': 'RSA',
    'RSA.import_key': 'RSA',
    'ECC.generate': 'ECDSA',
    'ECDSA': 'ECDSA',
    'ECDH': 'ECDH',
    'Ed25519PrivateKey': 'Ed25519',
    'X25519PrivateKey': 'X25519',
    'generate_parameters': 'DH',
    # Hashes — weakened/broken
    'md5': 'MD5',
    'sha1': 'SHA-1',
    # Symmetric — weak
    'DES.new': '3DES',
    'DES3.new': '3DES',
    'Blowfish.new': 'Blowfish',
    'ARC4.new': 'RC4',
    # TLS
    'SSLContext': 'TLS',
    'create_default_context': 'TLS',
    # JWT
    'jwt.encode': 'RSA/ECDSA',
    'jwt.decode': 'RSA/ECDSA',
}


# ============================================================================
# CALL GRAPH ENGINE
# ============================================================================

def analyze_callgraph(scan_path: str,
                      findings: Optional[list] = None) -> CallGraphResult:
    """Build a call graph and trace crypto call chains.

    Supports all 13 tree-sitter languages. Falls back to Python AST
    or pyan3 for Python-only codebases when tree-sitter is unavailable.

    Args:
        scan_path: Directory to analyze (all supported languages)
        findings: Optional list of Finding objects to cross-reference

    Returns:
        CallGraphResult with traced call chains
    """
    import time
    start = time.time()

    # Collect all supported source files
    source_files = _collect_source_files(scan_path)
    if not source_files:
        return CallGraphResult(0, 0, 0, [], [], 0.0)

    # Build call graph — tree-sitter first (all languages), then pyan3/AST for Python
    graph = None
    if _TS_AVAILABLE:
        graph = _build_treesitter_callgraph(source_files)
    if graph is None:
        py_files = [f for f in source_files if f.endswith('.py')]
        if py_files:
            graph = _build_callgraph(py_files)
    if graph is None:
        return CallGraphResult(0, 0, 0, [], [], 0.0)

    total_functions = len(graph)
    total_edges = sum(len(callees) for callees in graph.values())

    # Identify crypto sinks in the graph
    crypto_nodes = _find_crypto_nodes(graph, source_files, findings)

    # Identify entry points (functions not called by anything else)
    all_callees = set()
    for callees in graph.values():
        all_callees.update(callees)
    entry_points = set(graph.keys()) - all_callees

    # Also add common entry point patterns
    for func_name in graph:
        if any(p in func_name.lower() for p in ('main', '__main__', 'app.', 'handle_', 'view_',
                                                  'endpoint', 'route', 'api_', 'test_')):
            entry_points.add(func_name)

    # Trace paths from entry points to crypto sinks.
    # Single multi-source BFS: O(V+E) total regardless of entry_points × crypto_nodes count.
    # Previous nested loop was O(entry_points × crypto_nodes × BFS) — 500 × 50 × O(V+E)
    # which hung for minutes on real enterprise codebases.
    confirmed_chains = []
    reached_crypto = set()

    # Multi-source BFS: seed with all entry points, record shortest path to each crypto node.
    visited: Dict[str, List[str]] = {}  # node → path from nearest entry point
    bfs_queue: deque = deque()
    for ep in entry_points:
        visited[ep] = [ep]
        bfs_queue.append(ep)

    max_depth = 10
    while bfs_queue:
        current = bfs_queue.popleft()
        current_path = visited[current]
        if len(current_path) > max_depth:
            continue
        for neighbor in graph.get(current, set()):
            if neighbor not in visited:
                new_path = current_path + [neighbor]
                visited[neighbor] = new_path
                bfs_queue.append(neighbor)
                if neighbor in crypto_nodes:
                    reached_crypto.add(neighbor)
                    algo, crypto_file, crypto_line = crypto_nodes[neighbor]
                    entry_point = new_path[0]
                    entry_file = _func_to_file(entry_point, source_files)
                    confirmed_chains.append(CallChain(
                        entry_point=entry_point,
                        entry_file=entry_file,
                        crypto_call=neighbor,
                        crypto_file=crypto_file,
                        crypto_line=crypto_line,
                        chain=new_path,
                        chain_length=len(new_path),
                        algorithm=algo,
                    ))

    # Identify orphan crypto (no path from any entry point)
    orphan_crypto = [node for node in crypto_nodes if node not in reached_crypto]

    elapsed = (time.time() - start) * 1000
    return CallGraphResult(
        total_functions=total_functions,
        total_edges=total_edges,
        crypto_sinks=len(crypto_nodes),
        confirmed_chains=confirmed_chains,
        orphan_crypto=orphan_crypto,
        analysis_time_ms=elapsed,
    )


def _collect_source_files(scan_path: str) -> List[str]:
    """Collect all source files of supported languages from a directory."""
    skip = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
    files = []
    target = Path(scan_path)
    if target.is_file():
        if target.suffix.lower() in _SUPPORTED_EXTS:
            return [str(target)]
        return []
    max_files = 10000
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fname in filenames:
            if len(files) >= max_files:
                return files
            if Path(fname).suffix.lower() in _SUPPORTED_EXTS:
                files.append(os.path.join(dirpath, fname))
    return files


def _build_treesitter_callgraph(source_files: List[str]) -> Optional[Dict[str, Set[str]]]:
    """Build a call graph using tree-sitter across all supported languages.

    For each source file: parse with tree-sitter, extract function definitions
    and the calls within them, build an adjacency graph.
    """
    if not _TS_AVAILABLE:
        return None

    graph: Dict[str, Set[str]] = {}
    _skipped_langs: Set[str] = set()

    for filepath in source_files:
        ext = Path(filepath).suffix.lower()
        lang = _EXT_TO_LANG.get(ext)
        if not lang or lang in ('terraform', 'yaml_config', 'docker'):
            continue

        parser = _get_parser(lang)
        if not parser:
            continue

        try:
            source = Path(filepath).read_bytes()
            tree = parser.parse(source)
        except (OSError, UnicodeDecodeError):
            continue
        except Exception:
            # Tree-sitter grammar error (missing grammar, parse failure).
            # Track skipped files so caller can warn about incomplete graph.
            _skipped_langs.add(lang)
            continue

        module = Path(filepath).stem
        func_types = _FUNC_DEF_TYPES.get(lang, set())
        call_types = _CALL_TYPES.get(lang, set())

        if func_types and call_types:
            _walk_for_callgraph(tree.root_node, module, func_types, call_types, graph)

    if _skipped_langs:
        import sys as _sys
        print(f"Warning: call graph skipped {len(_skipped_langs)} language(s) "
              f"due to missing/failing tree-sitter grammars: {', '.join(sorted(_skipped_langs))}",
              file=_sys.stderr)

    return graph if graph else None


def _walk_for_callgraph(node, module: str, func_types: set,
                        call_types: set, graph: Dict[str, Set[str]]) -> None:
    """Recursively walk AST to find function definitions and their calls.

    Continues recursion even after finding a function definition, so nested
    function defs (closures, inner classes, lambdas) are also added to the graph.
    """
    if node.type in func_types:
        func_name = _extract_def_name(node)
        if func_name:
            qualified = f"{module}.{func_name}"
            if qualified not in graph:
                graph[qualified] = set()
            _find_calls_in(node, qualified, call_types, graph)
        # Continue recursion so nested function defs are also discovered.
        for child in node.children:
            _walk_for_callgraph(child, module, func_types, call_types, graph)
        return

    for child in node.children:
        _walk_for_callgraph(child, module, func_types, call_types, graph)


def _find_calls_in(node, caller: str, call_types: set,
                   graph: Dict[str, Set[str]]) -> None:
    """Find all call expressions within a function definition node."""
    for child in node.children:
        if child.type in call_types:
            callee = _extract_call_name(child)
            if callee:
                graph[caller].add(callee)
                if callee not in graph:
                    graph[callee] = set()
        _find_calls_in(child, caller, call_types, graph)


def _extract_def_name(node) -> Optional[str]:
    """Extract function/method name from a definition AST node."""
    # Try field-based access first (most tree-sitter grammars use 'name')
    name_node = node.child_by_field_name('name')
    if name_node:
        return name_node.text.decode('utf-8')

    # Scan children for identifier-type nodes
    for child in node.children:
        if child.type in _NAME_TYPES:
            return child.text.decode('utf-8')
        # C/C++: function_definition → function_declarator → identifier
        if child.type in ('function_declarator', 'declarator'):
            for gc in child.children:
                if gc.type in _NAME_TYPES:
                    return gc.text.decode('utf-8')
                if gc.type in ('function_declarator', 'pointer_declarator'):
                    for ggc in gc.children:
                        if ggc.type in _NAME_TYPES:
                            return ggc.text.decode('utf-8')
    return None


def _extract_call_name(node) -> Optional[str]:
    """Extract callee name from a call AST node."""
    # Try field-based access (most grammars use 'function')
    func_node = node.child_by_field_name('function')
    if func_node:
        if func_node.type in _NAME_TYPES:
            return func_node.text.decode('utf-8')
        # Attribute/member call: obj.method() — return full qualified text
        if func_node.type in ('attribute', 'member_expression', 'field_expression',
                               'member_access_expression', 'scoped_identifier',
                               'selector_expression', 'qualified_identifier'):
            return func_node.text.decode('utf-8')
        # Nested: return text as-is for complex expressions
        text = func_node.text.decode('utf-8')
        if text and len(text) < 100:
            return text

    # Try 'method' field (Java method_invocation)
    method_node = node.child_by_field_name('method')
    if method_node:
        return method_node.text.decode('utf-8')

    # Try 'name' field (PHP, Ruby)
    name_node = node.child_by_field_name('name')
    if name_node:
        return name_node.text.decode('utf-8')

    # Fallback: scan children for identifiers
    if node.children:
        first = node.children[0]
        if first.type in _NAME_TYPES:
            return first.text.decode('utf-8')
        # Return text of first child if short
        text = first.text.decode('utf-8')
        if text and len(text) < 80:
            return text

    return None


def _build_callgraph(py_files: List[str]) -> Optional[Dict[str, Set[str]]]:
    """Build a call graph using pyan3.

    Returns: dict mapping caller -> set of callees, or None if pyan3 fails.
    """
    try:
        from pyan import CallGraphVisitor
        visitor = CallGraphVisitor(py_files, logger=None)

        # Build adjacency dict from pyan's internal graph
        graph: Dict[str, Set[str]] = {}
        if hasattr(visitor, 'uses_edges'):
            for edge in visitor.uses_edges:
                caller = edge[0].get_name() if hasattr(edge[0], 'get_name') else str(edge[0])
                callee = edge[1].get_name() if hasattr(edge[1], 'get_name') else str(edge[1])
                graph.setdefault(caller, set()).add(callee)
                if callee not in graph:
                    graph[callee] = set()
        return graph if graph else None
    except Exception:
        # pyan3 can fail on syntax errors, encoding issues, etc.
        # Fall back to lightweight AST-based call graph
        return _build_simple_callgraph(py_files)


def _build_simple_callgraph(py_files: List[str]) -> Optional[Dict[str, Set[str]]]:
    """Lightweight fallback: build call graph from Python AST imports and calls."""
    import ast

    graph: Dict[str, Set[str]] = {}

    for filepath in py_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
            tree = ast.parse(source, filename=filepath)
        except (SyntaxError, OSError):
            continue

        module_name = Path(filepath).stem

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = f'{module_name}.{node.name}'
                if func_name not in graph:
                    graph[func_name] = set()

                # Find calls within this function
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        callee = _extract_ast_call_name(child)
                        if callee:
                            graph[func_name].add(callee)
                            if callee not in graph:
                                graph[callee] = set()

    return graph if graph else None


def _extract_ast_call_name(call_node) -> Optional[str]:
    """Extract function name from a Python AST Call node."""
    import ast
    func = call_node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _find_crypto_nodes(graph: Dict[str, Set[str]],
                       py_files: List[str],
                       findings: Optional[list]) -> Dict[str, Tuple[str, str, int]]:
    """Identify nodes in the call graph that are crypto API calls.

    Returns: dict mapping node_name -> (algorithm, file, line)
    """
    crypto_nodes = {}

    # Match graph nodes against crypto sink patterns
    for node_name in graph:
        for sink_pattern, algo in _CRYPTO_SINKS.items():
            if sink_pattern in node_name:
                crypto_nodes[node_name] = (algo, '', 0)
                break

    # Cross-reference with actual findings if provided.
    # Pre-build module→nodes index to avoid O(findings × graph_nodes) nested loop.
    if findings:
        _known_algorithms = set(_CRYPTO_SINKS.values())
        nodes_by_module: Dict[str, List[str]] = {}
        for node_name in graph:
            prefix = node_name.split('.')[0]
            nodes_by_module.setdefault(prefix, []).append(node_name)
        for f in findings:
            if f.algorithm not in _known_algorithms:
                continue
            module = Path(f.file).stem
            for node_name in nodes_by_module.get(module, []):
                crypto_nodes[node_name] = (f.algorithm, f.file, f.line)

    return crypto_nodes


def _func_to_file(func_name: str, source_files: List[str]) -> str:
    """Map a function name back to its source file."""
    module = func_name.split('.')[0] if '.' in func_name else func_name
    for filepath in source_files:
        if Path(filepath).stem == module:
            return filepath
    return ''


def _find_path(graph: Dict[str, Set[str]], start: str, end: str,
               max_depth: int = 10) -> Optional[List[str]]:
    """BFS to find shortest path from start to end in the call graph.

    Uses deque for O(1) popleft (list.pop(0) is O(n), turns BFS into O(V²)).
    Retained for backward compatibility with any external callers.
    """
    if start == end:
        return [start]

    visited = {start}
    queue: deque = deque([(start, [start])])

    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth:
            continue

        for neighbor in graph.get(current, set()):
            if neighbor == end:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None


# ============================================================================
# REPORTING
# ============================================================================

def format_callgraph_report(result: CallGraphResult) -> str:
    """Format call graph analysis as a human-readable report."""
    lines = [
        "=" * 70,
        "  CALL GRAPH ANALYSIS — Cross-File Crypto Tracing",
        "=" * 70,
        "",
        f"  Functions analyzed: {result.total_functions}",
        f"  Call edges:         {result.total_edges}",
        f"  Crypto sinks:       {result.crypto_sinks}",
        f"  Confirmed chains:   {len(result.confirmed_chains)}",
        f"  Orphan crypto:      {len(result.orphan_crypto)}",
        f"  Analysis time:      {result.analysis_time_ms:.0f}ms",
        "",
    ]

    if result.confirmed_chains:
        lines.append("  CONFIRMED REACHABLE (entry point -> crypto):")
        lines.append("  " + "-" * 60)
        # Deduplicate by crypto_call
        seen = set()
        for chain in sorted(result.confirmed_chains, key=lambda c: c.chain_length):
            key = (chain.entry_point, chain.crypto_call)
            if key in seen:
                continue
            seen.add(key)
            chain_str = ' -> '.join(chain.chain)
            lines.append(f"    [{chain.algorithm}] {chain_str}")
            if chain.crypto_file:
                lines.append(f"      Sink: {os.path.basename(chain.crypto_file)}:{chain.crypto_line}")
            lines.append(f"      Hops: {chain.chain_length}")
            lines.append("")

    if result.orphan_crypto:
        lines.append("  ORPHAN CRYPTO (no entry point reaches these):")
        lines.append("  " + "-" * 60)
        for node in result.orphan_crypto:
            lines.append(f"    {node} — may be dead code or dynamically invoked")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
