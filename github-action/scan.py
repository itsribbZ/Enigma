"""
PQC Scanner v4.0 — GitHub Action entry point.
Scans codebase for quantum-vulnerable cryptography and outputs SARIF/CBOM.
"""
import argparse
import json
import os
import sys

# Add scanner modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phases', 'phase6_scanner'))

from pqc_scanner import (
    PQCScanner, format_text_report, format_json_report,
    format_html_report, format_sarif_report, format_cbom_report,
    __version__,
)
from dependency_scanner import scan_dependencies, format_dep_report
from ast_scanner import ast_scan_directory
from treesitter_scanner import ts_scan_directory, TREE_SITTER_AVAILABLE


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--path', default='.')
    parser.add_argument('--severity', default='low')
    parser.add_argument('--format', default='sarif')
    parser.add_argument('--output', default='pqc-scan-results.sarif')
    parser.add_argument('--scan-deps', default='true')
    parser.add_argument('--fail-on-critical', default='true')
    args = parser.parse_args()

    print(f"::group::PQC Scanner v{__version__} Configuration")
    print(f"  Path: {args.path}")
    print(f"  Severity: {args.severity}")
    print(f"  Format: {args.format}")
    print(f"  Fail on critical: {args.fail_on_critical}")
    print(f"::endgroup::")

    # Run regex scanner (v4: with comment/string stripping)
    scanner = PQCScanner()
    result = scanner.scan(args.path)

    # Run tree-sitter deep analysis (v4: 7 languages)
    if TREE_SITTER_AVAILABLE:
        ts_findings = ts_scan_directory(args.path)
        existing = {(f.file, f.line, f.algorithm) for f in result.findings}
        for tf in ts_findings:
            if (tf.file, tf.line, tf.algorithm) not in existing:
                result.findings.append(tf)
                existing.add((tf.file, tf.line, tf.algorithm))
        print(f"  Tree-sitter: {len(ts_findings)} findings ({len(result.findings)} after dedup)")

    # Run AST scanner on Python files and merge findings
    ast_findings = ast_scan_directory(args.path)
    existing = {(f.file, f.line, f.algorithm) for f in result.findings}
    for af in ast_findings:
        if (af.file, af.line, af.algorithm) not in existing:
            result.findings.append(af)

    # Filter by severity
    sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
    min_idx = sev_order.index(args.severity.upper())
    result.findings = [f for f in result.findings if sev_order.index(f.severity.value) <= min_idx]
    result.compute_summary()

    # Format and save
    formatters = {
        'sarif': format_sarif_report, 'json': format_json_report,
        'text': format_text_report, 'html': format_html_report,
        'cbom': format_cbom_report,
    }
    output = formatters[args.format](result)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(output)

    # Dependency scan
    if args.scan_deps == 'true':
        dep_findings = scan_dependencies(args.path)
        if dep_findings:
            print(f"\n::group::Dependency Scan")
            print(format_dep_report(dep_findings))
            print(f"::endgroup::")

    # Summary
    print(f"\n::group::Results Summary")
    print(f"  Files scanned: {result.files_scanned}")
    print(f"  Findings: {len(result.findings)}")
    print(f"  Risk score: {result.risk_score}/100")
    if scanner.suppressed_count > 0:
        print(f"  Suppressed: {scanner.suppressed_count}")
    for sev in sev_order:
        count = result.summary.get(sev, 0)
        if count > 0:
            print(f"  {sev}: {count}")
    print(f"::endgroup::")

    # Set outputs
    with open(os.environ.get('GITHUB_OUTPUT', '/dev/null'), 'a') as f:
        f.write(f"findings={len(result.findings)}\n")
        f.write(f"risk-score={result.risk_score}\n")
        f.write(f"sarif-file={args.output}\n")

    # Exit code — respect fail-on-critical input (v4 fix)
    if result.summary.get('CRITICAL', 0) > 0 and args.fail_on_critical == 'true':
        print(f"\n::error::Found {result.summary['CRITICAL']} CRITICAL quantum-vulnerable findings")
        sys.exit(2)
    elif len(result.findings) > 0:
        print(f"\n::warning::Found {len(result.findings)} quantum-vulnerable findings")
        sys.exit(0)


if __name__ == '__main__':
    main()
