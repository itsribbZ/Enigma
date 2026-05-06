"""
Enigma pqc-scanner v4.0: Tests for Wave 3-5 features.
CNSA 2.0 deadlines, QARS scoring, lock file parsing, auto-fix engine.
"""
import json
import os
import tempfile
from datetime import date
import pytest

from compliance import (
    get_cnsa2_deadline, get_all_deadlines, compute_qars,
    analyze_compliance, format_compliance_report, format_qars_report,
    ComplianceStatus, QARSScore,
)
from pqc_scanner import ScanResult, Finding, Severity, Category
from dependency_scanner import (
    scan_dependencies, DepFinding, DepRisk,
    _parse_pipfile_lock, _parse_package_lock_json,
    _parse_cargo_lock, _parse_poetry_lock, _parse_go_sum,
)
from autofix import generate_fixes, format_fix_report, format_unified_diff, FixSuggestion


# ============================================================================
# CNSA 2.0 DEADLINE COUNTDOWN
# ============================================================================

class TestCNSA2Deadlines:
    def test_rsa_deadline(self):
        info = get_cnsa2_deadline('RSA', reference_date=date(2026, 3, 23))
        assert info is not None
        assert info.deadline_category == 'software_signing'
        # Corrected per NSA CNSA 2.0 spec: exclusive-use deadline for
        # software/firmware signing is 2030, not 2025.
        assert info.deadline_date == date(2030, 12, 31)
        assert info.days_remaining > 0
        assert info.urgency in ('DISTANT', 'APPROACHING')

    def test_dsa_deadline(self):
        info = get_cnsa2_deadline('DSA', reference_date=date(2026, 3, 23))
        assert info is not None
        # DSA maps to software_signing category (2030 deadline per corrected CNSA 2.0 map).
        assert info.urgency in ('OVERDUE', 'URGENT', 'APPROACHING', 'DISTANT')

    def test_aes256_compliant(self):
        info = get_cnsa2_deadline('AES-256')
        assert info is None  # No deadline — compliant

    def test_all_deadlines_sorted(self):
        algos = ['RSA', 'ECDSA', 'AES-128', 'SHA-1', 'MD5']
        deadlines = get_all_deadlines(algos, reference_date=date(2026, 3, 23))
        assert len(deadlines) >= 4
        # Should be sorted by days_remaining (most urgent first)
        for i in range(len(deadlines) - 1):
            assert deadlines[i].days_remaining <= deadlines[i + 1].days_remaining

    def test_compliance_includes_countdown(self):
        result = ScanResult(scan_path='/test', scan_date='2026-03-23', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        compliance = analyze_compliance(result)
        cnsa = compliance.get('CNSA 2.0', [])
        rsa_finding = [f for f in cnsa if f.algorithm == 'RSA']
        assert len(rsa_finding) == 1
        assert rsa_finding[0].days_remaining is not None
        assert rsa_finding[0].urgency is not None

    def test_compliance_report_format(self):
        result = ScanResult(scan_path='/test', scan_date='2026-03-23', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        compliance = analyze_compliance(result)
        report = format_compliance_report(compliance)
        assert 'CNSA 2.0' in report
        assert 'days remaining' in report or 'OVERDUE' in report
        assert 'NIST IR 8547' in report


# ============================================================================
# QARS RISK SCORING
# ============================================================================

class TestQARS:
    def test_empty_scan(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=0)
        qars = compute_qars(result)
        assert qars.overall_score == 0.0
        assert qars.grade == 'A'

    def test_critical_rsa(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA keygen', 'Replace', 'ML-KEM'),
        ]
        qars = compute_qars(result)
        assert qars.overall_score > 50  # RSA should be high risk
        assert qars.highest_risk_algo == 'RSA'
        assert qars.grade in ('D', 'F')

    def test_sensitivity_affects_score(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        low = compute_qars(result, sensitivity='public')
        high = compute_qars(result, sensitivity='restricted')
        assert high.overall_score > low.overall_score

    def test_mosca_urgency(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        # Urgent: shelf_life(20) + migration(5) > threat(10)
        urgent = compute_qars(result, data_shelf_life_years=20,
                              migration_time_years=5, quantum_threat_years=10)
        # Not urgent: shelf_life(1) + migration(1) < threat(20)
        calm = compute_qars(result, data_shelf_life_years=1,
                            migration_time_years=1, quantum_threat_years=20)
        assert urgent.mosca_urgency > calm.mosca_urgency
        assert urgent.overall_score > calm.overall_score

    def test_qars_report_format(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        qars = compute_qars(result)
        report = format_qars_report(qars)
        assert 'QARS' in report
        assert 'Grade' in report
        assert 'RSA' in report


# ============================================================================
# LOCK FILE PARSING
# ============================================================================

class TestLockFileParsing:
    def test_pipfile_lock(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False,
                                         encoding='utf-8') as f:
            json.dump({
                '_meta': {},
                'default': {
                    'cryptography': {'version': '==41.0.0'},
                    'requests': {'version': '==2.31.0'},
                    'flask': {'version': '==3.0.0'},
                },
                'develop': {}
            }, f)
            f.flush()
            deps = _parse_pipfile_lock(f.name)
        os.unlink(f.name)
        assert len(deps) == 3
        names = [d[0] for d in deps]
        assert 'cryptography' in names

    def test_package_lock_json_v3(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False,
                                         encoding='utf-8') as f:
            json.dump({
                'lockfileVersion': 3,
                'packages': {
                    '': {'name': 'my-app', 'version': '1.0.0'},
                    'node_modules/node-rsa': {'version': '1.1.1'},
                    'node_modules/elliptic': {'version': '6.5.4'},
                    'node_modules/express': {'version': '4.18.2'},
                }
            }, f)
            f.flush()
            deps = _parse_package_lock_json(f.name)
        os.unlink(f.name)
        assert len(deps) == 3
        names = [d[0] for d in deps]
        assert 'node-rsa' in names
        assert 'elliptic' in names

    def test_cargo_lock(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lock', delete=False,
                                         encoding='utf-8') as f:
            f.write('[[package]]\nname = "rsa"\nversion = "0.9.0"\n\n')
            f.write('[[package]]\nname = "tokio"\nversion = "1.32.0"\n')
            f.flush()
            deps = _parse_cargo_lock(f.name)
        os.unlink(f.name)
        assert len(deps) == 2
        assert deps[0][0] == 'rsa'
        assert deps[0][1] == '0.9.0'

    def test_poetry_lock(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.lock', delete=False,
                                         encoding='utf-8') as f:
            f.write('[[package]]\nname = "cryptography"\nversion = "41.0.0"\n\n')
            f.write('[[package]]\nname = "flask"\nversion = "3.0.0"\n')
            f.flush()
            deps = _parse_poetry_lock(f.name)
        os.unlink(f.name)
        assert len(deps) == 2

    def test_go_sum(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sum', delete=False,
                                         encoding='utf-8') as f:
            f.write('golang.org/x/crypto v0.14.0 h1:abc123=\n')
            f.write('golang.org/x/crypto v0.14.0/go.mod h1:def456=\n')
            f.write('github.com/gin-gonic/gin v1.9.1 h1:xyz=\n')
            f.flush()
            deps = _parse_go_sum(f.name)
        os.unlink(f.name)
        # Should deduplicate crypto entries
        assert len(deps) == 2

    def test_lock_file_scan_marks_transitive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock_path = os.path.join(tmpdir, 'Pipfile.lock')
            with open(lock_path, 'w') as f:
                json.dump({
                    '_meta': {},
                    'default': {
                        'cryptography': {'version': '==41.0.0'},
                    },
                    'develop': {}
                }, f)
            findings = scan_dependencies(tmpdir)
            crypto = [f for f in findings if 'cryptography' in f.package]
            assert len(crypto) >= 1
            assert crypto[0].is_transitive is True
            assert '[transitive]' in crypto[0].description


# ============================================================================
# AUTO-FIX ENGINE
# ============================================================================

class TestAutoFix:
    def test_tier1_md5_python(self):
        findings = [
            Finding('PQC-0001', Severity.HIGH, Category.HASH, 'MD5',
                    '/test/foo.py', 10, 'h = hashlib.md5(data)',
                    'MD5 hash', 'Upgrade', 'SHA-256'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        fix = fixes[0]
        assert fix.tier == 1
        assert fix.confidence == 'HIGH'
        assert 'sha256' in fix.replacement
        assert 'md5' not in fix.replacement.lower()

    def test_tier1_sha1_python(self):
        findings = [
            Finding('PQC-0001', Severity.MEDIUM, Category.HASH, 'SHA-1',
                    '/test/foo.py', 10, 'h = hashlib.sha1(data)',
                    'SHA-1 hash', 'Upgrade', 'SHA-256'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        assert 'sha256' in fixes[0].replacement

    def test_tier1_des_java(self):
        findings = [
            Finding('PQC-0001', Severity.HIGH, Category.SYMMETRIC, '3DES',
                    '/test/App.java', 10,
                    'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
                    '3DES', 'Upgrade', 'AES-256'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        assert 'AES/GCM' in fixes[0].replacement

    def test_tier2_rsa_python(self):
        findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10,
                    'key = rsa.generate_private_key(public_exponent=65537)',
                    'RSA keygen', 'Replace', 'ML-KEM'),
        ]
        fixes = generate_fixes(findings, '/test')
        rsa_fixes = [f for f in fixes if f.algorithm_before == 'RSA']
        assert len(rsa_fixes) >= 1
        assert rsa_fixes[0].tier == 2
        assert rsa_fixes[0].confidence == 'MEDIUM'
        assert 'ML-KEM' in rsa_fixes[0].explanation

    def test_tier2_generates_real_code_python(self):
        """Tier 2 should generate actual Python code, not just TODO comments."""
        findings = [
            Finding('T2-PY', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/app.py', 5,
                    '    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)',
                    'RSA keygen', 'Replace', 'ML-KEM'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        fix = fixes[0]
        # Should contain actual library import, not just a comment
        assert 'from oqs import KeyEncapsulation' in fix.replacement
        assert 'KeyEncapsulation("ML-KEM-768")' in fix.replacement
        # Should preserve indentation
        assert fix.replacement.startswith('    ')
        # Should include REVIEW-REQUIRED marker
        assert 'REVIEW-REQUIRED' in fix.replacement

    def test_tier2_generates_real_code_java(self):
        """Tier 2 should generate real Java code with BouncyCastle API."""
        findings = [
            Finding('T2-JV', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/Main.java', 12,
                    '        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");',
                    'RSA keygen', 'Replace', 'ML-KEM'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        fix = fixes[0]
        assert 'BouncyCastleProvider' in fix.replacement
        assert 'ML-KEM' in fix.replacement
        assert 'REVIEW-REQUIRED' in fix.replacement

    def test_tier2_generates_real_code_go(self):
        """Tier 2 should generate real Go code with circl library."""
        findings = [
            Finding('T2-GO', Severity.CRITICAL, Category.SIGNATURE, 'ECDSA',
                    '/test/main.go', 20,
                    '\tprivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)',
                    'ECDSA keygen', 'Replace', 'ML-DSA'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        fix = fixes[0]
        assert 'circl' in fix.replacement
        assert 'mldsa65' in fix.replacement

    def test_tier2_generates_real_code_csharp(self):
        """Tier 2 should generate real C# code with BouncyCastle NuGet."""
        findings = [
            Finding('T2-CS', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/Program.cs', 8,
                    '        var rsa = RSA.Create(2048);',
                    'C# RSA', 'Replace', 'ML-KEM'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        fix = fixes[0]
        assert 'MLKemKeyPairGenerator' in fix.replacement
        assert 'ml_kem_768' in fix.replacement

    def test_tier2_multiline_diff(self):
        """Tier 2 diffs should be multi-line (replacing 1 line with N lines)."""
        findings = [
            Finding('T2-DIFF', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/app.py', 5,
                    'key = rsa.generate_private_key()',
                    'RSA keygen', 'Replace', 'ML-KEM'),
        ]
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) >= 1
        diff = fixes[0].to_diff()
        assert diff.count('\n+') > 1  # Multiple added lines
        assert '-key = rsa.generate_private_key()' in diff

    def test_fix_report_format(self):
        findings = [
            Finding('PQC-0001', Severity.HIGH, Category.HASH, 'MD5',
                    '/test/foo.py', 10, 'h = hashlib.md5(data)',
                    'MD5', 'Upgrade', 'SHA-256'),
        ]
        fixes = generate_fixes(findings, '/test')
        report = format_fix_report(fixes)
        assert 'AUTO-FIX' in report
        assert 'Tier 1' in report or 'TIER 1' in report

    def test_unified_diff_format(self):
        findings = [
            Finding('PQC-0001', Severity.HIGH, Category.HASH, 'MD5',
                    '/test/foo.py', 10, 'h = hashlib.md5(data)',
                    'MD5', 'Upgrade', 'SHA-256'),
        ]
        fixes = generate_fixes(findings, '/test')
        diff = format_unified_diff(fixes)
        assert '---' in diff
        assert '+++' in diff
        assert '-h = hashlib.md5(data)' in diff
        assert '+h = hashlib.sha256(data)' in diff

    def test_no_fixes_for_clean_code(self):
        findings = []
        fixes = generate_fixes(findings, '/test')
        assert len(fixes) == 0
        report = format_fix_report(fixes)
        assert 'No auto-fix' in report
