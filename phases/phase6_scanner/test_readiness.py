"""
Enigma pqc-scanner v4.0: Tests for readiness grades, quality gates, and custom rules.
"""
import os
import tempfile
import pytest
from pqc_scanner import ScanResult, Finding, Severity, Category
from readiness import (
    compute_readiness_grade, format_readiness_report,
    evaluate_gate, format_gate_result, BUILTIN_GATES,
)
from rules_engine import (
    CustomRule, scan_with_rules, BUILTIN_RULES,
    load_rules_from_yaml, YAML_AVAILABLE,
)


# ============================================================================
# PQC READINESS GRADE
# ============================================================================

class TestReadinessGrade:
    def test_clean_codebase_gets_a_plus(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=10)
        grade = compute_readiness_grade(result)
        assert grade.grade == 'A+'
        assert grade.score == 100.0

    def test_rsa_caps_at_c_or_below(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        grade = compute_readiness_grade(result)
        # Shor-vulnerable cap means grade must be C or worse (not A/B).
        assert grade.grade in ('C', 'D', 'F')
        # Cap ceiling is max-C (74); RSA finding should not earn B.
        assert grade.score <= 74

    def test_md5_only_gets_moderate_grade(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.HIGH, Category.HASH, 'MD5',
                    '/test/foo.py', 10, 'hashlib.md5()', 'MD5', 'Replace', 'SHA-256'),
        ]
        grade = compute_readiness_grade(result)
        assert grade.grade in ('C', 'D', 'F')  # MD5 is CNSA overdue → may get F

    def test_report_format(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        grade = compute_readiness_grade(result)
        report = format_readiness_report(grade)
        assert 'READINESS GRADE' in report
        assert grade.grade in report
        assert 'Algorithm Security' in report
        assert 'Recommendations' in report

    def test_has_recommendations(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        grade = compute_readiness_grade(result)
        assert len(grade.recommendations) >= 1
        assert any('Shor' in r or 'RSA' in r for r in grade.recommendations)


# ============================================================================
# QUALITY GATES
# ============================================================================

class TestQualityGates:
    def test_clean_passes_all_gates(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=10)
        for gate_name in BUILTIN_GATES:
            gate_result = evaluate_gate(gate_name, result)
            assert gate_result.passed, f"Gate {gate_name} should pass for clean codebase"

    def test_rsa_fails_pqc_ready(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        gate_result = evaluate_gate('pqc-ready', result)
        assert not gate_result.passed
        assert len(gate_result.failed_conditions) >= 1

    def test_critical_fails_no_critical(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        gate_result = evaluate_gate('no-critical', result)
        assert not gate_result.passed

    def test_medium_passes_no_critical(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.MEDIUM, Category.HASH, 'SHA-1',
                    '/test/foo.py', 10, 'hashlib.sha1()', 'SHA-1', 'Replace', 'SHA-256'),
        ]
        gate_result = evaluate_gate('no-critical', result)
        assert gate_result.passed

    def test_gate_report_format(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        gate_result = evaluate_gate('pqc-ready', result)
        report = format_gate_result(gate_result)
        assert 'Quality Gate' in report
        assert 'FAILED' in report or 'PASSED' in report

    def test_unknown_gate(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=0)
        gate_result = evaluate_gate('nonexistent-gate', result)
        assert not gate_result.passed


# ============================================================================
# CUSTOM RULES
# ============================================================================

class TestCustomRules:
    def test_builtin_jwt_rule(self):
        content = 'token = jwt.encode(payload, key, algorithm="RS256")\n'
        findings = scan_with_rules(BUILTIN_RULES, '/test/auth.py', content)
        jwt = [f for f in findings if 'JWT' in f.description or 'RS256' in f.code_snippet]
        assert len(jwt) >= 1

    def test_builtin_hardcoded_key_rule(self):
        content = "secret_key = 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxyz123456'\n"
        findings = scan_with_rules(BUILTIN_RULES, '/test/config.py', content)
        hardcoded = [f for f in findings if 'hardcoded' in f.description.lower()]
        assert len(hardcoded) >= 1

    def test_custom_rule_matching(self):
        rule = CustomRule(
            id='test-rule', severity=Severity.HIGH,
            category=Category.SYMMETRIC, algorithm='WeakCipher',
            message='Custom weak cipher detected',
            pattern=r'WeakCipher\.encrypt',
            languages=['python'],
        )
        rule.compile()
        content = 'result = WeakCipher.encrypt(data, key)\n'
        findings = scan_with_rules([rule], '/test/app.py', content)
        assert len(findings) == 1
        assert findings[0].id.startswith('RULE-')
        assert 'Custom weak cipher' in findings[0].description

    def test_rule_language_filter(self):
        rule = CustomRule(
            id='java-only', severity=Severity.HIGH,
            category=Category.SYMMETRIC, algorithm='Test',
            message='Java only rule',
            pattern=r'Cipher\.getInstance',
            languages=['java'],
        )
        rule.compile()
        # Should NOT match Python file
        findings = scan_with_rules([rule], '/test/app.py', 'Cipher.getInstance("AES")')
        assert len(findings) == 0
        # SHOULD match Java file
        findings = scan_with_rules([rule], '/test/App.java', 'Cipher.getInstance("AES")')
        assert len(findings) == 1

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
    def test_load_yaml_rules(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("""
rules:
  - id: test-yaml-rule
    severity: critical
    category: key_exchange
    algorithm: RSA
    message: "YAML rule test"
    pattern: "rsa\\\\.generate"
    languages: [python]
    fix: "Use ML-KEM"
""")
            f.flush()
            rules = load_rules_from_yaml(f.name)
        os.unlink(f.name)
        assert len(rules) == 1
        assert rules[0].id == 'test-yaml-rule'
        assert rules[0].severity == Severity.CRITICAL

    def test_clean_file_no_rule_matches(self):
        content = 'x = 1 + 2\nprint("hello world")\n'
        findings = scan_with_rules(BUILTIN_RULES, '/test/clean.py', content)
        assert len(findings) == 0
