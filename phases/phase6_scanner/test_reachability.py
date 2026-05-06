"""
Enigma pqc-scanner v4.0: Tests for reachability analysis + backward slicing.
"""
import os
import tempfile
import pytest

from reachability import (
    analyze_reachability, format_reachability_report,
    backward_slice_function, resolve_crypto_call_parameters,
    ReachabilityLevel, ResolvedParameter,
)
from pqc_scanner import Finding, Severity, Category


# ============================================================================
# REACHABILITY ANALYSIS
# ============================================================================

class TestReachability:
    def test_confirmed_when_imported_and_called(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
                f.write('from cryptography.hazmat.primitives.asymmetric import rsa\n')
                f.write('key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
            results = analyze_reachability(tmpdir, ['cryptography'])
            assert len(results) == 1
            assert results[0].level == ReachabilityLevel.CONFIRMED
            assert results[0].confidence >= 0.7

    def test_reachable_when_imported_only(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
                f.write('import cryptography\n')
                f.write('print("hello")\n')
            results = analyze_reachability(tmpdir, ['cryptography'])
            assert len(results) == 1
            assert results[0].level == ReachabilityLevel.REACHABLE

    def test_available_when_not_imported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
                f.write('print("no crypto here")\n')
            results = analyze_reachability(tmpdir, ['cryptography'])
            assert len(results) == 1
            assert results[0].level == ReachabilityLevel.AVAILABLE
            assert results[0].confidence <= 0.2

    def test_multiple_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
                f.write('import rsa\nkey = rsa.generate_private_key()\n')
            results = analyze_reachability(tmpdir, ['rsa', 'pycryptodome', 'paramiko'])
            levels = {r.package: r.level for r in results}
            assert levels['rsa'] == ReachabilityLevel.CONFIRMED
            assert levels['pycryptodome'] == ReachabilityLevel.AVAILABLE
            assert levels['paramiko'] == ReachabilityLevel.AVAILABLE

    def test_javascript_require(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.js'), 'w') as f:
                f.write("const rsa = require('node-rsa');\n")
                f.write("const key = new rsa.generate_private_key();\n")
            results = analyze_reachability(tmpdir, ['node-rsa'])
            assert len(results) == 1
            assert results[0].level == ReachabilityLevel.CONFIRMED

    def test_report_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
                f.write('from cryptography.hazmat.primitives.asymmetric import rsa\n')
                f.write('key = rsa.generate_private_key()\n')
            results = analyze_reachability(tmpdir, ['cryptography', 'paramiko'])
            report = format_reachability_report(results)
            assert 'REACHABILITY' in report
            assert 'CONFIRMED' in report
            assert 'AVAILABLE' in report


# ============================================================================
# BACKWARD SLICING
# ============================================================================

class TestBackwardSlicing:
    def test_resolve_string_literal(self):
        source = 'algo = "RSA"\ncipher = Cipher.getInstance(algo)\n'
        result = backward_slice_function(source, 2, 'algo')
        assert result is not None
        assert result.value == 'RSA'
        assert result.value_type == 'string'
        assert result.confidence == 'HIGH'

    def test_resolve_integer_literal(self):
        source = 'key_size = 2048\nkey = rsa.generate_private_key(key_size=key_size)\n'
        result = backward_slice_function(source, 2, 'key_size')
        assert result is not None
        assert result.value == '2048'
        assert result.value_type == 'integer'
        assert result.confidence == 'HIGH'

    def test_resolve_chained_variable(self):
        source = 'base_algo = "RSA"\nalgo = base_algo\ncipher = Cipher.getInstance(algo)\n'
        result = backward_slice_function(source, 3, 'algo')
        assert result is not None
        assert result.value == 'RSA'
        assert result.confidence == 'HIGH'

    def test_resolve_dict_get_default(self):
        source = 'algo = config.get("algorithm", "RSA")\ncipher = Cipher.getInstance(algo)\n'
        result = backward_slice_function(source, 2, 'algo')
        assert result is not None
        assert result.value == 'RSA'
        assert result.confidence == 'MEDIUM'

    def test_resolve_function_default(self):
        source = 'def create_key(algo="RSA"):\n    return gen(algo)\n'
        result = backward_slice_function(source, 2, 'algo')
        assert result is not None
        assert result.value == 'RSA'
        assert result.confidence == 'MEDIUM'

    def test_unresolvable_returns_none(self):
        source = 'key = generate_key(get_algo_from_db())\n'
        result = backward_slice_function(source, 1, 'get_algo_from_db')
        assert result is None

    def test_resolve_enhances_findings(self):
        source = (
            'algo = "RSA"\n'
            'key_size = 2048\n'
            'key = rsa.generate_private_key(key_size=key_size)\n'
        )
        findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/app.py', 3, 'key = rsa.generate_private_key(key_size=key_size)',
                    'RSA key generation', 'Replace', 'ML-KEM'),
        ]
        enhanced = resolve_crypto_call_parameters(source, findings, '/test/app.py')
        assert len(enhanced) == 1
        assert 'resolved' in enhanced[0].description
        assert '2048' in enhanced[0].description

    def test_no_enhancement_for_literal(self):
        source = 'key = rsa.generate_private_key(key_size=2048)\n'
        findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/app.py', 1, 'key = rsa.generate_private_key(key_size=2048)',
                    'RSA key generation', 'Replace', 'ML-KEM'),
        ]
        enhanced = resolve_crypto_call_parameters(source, findings, '/test/app.py')
        assert enhanced[0].description == findings[0].description  # No change
