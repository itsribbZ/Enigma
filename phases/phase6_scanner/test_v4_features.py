"""
Enigma pqc-scanner v4.0 — Tests for new features.
Comment stripping, suppression, baseline diffing, CBOM output.
"""
import json
import os
import tempfile
import pytest
from pqc_scanner import (
    PQCScanner, ScanResult, Finding, Severity, Category,
    strip_comments, strip_string_literals, strip_block_comments,
    has_inline_suppression,
    load_pqcignore, is_suppressed, diff_against_baseline,
    format_cbom_report, format_json_report, __version__,
)


# ============================================================================
# COMMENT STRIPPING
# ============================================================================

class TestCommentStripping:
    def test_python_comment(self):
        line = 'key = rsa.generate_private_key()  # Generate RSA key'
        stripped = strip_comments(line, 'Python')
        assert 'rsa.generate_private_key()' in stripped
        assert '# Generate RSA key' not in stripped

    def test_python_comment_only(self):
        line = '# This uses RSA encryption for key exchange'
        stripped = strip_comments(line, 'Python')
        assert 'RSA' not in stripped

    def test_java_comment(self):
        line = 'Cipher cipher = Cipher.getInstance("RSA");  // RSA cipher'
        stripped = strip_comments(line, 'Java')
        assert 'Cipher.getInstance("RSA")' in stripped
        assert '// RSA cipher' not in stripped

    def test_go_comment(self):
        line = 'key, _ := rsa.GenerateKey(rand.Reader, 2048)  // generate key'
        stripped = strip_comments(line, 'Go')
        assert 'rsa.GenerateKey' in stripped

    def test_preserves_hash_in_string(self):
        """A # inside a string literal should NOT be treated as a comment."""
        line = 'algo = "sha1#old"  # comment'
        stripped = strip_comments(line, 'Python')
        assert '"sha1#old"' in stripped
        assert '# comment' not in stripped

    def test_no_comment_language(self):
        line = 'some content with RSA in it'
        stripped = strip_comments(line, 'UnknownLang')
        assert stripped == line


class TestBlockCommentStripping:
    """Tests for multi-line /* ... */, =begin/=end, and <!-- --> comment removal."""

    def test_c_style_block_comment(self):
        code = 'real();\n/* RSA.Create() */\nmore();'
        stripped = strip_block_comments(code, 'Java')
        assert 'RSA' not in stripped
        assert 'real()' in stripped
        assert 'more()' in stripped

    def test_multiline_block_preserves_line_count(self):
        code = 'line1\n/* block\ncomment\nhere */\nline5'
        stripped = strip_block_comments(code, 'Java')
        assert stripped.count('\n') == code.count('\n')
        lines = stripped.split('\n')
        assert lines[0] == 'line1'
        assert lines[4] == 'line5'

    def test_block_comment_inside_string_not_stripped(self):
        code = 'String s = "/* not a comment */";'
        stripped = strip_block_comments(code, 'Java')
        assert '/* not a comment */' in stripped

    def test_multiple_block_comments(self):
        code = '/* c1 */\ncode();\n/* c2 */\nmore();'
        stripped = strip_block_comments(code, 'Java')
        assert 'c1' not in stripped
        assert 'c2' not in stripped
        assert 'code()' in stripped
        assert 'more()' in stripped

    def test_ruby_begin_end(self):
        code = "code1\n=begin\nRSA.new(2048)\n=end\ncode2"
        stripped = strip_block_comments(code, 'Ruby')
        assert 'RSA' not in stripped
        assert 'code1' in stripped
        assert 'code2' in stripped

    def test_html_comment(self):
        code = '<!-- algorithm: RSA\nkey_size: 1024 -->\nalgorithm: ECDSA'
        stripped = strip_block_comments(code, 'Config')
        assert 'RSA' not in stripped
        assert 'ECDSA' in stripped

    def test_python_triple_strings_stripped(self):
        """Python triple-quoted strings (docstrings) ARE treated as comments for scanning
        purposes — algorithm names inside docstrings generate false positives otherwise.
        """
        code = '"""\nRSA key generation\n"""\nx = 1'
        stripped = strip_block_comments(code, 'Python')
        # Content inside docstring is blanked; line count preserved.
        assert 'RSA' not in stripped
        assert 'x = 1' in stripped

    def test_all_c_family_languages(self):
        """All C-family languages should strip /* */ comments."""
        code = '/* RSA */ real_code();'
        for lang in ['Java', 'Go', 'JavaScript', 'C/C++', 'Rust',
                     'C#', 'Kotlin', 'Swift', 'Scala', 'PHP']:
            stripped = strip_block_comments(code, lang)
            assert 'RSA' not in stripped, f'{lang} failed to strip block comment'
            assert 'real_code()' in stripped, f'{lang} stripped real code'

    def test_scanner_integration_block_comment(self):
        """Scanner should NOT fire on crypto patterns inside block comments."""
        scanner = PQCScanner(strip_comments=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write('/* Cipher.getInstance("RSA") */\n')
            f.write('// Cipher.getInstance("DES")\n')
            f.write('Cipher.getInstance("AES");\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        algos = [fnd.algorithm for fnd in result.findings]
        assert 'RSA' not in algos, 'Block comment RSA should be suppressed'
        assert 'DES' not in algos, 'Single-line comment DES should be suppressed'

    def test_scanner_no_strip_finds_block_comments(self):
        """With stripping disabled, block comment patterns SHOULD fire."""
        scanner = PQCScanner(strip_comments=False)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write('/* Cipher.getInstance("RSA") */\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        # With no stripping, regex will match inside the comment
        assert len(result.findings) >= 1


class TestStringStripping:
    def test_strips_double_quoted(self):
        line = 'print("Using RSA encryption")'
        stripped = strip_string_literals(line)
        assert 'RSA' not in stripped
        assert 'print(' in stripped

    def test_strips_single_quoted(self):
        line = "algo = 'sha1'"
        stripped = strip_string_literals(line)
        assert 'sha1' not in stripped

    def test_preserves_code(self):
        line = 'key = rsa.generate_private_key()'
        stripped = strip_string_literals(line)
        assert 'rsa.generate_private_key()' in stripped

    def test_triple_quotes(self):
        line = '"""RSA is quantum-vulnerable"""'
        stripped = strip_string_literals(line)
        assert 'RSA' not in stripped


class TestFalsePositiveElimination:
    """Integration tests: scanner should NOT fire on comments."""

    @pytest.fixture
    def scanner(self):
        return PQCScanner(strip_comments=True, strip_strings=False)

    @pytest.fixture
    def scanner_with_string_strip(self):
        return PQCScanner(strip_comments=True, strip_strings=True)

    @pytest.fixture
    def scanner_no_strip(self):
        return PQCScanner(strip_comments=False, strip_strings=False)

    def test_comment_not_detected(self, scanner):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('# OLD: key = rsa.generate_private_key()\n')
            f.write('# This uses SHA-1 for backward compat\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        assert len(result.findings) == 0

    def test_string_not_detected_when_enabled(self, scanner_with_string_strip):
        """With string stripping ON, algorithm names in strings are ignored."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('msg = "Please migrate from RSA to ML-KEM"\n')
            f.write('log.info("SHA-1 hash detected in legacy system")\n')
            f.flush()
            result = scanner_with_string_strip.scan(f.name)
        os.unlink(f.name)
        assert len(result.findings) == 0

    def test_real_code_still_detected(self, scanner):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        rsa = [ff for ff in result.findings if 'RSA' in ff.algorithm]
        assert len(rsa) >= 1

    def test_no_strip_catches_comments(self, scanner_no_strip):
        """Without stripping, comments SHOULD trigger findings (old behavior)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('# key = rsa.generate_private_key()\n')
            f.flush()
            result = scanner_no_strip.scan(f.name)
        os.unlink(f.name)
        assert len(result.findings) >= 1

    def test_java_string_args_still_detected(self, scanner):
        """With default settings, Java crypto APIs with string args still work."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
            f.write('KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        assert len(result.findings) >= 1


# ============================================================================
# SUPPRESSION SYSTEM
# ============================================================================

class TestInlineSuppression:
    def test_blanket_suppression(self):
        assert has_inline_suppression('key = rsa.gen()  # pqc-ignore')
        assert has_inline_suppression('key = rsa.gen()  # pqc-ignore  ')

    def test_algo_specific_suppression(self):
        assert has_inline_suppression('key = rsa.gen()  # pqc-ignore[RSA]', 'RSA')
        assert not has_inline_suppression('key = rsa.gen()  # pqc-ignore[DH]', 'RSA')

    def test_multi_algo_suppression(self):
        assert has_inline_suppression('x = y  # pqc-ignore[RSA,DH]', 'RSA')
        assert has_inline_suppression('x = y  # pqc-ignore[RSA,DH]', 'DH')
        assert not has_inline_suppression('x = y  # pqc-ignore[RSA,DH]', 'ECDSA')

    def test_no_suppression(self):
        assert not has_inline_suppression('key = rsa.generate_private_key()')

    def test_scanner_respects_inline_suppression(self):
        scanner = PQCScanner()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('key = rsa.generate_private_key()  # pqc-ignore\n')
            f.write('h = hashlib.sha1(data)\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)
        # RSA suppressed, SHA-1 should still be found
        rsa = [ff for ff in result.findings if 'RSA' in ff.algorithm]
        sha = [ff for ff in result.findings if 'SHA' in ff.algorithm]
        assert len(rsa) == 0
        assert len(sha) >= 1
        assert scanner.suppressed_count >= 1


class TestPqcignore:
    def test_load_pqcignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, '.pqcignore')
            with open(ignore_file, 'w') as f:
                f.write('# Comment\n')
                f.write('tests/*\n')
                f.write('vendor/**\n')
                f.write('\n')
                f.write('legacy.py\n')
            patterns = load_pqcignore(tmpdir)
            assert 'tests/*' in patterns
            assert 'vendor/**' in patterns
            assert 'legacy.py' in patterns
            assert len(patterns) == 3

    def test_is_suppressed(self):
        patterns = ['tests/*', 'legacy.py']
        assert is_suppressed('/project/tests/test_foo.py', '/project', patterns)
        assert is_suppressed('/project/legacy.py', '/project', patterns)
        assert not is_suppressed('/project/src/main.py', '/project', patterns)

    def test_scanner_respects_pqcignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create .pqcignore
            with open(os.path.join(tmpdir, '.pqcignore'), 'w') as f:
                f.write('ignored.py\n')
            # Create two files
            with open(os.path.join(tmpdir, 'ignored.py'), 'w') as f:
                f.write('key = rsa.generate_private_key()\n')
            with open(os.path.join(tmpdir, 'scanned.py'), 'w') as f:
                f.write('key = rsa.generate_private_key()\n')

            scanner = PQCScanner()
            result = scanner.scan(tmpdir)
            files_with_findings = {os.path.basename(ff.file) for ff in result.findings}
            assert 'scanned.py' in files_with_findings
            assert 'ignored.py' not in files_with_findings


# ============================================================================
# BASELINE DIFFING
# ============================================================================

class TestBaselineDiffing:
    def test_all_new_without_baseline(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        diff = diff_against_baseline(result, '/nonexistent/baseline.json')
        assert len(diff['new']) == 1
        assert len(diff['fixed']) == 0

    def test_existing_finding(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = [
            Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE, 'RSA',
                    '/test/foo.py', 10, 'rsa.gen()', 'RSA', 'Replace', 'ML-KEM'),
        ]
        # Create baseline with same finding (matching last 2 path components)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                'findings': [{
                    'file': '/test/foo.py', 'line': 10,
                    'algorithm': 'RSA', 'category': 'KEY_EXCHANGE',
                }]
            }, f)
            f.flush()
            diff = diff_against_baseline(result, f.name)
        os.unlink(f.name)
        assert len(diff['existing']) == 1
        assert len(diff['new']) == 0

    def test_fixed_finding(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=1)
        result.findings = []  # No findings in current scan
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                'findings': [{
                    'file': '/old/foo.py', 'line': 10,
                    'algorithm': 'RSA', 'category': 'KEY_EXCHANGE',
                }]
            }, f)
            f.flush()
            diff = diff_against_baseline(result, f.name)
        os.unlink(f.name)
        assert len(diff['fixed']) == 1


# ============================================================================
# CBOM OUTPUT
# ============================================================================

class TestCBOM:
    def test_cbom_structure(self):
        scanner = PQCScanner()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('key = rsa.generate_private_key()\n')
            f.write('h = hashlib.md5(data)\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)

        cbom_str = format_cbom_report(result)
        cbom = json.loads(cbom_str)

        assert cbom['bomFormat'] == 'CycloneDX'
        assert cbom['specVersion'] == '1.7'
        assert 'serialNumber' in cbom
        assert cbom['serialNumber'].startswith('urn:uuid:')
        assert cbom['metadata']['tools']['components'][0]['name'] == 'pqc-scanner'
        assert cbom['metadata']['tools']['components'][0]['version'] == __version__
        assert len(cbom['components']) >= 1

    def test_cbom_crypto_components(self):
        scanner = PQCScanner()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('key = rsa.generate_private_key()\n')
            f.flush()
            result = scanner.scan(f.name)
        os.unlink(f.name)

        cbom = json.loads(format_cbom_report(result))
        rsa_comps = [c for c in cbom['components'] if c['name'] == 'RSA']
        assert len(rsa_comps) == 1
        comp = rsa_comps[0]
        assert comp['type'] == 'cryptographic-asset'
        assert comp['cryptoProperties']['assetType'] == 'algorithm'
        assert 'quantumSafe' in str(comp['properties'])

    def test_cbom_empty_scan(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=0)
        cbom = json.loads(format_cbom_report(result))
        assert cbom['bomFormat'] == 'CycloneDX'
        assert len(cbom['components']) == 0


# ============================================================================
# VERSION
# ============================================================================

class TestVersion:
    def test_version_string(self):
        assert __version__ == '4.0.0'

    def test_sarif_version(self):
        result = ScanResult(scan_path='/test', scan_date='2026-01-01', files_scanned=0)
        from pqc_scanner import format_sarif_report
        sarif = json.loads(format_sarif_report(result))
        assert sarif['runs'][0]['tool']['driver']['version'] == '4.0.0'
