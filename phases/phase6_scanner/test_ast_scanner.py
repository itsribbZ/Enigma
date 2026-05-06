"""
Tests for AST-based scanner and dependency scanner.
"""
import os
import tempfile
import json
import pytest
from ast_scanner import ast_scan_file, ast_scan_directory, CryptoASTVisitor
from dependency_scanner import scan_dependencies, format_dep_report, DepRisk


# ============================================================================
# AST SCANNER TESTS
# ============================================================================

@pytest.fixture
def temp_py():
    files = []
    def _create(code):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
        f.write(code)
        f.close()
        files.append(f.name)
        return f.name
    yield _create
    for p in files:
        os.unlink(p)


def test_ast_detect_rsa_import(temp_py):
    path = temp_py("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                   "key = rsa.generate_private_key(65537, 2048)\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'RSA' for f in findings)
    assert any(f.severity.value == 'CRITICAL' for f in findings)


def test_ast_detect_aliased_import(temp_py):
    path = temp_py("from cryptography.hazmat.primitives.asymmetric import rsa as key_gen\n"
                   "k = key_gen.generate_private_key(65537, 2048)\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'RSA' for f in findings)


def test_ast_detect_hashlib_sha1(temp_py):
    path = temp_py("import hashlib\nh = hashlib.sha1(b'data')\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'SHA-1' for f in findings)


def test_ast_detect_hashlib_md5(temp_py):
    path = temp_py("import hashlib\nh = hashlib.md5(b'data')\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'MD5' for f in findings)


def test_ast_detect_hashlib_new_with_string(temp_py):
    path = temp_py("import hashlib\nh = hashlib.new('sha1', b'data')\n")
    findings = ast_scan_file(path)
    assert any('SHA-1' in f.algorithm for f in findings)


def test_ast_detect_ecdsa(temp_py):
    path = temp_py("from cryptography.hazmat.primitives.asymmetric import ec\n"
                   "key = ec.generate_private_key(ec.SECP256R1())\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'ECDSA' for f in findings)


def test_ast_detect_pycrypto_des(temp_py):
    path = temp_py("from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == '3DES' for f in findings)


def test_ast_detect_string_algo_arg(temp_py):
    path = temp_py("import some_lib\nsome_lib.encrypt(data, algorithm='RSA')\n")
    findings = ast_scan_file(path)
    assert any(f.algorithm == 'RSA' for f in findings)


def test_ast_clean_file(temp_py):
    path = temp_py("import os\nprint('hello quantum-safe world')\n")
    findings = ast_scan_file(path)
    assert len(findings) == 0


def test_ast_syntax_error(temp_py):
    path = temp_py("def broken(\n")
    findings = ast_scan_file(path)
    assert len(findings) == 0  # Graceful skip


def test_ast_directory_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, 'app.py'), 'w') as f:
            f.write("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "rsa.generate_private_key(65537, 2048)\n")
        with open(os.path.join(tmpdir, 'safe.py'), 'w') as f:
            f.write("print('safe')\n")
        findings = ast_scan_directory(tmpdir)
        assert any(f.algorithm == 'RSA' for f in findings)
        assert all('safe.py' not in f.file for f in findings)


# ============================================================================
# DEPENDENCY SCANNER TESTS
# ============================================================================

def test_dep_scan_requirements_txt():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False,
                                      encoding='utf-8') as f:
        f.write("cryptography==42.0.0\nrequests==2.31.0\nrsa==4.9\nflask==3.0.0\n")
        path = f.name
    # Rename to requirements.txt
    req_path = os.path.join(os.path.dirname(path), 'requirements.txt')
    os.rename(path, req_path)

    findings = scan_dependencies(req_path)
    os.unlink(req_path)

    assert any(f.package == 'rsa' and f.risk == DepRisk.CRITICAL for f in findings)
    assert any('cryptography' in f.package for f in findings)
    assert not any(f.package == 'flask' for f in findings)


def test_dep_scan_package_json():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False,
                                      encoding='utf-8') as f:
        json.dump({
            "dependencies": {"node-rsa": "^1.1.1", "express": "^4.18.0"},
            "devDependencies": {"elliptic": "^6.5.0"}
        }, f)
        path = f.name
    pkg_path = os.path.join(os.path.dirname(path), 'package.json')
    os.rename(path, pkg_path)

    findings = scan_dependencies(pkg_path)
    os.unlink(pkg_path)

    assert any(f.package == 'node-rsa' and f.risk == DepRisk.CRITICAL for f in findings)
    assert any(f.package == 'elliptic' and f.risk == DepRisk.CRITICAL for f in findings)


def test_dep_scan_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = os.path.join(tmpdir, 'requirements.txt')
        with open(req, 'w') as f:
            f.write("pycryptodome==3.20.0\nparamiko==3.4.0\n")
        findings = scan_dependencies(tmpdir)
        assert len(findings) >= 2


def test_dep_report_format():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("rsa==4.9\n")
        path = f.name
    req_path = os.path.join(os.path.dirname(path), 'requirements.txt')
    os.rename(path, req_path)

    findings = scan_dependencies(req_path)
    os.unlink(req_path)
    report = format_dep_report(findings)
    assert 'DEPENDENCY SCAN' in report
    assert 'CRITICAL' in report


def test_dep_empty_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, 'requirements.txt'), 'w') as f:
            f.write("flask==3.0.0\nnumpy==1.26.0\n")
        findings = scan_dependencies(tmpdir)
        assert len(findings) == 0
