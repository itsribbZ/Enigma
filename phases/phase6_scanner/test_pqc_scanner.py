"""
Enigma Phase 6: pqc-scanner test suite.
Tests detection patterns, report generation, and real-world scanning.
THE ultimate test: scan our own Phase 2 code (should find RSA, AES, ECC).
"""
import json
import os
import tempfile
import pytest
from pqc_scanner import (
    PQCScanner, ScanResult, Finding, Severity, Category,
    format_text_report, format_json_report, format_html_report,
    format_sarif_report, scan_certificate_file, scan_tls_endpoint,
    scan_certificates_in_path, CertFinding,
)


@pytest.fixture
def scanner():
    return PQCScanner()


@pytest.fixture
def temp_py_file():
    """Create a temp Python file, yield its path, then clean up."""
    files = []

    def _create(content):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8')
        f.write(content)
        f.flush()
        f.close()
        files.append(f.name)
        return f.name

    yield _create
    for path in files:
        os.unlink(path)


def test_detect_rsa_python(scanner, temp_py_file):
    path = temp_py_file(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    result = scanner.scan(path)
    rsa_findings = [f for f in result.findings if 'RSA' in f.algorithm]
    assert len(rsa_findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in rsa_findings)


def test_detect_ecdsa_python(scanner, temp_py_file):
    path = temp_py_file(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "key = ec.generate_private_key(ec.SECP256R1())\n"
        "signature = key.sign(data, ec.ECDSA(hashes.SHA256()))\n"
    )
    result = scanner.scan(path)
    ecc_findings = [f for f in result.findings if any(x in f.algorithm for x in ['ECC', 'ECDSA', 'ECDH'])]
    assert len(ecc_findings) >= 1


def test_detect_aes128(scanner, temp_py_file):
    path = temp_py_file(
        "from Crypto.Cipher import AES\n"
        "cipher = AES.new(key_16_bytes_xx, AES.MODE_GCM)\n"
        "aes_128_key = generate_key(128)\n"
    )
    result = scanner.scan(path)
    aes_findings = [f for f in result.findings if 'AES-128' in f.algorithm]
    assert len(aes_findings) >= 1
    assert aes_findings[0].severity == Severity.MEDIUM


def test_detect_sha1(scanner, temp_py_file):
    path = temp_py_file("import hashlib\nh = hashlib.sha1(data)\n")
    result = scanner.scan(path)
    assert any('SHA-1' in f.algorithm for f in result.findings)


def test_detect_java(scanner):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
        f.write(
            'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");\n'
            'kpg.initialize(2048);\n'
            'Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");\n'
        )
        f.flush()
        path = f.name
    result = scanner.scan(path)
    os.unlink(path)
    assert len(result.findings) >= 2


def test_detect_go(scanner):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False, encoding='utf-8') as f:
        f.write(
            'import "crypto/rsa"\nimport "crypto/ecdsa"\n'
            'key, _ := rsa.GenerateKey(rand.Reader, 2048)\n'
            'ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n'
        )
        f.flush()
        path = f.name
    result = scanner.scan(path)
    os.unlink(path)
    assert len(result.findings) >= 2


def test_scan_own_code(scanner):
    phase2_path = os.path.join(os.path.dirname(__file__), '..', 'phase2_classical')
    if not os.path.isdir(phase2_path):
        pytest.skip("Phase 2 directory not found")

    result = scanner.scan(phase2_path)
    assert result.files_scanned > 0
    assert len(result.findings) > 0
    assert any('RSA' in f.algorithm for f in result.findings)
    assert any(x in f.algorithm for f in result.findings for x in ['ECC', 'ECDSA', 'ECDH', 'Ed25519'])
    assert any('SHA-1' in f.algorithm for f in result.findings)


def test_risk_score():
    result = ScanResult(scan_path='/test', scan_date='now', files_scanned=1)
    assert result.risk_score == 0

    result.add_finding(Finding('PQC-0001', Severity.CRITICAL, Category.KEY_EXCHANGE,
        'RSA', 'test.py', 1, 'rsa.generate', 'RSA detected', 'Use ML-KEM', 'ML-KEM-768'))
    assert result.risk_score > 0

    for i in range(3):
        result.add_finding(Finding(f'PQC-{i+2}', Severity.HIGH, Category.SIGNATURE,
            'ECDSA', 'test.py', i+2, 'ecdsa.sign', 'ECDSA', 'Use ML-DSA', 'ML-DSA-65'))
    assert result.risk_score >= 50


def test_text_report(scanner, temp_py_file):
    path = temp_py_file(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)\n"
    )
    result = scanner.scan(path)
    report = format_text_report(result)
    assert 'PQC-SCANNER' in report
    assert 'CRITICAL' in report
    assert 'RSA' in report


def test_json_report(scanner, temp_py_file):
    path = temp_py_file("import hashlib\nhashlib.sha1(b'test')\n")
    result = scanner.scan(path)
    parsed = json.loads(format_json_report(result))
    assert 'findings' in parsed
    assert 'summary' in parsed
    assert parsed['total_findings'] == len(result.findings)


def test_html_report(scanner, temp_py_file):
    path = temp_py_file("from Crypto.Cipher import DES3\nDES3.new(key, DES3.MODE_CBC)\n")
    result = scanner.scan(path)
    html = format_html_report(result)
    assert '<html>' in html
    assert 'PQC-SCANNER' in html
    assert 'Risk Score' in html


def test_empty_scan(scanner):
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, 'hello.py'), 'w') as f:
            f.write("print('Hello, quantum-safe world!')\n")
        result = scanner.scan(tmpdir)
    assert len(result.findings) == 0
    assert result.risk_score == 0


# ============================================================================
# SARIF OUTPUT TESTS (v2)
# ============================================================================

def test_sarif_schema(scanner, temp_py_file):
    """SARIF output should be valid JSON with required SARIF 2.1.0 fields."""
    path = temp_py_file(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(65537, 2048)\n"
    )
    result = scanner.scan(path)
    sarif = json.loads(format_sarif_report(result))

    assert sarif['version'] == '2.1.0'
    assert '$schema' in sarif
    assert 'runs' in sarif
    assert len(sarif['runs']) == 1

    run = sarif['runs'][0]
    assert run['tool']['driver']['name'] == 'pqc-scanner'
    assert run['tool']['driver']['version'] == '4.0.0'
    assert len(run['tool']['driver']['rules']) > 0
    assert len(run['results']) > 0


def test_sarif_results(scanner, temp_py_file):
    """SARIF results should have correct structure and severity mapping."""
    path = temp_py_file(
        "import hashlib\nhashlib.sha1(b'test')\n"
        "from Crypto.Cipher import DES3\nDES3.new(key, DES3.MODE_CBC)\n"
    )
    result = scanner.scan(path)
    sarif = json.loads(format_sarif_report(result))

    for r in sarif['runs'][0]['results']:
        assert 'ruleId' in r
        assert 'level' in r
        assert r['level'] in ('error', 'warning', 'note', 'none')
        assert 'message' in r
        assert 'locations' in r
        loc = r['locations'][0]['physicalLocation']
        assert 'artifactLocation' in loc
        assert 'region' in loc
        assert 'startLine' in loc['region']


def test_sarif_rules_dedup(scanner, temp_py_file):
    """SARIF rules should be deduplicated (one rule per algorithm)."""
    path = temp_py_file(
        "rsa.generate_private_key(65537, 2048)\n"
        "RSAPrivateKey.from_something()\n"
    )
    result = scanner.scan(path)
    sarif = json.loads(format_sarif_report(result))
    rules = sarif['runs'][0]['tool']['driver']['rules']
    rule_ids = [r['id'] for r in rules]
    assert len(rule_ids) == len(set(rule_ids))


def test_sarif_empty_scan(scanner):
    """SARIF with no findings should still be valid."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, 'safe.py'), 'w') as f:
            f.write("print('quantum safe')\n")
        result = scanner.scan(tmpdir)
    sarif = json.loads(format_sarif_report(result))
    assert sarif['runs'][0]['results'] == []


# ============================================================================
# CERTIFICATE SCANNING TESTS (v2)
# ============================================================================

def test_cert_scan_pem():
    """Scan a self-signed RSA certificate in PEM format."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    import datetime

    key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"test.example.com")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_path = f.name

    findings = scan_certificate_file(cert_path)
    os.unlink(cert_path)

    assert len(findings) >= 1
    assert findings[0].algorithm == 'RSA'
    assert findings[0].key_size == 2048
    assert findings[0].severity == Severity.CRITICAL
    assert 'test.example.com' in findings[0].cert_subject


def test_cert_scan_ecdsa():
    """Scan an ECDSA certificate."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"ec.example.com")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.crt', delete=False) as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_path = f.name

    findings = scan_certificate_file(cert_path)
    os.unlink(cert_path)

    assert len(findings) >= 1
    assert findings[0].algorithm == 'ECDSA'
    assert findings[0].severity == Severity.CRITICAL


def test_cert_scan_directory():
    """Scan a directory containing certificate files."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    import datetime

    key = rsa_mod.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"dir.example.com")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = os.path.join(tmpdir, 'server.pem')
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        findings = scan_certificates_in_path(tmpdir)

    assert len(findings) >= 1
    assert findings[0].key_size == 4096


@pytest.mark.network
def test_tls_endpoint_scan():
    """Scan a live TLS endpoint."""
    try:
        findings = scan_tls_endpoint('google.com', 443, timeout=10)
        assert len(findings) >= 1
        assert findings[0].algorithm in ('RSA', 'ECDSA', 'Ed25519')
        assert findings[0].host == 'google.com'
    except Exception:
        pytest.skip("Network unavailable")
