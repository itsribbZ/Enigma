"""
Enigma Phase 2: TLS Analyzer test suite.
Tests parsing, cipher suite analysis, and live connection analysis.
"""
import struct
import pytest
from tls_analyzer import (
    parse_record_header, parse_handshake_header, parse_server_hello,
    analyze_cipher_suite, detect_pqc, format_report,
    TLSAnalyzer, TLSAnalysisResult, CIPHER_SUITES, NAMED_GROUPS,
)


def test_parse_record_header():
    data = struct.pack('!BBBH', 0x16, 0x03, 0x03, 0x0200)
    rec = parse_record_header(data)
    assert rec['content_type'] == 0x16
    assert rec['content_type_name'] == 'Handshake'
    assert rec['version'] == (3, 3)
    assert rec['length'] == 512

    data2 = struct.pack('!BBBH', 0x15, 0x03, 0x01, 0x0002)
    rec2 = parse_record_header(data2)
    assert rec2['content_type_name'] == 'Alert'
    assert rec2['length'] == 2


def test_parse_handshake_header():
    data = b'\x02' + (100).to_bytes(3, 'big')
    hs = parse_handshake_header(data)
    assert hs['type'] == 0x02
    assert hs['type_name'] == 'ServerHello'
    assert hs['length'] == 100

    data2 = b'\x01' + (200).to_bytes(3, 'big')
    assert parse_handshake_header(data2)['type_name'] == 'ClientHello'


def test_cipher_suite_analysis():
    a1 = analyze_cipher_suite('TLS_AES_256_GCM_SHA384')
    assert a1['tls_version'] == '1.3'
    assert a1['encryption'] == 'AES-256-GCM'

    a2 = analyze_cipher_suite('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256')
    assert a2['tls_version'] == '1.2'
    assert 'ECDHE' in a2['key_exchange']
    assert a2['authentication'] == 'RSA'

    a3 = analyze_cipher_suite('TLS_RSA_WITH_AES_256_CBC_SHA')
    assert 'NO forward secrecy' in a3['key_exchange']


def test_pqc_detection():
    detected, pqc = detect_pqc(['x25519', 'secp256r1', 'secp384r1'])
    assert not detected

    detected2, pqc2 = detect_pqc(['x25519', 'X25519Kyber768Draft00', 'secp256r1'])
    assert detected2
    assert 'X25519Kyber768Draft00' in pqc2

    detected3, _ = detect_pqc(['X25519MLKEM768', 'x25519'])
    assert detected3


def test_format_report():
    result = TLSAnalysisResult(
        host='example.com', port=443,
        tls_version='TLSv1.3',
        cipher_suite='TLS_AES_256_GCM_SHA384',
        certificate_subject='example.com',
        certificate_issuer='DigiCert Inc',
        key_exchange='ECDHE',
    )
    report = format_report(result)
    assert 'example.com' in report
    assert 'TLSv1.3' in report


def test_cipher_suite_constants():
    assert CIPHER_SUITES[0x1301] == 'TLS_AES_128_GCM_SHA256'
    assert CIPHER_SUITES[0xC02F] == 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    assert 'Kyber' in NAMED_GROUPS[0x6399]


@pytest.mark.network
def test_live_analysis():
    analyzer = TLSAnalyzer()
    try:
        result = analyzer.analyze('google.com', 443, timeout=10)
        assert 'ERROR' not in result.tls_version
        assert result.tls_version != ''
        assert result.cipher_suite != ''
        assert result.certificate_subject != ''
    except Exception:
        pytest.skip("Network unavailable")


@pytest.mark.network
def test_raw_analysis():
    analyzer = TLSAnalyzer()
    try:
        result = analyzer.analyze_raw('google.com', 443, timeout=10)
        if result.raw_server_hello:
            sh = result.raw_server_hello
            assert 'cipher_suite' in sh
            assert 'cipher_suite_id' in sh
        else:
            pytest.skip("No ServerHello received")
    except Exception:
        pytest.skip("Network unavailable")
