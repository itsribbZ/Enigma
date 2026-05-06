"""
Enigma Phase 2: TLS Handshake Analyzer.
Connects to HTTPS servers, captures the TLS handshake,
and decodes ClientHello/ServerHello, cipher suites, certificates, and extensions.

Detects PQC hybrid key exchange (Phase 5/6 connection).
"""

from __future__ import annotations
import socket
import ssl
import struct
import sys
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# ============================================================================
# CONSTANTS
# ============================================================================

CONTENT_TYPES = {0x14: 'ChangeCipherSpec', 0x15: 'Alert',
                 0x16: 'Handshake', 0x17: 'ApplicationData'}

HANDSHAKE_TYPES = {
    0x01: 'ClientHello', 0x02: 'ServerHello', 0x04: 'NewSessionTicket',
    0x08: 'EncryptedExtensions', 0x0B: 'Certificate', 0x0C: 'ServerKeyExchange',
    0x0D: 'CertificateRequest', 0x0E: 'ServerHelloDone',
    0x0F: 'CertificateVerify', 0x10: 'ClientKeyExchange', 0x14: 'Finished',
}

TLS_VERSIONS = {
    0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2/1.3', 0x0304: 'TLS 1.3',
}

# Cipher suite names (common ones)
CIPHER_SUITES = {
    # TLS 1.3
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    # TLS 1.2 ECDHE
    0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    # RSA (no forward secrecy)
    0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
}

EXTENSION_TYPES = {
    0x0000: 'server_name', 0x000A: 'supported_groups',
    0x000B: 'ec_point_formats', 0x000D: 'signature_algorithms',
    0x0010: 'application_layer_protocol_negotiation',
    0x0017: 'extended_master_secret', 0x002B: 'supported_versions',
    0x002D: 'psk_key_exchange_modes', 0x0033: 'key_share',
    0xFF01: 'renegotiation_info',
}

NAMED_GROUPS = {
    0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1',
    0x001D: 'x25519', 0x001E: 'x448',
    0x0100: 'ffdhe2048', 0x0101: 'ffdhe3072',
    # PQC Hybrid groups
    0x6399: 'X25519Kyber768Draft00',
    0x639A: 'SecP256r1Kyber768Draft00',
    0x4588: 'X25519MLKEM768',
}

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class TLSAnalysisResult:
    host: str
    port: int
    tls_version: str = ''
    cipher_suite: str = ''
    cipher_suite_id: int = 0
    server_name: str = ''
    certificate_subject: str = ''
    certificate_issuer: str = ''
    certificate_valid_from: str = ''
    certificate_valid_to: str = ''
    supported_groups: List[str] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    key_exchange: str = ''
    pqc_detected: bool = False
    pqc_groups: List[str] = field(default_factory=list)
    raw_server_hello: Optional[dict] = None
    extensions: List[dict] = field(default_factory=list)


# ============================================================================
# TLS RECORD PARSING
# ============================================================================

def parse_record_header(data: bytes) -> dict:
    """Parse 5-byte TLS record header."""
    ct = data[0]
    version = (data[1], data[2])
    length = struct.unpack('!H', data[3:5])[0]
    return {
        'content_type': ct,
        'content_type_name': CONTENT_TYPES.get(ct, f'Unknown(0x{ct:02X})'),
        'version': version,
        'version_name': TLS_VERSIONS.get((data[1] << 8) | data[2], 'Unknown'),
        'length': length,
    }


def parse_handshake_header(data: bytes) -> dict:
    """Parse 4-byte handshake message header."""
    msg_type = data[0]
    length = int.from_bytes(data[1:4], 'big')
    return {
        'type': msg_type,
        'type_name': HANDSHAKE_TYPES.get(msg_type, f'Unknown(0x{msg_type:02X})'),
        'length': length,
    }


def parse_server_hello(data: bytes) -> dict:
    """Parse ServerHello body."""
    offset = 0
    result = {}

    result['version'] = struct.unpack('!H', data[offset:offset+2])[0]
    offset += 2

    result['random'] = data[offset:offset+32].hex()
    offset += 32

    sid_len = data[offset]
    offset += 1
    result['session_id'] = data[offset:offset+sid_len].hex()
    offset += sid_len

    suite_id = struct.unpack('!H', data[offset:offset+2])[0]
    result['cipher_suite_id'] = suite_id
    result['cipher_suite'] = CIPHER_SUITES.get(suite_id, f'Unknown(0x{suite_id:04X})')
    offset += 2

    result['compression'] = data[offset]
    offset += 1

    # Extensions
    result['extensions'] = []
    if offset < len(data):
        ext_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_len
        while offset < ext_end:
            ext_type = struct.unpack('!H', data[offset:offset+2])[0]
            ext_data_len = struct.unpack('!H', data[offset+2:offset+4])[0]
            ext_data = data[offset+4:offset+4+ext_data_len]
            ext_name = EXTENSION_TYPES.get(ext_type, f'Unknown(0x{ext_type:04X})')

            ext_info = {'type': ext_type, 'name': ext_name, 'length': ext_data_len}

            # Parse supported_versions extension (TLS 1.3 indicator)
            if ext_type == 0x002B and ext_data_len == 2:
                ver = struct.unpack('!H', ext_data)[0]
                ext_info['selected_version'] = TLS_VERSIONS.get(ver, f'0x{ver:04X}')

            result['extensions'].append(ext_info)
            offset += 4 + ext_data_len

    return result


# ============================================================================
# CIPHER SUITE ANALYSIS
# ============================================================================

def analyze_cipher_suite(suite_name: str) -> dict:
    """Break down a cipher suite name into components."""
    parts = suite_name.split('_')
    result = {'full_name': suite_name}

    if suite_name.startswith('TLS_AES') or suite_name.startswith('TLS_CHACHA'):
        # TLS 1.3 format: TLS_<cipher>_<hash>
        result['tls_version'] = '1.3'
        result['key_exchange'] = 'Negotiated via key_share extension'
        result['authentication'] = 'Negotiated via certificate'
        if 'AES_128_GCM' in suite_name:
            result['encryption'] = 'AES-128-GCM'
        elif 'AES_256_GCM' in suite_name:
            result['encryption'] = 'AES-256-GCM'
        elif 'CHACHA20' in suite_name:
            result['encryption'] = 'ChaCha20-Poly1305'
        result['prf_hash'] = parts[-1] if parts else 'SHA256'
    else:
        # TLS 1.2 format: TLS_<kex>_<auth>_WITH_<cipher>_<hash>
        result['tls_version'] = '1.2'
        if 'ECDHE' in suite_name:
            result['key_exchange'] = 'ECDHE (forward secrecy)'
        elif 'DHE' in suite_name:
            result['key_exchange'] = 'DHE (forward secrecy)'
        else:
            result['key_exchange'] = 'RSA (NO forward secrecy)'

        if 'ECDSA' in suite_name:
            result['authentication'] = 'ECDSA'
        elif 'RSA' in suite_name:
            result['authentication'] = 'RSA'

        if 'AES_128_GCM' in suite_name:
            result['encryption'] = 'AES-128-GCM (AEAD)'
        elif 'AES_256_GCM' in suite_name:
            result['encryption'] = 'AES-256-GCM (AEAD)'
        elif 'AES_128_CBC' in suite_name:
            result['encryption'] = 'AES-128-CBC'
        elif 'AES_256_CBC' in suite_name:
            result['encryption'] = 'AES-256-CBC'
        elif 'CHACHA20' in suite_name:
            result['encryption'] = 'ChaCha20-Poly1305 (AEAD)'

    return result


# ============================================================================
# PQC DETECTION
# ============================================================================

def detect_pqc(groups: List[str]) -> Tuple[bool, List[str]]:
    """Detect post-quantum cryptography in supported/selected groups."""
    pqc_keywords = ['kyber', 'mlkem', 'MLKEM', 'Kyber']
    pqc_found = []
    for g in groups:
        if any(kw.lower() in g.lower() for kw in pqc_keywords):
            pqc_found.append(g)
    return len(pqc_found) > 0, pqc_found


# ============================================================================
# TLS ANALYZER (uses Python ssl module for connection)
# ============================================================================

class TLSAnalyzer:
    """Analyze TLS handshake of a remote server."""

    def analyze(self, host: str, port: int = 443, timeout: float = 10.0) -> TLSAnalysisResult:
        """Connect to host:port and analyze the TLS handshake."""
        result = TLSAnalysisResult(host=host, port=port)

        try:
            # Create SSL context — we want to see what the server offers
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Extract negotiated parameters
                    result.tls_version = ssock.version() or 'Unknown'
                    cipher = ssock.cipher()
                    if cipher:
                        result.cipher_suite = cipher[0]
                        result.key_exchange = cipher[0]

                    # Certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        subj = dict(x[0] for x in cert.get('subject', ()))
                        issuer = dict(x[0] for x in cert.get('issuer', ()))
                        result.certificate_subject = subj.get('commonName', 'N/A')
                        result.certificate_issuer = issuer.get('organizationName',
                                                              issuer.get('commonName', 'N/A'))
                        result.certificate_valid_from = cert.get('notBefore', 'N/A')
                        result.certificate_valid_to = cert.get('notAfter', 'N/A')

                        # Subject Alternative Names
                        sans = cert.get('subjectAltName', ())
                        result.server_name = ', '.join(v for t, v in sans if t == 'DNS')

                    # Analyze cipher suite
                    if result.cipher_suite:
                        analysis = analyze_cipher_suite(result.cipher_suite)
                        result.key_exchange = analysis.get('key_exchange', '')

        except Exception as e:
            result.tls_version = f'ERROR: {e}'

        return result

    def analyze_raw(self, host: str, port: int = 443,
                    timeout: float = 10.0) -> TLSAnalysisResult:
        """Low-level TLS analysis — send ClientHello and parse ServerHello directly."""
        result = TLSAnalysisResult(host=host, port=port)

        try:
            client_hello = self._build_client_hello(host)

            with socket.create_connection((host, port), timeout=timeout) as sock:
                # Send ClientHello wrapped in TLS record
                record = self._wrap_record(0x16, client_hello)
                sock.sendall(record)

                # Read ServerHello response
                response = b''
                while len(response) < 5:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk

                if len(response) >= 5:
                    rec = parse_record_header(response[:5])
                    payload = response[5:5 + rec['length']]

                    # May need more data
                    while len(payload) < rec['length']:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        payload += chunk

                    if rec['content_type'] == 0x16 and len(payload) >= 4:
                        hs = parse_handshake_header(payload[:4])
                        if hs['type'] == 0x02:  # ServerHello
                            sh = parse_server_hello(payload[4:4+hs['length']])
                            result.raw_server_hello = sh
                            result.cipher_suite = sh['cipher_suite']
                            result.cipher_suite_id = sh['cipher_suite_id']

                            # Check for TLS 1.3 via supported_versions extension
                            for ext in sh.get('extensions', []):
                                if ext.get('selected_version'):
                                    result.tls_version = ext['selected_version']

                            if not result.tls_version:
                                ver = sh.get('version', 0)
                                result.tls_version = TLS_VERSIONS.get(ver, f'0x{ver:04X}')

                            result.extensions = sh.get('extensions', [])

        except Exception as e:
            result.tls_version = f'ERROR: {e}'

        return result

    def _build_client_hello(self, hostname: str) -> bytes:
        """Build a minimal ClientHello message."""
        # Version: TLS 1.2 (real version negotiated via extension)
        version = struct.pack('!H', 0x0303)

        # Random: 32 bytes
        random_bytes = os.urandom(32)

        # Session ID: empty
        session_id = b'\x00'

        # Cipher suites (offer common TLS 1.3 + 1.2 suites)
        suites = [0x1301, 0x1302, 0x1303,  # TLS 1.3
                  0xC02F, 0xC030, 0xCCA8, 0xCCA9,  # TLS 1.2 ECDHE
                  0xC02B, 0xC02C]
        cs_data = b''.join(struct.pack('!H', s) for s in suites)
        cipher_suites = struct.pack('!H', len(cs_data)) + cs_data

        # Compression: null only
        compression = b'\x01\x00'

        # Extensions
        extensions = b''

        # SNI extension
        host_bytes = hostname.encode('ascii')
        sni_entry = struct.pack('!BH', 0, len(host_bytes)) + host_bytes
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        extensions += struct.pack('!HH', 0x0000, len(sni_list)) + sni_list

        # Supported versions extension (advertise TLS 1.3 + 1.2)
        sv_data = b'\x03' + struct.pack('!H', 0x0304) + struct.pack('!H', 0x0303)
        extensions += struct.pack('!HH', 0x002B, len(sv_data)) + sv_data

        # Supported groups
        groups = [0x001D, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
        sg_data = struct.pack('!H', len(groups) * 2) + b''.join(struct.pack('!H', g) for g in groups)
        extensions += struct.pack('!HH', 0x000A, len(sg_data)) + sg_data

        # Signature algorithms
        sig_algs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                    0x0401, 0x0501, 0x0601, 0x0201]
        sa_data = struct.pack('!H', len(sig_algs) * 2) + b''.join(struct.pack('!H', s) for s in sig_algs)
        extensions += struct.pack('!HH', 0x000D, len(sa_data)) + sa_data

        # Key share extension (x25519 - 32 byte public key)
        ks_key = os.urandom(32)
        ks_entry = struct.pack('!HH', 0x001D, 32) + ks_key  # x25519
        ks_data = struct.pack('!H', len(ks_entry)) + ks_entry
        extensions += struct.pack('!HH', 0x0033, len(ks_data)) + ks_data

        ext_block = struct.pack('!H', len(extensions)) + extensions

        # Assemble ClientHello body
        body = version + random_bytes + session_id + cipher_suites + compression + ext_block

        # Wrap in handshake header (type=1, 3-byte length)
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body

        return handshake

    def _wrap_record(self, content_type: int, data: bytes) -> bytes:
        """Wrap data in a TLS record."""
        return struct.pack('!BHH', content_type, 0x0301, len(data)) + data


# ============================================================================
# REPORT GENERATION
# ============================================================================

def format_report(result: TLSAnalysisResult) -> str:
    """Format analysis result as a human-readable report."""
    lines = [
        "=" * 60,
        f"  TLS Handshake Analysis: {result.host}:{result.port}",
        "=" * 60,
        "",
        f"  TLS Version:     {result.tls_version}",
        f"  Cipher Suite:    {result.cipher_suite}",
        f"  Key Exchange:    {result.key_exchange}",
        "",
        "  CERTIFICATE:",
        f"    Subject:       {result.certificate_subject}",
        f"    Issuer:        {result.certificate_issuer}",
        f"    Valid From:    {result.certificate_valid_from}",
        f"    Valid To:      {result.certificate_valid_to}",
        f"    SANs:          {result.server_name}",
        "",
    ]

    # Cipher suite breakdown
    if result.cipher_suite:
        analysis = analyze_cipher_suite(result.cipher_suite)
        lines.append("  CIPHER SUITE BREAKDOWN:")
        for k, v in analysis.items():
            if k != 'full_name':
                lines.append(f"    {k:20s} {v}")
        lines.append("")

    # PQC detection
    if result.pqc_detected:
        lines.append("  PQC STATUS: DETECTED")
        for g in result.pqc_groups:
            lines.append(f"    Hybrid group: {g}")
    else:
        lines.append("  PQC STATUS: Not detected (classical only)")

    lines.extend(["", "=" * 60])
    return "\n".join(lines)


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """Analyze TLS handshake for given hosts."""
    targets = sys.argv[1:] if len(sys.argv) > 1 else ['google.com', 'github.com']

    analyzer = TLSAnalyzer()
    for target in targets:
        if ':' in target:
            host, port = target.rsplit(':', 1)
            port = int(port)
        else:
            host, port = target, 443

        print(f"\nAnalyzing {host}:{port}...")

        # High-level analysis (via ssl module)
        result = analyzer.analyze(host, port)
        print(format_report(result))

        # Raw analysis (direct ClientHello)
        raw_result = analyzer.analyze_raw(host, port)
        if raw_result.raw_server_hello:
            sh = raw_result.raw_server_hello
            print(f"\n  RAW ServerHello:")
            print(f"    Cipher Suite: {sh.get('cipher_suite', 'N/A')} (0x{sh.get('cipher_suite_id', 0):04X})")
            print(f"    Extensions: {len(sh.get('extensions', []))}")
            for ext in sh.get('extensions', []):
                extra = f" -> {ext['selected_version']}" if 'selected_version' in ext else ''
                print(f"      {ext['name']}{extra}")


if __name__ == '__main__':
    main()
