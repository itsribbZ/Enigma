"""
Enigma Phase 5: Post-Quantum Cryptography — LWE encryption, benchmarks, migration.

Implements:
  1. Regev's LWE encryption from scratch (the math, not a library)
  2. ML-KEM benchmark comparison (ML-KEM vs RSA vs ECDH)
  3. PQC migration guide generator

LWE = noisy linear regression over Z_q where noise makes inversion intractable.
This is the DEFENSE against Shor's algorithm.
"""

from __future__ import annotations
import os
import time
import math
import numpy as np
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase1_math'))
from modular_math import mod_inverse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase2_classical'))
from rsa import generate_rsa_keypair, rsa_encrypt_pkcs1v15, rsa_decrypt_pkcs1v15
from ecc import ecdh_keygen, ecdh_shared_secret, SECP256K1


# ============================================================================
# CENTERED BINOMIAL DISTRIBUTION (CBD)
# ============================================================================

def cbd_sample(eta: int) -> int:
    """Sample from centered binomial distribution CBD_eta.

    CBD_eta: sum of eta coin flips minus sum of eta coin flips.
    Range: [-eta, eta], variance = eta/2.
    Used in ML-KEM for noise sampling (constant-time, no rejection).
    """
    bits = int.from_bytes(os.urandom((2 * eta + 7) // 8), 'big')
    a = sum((bits >> i) & 1 for i in range(eta))
    b = sum((bits >> (eta + i)) & 1 for i in range(eta))
    return a - b


def cbd_vector(n: int, eta: int) -> np.ndarray:
    """Sample n-dimensional vector from CBD_eta."""
    return np.array([cbd_sample(eta) for _ in range(n)])


# ============================================================================
# REGEV'S LWE ENCRYPTION (from scratch)
# ============================================================================

class LWEEncrypt:
    """Regev's LWE-based encryption scheme.

    Encrypts single bits. For multi-bit messages, encrypt each bit separately.

    Parameters:
        n: lattice dimension (security parameter)
        m: number of LWE samples (rows of A)
        q: modulus (prime)
        eta: CBD parameter for noise
    """

    # Security level estimates (approximate)
    SECURITY_LEVELS = {
        32: '~15-bit (toy)', 64: '~30-bit (educational)',
        128: '~60-bit (weak)', 256: '~128-bit (ML-KEM-512 level)',
        512: '~192-bit (ML-KEM-768 level)', 768: '~256-bit (ML-KEM-1024 level)',
    }

    def __init__(self, n: int = 64, m: int = 128, q: int = 3329, eta: int = 2):
        """Initialize LWE encryption.

        WARNING: Default n=64 provides only ~30-bit security (educational).
        Production ML-KEM uses n=256 minimum (FIPS 203).
        Use n=256+ for any real security assessment.
        """
        self.n = n
        self.m = m
        self.q = q
        self.eta = eta
        self.security_note = self.SECURITY_LEVELS.get(n, f'~{n//2}-bit (estimated)')

    def keygen(self) -> Tuple[Tuple[np.ndarray, np.ndarray], np.ndarray]:
        """Generate LWE key pair.

        Returns: (public_key=(A, b), secret_key=s)
        where b = A*s + e (mod q)
        """
        # Secret key: small vector from CBD
        s = cbd_vector(self.n, self.eta) % self.q

        # Random matrix A
        A = np.random.randint(0, self.q, size=(self.m, self.n))

        # Error vector
        e = cbd_vector(self.m, self.eta) % self.q

        # Public key: b = A*s + e mod q
        b = (A @ s + e) % self.q

        return (A, b), s

    def encrypt_bit(self, public_key: Tuple[np.ndarray, np.ndarray],
                    bit: int) -> Tuple[np.ndarray, int]:
        """Encrypt a single bit (0 or 1).

        Choose random subset of rows (via random binary vector r),
        sum selected rows of A and b, add q/2 if bit=1.

        Returns: (u, v) where u = A^T * r mod q, v = b^T * r + bit*floor(q/2) mod q
        """
        A, b = public_key

        # Random binary vector (selects subset of rows)
        r = np.random.randint(0, 2, size=self.m)

        # u = A^T * r mod q
        u = (A.T @ r) % self.q

        # v = b^T * r + bit * floor(q/2) mod q
        v = int((b @ r + bit * (self.q // 2)) % self.q)

        return u, v

    def decrypt_bit(self, secret_key: np.ndarray,
                    ciphertext: Tuple[np.ndarray, int]) -> int:
        """Decrypt a single bit.

        Compute w = v - s^T * u mod q.
        If w is closer to 0 than to q/2, output 0; else output 1.
        """
        u, v = ciphertext
        s = secret_key

        # w = v - <s, u> mod q
        w = int((v - s @ u) % self.q)

        # Decode: check if w is closer to 0 or q/2
        half_q = self.q // 2
        quarter_q = self.q // 4

        # In centered representation: if |w| < q/4, bit=0; else bit=1
        if w > half_q:
            w = w - self.q  # Center around 0

        return 0 if abs(w) < quarter_q else 1

    def encrypt_bytes(self, public_key: Tuple[np.ndarray, np.ndarray],
                      message: bytes) -> List[Tuple[np.ndarray, int]]:
        """Encrypt a byte string (each bit separately)."""
        ciphertexts = []
        for byte in message:
            for i in range(8):
                bit = (byte >> (7 - i)) & 1
                ciphertexts.append(self.encrypt_bit(public_key, bit))
        return ciphertexts

    def decrypt_bytes(self, secret_key: np.ndarray,
                      ciphertexts: List[Tuple[np.ndarray, int]]) -> bytes:
        """Decrypt a list of bit ciphertexts back to bytes."""
        bits = [self.decrypt_bit(secret_key, ct) for ct in ciphertexts]
        result = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)


# ============================================================================
# BENCHMARK SUITE
# ============================================================================

@dataclass
class BenchmarkResult:
    algorithm: str
    operation: str
    mean_ms: float
    iterations: int
    key_size_bytes: int
    ciphertext_size_bytes: int


def benchmark_lwe(iterations: int = 10) -> List[BenchmarkResult]:
    """Benchmark LWE encryption."""
    lwe = LWEEncrypt(n=64, m=128, q=3329, eta=2)
    results = []

    # Keygen
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        pub, sec = lwe.keygen()
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('LWE (n=64)', 'keygen',
                                   sum(times)/len(times), iterations,
                                   pub[0].nbytes + pub[1].nbytes, 0))

    # Encrypt
    pub, sec = lwe.keygen()
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = lwe.encrypt_bit(pub, 1)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('LWE (n=64)', 'encrypt_bit',
                                   sum(times)/len(times), iterations,
                                   0, ct[0].nbytes + 8))

    # Decrypt
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        lwe.decrypt_bit(sec, ct)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('LWE (n=64)', 'decrypt_bit',
                                   sum(times)/len(times), iterations, 0, 0))

    return results


def benchmark_rsa(iterations: int = 3) -> List[BenchmarkResult]:
    """Benchmark RSA-1024 (small for speed in tests)."""
    results = []

    # Keygen
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        pub, priv = generate_rsa_keypair(bits=1024)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('RSA-1024', 'keygen',
                                   sum(times)/len(times), iterations, 128, 0))

    # Encrypt
    pub, priv = generate_rsa_keypair(bits=1024)
    msg = b"benchmark"
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ct = rsa_encrypt_pkcs1v15(msg, pub)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('RSA-1024', 'encrypt',
                                   sum(times)/len(times), iterations, 0, len(ct)))

    # Decrypt
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        rsa_decrypt_pkcs1v15(ct, priv)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('RSA-1024', 'decrypt',
                                   sum(times)/len(times), iterations, 0, 0))

    return results


def benchmark_ecdh(iterations: int = 5) -> List[BenchmarkResult]:
    """Benchmark ECDH on secp256k1."""
    results = []

    # Keygen
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        priv, pub = ecdh_keygen(SECP256K1)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('ECDH secp256k1', 'keygen',
                                   sum(times)/len(times), iterations, 64, 0))

    # Key exchange
    priv_a, pub_a = ecdh_keygen(SECP256K1)
    priv_b, pub_b = ecdh_keygen(SECP256K1)
    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        ecdh_shared_secret(priv_a, pub_b, SECP256K1)
        times.append((time.perf_counter() - t0) * 1000)
    results.append(BenchmarkResult('ECDH secp256k1', 'key_exchange',
                                   sum(times)/len(times), iterations, 0, 32))

    return results


def run_benchmarks() -> str:
    """Run all benchmarks and return formatted report."""
    lines = [
        "=" * 70,
        "  PQC BENCHMARK SUITE — ML-KEM vs RSA vs ECDH",
        "=" * 70,
        "",
    ]

    all_results = []

    lines.append("  LWE Encryption (from scratch, n=64, q=3329):")
    for r in benchmark_lwe():
        lines.append(f"    {r.operation:20s} {r.mean_ms:8.2f} ms  (avg of {r.iterations})")
        all_results.append(r)

    lines.append("")
    lines.append("  RSA-1024 (from scratch):")
    for r in benchmark_rsa():
        lines.append(f"    {r.operation:20s} {r.mean_ms:8.2f} ms  (avg of {r.iterations})")
        all_results.append(r)

    lines.append("")
    lines.append("  ECDH secp256k1 (from scratch):")
    for r in benchmark_ecdh():
        lines.append(f"    {r.operation:20s} {r.mean_ms:8.2f} ms  (avg of {r.iterations})")
        all_results.append(r)

    lines.extend([
        "",
        "  KEY SIZE COMPARISON (production implementations):",
        "  " + "-" * 50,
        f"  {'Algorithm':25s} {'Public Key':>12s} {'Ciphertext':>12s} {'Security':>10s}",
        f"  {'RSA-2048':25s} {'256 B':>12s} {'256 B':>12s} {'0-bit PQ':>10s}",
        f"  {'ECDH P-256':25s} {'64 B':>12s} {'64 B':>12s} {'0-bit PQ':>10s}",
        f"  {'ML-KEM-768':25s} {'1184 B':>12s} {'1088 B':>12s} {'192-bit PQ':>10s}",
        f"  {'ML-KEM-1024':25s} {'1568 B':>12s} {'1568 B':>12s} {'256-bit PQ':>10s}",
        "",
        "  NOTE: Our implementations are unoptimized Python (educational).",
        "  Production ML-KEM is ~1000x faster than RSA-2048 keygen.",
        "",
        "=" * 70,
    ])

    return "\n".join(lines)


# ============================================================================
# PQC MIGRATION GUIDE
# ============================================================================

@dataclass
class ProtocolMigration:
    protocol: str
    current_crypto: str
    pqc_replacement: str
    status: str
    timeline: str
    priority: str


MIGRATION_TABLE = [
    ProtocolMigration('TLS 1.3', 'ECDHE key exchange', 'X25519+ML-KEM-768 hybrid',
                      'In production (Chrome, Cloudflare)', '2024-2026', 'P1-CRITICAL'),
    ProtocolMigration('TLS 1.3', 'ECDSA/RSA certificates', 'ML-DSA certificates',
                      'Standards ready, limited deployment', '2026-2030', 'P2-HIGH'),
    ProtocolMigration('SSH', 'ECDH key exchange', 'sntrup761+x25519 hybrid',
                      'Default in OpenSSH 9.0+', '2023-2025', 'P1-CRITICAL'),
    ProtocolMigration('SSH', 'Ed25519 host keys', 'ML-DSA host keys',
                      'In development', '2026-2028', 'P2-HIGH'),
    ProtocolMigration('IPsec/IKEv2', 'DH/ECDH key exchange', 'ML-KEM via RFC 9370',
                      'Experimental (strongSwan)', '2025-2028', 'P2-HIGH'),
    ProtocolMigration('S/MIME', 'RSA/ECDSA signatures', 'ML-DSA + composite certs',
                      'Standards in progress', '2027-2035', 'P3-MEDIUM'),
    ProtocolMigration('Code Signing', 'RSA/ECDSA', 'ML-DSA or SLH-DSA',
                      'Planning stage', '2026-2030', 'P2-HIGH'),
    ProtocolMigration('Symmetric (AES)', 'AES-128', 'AES-256',
                      'Trivial upgrade', 'Immediate', 'P1-CRITICAL'),
]


def generate_migration_guide(org_name: str = "Organization") -> str:
    """Generate a PQC migration guide document."""
    lines = [
        "=" * 70,
        f"  POST-QUANTUM CRYPTOGRAPHY MIGRATION GUIDE",
        f"  {org_name}",
        "=" * 70,
        "",
        "  1. EXECUTIVE SUMMARY",
        "  " + "-" * 40,
        "  NIST finalized three PQC standards in August 2024:",
        "    FIPS 203: ML-KEM (Kyber) -- key encapsulation",
        "    FIPS 204: ML-DSA (Dilithium) -- digital signatures",
        "    FIPS 205: SLH-DSA (SPHINCS+) -- hash-based signatures",
        "",
        "  Migration is URGENT for key exchange (HNDL threat).",
        "  Certificate migration has a longer timeline.",
        "",
        "  2. PROTOCOL MIGRATION STATUS",
        "  " + "-" * 40,
    ]

    for m in MIGRATION_TABLE:
        lines.extend([
            f"  [{m.priority}] {m.protocol} -- {m.current_crypto}",
            f"    Replace with: {m.pqc_replacement}",
            f"    Status: {m.status}",
            f"    Timeline: {m.timeline}",
            "",
        ])

    lines.extend([
        "  3. MIGRATION PHASES",
        "  " + "-" * 40,
        "  Phase 1 - Discovery (Month 1-2):",
        "    - Inventory all cryptographic algorithms in use",
        "    - Map data flows and encryption points",
        "    - Identify HNDL-vulnerable data stores",
        "",
        "  Phase 2 - Assessment (Month 2-4):",
        "    - Apply Mosca's inequality to prioritize",
        "    - Test ML-KEM/ML-DSA in staging environments",
        "    - Evaluate library support (liboqs, BoringSSL, OpenSSL 3.x)",
        "",
        "  Phase 3 - Hybrid Deployment (Month 4-8):",
        "    - Deploy hybrid TLS (X25519+ML-KEM-768)",
        "    - Enable PQC SSH key exchange",
        "    - Test VPN PQC integration",
        "",
        "  Phase 4 - Full Migration (Month 8-18):",
        "    - Replace all RSA/ECDSA certificates with ML-DSA",
        "    - Update code signing infrastructure",
        "    - Migrate S/MIME and email encryption",
        "",
        "  Phase 5 - Validation (Ongoing):",
        "    - Continuous monitoring for PQC algorithm health",
        "    - Performance benchmarking",
        "    - Compliance verification",
        "",
        "=" * 70,
    ])

    return "\n".join(lines)
