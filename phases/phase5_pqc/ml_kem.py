"""
Enigma Phase 5 (v2): ML-KEM (FIPS 203) — from lattice math.

Full implementation of ML-KEM (Kyber) key encapsulation:
  - Polynomial ring arithmetic over R_q = Z_3329[X]/(X^256 + 1)
  - Number Theoretic Transform (NTT) for fast polynomial multiplication
  - Centered Binomial Distribution (CBD) sampling
  - K-PKE: inner CPA-secure public-key encryption
  - ML-KEM: CCA-secure KEM via Fujisaki-Okamoto transform
  - All three parameter sets: ML-KEM-512, ML-KEM-768, ML-KEM-1024

Built from math, not libraries. Uses hashlib for SHA3/SHAKE.
"""

from __future__ import annotations
import hashlib
import hmac as hmac_mod
import os
from dataclasses import dataclass
from typing import List, Tuple

# ============================================================================
# CONSTANTS (FIPS 203)
# ============================================================================

N = 256       # Polynomial degree
Q = 3329      # Modulus (prime, Q ≡ 1 mod 256)

# Parameter sets: (k, eta1, eta2, du, dv)
PARAMS = {
    512:  {'k': 2, 'eta1': 3, 'eta2': 2, 'du': 10, 'dv': 4},
    768:  {'k': 3, 'eta1': 2, 'eta2': 2, 'du': 10, 'dv': 4},
    1024: {'k': 4, 'eta1': 2, 'eta2': 2, 'du': 11, 'dv': 5},
}

# Primitive 256th root of unity mod Q: zeta = 17
# 17^256 ≡ 1 mod 3329
ZETA = 17

# Precomputed zetas in bit-reversed order for NTT
# zetas[i] = ZETA^(bit_reverse_7(i)) mod Q
def _compute_zetas() -> List[int]:
    """Precompute NTT twiddle factors in bit-reversed order."""
    zetas = [0] * 128
    for i in range(128):
        # Bit-reverse the 7-bit index
        br = int(format(i, '07b')[::-1], 2)
        zetas[i] = pow(ZETA, br, Q)
    return zetas

ZETAS = _compute_zetas()


# ============================================================================
# POLYNOMIAL RING R_q = Z_q[X]/(X^256+1)
# ============================================================================

class Poly:
    """Polynomial in R_q = Z_3329[X]/(X^256+1). Coefficients in [0, Q-1]."""

    __slots__ = ['coeffs']

    def __init__(self, coeffs: List[int] = None):
        if coeffs is None:
            self.coeffs = [0] * N
        else:
            self.coeffs = [c % Q for c in coeffs]

    def __add__(self, other: 'Poly') -> 'Poly':
        return Poly([(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __sub__(self, other: 'Poly') -> 'Poly':
        return Poly([(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)])

    def __eq__(self, other) -> bool:
        if not isinstance(other, Poly):
            return False
        return self.coeffs == other.coeffs

    def scalar_mul(self, s: int) -> 'Poly':
        return Poly([(c * s) % Q for c in self.coeffs])

    def compress(self, d: int) -> List[int]:
        """Compress coefficients to d bits: round(2^d / q * x) mod 2^d."""
        result = []
        for c in self.coeffs:
            compressed = ((c << d) + Q // 2) // Q % (1 << d)
            result.append(compressed)
        return result

    @staticmethod
    def decompress(vals: List[int], d: int) -> 'Poly':
        """Decompress d-bit values back to Z_q."""
        coeffs = []
        for v in vals:
            decompressed = (v * Q + (1 << (d - 1))) >> d
            coeffs.append(decompressed % Q)
        return Poly(coeffs)


# ============================================================================
# NTT (Number Theoretic Transform)
# ============================================================================

def ntt(f: Poly) -> Poly:
    """Forward NTT: convert from normal to NTT domain.

    Cooley-Tukey butterfly, in-place, using precomputed zetas.
    After NTT, polynomial multiplication becomes pointwise.
    """
    a = list(f.coeffs)
    k = 1
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = (zeta * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length //= 2
    return Poly(a)


def inv_ntt(f_hat: Poly) -> Poly:
    """Inverse NTT: convert from NTT domain back to normal.

    Gentleman-Sande butterfly, in-place.
    """
    a = list(f_hat.coeffs)
    k = 127
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = (zeta * (a[j + length] - t)) % Q
            start += 2 * length
        length *= 2

    # Multiply by 128^(-1) mod Q (NTT is 128-point on pairs, not 256-point)
    # 128^(-1) mod 3329 = 3303
    f_inv = 3303  # pow(128, Q - 2, Q)
    a = [(c * f_inv) % Q for c in a]
    return Poly(a)


def _compute_basemul_gammas() -> List[int]:
    """Precompute basemul twist factors: gamma_i = zeta^(2*BitRev7(i)+1)."""
    gammas = []
    for i in range(128):
        br = int(format(i, '07b')[::-1], 2)
        gammas.append(pow(ZETA, 2 * br + 1, Q))
    return gammas

GAMMAS = _compute_basemul_gammas()


def ntt_multiply(f_hat: Poly, g_hat: Poly) -> Poly:
    """Multiply two polynomials in NTT domain (pointwise with twist).

    In NTT domain of R_q/(X^256+1), multiplication is done as 128
    pairwise multiplications in Z_q[X]/(X^2 - gamma_i).

    BaseMul((a0,a1), (b0,b1), gamma) = (a0*b0 + a1*b1*gamma, a0*b1 + a1*b0)
    """
    result = [0] * N
    for i in range(128):
        gamma = GAMMAS[i]
        a0 = f_hat.coeffs[2 * i]
        a1 = f_hat.coeffs[2 * i + 1]
        b0 = g_hat.coeffs[2 * i]
        b1 = g_hat.coeffs[2 * i + 1]
        result[2 * i] = (a0 * b0 + a1 * b1 * gamma) % Q
        result[2 * i + 1] = (a0 * b1 + a1 * b0) % Q

    return Poly(result)


def poly_multiply(f: Poly, g: Poly) -> Poly:
    """Multiply two polynomials using NTT."""
    f_hat = ntt(f)
    g_hat = ntt(g)
    h_hat = ntt_multiply(f_hat, g_hat)
    return inv_ntt(h_hat)


# ============================================================================
# SAMPLING
# ============================================================================

def _shake128(seed: bytes, length: int) -> bytes:
    """SHAKE-128 extendable output function."""
    return hashlib.shake_128(seed).digest(length)


def _shake256(seed: bytes, length: int) -> bytes:
    """SHAKE-256 extendable output function."""
    return hashlib.shake_256(seed).digest(length)


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _bit(data: bytes, i: int) -> int:
    """Extract bit i from byte array (LSB-first per byte, per FIPS 203)."""
    return (data[i // 8] >> (i % 8)) & 1


def cbd(eta: int, noise_bytes: bytes) -> Poly:
    """Sample from Centered Binomial Distribution CBD_eta (FIPS 203 Algorithm 8).

    Each coefficient is sum of eta bits minus sum of eta bits.
    Bits extracted LSB-first per byte, matching FIPS 203 specification.
    Range: [-eta, eta].
    """
    coeffs = []
    idx = 0

    for _ in range(N):
        a = sum(_bit(noise_bytes, idx + j) for j in range(eta))
        b = sum(_bit(noise_bytes, idx + eta + j) for j in range(eta))
        coeffs.append((a - b) % Q)
        idx += 2 * eta

    return Poly(coeffs)


def sample_ntt(seed: bytes, i: int, j: int) -> Poly:
    """Sample a polynomial in NTT domain from SHAKE-128(seed || i || j).

    Rejection sampling: generate 3 bytes at a time, extract two 12-bit values,
    keep values < Q. Uses streaming XOF (increasing output length on extension).
    """
    xof_input = seed + bytes([i, j])
    stream_len = 3 * N  # 768 bytes initial (sufficient for ~99.9% of seeds)
    stream = _shake128(xof_input, stream_len)

    coeffs = []
    pos = 0
    while len(coeffs) < N:
        if pos + 3 > len(stream):
            # Extend XOF output (SHAKE-128 is deterministic: longer output
            # includes all previous bytes as prefix)
            stream_len += 3 * N
            stream = _shake128(xof_input, stream_len)

        b0, b1, b2 = stream[pos], stream[pos + 1], stream[pos + 2]
        pos += 3

        d1 = b0 + 256 * (b1 % 16)
        d2 = (b1 >> 4) + 16 * b2

        if d1 < Q:
            coeffs.append(d1)
        if len(coeffs) < N and d2 < Q:
            coeffs.append(d2)

    return Poly(coeffs[:N])


# ============================================================================
# BYTE ENCODING / DECODING
# ============================================================================

def encode_poly(p: Poly, d: int) -> bytes:
    """Encode polynomial coefficients (d bits each) to bytes."""
    bits = 0
    bit_count = 0
    result = []
    for c in p.coeffs:
        bits |= (c & ((1 << d) - 1)) << bit_count
        bit_count += d
        while bit_count >= 8:
            result.append(bits & 0xFF)
            bits >>= 8
            bit_count -= 8
    if bit_count > 0:
        result.append(bits & 0xFF)
    return bytes(result)


def decode_poly(data: bytes, d: int) -> Poly:
    """Decode bytes to polynomial coefficients (d bits each)."""
    bits = int.from_bytes(data, 'little')
    mask = (1 << d) - 1
    coeffs = []
    for _ in range(N):
        coeffs.append(bits & mask)
        bits >>= d
    return Poly(coeffs)


# ============================================================================
# K-PKE (Inner CPA-secure encryption)
# ============================================================================

@dataclass
class KPKEPublicKey:
    t_hat: List[Poly]  # NTT domain
    rho: bytes          # 32-byte seed for A matrix

@dataclass
class KPKEPrivateKey:
    s_hat: List[Poly]   # NTT domain


def kpke_keygen(params: dict, d: bytes = None) -> Tuple[KPKEPublicKey, KPKEPrivateKey]:
    """K-PKE.KeyGen: generate CPA-secure key pair."""
    k = params['k']
    eta1 = params['eta1']

    if d is None:
        d = os.urandom(32)

    # FIPS 203 Algorithm 13: G(d || k) for domain separation across parameter sets
    g_output = _sha3_512(d + bytes([k]))
    rho = g_output[:32]
    sigma = g_output[32:]

    # Generate matrix A (in NTT domain) from rho
    A_hat = [[sample_ntt(rho, i, j) for j in range(k)] for i in range(k)]

    # Sample secret vector s
    s = []
    for i in range(k):
        noise = _shake256(sigma + bytes([i]), 64 * eta1)
        s.append(cbd(eta1, noise))

    # Sample error vector e
    e = []
    for i in range(k):
        noise = _shake256(sigma + bytes([k + i]), 64 * eta1)
        e.append(cbd(eta1, noise))

    # NTT(s)
    s_hat = [ntt(si) for si in s]

    # t_hat = A_hat * s_hat + NTT(e)
    t_hat = []
    for i in range(k):
        ti = ntt(e[i])
        for j in range(k):
            ti = ti + ntt_multiply(A_hat[i][j], s_hat[j])
        t_hat.append(ti)

    return KPKEPublicKey(t_hat, rho), KPKEPrivateKey(s_hat)


def kpke_encrypt(pk: KPKEPublicKey, msg: bytes, r_coins: bytes, params: dict) -> bytes:
    """K-PKE.Encrypt: CPA-secure encryption."""
    k = params['k']
    eta1 = params['eta1']
    eta2 = params['eta2']
    du = params['du']
    dv = params['dv']

    # Regenerate A from rho
    A_hat = [[sample_ntt(pk.rho, i, j) for j in range(k)] for i in range(k)]

    # Sample r, e1, e2
    r = []
    for i in range(k):
        noise = _shake256(r_coins + bytes([i]), 64 * eta1)
        r.append(cbd(eta1, noise))

    e1 = []
    for i in range(k):
        noise = _shake256(r_coins + bytes([k + i]), 64 * eta2)
        e1.append(cbd(eta2, noise))

    noise = _shake256(r_coins + bytes([2 * k]), 64 * eta2)
    e2 = cbd(eta2, noise)

    # NTT(r)
    r_hat = [ntt(ri) for ri in r]

    # u = INTT(A^T * r_hat) + e1
    u = []
    for i in range(k):
        ui = Poly()
        for j in range(k):
            ui = ui + ntt_multiply(A_hat[j][i], r_hat[j])
        ui = inv_ntt(ui) + e1[i]
        u.append(ui)

    # v = INTT(t^T * r_hat) + e2 + Decompress(msg, 1)
    v = Poly()
    for j in range(k):
        v = v + ntt_multiply(pk.t_hat[j], r_hat[j])
    v = inv_ntt(v) + e2

    # Add message (each bit maps to 0 or Q/2)
    msg_poly = Poly.decompress([int(b) for b in _bytes_to_bits(msg, N)], 1)
    v = v + msg_poly

    # Compress and encode
    ct = b''
    for ui in u:
        ct += encode_poly(Poly(ui.compress(du)), du)
    ct += encode_poly(Poly(v.compress(dv)), dv)

    return ct


def kpke_decrypt(sk: KPKEPrivateKey, ct: bytes, params: dict) -> bytes:
    """K-PKE.Decrypt: CPA-secure decryption."""
    k = params['k']
    du = params['du']
    dv = params['dv']

    # Validate ciphertext length
    expected_len = k * ((N * du + 7) // 8) + (N * dv + 7) // 8
    if len(ct) != expected_len:
        raise ValueError(f"Ciphertext length {len(ct)} != expected {expected_len}")

    # Decode u and v from ciphertext
    u_size = k * (N * du + 7) // 8
    u = []
    pos = 0
    for i in range(k):
        chunk_size = (N * du + 7) // 8
        ui_compressed = decode_poly(ct[pos:pos + chunk_size], du)
        u.append(Poly.decompress(ui_compressed.coeffs, du))
        pos += chunk_size

    v_compressed = decode_poly(ct[pos:], dv)
    v = Poly.decompress(v_compressed.coeffs, dv)

    # m = Compress(v - INTT(s^T * NTT(u)), 1)
    inner = Poly()
    for j in range(k):
        inner = inner + ntt_multiply(sk.s_hat[j], ntt(u[j]))
    inner = inv_ntt(inner)

    diff = v - inner
    msg_bits = diff.compress(1)

    return _bits_to_bytes(msg_bits)


def _bytes_to_bits(data: bytes, n: int) -> List[int]:
    """Convert bytes to n bits."""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
            if len(bits) >= n:
                return bits
    while len(bits) < n:
        bits.append(0)
    return bits[:n]


def _bits_to_bytes(bits: List[int]) -> bytes:
    """Convert bits to bytes."""
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] & 1) << j
        result.append(byte)
    return bytes(result)


# ============================================================================
# ML-KEM (CCA-secure KEM via Fujisaki-Okamoto transform)
# ============================================================================

@dataclass
class MLKEMPublicKey:
    kpke_pk: KPKEPublicKey
    h: bytes              # H(pk) — 32 bytes

@dataclass
class MLKEMPrivateKey:
    kpke_sk: KPKEPrivateKey
    kpke_pk: KPKEPublicKey
    h: bytes              # H(pk)
    z: bytes              # 32-byte random for implicit rejection


def ml_kem_keygen(security_level: int = 768) -> Tuple[MLKEMPublicKey, MLKEMPrivateKey]:
    """ML-KEM.KeyGen: Generate CCA-secure KEM key pair.

    Args:
        security_level: 512, 768, or 1024
    """
    if security_level not in PARAMS:
        raise ValueError(f"Invalid security level: {security_level}. Use 512, 768, or 1024.")

    params = PARAMS[security_level]
    d = os.urandom(32)
    z = os.urandom(32)

    kpke_pk, kpke_sk = kpke_keygen(params, d)

    # Serialize public key for hashing
    pk_bytes = _serialize_kpke_pk(kpke_pk, params)
    h = _sha3_256(pk_bytes)

    ek = MLKEMPublicKey(kpke_pk, h)
    dk = MLKEMPrivateKey(kpke_sk, kpke_pk, h, z)

    return ek, dk


def ml_kem_encaps(ek: MLKEMPublicKey, security_level: int = 768) -> Tuple[bytes, bytes]:
    """ML-KEM.Encaps: Encapsulate a shared secret.

    Returns:
        (ciphertext, shared_secret) — both deterministic from randomness
    """
    if security_level not in PARAMS:
        raise ValueError(f"Invalid security level: {security_level}. Use 512, 768, or 1024.")
    params = PARAMS[security_level]
    m = os.urandom(32)

    # (K, r) = G(m || H(ek))
    g_output = _sha3_512(m + ek.h)
    K = g_output[:32]
    r = g_output[32:]

    # ct = K-PKE.Encrypt(ek, m, r)
    ct = kpke_encrypt(ek.kpke_pk, m, r, params)

    return ct, K


def ml_kem_decaps(dk: MLKEMPrivateKey, ct: bytes, security_level: int = 768) -> bytes:
    """ML-KEM.Decaps: Decapsulate a shared secret.

    Uses implicit rejection: if decryption fails, returns a pseudorandom
    value derived from z and ct (prevents chosen-ciphertext attacks).
    """
    if security_level not in PARAMS:
        raise ValueError(f"Invalid security level: {security_level}. Use 512, 768, or 1024.")
    params = PARAMS[security_level]

    # m' = K-PKE.Decrypt(dk, ct)
    m_prime = kpke_decrypt(dk.kpke_sk, ct, params)

    # (K', r') = G(m' || h)
    g_output = _sha3_512(m_prime + dk.h)
    K_prime = g_output[:32]
    r_prime = g_output[32:]

    # Re-encrypt to verify
    ct_prime = kpke_encrypt(dk.kpke_pk, m_prime, r_prime, params)

    # Implicit rejection: if ct != ct', return J(z || ct)
    # Constant-time comparison prevents timing oracle (FIPS 203 Section 7.3)
    if hmac_mod.compare_digest(ct, ct_prime):
        return K_prime
    else:
        return _shake256(dk.z + ct, 32)


def _serialize_kpke_pk(pk: KPKEPublicKey, params: dict) -> bytes:
    """Serialize K-PKE public key to bytes: encode(t_hat, 12) || rho."""
    result = b''
    for ti in pk.t_hat:
        result += encode_poly(ti, 12)  # 12 bits per coefficient in NTT domain
    result += pk.rho
    return result


def _deserialize_kpke_pk(data: bytes, params: dict) -> KPKEPublicKey:
    """Deserialize K-PKE public key from bytes."""
    k = params['k']
    poly_bytes = (N * 12 + 7) // 8  # 384 bytes per polynomial
    t_hat = []
    pos = 0
    for _ in range(k):
        t_hat.append(decode_poly(data[pos:pos + poly_bytes], 12))
        pos += poly_bytes
    rho = data[pos:pos + 32]
    if len(rho) != 32:
        raise ValueError("Truncated public key")
    return KPKEPublicKey(t_hat, rho)


def _serialize_kpke_sk(sk: KPKEPrivateKey, params: dict) -> bytes:
    """Serialize K-PKE secret key: encode(s_hat, 12)."""
    result = b''
    for si in sk.s_hat:
        result += encode_poly(si, 12)
    return result


def _deserialize_kpke_sk(data: bytes, params: dict) -> KPKEPrivateKey:
    """Deserialize K-PKE secret key from bytes."""
    k = params['k']
    poly_bytes = (N * 12 + 7) // 8
    s_hat = []
    pos = 0
    for _ in range(k):
        s_hat.append(decode_poly(data[pos:pos + poly_bytes], 12))
        pos += poly_bytes
    return KPKEPrivateKey(s_hat)


# ============================================================================
# ML-KEM KEY SERIALIZATION (FIPS 203 Section 7.2 / 7.3)
# ============================================================================

# Key sizes per parameter set (bytes)
KEY_SIZES = {
    512:  {'ek': 800,  'dk': 1632},
    768:  {'ek': 1184, 'dk': 2400},
    1024: {'ek': 1568, 'dk': 3168},
}


def ml_kem_serialize_ek(ek: MLKEMPublicKey, security_level: int = 768) -> bytes:
    """Serialize ML-KEM encapsulation (public) key.

    Format: encode(t_hat, 12) || rho
    """
    params = PARAMS[security_level]
    return _serialize_kpke_pk(ek.kpke_pk, params)


def ml_kem_deserialize_ek(data: bytes, security_level: int = 768) -> MLKEMPublicKey:
    """Deserialize ML-KEM encapsulation (public) key."""
    if security_level not in PARAMS:
        raise ValueError(f"Invalid security level: {security_level}")
    params = PARAMS[security_level]
    expected = KEY_SIZES[security_level]['ek']
    if len(data) != expected:
        raise ValueError(f"Encapsulation key must be {expected} bytes, got {len(data)}")
    kpke_pk = _deserialize_kpke_pk(data, params)
    h = _sha3_256(data)
    return MLKEMPublicKey(kpke_pk, h)


def ml_kem_serialize_dk(dk: MLKEMPrivateKey, security_level: int = 768) -> bytes:
    """Serialize ML-KEM decapsulation (private) key.

    Format per FIPS 203: dk_PKE || ek || H(ek) || z
    """
    params = PARAMS[security_level]
    sk_bytes = _serialize_kpke_sk(dk.kpke_sk, params)
    pk_bytes = _serialize_kpke_pk(dk.kpke_pk, params)
    return sk_bytes + pk_bytes + dk.h + dk.z


def ml_kem_deserialize_dk(data: bytes, security_level: int = 768) -> MLKEMPrivateKey:
    """Deserialize ML-KEM decapsulation (private) key."""
    if security_level not in PARAMS:
        raise ValueError(f"Invalid security level: {security_level}")
    params = PARAMS[security_level]
    expected = KEY_SIZES[security_level]['dk']
    if len(data) != expected:
        raise ValueError(f"Decapsulation key must be {expected} bytes, got {len(data)}")

    k = params['k']
    poly_bytes = (N * 12 + 7) // 8
    sk_size = k * poly_bytes
    pk_size = KEY_SIZES[security_level]['ek']

    pos = 0
    kpke_sk = _deserialize_kpke_sk(data[pos:pos + sk_size], params)
    pos += sk_size
    kpke_pk = _deserialize_kpke_pk(data[pos:pos + pk_size], params)
    pos += pk_size
    h = data[pos:pos + 32]
    pos += 32
    z = data[pos:pos + 32]

    return MLKEMPrivateKey(kpke_sk, kpke_pk, h, z)
