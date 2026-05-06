"""
Enigma Phase 2: RSA — from scratch.
Implements key generation, PKCS#1 v1.5 encryption/signing, and OAEP.
Uses Phase 1's modular_math for core primitives.
"""

from __future__ import annotations
import os
import sys
import struct
import hashlib
from typing import Tuple, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase1_math'))
from modular_math import (
    generate_prime, mod_inverse, mod_exp, euler_totient_pq,
    carmichael_lambda, rsa_crt_decrypt,
)

sys.path.insert(0, os.path.dirname(__file__))
from sha256 import sha256


# ============================================================================
# RSA KEY GENERATION
# ============================================================================

class RSAPublicKey:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e
        self.key_size = n.bit_length()

    def __repr__(self):
        return f"RSAPublicKey(bits={self.key_size}, e={self.e})"


class RSAPrivateKey:
    def __init__(self, n: int, e: int, d: int, p: int, q: int):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.dp = d % (p - 1)
        self.dq = d % (q - 1)
        self.qinv = mod_inverse(q, p)
        self.key_size = n.bit_length()
        self.public_key = RSAPublicKey(n, e)

    def __repr__(self):
        return f"RSAPrivateKey(bits={self.key_size})"


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """Generate an RSA key pair.

    Args:
        bits: Key size in bits (2048, 3072, or 4096 recommended).
        e: Public exponent (65537 is standard).
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = carmichael_lambda(p, q)
        if lam % e == 0:
            continue  # gcd(e, lambda) != 1
        d = mod_inverse(e, lam)
        if d.bit_length() > bits // 2:  # Wiener's attack protection
            break

    pub = RSAPublicKey(n, e)
    priv = RSAPrivateKey(n, e, d, p, q)
    return pub, priv


# ============================================================================
# RAW RSA OPERATIONS
# ============================================================================

def _rsa_encrypt_raw(m: int, pub: RSAPublicKey) -> int:
    return pow(m, pub.e, pub.n)


def _rsa_decrypt_raw(c: int, priv: RSAPrivateKey) -> int:
    return rsa_crt_decrypt(c, priv.d, priv.p, priv.q)


def _i2osp(x: int, x_len: int) -> bytes:
    """Integer to Octet String Primitive (RFC 8017)."""
    return x.to_bytes(x_len, byteorder='big')


def _os2ip(x: bytes) -> int:
    """Octet String to Integer Primitive (RFC 8017)."""
    return int.from_bytes(x, byteorder='big')


# ============================================================================
# PKCS#1 v1.5 ENCRYPTION
# ============================================================================

def rsa_encrypt_pkcs1v15(message: bytes, pub: RSAPublicKey) -> bytes:
    """RSA encryption with PKCS#1 v1.5 padding."""
    k = (pub.key_size + 7) // 8  # key length in bytes
    m_len = len(message)

    if m_len > k - 11:
        raise ValueError(f"Message too long: {m_len} bytes, max {k - 11}")

    # Padding: 0x00 || 0x02 || PS (random nonzero, >= 8 bytes) || 0x00 || M
    ps_len = k - m_len - 3
    ps = b''
    while len(ps) < ps_len:
        byte = os.urandom(1)
        if byte != b'\x00':
            ps += byte

    em = b'\x00\x02' + ps + b'\x00' + message
    m_int = _os2ip(em)
    c_int = _rsa_encrypt_raw(m_int, pub)
    return _i2osp(c_int, k)


def rsa_decrypt_pkcs1v15(ciphertext: bytes, priv: RSAPrivateKey) -> bytes:
    """RSA decryption with PKCS#1 v1.5 unpadding."""
    k = (priv.key_size + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("Invalid ciphertext length")

    c_int = _os2ip(ciphertext)
    m_int = _rsa_decrypt_raw(c_int, priv)
    em = _i2osp(m_int, k)

    # Constant-time checks to prevent Bleichenbacher's attack
    valid = 1
    valid &= 1 if em[0] == 0x00 else 0
    valid &= 1 if em[1] == 0x02 else 0

    # Find 0x00 separator — scan all bytes to avoid timing leak
    sep_idx = -1
    for i in range(2, len(em)):
        if em[i] == 0x00 and sep_idx == -1:
            sep_idx = i

    valid &= 1 if sep_idx >= 10 else 0
    valid &= 1 if sep_idx != -1 else 0

    if not valid:
        raise ValueError("Decryption error")

    return em[sep_idx + 1:]


# ============================================================================
# RSA-OAEP (RFC 8017)
# ============================================================================

def _mgf1(seed: bytes, mask_len: int) -> bytes:
    """MGF1 Mask Generation Function using SHA-256."""
    mask = b''
    counter = 0
    while len(mask) < mask_len:
        C = counter.to_bytes(4, byteorder='big')
        mask += sha256(seed + C)
        counter += 1
    return mask[:mask_len]


def rsa_encrypt_oaep(message: bytes, pub: RSAPublicKey,
                     label: bytes = b'') -> bytes:
    """RSA-OAEP encryption with SHA-256."""
    h_len = 32  # SHA-256 output length
    k = (pub.key_size + 7) // 8
    m_len = len(message)

    if m_len > k - 2 * h_len - 2:
        raise ValueError("Message too long for OAEP")

    l_hash = sha256(label)
    ps = b'\x00' * (k - m_len - 2 * h_len - 2)
    db = l_hash + ps + b'\x01' + message

    seed = os.urandom(h_len)
    db_mask = _mgf1(seed, k - h_len - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = _mgf1(masked_db, h_len)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    em = b'\x00' + masked_seed + masked_db
    m_int = _os2ip(em)
    c_int = _rsa_encrypt_raw(m_int, pub)
    return _i2osp(c_int, k)


def rsa_decrypt_oaep(ciphertext: bytes, priv: RSAPrivateKey,
                     label: bytes = b'') -> bytes:
    """RSA-OAEP decryption with SHA-256."""
    h_len = 32
    k = (priv.key_size + 7) // 8

    if len(ciphertext) != k:
        raise ValueError("Decryption error")

    c_int = _os2ip(ciphertext)
    m_int = _rsa_decrypt_raw(c_int, priv)
    em = _i2osp(m_int, k)

    if em[0] != 0:
        raise ValueError("Decryption error")

    masked_seed = em[1:1 + h_len]
    masked_db = em[1 + h_len:]

    seed_mask = _mgf1(masked_db, h_len)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = _mgf1(seed, k - h_len - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    l_hash = sha256(label)

    # Constant-time validation (RFC 8017 Section 7.1.2: all checks at same time)
    import hmac as hmac_mod
    valid = hmac_mod.compare_digest(db[:h_len], l_hash)

    # Find 0x01 separator — scan all bytes regardless of outcome
    sep_idx = -1
    for i in range(h_len, len(db)):
        if db[i] == 1 and sep_idx == -1:
            sep_idx = i
        elif db[i] != 0 and sep_idx == -1:
            valid = False

    if sep_idx == -1:
        valid = False

    if not valid:
        raise ValueError("Decryption error")

    return db[sep_idx + 1:]


# ============================================================================
# RSA SIGNATURES (PKCS#1 v1.5)
# ============================================================================

# DER-encoded DigestInfo prefix for SHA-256
SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


def rsa_sign(message: bytes, priv: RSAPrivateKey) -> bytes:
    """RSA PKCS#1 v1.5 signature with SHA-256."""
    k = (priv.key_size + 7) // 8
    digest = sha256(message)
    T = SHA256_DIGEST_INFO + digest

    if len(T) + 11 > k:
        raise ValueError("Key too short for signature")

    ps_len = k - len(T) - 3
    em = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + T

    m_int = _os2ip(em)
    s_int = _rsa_decrypt_raw(m_int, priv)  # sign = decrypt with private key
    return _i2osp(s_int, k)


def rsa_verify(message: bytes, signature: bytes, pub: RSAPublicKey) -> bool:
    """RSA PKCS#1 v1.5 signature verification."""
    k = (pub.key_size + 7) // 8
    if len(signature) != k:
        return False

    s_int = _os2ip(signature)
    m_int = _rsa_encrypt_raw(s_int, pub)  # verify = encrypt with public key
    em = _i2osp(m_int, k)

    digest = sha256(message)
    T = SHA256_DIGEST_INFO + digest

    ps_len = k - len(T) - 3
    expected = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + T

    import hmac as hmac_mod
    return hmac_mod.compare_digest(em, expected)
