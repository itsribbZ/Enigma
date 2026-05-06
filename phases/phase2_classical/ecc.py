"""
Enigma Phase 2: Elliptic Curve Cryptography — from scratch.
Point arithmetic, ECDH, ECDSA over secp256k1 and NIST P-256.
Uses Phase 1's mod_inverse and tonelli_shanks.
"""

from __future__ import annotations
import os
import sys
from typing import Optional, Tuple, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase1_math'))
from modular_math import mod_inverse, tonelli_shanks

sys.path.insert(0, os.path.dirname(__file__))
from sha256 import sha256

# ============================================================================
# CURVE PARAMETERS (SEC 2 v2, FIPS 186-5)
# ============================================================================

SECP256K1 = {
    'name': 'secp256k1',
    'p': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    'a': 0,
    'b': 7,
    'Gx': 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    'Gy': 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    'n': 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    'h': 1,
}

P256 = {
    'name': 'P-256',
    'p': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    'a': 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    'b': 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    'Gx': 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    'Gy': 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    'n': 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    'h': 1,
}

# Type alias: a point is (int, int) or None (point at infinity)
Point = Optional[Tuple[int, int]]

# ============================================================================
# POINT ARITHMETIC
# ============================================================================

def is_on_curve(P: Point, curve: Dict) -> bool:
    """Check if point P lies on the curve."""
    if P is None:
        return True
    x, y = P
    p, a, b = curve['p'], curve['a'], curve['b']
    return (y * y - x * x * x - a * x - b) % p == 0


def point_add(P: Point, Q: Point, curve: Dict) -> Point:
    """Add two points on the curve. Handles all edge cases."""
    if P is None:
        return Q
    if Q is None:
        return P

    p, a = curve['p'], curve['a']
    x1, y1 = P
    x2, y2 = Q

    if x1 == x2:
        if y1 != y2:
            return None  # P + (-P) = O
        # Point doubling
        if y1 == 0:
            return None
        lam = (3 * x1 * x1 + a) * mod_inverse(2 * y1, p) % p
    else:
        # Point addition
        lam = (y2 - y1) * mod_inverse((x2 - x1) % p, p) % p

    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def point_negate(P: Point, curve: Dict) -> Point:
    """Negate a point: -(x, y) = (x, p - y)."""
    if P is None:
        return None
    return (P[0], (curve['p'] - P[1]) % curve['p'])


def scalar_multiply(k: int, P: Point, curve: Dict) -> Point:
    """Compute k*P using double-and-add (right-to-left binary method)."""
    if k == 0 or P is None:
        return None
    if k < 0:
        k = -k
        P = point_negate(P, curve)

    result = None  # Point at infinity
    addend = P

    while k:
        if k & 1:
            result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1

    return result


# ============================================================================
# POINT COMPRESSION / DECOMPRESSION
# ============================================================================

def compress_point(P: Point) -> bytes:
    """Compress point to 33 bytes: 0x02/0x03 prefix + x-coordinate."""
    if P is None:
        raise ValueError("Cannot compress point at infinity")
    x, y = P
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, 'big')


def decompress_point(data: bytes, curve: Dict) -> Point:
    """Decompress point from 33 bytes using tonelli_shanks."""
    if len(data) != 33:
        raise ValueError("Compressed point must be 33 bytes")
    prefix = data[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid prefix: {prefix:#x}")

    x = int.from_bytes(data[1:], 'big')
    p, a, b = curve['p'], curve['a'], curve['b']

    # y^2 = x^3 + ax + b mod p
    y_sq = (x * x * x + a * x + b) % p
    y = tonelli_shanks(y_sq, p)

    # Choose correct parity
    if (y % 2 == 0) != (prefix == 0x02):
        y = p - y

    return (x, y)


# ============================================================================
# ECDH KEY EXCHANGE
# ============================================================================

def ecdh_keygen(curve: Dict) -> Tuple[int, Point]:
    """Generate ECDH key pair. Returns (private_key, public_key)."""
    n = curve['n']
    G = (curve['Gx'], curve['Gy'])
    priv = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
    pub = scalar_multiply(priv, G, curve)
    return priv, pub


def ecdh_shared_secret(my_private: int, their_public: Point, curve: Dict) -> int:
    """Compute ECDH shared secret (x-coordinate of shared point)."""
    if not is_on_curve(their_public, curve):
        raise ValueError("Public key is not on the curve")
    shared = scalar_multiply(my_private, their_public, curve)
    if shared is None:
        raise ValueError("Shared secret is point at infinity")
    return shared[0]


# ============================================================================
# ECDSA SIGNATURES
# ============================================================================

def _hash_to_int(message: bytes, n: int) -> int:
    """Hash message with SHA-256 and truncate to bit length of n."""
    digest = sha256(message)
    e = int.from_bytes(digest, 'big')
    # Truncate to the bit length of n
    n_bits = n.bit_length()
    if e.bit_length() > n_bits:
        e >>= (e.bit_length() - n_bits)
    return e


def _rfc6979_k(message: bytes, private_key: int, n: int) -> int:
    """Generate deterministic k per RFC 6979. Prevents Sony PS3-class nonce reuse."""
    import hmac as hmac_mod, hashlib
    hash_digest = hashlib.sha256(message).digest()
    x_bytes = private_key.to_bytes(32, 'big')

    # RFC 6979 Section 3.2
    v = b'\x01' * 32
    k_hmac = b'\x00' * 32
    k_hmac = hmac_mod.new(k_hmac, v + b'\x00' + x_bytes + hash_digest, hashlib.sha256).digest()
    v = hmac_mod.new(k_hmac, v, hashlib.sha256).digest()
    k_hmac = hmac_mod.new(k_hmac, v + b'\x01' + x_bytes + hash_digest, hashlib.sha256).digest()
    v = hmac_mod.new(k_hmac, v, hashlib.sha256).digest()

    while True:
        v = hmac_mod.new(k_hmac, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, 'big')
        if 1 <= candidate < n:
            return candidate
        k_hmac = hmac_mod.new(k_hmac, v + b'\x00', hashlib.sha256).digest()
        v = hmac_mod.new(k_hmac, v, hashlib.sha256).digest()


def ecdsa_sign(message: bytes, private_key: int, curve: Dict,
               deterministic: bool = True) -> Tuple[int, int]:
    """Sign message using ECDSA with SHA-256. Returns (r, s).

    deterministic=True uses RFC 6979 (prevents nonce reuse attacks).
    """
    n = curve['n']
    G = (curve['Gx'], curve['Gy'])

    z = _hash_to_int(message, n)

    while True:
        if deterministic:
            k = _rfc6979_k(message, private_key, n)
        else:
            k = int.from_bytes(os.urandom(32), 'big') % (n - 1) + 1
        point = scalar_multiply(k, G, curve)
        if point is None:
            continue
        r = point[0] % n
        if r == 0:
            continue
        k_inv = mod_inverse(k, n)
        s = (k_inv * (z + r * private_key)) % n
        if s == 0:
            continue
        return (r, s)


def ecdsa_verify(message: bytes, signature: Tuple[int, int],
                 public_key: Point, curve: Dict) -> bool:
    """Verify ECDSA signature. Returns True if valid."""
    r, s = signature
    n = curve['n']
    G = (curve['Gx'], curve['Gy'])

    if not (1 <= r < n and 1 <= s < n):
        return False
    if not is_on_curve(public_key, curve):
        return False

    z = _hash_to_int(message, n)

    w = mod_inverse(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n

    # Compute u1*G + u2*Q
    p1 = scalar_multiply(u1, G, curve)
    p2 = scalar_multiply(u2, public_key, curve)
    point = point_add(p1, p2, curve)

    if point is None:
        return False

    return point[0] % n == r
