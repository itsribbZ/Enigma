"""
Enigma Phase 2 (v2): Ed25519 Digital Signatures — from scratch.

RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA).
Twisted Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
Over GF(2^255 - 19).

Built from math, not libraries. Uses SHA-512 for hashing.
"""

from __future__ import annotations
import hashlib
import os
from typing import Optional, Tuple

# ============================================================================
# CURVE CONSTANTS
# ============================================================================

# Field prime: p = 2^255 - 19
P = (1 << 255) - 19

# Curve parameter d = -121665/121666 mod p
D = -121665 * pow(121666, P - 2, P) % P

# Group order
L = (1 << 252) + 27742317777372353535851937790883648493

# Base point B (RFC 8032 Section 5.1)
# Known coordinates from the Ed25519 specification:
BY = 4 * pow(5, P - 2, P) % P

# Recover Bx using the mod_sqrt approach for p ≡ 5 mod 8:
# x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
_BY2 = BY * BY % P
_u = (_BY2 - 1) % P
_v = (D * _BY2 + 1) % P

# Compute sqrt(u/v) using the Bernstein method:
# x = (u/v)^{(p+3)/8} if (u/v) is a QR
# Otherwise x = (u/v)^{(p+3)/8} * 2^{(p-1)/4}
_v3 = pow(_v, 3, P)
_v7 = pow(_v, 7, P)
BX = (_u * _v3 * pow(_u * _v7, (P - 5) // 8, P)) % P

# Verify and adjust
if (BX * BX * _v - _u) % P != 0:
    # Multiply by sqrt(-1) = 2^((p-1)/4)
    _I = pow(2, (P - 1) // 4, P)
    BX = (BX * _I) % P

assert (BX * BX * _v - _u) % P == 0, "Base point recovery failed"

# RFC 8032: "positive" square root = the one where x % 2 == 0 (sign bit 0)
# The encoding stores the sign bit (x & 1) in bit 255 of the y encoding.
if BX % 2 != 0:
    BX = P - BX

B = (BX, BY)

# Verify B is on the curve: -x^2 + y^2 = 1 + d*x^2*y^2
assert (-BX * BX + BY * BY - 1 - D * BX * BX * BY * BY) % P == 0

# ============================================================================
# FIELD ARITHMETIC
# ============================================================================

def mod_sqrt(a: int) -> int:
    """Compute sqrt(a) mod P using the Tonelli-Shanks special case for p ≡ 5 (mod 8).

    For p = 2^255 - 19, p ≡ 5 mod 8.
    Uses the formula: sqrt(a) = a^((p+3)/8) or i*a^((p+3)/8)
    where i = 2^((p-1)/4) is the square root of -1.
    """
    # candidate = a^((p+3)/8) mod p
    candidate = pow(a, (P + 3) // 8, P)

    if (candidate * candidate) % P == a % P:
        return candidate

    # Try multiplying by sqrt(-1): i = 2^((p-1)/4) mod p
    I = pow(2, (P - 1) // 4, P)
    candidate = (candidate * I) % P

    if (candidate * candidate) % P == a % P:
        return candidate

    raise ValueError(f"No square root exists for {a} mod P")


# ============================================================================
# EXTENDED TWISTED EDWARDS POINT ARITHMETIC
# ============================================================================

# Point representation: (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z
# Neutral element: (0, 1, 1, 0)

NEUTRAL = (0, 1, 1, 0)

ExtendedPoint = Tuple[int, int, int, int]


def to_extended(x: int, y: int) -> ExtendedPoint:
    """Convert affine (x, y) to extended coordinates (X, Y, Z, T)."""
    return (x % P, y % P, 1, (x * y) % P)


def to_affine(point: ExtendedPoint) -> Tuple[int, int]:
    """Convert extended coordinates back to affine."""
    X, Y, Z, T = point
    z_inv = pow(Z, P - 2, P)
    x = (X * z_inv) % P
    y = (Y * z_inv) % P
    return (x, y)


def point_add(P1: ExtendedPoint, P2: ExtendedPoint) -> ExtendedPoint:
    """Add two points in extended twisted Edwards coordinates.

    Uses the unified addition formula (works for doubling too).
    From: Hisil, Wong, Carter, Dawson (2008)
    Cost: 8M + 1D (where D = multiplication by curve constant d)
    """
    X1, Y1, Z1, T1 = P1
    X2, Y2, Z2, T2 = P2

    A = (X1 * X2) % P
    B = (Y1 * Y2) % P
    C = (T1 * D * T2) % P
    DD = (Z1 * Z2) % P

    E = ((X1 + Y1) * (X2 + Y2) - A - B) % P
    F = (DD - C) % P
    G = (DD + C) % P
    H = (B + A) % P  # Note: twisted Edwards uses -x^2, so B + A (not B - a*A where a=-1)

    X3 = (E * F) % P
    Y3 = (G * H) % P
    T3 = (E * H) % P
    Z3 = (F * G) % P

    return (X3, Y3, Z3, T3)


def point_double(P1: ExtendedPoint) -> ExtendedPoint:
    """Double a point using dedicated HWCD08 formula (faster than generic add).

    For twisted Edwards with a=-1:
    A=X1^2, B=Y1^2, C=2*Z1^2, D=a*A=-A
    E=(X1+Y1)^2-A-B, G=D+B, F=G-C, H=D-B
    """
    X1, Y1, Z1, _ = P1

    A = (X1 * X1) % P
    B = (Y1 * Y1) % P
    C = (2 * Z1 * Z1) % P
    D = (-A) % P  # a = -1
    E = ((X1 + Y1) * (X1 + Y1) - A - B) % P
    G = (D + B) % P
    F = (G - C) % P
    H = (D - B) % P

    X3 = (E * F) % P
    Y3 = (G * H) % P
    T3 = (E * H) % P
    Z3 = (F * G) % P

    return (X3, Y3, Z3, T3)


def scalar_multiply(k: int, point: ExtendedPoint) -> ExtendedPoint:
    """Compute k * point using double-and-add.

    WARNING: This is variable-time (educational implementation).
    Production Ed25519 must use a Montgomery ladder or constant-time
    conditional select to prevent timing side-channel attacks that
    leak the private scalar.
    """
    if k == 0:
        return NEUTRAL
    if k < 0:
        # Negate point: (X, Y, Z, T) -> (-X, Y, Z, -T)
        X, Y, Z, T = point
        point = ((-X) % P, Y, Z, (-T) % P)
        k = -k

    result = NEUTRAL
    addend = point

    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1

    return result


# ============================================================================
# POINT ENCODING / DECODING (RFC 8032 Section 5.1.2)
# ============================================================================

def encode_point(point: ExtendedPoint) -> bytes:
    """Encode point as 32 bytes per RFC 8032.

    Encode y-coordinate as little-endian 32 bytes.
    Set the high bit of the last byte to the sign of x (x % 2).
    """
    x, y = to_affine(point)
    # Encode y as 255 bits, with the sign of x as the top bit
    encoded = y.to_bytes(32, 'little')
    # Set high bit to x's parity
    if x % 2:
        encoded = encoded[:31] + bytes([encoded[31] | 0x80])
    return encoded


def decode_point(data: bytes) -> ExtendedPoint:
    """Decode 32 bytes to a point per RFC 8032.

    Read y from the lower 255 bits, sign of x from the top bit.
    Recover x from the curve equation.
    """
    if len(data) != 32:
        raise ValueError("Point encoding must be 32 bytes")

    # Extract sign bit
    x_sign = (data[31] >> 7) & 1

    # Extract y (clear the sign bit)
    y_bytes = bytearray(data)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, 'little')

    if y >= P:
        raise ValueError("y coordinate out of range")

    # Recover x from curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
    # x^2 = (y^2 - 1) / (d*y^2 + 1)
    y2 = (y * y) % P
    x2 = ((y2 - 1) * pow(D * y2 + 1, P - 2, P)) % P

    if x2 == 0:
        if x_sign:
            raise ValueError("x=0 cannot have sign bit set")
        return to_extended(0, y)

    x = mod_sqrt(x2)

    # Match sign
    if x % 2 != x_sign:
        x = P - x

    return to_extended(x, y)


# ============================================================================
# KEY GENERATION (RFC 8032 Section 5.1.5)
# ============================================================================

def keygen(private_seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Generate Ed25519 key pair.

    Args:
        private_seed: 32 random bytes (or None to generate)

    Returns:
        (private_seed, public_key) — both 32 bytes
    """
    if private_seed is None:
        private_seed = os.urandom(32)
    if len(private_seed) != 32:
        raise ValueError("Private seed must be 32 bytes")

    # Hash the seed
    h = hashlib.sha512(private_seed).digest()

    # Clamp the lower 32 bytes to get the scalar
    a = _clamp_scalar(h[:32])

    # Public key = a * B
    A = scalar_multiply(a, to_extended(*B))
    public_key = encode_point(A)

    return private_seed, public_key


def _clamp_scalar(h_lower: bytes) -> int:
    """Clamp the first 32 bytes of SHA-512(seed) per RFC 8032.

    Clear bits 0, 1, 2 of the first byte.
    Clear bit 7 of the last byte.
    Set bit 6 of the last byte.
    """
    a = bytearray(h_lower[:32])
    a[0] &= 0xF8   # Clear bottom 3 bits
    a[31] &= 0x7F  # Clear top bit
    a[31] |= 0x40  # Set second-to-top bit
    return int.from_bytes(a, 'little')


# ============================================================================
# SIGNING (RFC 8032 Section 5.1.6)
# ============================================================================

def sign(private_seed: bytes, message: bytes) -> bytes:
    """Sign a message using Ed25519.

    Returns 64-byte signature: R (32 bytes) || S (32 bytes).
    """
    if len(private_seed) != 32:
        raise ValueError("Private seed must be 32 bytes")

    h = hashlib.sha512(private_seed).digest()
    a = _clamp_scalar(h[:32])
    prefix = h[32:]  # Upper 32 bytes

    # Compute public key
    A = scalar_multiply(a, to_extended(*B))
    A_bytes = encode_point(A)

    # r = SHA-512(prefix || message) mod L
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % L

    # R = r * B
    R = scalar_multiply(r, to_extended(*B))
    R_bytes = encode_point(R)

    # k = SHA-512(R || A || message) mod L
    k = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + message).digest(), 'little') % L

    # S = (r + k * a) mod L
    S = (r + k * a) % L
    S_bytes = S.to_bytes(32, 'little')

    return R_bytes + S_bytes


# ============================================================================
# VERIFICATION (RFC 8032 Section 5.1.7)
# ============================================================================

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: 32 bytes
        message: arbitrary bytes
        signature: 64 bytes (R || S)

    Returns:
        True if signature is valid, False otherwise.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False

    try:
        A = decode_point(public_key)
    except ValueError:
        return False

    R_bytes = signature[:32]
    try:
        R = decode_point(R_bytes)
    except ValueError:
        return False

    S = int.from_bytes(signature[32:], 'little')
    if S >= L:
        return False

    # k = SHA-512(R || A_bytes || message) mod L
    k = int.from_bytes(
        hashlib.sha512(R_bytes + public_key + message).digest(), 'little'
    ) % L

    # Check: S*B == R + k*A
    B_ext = to_extended(*B)
    lhs = scalar_multiply(S, B_ext)
    rhs = point_add(R, scalar_multiply(k, A))

    # Compare in affine coordinates
    lhs_affine = to_affine(lhs)
    rhs_affine = to_affine(rhs)

    return lhs_affine == rhs_affine
