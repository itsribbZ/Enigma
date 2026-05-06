"""
Enigma Phase 2: SHA-256, SHA-1, HMAC — from scratch.
Implements FIPS 180-4 (SHA-256, SHA-1), RFC 2104 (HMAC).

SHA-1 included for CryptoPals Set 4 (length extension attacks).
SHA-1 is BROKEN for collisions — do not use for security.
"""

from __future__ import annotations
import struct
from typing import List, Optional

MASK = 0xFFFFFFFF

# ============================================================================
# SHA-256 CONSTANTS (FIPS 180-4)
# ============================================================================

# Initial hash values: first 32 bits of fractional parts of sqrt of first 8 primes
SHA256_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round constants: first 32 bits of cube roots of first 64 primes
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# ============================================================================
# SHA-256 INTERNAL FUNCTIONS
# ============================================================================

def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK

def _shr(x: int, n: int) -> int:
    return x >> n

def _ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x) & z)) & MASK

def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def _sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _gamma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)

def _gamma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)

# ============================================================================
# SHA-256 CORE
# ============================================================================

def _sha256_pad(message: bytes) -> bytes:
    """Pad message per FIPS 180-4 Section 5.1.1."""
    length_bits = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += length_bits.to_bytes(8, byteorder='big')
    return message


def _sha256_compress(H: List[int], block: bytes) -> List[int]:
    """Process one 512-bit block through 64 rounds of SHA-256."""
    # Parse block into 16 words
    W = list(struct.unpack('>16I', block))

    # Expand to 64-word schedule
    for t in range(16, 64):
        W.append((_gamma1(W[t-2]) + W[t-7] + _gamma0(W[t-15]) + W[t-16]) & MASK)

    # Initialize working variables
    a, b, c, d, e, f, g, h = H

    # 64 rounds
    for t in range(64):
        T1 = (h + _sigma1(e) + _ch(e, f, g) + SHA256_K[t] + W[t]) & MASK
        T2 = (_sigma0(a) + _maj(a, b, c)) & MASK
        h = g
        g = f
        f = e
        e = (d + T1) & MASK
        d = c
        c = b
        b = a
        a = (T1 + T2) & MASK

    return [
        (H[0] + a) & MASK, (H[1] + b) & MASK,
        (H[2] + c) & MASK, (H[3] + d) & MASK,
        (H[4] + e) & MASK, (H[5] + f) & MASK,
        (H[6] + g) & MASK, (H[7] + h) & MASK,
    ]


def sha256(message: bytes) -> bytes:
    """Compute SHA-256 hash. Returns 32 bytes."""
    padded = _sha256_pad(message)
    H = list(SHA256_H0)
    for i in range(0, len(padded), 64):
        H = _sha256_compress(H, padded[i:i+64])
    return struct.pack('>8I', *H)


def sha256_hex(message: bytes) -> str:
    """Return hex string of SHA-256 digest."""
    return sha256(message).hex()


# ============================================================================
# SHA-256 WITH INITIAL STATE (for length extension testing)
# ============================================================================

def sha256_with_state(message: bytes, state: List[int],
                      msg_len: int) -> bytes:
    """SHA-256 starting from a given internal state and message length.

    Used for length extension attacks (to demonstrate the vulnerability
    that HMAC prevents).
    """
    # Pad as if the total message length is msg_len + len(message)
    fake_msg = b'\x00' * msg_len + message
    padded_full = _sha256_pad(fake_msg)
    # Only process blocks after the original padded message
    original_padded_len = msg_len + 1  # +1 for 0x80
    while original_padded_len % 64 != 56:
        original_padded_len += 1
    original_padded_len += 8  # 64-bit length

    H = list(state)
    for i in range(original_padded_len, len(padded_full), 64):
        H = _sha256_compress(H, padded_full[i:i+64])
    return struct.pack('>8I', *H)


# ============================================================================
# SHA-1 (FIPS 180-4, Legacy — BROKEN for collisions)
# ============================================================================

SHA1_H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK


def _sha1_f(t: int, b: int, c: int, d: int) -> int:
    if t <= 19:
        return ((b & c) | ((~b) & d)) & MASK
    elif t <= 39:
        return b ^ c ^ d
    elif t <= 59:
        return (b & c) | (b & d) | (c & d)
    else:
        return b ^ c ^ d


def _sha1_pad(message: bytes) -> bytes:
    """Same padding as SHA-256."""
    length_bits = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += length_bits.to_bytes(8, byteorder='big')
    return message


def _sha1_compress(H: List[int], block: bytes) -> List[int]:
    """Process one 512-bit block through 80 rounds of SHA-1."""
    W = list(struct.unpack('>16I', block))
    for t in range(16, 80):
        w = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
        W.append(_rotl(w, 1))

    a, b, c, d, e = H

    for t in range(80):
        if t < 20:
            kt = 0x5A827999
        elif t < 40:
            kt = 0x6ED9EBA1
        elif t < 60:
            kt = 0x8F1BBCDC
        else:
            kt = 0xCA62C1D6

        temp = (_rotl(a, 5) + _sha1_f(t, b, c, d) + e + kt + W[t]) & MASK
        e = d
        d = c
        c = _rotl(b, 30)
        b = a
        a = temp

    return [
        (H[0] + a) & MASK, (H[1] + b) & MASK,
        (H[2] + c) & MASK, (H[3] + d) & MASK,
        (H[4] + e) & MASK,
    ]


def sha1(message: bytes) -> bytes:
    """Compute SHA-1 hash. Returns 20 bytes. BROKEN — do not use for security."""
    padded = _sha1_pad(message)
    H = list(SHA1_H0)
    for i in range(0, len(padded), 64):
        H = _sha1_compress(H, padded[i:i+64])
    return struct.pack('>5I', *H)


def sha1_hex(message: bytes) -> str:
    return sha1(message).hex()


def sha1_with_state(message: bytes, state: List[int],
                    msg_len: int) -> bytes:
    """SHA-1 from given state. For length extension attacks (CryptoPals 29)."""
    fake_msg = b'\x00' * msg_len + message
    padded_full = _sha1_pad(fake_msg)
    original_padded_len = msg_len + 1
    while original_padded_len % 64 != 56:
        original_padded_len += 1
    original_padded_len += 8

    H = list(state)
    for i in range(original_padded_len, len(padded_full), 64):
        H = _sha1_compress(H, padded_full[i:i+64])
    return struct.pack('>5I', *H)


# ============================================================================
# HMAC (RFC 2104)
# ============================================================================

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256. Returns 32 bytes."""
    BLOCK_SIZE = 64

    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key_prime = key + b'\x00' * (BLOCK_SIZE - len(key))

    ipad = bytes(k ^ 0x36 for k in key_prime)
    opad = bytes(k ^ 0x5C for k in key_prime)

    inner_hash = sha256(ipad + message)
    return sha256(opad + inner_hash)


def hmac_sha1(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA1. Returns 20 bytes. For CryptoPals compatibility."""
    BLOCK_SIZE = 64

    if len(key) > BLOCK_SIZE:
        key = sha1(key)
    key_prime = key + b'\x00' * (BLOCK_SIZE - len(key))

    ipad = bytes(k ^ 0x36 for k in key_prime)
    opad = bytes(k ^ 0x5C for k in key_prime)

    inner_hash = sha1(ipad + message)
    return sha1(opad + inner_hash)


# ============================================================================
# MERKLE TREE
# ============================================================================

def merkle_root(data_blocks: List[bytes]) -> bytes:
    """Compute Merkle root of data blocks using SHA-256."""
    if not data_blocks:
        return sha256(b'')

    hashes = [sha256(block) for block in data_blocks]

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])
        next_level = []
        for i in range(0, len(hashes), 2):
            next_level.append(sha256(hashes[i] + hashes[i+1]))
        hashes = next_level

    return hashes[0]
