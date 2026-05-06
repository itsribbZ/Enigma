"""
Enigma Phase 2: AES — from scratch.
Implements FIPS 197 (AES-128/192/256), SP 800-38A (ECB/CBC/CTR).

Uses Phase 1's build_aes_sbox() for S-Box generation.
"""

from __future__ import annotations
import os
import struct
import sys
from typing import List, Tuple

# Import Phase 1 S-Box generators
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'phase1_math'))
from modular_math import build_aes_sbox, build_aes_inv_sbox

# ============================================================================
# CONSTANTS
# ============================================================================

SBOX = build_aes_sbox()
INV_SBOX = build_aes_inv_sbox(SBOX)

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]

# ============================================================================
# GF(2^8) MULTIPLICATION
# ============================================================================

def _xtime(a: int) -> int:
    """Multiply by 0x02 in GF(2^8)."""
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _galois_mult(a: int, b: int) -> int:
    """Multiply a and b in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

# ============================================================================
# STATE MATRIX HELPERS
# ============================================================================

def _bytes_to_state(data: bytes) -> List[List[int]]:
    """Convert 16 bytes to 4x4 state matrix (column-major)."""
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = data[i]
    return state


def _state_to_bytes(state: List[List[int]]) -> bytes:
    """Convert 4x4 state matrix back to 16 bytes."""
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return bytes(out)

# ============================================================================
# AES ROUND OPERATIONS
# ============================================================================

def _sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]


def _inv_sub_bytes(state: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]


def _shift_rows(state: List[List[int]]) -> None:
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def _inv_shift_rows(state: List[List[int]]) -> None:
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]


def _mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _galois_mult(2, a[0]) ^ _galois_mult(3, a[1]) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _galois_mult(2, a[1]) ^ _galois_mult(3, a[2]) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _galois_mult(2, a[2]) ^ _galois_mult(3, a[3])
        state[3][c] = _galois_mult(3, a[0]) ^ a[1] ^ a[2] ^ _galois_mult(2, a[3])


def _inv_mix_columns(state: List[List[int]]) -> None:
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _galois_mult(0x0E, a[0]) ^ _galois_mult(0x0B, a[1]) ^ _galois_mult(0x0D, a[2]) ^ _galois_mult(0x09, a[3])
        state[1][c] = _galois_mult(0x09, a[0]) ^ _galois_mult(0x0E, a[1]) ^ _galois_mult(0x0B, a[2]) ^ _galois_mult(0x0D, a[3])
        state[2][c] = _galois_mult(0x0D, a[0]) ^ _galois_mult(0x09, a[1]) ^ _galois_mult(0x0E, a[2]) ^ _galois_mult(0x0B, a[3])
        state[3][c] = _galois_mult(0x0B, a[0]) ^ _galois_mult(0x0D, a[1]) ^ _galois_mult(0x09, a[2]) ^ _galois_mult(0x0E, a[3])


def _add_round_key(state: List[List[int]], round_key: List[List[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]

# ============================================================================
# KEY EXPANSION
# ============================================================================

def _rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]


def _sub_word(word: List[int]) -> List[int]:
    return [SBOX[b] for b in word]


def _key_expansion(key: bytes) -> List[List[List[int]]]:
    """Expand key into round key schedule. Returns list of 4x4 round key matrices."""
    key_len = len(key)
    if key_len == 16:
        Nk, Nr = 4, 10
    elif key_len == 24:
        Nk, Nr = 6, 12
    elif key_len == 32:
        Nk, Nr = 8, 14
    else:
        raise ValueError(f"Invalid key length: {key_len} (must be 16, 24, or 32)")

    # Initialize W[0..Nk-1]
    W = []
    for i in range(Nk):
        W.append(list(key[4*i:4*i+4]))

    for i in range(Nk, 4 * (Nr + 1)):
        temp = W[i - 1][:]
        if i % Nk == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = _sub_word(temp)
        W.append([W[i - Nk][j] ^ temp[j] for j in range(4)])

    # Convert words to 4x4 round key matrices
    round_keys = []
    for rnd in range(Nr + 1):
        rk = [[0] * 4 for _ in range(4)]
        for c in range(4):
            word = W[rnd * 4 + c]
            for r in range(4):
                rk[r][c] = word[r]
        round_keys.append(rk)

    return round_keys

# ============================================================================
# AES ENCRYPT/DECRYPT BLOCK
# ============================================================================

def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES."""
    if len(plaintext) != 16:
        raise ValueError(f"Block must be 16 bytes, got {len(plaintext)}")

    round_keys = _key_expansion(key)
    Nr = len(round_keys) - 1
    state = _bytes_to_state(plaintext)

    _add_round_key(state, round_keys[0])

    for rnd in range(1, Nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])

    # Final round (no MixColumns)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[Nr])

    return _state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt a single 16-byte block with AES."""
    if len(ciphertext) != 16:
        raise ValueError(f"Block must be 16 bytes, got {len(ciphertext)}")

    round_keys = _key_expansion(key)
    Nr = len(round_keys) - 1
    state = _bytes_to_state(ciphertext)

    _add_round_key(state, round_keys[Nr])

    for rnd in range(Nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)

    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)

# ============================================================================
# PKCS#7 PADDING
# ============================================================================

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 padding. Always adds padding (even if already aligned)."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding. Raises ValueError if invalid.

    Uses constant-time comparison to prevent padding oracle attacks.
    """
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    # Constant-time padding check to prevent timing side-channel
    import hmac
    expected = bytes([pad_len] * pad_len)
    if not hmac.compare_digest(data[-pad_len:], expected):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]

# ============================================================================
# ECB MODE
# ============================================================================

def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """AES-ECB encryption. Applies PKCS#7 padding."""
    padded = pkcs7_pad(plaintext)
    ct = b''
    for i in range(0, len(padded), 16):
        ct += aes_encrypt_block(padded[i:i+16], key)
    return ct


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """AES-ECB decryption. Removes PKCS#7 padding."""
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16")
    pt = b''
    for i in range(0, len(ciphertext), 16):
        pt += aes_decrypt_block(ciphertext[i:i+16], key)
    return pkcs7_unpad(pt)

# ============================================================================
# CBC MODE
# ============================================================================

def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC encryption with PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    padded = pkcs7_pad(plaintext)
    ct = b''
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        encrypted = aes_encrypt_block(block, key)
        ct += encrypted
        prev = encrypted
    return ct


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-CBC decryption. Removes PKCS#7 padding."""
    if len(iv) != 16 or len(ciphertext) % 16 != 0:
        raise ValueError("IV must be 16 bytes, ciphertext must be block-aligned")
    pt = b''
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted = aes_decrypt_block(block, key)
        pt += bytes(a ^ b for a, b in zip(decrypted, prev))
        prev = block
    return pkcs7_unpad(pt)

# ============================================================================
# CTR MODE
# ============================================================================

def _inc_counter(counter: bytes) -> bytes:
    """Increment 16-byte counter (last 4 bytes as big-endian integer)."""
    nonce = counter[:12]
    ctr = int.from_bytes(counter[12:], 'big')
    ctr = (ctr + 1) & 0xFFFFFFFF
    return nonce + ctr.to_bytes(4, 'big')


def aes_ctr_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES-CTR encryption. No padding needed (stream mode).

    Maximum plaintext: 2^32 * 16 = 64 GB per nonce (counter overflow protection).
    """
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")
    max_blocks = 2**32 - 1
    n_blocks = (len(plaintext) + 15) // 16
    if n_blocks > max_blocks:
        raise ValueError(f"Plaintext too large for CTR mode: {n_blocks} blocks > {max_blocks}")
    counter = nonce + b'\x00\x00\x00\x01'
    ct = b''
    for i in range(0, len(plaintext), 16):
        keystream = aes_encrypt_block(counter, key)
        block = plaintext[i:i+16]
        ct += bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        counter = _inc_counter(counter)
    return ct


# CTR decryption = CTR encryption (XOR is self-inverse)
aes_ctr_decrypt = aes_ctr_encrypt


# ============================================================================
# GCM MODE (Authenticated Encryption with Associated Data)
# ============================================================================

def _ghash_mult(x: bytes, y: bytes) -> bytes:
    """Multiply two 128-bit blocks in GF(2^128) for GHASH.
    Irreducible polynomial: x^128 + x^7 + x^2 + x + 1.
    """
    R = 0xE1000000000000000000000000000000  # R = 11100001 || 0^120
    xi = int.from_bytes(x, 'big')
    yi = int.from_bytes(y, 'big')
    z = 0
    for i in range(128):
        if (yi >> (127 - i)) & 1:
            z ^= xi
        if xi & 1:
            xi = (xi >> 1) ^ R
        else:
            xi >>= 1
    return z.to_bytes(16, 'big')


def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """GHASH function for GCM authentication tag computation."""
    def pad_to_16(data: bytes) -> bytes:
        r = len(data) % 16
        return data + b'\x00' * (16 - r) if r else data

    # Process AAD
    tag = b'\x00' * 16
    padded_aad = pad_to_16(aad)
    for i in range(0, len(padded_aad), 16):
        block = padded_aad[i:i+16]
        tag = bytes(a ^ b for a, b in zip(tag, block))
        tag = _ghash_mult(tag, h)

    # Process ciphertext
    padded_ct = pad_to_16(ciphertext)
    for i in range(0, len(padded_ct), 16):
        block = padded_ct[i:i+16]
        tag = bytes(a ^ b for a, b in zip(tag, block))
        tag = _ghash_mult(tag, h)

    # Final block: len(AAD) || len(CT) in bits, each as 64-bit big-endian
    lengths = (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')
    tag = bytes(a ^ b for a, b in zip(tag, lengths))
    tag = _ghash_mult(tag, h)

    return tag


def aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes,
                    aad: bytes = b'') -> tuple:
    """AES-GCM authenticated encryption.

    Returns (ciphertext, tag) where tag is 16 bytes.
    Nonce must be 12 bytes (96 bits) per NIST SP 800-38D.
    """
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")

    # Hash subkey H = AES_K(0^128)
    h = aes_encrypt_block(b'\x00' * 16, key)

    # Initial counter J0 = nonce || 0x00000001
    j0 = nonce + b'\x00\x00\x00\x01'

    # Encrypt plaintext with CTR mode starting at J0 + 1
    counter = _inc_counter(j0)
    ciphertext = b''
    for i in range(0, len(plaintext), 16):
        keystream = aes_encrypt_block(counter, key)
        block = plaintext[i:i+16]
        ciphertext += bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        counter = _inc_counter(counter)

    # Compute GHASH tag
    ghash_tag = _ghash(h, aad, ciphertext)

    # Final tag = GHASH XOR E_K(J0)
    j0_enc = aes_encrypt_block(j0, key)
    tag = bytes(a ^ b for a, b in zip(ghash_tag, j0_enc))

    return ciphertext, tag


def aes_gcm_decrypt(ciphertext: bytes, key: bytes, nonce: bytes,
                    tag: bytes, aad: bytes = b'') -> bytes:
    """AES-GCM authenticated decryption.

    Raises ValueError if authentication tag is invalid.
    """
    import hmac as hmac_mod
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")

    # Recompute tag
    h = aes_encrypt_block(b'\x00' * 16, key)
    j0 = nonce + b'\x00\x00\x00\x01'

    ghash_tag = _ghash(h, aad, ciphertext)
    j0_enc = aes_encrypt_block(j0, key)
    expected_tag = bytes(a ^ b for a, b in zip(ghash_tag, j0_enc))

    # Constant-time tag comparison
    if not hmac_mod.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed: invalid tag")

    # Decrypt with CTR
    counter = _inc_counter(j0)
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        keystream = aes_encrypt_block(counter, key)
        block = ciphertext[i:i+16]
        plaintext += bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
        counter = _inc_counter(counter)

    return plaintext
