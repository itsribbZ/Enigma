"""
Enigma Phase 2: CryptoPals Sets 1-4 — Core utilities and attacks.
Proves ability to BREAK crypto, not just build it.

Key attacks implemented:
  - Single-byte XOR cipher (frequency analysis)
  - Repeating-key XOR (Vigenere break via Hamming distance)
  - Byte-at-a-time ECB decryption oracle
  - CBC padding oracle attack
  - ECB/CBC detection oracle
"""

from __future__ import annotations
import base64
import os
import struct
import sys
from typing import Callable, List, Optional, Tuple
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from aes import (
    aes_encrypt_block, aes_decrypt_block,
    aes_ecb_encrypt, aes_ecb_decrypt,
    aes_cbc_encrypt, aes_cbc_decrypt,
    pkcs7_pad, pkcs7_unpad,
)

# ============================================================================
# SET 1: BASICS
# ============================================================================

# --- Challenge 1: Hex to Base64 ---

def hex_to_base64(hex_str: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_str)).decode('ascii')


# --- Challenge 2: Fixed XOR ---

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (truncates to shorter)."""
    return bytes(x ^ y for x, y in zip(a, b))


# --- Challenge 3: Single-byte XOR Cipher ---

ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.361, 'x': 0.150, 'y': 1.974,
    'z': 0.074, ' ': 13.0,
}


def score_english(text: bytes) -> float:
    """Score how likely a byte string is English text."""
    score = 0.0
    for byte in text:
        char = chr(byte).lower()
        if char in ENGLISH_FREQ:
            score += ENGLISH_FREQ[char]
        elif 32 <= byte <= 126:
            score += 0.5
        else:
            score -= 10.0
    return score


def single_byte_xor_decrypt(ciphertext: bytes) -> Tuple[int, bytes, float]:
    """Try all 256 key bytes. Returns (key, plaintext, score)."""
    best = (0, b'', float('-inf'))
    for key in range(256):
        plaintext = bytes(b ^ key for b in ciphertext)
        sc = score_english(plaintext)
        if sc > best[2]:
            best = (key, plaintext, sc)
    return best


# --- Challenge 4: Detect single-byte XOR ---

def detect_single_byte_xor(hex_lines: List[str]) -> Tuple[int, int, bytes, float]:
    """Find which line is encrypted with single-byte XOR."""
    best = (0, 0, b'', float('-inf'))
    for i, line in enumerate(hex_lines):
        ct = bytes.fromhex(line.strip())
        key, pt, sc = single_byte_xor_decrypt(ct)
        if sc > best[3]:
            best = (i, key, pt, sc)
    return best


# --- Challenge 5: Repeating-key XOR ---

def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt/decrypt with repeating-key XOR (Vigenere)."""
    return bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))


# --- Challenge 6: Break repeating-key XOR ---

def hamming_distance(a: bytes, b: bytes) -> int:
    """Count differing bits between two byte strings."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def break_repeating_key_xor(ciphertext: bytes,
                             min_keysize: int = 2,
                             max_keysize: int = 40) -> Tuple[bytes, bytes]:
    """Break repeating-key XOR. Returns (key, plaintext)."""
    # Step 1: Find likely key size via normalized Hamming distance
    scores = []
    for ks in range(min_keysize, min(max_keysize + 1, len(ciphertext) // 4)):
        chunks = [ciphertext[i*ks:(i+1)*ks] for i in range(4)]
        dists = []
        for i in range(len(chunks)):
            for j in range(i + 1, len(chunks)):
                dists.append(hamming_distance(chunks[i], chunks[j]) / ks)
        scores.append((sum(dists) / len(dists), ks))
    scores.sort()

    # Try top 3 key sizes
    best = (b'', b'', float('-inf'))
    for _, keysize in scores[:3]:
        # Step 2: Transpose into keysize blocks
        blocks = [b'' for _ in range(keysize)]
        for i, byte in enumerate(ciphertext):
            blocks[i % keysize] += bytes([byte])

        # Step 3: Solve each block as single-byte XOR
        key = b''
        for block in blocks:
            k, _, _ = single_byte_xor_decrypt(block)
            key += bytes([k])

        # Step 4: Decrypt and score
        pt = repeating_key_xor(ciphertext, key)
        sc = score_english(pt)
        if sc > best[2]:
            best = (key, pt, sc)

    return best[0], best[1]


# --- Challenge 7: AES-ECB decrypt (uses our AES) ---
# Already implemented via aes_ecb_decrypt


# --- Challenge 8: Detect AES-ECB ---

def detect_ecb(ciphertexts: List[bytes], block_size: int = 16) -> List[int]:
    """Detect ECB-encrypted ciphertexts by looking for repeated blocks."""
    ecb_indices = []
    for idx, ct in enumerate(ciphertexts):
        blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
        if len(blocks) != len(set(blocks)):
            ecb_indices.append(idx)
    return ecb_indices


# ============================================================================
# SET 2: BLOCK CIPHER CRYPTANALYSIS
# ============================================================================

# --- Challenge 9: PKCS#7 padding ---
# Already implemented in aes.py as pkcs7_pad/pkcs7_unpad


# --- Challenge 10: CBC mode ---
# Already implemented in aes.py as aes_cbc_encrypt/decrypt


# --- Challenge 11: ECB/CBC detection oracle ---

def encryption_oracle(plaintext: bytes) -> Tuple[bytes, str]:
    """Randomly encrypt with ECB or CBC. Returns (ciphertext, mode_used)."""
    key = os.urandom(16)
    prefix = os.urandom(5 + int.from_bytes(os.urandom(1), 'big') % 6)  # 5-10 bytes
    suffix = os.urandom(5 + int.from_bytes(os.urandom(1), 'big') % 6)
    padded_pt = pkcs7_pad(prefix + plaintext + suffix)

    if os.urandom(1)[0] % 2 == 0:
        # ECB
        ct = b''
        for i in range(0, len(padded_pt), 16):
            ct += aes_encrypt_block(padded_pt[i:i+16], key)
        return ct, 'ECB'
    else:
        iv = os.urandom(16)
        return aes_cbc_encrypt(prefix + plaintext + suffix, key, iv), 'CBC'


def detect_ecb_or_cbc(ciphertext: bytes) -> str:
    """Detect whether ciphertext was encrypted with ECB or CBC."""
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    if len(blocks) != len(set(blocks)):
        return 'ECB'
    return 'CBC'


# --- Challenge 12: Byte-at-a-time ECB decryption (SIMPLE) ---
# THE classic chosen-plaintext attack

def byte_at_a_time_ecb_decrypt(oracle: Callable[[bytes], bytes]) -> bytes:
    """Decrypt unknown suffix appended by an ECB oracle.

    The oracle encrypts: AES-ECB(your_input || unknown_suffix, key)
    We recover unknown_suffix one byte at a time.
    """
    # Step 1: Determine block size
    initial_len = len(oracle(b''))
    block_size = 0
    for i in range(1, 64):
        new_len = len(oracle(b'A' * i))
        if new_len > initial_len:
            block_size = new_len - initial_len
            break
    if block_size == 0:
        raise ValueError("Could not determine block size")

    # Step 2: Confirm ECB
    test = oracle(b'A' * block_size * 3)
    if test[block_size:2*block_size] != test[2*block_size:3*block_size]:
        raise ValueError("Oracle is not using ECB mode")

    # Step 3: Decrypt byte-by-byte
    unknown_len = len(oracle(b''))
    recovered = b''

    for i in range(unknown_len):
        block_idx = i // block_size
        byte_idx = i % block_size
        pad_len = block_size - byte_idx - 1

        # Create input that puts the target byte at the end of a block
        padding = b'A' * pad_len
        target_ct = oracle(padding)
        target_block = target_ct[block_idx * block_size:(block_idx + 1) * block_size]

        # Try all 256 possible bytes
        found = False
        for guess in range(256):
            test_input = padding + recovered + bytes([guess])
            test_ct = oracle(test_input)
            test_block = test_ct[block_idx * block_size:(block_idx + 1) * block_size]
            if test_block == target_block:
                recovered += bytes([guess])
                found = True
                break

        if not found:
            break  # Hit padding or end

    # Strip PKCS#7 padding from result
    try:
        return pkcs7_unpad(recovered)
    except ValueError:
        return recovered


# --- Challenge 15: PKCS#7 padding validation ---

def validate_pkcs7(data: bytes) -> bytes:
    """Validate and strip PKCS#7 padding. Raises ValueError if invalid."""
    return pkcs7_unpad(data)


# --- Challenge 16: CBC bitflipping ---

def cbc_bitflip(ciphertext: bytes, block_idx: int,
                byte_idx: int, target: int, known: int) -> bytes:
    """Flip a byte in CBC ciphertext to produce a different plaintext byte.

    Modifies block (block_idx - 1) to change byte byte_idx of block block_idx.
    target XOR known gives the XOR mask to apply.
    """
    ct = bytearray(ciphertext)
    # XOR the corresponding byte in the PREVIOUS block
    offset = (block_idx - 1) * 16 + byte_idx
    ct[offset] ^= known ^ target
    return bytes(ct)


# ============================================================================
# SET 3: BLOCK & STREAM CIPHER ATTACKS
# ============================================================================

# --- Challenge 17: CBC Padding Oracle ---
# THE most important practical attack

def cbc_padding_oracle_attack(ciphertext: bytes, iv: bytes,
                               oracle: Callable[[bytes, bytes], bool]) -> bytes:
    """Decrypt CBC ciphertext using only a padding oracle.

    oracle(ciphertext, iv) -> True if padding is valid, False otherwise.
    ~4096 queries per block (256 * 16).
    """
    block_size = 16
    blocks = [iv] + [ciphertext[i:i+block_size]
                     for i in range(0, len(ciphertext), block_size)]

    plaintext = b''

    for block_idx in range(1, len(blocks)):
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = blocks[block_idx]
        intermediate = [0] * block_size

        for byte_pos in range(block_size - 1, -1, -1):
            pad_value = block_size - byte_pos

            # Set already-known bytes to produce correct padding
            crafted = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                crafted[k] = intermediate[k] ^ pad_value

            # Try all 256 values for the target byte
            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                if oracle(bytes(curr_block), bytes(crafted)):
                    # Verify it's not a false positive for byte_pos == 15
                    if byte_pos == block_size - 1:
                        # Flip an earlier byte to confirm
                        verify = bytearray(crafted)
                        verify[byte_pos - 1] ^= 1
                        if not oracle(bytes(curr_block), bytes(verify)):
                            continue
                    intermediate[byte_pos] = guess ^ pad_value
                    found = True
                    break

            if not found:
                raise ValueError(f"Padding oracle attack failed at block {block_idx}, byte {byte_pos}")

        # Recover plaintext: P = intermediate XOR prev_block
        block_pt = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
        plaintext += block_pt

    try:
        return pkcs7_unpad(plaintext)
    except ValueError:
        return plaintext


# --- Challenge 18: CTR mode ---
# Already implemented in aes.py as aes_ctr_encrypt/decrypt


# --- Challenge 21-24: Mersenne Twister (MT19937) ---

class MT19937:
    """Mersenne Twister PRNG (Challenge 21)."""

    def __init__(self, seed: int = 0):
        self.mt = [0] * 624
        self.index = 624
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            self.mt[i] = (1812433253 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i) & 0xFFFFFFFF

    def _twist(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 624] & 0x7FFFFFFF)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.mt[i] ^= 0x9908B0DF
        self.index = 0

    def extract_number(self) -> int:
        if self.index >= 624:
            self._twist()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        self.index += 1
        return y & 0xFFFFFFFF


def untemper(y: int) -> int:
    """Reverse the MT19937 tempering transform (Challenge 23).

    Forward tempering:
      y ^= y >> 11
      y ^= (y << 7) & 0x9D2C5680
      y ^= (y << 15) & 0xEFC60000
      y ^= y >> 18
    """
    # Undo y ^= y >> 18  (top 18 bits are unchanged, XOR recovers bottom 14)
    y ^= (y >> 18)

    # Undo y ^= (y << 15) & 0xEFC60000  (bottom 15 bits unchanged)
    y ^= (y << 15) & 0xEFC60000

    # Undo y ^= (y << 7) & 0x9D2C5680  (bottom 7 bits unchanged, recover 7 bits at a time)
    tmp = y
    for _ in range(4):
        tmp = y ^ ((tmp << 7) & 0x9D2C5680)
    y = tmp

    # Undo y ^= y >> 11  (top 11 bits unchanged, recover 11 bits at a time)
    tmp = y
    for _ in range(3):
        tmp = y ^ (tmp >> 11)
    y = tmp

    return y & 0xFFFFFFFF


def clone_mt19937(outputs: List[int]) -> MT19937:
    """Clone MT19937 state from 624 consecutive outputs (Challenge 23)."""
    if len(outputs) < 624:
        raise ValueError("Need 624 outputs to clone MT19937")
    cloned = MT19937(0)
    for i in range(624):
        cloned.mt[i] = untemper(outputs[i])
    cloned.index = 624
    return cloned
