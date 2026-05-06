"""
Enigma Phase 2: AES test suite.
Test vectors from FIPS 197 Appendix B/C, NIST SP 800-38A.
"""
import os
import pytest
from aes import (
    aes_encrypt_block, aes_decrypt_block,
    aes_ecb_encrypt, aes_ecb_decrypt,
    aes_cbc_encrypt, aes_cbc_decrypt,
    aes_ctr_encrypt, aes_ctr_decrypt,
    aes_gcm_encrypt, aes_gcm_decrypt,
    pkcs7_pad, pkcs7_unpad,
    SBOX,
)


def test_sbox():
    assert SBOX[0x00] == 0x63
    assert SBOX[0x01] == 0x7C
    assert SBOX[0x53] == 0xED
    assert SBOX[0xFF] == 0x16


def test_aes128_block():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    ct = aes_encrypt_block(pt, key)
    assert ct == expected_ct
    assert aes_decrypt_block(ct, key) == pt


def test_aes192_block():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
    assert aes_encrypt_block(pt, key) == expected_ct
    assert aes_decrypt_block(expected_ct, key) == pt


def test_aes256_block():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
    assert aes_encrypt_block(pt, key) == expected_ct
    assert aes_decrypt_block(expected_ct, key) == pt


def test_pkcs7():
    assert pkcs7_pad(b"YELLOW SUBMARINE") == b"YELLOW SUBMARINE" + bytes([16] * 16)
    assert pkcs7_pad(b"abc") == b"abc" + bytes([13] * 13)
    assert pkcs7_pad(b"") == bytes([16] * 16)
    assert pkcs7_unpad(b"abc" + bytes([13] * 13)) == b"abc"
    assert pkcs7_unpad(bytes([16] * 16)) == b""

    with pytest.raises(ValueError):
        pkcs7_unpad(b"abc\x00")


@pytest.mark.parametrize("msg", [b"Hello AES!", b"Exactly 16 bytes", b"x" * 100, b""])
def test_ecb_roundtrip(msg):
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    assert aes_ecb_decrypt(aes_ecb_encrypt(msg, key), key) == msg


def test_ecb_identical_blocks():
    key = b'\x00' * 16
    ct = aes_ecb_encrypt(b'\xAA' * 32, key)
    assert ct[:16] == ct[16:32]


def test_cbc_nist_vector():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt_block1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ct1 = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    xored = bytes(a ^ b for a, b in zip(pt_block1, iv))
    assert aes_encrypt_block(xored, key) == expected_ct1


@pytest.mark.parametrize("msg", [b"Hello CBC mode!", b"x" * 100, b"Short", b"Exactly 16 bytes"])
def test_cbc_roundtrip(msg):
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert aes_cbc_decrypt(aes_cbc_encrypt(msg, key, iv), key, iv) == msg


@pytest.mark.parametrize("msg", [b"Hello CTR!", b"x" * 100, b"", b"a" * 33])
def test_ctr_roundtrip(msg):
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafb")
    assert aes_ctr_decrypt(aes_ctr_encrypt(msg, key, nonce), key, nonce) == msg


def test_ctr_nonce_sensitivity():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    ct1 = aes_ctr_encrypt(b"same data", key, b'\x00' * 12)
    ct2 = aes_ctr_encrypt(b"same data", key, b'\x01' * 12)
    assert ct1 != ct2


def test_ctr_length():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    nonce = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafb")
    msg = b"Hello"
    assert len(aes_ctr_encrypt(msg, key, nonce)) == len(msg)


@pytest.mark.parametrize("msg", [b"Hello GCM!", b"x" * 100, b"", b"Short"])
def test_gcm_roundtrip(msg):
    key = os.urandom(16)
    nonce = os.urandom(12)
    ct, tag = aes_gcm_encrypt(msg, key, nonce, aad=b"")
    assert aes_gcm_decrypt(ct, key, nonce, tag, aad=b"") == msg


def test_gcm_aad():
    key = os.urandom(16)
    nonce = os.urandom(12)
    aad = b"additional authenticated data"
    ct, tag = aes_gcm_encrypt(b"secret", key, nonce, aad=aad)
    assert aes_gcm_decrypt(ct, key, nonce, tag, aad=aad) == b"secret"

    with pytest.raises(ValueError):
        aes_gcm_decrypt(ct, key, nonce, tag, aad=b"wrong")


def test_gcm_tamper_detection():
    key = os.urandom(16)
    nonce = os.urandom(12)
    aad = b"aad"
    ct, tag = aes_gcm_encrypt(b"secret", key, nonce, aad=aad)

    with pytest.raises(ValueError):
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        aes_gcm_decrypt(bytes(tampered), key, nonce, tag, aad=aad)

    with pytest.raises(ValueError):
        bad_tag = bytearray(tag)
        bad_tag[0] ^= 1
        aes_gcm_decrypt(ct, key, nonce, bytes(bad_tag), aad=aad)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 100, 256])
def test_all_modes_consistency(size):
    key128 = os.urandom(16)
    key256 = os.urandom(32)
    iv = os.urandom(16)
    nonce = os.urandom(12)
    data = os.urandom(size) if size > 0 else b""

    assert aes_ecb_decrypt(aes_ecb_encrypt(data, key128), key128) == data
    assert aes_ecb_decrypt(aes_ecb_encrypt(data, key256), key256) == data
    assert aes_cbc_decrypt(aes_cbc_encrypt(data, key128, iv), key128, iv) == data
    assert aes_ctr_decrypt(aes_ctr_encrypt(data, key128, nonce), key128, nonce) == data
