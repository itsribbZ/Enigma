"""
Enigma Phase 2: CryptoPals test suite.
Tests core utilities and key attacks from Sets 1-4.
"""
import os
import pytest
from cryptopals import (
    hex_to_base64, xor_bytes, score_english,
    single_byte_xor_decrypt, repeating_key_xor,
    hamming_distance, break_repeating_key_xor,
    detect_ecb, encryption_oracle, detect_ecb_or_cbc,
    byte_at_a_time_ecb_decrypt, validate_pkcs7,
    cbc_padding_oracle_attack, cbc_bitflip,
    MT19937, untemper, clone_mt19937,
)
from aes import (
    aes_encrypt_block, aes_ecb_encrypt, aes_ecb_decrypt,
    aes_cbc_encrypt, aes_cbc_decrypt, pkcs7_pad, pkcs7_unpad,
)


def test_hex_to_base64():
    inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex_to_base64(inp) == expected


def test_fixed_xor():
    a = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    b = bytes.fromhex("686974207468652062756c6c277320657965")
    assert xor_bytes(a, b) == bytes.fromhex("746865206b696420646f6e277420706c6179")


def test_single_byte_xor():
    ct = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    key, pt, _ = single_byte_xor_decrypt(ct)
    assert key == 88
    assert b"Cooking MC" in pt


def test_repeating_key_xor():
    pt = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    ct = repeating_key_xor(pt, key)
    assert ct.hex() == expected
    assert repeating_key_xor(ct, key) == pt


def test_hamming_distance():
    assert hamming_distance(b"this is a test", b"wokka wokka!!!") == 37


def test_break_repeating_key_xor():
    secret = (b"Now is the time for all good men to come to the aid of their country. "
              b"The quick brown fox jumps over the lazy dog several times in succession. "
              b"We hold these truths to be self evident that all men are created equal and "
              b"that they are endowed by their creator with certain unalienable rights among "
              b"these are life liberty and the pursuit of happiness. This message must be "
              b"long enough for the statistical frequency analysis to work correctly on the "
              b"transposed blocks that result from splitting the ciphertext by key size.")
    key = b"ICE"
    ct = repeating_key_xor(secret, key)
    recovered_key, recovered_pt = break_repeating_key_xor(ct)
    assert recovered_pt == secret
    assert key in recovered_key or recovered_key in key * 10


def test_detect_ecb():
    key = os.urandom(16)
    ecb_ct = aes_ecb_encrypt(b'\x00' * 48, key)
    cbc_ct = os.urandom(64)
    detected = detect_ecb([cbc_ct, ecb_ct, os.urandom(64)])
    assert 1 in detected
    assert 0 not in detected


def test_ecb_cbc_oracle():
    test_input = b'\x00' * 48
    correct = sum(
        1 for _ in range(20)
        if detect_ecb_or_cbc(encryption_oracle(test_input)[0]) == encryption_oracle(test_input)[1]
    )
    # Re-do properly to avoid double-call issue
    correct = 0
    for _ in range(20):
        ct, actual_mode = encryption_oracle(test_input)
        if detect_ecb_or_cbc(ct) == actual_mode:
            correct += 1
    assert correct >= 14


def test_byte_at_a_time_ecb():
    secret_suffix = b"This is the unknown secret text that we will recover byte by byte!"
    key = os.urandom(16)

    def oracle(plaintext: bytes) -> bytes:
        return aes_ecb_encrypt(plaintext + secret_suffix, key)

    assert byte_at_a_time_ecb_decrypt(oracle) == secret_suffix


def test_pkcs7_validation():
    assert validate_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY"
    with pytest.raises(ValueError):
        validate_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    with pytest.raises(ValueError):
        validate_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")


def test_cbc_padding_oracle():
    key = os.urandom(16)
    iv = os.urandom(16)
    secret = b"Attack at dawn! This is secret."
    ct = aes_cbc_encrypt(secret, key, iv)

    def oracle(ciphertext: bytes, test_iv: bytes) -> bool:
        try:
            aes_cbc_decrypt(ciphertext, key, test_iv)
            return True
        except ValueError:
            return False

    assert cbc_padding_oracle_attack(ct, iv, oracle) == secret


def test_mt19937():
    mt = MT19937(42)
    outputs = [mt.extract_number() for _ in range(10)]
    mt2 = MT19937(42)
    assert [mt2.extract_number() for _ in range(10)] == outputs
    mt3 = MT19937(43)
    assert [mt3.extract_number() for _ in range(10)] != outputs


def test_clone_mt19937():
    mt = MT19937(12345)
    outputs = [mt.extract_number() for _ in range(624)]
    cloned = clone_mt19937(outputs)
    for i in range(100):
        assert mt.extract_number() == cloned.extract_number()
