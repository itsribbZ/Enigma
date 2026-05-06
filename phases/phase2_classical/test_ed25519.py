"""
Enigma Phase 2 (v2): Ed25519 test suite.
Test vectors from RFC 8032 Section 7.1.
"""
import pytest
from ed25519 import (
    P, D, L, B, BX, BY,
    to_extended, to_affine, point_add, scalar_multiply,
    encode_point, decode_point,
    keygen, sign, verify,
    mod_sqrt, NEUTRAL,
)


# ============================================================================
# CURVE CONSTANTS
# ============================================================================

def test_field_prime():
    assert P == 2**255 - 19
    assert P % 8 == 5  # Important for sqrt algorithm


def test_curve_parameter_d():
    assert D == (-121665 * pow(121666, P - 2, P)) % P


def test_group_order():
    assert L == 2**252 + 27742317777372353535851937790883648493


def test_base_point_on_curve():
    x, y = B
    # -x^2 + y^2 == 1 + d*x^2*y^2 (mod p)
    lhs = (-x * x + y * y) % P
    rhs = (1 + D * x * x * y * y) % P
    assert lhs == rhs


def test_base_point_order():
    B_ext = to_extended(*B)
    # L*B should be neutral
    result = scalar_multiply(L, B_ext)
    x, y = to_affine(result)
    assert x % P == 0
    assert y % P == 1


# ============================================================================
# POINT ARITHMETIC
# ============================================================================

def test_neutral_element():
    B_ext = to_extended(*B)
    result = point_add(B_ext, NEUTRAL)
    assert to_affine(result) == B


def test_double_equals_add():
    B_ext = to_extended(*B)
    doubled = point_add(B_ext, B_ext)
    assert to_affine(doubled) == to_affine(scalar_multiply(2, B_ext))


def test_scalar_associativity():
    B_ext = to_extended(*B)
    p3 = scalar_multiply(3, B_ext)
    p5 = scalar_multiply(5, B_ext)
    p8 = scalar_multiply(8, B_ext)
    assert to_affine(point_add(p3, p5)) == to_affine(p8)


# ============================================================================
# POINT ENCODING / DECODING
# ============================================================================

def test_encode_decode_base_point():
    B_ext = to_extended(*B)
    encoded = encode_point(B_ext)
    assert len(encoded) == 32
    decoded = decode_point(encoded)
    assert to_affine(decoded) == B


def test_encode_decode_roundtrip():
    B_ext = to_extended(*B)
    for k in [1, 2, 3, 7, 42, 12345]:
        point = scalar_multiply(k, B_ext)
        encoded = encode_point(point)
        decoded = decode_point(encoded)
        assert to_affine(decoded) == to_affine(point)


def test_encode_neutral():
    encoded = encode_point(NEUTRAL)
    decoded = decode_point(encoded)
    assert to_affine(decoded) == (0, 1)


# ============================================================================
# RFC 8032 Section 7.1 TEST VECTORS
# ============================================================================

# Test 1: empty message (verified against cryptography library)
RFC_TEST_1 = {
    'seed': bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60"
    ),
    'public': bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    ),
    'message': b"",
    'signature': bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    ),
}

# Test 2: single byte 0x72 (verified against cryptography library)
RFC_TEST_2 = {
    'seed': bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    ),
    'public': bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc"
        "9c982ccf2ec4968cc0cd55f12af4660c"
    ),
    'message': bytes.fromhex("72"),
    'signature': bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540"
        "a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c"
        "387b2eaeb4302aeeb00d291612bb0c00"
    ),
}

# Test 3: 2-byte message (verified against cryptography library)
RFC_TEST_3 = {
    'seed': bytes.fromhex(
        "c5aa8df43f9f837bedb7442f31dcb7b1"
        "66d38535076f094b85ce3a2e0b4458f7"
    ),
    'public': bytes.fromhex(
        "fc51cd8e6218a1a38da47ed00230f058"
        "0816ed13ba3303ac5deb911548908025"
    ),
    'message': bytes.fromhex("af82"),
    'signature': bytes.fromhex(
        "6291d657deec24024827e69c3abe01a3"
        "0ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc659"
        "4a7c15e9716ed28dc027beceea1ec40a"
    ),
}


def test_rfc8032_keygen_test1():
    seed = RFC_TEST_1['seed']
    _, pub = keygen(seed)
    assert pub == RFC_TEST_1['public']


def test_rfc8032_keygen_test2():
    _, pub = keygen(RFC_TEST_2['seed'])
    assert pub == RFC_TEST_2['public']


def test_rfc8032_keygen_test3():
    _, pub = keygen(RFC_TEST_3['seed'])
    assert pub == RFC_TEST_3['public']


def test_rfc8032_sign_test1():
    sig = sign(RFC_TEST_1['seed'], RFC_TEST_1['message'])
    assert sig == RFC_TEST_1['signature']


def test_rfc8032_sign_test3():
    sig = sign(RFC_TEST_3['seed'], RFC_TEST_3['message'])
    assert sig == RFC_TEST_3['signature']


def test_rfc8032_verify_test1():
    assert verify(RFC_TEST_1['public'], RFC_TEST_1['message'], RFC_TEST_1['signature'])


def test_rfc8032_verify_test2():
    assert verify(RFC_TEST_2['public'], RFC_TEST_2['message'], RFC_TEST_2['signature'])


def test_rfc8032_verify_test3():
    assert verify(RFC_TEST_3['public'], RFC_TEST_3['message'], RFC_TEST_3['signature'])


# ============================================================================
# SIGN/VERIFY ROUNDTRIP
# ============================================================================

def test_sign_verify_roundtrip():
    seed, pub = keygen()
    for msg in [b"", b"Hello Ed25519!", b"x" * 1000]:
        sig = sign(seed, msg)
        assert verify(pub, msg, sig)


def test_wrong_message_fails():
    seed, pub = keygen()
    sig = sign(seed, b"correct message")
    assert not verify(pub, b"wrong message", sig)


def test_wrong_key_fails():
    seed1, pub1 = keygen()
    _, pub2 = keygen()
    sig = sign(seed1, b"test")
    assert not verify(pub2, b"test", sig)


def test_tampered_signature_fails():
    seed, pub = keygen()
    sig = sign(seed, b"test")
    tampered = bytearray(sig)
    tampered[0] ^= 0xFF
    assert not verify(pub, b"test", bytes(tampered))


def test_deterministic():
    seed, pub = keygen()
    msg = b"deterministic"
    sig1 = sign(seed, msg)
    sig2 = sign(seed, msg)
    assert sig1 == sig2
