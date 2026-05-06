"""
Enigma Phase 2: ECC/ECDH/ECDSA test suite.
Test vectors from SEC 2 v2, Agent C research.
"""
import pytest
from ecc import (
    SECP256K1, P256, Point,
    is_on_curve, point_add, point_negate, scalar_multiply,
    compress_point, decompress_point,
    ecdh_keygen, ecdh_shared_secret,
    ecdsa_sign, ecdsa_verify,
)

SMALL_CURVE = {'p': 11, 'a': 1, 'b': 6, 'n': 13, 'Gx': 2, 'Gy': 7}


@pytest.mark.parametrize("curve", [SECP256K1, P256], ids=["secp256k1", "P-256"])
def test_point_on_curve(curve):
    G = (curve['Gx'], curve['Gy'])
    assert is_on_curve(G, curve)
    assert is_on_curve(None, curve)
    assert not is_on_curve((0, 0), curve)


def test_small_curve_arithmetic():
    G = (2, 7)
    assert is_on_curve(G, SMALL_CURVE)

    G2 = point_add(G, G, SMALL_CURVE)
    assert is_on_curve(G2, SMALL_CURVE)
    assert G2 == (5, 2)

    G3 = point_add(G, G2, SMALL_CURVE)
    assert is_on_curve(G3, SMALL_CURVE)
    assert G3 == (8, 3)

    assert scalar_multiply(2, G, SMALL_CURVE) == G2
    assert scalar_multiply(3, G, SMALL_CURVE) == G3
    assert scalar_multiply(13, G, SMALL_CURVE) is None
    assert scalar_multiply(14, G, SMALL_CURVE) == G


def test_ecdh_small_curve():
    G = (2, 7)
    alice_pub = scalar_multiply(3, G, SMALL_CURVE)
    assert alice_pub == (8, 3)
    bob_pub = scalar_multiply(5, G, SMALL_CURVE)
    assert bob_pub == (3, 6)

    alice_secret = scalar_multiply(3, bob_pub, SMALL_CURVE)
    bob_secret = scalar_multiply(5, alice_pub, SMALL_CURVE)
    assert alice_secret == bob_secret == (5, 2)


def test_secp256k1_generator_multiples():
    curve = SECP256K1
    G = (curve['Gx'], curve['Gy'])

    assert scalar_multiply(1, G, curve) == G

    G2 = scalar_multiply(2, G, curve)
    assert is_on_curve(G2, curve)
    assert G2[0] == 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5

    assert scalar_multiply(curve['n'], G, curve) is None


def test_p256_generator():
    curve = P256
    G = (curve['Gx'], curve['Gy'])
    assert is_on_curve(G, curve)
    assert is_on_curve(scalar_multiply(2, G, curve), curve)
    assert scalar_multiply(curve['n'], G, curve) is None


def test_point_compression():
    curve = SECP256K1
    G = (curve['Gx'], curve['Gy'])

    compressed = compress_point(G)
    assert len(compressed) == 33
    assert compressed[0] in (0x02, 0x03)
    assert decompress_point(compressed, curve) == G

    G2 = scalar_multiply(2, G, curve)
    assert decompress_point(compress_point(G2), curve) == G2


def test_ecdh_secp256k1():
    curve = SECP256K1
    alice_priv, alice_pub = ecdh_keygen(curve)
    bob_priv, bob_pub = ecdh_keygen(curve)

    assert is_on_curve(alice_pub, curve)
    assert is_on_curve(bob_pub, curve)

    alice_secret = ecdh_shared_secret(alice_priv, bob_pub, curve)
    bob_secret = ecdh_shared_secret(bob_priv, alice_pub, curve)
    assert alice_secret == bob_secret


def test_ecdsa_secp256k1():
    curve = SECP256K1
    priv, pub = ecdh_keygen(curve)
    msg = b"Hello ECDSA on secp256k1!"
    sig = ecdsa_sign(msg, priv, curve)
    r, s = sig

    assert 1 <= r < curve['n'] and 1 <= s < curve['n']
    assert ecdsa_verify(msg, sig, pub, curve)
    assert not ecdsa_verify(b"Wrong message", sig, pub, curve)
    assert not ecdsa_verify(msg, (r + 1, s), pub, curve)


@pytest.mark.parametrize("msg", [b"Test", b"", b"x" * 100], ids=["short", "empty", "long"])
def test_ecdsa_p256(msg):
    curve = P256
    priv, pub = ecdh_keygen(curve)
    sig = ecdsa_sign(msg, priv, curve)
    assert ecdsa_verify(msg, sig, pub, curve)


def test_ecdsa_cross_key():
    curve = SECP256K1
    priv1, pub1 = ecdh_keygen(curve)
    _, pub2 = ecdh_keygen(curve)
    sig = ecdsa_sign(b"Cross-key test", priv1, curve)
    assert not ecdsa_verify(b"Cross-key test", sig, pub2, curve)


def test_ecdsa_deterministic():
    curve = SECP256K1
    priv, pub = ecdh_keygen(curve)
    msg = b"Deterministic nonce test"

    sig1 = ecdsa_sign(msg, priv, curve, deterministic=True)
    sig2 = ecdsa_sign(msg, priv, curve, deterministic=True)
    assert sig1 == sig2
    assert ecdsa_verify(msg, sig1, pub, curve)

    sig3 = ecdsa_sign(b"Different msg", priv, curve, deterministic=True)
    assert sig3 != sig1
