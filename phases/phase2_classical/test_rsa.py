"""
Enigma Phase 2: RSA test suite.
Tests keygen, PKCS#1 v1.5, OAEP, and signatures.
"""
import math
import pytest
from rsa import (
    generate_rsa_keypair, rsa_encrypt_pkcs1v15, rsa_decrypt_pkcs1v15,
    rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign, rsa_verify,
    RSAPublicKey, RSAPrivateKey, _rsa_encrypt_raw, _rsa_decrypt_raw,
)
from modular_math import mod_exp, mod_inverse, euler_totient_pq


def test_textbook_rsa():
    p, q = 61, 53
    n = 3233
    e = 17
    d = mod_inverse(e, euler_totient_pq(p, q))
    assert d == 2753
    assert mod_exp(65, e, n) == 2790
    assert mod_exp(2790, d, n) == 65


def test_keygen():
    pub, priv = generate_rsa_keypair(bits=1024)
    assert pub.key_size == 1024
    assert pub.e == 65537
    assert priv.p * priv.q == pub.n

    lam = (priv.p - 1) * (priv.q - 1) // math.gcd(priv.p - 1, priv.q - 1)
    assert (pub.e * priv.d) % lam == 1
    assert priv.dp == priv.d % (priv.p - 1)
    assert priv.dq == priv.d % (priv.q - 1)


@pytest.mark.parametrize("msg", [b"Hello RSA!", b"x" * 50, b"A", b""])
def test_pkcs1v15(msg):
    pub, priv = generate_rsa_keypair(bits=1024)
    assert rsa_decrypt_pkcs1v15(rsa_encrypt_pkcs1v15(msg, pub), priv) == msg


def test_pkcs1v15_probabilistic():
    pub, priv = generate_rsa_keypair(bits=1024)
    ct1 = rsa_encrypt_pkcs1v15(b"test", pub)
    ct2 = rsa_encrypt_pkcs1v15(b"test", pub)
    assert ct1 != ct2


@pytest.mark.parametrize("msg", [b"Hello OAEP!", b"x" * 30, b"A", b""])
def test_oaep(msg):
    pub, priv = generate_rsa_keypair(bits=1024)
    assert rsa_decrypt_oaep(rsa_encrypt_oaep(msg, pub), priv) == msg


def test_oaep_probabilistic():
    pub, priv = generate_rsa_keypair(bits=1024)
    assert rsa_encrypt_oaep(b"test", pub) != rsa_encrypt_oaep(b"test", pub)


def test_signatures():
    pub, priv = generate_rsa_keypair(bits=1024)
    msg = b"Sign this message"
    sig = rsa_sign(msg, priv)

    assert rsa_verify(msg, sig, pub)
    assert not rsa_verify(b"Wrong message", sig, pub)
    assert not rsa_verify(msg, b'\x00' * len(sig), pub)


@pytest.mark.parametrize("msg", [b"", b"Hello", b"x" * 100])
def test_signatures_various_messages(msg):
    pub, priv = generate_rsa_keypair(bits=1024)
    sig = rsa_sign(msg, priv)
    assert rsa_verify(msg, sig, pub)


def test_cross_key_reject():
    _, priv1 = generate_rsa_keypair(bits=1024)
    pub2, _ = generate_rsa_keypair(bits=1024)
    sig = rsa_sign(b"Cross-key test", priv1)
    assert not rsa_verify(b"Cross-key test", sig, pub2)
