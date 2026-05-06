"""
Enigma Phase 2: SHA-256/SHA-1/HMAC test suite.
Test vectors from FIPS 180-4, RFC 4231, RFC 3174.
"""
import os
import hashlib
import hmac as hmac_stdlib
import pytest
from sha256 import (
    sha256, sha256_hex, sha1, sha1_hex,
    hmac_sha256, hmac_sha1, merkle_root,
)


@pytest.mark.parametrize("msg,expected", [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
])
def test_sha256_nist(msg, expected):
    assert sha256_hex(msg) == expected


@pytest.mark.parametrize("msg", [b"", b"abc", b"hello world", b"x" * 1000])
def test_sha256_hashlib_crosscheck(msg):
    assert sha256_hex(msg) == hashlib.sha256(msg).hexdigest()


def test_sha256_million_a():
    assert sha256_hex(b"a" * 1_000_000) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


@pytest.mark.parametrize("msg,expected", [
    (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
    (b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
])
def test_sha1_nist(msg, expected):
    assert sha1_hex(msg) == expected


@pytest.mark.parametrize("msg", [b"", b"abc", b"hello world", b"x" * 500])
def test_sha1_hashlib_crosscheck(msg):
    assert sha1_hex(msg) == hashlib.sha1(msg).hexdigest()


def test_hmac_sha256():
    # RFC 4231 Test Case 1
    assert hmac_sha256(bytes.fromhex("0b" * 20), b"Hi There").hex() == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    # Test Case 2
    assert hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    # Test Case 3
    assert hmac_sha256(bytes.fromhex("aa" * 20), bytes.fromhex("dd" * 50)).hex() == \
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    # Test Case 6
    assert hmac_sha256(bytes.fromhex("aa" * 131),
        b"Test Using Larger Than Block-Size Key - Hash Key First").hex() == \
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"


@pytest.mark.parametrize("key,msg", [(b"secret", b"message"), (b"k" * 100, b"data"), (b"x", b"y" * 500)])
def test_hmac_sha256_crosscheck(key, msg):
    assert hmac_sha256(key, msg) == hmac_stdlib.new(key, msg, hashlib.sha256).digest()


@pytest.mark.parametrize("key,msg", [(b"key", b"message"), (b"secret", b"data"), (b"x" * 100, b"y" * 200)])
def test_hmac_sha1_crosscheck(key, msg):
    assert hmac_sha1(key, msg) == hmac_stdlib.new(key, msg, hashlib.sha1).digest()


def test_merkle_tree():
    blocks = [b"block0", b"block1", b"block2", b"block3"]
    root = merkle_root(blocks)
    assert len(root) == 32
    assert merkle_root(blocks) == root
    assert merkle_root([b"other", b"data"]) != root
    assert merkle_root([b"only"]) == sha256(b"only")
    assert len(merkle_root([b"a", b"b", b"c"])) == 32
