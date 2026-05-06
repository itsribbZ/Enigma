"""
Enigma Phase 5 (v2): ML-KEM (FIPS 203) test suite.
Tests NTT, polynomial arithmetic, KEM operations, all parameter sets.
"""
import pytest
from ml_kem import (
    N, Q, ZETA, ZETAS, Poly,
    ntt, inv_ntt, ntt_multiply, poly_multiply,
    cbd, sample_ntt,
    encode_poly, decode_poly,
    kpke_keygen, kpke_encrypt, kpke_decrypt,
    ml_kem_keygen, ml_kem_encaps, ml_kem_decaps,
    PARAMS,
)


# ============================================================================
# CONSTANTS
# ============================================================================

def test_constants():
    assert N == 256
    assert Q == 3329
    assert pow(ZETA, 256, Q) == 1
    assert pow(ZETA, 128, Q) != 1  # primitive 256th root


def test_zetas_precomputed():
    assert len(ZETAS) == 128
    assert ZETAS[0] == 1  # zeta^0 = 1
    assert all(0 <= z < Q for z in ZETAS)


# ============================================================================
# POLYNOMIAL ARITHMETIC
# ============================================================================

def test_poly_add():
    a = Poly([1, 2, 3] + [0] * (N - 3))
    b = Poly([4, 5, 6] + [0] * (N - 3))
    c = a + b
    assert c.coeffs[0] == 5
    assert c.coeffs[1] == 7
    assert c.coeffs[2] == 9


def test_poly_sub():
    a = Poly([10, 20, 30] + [0] * (N - 3))
    b = Poly([1, 2, 3] + [0] * (N - 3))
    c = a - b
    assert c.coeffs[0] == 9
    assert c.coeffs[1] == 18
    assert c.coeffs[2] == 27


def test_poly_mod_reduction():
    a = Poly([Q + 5] + [0] * (N - 1))
    assert a.coeffs[0] == 5


# ============================================================================
# NTT
# ============================================================================

def test_ntt_inv_roundtrip():
    """NTT followed by inverse NTT should be identity."""
    coeffs = list(range(N))
    f = Poly(coeffs)
    f_hat = ntt(f)
    f_recovered = inv_ntt(f_hat)
    assert f_recovered.coeffs == [c % Q for c in coeffs]


def test_ntt_inv_roundtrip_random():
    """NTT roundtrip with random polynomial."""
    import os
    coeffs = [int.from_bytes(os.urandom(2), 'big') % Q for _ in range(N)]
    f = Poly(coeffs)
    assert inv_ntt(ntt(f)).coeffs == coeffs


def test_ntt_linearity():
    """NTT(a + b) == NTT(a) + NTT(b)."""
    a = Poly(list(range(N)))
    b = Poly(list(range(N, 2*N)))
    assert ntt(a + b) == ntt(a) + ntt(b)


# ============================================================================
# POLYNOMIAL MULTIPLICATION
# ============================================================================

def test_poly_multiply_simple():
    """Multiply (1 + x) * (1 + x) = 1 + 2x + x^2 in R_q."""
    a = Poly([1, 1] + [0] * (N - 2))
    result = poly_multiply(a, a)
    assert result.coeffs[0] == 1
    assert result.coeffs[1] == 2
    assert result.coeffs[2] == 1


def test_poly_multiply_identity():
    """Multiply by 1 should give identity."""
    a = Poly(list(range(1, N + 1)))
    one = Poly([1] + [0] * (N - 1))
    result = poly_multiply(a, one)
    assert result.coeffs == [(c % Q) for c in range(1, N + 1)]


def test_poly_multiply_reduction():
    """x^255 * x = x^256 ≡ -1 mod (x^256 + 1), so it wraps with negation."""
    a = Poly([0] * 255 + [1])  # x^255
    b = Poly([0, 1] + [0] * (N - 2))  # x
    result = poly_multiply(a, b)
    # x^256 ≡ -1 mod (x^256+1)
    assert result.coeffs[0] == Q - 1  # -1 mod Q


# ============================================================================
# SAMPLING
# ============================================================================

@pytest.mark.parametrize("eta", [2, 3])
def test_cbd_range(eta):
    """CBD samples should be in [-eta, eta]."""
    import os
    noise = os.urandom(64 * eta)
    p = cbd(eta, noise)
    for c in p.coeffs:
        centered = c if c <= Q // 2 else c - Q
        assert -eta <= centered <= eta


def test_sample_ntt_deterministic():
    """Same seed + indices should produce same polynomial."""
    seed = b'\x00' * 32
    p1 = sample_ntt(seed, 0, 0)
    p2 = sample_ntt(seed, 0, 0)
    assert p1 == p2

    p3 = sample_ntt(seed, 0, 1)
    assert p3 != p1


# ============================================================================
# ENCODING / DECODING
# ============================================================================

@pytest.mark.parametrize("d", [1, 4, 10, 11, 12])
def test_encode_decode_roundtrip(d):
    """Encode then decode should recover original (for d-bit values)."""
    mask = (1 << d) - 1
    import os
    # For d < 12, values fit below Q. For d=12 (max 4095 > Q=3329), use Q-1 cap.
    max_val = min(mask, Q - 1)
    coeffs = [int.from_bytes(os.urandom(2), 'big') % (max_val + 1) for _ in range(N)]
    p = Poly(coeffs)
    encoded = encode_poly(p, d)
    decoded = decode_poly(encoded, d)
    assert decoded.coeffs == p.coeffs


# ============================================================================
# K-PKE (CPA-secure encryption)
# ============================================================================

@pytest.mark.parametrize("level", [512, 768, 1024])
def test_kpke_roundtrip(level):
    """K-PKE encrypt/decrypt roundtrip for all parameter sets."""
    params = PARAMS[level]
    pk, sk = kpke_keygen(params)

    msg = b'\xAB' * 32  # 256 bits
    r = b'\x42' * 32

    ct = kpke_encrypt(pk, msg, r, params)
    recovered = kpke_decrypt(sk, ct, params)
    assert recovered == msg


def test_kpke_different_messages():
    """Different messages produce different ciphertexts."""
    params = PARAMS[768]
    pk, sk = kpke_keygen(params)
    r = b'\x00' * 32

    msg1 = b'\x00' * 32
    msg2 = b'\xFF' * 32
    ct1 = kpke_encrypt(pk, msg1, r, params)
    ct2 = kpke_encrypt(pk, msg2, r, params)
    assert ct1 != ct2

    assert kpke_decrypt(sk, ct1, params) == msg1
    assert kpke_decrypt(sk, ct2, params) == msg2


# ============================================================================
# ML-KEM (CCA-secure KEM)
# ============================================================================

@pytest.mark.parametrize("level", [512, 768, 1024])
def test_ml_kem_roundtrip(level):
    """ML-KEM keygen -> encaps -> decaps roundtrip."""
    ek, dk = ml_kem_keygen(level)
    ct, K_encaps = ml_kem_encaps(ek, level)
    K_decaps = ml_kem_decaps(dk, ct, level)
    assert K_encaps == K_decaps
    assert len(K_encaps) == 32


def test_ml_kem_different_encapsulations():
    """Each encapsulation should produce a different shared secret."""
    ek, dk = ml_kem_keygen(768)
    ct1, K1 = ml_kem_encaps(ek, 768)
    ct2, K2 = ml_kem_encaps(ek, 768)
    assert K1 != K2
    assert ct1 != ct2
    assert ml_kem_decaps(dk, ct1, 768) == K1
    assert ml_kem_decaps(dk, ct2, 768) == K2


def test_ml_kem_implicit_rejection():
    """Tampered ciphertext should trigger implicit rejection (different key)."""
    ek, dk = ml_kem_keygen(768)
    ct, K = ml_kem_encaps(ek, 768)

    # Tamper with ciphertext
    ct_tampered = bytearray(ct)
    ct_tampered[0] ^= 0xFF
    K_rejected = ml_kem_decaps(dk, bytes(ct_tampered), 768)

    assert K_rejected != K  # Should get a different (pseudorandom) key
    assert len(K_rejected) == 32


def test_ml_kem_wrong_key():
    """Decapsulating with wrong private key should fail."""
    ek1, dk1 = ml_kem_keygen(768)
    _, dk2 = ml_kem_keygen(768)

    ct, K = ml_kem_encaps(ek1, 768)
    K_wrong = ml_kem_decaps(dk2, ct, 768)
    assert K_wrong != K


def test_ml_kem_invalid_level():
    with pytest.raises(ValueError):
        ml_kem_keygen(256)


# ============================================================================
# KEY SERIALIZATION (FIPS 203)
# ============================================================================

from ml_kem import (
    ml_kem_serialize_ek, ml_kem_deserialize_ek,
    ml_kem_serialize_dk, ml_kem_deserialize_dk,
    KEY_SIZES,
)


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_serialize_ek_roundtrip(level):
    """Public key serialization roundtrip."""
    ek, dk = ml_kem_keygen(level)
    data = ml_kem_serialize_ek(ek, level)
    assert len(data) == KEY_SIZES[level]['ek']
    ek2 = ml_kem_deserialize_ek(data, level)
    # Verify by encapsulating with deserialized key and decapsulating
    ct, K = ml_kem_encaps(ek2, level)
    K2 = ml_kem_decaps(dk, ct, level)
    assert K == K2


@pytest.mark.parametrize("level", [512, 768, 1024])
def test_serialize_dk_roundtrip(level):
    """Private key serialization roundtrip."""
    ek, dk = ml_kem_keygen(level)
    data = ml_kem_serialize_dk(dk, level)
    assert len(data) == KEY_SIZES[level]['dk']
    dk2 = ml_kem_deserialize_dk(data, level)
    # Verify by decapsulating with deserialized key
    ct, K = ml_kem_encaps(ek, level)
    K2 = ml_kem_decaps(dk2, ct, level)
    assert K == K2


def test_serialize_key_sizes():
    """Verify key sizes match FIPS 203 spec."""
    assert KEY_SIZES[512] == {'ek': 800, 'dk': 1632}
    assert KEY_SIZES[768] == {'ek': 1184, 'dk': 2400}
    assert KEY_SIZES[1024] == {'ek': 1568, 'dk': 3168}


def test_deserialize_invalid_length():
    """Wrong-length data should raise ValueError."""
    with pytest.raises(ValueError):
        ml_kem_deserialize_ek(b'\x00' * 100, 768)
    with pytest.raises(ValueError):
        ml_kem_deserialize_dk(b'\x00' * 100, 768)
