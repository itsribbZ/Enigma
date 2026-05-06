"""
Enigma Phase 1: Comprehensive tests for modular_math.py
Test vectors from: CLRS, FIPS 186-5, FIPS 197, RFC 3526, HoAC
"""
import pytest
from modular_math import (
    extended_gcd, mod_inverse, mod_exp, euler_totient, euler_totient_pq,
    carmichael_lambda, GFp, GF2n, build_aes_sbox, build_aes_inv_sbox,
    legendre_symbol, jacobi_symbol, miller_rabin, generate_prime,
    crt_two, crt_general, rsa_crt_decrypt, tonelli_shanks, pollard_rho,
    full_factorization, SMALL_PRIMES,
)


# ============================================================================
# 1. EXTENDED GCD
# ============================================================================

@pytest.mark.parametrize("a,b,exp_g,exp_x,exp_y", [
    (240, 46, 2, -9, 47),
    (35, 15, 5, 1, -2),
    (99, 78, 3, -11, 14),
    (3, 11, 1, 4, -1),
    (17, 3120, 1, -367, 2),
    (0, 5, 5, 0, 1),
    (1, 0, 1, 1, 0),
])
def test_extended_gcd(a, b, exp_g, exp_x, exp_y):
    g, x, y = extended_gcd(a, b)
    assert g == exp_g
    assert a * x + b * y == g


@pytest.mark.parametrize("a,b", [(-6, 4), (6, -4), (-6, -4), (-240, 46), (17, -3120)])
def test_extended_gcd_negative_inputs(a, b):
    g, x, y = extended_gcd(a, b)
    assert g >= 0
    assert a * x + b * y == g


# ============================================================================
# 2. MODULAR INVERSE
# ============================================================================

@pytest.mark.parametrize("a,m,expected", [
    (3, 11, 4),
    (17, 3120, 2753),
    (7, 40, 23),
    (42, 2017, 1969),
])
def test_mod_inverse(a, m, expected):
    result = mod_inverse(a, m)
    assert result == expected
    assert (a * result) % m == 1


def test_mod_inverse_no_inverse():
    with pytest.raises(ValueError):
        mod_inverse(6, 12)


# ============================================================================
# 3. MODULAR EXPONENTIATION
# ============================================================================

@pytest.mark.parametrize("base,exp,mod,expected", [
    (4, 13, 497, 445),
    (2, 10, 1000, 24),
    (3, 644, 645, 36),
    (2, 0, 100, 1),
    (123, 1, 1000, 123),
    (5, 3, 13, 8),
    (7, 12, 13, 1),
    (2, 16, 65537, 65536),
    (0, 0, 5, 1),
    (0, 5, 7, 0),
])
def test_mod_exp(base, exp, mod, expected):
    result = mod_exp(base, exp, mod)
    assert result == expected
    assert result == pow(base, exp, mod)


# ============================================================================
# 4. EULER'S TOTIENT
# ============================================================================

@pytest.mark.parametrize("n,expected", [
    (1, 1), (2, 1), (7, 6), (10, 4), (12, 4),
    (15, 8), (100, 40), (97, 96), (3233, 3120),
])
def test_euler_totient(n, expected):
    assert euler_totient(n) == expected


def test_euler_totient_rsa_shortcuts():
    assert euler_totient_pq(61, 53) == 3120
    assert carmichael_lambda(61, 53) == (60 * 52) // 4


# ============================================================================
# 5. GF(p) CLASS
# ============================================================================

def test_gfp():
    p = 7
    a, b = GFp(3, p), GFp(5, p)

    assert a + b == GFp(1, p)
    assert a - b == GFp(5, p)
    assert a * b == GFp(1, p)
    assert a.inverse() == GFp(5, p)
    assert a ** 3 == GFp(6, p)
    assert GFp(4, p).inverse() == GFp(2, p)
    assert a / GFp(4, p) == GFp(6, p)

    assert not GFp(0, p)
    assert GFp(1, p)

    with pytest.raises(ZeroDivisionError):
        GFp(0, p).inverse()

    p256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = GFp(7, p256)
    assert x * x.inverse() == GFp(1, p256)


# ============================================================================
# 6. GF(2^8) CLASS
# ============================================================================

def test_gf2n():
    a = GF2n(0x57)
    b = GF2n(0x83)

    assert a + b == GF2n(0xD4)
    assert a - b == GF2n(0xD4)
    assert a * b == GF2n(0xC1)
    assert a * GF2n(0x01) == a
    assert a * GF2n(0x00) == GF2n(0x00)

    assert GF2n(0x57).xtime() == GF2n(0xAE)
    assert GF2n(0xAE).xtime() == GF2n(0x47)
    assert GF2n(0x47).xtime() == GF2n(0x8E)
    assert GF2n(0x8E).xtime() == GF2n(0x07)

    assert GF2n(0x02).inverse().value == 0x8D
    assert GF2n(0x03).inverse().value == 0xF6

    for val in [0x01, 0x02, 0x03, 0x53, 0xFF, 0x0F, 0x80]:
        elem = GF2n(val)
        assert (elem * elem.inverse()).value == 1

    mismatches = 0
    for val in range(1, 256):
        elem = GF2n(val)
        if elem.inverse() != elem.inverse_euclidean():
            mismatches += 1
    assert mismatches == 0

    exp_table, log_table = GF2n.generate_tables()
    assert exp_table[0] == 0x01
    assert exp_table[1] == 0x03
    assert exp_table[25] == 0x02


# ============================================================================
# 6b. AES S-BOX
# ============================================================================

def test_aes_sbox():
    sbox = build_aes_sbox()
    expected = {0x00: 0x63, 0x01: 0x7C, 0x02: 0x77, 0x03: 0x7B, 0x53: 0xED, 0xFF: 0x16}
    for inp, out in expected.items():
        assert sbox[inp] == out

    inv_sbox = build_aes_inv_sbox(sbox)
    for i in range(256):
        assert inv_sbox[sbox[i]] == i


# ============================================================================
# 7. LEGENDRE & JACOBI SYMBOLS
# ============================================================================

@pytest.mark.parametrize("a,p,expected", [
    (2, 7, 1), (5, 7, -1), (3, 7, -1), (4, 7, 1), (0, 7, 0),
    (2, 11, -1), (3, 11, 1), (10, 13, 1),
])
def test_legendre_symbol(a, p, expected):
    assert legendre_symbol(a, p) == expected


def test_jacobi_symbol():
    assert jacobi_symbol(2, 15) == 1
    assert jacobi_symbol(3, 35) == 1

    for a, p, expected in [(2, 7, 1), (5, 7, -1), (3, 7, -1), (4, 7, 1), (0, 7, 0)]:
        assert jacobi_symbol(a, p) == expected


# ============================================================================
# 8. MILLER-RABIN
# ============================================================================

@pytest.mark.parametrize("p", [2, 3, 5, 7, 11, 13, 97, 2147483647, 2305843009213693951])
def test_miller_rabin_primes(p):
    assert miller_rabin(p)


@pytest.mark.parametrize("c", [0, 1, 4, 6, 8, 9, 15, 100, 1000])
def test_miller_rabin_composites(c):
    assert not miller_rabin(c)


@pytest.mark.parametrize("c", [561, 1105, 1729])
def test_miller_rabin_carmichaels(c):
    assert not miller_rabin(c)


# ============================================================================
# 9. PRIME GENERATION
# ============================================================================

@pytest.mark.parametrize("bits", [32, 64, 128, 256])
def test_generate_prime(bits):
    p = generate_prime(bits)
    assert p.bit_length() == bits
    assert miller_rabin(p)


def test_generate_safe_prime():
    sp = generate_prime(32, safe=True)
    assert miller_rabin(sp)
    assert miller_rabin((sp - 1) // 2)


# ============================================================================
# 10. CRT
# ============================================================================

@pytest.mark.parametrize("rems,mods,exp_sol,exp_mod", [
    ([2, 3, 2], [3, 5, 7], 23, 105),
    ([1, 2, 3], [2, 3, 5], 23, 30),
    ([3, 1], [5, 7], 8, 35),
    ([0, 3, 4], [3, 4, 5], 39, 60),
    ([2, 3], [3, 5], 8, 15),
])
def test_crt(rems, mods, exp_sol, exp_mod):
    sol, mod = crt_general(rems, mods)
    assert sol == exp_sol
    assert mod == exp_mod
    for r, m in zip(rems, mods):
        assert sol % m == r % m


# ============================================================================
# 10b. RSA END-TO-END
# ============================================================================

def test_rsa_end_to_end():
    p, q = 61, 53
    n = p * q
    e = 17
    phi_n = euler_totient_pq(p, q)
    d = mod_inverse(e, phi_n)

    assert n == 3233
    assert phi_n == 3120
    assert d == 2753

    plaintext = 65
    ciphertext = mod_exp(plaintext, e, n)
    assert ciphertext == 2790

    decrypted = mod_exp(ciphertext, d, n)
    assert decrypted == plaintext

    crt_decrypted = rsa_crt_decrypt(ciphertext, d, p, q)
    assert crt_decrypted == plaintext


# ============================================================================
# 11. TONELLI-SHANKS
# ============================================================================

@pytest.mark.parametrize("a,p,expected", [
    (10, 13, 6), (56, 101, 37), (2, 7, 3), (4, 7, 2),
    (2, 17, 6), (3, 11, 5), (44, 97, 23),
])
def test_tonelli_shanks(a, p, expected):
    r = tonelli_shanks(a, p)
    assert r == expected
    assert (r * r) % p == a % p


def test_tonelli_shanks_non_qr():
    with pytest.raises(ValueError):
        tonelli_shanks(5, 7)


# ============================================================================
# 12. FACTORIZATION
# ============================================================================

@pytest.mark.parametrize("n,expected", [
    (15, [3, 5]),
    (91, [7, 13]),
    (561, [3, 11, 17]),
    (1729, [7, 13, 19]),
    (100, [2, 2, 5, 5]),
    (2 * 3 * 5 * 7 * 11, [2, 3, 5, 7, 11]),
])
def test_factorization(n, expected):
    factors = full_factorization(n)
    assert factors == expected
    product = 1
    for f in factors:
        product *= f
    assert product == n


def test_factorization_semiprime():
    sp = 10007 * 10009
    factors = full_factorization(sp)
    assert sorted(factors) == [10007, 10009]
