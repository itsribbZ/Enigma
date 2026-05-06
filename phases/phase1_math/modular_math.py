"""
Enigma Phase 1: modular_math.py
Cryptographic math primitives built from scratch (no library wrappers).

Dependency order:
  1. extended_gcd → 2. mod_inverse → 3. mod_exp → 4. euler_totient
  5. GFp class → 6. GF2n class → 7. legendre/jacobi → 8. miller_rabin
  9. generate_prime → 10. CRT → 11. tonelli_shanks → 12. pollard_rho

All implementations from: CLRS, Handbook of Applied Cryptography, FIPS 186-5,
FIPS 197 (AES), RFC 3526, Sorenson & Webster 2015.
"""

from __future__ import annotations
import math
import os
import secrets
from typing import List, Tuple

# ============================================================================
# 1. EXTENDED EUCLIDEAN ALGORITHM
# ============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (gcd, x, y) such that a*x + b*y = gcd(a, b).

    Always returns non-negative gcd. Iterative to avoid stack overflow.
    """
    sign_a = 1 if a >= 0 else -1
    sign_b = 1 if b >= 0 else -1
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s * sign_a, old_t * sign_b


# ============================================================================
# 2. MODULAR INVERSE
# ============================================================================

def mod_inverse(a: int, m: int) -> int:
    """Return modular inverse of a modulo m.

    Raises ValueError if gcd(a, m) != 1 (inverse does not exist).
    Always returns a value in [0, m).
    """
    if m <= 0:
        raise ValueError(f"Modulus must be positive, got {m}")
    a_reduced = a % m
    g, x, _ = extended_gcd(a_reduced, m)
    if g != 1:
        raise ValueError(
            f"Modular inverse does not exist: gcd({a}, {m}) = {g}"
        )
    return x % m


# ============================================================================
# 3. MODULAR EXPONENTIATION (Square-and-Multiply)
# ============================================================================

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Compute base^exp mod mod using binary square-and-multiply. O(log exp).

    WARNING: This is NOT constant-time (educational implementation).
    For secret exponents, use Python's built-in pow(base, exp, mod).
    rsa_crt_decrypt() also does NOT implement blinding — it is educational.
    """
    if mod <= 0:
        raise ValueError(f"Modulus must be positive, got {mod}")
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("Negative exponent not supported directly")
    # Use Python's built-in pow for correctness and better constant-time behavior
    return pow(base, exp, mod)


# ============================================================================
# 4. EULER'S TOTIENT
# ============================================================================

def euler_totient(n: int) -> int:
    """Compute Euler's totient phi(n) via trial division."""
    if n <= 0:
        raise ValueError(f"n must be positive, got {n}")
    if n == 1:
        return 1
    result = n
    temp = n
    p = 2
    while p * p <= temp:
        if temp % p == 0:
            while temp % p == 0:
                temp //= p
            result -= result // p
        p += 1
    if temp > 1:
        result -= result // temp
    return result


def euler_totient_pq(p: int, q: int) -> int:
    """Compute phi(p*q) = (p-1)*(q-1) for distinct primes p, q (RSA)."""
    return (p - 1) * (q - 1)


def carmichael_lambda(p: int, q: int) -> int:
    """Compute lambda(p*q) = lcm(p-1, q-1) for RSA (FIPS 186-4 preferred)."""
    return (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)


# ============================================================================
# 5. PRIME FIELD GF(p)
# ============================================================================

class GFp:
    """Element of the prime field GF(p) with full operator overloading."""

    def __init__(self, value: int, p: int):
        if not isinstance(p, int) or p < 2:
            raise ValueError(f"p must be an integer >= 2, got {p}")
        self.p = p
        self.value = value % p

    def _check_field(self, other: GFp) -> None:
        if not isinstance(other, GFp) or self.p != other.p:
            raise TypeError("Cannot operate on elements from different fields")

    def __add__(self, other: GFp) -> GFp:
        self._check_field(other)
        return GFp((self.value + other.value) % self.p, self.p)

    def __sub__(self, other: GFp) -> GFp:
        self._check_field(other)
        return GFp((self.value - other.value) % self.p, self.p)

    def __mul__(self, other: GFp) -> GFp:
        self._check_field(other)
        return GFp((self.value * other.value) % self.p, self.p)

    def __truediv__(self, other: GFp) -> GFp:
        self._check_field(other)
        return self * other.inverse()

    def __pow__(self, exp: int) -> GFp:
        if not isinstance(exp, int):
            raise TypeError("Exponent must be an integer")
        if exp < 0:
            return self.inverse() ** (-exp)
        return GFp(pow(self.value, exp, self.p), self.p)

    def __neg__(self) -> GFp:
        return GFp((-self.value) % self.p, self.p)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GFp):
            return self.value == other.value and self.p == other.p
        if isinstance(other, int):
            return self.value == other % self.p
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.value, self.p))

    def __bool__(self) -> bool:
        return self.value != 0

    def __repr__(self) -> str:
        return f"GFp({self.value}, {self.p})"

    def __str__(self) -> str:
        return str(self.value)

    def __int__(self) -> int:
        return self.value

    def inverse(self) -> GFp:
        """Multiplicative inverse via Extended GCD."""
        if self.value == 0:
            raise ZeroDivisionError("Zero has no multiplicative inverse in GF(p)")
        g, x, _ = extended_gcd(self.value, self.p)
        if g != 1:
            raise ValueError(f"Inverse does not exist (p={self.p} may not be prime)")
        return GFp(x % self.p, self.p)


# ============================================================================
# 6. EXTENSION FIELD GF(2^n) — Default: AES GF(2^8)
# ============================================================================

class GF2n:
    """Element of GF(2^n). Polynomials over GF(2) as integers (bit i = coeff of x^i).

    Default: GF(2^8) with AES irreducible x^8 + x^4 + x^3 + x + 1 (0x11B).
    """

    AES_IRREDUCIBLE = 0x11B
    AES_N = 8

    def __init__(self, value: int, irreducible: int = 0x11B, n: int = 8):
        self.n = n
        self.irreducible = irreducible
        self.mask = (1 << n) - 1
        self.value = value & self.mask

    def _check_field(self, other: GF2n) -> None:
        if not isinstance(other, GF2n):
            raise TypeError(f"Expected GF2n, got {type(other)}")
        if self.irreducible != other.irreducible or self.n != other.n:
            raise TypeError("Cannot operate on elements from different fields")

    def __add__(self, other: GF2n) -> GF2n:
        self._check_field(other)
        return GF2n(self.value ^ other.value, self.irreducible, self.n)

    def __sub__(self, other: GF2n) -> GF2n:
        return self.__add__(other)  # In GF(2^n), addition = subtraction = XOR

    def __mul__(self, other: GF2n) -> GF2n:
        self._check_field(other)
        result = self._poly_mul_mod(self.value, other.value, self.irreducible, self.n)
        return GF2n(result, self.irreducible, self.n)

    def __truediv__(self, other: GF2n) -> GF2n:
        self._check_field(other)
        return self * other.inverse()

    def __pow__(self, exp: int) -> GF2n:
        if not isinstance(exp, int):
            raise TypeError("Exponent must be an integer")
        if exp < 0:
            return self.inverse() ** (-exp)
        if exp == 0:
            return GF2n(1, self.irreducible, self.n)
        result = GF2n(1, self.irreducible, self.n)
        base = GF2n(self.value, self.irreducible, self.n)
        e = exp
        while e > 0:
            if e & 1:
                result = result * base
            base = base * base
            e >>= 1
        return result

    def __neg__(self) -> GF2n:
        return GF2n(self.value, self.irreducible, self.n)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, GF2n):
            return (self.value == other.value and
                    self.irreducible == other.irreducible and
                    self.n == other.n)
        if isinstance(other, int):
            return self.value == (other & self.mask)
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.value, self.irreducible, self.n))

    def __bool__(self) -> bool:
        return self.value != 0

    def __repr__(self) -> str:
        return f"GF2n(0x{self.value:0{(self.n + 3) // 4}X}, 0x{self.irreducible:X}, {self.n})"

    def __str__(self) -> str:
        return f"0x{self.value:0{(self.n + 3) // 4}X}"

    def __int__(self) -> int:
        return self.value

    @staticmethod
    def _poly_mul_unreduced(a: int, b: int) -> int:
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            b >>= 1
        return result

    @staticmethod
    def _poly_mod(dividend: int, modulus: int) -> int:
        deg_mod = modulus.bit_length() - 1
        while True:
            deg_div = dividend.bit_length() - 1
            if deg_div < deg_mod:
                break
            dividend ^= modulus << (deg_div - deg_mod)
        return dividend

    @staticmethod
    def _poly_mul_mod(a: int, b: int, modulus: int, n: int) -> int:
        product = GF2n._poly_mul_unreduced(a, b)
        return GF2n._poly_mod(product, modulus)

    def inverse(self) -> GF2n:
        """Multiplicative inverse via Fermat: a^(-1) = a^(2^n - 2)."""
        if self.value == 0:
            raise ZeroDivisionError("Zero has no multiplicative inverse")
        return self ** ((1 << self.n) - 2)

    def inverse_euclidean(self) -> GF2n:
        """Multiplicative inverse via polynomial Extended GCD."""
        if self.value == 0:
            raise ZeroDivisionError("Zero has no multiplicative inverse")
        old_r, r = self.value, self.irreducible
        old_s, s = 1, 0
        while r != 0:
            deg_old = old_r.bit_length() - 1
            deg_r = r.bit_length() - 1
            if deg_old < deg_r:
                old_r, r = r, old_r
                old_s, s = s, old_s
                continue
            shift = deg_old - deg_r
            old_r ^= r << shift
            old_s ^= s << shift
        if old_r != 1:
            raise ValueError(f"Element is not invertible (GCD={old_r}, expected 1)")
        return GF2n(old_s & self.mask, self.irreducible, self.n)

    def xtime(self) -> GF2n:
        """Multiply by x (0x02) in GF(2^8). Core AES MixColumns operation."""
        assert self.n == 8, "xtime is defined for GF(2^8)"
        result = self.value << 1
        if result & 0x100:
            result ^= self.irreducible
        return GF2n(result & 0xFF, self.irreducible, self.n)

    @classmethod
    def generate_tables(cls, generator: int = 0x03,
                        irreducible: int = 0x11B, n: int = 8
                        ) -> Tuple[List[int], List[int]]:
        """Generate exp/log tables for fast multiplication."""
        order = (1 << n) - 1
        exp_table = [0] * (order + 1)
        log_table = [0] * (1 << n)
        x = 1
        for i in range(order):
            exp_table[i] = x
            log_table[x] = i
            x = cls._poly_mul_mod(x, generator, irreducible, n)
        exp_table[order] = exp_table[0]
        return exp_table, log_table


def build_aes_sbox() -> List[int]:
    """Build the AES S-Box from GF(2^8) inversion + affine transform."""
    sbox = [0] * 256
    for i in range(256):
        b = 0 if i == 0 else GF2n(i).inverse().value
        s = b
        for shift in [1, 2, 3, 4]:
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        s ^= 0x63
        sbox[i] = s & 0xFF
    return sbox


def build_aes_inv_sbox(sbox: List[int]) -> List[int]:
    """Build the AES inverse S-Box."""
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox


# ============================================================================
# 7. LEGENDRE & JACOBI SYMBOLS
# ============================================================================

def legendre_symbol(a: int, p: int) -> int:
    """Compute Legendre symbol (a/p) via Euler's criterion. p must be odd prime."""
    if p == 2:
        raise ValueError("p must be an odd prime")
    result = pow(a, (p - 1) // 2, p)
    if result == p - 1:
        return -1
    return result  # 0 or 1


def jacobi_symbol(a: int, n: int) -> int:
    """Compute Jacobi symbol (a/n). n must be positive odd integer."""
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")
    a = a % n
    result = 1
    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a = a % n
    if n == 1:
        return result
    return 0


# ============================================================================
# 8. MILLER-RABIN PRIMALITY TEST
# ============================================================================

# Deterministic witnesses for n < 3.3×10^24 (Sorenson & Webster 2015)
_DETERMINISTIC_WITNESSES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def _decompose(n: int) -> Tuple[int, int]:
    """Write n-1 as 2^s * d where d is odd. Returns (s, d)."""
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def _is_witness(a: int, n: int, s: int, d: int) -> bool:
    """Check if a is a witness to n being composite."""
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False
    return True


def miller_rabin(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test.

    For n < 3.3×10^24: deterministic (uses fixed witness set).
    For larger n: probabilistic with error ≤ 4^(-k).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    s, d = _decompose(n)

    # Deterministic for small n
    if n < 3_317_044_064_679_887_385_961_981:
        for a in _DETERMINISTIC_WITNESSES:
            if a >= n:
                continue
            if _is_witness(a, n, s, d):
                return False
        return True

    # Probabilistic for very large n — use CSPRNG for witness selection
    for _ in range(k):
        a = int.from_bytes(os.urandom(max(1, (n.bit_length() + 7) // 8)), 'big')
        a = a % (n - 3) + 2  # Map to range [2, n-2]
        if _is_witness(a, n, s, d):
            return False
    return True


# ============================================================================
# 9. PRIME GENERATION
# ============================================================================

SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
    317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
    419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
    503, 509, 521, 523, 541,
]


def _trial_division_prescreen(n: int) -> bool:
    """Quick check against first 100 primes. Returns False if definitely composite."""
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True


def generate_prime(bits: int, safe: bool = False) -> int:
    """Generate a random prime of given bit length using CSPRNG + Miller-Rabin.

    Args:
        bits: Bit length of the prime (must be >= 2).
        safe: If True, generate a safe prime p where (p-1)/2 is also prime.
    """
    if bits < 2:
        raise ValueError("Bit length must be >= 2")
    if safe:
        return _generate_safe_prime(bits)
    while True:
        n = int.from_bytes(os.urandom((bits + 7) // 8), "big")
        n |= (1 << (bits - 1))  # Ensure high bit set (correct bit length)
        n |= 1                   # Ensure odd
        n &= (1 << bits) - 1     # Mask to exact bit length
        n |= (1 << (bits - 1))   # Re-set high bit after mask
        if _trial_division_prescreen(n) and miller_rabin(n, k=40):
            return n


def _generate_safe_prime(bits: int) -> int:
    """Generate safe prime p = 2q + 1 where q is also prime."""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if p.bit_length() == bits and miller_rabin(p, k=40):
            return p


# ============================================================================
# 10. CHINESE REMAINDER THEOREM
# ============================================================================

def crt_two(r1: int, m1: int, r2: int, m2: int) -> Tuple[int, int]:
    """Solve x ≡ r1 (mod m1), x ≡ r2 (mod m2). Returns (solution, lcm(m1,m2))."""
    g, p, _ = extended_gcd(m1, m2)
    if (r2 - r1) % g != 0:
        raise ValueError(f"No solution: {r2}-{r1}={r2 - r1} not divisible by gcd={g}")
    lcm = m1 // g * m2
    solution = (r1 + m1 * ((r2 - r1) // g) * p) % lcm
    return solution, lcm


def crt_general(remainders: List[int], moduli: List[int]) -> Tuple[int, int]:
    """Solve system x ≡ r_i (mod m_i) for all i. Returns (solution, combined_modulus)."""
    if len(remainders) != len(moduli):
        raise ValueError("remainders and moduli must have same length")
    if len(remainders) == 0:
        raise ValueError("Empty input")
    cur_r, cur_m = remainders[0], moduli[0]
    for i in range(1, len(remainders)):
        cur_r, cur_m = crt_two(cur_r, cur_m, remainders[i], moduli[i])
    return cur_r, cur_m


def rsa_crt_decrypt(c: int, d: int, p: int, q: int) -> int:
    """RSA decryption using CRT (~4x faster for 2048-bit keys)."""
    dp = d % (p - 1)
    dq = d % (q - 1)
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    q_inv = mod_inverse(q, p)
    h = (q_inv * (m1 - m2)) % p
    return (m2 + h * q) % (p * q)


# ============================================================================
# 11. TONELLI-SHANKS (Modular Square Root)
# ============================================================================

def tonelli_shanks(a: int, p: int) -> int:
    """Find r such that r^2 ≡ a (mod p), p odd prime. Returns smaller root."""
    if p == 2:
        return a % 2
    if a % p == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise ValueError(f"{a} is not a quadratic residue mod {p}")

    # Fast path: p ≡ 3 (mod 4)
    if p % 4 == 3:
        r = pow(a, (p + 1) // 4, p)
        return min(r, p - r)

    # General case
    Q, S = p - 1, 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(a, Q, p)
    R = pow(a, (Q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return min(R, p - R)
        i = 1
        temp = (t * t) % p
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
        b = c
        for _ in range(M - i - 1):
            b = (b * b) % p
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p


# ============================================================================
# 12. FACTORIZATION (Pollard's Rho)
# ============================================================================

def pollard_rho(n: int) -> int:
    """Find a non-trivial factor of n using Pollard's rho. O(n^(1/4)) expected."""
    if n <= 1:
        raise ValueError(f"n must be > 1, got {n}")
    if n % 2 == 0:
        return 2
    while True:
        x = secrets.randbelow(n - 2) + 2  # [2, n-1]
        y = x
        c = secrets.randbelow(n - 1) + 1  # [1, n-1]
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def full_factorization(n: int) -> List[int]:
    """Fully factor n into primes using trial division + Pollard's rho."""
    if n <= 1:
        return []
    factors = []
    # Trial division with small primes
    for p in SMALL_PRIMES:
        while n % p == 0:
            factors.append(p)
            n //= p
    if n == 1:
        return sorted(factors)
    # Pollard's rho for remaining factors
    stack = [n]
    while stack:
        num = stack.pop()
        if num == 1:
            continue
        if miller_rabin(num):
            factors.append(num)
            continue
        d = pollard_rho(num)
        stack.append(d)
        stack.append(num // d)
    return sorted(factors)
