"""
Enigma Phase 5: PQC test suite.
Tests LWE encryption, benchmarks, and migration guide.
"""
import pytest
import numpy as np
from pqc_lattice import (
    LWEEncrypt, cbd_sample, cbd_vector,
    benchmark_lwe, run_benchmarks,
    generate_migration_guide, MIGRATION_TABLE,
)


@pytest.mark.parametrize("eta", [1, 2, 3])
def test_cbd_distribution(eta):
    samples = [cbd_sample(eta) for _ in range(1000)]
    assert all(-eta <= s <= eta for s in samples)
    mean = sum(samples) / len(samples)
    assert abs(mean) < 0.5


def test_lwe_single_bit():
    lwe = LWEEncrypt(n=64, m=128, q=3329, eta=2)
    pub, sec = lwe.keygen()

    correct = 0
    trials = 50
    for _ in range(trials):
        for bit in [0, 1]:
            ct = lwe.encrypt_bit(pub, bit)
            if lwe.decrypt_bit(sec, ct) == bit:
                correct += 1

    assert correct / (trials * 2) > 0.95


def test_lwe_bytes():
    lwe = LWEEncrypt(n=64, m=128, q=3329, eta=2)
    pub, sec = lwe.keygen()
    msg = b"Hi"
    assert lwe.decrypt_bytes(sec, lwe.encrypt_bytes(pub, msg)) == msg


def test_lwe_different_keys():
    lwe = LWEEncrypt(n=64, m=128, q=3329, eta=2)
    pub1, sec1 = lwe.keygen()
    _, sec2 = lwe.keygen()

    wrong_count = sum(
        1 for _ in range(20)
        if lwe.decrypt_bit(sec2, lwe.encrypt_bit(pub1, 1)) != 1
    )
    assert wrong_count > 5


def test_lwe_probabilistic():
    lwe = LWEEncrypt(n=64, m=128, q=3329, eta=2)
    pub, sec = lwe.keygen()
    ct1 = lwe.encrypt_bit(pub, 0)
    ct2 = lwe.encrypt_bit(pub, 0)
    assert not np.array_equal(ct1[0], ct2[0])


@pytest.mark.parametrize("n,m,q", [(32, 64, 97), (64, 128, 3329), (128, 256, 3329)])
def test_lwe_parameters(n, m, q):
    lwe = LWEEncrypt(n=n, m=m, q=q, eta=2)
    pub, sec = lwe.keygen()
    correct = sum(
        1 for _ in range(20)
        if lwe.decrypt_bit(sec, lwe.encrypt_bit(pub, np.random.randint(0, 2))) == lwe.decrypt_bit(sec, lwe.encrypt_bit(pub, 0)) or True
    )
    # Simpler: just test encrypt/decrypt works
    pub, sec = lwe.keygen()
    correct = 0
    for _ in range(20):
        bit = np.random.randint(0, 2)
        ct = lwe.encrypt_bit(pub, bit)
        if lwe.decrypt_bit(sec, ct) == bit:
            correct += 1
    assert correct >= 16


def test_benchmark_lwe():
    results = benchmark_lwe(iterations=3)
    assert len(results) == 3
    for r in results:
        assert r.mean_ms > 0


def test_full_benchmark():
    report = run_benchmarks()
    assert "PQC BENCHMARK SUITE" in report
    assert "LWE" in report
    assert "RSA" in report
    assert "ECDH" in report
    assert "ML-KEM-768" in report


def test_migration_table():
    protocols = {m.protocol for m in MIGRATION_TABLE}
    assert 'TLS 1.3' in protocols
    assert 'SSH' in protocols
    assert 'IPsec/IKEv2' in protocols
    assert len([m for m in MIGRATION_TABLE if 'CRITICAL' in m.priority]) >= 3


def test_migration_guide():
    guide = generate_migration_guide("Enigma Corp")
    assert "Enigma Corp" in guide
    assert "FIPS 203" in guide
    assert "ML-KEM" in guide
    assert "ML-DSA" in guide
    assert "Phase 1" in guide
    assert "Phase 5" in guide
