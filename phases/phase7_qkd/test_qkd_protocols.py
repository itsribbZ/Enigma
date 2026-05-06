"""
Enigma Phase 7: QKD Protocols test suite.
Tests BB84, E91, QRNG, and hybrid analysis.
"""
import pytest
from qkd_protocols import (
    qrng_bits, qrng_bytes,
    bb84_simulate, BB84Result,
    e91_simulate, E91Result,
    hybrid_qkd_pqc_analysis,
)


def test_qrng_bits():
    bits = qrng_bits(1000)
    assert len(bits) == 1000
    assert all(b in (0, 1) for b in bits)
    ratio = sum(bits) / len(bits)
    assert 0.4 < ratio < 0.6


def test_qrng_bytes():
    data = qrng_bytes(16)
    assert len(data) == 16
    assert isinstance(data, bytes)
    assert len(set(data)) > 1


@pytest.mark.slow
def test_bb84_no_eve():
    result = bb84_simulate(n_qubits=200, eve_present=False)
    assert result.qber < 0.05
    assert not result.eavesdropper_detected
    assert result.key_length > 0
    assert len(result.matching_indices) > 0

    errors = sum(1 for a, b in zip(result.sifted_key_alice, result.sifted_key_bob) if a != b)
    error_rate = errors / len(result.sifted_key_alice) if result.sifted_key_alice else 0
    assert error_rate < 0.05


@pytest.mark.slow
def test_bb84_with_eve():
    result = bb84_simulate(n_qubits=500, eve_present=True)
    assert result.qber > 0.10
    assert result.eavesdropper_detected
    assert result.eavesdropper_present


@pytest.mark.slow
def test_bb84_sifting():
    result = bb84_simulate(n_qubits=1000, eve_present=False)
    sift_ratio = len(result.matching_indices) / result.n_qubits
    assert 0.35 < sift_ratio < 0.65


@pytest.mark.slow
def test_e91():
    result = e91_simulate(n_pairs=500)
    assert result.key_length > 0
    assert result.chsh_value > 2.0


@pytest.mark.slow
def test_e91_key_generation():
    result = e91_simulate(n_pairs=200)
    assert result.key_length > 0
    assert all(b in (0, 1) for b in result.sifted_key)


def test_hybrid_analysis():
    analysis = hybrid_qkd_pqc_analysis()
    assert 'HYBRID' in analysis
    assert 'QKD' in analysis
    assert 'PQC' in analysis
    assert 'ML-KEM' in analysis
    assert 'BB84' in analysis or 'E91' in analysis
    assert 'Tier 1' in analysis
    assert 'Tier 3' in analysis
