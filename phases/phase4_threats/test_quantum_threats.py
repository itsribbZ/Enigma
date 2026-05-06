"""
Enigma Phase 4: Quantum Threat Model test suite.
Tests Shor's factoring, Grover's search, and threat assessment.
"""
import pytest
from quantum_threats import (
    shor_factor, shor_demo_n15, shor_extract_factors, shor_circuit_n15,
    _classical_order, _is_perfect_power,
    grover_search, grover_demo,
    moscas_inequality, generate_threat_report,
    SECURITY_TABLE, CryptoSecurityLevel,
)
from quantum_circuits import run_counts


def test_classical_order():
    assert _classical_order(7, 15) == 4
    assert _classical_order(2, 15) == 4
    assert _classical_order(4, 15) == 2
    assert _classical_order(11, 15) == 2
    assert _classical_order(2, 21) == 6


def test_perfect_power():
    assert _is_perfect_power(4) == 2
    assert _is_perfect_power(8) == 2
    assert _is_perfect_power(27) == 3
    assert _is_perfect_power(15) is None
    assert _is_perfect_power(21) is None


@pytest.mark.parametrize("N,expected_factors", [
    (15, {3, 5}), (21, {3, 7}), (35, {5, 7}), (77, {7, 11}), (91, {7, 13}),
])
def test_shor_factor_small(N, expected_factors):
    result = shor_factor(N)
    assert result is not None
    p, q = result
    assert p * q == N
    assert {p, q} == expected_factors


def test_shor_factor_extraction():
    factors = shor_extract_factors(15, 7, 4)
    assert factors is not None
    assert set(factors) == {3, 5}

    factors2 = shor_extract_factors(21, 2, 6)
    assert factors2 is not None
    assert set(factors2) == {3, 7}

    assert shor_extract_factors(15, 2, 3) is None


@pytest.mark.slow
def test_shor_circuit_n15():
    qc, info = shor_circuit_n15(a=7)
    counts = run_counts(qc, shots=1000)
    valid_outcomes = {'0000', '0100', '1000', '1100'}
    total_valid = sum(counts.get(o, 0) for o in valid_outcomes)
    assert total_valid > 400


@pytest.mark.slow
def test_shor_demo():
    result = shor_demo_n15()
    assert result['N'] == 15
    assert result['factors'] is not None
    p, q = result['factors']
    assert p * q == 15
    assert {p, q} == {3, 5}


@pytest.mark.slow
@pytest.mark.parametrize("target", ['00', '01', '10', '11'])
def test_grover_2qubit(target):
    counts = run_counts(grover_search(2, target), shots=500)
    assert counts.get(target, 0) > 400


@pytest.mark.slow
def test_grover_3qubit():
    result = grover_demo(3, '101')
    assert result['success_rate'] > 0.8
    assert result['search_space'] == 8


def test_moscas_inequality():
    urgent = moscas_inequality(30, 5, 15)
    assert urgent['is_urgent']
    assert 'NOW' in urgent['recommendation']

    safe = moscas_inequality(5, 2, 15)
    assert not safe['is_urgent']
    assert safe['margin_years'] == 8


def test_security_table():
    broken = [e for e in SECURITY_TABLE if e.status == 'BROKEN']
    safe = [e for e in SECURITY_TABLE if e.status == 'SAFE']
    weakened = [e for e in SECURITY_TABLE if e.status == 'WEAKENED']

    assert len(broken) >= 7
    assert len(safe) >= 6
    assert len(weakened) >= 1

    for entry in broken:
        assert entry.quantum_bits == 0

    aes256 = [e for e in SECURITY_TABLE if 'AES-256' in e.algorithm][0]
    assert aes256.quantum_bits == 128
    assert aes256.status == 'SAFE'


def test_threat_report():
    report = generate_threat_report("Test Corp", 10, 3, 15)
    assert "QUANTUM THREAT ASSESSMENT" in report
    assert "Test Corp" in report
    assert "RSA" in report
    assert "AES-256" in report
