"""
Enigma Phase 3: Quantum Circuits test suite.
Verifies all 10 circuits, teleportation, and QFT.
"""
import numpy as np
import pytest
from quantum_circuits import (
    get_statevector, run_counts,
    circuit_superposition, circuit_bell_state, circuit_ghz,
    circuit_not_gate, circuit_phase_kickback,
    circuit_deutsch, circuit_bernstein_vazirani,
    circuit_teleportation, teleportation_deferred,
    circuit_qft, qft, inverse_qft, circuit_grover,
    qft_state_evolution, qft_matrix,
)
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector, partial_trace, DensityMatrix


@pytest.mark.slow
def test_superposition():
    counts = run_counts(circuit_superposition(), shots=2000)
    assert '0' in counts and '1' in counts
    assert 0.4 < counts.get('0', 0) / 2000 < 0.6


@pytest.mark.slow
def test_bell_state():
    counts = run_counts(circuit_bell_state(), shots=2000)
    for outcome in counts:
        assert outcome in ('00', '11')


@pytest.mark.slow
def test_ghz():
    counts = run_counts(circuit_ghz(), shots=2000)
    for outcome in counts:
        assert outcome in ('000', '111')


def test_not_gate():
    counts = run_counts(circuit_not_gate(), shots=100)
    assert counts == {'1': 100}


def test_phase_kickback():
    counts = run_counts(circuit_phase_kickback(), shots=100)
    assert counts == {'1': 100}


@pytest.mark.parametrize("oracle,expected", [('balanced', '1'), ('constant_0', '0')])
def test_deutsch(oracle, expected):
    counts = run_counts(circuit_deutsch(oracle), shots=100)
    assert counts == {expected: 100}


@pytest.mark.parametrize("secret", ['101', '110', '011', '111'])
def test_bernstein_vazirani(secret):
    counts = run_counts(circuit_bernstein_vazirani(secret), shots=100)
    assert counts == {secret: 100}


@pytest.mark.slow
def test_teleportation():
    qc_def = teleportation_deferred()
    sv = Statevector.from_instruction(qc_def)

    qc_expected = QuantumCircuit(1)
    qc_expected.rx(np.pi / 3, 0)
    qc_expected.rz(np.pi / 6, 0)
    expected_sv = Statevector.from_instruction(qc_expected)

    dm = DensityMatrix(sv)
    q2_dm = partial_trace(dm, [0, 1])
    expected_dm = DensityMatrix(expected_sv)

    fidelity = float(np.real(np.trace(q2_dm.data @ expected_dm.data)))
    assert fidelity > 0.99


@pytest.mark.parametrize("n", [2, 3, 4])
def test_qft_unitarity(n):
    M = qft_matrix(n)
    assert np.allclose(M @ M.conj().T, np.eye(2**n), atol=1e-10)


def test_qft_properties():
    n = 3
    N = 2**n
    qft_mat = qft_matrix(n)

    assert np.allclose(np.linalg.matrix_power(qft_mat, 4), np.eye(N), atol=1e-10)

    psi0 = np.zeros(N)
    psi0[0] = 1.0
    result = qft_mat @ psi0
    assert np.allclose(np.abs(result), 1.0 / np.sqrt(N), atol=1e-10)


@pytest.mark.parametrize("input_state", [0, 3, 5, 7])
def test_qft_inverse_roundtrip(input_state):
    n = 3
    qc = QuantumCircuit(n)
    for i in range(n):
        if (input_state >> i) & 1:
            qc.x(i)
    qft(qc, n)
    inverse_qft(qc, n)
    sv = Statevector.from_instruction(qc)
    probs = sv.probabilities_dict()
    expected = format(input_state, f'0{n}b')
    assert probs.get(expected, 0) > 0.99


def test_qft_state_evolution():
    states = qft_state_evolution(3, 5)
    assert len(states) >= 7
    final = states[-1][1]
    qft_mat = qft_matrix(3)
    psi = np.zeros(8)
    psi[5] = 1.0
    assert np.allclose(np.abs(final), np.abs(qft_mat @ psi), atol=0.01)


@pytest.mark.slow
@pytest.mark.parametrize("target", ['00', '01', '10', '11'])
def test_grover(target):
    counts = run_counts(circuit_grover(target), shots=500)
    assert counts.get(target, 0) > 400
