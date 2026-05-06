"""
Enigma Phase 3: Quantum Circuits — 10 fundamental circuits + teleportation + QFT.
Built with Qiskit 2.x, verified on Aer simulator.

Deliverables:
  1. 10 fundamental quantum circuits
  2. Quantum teleportation protocol
  3. QFT with state evolution
"""

from __future__ import annotations
import numpy as np
from typing import Dict, List, Optional, Tuple
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit.quantum_info import Statevector, Operator
from qiskit_aer import AerSimulator


# ============================================================================
# SIMULATION HELPERS
# ============================================================================

def get_statevector(qc: QuantumCircuit) -> Statevector:
    """Get exact statevector from a circuit (no measurement gates allowed)."""
    return Statevector.from_instruction(qc)


def run_counts(qc: QuantumCircuit, shots: int = 1024) -> Dict[str, int]:
    """Run circuit on Aer simulator, return measurement counts."""
    backend = AerSimulator()
    transpiled = transpile(qc, backend)
    result = backend.run(transpiled, shots=shots).result()
    return result.get_counts()


# ============================================================================
# CIRCUIT 1: SUPERPOSITION (Hadamard)
# ============================================================================

def circuit_superposition() -> QuantumCircuit:
    """Single qubit in equal superposition via Hadamard gate.
    Expected: |+> = (|0> + |1>)/sqrt(2), ~50% each on measurement.
    """
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)
    return qc


# ============================================================================
# CIRCUIT 2: BELL STATE (Entanglement)
# ============================================================================

def circuit_bell_state() -> QuantumCircuit:
    """Create Bell state |Phi+> = (|00> + |11>)/sqrt(2).
    Expected: ~50% |00>, ~50% |11>, never |01> or |10>.
    """
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.measure([0, 1], [0, 1])
    return qc


# ============================================================================
# CIRCUIT 3: GHZ STATE (3-qubit entanglement)
# ============================================================================

def circuit_ghz() -> QuantumCircuit:
    """Create GHZ state (|000> + |111>)/sqrt(2).
    Expected: ~50% |000>, ~50% |111>.
    """
    qc = QuantumCircuit(3, 3)
    qc.h(0)
    qc.cx(0, 1)
    qc.cx(0, 2)
    qc.measure([0, 1, 2], [0, 1, 2])
    return qc


# ============================================================================
# CIRCUIT 4: QUANTUM NOT (X gate)
# ============================================================================

def circuit_not_gate() -> QuantumCircuit:
    """Apply X gate: |0> -> |1>.
    Expected: 100% |1>.
    """
    qc = QuantumCircuit(1, 1)
    qc.x(0)
    qc.measure(0, 0)
    return qc


# ============================================================================
# CIRCUIT 5: PHASE KICKBACK
# ============================================================================

def circuit_phase_kickback() -> QuantumCircuit:
    """Demonstrate phase kickback: eigenvalue appears on control qubit.
    H|0> = |+>, then CZ flips phase of |1> component -> |-> = H|1>.
    After second H: measures |1> with certainty.
    """
    qc = QuantumCircuit(2, 1)
    qc.h(0)       # Control in |+>
    qc.x(1)       # Target in |1> (eigenstate of Z)
    qc.cz(0, 1)   # Phase kickback: control gets phase
    qc.h(0)       # Convert phase to measurement basis
    qc.measure(0, 0)
    return qc


# ============================================================================
# CIRCUIT 6: DEUTSCH ALGORITHM
# ============================================================================

def circuit_deutsch(oracle_type: str = 'balanced') -> QuantumCircuit:
    """Deutsch algorithm: determine if f(x) is constant or balanced in 1 query.
    Constant f: f(0)=f(1) -> measure |0>
    Balanced f: f(0)!=f(1) -> measure |1>
    """
    qc = QuantumCircuit(2, 1)
    # Prepare |+>|->
    qc.x(1)
    qc.h(0)
    qc.h(1)

    # Oracle
    if oracle_type == 'balanced':
        qc.cx(0, 1)  # f(x) = x (balanced)
    elif oracle_type == 'constant_1':
        qc.x(1)      # f(x) = 1 (constant)
    # constant_0: identity (no gate needed)

    qc.h(0)
    qc.measure(0, 0)
    return qc


# ============================================================================
# CIRCUIT 7: BERNSTEIN-VAZIRANI
# ============================================================================

def circuit_bernstein_vazirani(secret: str = '101') -> QuantumCircuit:
    """Bernstein-Vazirani: find hidden string s in 1 query.
    Oracle: f(x) = s dot x (mod 2).
    """
    n = len(secret)
    qc = QuantumCircuit(n + 1, n)

    # Put ancilla in |->
    qc.x(n)
    qc.h(range(n + 1))

    # Oracle: CNOT from qubit i to ancilla wherever secret[i] = '1'
    for i, bit in enumerate(reversed(secret)):
        if bit == '1':
            qc.cx(i, n)

    # Apply H to input qubits and measure
    qc.h(range(n))
    qc.measure(range(n), range(n))
    return qc


# ============================================================================
# CIRCUIT 8: QUANTUM TELEPORTATION
# ============================================================================

def circuit_teleportation(state_prep: Optional[str] = None) -> QuantumCircuit:
    """Quantum teleportation: transfer qubit state from q0 to q2.

    Uses deferred measurement pattern for statevector verification.
    state_prep: 'plus', 'one', or None (|0> default)
    """
    qc = QuantumCircuit(3, 3)

    # Prepare state to teleport on q0
    if state_prep == 'plus':
        qc.h(0)
    elif state_prep == 'one':
        qc.x(0)
    elif state_prep == 'custom':
        qc.rx(np.pi / 4, 0)  # Arbitrary state

    qc.barrier()

    # Create Bell pair between q1 and q2
    qc.h(1)
    qc.cx(1, 2)

    qc.barrier()

    # Alice's operations: entangle q0 with q1
    qc.cx(0, 1)
    qc.h(0)

    qc.barrier()

    # Measure Alice's qubits
    qc.measure(0, 0)
    qc.measure(1, 1)

    # Bob's corrections (classically controlled)
    with qc.if_test((1, 1)):
        qc.x(2)
    with qc.if_test((0, 1)):
        qc.z(2)

    qc.measure(2, 2)
    return qc


def teleportation_deferred() -> QuantumCircuit:
    """Teleportation with deferred measurement (for statevector verification).
    Uses CX/CZ instead of classical conditioning.
    """
    qc = QuantumCircuit(3)

    # Prepare state to teleport: arbitrary rotation
    qc.rx(np.pi / 3, 0)
    qc.rz(np.pi / 6, 0)

    # Save expected state
    # (verified by checking q2 statevector after tracing out q0,q1)

    qc.barrier()

    # Bell pair q1-q2
    qc.h(1)
    qc.cx(1, 2)

    qc.barrier()

    # Alice: CNOT + H
    qc.cx(0, 1)
    qc.h(0)

    qc.barrier()

    # Deferred corrections (quantum gates instead of classical conditioning)
    qc.cx(1, 2)   # Equivalent to: if q1=1, apply X to q2
    qc.cz(0, 2)   # Equivalent to: if q0=1, apply Z to q2

    return qc


# ============================================================================
# CIRCUIT 9: QUANTUM FOURIER TRANSFORM (QFT)
# ============================================================================

def qft(qc: QuantumCircuit, n: int, start: int = 0) -> QuantumCircuit:
    """Apply QFT to qubits [start, start+n) in circuit qc."""
    for i in range(n):
        qc.h(start + i)
        for j in range(i + 1, n):
            angle = np.pi / (2 ** (j - i))
            qc.cp(angle, start + j, start + i)

    # Reverse qubit order
    for i in range(n // 2):
        qc.swap(start + i, start + n - 1 - i)

    return qc


def inverse_qft(qc: QuantumCircuit, n: int, start: int = 0) -> QuantumCircuit:
    """Apply inverse QFT to qubits [start, start+n)."""
    # Reverse qubit order
    for i in range(n // 2):
        qc.swap(start + i, start + n - 1 - i)

    for i in range(n - 1, -1, -1):
        for j in range(n - 1, i, -1):
            angle = -np.pi / (2 ** (j - i))
            qc.cp(angle, start + j, start + i)
        qc.h(start + i)

    return qc


def circuit_qft(n_qubits: int = 3, input_state: int = 5) -> QuantumCircuit:
    """Build QFT circuit with specified input state.
    Default: QFT|5> = QFT|101> on 3 qubits.
    """
    qc = QuantumCircuit(n_qubits)

    # Prepare input state
    for i in range(n_qubits):
        if (input_state >> i) & 1:
            qc.x(i)

    qc.barrier()
    qft(qc, n_qubits)
    return qc


# ============================================================================
# CIRCUIT 10: GROVER'S SEARCH (2-qubit)
# ============================================================================

def circuit_grover(target: str = '11') -> QuantumCircuit:
    """Grover's search on 2 qubits. Finds target state in 1 iteration.
    For 2 qubits, 1 iteration gives ~100% probability.
    """
    if len(target) != 2:
        raise ValueError(f"circuit_grover only supports 2-qubit targets; got len={len(target)}")
    n = len(target)
    qc = QuantumCircuit(n, n)

    # Initialize superposition
    qc.h(range(n))

    # Oracle: flip phase of target state
    # For target |11>: CZ gate
    # For other targets: apply X gates to flip, then CZ, then X back
    for i, bit in enumerate(reversed(target)):
        if bit == '0':
            qc.x(i)
    qc.cz(0, 1)
    for i, bit in enumerate(reversed(target)):
        if bit == '0':
            qc.x(i)

    # Diffusion operator: 2|s><s| - I
    qc.h(range(n))
    qc.x(range(n))
    qc.cz(0, 1)
    qc.x(range(n))
    qc.h(range(n))

    qc.measure(range(n), range(n))
    return qc


# ============================================================================
# QFT STATE EVOLUTION VISUALIZATION
# ============================================================================

def qft_state_evolution(n_qubits: int = 3, input_state: int = 5) -> List[Tuple[str, np.ndarray]]:
    """Track state vector after each gate in QFT circuit.
    Returns list of (gate_description, statevector) pairs.
    """
    states = []

    # Prepare input
    qc = QuantumCircuit(n_qubits)
    for i in range(n_qubits):
        if (input_state >> i) & 1:
            qc.x(i)
    states.append((f"Input |{input_state}> = |{bin(input_state)[2:].zfill(n_qubits)}>",
                   np.array(Statevector.from_instruction(qc))))

    # Apply QFT gates one by one
    for i in range(n_qubits):
        qc.h(i)
        states.append((f"H on q{i}", np.array(Statevector.from_instruction(qc))))

        for j in range(i + 1, n_qubits):
            angle = np.pi / (2 ** (j - i))
            qc.cp(angle, j, i)
            states.append((f"CR_{j-i+1}(q{j}->q{i})",
                           np.array(Statevector.from_instruction(qc))))

    # Swaps
    for i in range(n_qubits // 2):
        qc.swap(i, n_qubits - 1 - i)
        states.append((f"SWAP(q{i},q{n_qubits-1-i})",
                       np.array(Statevector.from_instruction(qc))))

    return states


# ============================================================================
# NUMPY QFT MATRIX (for verification)
# ============================================================================

def qft_matrix(n: int) -> np.ndarray:
    """Build N x N QFT matrix (N = 2^n) for verification against Qiskit."""
    N = 2 ** n
    omega = np.exp(2j * np.pi / N)
    return np.array([[omega ** (j * k) for k in range(N)] for j in range(N)]) / np.sqrt(N)
