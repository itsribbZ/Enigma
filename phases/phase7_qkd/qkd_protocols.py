"""
Enigma Phase 7: Quantum Key Distribution — BB84, E91, QRNG.

BB84: prepare-and-measure QKD (Bennett & Brassard 1984)
E91: entanglement-based QKD (Ekert 1991)
QRNG: quantum random number generation

Uses Phase 3's Qiskit circuits for quantum operations.
"""

from __future__ import annotations
import numpy as np
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
from qiskit.quantum_info import Statevector


# ============================================================================
# QRNG — Quantum Random Number Generator
# ============================================================================

def qrng_bits(n: int) -> List[int]:
    """Generate n random bits using quantum Hadamard + measurement.

    Each bit: H|0> -> measure -> 50/50 outcome.
    NOTE: On AerSimulator this uses a classical PRNG internally.
    For true quantum randomness, run on IBM Quantum hardware.
    """
    qc = QuantumCircuit(1, 1)
    qc.h(0)
    qc.measure(0, 0)

    backend = AerSimulator()
    transpiled = transpile(qc, backend)
    result = backend.run(transpiled, shots=n, memory=True).result()
    memory = result.get_memory()
    return [int(bit) for bit in memory]


def qrng_bytes(n: int) -> bytes:
    """Generate n random bytes using QRNG."""
    bits = qrng_bits(n * 8)
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        result.append(byte)
    return bytes(result)


# ============================================================================
# BB84 PROTOCOL
# ============================================================================

@dataclass
class BB84Result:
    n_qubits: int
    alice_bits: List[int]
    alice_bases: List[int]  # 0=Z, 1=X
    bob_bases: List[int]
    bob_measurements: List[int]
    matching_indices: List[int]
    sifted_key_alice: List[int]
    sifted_key_bob: List[int]
    qber: float
    key_length: int
    eavesdropper_present: bool
    eavesdropper_detected: bool


def bb84_simulate(n_qubits: int = 100, eve_present: bool = False) -> BB84Result:
    """Simulate the BB84 QKD protocol.

    Args:
        n_qubits: Number of qubits to transmit
        eve_present: Whether Eve performs intercept-resend attack
    """
    # Step 1: Alice prepares random bits and bases
    alice_bits = [int(b) for b in np.random.randint(0, 2, n_qubits)]
    alice_bases = [int(b) for b in np.random.randint(0, 2, n_qubits)]  # 0=Z, 1=X

    # Step 2: Alice encodes qubits
    # Z basis: 0->|0>, 1->|1>
    # X basis: 0->|+>, 1->|->
    bob_measurements = []

    # Step 2.5: Eve's intercept-resend attack (if present)
    eve_bases = [int(b) for b in np.random.randint(0, 2, n_qubits)] if eve_present else None

    # Step 3: Bob chooses random measurement bases
    bob_bases = [int(b) for b in np.random.randint(0, 2, n_qubits)]

    # Simulate qubit-by-qubit (using Qiskit for accuracy)
    backend = AerSimulator()

    for i in range(n_qubits):
        qc = QuantumCircuit(1, 1)

        # Alice prepares qubit
        if alice_bits[i] == 1:
            qc.x(0)
        if alice_bases[i] == 1:  # X basis
            qc.h(0)

        # Eve intercepts (if present)
        if eve_present:
            # Eve measures in her random basis
            if eve_bases[i] == 1:
                qc.h(0)
            qc.measure(0, 0)

            # Simulate Eve's measurement
            transpiled = transpile(qc, backend)
            result = backend.run(transpiled, shots=1, memory=True).result()
            eve_bit = int(result.get_memory()[0])

            # Eve resends based on her measurement
            qc = QuantumCircuit(1, 1)
            if eve_bit == 1:
                qc.x(0)
            if eve_bases[i] == 1:
                qc.h(0)

        # Bob measures in his basis
        if bob_bases[i] == 1:  # X basis
            qc.h(0)
        qc.measure(0, 0)

        transpiled = transpile(qc, backend)
        result = backend.run(transpiled, shots=1, memory=True).result()
        bob_bit = int(result.get_memory()[0])
        bob_measurements.append(bob_bit)

    # Step 4: Sifting — keep only matching bases
    matching_indices = [i for i in range(n_qubits) if alice_bases[i] == bob_bases[i]]
    sifted_alice = [alice_bits[i] for i in matching_indices]
    sifted_bob = [bob_measurements[i] for i in matching_indices]

    # Step 5: Error estimation (use ~half for testing, keep rest as key)
    n_sifted = len(matching_indices)
    n_test = max(1, n_sifted // 4)

    errors = sum(1 for a, b in zip(sifted_alice[:n_test], sifted_bob[:n_test]) if a != b)
    qber = errors / n_test if n_test > 0 else 0.0

    # Step 6: Error reconciliation (correct Bob's errors using parity checks)
    reconciled_alice = sifted_alice[n_test:]
    reconciled_bob = sifted_bob[n_test:]

    # Simple reconciliation: discard mismatched bits using parity blocks
    block_size = 4
    final_key_alice = []
    final_key_bob = []
    for i in range(0, len(reconciled_alice) - block_size + 1, block_size):
        block_a = reconciled_alice[i:i+block_size]
        block_b = reconciled_bob[i:i+block_size]
        parity_a = sum(block_a) % 2
        parity_b = sum(block_b) % 2
        if parity_a == parity_b:
            # Parity matches — keep block (minus the parity bit for privacy)
            final_key_alice.extend(block_a[:-1])
            final_key_bob.extend(block_b[:-1])

    # Step 7: Privacy amplification (compress key with universal hash)
    # Use XOR-based compression: reduces Eve's information
    amplified_alice = []
    amplified_bob = []
    for i in range(0, len(final_key_alice) - 1, 2):
        amplified_alice.append(final_key_alice[i] ^ final_key_alice[i+1])
        amplified_bob.append(final_key_bob[i] ^ final_key_bob[i+1])
    final_key_alice = amplified_alice
    final_key_bob = amplified_bob

    # Eavesdropper detection: QBER > 11% indicates Eve
    detected = qber > 0.11

    return BB84Result(
        n_qubits=n_qubits,
        alice_bits=alice_bits,
        alice_bases=alice_bases,
        bob_bases=bob_bases,
        bob_measurements=bob_measurements,
        matching_indices=matching_indices,
        sifted_key_alice=final_key_alice,
        sifted_key_bob=final_key_bob,
        qber=qber,
        key_length=len(final_key_alice),
        eavesdropper_present=eve_present,
        eavesdropper_detected=detected,
    )


# ============================================================================
# E91 PROTOCOL (Entanglement-Based)
# ============================================================================

@dataclass
class E91Result:
    n_pairs: int
    alice_bases: List[int]
    bob_bases: List[int]
    alice_measurements: List[int]
    bob_measurements: List[int]
    matching_indices: List[int]
    sifted_key: List[int]
    chsh_value: float
    key_length: int
    eavesdropper_detected: bool


def e91_simulate(n_pairs: int = 100) -> E91Result:
    """Simulate E91 entanglement-based QKD protocol.

    Uses Bell pairs (|Phi+>). Alice and Bob measure in different bases.
    CHSH inequality violation (S ≈ 2.83) proves no eavesdropper.
    """
    # Alice's measurement bases: 0, pi/8, pi/4 (angles)
    alice_angles = [0, np.pi/8, np.pi/4]
    # Bob's measurement bases: pi/8, pi/4, 3pi/8
    bob_angles = [np.pi/8, np.pi/4, 3*np.pi/8]

    alice_basis_choices = np.random.randint(0, 3, n_pairs)
    bob_basis_choices = np.random.randint(0, 3, n_pairs)

    alice_measurements = []
    bob_measurements = []

    backend = AerSimulator()

    for i in range(n_pairs):
        qc = QuantumCircuit(2, 2)

        # Create Bell pair |Phi+> = (|00> + |11>)/sqrt(2)
        qc.h(0)
        qc.cx(0, 1)

        # Alice measures in her chosen basis (rotation before Z measurement)
        a_angle = alice_angles[alice_basis_choices[i]]
        qc.ry(-2 * a_angle, 0)

        # Bob measures in his chosen basis
        b_angle = bob_angles[bob_basis_choices[i]]
        qc.ry(-2 * b_angle, 1)

        qc.measure([0, 1], [0, 1])

        transpiled = transpile(qc, backend)
        result = backend.run(transpiled, shots=1, memory=True).result()
        bits = result.get_memory()[0]

        alice_measurements.append(int(bits[1]))  # Qiskit little-endian
        bob_measurements.append(int(bits[0]))

    # Sifting: keep pairs where Alice and Bob measured at the SAME ANGLE
    # Alice basis 1 (pi/8) matches Bob basis 0 (pi/8)
    # Alice basis 2 (pi/4) matches Bob basis 1 (pi/4)
    matching = []
    for i in range(n_pairs):
        a_angle = alice_angles[alice_basis_choices[i]]
        b_angle = bob_angles[bob_basis_choices[i]]
        if abs(a_angle - b_angle) < 1e-10:  # Same angle
            matching.append(i)

    sifted_key = [alice_measurements[i] for i in matching]

    # CHSH value estimation using non-matching basis pairs
    # E(a,b) = P(same) - P(different) for basis pair (a,b)
    def correlator(a_basis, b_basis):
        same = 0
        total = 0
        for i in range(n_pairs):
            if alice_basis_choices[i] == a_basis and bob_basis_choices[i] == b_basis:
                total += 1
                # Convert 0,1 to +1,-1
                a_val = 1 - 2 * alice_measurements[i]
                b_val = 1 - 2 * bob_measurements[i]
                same += a_val * b_val
        return same / total if total > 0 else 0

    # S = E(a1,b1) - E(a1,b3) + E(a3,b1) + E(a3,b3)
    # For our angle choices: S should be ~2*sqrt(2) ≈ 2.83
    E_00 = correlator(0, 0)  # a=0, b=pi/8
    E_02 = correlator(0, 2)  # a=0, b=3pi/8
    E_20 = correlator(2, 0)  # a=pi/4, b=pi/8
    E_22 = correlator(2, 2)  # a=pi/4, b=3pi/8

    chsh = abs(E_00 - E_02 + E_20 + E_22)

    # CHSH > 2 means quantum correlations (no local hidden variables / no Eve)
    detected = chsh < 2.0  # If CHSH drops below 2, Eve may be present

    return E91Result(
        n_pairs=n_pairs,
        alice_bases=[int(b) for b in alice_basis_choices],
        bob_bases=[int(b) for b in bob_basis_choices],
        alice_measurements=alice_measurements,
        bob_measurements=bob_measurements,
        matching_indices=matching,
        sifted_key=sifted_key,
        chsh_value=chsh,
        key_length=len(sifted_key),
        eavesdropper_detected=detected,
    )


# ============================================================================
# HYBRID QKD + PQC ARCHITECTURE ANALYSIS
# ============================================================================

def hybrid_qkd_pqc_analysis() -> str:
    """Generate analysis of hybrid QKD + PQC security architecture."""
    return """
===============================================================
  HYBRID QKD + PQC SECURITY ARCHITECTURE
  Technical Whitepaper Summary
===============================================================

  1. THE DUAL-LAYER APPROACH
  -----------------------------------------------
  Layer 1: QKD (Physics-Based Security)
    - BB84/E91 for key distribution
    - Information-theoretic security (unbreakable by ANY computer)
    - Limited by distance (~100km fiber, ~1000km satellite)
    - Requires dedicated quantum channel

  Layer 2: PQC (Math-Based Security)
    - ML-KEM/ML-DSA for key exchange and authentication
    - Computational security (hard problem assumption)
    - Works over existing internet infrastructure
    - No distance limitation

  2. WHY BOTH?
  -----------------------------------------------
  QKD alone:
    + Unbreakable key exchange
    - Cannot authenticate (needs classical crypto for that)
    - Distance-limited
    - Expensive infrastructure (dedicated fiber)
    - Low key rate (~kbps)

  PQC alone:
    + Works everywhere, any distance
    + High performance
    - Relies on hardness assumption (could be broken by new algorithm)
    - No detection of eavesdropping

  Hybrid:
    + QKD provides information-theoretic key exchange (short range)
    + PQC provides authentication and long-range fallback
    + Belt-and-suspenders: secure even if one layer has unknown weakness
    + QKD detects eavesdropping; PQC handles authentication

  3. DEPLOYMENT ARCHITECTURE
  -----------------------------------------------
  Tier 1 (Highest Security): QKD + PQC + OTP
    - Government/military, banking core networks
    - QKD for key distribution, PQC for authentication
    - One-time pad encryption when QKD key rate allows

  Tier 2 (High Security): PQC + QKD-enhanced
    - Financial services, healthcare
    - PQC as primary, QKD for periodic key refresh
    - QKD key mixed into PQC key schedule

  Tier 3 (Standard Security): PQC only
    - General enterprise, consumer
    - ML-KEM + ML-DSA over standard TLS
    - Most practical for majority of use cases

  4. CURRENT STATE (2026)
  -----------------------------------------------
  QKD Hardware:
    - ID Quantique (Switzerland): commercial QKD systems
    - Toshiba (Japan): long-distance fiber QKD
    - China Micius satellite: 1200km QKD demonstrated
    - EU EuroQCI: pan-European QKD network planned

  QKD Limitations:
    - Trusted node problem (repeaters must be trusted)
    - Quantum repeaters not yet practical
    - Key rate: ~1-100 kbps (vs Gbps for PQC)
    - Cost: $100K+ per link

  5. RECOMMENDATION
  -----------------------------------------------
  For most organizations: PQC is sufficient (Tier 3).
  QKD adds value for:
    - Government/defense with physical security requirements
    - Financial networks with dedicated fiber
    - Organizations wanting defense-in-depth against unknown attacks

===============================================================
"""
