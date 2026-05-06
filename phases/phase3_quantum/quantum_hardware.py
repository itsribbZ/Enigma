"""
Enigma Phase 3 (v2): Real IBM Quantum Hardware Execution.

Runs quantum circuits on IBM Quantum hardware via Qiskit Runtime,
with noise-model fallback for when hardware is unavailable.

Circuits executed:
  1. Bell state (2 qubits) — entanglement verification
  2. GHZ state (3 qubits) — multi-qubit entanglement
  3. Grover's search (2 qubits) — quantum speedup demo
  4. Bernstein-Vazirani (3 qubits) — oracle algorithm
  5. Quantum Fourier Transform (3 qubits) — fundamental subroutine

Each circuit runs on real hardware if available, otherwise on a
noise-model simulator that mimics real device characteristics.
"""

from __future__ import annotations
import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from qiskit import QuantumCircuit, transpile
from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel, depolarizing_error, thermal_relaxation_error, ReadoutError

# Import hardware circuits from existing module
import sys
sys.path.insert(0, os.path.dirname(__file__))
from quantum_circuits import (
    circuit_bell_state, circuit_ghz, circuit_grover,
    circuit_bernstein_vazirani, circuit_superposition,
)


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass
class HardwareResult:
    """Result from a quantum hardware (or noise-sim) execution."""
    circuit_name: str
    backend_name: str
    is_real_hardware: bool
    shots: int
    counts: Dict[str, int]
    execution_time_ms: float
    expected_outcomes: List[str]
    success_rate: float
    notes: str = ""


@dataclass
class HardwareReport:
    """Complete report of all hardware executions."""
    timestamp: str
    backend: str
    is_real_hardware: bool
    total_circuits: int
    results: List[HardwareResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp,
            'backend': self.backend,
            'is_real_hardware': self.is_real_hardware,
            'total_circuits': self.total_circuits,
            'results': [asdict(r) for r in self.results],
        }

    def format_report(self) -> str:
        lines = [
            "=" * 70,
            "  ENIGMA — QUANTUM HARDWARE EXECUTION REPORT",
            "=" * 70,
            "",
            f"  Backend:    {self.backend}",
            f"  Hardware:   {'REAL IBM QUANTUM' if self.is_real_hardware else 'NOISE-MODEL SIMULATOR'}",
            f"  Timestamp:  {self.timestamp}",
            f"  Circuits:   {self.total_circuits}",
            "",
        ]

        for r in self.results:
            mode = "REAL" if r.is_real_hardware else "SIM"
            lines.append(f"  [{mode}] {r.circuit_name}")
            lines.append(f"    Backend: {r.backend_name} | Shots: {r.shots}")

            # Show top 5 outcomes
            sorted_counts = sorted(r.counts.items(), key=lambda x: -x[1])
            for outcome, count in sorted_counts[:5]:
                pct = count / r.shots * 100
                bar = "#" * int(pct / 2)
                marker = " *" if outcome in r.expected_outcomes else ""
                lines.append(f"    |{outcome}> {count:5d} ({pct:5.1f}%) {bar}{marker}")
            if len(sorted_counts) > 5:
                lines.append(f"    ... and {len(sorted_counts) - 5} more outcomes")

            lines.append(f"    Success: {r.success_rate:.1%} | Expected: {r.expected_outcomes}")
            if r.notes:
                lines.append(f"    Note: {r.notes}")
            lines.append("")

        # Summary
        avg_success = sum(r.success_rate for r in self.results) / len(self.results) if self.results else 0
        lines.extend([
            "  SUMMARY",
            "  " + "-" * 50,
            f"  Average success rate: {avg_success:.1%}",
            f"  {'Real hardware noise visible' if not self.is_real_hardware else 'Results from actual quantum processor'}",
            "",
            "=" * 70,
        ])
        return "\n".join(lines)


# ============================================================================
# NOISE MODEL (simulates real hardware characteristics)
# ============================================================================

def build_realistic_noise_model() -> NoiseModel:
    """Build a noise model approximating IBM Eagle/Heron processors.

    Typical error rates for IBM quantum devices (2024-2026):
      - Single-qubit gate error: ~0.03% (3e-4)
      - Two-qubit (CX) gate error: ~0.5-1% (5e-3 to 1e-2)
      - Measurement error: ~1% (1e-2)
      - T1 relaxation: ~300 μs
      - T2 dephasing: ~150 μs
    """
    noise_model = NoiseModel()

    # Single-qubit depolarizing error (post-transpile basis gates only)
    error_1q = depolarizing_error(3e-4, 1)
    noise_model.add_all_qubit_quantum_error(error_1q, ['rz', 'sx', 'x'])

    # Two-qubit depolarizing error (CX gate)
    error_2q = depolarizing_error(8e-3, 2)
    noise_model.add_all_qubit_quantum_error(error_2q, ['cx'])

    # T1/T2 thermal relaxation on single-qubit gates
    t1, t2, gate_time = 300e-6, 150e-6, 50e-9
    error_thermal = thermal_relaxation_error(t1, t2, gate_time)
    noise_model.add_all_qubit_quantum_error(error_thermal, ['rz', 'sx', 'x'])

    # Readout error (classical bit-flip, not quantum depolarizing)
    import numpy as np
    p_meas = 0.01
    readout = ReadoutError([[1 - p_meas, p_meas], [p_meas, 1 - p_meas]])
    noise_model.add_all_qubit_readout_error(readout)

    return noise_model


# ============================================================================
# CIRCUIT PREPARATION
# ============================================================================

def prepare_circuits() -> List[Tuple[str, QuantumCircuit, List[str], str]]:
    """Prepare circuits for hardware execution.

    Returns: [(name, circuit, expected_outcomes, description), ...]
    """
    circuits = []

    # 1. Bell State
    circuits.append((
        "Bell State (Phi+)",
        circuit_bell_state(),
        ['00', '11'],
        "Maximally entangled 2-qubit state. Expect ~50/50 |00> and |11>."
    ))

    # 2. GHZ State
    circuits.append((
        "GHZ State (3-qubit)",
        circuit_ghz(),
        ['000', '111'],
        "3-qubit entangled state. Expect ~50/50 |000> and |111>."
    ))

    # 3. Grover Search (target |11>)
    circuits.append((
        "Grover Search (target=11)",
        circuit_grover('11'),
        ['11'],
        "Amplitude amplification should find |11> with >90% probability."
    ))

    # 4. Bernstein-Vazirani (secret = 101)
    circuits.append((
        "Bernstein-Vazirani (s=101)",
        circuit_bernstein_vazirani('101'),
        ['101'],
        "Single query finds hidden string. Should be 100% on ideal hardware."
    ))

    # 5. Superposition
    circuits.append((
        "Hadamard Superposition",
        circuit_superposition(),
        ['0', '1'],
        "Equal superposition. Expect ~50/50 |0> and |1>."
    ))

    return circuits


# ============================================================================
# EXECUTION ENGINE
# ============================================================================

def try_real_hardware() -> Optional[object]:
    """Attempt to connect to IBM Quantum and get a real backend."""
    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
        service = QiskitRuntimeService()
        # Get least busy backend with enough qubits
        backends = service.backends(
            filters=lambda b: b.status().operational and b.num_qubits >= 5
        )
        if backends:
            # Sort by queue length
            backend = min(backends, key=lambda b: b.status().pending_jobs)
            return backend
    except Exception:
        pass
    return None


def run_on_simulator(circuits: List[Tuple[str, QuantumCircuit, List[str], str]],
                     shots: int = 4096,
                     use_noise: bool = True) -> HardwareReport:
    """Run circuits on AerSimulator with optional noise model."""
    import time

    noise_model = build_realistic_noise_model() if use_noise else None
    backend_name = "aer_simulator_noise" if use_noise else "aer_simulator_ideal"
    backend = AerSimulator(noise_model=noise_model) if use_noise else AerSimulator()

    report = HardwareReport(
        timestamp=datetime.now().isoformat(),
        backend=backend_name,
        is_real_hardware=False,
        total_circuits=len(circuits),
    )

    for name, qc, expected, description in circuits:
        t0 = time.perf_counter()
        transpiled = transpile(qc, backend)
        job = backend.run(transpiled, shots=shots)
        result = job.result()
        elapsed = (time.perf_counter() - t0) * 1000

        counts = result.get_counts()

        # Calculate success rate
        total_expected = sum(counts.get(o, 0) for o in expected)
        success_rate = total_expected / shots

        report.results.append(HardwareResult(
            circuit_name=name,
            backend_name=backend_name,
            is_real_hardware=False,
            shots=shots,
            counts=dict(counts),
            execution_time_ms=elapsed,
            expected_outcomes=expected,
            success_rate=success_rate,
            notes=description,
        ))

    return report


def run_on_hardware(circuits: List[Tuple[str, QuantumCircuit, List[str], str]],
                    backend,
                    shots: int = 4096) -> HardwareReport:
    """Run circuits on real IBM Quantum hardware."""
    import time
    from qiskit_ibm_runtime import SamplerV2

    report = HardwareReport(
        timestamp=datetime.now().isoformat(),
        backend=backend.name,
        is_real_hardware=True,
        total_circuits=len(circuits),
    )

    sampler = SamplerV2(backend)

    for name, qc, expected, description in circuits:
        t0 = time.perf_counter()
        transpiled = transpile(qc, backend, optimization_level=3)
        job = sampler.run([transpiled], shots=shots)
        result = job.result()
        elapsed = (time.perf_counter() - t0) * 1000

        # Extract counts from SamplerV2 result
        pub_result = result[0]
        counts = pub_result.data.meas.get_counts() if hasattr(pub_result.data, 'meas') else {}

        total_expected = sum(counts.get(o, 0) for o in expected)
        success_rate = total_expected / shots if shots > 0 else 0

        report.results.append(HardwareResult(
            circuit_name=name,
            backend_name=backend.name,
            is_real_hardware=True,
            shots=shots,
            counts=dict(counts),
            execution_time_ms=elapsed,
            expected_outcomes=expected,
            success_rate=success_rate,
            notes=f"{description} [Real hardware: {backend.name}]",
        ))

    return report


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def run_hardware_demo(shots: int = 4096, force_simulator: bool = False) -> HardwareReport:
    """Run the full hardware demo.

    Tries real IBM Quantum hardware first; falls back to noise-model simulator.

    Args:
        shots: Number of measurement shots per circuit
        force_simulator: Skip hardware attempt, use simulator directly
    """
    circuits = prepare_circuits()

    if not force_simulator:
        backend = try_real_hardware()
        if backend is not None:
            print(f"  Connected to IBM Quantum: {backend.name} ({backend.num_qubits} qubits)")
            print(f"  Queue: {backend.status().pending_jobs} pending jobs")
            return run_on_hardware(circuits, backend, shots)

    print("  Using noise-model simulator (IBM Eagle/Heron characteristics)")
    return run_on_simulator(circuits, shots, use_noise=True)


def compare_ideal_vs_noisy(shots: int = 4096) -> Tuple[HardwareReport, HardwareReport]:
    """Run circuits on both ideal and noisy simulators for comparison."""
    circuits = prepare_circuits()
    ideal = run_on_simulator(circuits, shots, use_noise=False)
    noisy = run_on_simulator(circuits, shots, use_noise=True)
    return ideal, noisy
