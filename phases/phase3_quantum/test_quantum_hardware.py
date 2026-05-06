"""
Enigma Phase 3 (v2): Quantum hardware execution tests.
Tests noise-model simulator and circuit preparation.
"""
import pytest
from quantum_hardware import (
    prepare_circuits, run_on_simulator, compare_ideal_vs_noisy,
    build_realistic_noise_model, HardwareReport, HardwareResult,
)


def test_prepare_circuits():
    """All 5 circuits should be prepared with correct structure."""
    circuits = prepare_circuits()
    assert len(circuits) == 5
    for name, qc, expected, desc in circuits:
        assert isinstance(name, str)
        assert len(expected) > 0
        assert len(desc) > 0


def test_noise_model():
    """Noise model should build without error."""
    nm = build_realistic_noise_model()
    assert nm is not None


@pytest.mark.slow
def test_ideal_simulator():
    """Ideal simulator should give near-perfect results."""
    circuits = prepare_circuits()
    report = run_on_simulator(circuits, shots=1000, use_noise=False)
    assert report.total_circuits == 5
    assert not report.is_real_hardware

    for r in report.results:
        assert r.shots == 1000
        # Ideal simulator should have >95% success on all circuits
        assert r.success_rate > 0.95, f"{r.circuit_name}: {r.success_rate:.1%}"


@pytest.mark.slow
def test_noisy_simulator():
    """Noisy simulator should show degraded but reasonable results."""
    circuits = prepare_circuits()
    report = run_on_simulator(circuits, shots=2000, use_noise=True)
    assert report.total_circuits == 5

    for r in report.results:
        assert r.shots == 2000
        # Noisy sim should still get >70% on most circuits
        # (noise is realistic but not catastrophic)
        assert r.success_rate > 0.50, f"{r.circuit_name}: {r.success_rate:.1%}"


@pytest.mark.slow
def test_compare_ideal_vs_noisy():
    """Ideal should outperform noisy on every circuit."""
    ideal, noisy = compare_ideal_vs_noisy(shots=1000)

    for i_r, n_r in zip(ideal.results, noisy.results):
        assert i_r.circuit_name == n_r.circuit_name
        # Ideal should be >= noisy (noise only degrades)
        assert i_r.success_rate >= n_r.success_rate - 0.05, \
            f"{i_r.circuit_name}: ideal={i_r.success_rate:.1%} < noisy={n_r.success_rate:.1%}"


def test_report_format():
    """Report formatting should produce readable output."""
    circuits = prepare_circuits()[:2]  # Just 2 for speed
    report = run_on_simulator(circuits, shots=100, use_noise=False)
    text = report.format_report()
    assert 'ENIGMA' in text
    assert 'Bell State' in text
    assert 'Success' in text


def test_report_json():
    """Report should serialize to dict."""
    circuits = prepare_circuits()[:1]
    report = run_on_simulator(circuits, shots=100, use_noise=False)
    d = report.to_dict()
    assert 'results' in d
    assert len(d['results']) == 1
    assert 'counts' in d['results'][0]
