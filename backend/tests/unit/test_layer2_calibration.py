"""
Unit tests – Layer 2 Calibration Utility

Tests that the HonestNoiseCalibrator:
1. Only modifies COPIES of positions, never originals.
2. Perturbs at the configured rate (within statistical tolerance with seeded RNG).
3. Computes the Hoeffding bound correctly.
4. Validates threshold separation correctly.
"""

import math
import pytest

from app.schemas.protocol import SignaturePositionRecord
from app.layer2_threat.calibration import HonestNoiseCalibrator


def _make_clean_position(index: int) -> SignaturePositionRecord:
    """Helper: a perfect-match position record."""
    return SignaturePositionRecord(
        index=index,
        pauli_basis="X",
        encoded_bit=0,
        prepared_state_label="|+>",
        bell_state="PHI_PLUS",
        bell_measurement_bits="00",
        expected_correction="I",
        actual_correction="I",
        final_measured_bit=0,
        expected_bit=0,
        fidelity=1.0,
        is_match=True,
    )


def test_calibrator_does_not_modify_originals():
    """Originals must be unchanged after perturbation."""
    positions = [_make_clean_position(i) for i in range(20)]
    original_ids = [id(p) for p in positions]

    calibrator = HonestNoiseCalibrator(e_honest=0.5, seed=0)
    perturbed = calibrator.perturb_positions(positions)

    # Original objects are untouched
    for orig_id, orig_pos in zip(original_ids, positions):
        assert id(orig_pos) == orig_id
        assert orig_pos.is_match is True
        assert orig_pos.final_measured_bit == 0


def test_calibrator_zero_honest_error_produces_no_flips():
    """e_honest=0.0 must produce zero flips (matches Layer 1 NoNoise)."""
    positions = [_make_clean_position(i) for i in range(50)]
    calibrator = HonestNoiseCalibrator(e_honest=0.0, seed=1)
    perturbed = calibrator.perturb_positions(positions)

    assert all(p.is_match for p in perturbed)
    assert all(p.final_measured_bit == 0 for p in perturbed)


def test_calibrator_full_error_rate_flips_all():
    """e_honest approaching 1.0 must flip nearly all positions."""
    # e_honest must be < 1.0; use 0.9999
    positions = [_make_clean_position(i) for i in range(200)]
    calibrator = HonestNoiseCalibrator(e_honest=0.9999, seed=7)
    perturbed = calibrator.perturb_positions(positions)
    flip_count = sum(1 for p in perturbed if not p.is_match)
    # With p=0.9999 and n=200, expect ~199-200 flips; allow ≥ 190
    assert flip_count >= 190, f"Expected ~200 flips, got {flip_count}"


def test_calibrator_rate_approximately_correct():
    """Empirical flip rate should be within 3σ of e_honest for large n."""
    n = 10_000
    e = 0.15
    positions = [_make_clean_position(i) for i in range(n)]
    calibrator = HonestNoiseCalibrator(e_honest=e, seed=42)
    perturbed = calibrator.perturb_positions(positions)
    empirical_rate = sum(1 for p in perturbed if not p.is_match) / n
    std = math.sqrt(e * (1 - e) / n)
    assert abs(empirical_rate - e) < 3 * std, (
        f"Empirical rate {empirical_rate:.4f} too far from e_honest={e} (std={std:.4f})"
    )


def test_hoeffding_bound_vacuous_at_or_below_honest_rate():
    """Hoeffding bound = 1.0 when observed_rate <= e_honest."""
    cal = HonestNoiseCalibrator(e_honest=0.05, seed=0)
    assert cal.hoeffding_bound(n=100, observed_rate=0.05) == 1.0
    assert cal.hoeffding_bound(n=100, observed_rate=0.03) == 1.0


def test_hoeffding_bound_decreases_with_n():
    """Larger n must give a tighter (smaller) bound for same rate."""
    cal = HonestNoiseCalibrator(e_honest=0.0, seed=0)
    b16 = cal.hoeffding_bound(n=16, observed_rate=0.10)
    b64 = cal.hoeffding_bound(n=64, observed_rate=0.10)
    b256 = cal.hoeffding_bound(n=256, observed_rate=0.10)
    assert b16 > b64 > b256
    assert 0.0 < b256 < 1.0


def test_hoeffding_bound_formula():
    """Manual verification of exp(-2 * n * (rate - e)^2)."""
    cal = HonestNoiseCalibrator(e_honest=0.0, seed=0)
    n, rate = 16, 0.10
    expected = math.exp(-2 * n * (rate ** 2))
    assert abs(cal.hoeffding_bound(n, rate) - expected) < 1e-12


def test_threshold_separation_valid():
    """Valid ordering: e_honest < s_a < s_v passes."""
    cal = HonestNoiseCalibrator(e_honest=0.0, seed=0)
    ok, msg = cal.validate_threshold_separation(s_a=0.10, s_v=0.20)
    assert ok is True
    assert msg == ""


def test_threshold_separation_invalid_sa_le_ehonest():
    """s_a <= e_honest must fail."""
    cal = HonestNoiseCalibrator(e_honest=0.10, seed=0)
    ok, msg = cal.validate_threshold_separation(s_a=0.10, s_v=0.20)
    assert ok is False
    assert "e_honest" in msg


def test_threshold_separation_invalid_sv_le_sa():
    """s_v <= s_a must fail."""
    cal = HonestNoiseCalibrator(e_honest=0.0, seed=0)
    ok, msg = cal.validate_threshold_separation(s_a=0.20, s_v=0.10)
    assert ok is False
    assert "s_v" in msg


def test_calibrator_invalid_e_honest_raises():
    """e_honest >= 1.0 or < 0 must raise ValueError."""
    with pytest.raises(ValueError):
        HonestNoiseCalibrator(e_honest=1.0)
    with pytest.raises(ValueError):
        HonestNoiseCalibrator(e_honest=-0.01)
