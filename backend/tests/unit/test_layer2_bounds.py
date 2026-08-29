"""
Layer 2 – Finite-Sample Bounds and Threshold Logic Unit Tests

Tests:
1. Hoeffding upper/lower/tail bounds formulas & clamping to [0, 1].
2. Serfling bound finite-population correction term (1 - (k-1)/n) & rejection of k > n.
3. Threshold chain validation (e_upper < s_a < s_v < p_E) raising ConfigurationWarning.
4. Deliberately invalid threshold ordering producing ConfigurationWarning + REJECT (never false ACCEPT).
5. Boundary case where mismatch rate sits at s_a.
6. Independent divergence of direct (s_a) and forwarded (s_v) confidence-adjusted error rates.
"""

import pytest
import warnings

from app.schemas.telemetry import ProtocolSessionResult
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.bounds import (
    ConfigurationWarning,
    hoeffding_upper_bound,
    hoeffding_lower_bound,
    hoeffding_tail_bound,
    serfling_upper_bound,
    serfling_lower_bound,
    serfling_tail_bound,
    validate_threshold_chain,
)
from app.layer2_threat.detectors import run_bob_charlie_split
from app.layer2_threat.engine import assess_session
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.schemas import ThreatLevel


def _make_pos(idx: int, is_match: bool = True) -> SignaturePositionRecord:
    bit = 0 if is_match else 1
    return SignaturePositionRecord(
        index=idx,
        pauli_basis="Z",
        encoded_bit=0,
        prepared_state_label="|0>",
        bell_state="PHI_PLUS",
        bell_measurement_bits="00",
        expected_correction="I",
        actual_correction="I",
        final_measured_bit=bit,
        expected_bit=0,
        fidelity=0.999999,
        is_match=is_match,
    )


def _make_session(positions: list[SignaturePositionRecord]) -> ProtocolSessionResult:
    mismatches = sum(1 for p in positions if not p.is_match)
    total = len(positions)
    rate = mismatches / total if total > 0 else 0.0
    summary = BasicVerificationSummary(
        total_positions=total,
        matching_positions=total - mismatches,
        mismatching_positions=mismatches,
        mismatch_count=mismatches,
        mismatch_rate=rate,
        average_fidelity=sum(p.fidelity for p in positions) / total if total > 0 else 0.0,
        basis_distribution={"Z": total, "X": 0, "Y": 0},
        correction_distribution={"I": total, "X": 0, "Z": 0, "XZ": 0},
        digest_matches=True,
        is_perfect_match=(mismatches == 0),
    )
    return ProtocolSessionResult(
        protocol_version="1.0.0",
        session_id="test-bounds-session",
        signature_block_id="block-0",
        sender_id="Alice",
        recipient_id="Bob",
        message="MSG",
        message_digest="a" * 64,
        nonce="nonce",
        sequence_number=1,
        created_at="2026-08-30T00:00:00+00:00",
        configuration={},
        signature_positions=positions,
        teleportation_events=[],
        measurement_events=[],
        verification_summary=summary,
        seed=42,
    )


# ---------------------------------------------------------------------------
# 1. Hoeffding Bounds Clamping and Formulas
# ---------------------------------------------------------------------------

def test_hoeffding_upper_bound_clamping():
    # Large margin would exceed 1.0 -> must clamp to 1.0
    val_upper = hoeffding_upper_bound(p_obs=0.9, n=1, epsilon=0.01)
    assert val_upper == 1.0

    # Normal range
    val_normal = hoeffding_upper_bound(p_obs=0.1, n=100, epsilon=0.05)
    assert 0.1 < val_normal <= 1.0

    # Negative observed -> clamped at 0.0 before margin
    val_zero = hoeffding_upper_bound(p_obs=-0.5, n=100, epsilon=0.05)
    assert 0.0 < val_zero <= 1.0


def test_hoeffding_lower_bound_clamping():
    # Observed 0.0 -> lower bound clamped to 0.0
    val_lower = hoeffding_lower_bound(p_obs=0.0, n=10, epsilon=0.05)
    assert val_lower == 0.0

    # High p_obs -> valid lower bound
    val_high = hoeffding_lower_bound(p_obs=0.8, n=100, epsilon=0.05)
    assert 0.0 <= val_high < 0.8


def test_hoeffding_tail_bound():
    # rate <= e_honest -> 1.0
    assert hoeffding_tail_bound(observed_rate=0.05, e_honest=0.05, n=100) == 1.0
    # rate > e_honest -> inside (0, 1)
    b = hoeffding_tail_bound(observed_rate=0.15, e_honest=0.05, n=100)
    assert 0.0 < b < 1.0


# ---------------------------------------------------------------------------
# 2. Serfling Bounds Finite Population Correction & k > n Rejection
# ---------------------------------------------------------------------------

def test_serfling_k_greater_than_n_raises_value_error():
    with pytest.raises(ValueError, match="cannot exceed population size"):
        serfling_upper_bound(p_obs=0.1, k=20, n=10)

    with pytest.raises(ValueError, match="cannot exceed population size"):
        serfling_lower_bound(p_obs=0.1, k=15, n=10)

    with pytest.raises(ValueError, match="cannot exceed population size"):
        serfling_tail_bound(observed_rate=0.15, e_honest=0.05, k=12, n=10)


def test_serfling_finite_population_correction_term():
    # k = 1: (1 - (1-1)/n) = 1.0 -> reduces to Hoeffding bound
    sb_k1 = serfling_upper_bound(p_obs=0.1, k=1, n=100, epsilon=0.05)
    hb_n1 = hoeffding_upper_bound(p_obs=0.1, n=1, epsilon=0.05)
    assert pytest.approx(sb_k1) == hb_n1

    # k = 50 out of n = 100: fpc = (1 - 49/100) = 0.51
    # margin should be smaller than standard uncorrected Hoeffding bound for n=50
    sb_fpc = serfling_upper_bound(p_obs=0.1, k=50, n=100, epsilon=0.05)
    hb_n50 = hoeffding_upper_bound(p_obs=0.1, n=50, epsilon=0.05)
    assert sb_fpc < hb_n50


# ---------------------------------------------------------------------------
# 3 & 4. Threshold Chain Validation & Deliberately Invalid Order
# ---------------------------------------------------------------------------

def test_threshold_chain_valid():
    ok, msg = validate_threshold_chain(e_upper=0.05, s_a=0.10, s_v=0.20, p_E=0.25)
    assert ok is True
    assert msg == ""


def test_deliberately_invalid_threshold_order_triggers_warning_and_reject():
    # Invalid order: s_a (0.25) >= s_v (0.20)
    invalid_cfg = Layer2Config(s_a=0.25, s_v=0.20, p_E=0.25, verification_mode="direct")
    positions = [_make_pos(i, is_match=True) for i in range(16)]
    session = _make_session(positions)
    ledger = ReplayLedger()

    with pytest.warns(ConfigurationWarning, match="Invalid QDS threshold ordering chain"):
        assessment = assess_session(session, config=invalid_cfg, ledger=ledger)

    # Security decision MUST REJECT and not emit a false ACCEPT
    assert assessment.threat_level == ThreatLevel.CRITICAL
    assert any("CONFIGURATION_WARNING" in f for f in assessment.findings)
    assert assessment.security_decision.startswith("REJECT")
    assert "CONFIGURATION_WARNING" in assessment.security_decision


def test_invalid_ehonest_ge_sa_triggers_warning_and_reject():
    # Invalid order: e_honest (0.15) >= s_a (0.10)
    invalid_cfg = Layer2Config(e_honest=0.15, s_a=0.10, s_v=0.20, p_E=0.25)
    positions = [_make_pos(i, is_match=True) for i in range(16)]
    session = _make_session(positions)
    ledger = ReplayLedger()

    with pytest.warns(ConfigurationWarning, match="e_upper / e_honest"):
        assessment = assess_session(session, config=invalid_cfg, ledger=ledger)

    assert assessment.threat_level == ThreatLevel.CRITICAL
    assert assessment.security_decision.startswith("REJECT")


# ---------------------------------------------------------------------------
# 5. Boundary Case where Mismatch Rate sits Exactly at s_a
# ---------------------------------------------------------------------------

def test_boundary_case_mismatch_rate_equals_sa():
    # s_a = 0.125. 2 mismatches out of 16 total positions -> Bob gets 2 / 8 = 0.25 or 1 / 8 = 0.125
    # Let's set 1 mismatch in Bob's 8 positions -> mismatch_rate = 1/8 = 0.125 exactly equal to s_a
    positions = [_make_pos(i, is_match=True) for i in range(16)]
    positions[0] = _make_pos(0, is_match=False)  # 1 mismatch in Bob's half (8 positions)
    session = _make_session(positions)

    cfg = Layer2Config(s_a=0.125, s_v=0.20, verification_mode="direct")
    ledger = ReplayLedger()

    assessment = assess_session(session, config=cfg, ledger=ledger)

    # Bob's mismatch rate is 0.125. Since s_a is 0.125, if breach check is > s_a, 0.125 is not > 0.125.
    # Check BobCharlie metrics and findings
    assert assessment.bob_charlie_metrics.direct_mismatch_rate == 0.125
    assert assessment.bob_charlie_metrics.direct_threshold_s_a == 0.125
    # Confirm exact boundary value behavior is deterministic and audited
    assert assessment.bob_charlie_metrics.direct_e_upper > 0.125


# ---------------------------------------------------------------------------
# 6. Divergence of Bob (s_a) and Charlie (s_v) Confidence-Adjusted Error Rates
# ---------------------------------------------------------------------------

def test_bob_charlie_confidence_rates_diverge_when_copies_differ():
    # Bob gets positions 0..7 (2 mismatches -> rate = 2/8 = 0.25)
    # Charlie gets positions 8..15 (0 mismatches -> rate = 0/8 = 0.0)
    positions = [_make_pos(i, is_match=True) for i in range(16)]
    positions[0] = _make_pos(0, is_match=False)
    positions[1] = _make_pos(1, is_match=False)

    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.10, s_v=0.20)

    metrics = run_bob_charlie_split(session, cfg)

    # Print proof of divergence for audit inspection
    print("\n--- PROOF OF DIVERGENCE FOR BOB (DIRECT) VS CHARLIE (FORWARDED) ---")
    print(f"Bob positions count:      {metrics.direct_positions_count}")
    print(f"Bob raw mismatch rate:     {metrics.direct_mismatch_rate:.4f}")
    print(f"Bob direct_e_upper:       {metrics.direct_e_upper:.4f}")
    print(f"Charlie positions count:  {metrics.forwarded_positions_count}")
    print(f"Charlie raw mismatch rate: {metrics.forwarded_mismatch_rate:.4f}")
    print(f"Charlie forwarded_e_upper:{metrics.forwarded_e_upper:.4f}")
    print("--------------------------------------------------------------------\n")

    assert metrics.direct_mismatch_rate != metrics.forwarded_mismatch_rate
    assert metrics.direct_e_upper != metrics.forwarded_e_upper
    assert metrics.direct_e_upper > metrics.forwarded_e_upper
