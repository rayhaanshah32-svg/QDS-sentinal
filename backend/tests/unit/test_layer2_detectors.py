from __future__ import annotations

import hashlib
import math
import pytest

from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.schemas.telemetry import (
    ProtocolSessionResult,
    TeleportationEvent,
    MeasurementEvent,
)
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.detectors import (
    run_digest_check,
    run_qber_analysis,
    run_correction_consistency_check,
    run_fidelity_analysis,
    run_replay_detection,
    run_bob_charlie_split,
)


def _make_position(
    index: int,
    basis: str = "X",
    expected_correction: str = "I",
    actual_correction: str = "I",
    fidelity: float = 1.0,
    is_match: bool = True,
    final_measured_bit: int = 0,
    expected_bit: int = 0,
) -> SignaturePositionRecord:
    return SignaturePositionRecord(
        index=index,
        pauli_basis=basis,
        encoded_bit=expected_bit,
        prepared_state_label="|+>",
        bell_state="PHI_PLUS",
        bell_measurement_bits="00",
        expected_correction=expected_correction,
        actual_correction=actual_correction,
        final_measured_bit=final_measured_bit,
        expected_bit=expected_bit,
        fidelity=fidelity,
        is_match=is_match,
    )


def _make_summary(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
) -> BasicVerificationSummary:
    total = len(positions)
    matching = sum(1 for p in positions if p.is_match)
    mismatching = total - matching
    avg_fidelity = sum(p.fidelity for p in positions) / total if total > 0 else 0.0
    return BasicVerificationSummary(
        total_positions=total,
        matching_positions=matching,
        mismatching_positions=mismatching,
        mismatch_count=mismatching,
        mismatch_rate=mismatching / total if total > 0 else 0.0,
        average_fidelity=avg_fidelity,
        basis_distribution={"X": total, "Y": 0, "Z": 0},
        correction_distribution={"I": total, "X": 0, "Z": 0, "XZ": 0},
        digest_matches=digest_matches,
        is_perfect_match=(mismatching == 0) and digest_matches,
    )


def _make_session(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
    session_id: str = "test-session",
    signature_block_id: str = "test-block",
    nonce: str = "test-nonce",
    sequence_number: int = 1,
    message_digest: str | None = None,
    message: str = "TEST_MESSAGE",
) -> ProtocolSessionResult:
    if message_digest is None:
        message_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return ProtocolSessionResult(
        protocol_version="1.0.0",
        session_id=session_id,
        signature_block_id=signature_block_id,
        sender_id="alice",
        recipient_id="bob",
        message=message,
        message_digest=message_digest,
        nonce=nonce,
        sequence_number=sequence_number,
        created_at="2026-08-30T00:00:00+00:00",
        configuration={},
        signature_positions=positions,
        teleportation_events=[],
        measurement_events=[],
        verification_summary=_make_summary(positions, digest_matches=digest_matches),
    )


def test_digest_check_pass():
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, digest_matches=True)
    result = run_digest_check(session)
    assert result.digest_matches is True
    assert result.is_authoritative is True
    assert result.recorded_digest == session.message_digest
    assert result.recomputed_digest == session.message_digest


def test_digest_check_fail():
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, digest_matches=False, message_digest="0" * 64)
    result = run_digest_check(session)
    assert result.digest_matches is False
    assert result.recorded_digest == "0" * 64
    assert result.recomputed_digest != "0" * 64


def test_qber_basis_wise_breakdown():
    positions = [
        _make_position(0, basis="X", is_match=True),
        _make_position(1, basis="X", is_match=False),
        _make_position(2, basis="Y", is_match=True),
        _make_position(3, basis="Z", is_match=False),
    ]
    session = _make_session(positions)
    cfg = Layer2Config(q_alert=0.11, e_honest=0.0, min_basis_samples=2)
    result = run_qber_analysis(session, cfg)

    assert result.global_mismatch_rate == 0.5
    assert result.qber_x.sample_count == 2
    assert result.qber_x.mismatch_count == 1
    assert result.qber_x.rate == 0.5
    assert result.qber_x.insufficient_samples is False

    assert result.qber_y.sample_count == 1
    assert result.qber_y.mismatch_count == 0
    assert result.qber_y.rate == 0.0
    assert result.qber_y.insufficient_samples is True

    assert result.qber_z.sample_count == 1
    assert result.qber_z.mismatch_count == 1
    assert result.qber_z.rate == 1.0
    assert result.qber_z.insufficient_samples is True


def test_qber_clean_session_no_alert():
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(q_alert=0.11, e_honest=0.0)
    result = run_qber_analysis(session, cfg)
    assert result.observed_mismatch_rate == 0.0
    assert result.global_mismatch_rate == 0.0
    assert result.exceeds_threshold is False
    assert result.hoeffding_false_positive_bound == 1.0


def test_qber_above_alert_threshold():
    positions = (
        [_make_position(i, is_match=False, final_measured_bit=1) for i in range(4)]
        + [_make_position(i + 4) for i in range(4)]
    )
    session = _make_session(positions)
    cfg = Layer2Config(q_alert=0.11, e_honest=0.0)
    result = run_qber_analysis(session, cfg)
    assert result.exceeds_threshold is True
    assert result.global_mismatch_rate == pytest.approx(0.5)
    expected_bound = math.exp(-2 * 8 * (0.5 ** 2))
    assert abs(result.hoeffding_false_positive_bound - expected_bound) < 1e-10


def test_qber_hoeffding_uses_e_honest_correctly():
    positions = (
        [_make_position(i, is_match=False, final_measured_bit=1) for i in range(4)]
        + [_make_position(i + 4) for i in range(6)]
    )
    session = _make_session(positions)
    cfg = Layer2Config(q_alert=0.11, e_honest=0.3)
    result = run_qber_analysis(session, cfg)
    n = 10
    rate = 0.4
    gap = rate - 0.3
    expected = math.exp(-2 * n * (gap ** 2))
    assert abs(result.hoeffding_false_positive_bound - expected) < 1e-10


def test_correction_consistency_all_match():
    positions = [_make_position(i, expected_correction="I", actual_correction="I") for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config(c_tamper_rate=0.0)
    result = run_correction_consistency_check(session, cfg)
    assert result.inconsistency_count == 0
    assert result.flag_raised is False


def test_correction_consistency_detects_tampering():
    positions = [
        _make_position(0, expected_correction="I", actual_correction="X"),
        _make_position(1, expected_correction="X", actual_correction="X"),
        _make_position(2, expected_correction="Z", actual_correction="I"),
    ]
    session = _make_session(positions)
    cfg = Layer2Config(c_tamper_rate=0.0)
    result = run_correction_consistency_check(session, cfg)
    assert result.inconsistency_count == 2
    assert 0 in result.inconsistent_positions
    assert 2 in result.inconsistent_positions
    assert result.flag_raised is True


def test_correction_consistency_case_insensitive():
    positions = [_make_position(0, expected_correction="xz", actual_correction="XZ")]
    session = _make_session(positions)
    cfg = Layer2Config(c_tamper_rate=0.0)
    result = run_correction_consistency_check(session, cfg)
    assert result.inconsistency_count == 0


def test_fidelity_clean():
    positions = [_make_position(i, fidelity=1.0) for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config(f_floor=0.999)
    result = run_fidelity_analysis(session, cfg)
    assert result.flag_raised is False
    assert result.min_fidelity == pytest.approx(1.0)
    assert result.average_fidelity == pytest.approx(1.0)


def test_fidelity_flags_low_positions():
    positions = [_make_position(i, fidelity=0.5) for i in range(3)]
    positions += [_make_position(i + 3, fidelity=1.0) for i in range(5)]
    session = _make_session(positions)
    cfg = Layer2Config(f_floor=0.999)
    result = run_fidelity_analysis(session, cfg)
    assert result.flag_raised is True
    assert len(result.low_fidelity_positions) == 3
    assert result.min_fidelity == pytest.approx(0.5)


def test_fidelity_empty_positions():
    session = _make_session([])
    cfg = Layer2Config(f_floor=0.999)
    result = run_fidelity_analysis(session, cfg)
    assert result.flag_raised is False
    assert result.average_fidelity == 0.0


def test_replay_first_call_not_replay():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(4)]
    session = _make_session(positions, session_id="s1", signature_block_id="b1",
                             nonce="n1", sequence_number=1)
    result = run_replay_detection(session, ledger)
    assert result.is_replay is False
    assert "s1|b1|n1|1" == result.fingerprint


def test_replay_second_call_is_replay():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(4)]
    session = _make_session(positions, session_id="s2", signature_block_id="b2",
                             nonce="n2", sequence_number=1)
    run_replay_detection(session, ledger)
    result = run_replay_detection(session, ledger)
    assert result.is_replay is True


def test_bob_charlie_split_uses_s_a_for_direct_only():
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.10, s_v=0.20)

    result = run_bob_charlie_split(session, cfg)

    assert result.direct_threshold_s_a == cfg.s_a
    assert result.forwarded_threshold_s_v == cfg.s_v
    assert result.direct_threshold_s_a != result.forwarded_threshold_s_v


def test_bob_charlie_split_correct_counts():
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.10, s_v=0.20, forwarding_split=0.5)
    result = run_bob_charlie_split(session, cfg)
    assert result.direct_positions_count == 8
    assert result.forwarded_positions_count == 8


def test_bob_charlie_split_odd_n():
    positions = [_make_position(i) for i in range(7)]
    session = _make_session(positions)
    cfg = Layer2Config(forwarding_split=0.5)
    result = run_bob_charlie_split(session, cfg)
    assert result.direct_positions_count == 4
    assert result.forwarded_positions_count == 3


def test_bob_charlie_split_clean_no_breach():
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.10, s_v=0.20)
    result = run_bob_charlie_split(session, cfg)
    assert result.direct_exceeds_threshold is False
    assert result.forwarded_exceeds_threshold is False
    assert result.direct_confidence_upper_bound >= 0.0
    assert result.forwarded_confidence_upper_bound >= 0.0


def test_bob_charlie_separate_rates_never_collapsed():
    positions = (
        [_make_position(i, is_match=False, final_measured_bit=1) for i in range(8)]
        + [_make_position(i + 8, is_match=True) for i in range(8)]
    )
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.10, s_v=0.20, forwarding_split=0.5)
    result = run_bob_charlie_split(session, cfg)

    assert result.direct_mismatch_rate == pytest.approx(1.0)
    assert result.forwarded_mismatch_rate == pytest.approx(0.0)
    assert result.direct_mismatch_rate != result.forwarded_mismatch_rate

