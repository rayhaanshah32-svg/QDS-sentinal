"""
Unit tests – Layer 2 Threat Assessment Engine

Tests the engine's priority ordering, verdict logic, and security decision text.
"""

import pytest

from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.schemas.telemetry import ProtocolSessionResult
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.engine import assess_session
from app.layer2_threat.schemas import ThreatLevel, ThreatCategory, VerificationMode


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_position(index: int, is_match: bool = True, fidelity: float = 1.0,
                   expected_correction: str = "I", actual_correction: str = "I",
                   final_measured_bit: int = 0, expected_bit: int = 0) -> SignaturePositionRecord:
    return SignaturePositionRecord(
        index=index,
        pauli_basis="X",
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


def _make_session(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
    session_id: str = "sess",
    signature_block_id: str = "blk",
    nonce: str = "nonce",
    sequence_number: int = 1,
    message_digest: str = "a" * 64,
) -> ProtocolSessionResult:
    total = len(positions)
    matching = sum(1 for p in positions if p.is_match)
    mismatching = total - matching
    summary = BasicVerificationSummary(
        total_positions=total,
        matching_positions=matching,
        mismatching_positions=mismatching,
        mismatch_count=mismatching,
        mismatch_rate=mismatching / total if total > 0 else 0.0,
        average_fidelity=sum(p.fidelity for p in positions) / total if total > 0 else 0.0,
        basis_distribution={"X": total, "Y": 0, "Z": 0},
        correction_distribution={"I": total, "X": 0, "Z": 0, "XZ": 0},
        digest_matches=digest_matches,
        is_perfect_match=(mismatching == 0) and digest_matches,
    )
    return ProtocolSessionResult(
        protocol_version="1.0.0",
        session_id=session_id,
        signature_block_id=signature_block_id,
        sender_id="alice",
        recipient_id="bob",
        message="MSG",
        message_digest=message_digest,
        nonce=nonce,
        sequence_number=sequence_number,
        created_at="2026-08-30T00:00:00+00:00",
        configuration={},
        signature_positions=positions,
        teleportation_events=[],
        measurement_events=[],
        verification_summary=summary,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_clean_session_produces_clean_verdict():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.threat_level == ThreatLevel.CLEAN
    assert result.threat_category == ThreatCategory.NONE
    assert result.findings == []
    assert "ACCEPT" in result.security_decision


def test_security_decision_declares_verification_mode_direct():
    """MUST: decision string references verification_mode=direct and s_a."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "verification_mode=direct" in result.security_decision
    assert "s_a=0.1" in result.security_decision


def test_security_decision_declares_verification_mode_forwarded():
    """MUST: decision string references verification_mode=forwarded and s_v."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="forwarded", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "verification_mode=forwarded" in result.security_decision
    assert "s_v=0.2" in result.security_decision


def test_cross_wire_prevention_direct_mode_never_uses_s_v():
    """
    Cross-wire test (Section 11 requirement):
    In direct mode, s_v must NEVER appear as the evaluated threshold
    in the security_decision.
    """
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    # The decision must reference s_a and must NOT use s_v as the evaluated threshold
    assert "s_a=" in result.security_decision
    # s_v should not appear as the primary threshold label in the decision
    assert "threshold=s_v" not in result.security_decision


def test_cross_wire_prevention_forwarded_mode_never_uses_s_a():
    """
    Cross-wire test (Section 11 requirement):
    In forwarded mode, s_a must NEVER appear as the evaluated threshold
    in the security_decision.
    """
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="forwarded", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "s_v=" in result.security_decision
    assert "threshold=s_a" not in result.security_decision


def test_digest_forgery_produces_critical():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, digest_matches=False, message_digest="0" * 64)
    cfg = Layer2Config(verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category in (ThreatCategory.DIGEST_FORGERY, ThreatCategory.COMBINED)
    assert "REJECT" in result.security_decision
    assert any("DIGEST_FORGERY" in f for f in result.findings)


def test_replay_attack_produces_critical():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, session_id="repl", signature_block_id="b",
                             nonce="n", sequence_number=1)
    cfg = Layer2Config(verification_mode="direct")
    assess_session(session, config=cfg, ledger=ledger)  # first call
    result = assess_session(session, config=cfg, ledger=ledger)  # replay

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category in (ThreatCategory.REPLAY_ATTACK, ThreatCategory.COMBINED)
    assert "REJECT" in result.security_decision
    assert any("REPLAY" in f for f in result.findings)


def test_correction_tampering_produces_critical():
    ledger = ReplayLedger()
    positions = [
        _make_position(0, expected_correction="I", actual_correction="X"),
        _make_position(1),
    ]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", c_tamper_rate=0.0)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.threat_level == ThreatLevel.CRITICAL
    assert any("CORRECTION_TAMPERING" in f for f in result.findings)
    assert "REJECT" in result.security_decision


def test_qber_anomaly_produces_suspicious():
    ledger = ReplayLedger()
    # 12/16 = 75% mismatch rate — well above q_alert=0.11
    positions = (
        [_make_position(i, is_match=False, final_measured_bit=1) for i in range(12)]
        + [_make_position(i + 12) for i in range(4)]
    )
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", q_alert=0.11, e_honest=0.0)
    result = assess_session(session, config=cfg, ledger=ledger)

    # At minimum SUSPICIOUS (could be CRITICAL if other detectors also fire)
    assert result.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.CRITICAL)
    assert any("QBER" in f for f in result.findings)


def test_verdict_includes_provenance_fields():
    """ThreatAssessment must forward session_id, sender_id, recipient_id."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, session_id="mysession")
    cfg = Layer2Config()
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.session_id == "mysession"
    assert result.sender_id == "alice"
    assert result.recipient_id == "bob"


def test_verdict_includes_config_snapshot():
    """ThreatAssessment must record the thresholds used."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.12, s_v=0.25, e_honest=0.01, verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.s_a_used == pytest.approx(0.12)
    assert result.s_v_used == pytest.approx(0.25)
    assert result.e_honest_used == pytest.approx(0.01)
    assert result.verification_mode == VerificationMode.DIRECT


def test_combined_category_when_multiple_detectors_fire():
    """If both replay and digest fail, category should be COMBINED."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, digest_matches=False, session_id="combo",
                             signature_block_id="cb", nonce="cn", sequence_number=1)
    cfg = Layer2Config(verification_mode="direct")
    assess_session(session, config=cfg, ledger=ledger)  # pre-populate ledger
    result = assess_session(session, config=cfg, ledger=ledger)  # replay + forgery

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category == ThreatCategory.COMBINED


def test_disclaimer_always_present():
    """Scientific disclaimer must always be in the response."""
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config()
    result = assess_session(session, config=cfg, ledger=ledger)
    assert "software simulation" in result.simulation_disclaimer.lower()


def test_boundary_value_exactly_at_threshold():
    """Test boundary condition where mismatch rate is EXACTLY at the threshold."""
    # 10 positions, Bob evaluates even indices (0, 2, 4, 6, 8) -> 5 positions
    # We want 1 mismatch out of 5 for Bob -> mismatch_rate = 0.20
    # Set threshold s_a = 0.20 exactly.
    # Exceeds threshold is strictly > (greater than), so exactly equal should be False.
    cfg = Layer2Config(verification_mode="direct", s_a=0.20, s_v=0.30, e_honest=0.0)
    
    positions = []
    for i in range(10):
        # Even index 0 is mismatched, others match -> 1 mismatch on Bob's side
        is_match = not (i == 0)
        positions.append(_make_position(i, is_match=is_match))
        
    session = _make_session(positions)
    ledger = ReplayLedger()
    assessment = assess_session(session, config=cfg, ledger=ledger)
    
    bc_metrics = assessment.bob_charlie_metrics
    assert bc_metrics.direct_mismatch_rate == 0.20
    assert bc_metrics.direct_threshold_s_a == 0.20
    assert bc_metrics.direct_exceeds_threshold is False
    
    # Ensure BOB_THRESHOLD_BREACH is not triggered
    assert not any("BOB_THRESHOLD_BREACH" in f for f in assessment.findings)
