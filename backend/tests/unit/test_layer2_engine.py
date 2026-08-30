from __future__ import annotations

import hashlib
import pytest

from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.schemas.telemetry import ProtocolSessionResult
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.engine import assess_session
from app.layer2_threat.schemas import ThreatLevel, ThreatCategory, VerificationMode


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
    message_digest: str | None = None,
    message: str = "MSG",
    sender_id: str = "alice",
    recipient_id: str = "bob",
) -> ProtocolSessionResult:
    if message_digest is None:
        message_digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
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
        sender_id=sender_id,
        recipient_id=recipient_id,
        message=message,
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
    assert result.identity_authorization.is_authorized is True


def test_security_decision_declares_verification_mode_direct():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "verification_mode=direct" in result.security_decision
    assert "s_a=0.1" in result.security_decision
    assert "confidence_upper_bound=" in result.security_decision


def test_security_decision_declares_verification_mode_forwarded():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="forwarded", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "verification_mode=forwarded" in result.security_decision
    assert "s_v=0.2" in result.security_decision
    assert "confidence_upper_bound=" in result.security_decision


def test_cross_wire_prevention_direct_mode_never_uses_s_v():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(16)]
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", s_a=0.10, s_v=0.20)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert "s_a=" in result.security_decision
    assert "threshold=s_v" not in result.security_decision


def test_cross_wire_prevention_forwarded_mode_never_uses_s_a():
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
    assert result.threat_category in (ThreatCategory.PAYLOAD_DIGEST_MISMATCH, ThreatCategory.COMBINED)
    assert "REJECT" in result.security_decision
    assert any("PAYLOAD_DIGEST_MISMATCH" in f for f in result.findings)


def test_unauthorized_verifier_produces_critical():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, recipient_id="bob")
    cfg = Layer2Config(verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger, requested_verifier_id="eve")

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category in (ThreatCategory.UNAUTHORIZED_VERIFICATION, ThreatCategory.COMBINED)
    assert result.identity_authorization.unauthorized_verifier_detected is True
    assert result.identity_authorization.is_authorized is False
    assert "REJECT" in result.security_decision
    assert any("UNAUTHORIZED_VERIFICATION" in f for f in result.findings)


def test_impersonation_sender_mismatch_produces_critical():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, sender_id="alice")
    cfg = Layer2Config(verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger, expected_sender_id="mallory")

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category in (ThreatCategory.IMPERSONATION, ThreatCategory.COMBINED)
    assert result.identity_authorization.impersonation_detected is True
    assert result.identity_authorization.is_authorized is False
    assert "REJECT" in result.security_decision
    assert any("IMPERSONATION" in f for f in result.findings)


def test_replay_attack_produces_critical():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, session_id="repl", signature_block_id="b",
                             nonce="n", sequence_number=1)
    cfg = Layer2Config(verification_mode="direct")
    assess_session(session, config=cfg, ledger=ledger)
    result = assess_session(session, config=cfg, ledger=ledger)

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
    positions = (
        [_make_position(i, is_match=False, final_measured_bit=1) for i in range(12)]
        + [_make_position(i + 12) for i in range(4)]
    )
    session = _make_session(positions)
    cfg = Layer2Config(verification_mode="direct", q_alert=0.11, e_honest=0.0)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.CRITICAL)
    assert any("QBER" in f for f in result.findings)


def test_verdict_includes_provenance_fields():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, session_id="mysession")
    cfg = Layer2Config()
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.session_id == "mysession"
    assert result.sender_id == "alice"
    assert result.recipient_id == "bob"


def test_verdict_includes_config_snapshot():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config(s_a=0.12, s_v=0.20, e_honest=0.01, p_E=0.25, verification_mode="direct")
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.s_a_used == pytest.approx(0.12)
    assert result.s_v_used == pytest.approx(0.20)
    assert result.e_honest_used == pytest.approx(0.01)
    assert result.verification_mode == VerificationMode.DIRECT


def test_combined_category_when_multiple_detectors_fire():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions, message_digest="0" * 64, session_id="combo",
                             signature_block_id="cb", nonce="cn", sequence_number=1)
    cfg = Layer2Config(verification_mode="direct")
    assess_session(session, config=cfg, ledger=ledger)
    result = assess_session(session, config=cfg, ledger=ledger)

    assert result.threat_level == ThreatLevel.CRITICAL
    assert result.threat_category == ThreatCategory.COMBINED


def test_disclaimer_always_present():
    ledger = ReplayLedger()
    positions = [_make_position(i) for i in range(8)]
    session = _make_session(positions)
    cfg = Layer2Config()
    result = assess_session(session, config=cfg, ledger=ledger)
    assert "software simulation" in result.simulation_disclaimer.lower()


def test_boundary_value_exactly_at_threshold():
    cfg = Layer2Config(verification_mode="direct", s_a=0.20, s_v=0.22, p_E=0.25, e_honest=0.0)
    
    positions = []
    for i in range(10):
        is_match = not (i == 0)
        positions.append(_make_position(i, is_match=is_match))
        
    session = _make_session(positions)
    ledger = ReplayLedger()
    assessment = assess_session(session, config=cfg, ledger=ledger)
    
    bc_metrics = assessment.bob_charlie_metrics
    assert bc_metrics.direct_mismatch_rate == 0.20
    assert bc_metrics.direct_threshold_s_a == 0.20
    assert bc_metrics.direct_exceeds_threshold is False
    
    assert not any("BOB_THRESHOLD_BREACH" in f for f in assessment.findings)
