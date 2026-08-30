from __future__ import annotations

from datetime import datetime, timezone

from app.schemas.telemetry import ProtocolSessionResult
from app.layer2_threat.config import Layer2Config, default_config
from app.layer2_threat.replay_ledger import ReplayLedger, default_ledger
from app.layer2_threat.detectors import (
    run_digest_check,
    run_qber_analysis,
    run_correction_consistency_check,
    run_fidelity_analysis,
    run_replay_detection,
    run_bob_charlie_split,
)
from app.layer2_threat.schemas import (
    ThreatAssessment,
    ThreatLevel,
    ThreatCategory,
    VerificationMode,
    IdentityAuthorizationResult,
)


def assess_session(
    session: ProtocolSessionResult,
    config: Layer2Config | None = None,
    ledger: ReplayLedger | None = None,
    expected_sender_id: str | None = None,
    expected_recipient_id: str | None = None,
    requested_verifier_id: str | None = None,
) -> ThreatAssessment:
    if config is None:
        config = default_config
    if ledger is None:
        ledger = default_ledger

    assessed_at = datetime.now(timezone.utc).isoformat()
    findings: list[str] = []

    impersonation_detected = False
    unauthorized_verifier_detected = False

    if requested_verifier_id is not None and requested_verifier_id != session.recipient_id:
        unauthorized_verifier_detected = True

    if expected_sender_id is not None and expected_sender_id != session.sender_id:
        impersonation_detected = True

    if expected_recipient_id is not None and expected_recipient_id != session.recipient_id:
        impersonation_detected = True

    is_authorized = not (impersonation_detected or unauthorized_verifier_detected)

    identity_authorization = IdentityAuthorizationResult(
        is_authorized=is_authorized,
        expected_sender_id=expected_sender_id,
        expected_recipient_id=expected_recipient_id,
        requested_verifier_id=requested_verifier_id,
        actual_sender_id=session.sender_id,
        actual_recipient_id=session.recipient_id,
        impersonation_detected=impersonation_detected,
        unauthorized_verifier_detected=unauthorized_verifier_detected,
    )

    digest_result = run_digest_check(session)
    replay_result = run_replay_detection(session, ledger)
    correction_result = run_correction_consistency_check(session, config)
    qber_result = run_qber_analysis(session, config)
    fidelity_result = run_fidelity_analysis(session, config)
    bob_charlie_result = run_bob_charlie_split(session, config)

    threat_level = ThreatLevel.CLEAN
    threat_category = ThreatCategory.NONE
    triggered_categories: list[ThreatCategory] = []

    if unauthorized_verifier_detected:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.UNAUTHORIZED_VERIFICATION)
        findings.append(
            f"UNAUTHORIZED_VERIFICATION [CRITICAL] — verifier '{requested_verifier_id}' is not the intended packet recipient '{session.recipient_id}'."
        )

    if impersonation_detected:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.IMPERSONATION)
        if expected_sender_id is not None and expected_sender_id != session.sender_id:
            findings.append(
                f"IMPERSONATION [CRITICAL] — expected sender '{expected_sender_id}' does not match packet sender '{session.sender_id}'."
            )
        if expected_recipient_id is not None and expected_recipient_id != session.recipient_id:
            findings.append(
                f"IMPERSONATION [CRITICAL] — expected recipient '{expected_recipient_id}' does not match packet recipient '{session.recipient_id}'."
            )

    if replay_result.is_replay:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.REPLAY_ATTACK)
        findings.append(
            f"REPLAY_ATTACK [CRITICAL] — fingerprint '{replay_result.fingerprint}' already recorded in the replay ledger."
        )

    if not digest_result.digest_matches:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.PAYLOAD_DIGEST_MISMATCH)
        findings.append(
            f"PAYLOAD_DIGEST_MISMATCH [CRITICAL] — SHA-256 digest mismatch. Recorded: {digest_result.recorded_digest}, Recomputed: {digest_result.recomputed_digest}."
        )

    if correction_result.flag_raised:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.CORRECTION_TAMPERING)
        findings.append(
            f"CORRECTION_TAMPERING [CRITICAL] — {correction_result.inconsistency_count} position(s) have expected_correction != actual_correction."
        )

    if qber_result.exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.SUSPICIOUS
        triggered_categories.append(ThreatCategory.QBER_ANOMALY)
        findings.append(
            f"QBER_ANOMALY [SUSPICIOUS] — observed mismatch rate {qber_result.global_mismatch_rate:.4f} exceeds q_alert threshold {qber_result.alert_threshold:.4f}."
        )

    if fidelity_result.flag_raised:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.SUSPICIOUS
        triggered_categories.append(ThreatCategory.BELL_INTEGRITY_VIOLATION)
        findings.append(
            f"BELL_INTEGRITY_VIOLATION [SUSPICIOUS] — {len(fidelity_result.low_fidelity_positions)} position(s) with fidelity < f_floor={fidelity_result.fidelity_floor}."
        )

    if bob_charlie_result.direct_exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.ADVISORY
        findings.append(
            f"BOB_THRESHOLD_BREACH [ADVISORY] — Bob (direct) mismatch rate {bob_charlie_result.direct_mismatch_rate:.4f} > s_a={bob_charlie_result.direct_threshold_s_a}."
        )

    if bob_charlie_result.forwarded_exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.ADVISORY
        findings.append(
            f"CHARLIE_THRESHOLD_BREACH [ADVISORY] — Charlie (forwarded) mismatch rate {bob_charlie_result.forwarded_mismatch_rate:.4f} > s_v={bob_charlie_result.forwarded_threshold_s_v}."
        )

    if len(triggered_categories) > 1:
        threat_category = ThreatCategory.COMBINED
    elif len(triggered_categories) == 1:
        threat_category = triggered_categories[0]
    else:
        threat_category = ThreatCategory.NONE

    from app.layer2_threat.bounds import validate_threshold_chain

    mode = VerificationMode(config.verification_mode)

    if mode == VerificationMode.DIRECT:
        rate_for_decision = bob_charlie_result.direct_mismatch_rate
        confidence_upper_bound_for_decision = bob_charlie_result.direct_confidence_upper_bound
        threshold_for_decision = config.s_a
        threshold_label = "s_a"
        breach_for_decision = bob_charlie_result.direct_exceeds_threshold
    elif mode == VerificationMode.FORWARDED:
        rate_for_decision = bob_charlie_result.forwarded_mismatch_rate
        confidence_upper_bound_for_decision = bob_charlie_result.forwarded_confidence_upper_bound
        threshold_for_decision = config.s_v
        threshold_label = "s_v"
        breach_for_decision = bob_charlie_result.forwarded_exceeds_threshold
    else:
        raise ValueError(f"Unknown verification_mode: {config.verification_mode!r}")

    chain_valid, chain_msg = validate_threshold_chain(
        e_upper=config.e_honest,
        s_a=config.s_a,
        s_v=config.s_v,
        p_E=config.p_E,
    )

    if not chain_valid:
        threat_level = ThreatLevel.CRITICAL
        findings.append(f"CONFIGURATION_WARNING [CRITICAL] — {chain_msg}")

    hard_reject = (
        not is_authorized
        or not digest_result.digest_matches
        or replay_result.is_replay
        or correction_result.flag_raised
        or not chain_valid
    )

    if hard_reject or breach_for_decision:
        reject_reasons = [f.split(" [")[0] for f in findings]
        if not reject_reasons and not chain_valid:
            reject_reasons = ["CONFIGURATION_WARNING"]
        decision = (
            f"REJECT — verification_mode={mode.value}, "
            f"threshold={threshold_label}={threshold_for_decision}, "
            f"mismatch_rate={rate_for_decision:.4f}, "
            f"confidence_upper_bound={confidence_upper_bound_for_decision:.4f}; "
            f"reason(s): {', '.join(reject_reasons)}"
        )
    else:
        decision = (
            f"ACCEPT — verification_mode={mode.value}, "
            f"threshold={threshold_label}={threshold_for_decision}, "
            f"mismatch_rate={rate_for_decision:.4f}, "
            f"confidence_upper_bound={confidence_upper_bound_for_decision:.4f}"
        )

    return ThreatAssessment(
        session_id=session.session_id,
        signature_block_id=session.signature_block_id,
        sender_id=session.sender_id,
        recipient_id=session.recipient_id,
        sequence_number=session.sequence_number,
        assessed_at=assessed_at,
        verification_mode=mode,
        s_a_used=config.s_a,
        s_v_used=config.s_v,
        p_E_used=config.p_E,
        e_honest_used=config.e_honest,
        digest_check=digest_result,
        qber_analysis=qber_result,
        correction_consistency=correction_result,
        fidelity_analysis=fidelity_result,
        replay_detection=replay_result,
        identity_authorization=identity_authorization,
        bob_charlie_metrics=bob_charlie_result,
        threat_level=threat_level,
        threat_category=threat_category,
        findings=findings,
        security_decision=decision,
    )
