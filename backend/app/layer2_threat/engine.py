"""
Layer 2 – Threat Assessment Engine

The engine coordinates all detectors, applies the priority ordering
(deterministic first, statistical second), and emits a ThreatAssessment.

Priority rules
--------------
1. REPLAY (deterministic) → if detected, verdict = CRITICAL immediately.
2. DIGEST_FORGERY (deterministic) → if detected, verdict = CRITICAL.
3. CORRECTION_TAMPERING (deterministic) → if detected, verdict = CRITICAL.
4. QBER_ANOMALY (statistical advisory) → if rate > q_alert, SUSPICIOUS.
5. BELL_INTEGRITY (fidelity floor breach) → SUSPICIOUS.
6. If only Bob/Charlie threshold breached but not above → ADVISORY.
7. CLEAN if none of the above.

Security decision rules
-----------------------
- verification_mode MUST be declared in the decision text.
- In "direct" mode the threshold used is s_a (Bob).
- In "forwarded" mode the threshold used is s_v (Charlie).
- Cross-wiring is prohibited; a unit test enforces this constraint.
- The decision string always reads:
    "ACCEPT — verification_mode=direct, threshold=s_a=0.10, mismatch_rate=0.00"
    "REJECT — verification_mode=forwarded, threshold=s_v=0.20, mismatch_rate=0.25; reason: QBER_ANOMALY"
"""

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
)


def assess_session(
    session: ProtocolSessionResult,
    config: Layer2Config | None = None,
    ledger: ReplayLedger | None = None,
) -> ThreatAssessment:
    """
    Run all Layer 2 detectors against a ProtocolSessionResult and produce
    a ThreatAssessment.

    Parameters
    ----------
    session : ProtocolSessionResult
        The Layer 1 output to evaluate.  Never modified.
    config : Layer2Config, optional
        Threshold and mode configuration.  Defaults to default_config.
    ledger : ReplayLedger, optional
        Replay ledger instance.  Defaults to default_ledger.

    Returns
    -------
    ThreatAssessment
        Complete structured threat report.
    """
    if config is None:
        config = default_config
    if ledger is None:
        ledger = default_ledger

    assessed_at = datetime.now(timezone.utc).isoformat()
    findings: list[str] = []

    # ------------------------------------------------------------------
    # Run all detectors
    # ------------------------------------------------------------------
    digest_result = run_digest_check(session)
    replay_result = run_replay_detection(session, ledger)
    correction_result = run_correction_consistency_check(session, config)
    qber_result = run_qber_analysis(session, config)
    fidelity_result = run_fidelity_analysis(session, config)
    bob_charlie_result = run_bob_charlie_split(session, config)

    # ------------------------------------------------------------------
    # Determine threat level and category (priority-ordered)
    # ------------------------------------------------------------------
    threat_level = ThreatLevel.CLEAN
    threat_category = ThreatCategory.NONE
    triggered_categories: list[str] = []

    # --- Priority 1: Replay (deterministic) ---
    if replay_result.is_replay:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.REPLAY_ATTACK)
        findings.append(
            f"REPLAY_ATTACK [CRITICAL] — fingerprint '{replay_result.fingerprint}' "
            "already recorded in the replay ledger. Deterministic check."
        )

    # --- Priority 2: Digest forgery (deterministic) ---
    if not digest_result.digest_matches:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.DIGEST_FORGERY)
        findings.append(
            f"DIGEST_FORGERY [CRITICAL] — SHA-256 digest mismatch. "
            f"Recorded digest: {digest_result.recorded_digest}. "
            "Deterministic check; overrides all statistical findings."
        )

    # --- Priority 3: Correction tampering (deterministic) ---
    if correction_result.flag_raised:
        threat_level = ThreatLevel.CRITICAL
        triggered_categories.append(ThreatCategory.CORRECTION_TAMPERING)
        findings.append(
            f"CORRECTION_TAMPERING [CRITICAL] — {correction_result.inconsistency_count} "
            f"position(s) have expected_correction != actual_correction "
            f"(rate={correction_result.inconsistency_rate:.4f} > threshold={correction_result.tamper_threshold}). "
            f"Affected indices: {correction_result.inconsistent_positions}. Deterministic check."
        )

    # --- Priority 4: QBER anomaly (statistical advisory) ---
    if qber_result.exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.SUSPICIOUS
        triggered_categories.append(ThreatCategory.QBER_ANOMALY)
        findings.append(
            f"QBER_ANOMALY [SUSPICIOUS] — observed mismatch rate "
            f"{qber_result.observed_mismatch_rate:.4f} exceeds q_alert threshold "
            f"{qber_result.alert_threshold:.4f}. "
            f"Hoeffding false-positive bound: {qber_result.hoeffding_false_positive_bound:.4e} "
            f"(n={qber_result.n_positions}, e_honest={config.e_honest}). "
            "Statistical evidence only — not a standalone security guarantee."
        )

    # --- Priority 5: Bell integrity / fidelity (statistical) ---
    if fidelity_result.flag_raised:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.SUSPICIOUS
        triggered_categories.append(ThreatCategory.BELL_INTEGRITY_VIOLATION)
        findings.append(
            f"BELL_INTEGRITY_VIOLATION [SUSPICIOUS] — "
            f"{len(fidelity_result.low_fidelity_positions)} position(s) with fidelity "
            f"< f_floor={fidelity_result.fidelity_floor} "
            f"(min_fidelity={fidelity_result.min_fidelity:.6f}). "
            f"Affected indices: {fidelity_result.low_fidelity_positions}. "
            "Statistical indicator — may signal channel interference."
        )

    # --- Advisory: Bob/Charlie threshold breach ---
    if bob_charlie_result.direct_exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.ADVISORY
        findings.append(
            f"BOB_THRESHOLD_BREACH [ADVISORY] — Bob (direct) mismatch rate "
            f"{bob_charlie_result.direct_mismatch_rate:.4f} > s_a={bob_charlie_result.direct_threshold_s_a}. "
            f"({bob_charlie_result.direct_mismatch_count}/{bob_charlie_result.direct_positions_count} positions). "
            "verification_mode=direct evaluated against s_a."
        )

    if bob_charlie_result.forwarded_exceeds_threshold:
        if threat_level == ThreatLevel.CLEAN:
            threat_level = ThreatLevel.ADVISORY
        findings.append(
            f"CHARLIE_THRESHOLD_BREACH [ADVISORY] — Charlie (forwarded) mismatch rate "
            f"{bob_charlie_result.forwarded_mismatch_rate:.4f} > s_v={bob_charlie_result.forwarded_threshold_s_v}. "
            f"({bob_charlie_result.forwarded_mismatch_count}/{bob_charlie_result.forwarded_positions_count} positions). "
            "verification_mode=forwarded evaluated against s_v."
        )

    # --- Consolidate threat category ---
    if len(triggered_categories) > 1:
        threat_category = ThreatCategory.COMBINED
    elif len(triggered_categories) == 1:
        threat_category = triggered_categories[0]
    else:
        threat_category = ThreatCategory.NONE

    # ------------------------------------------------------------------
    # Security decision (must declare verification_mode and threshold)
    # CONSTRAINT: Never cross-wire s_a into forwarded mode or s_v into direct.
    # ------------------------------------------------------------------
    from app.layer2_threat.bounds import validate_threshold_chain

    mode = VerificationMode(config.verification_mode)

    if mode == VerificationMode.DIRECT:
        # Evaluate against Bob's half with s_a
        rate_for_decision = bob_charlie_result.direct_mismatch_rate
        e_upper_for_decision = bob_charlie_result.direct_e_upper
        threshold_for_decision = config.s_a
        threshold_label = "s_a"
        breach_for_decision = bob_charlie_result.direct_exceeds_threshold
    elif mode == VerificationMode.FORWARDED:
        # Evaluate against Charlie's half with s_v
        rate_for_decision = bob_charlie_result.forwarded_mismatch_rate
        e_upper_for_decision = bob_charlie_result.forwarded_e_upper
        threshold_for_decision = config.s_v
        threshold_label = "s_v"
        breach_for_decision = bob_charlie_result.forwarded_exceeds_threshold
    else:
        raise ValueError(f"Unknown verification_mode: {config.verification_mode!r}")

    # Programmatically validate the threshold chain e_upper < s_a < s_v < p_E
    chain_valid, chain_msg = validate_threshold_chain(
        e_upper=config.e_honest,
        s_a=config.s_a,
        s_v=config.s_v,
        p_E=config.p_E,
    )

    if not chain_valid:
        threat_level = ThreatLevel.CRITICAL
        findings.append(f"CONFIGURATION_WARNING [CRITICAL] — {chain_msg}")

    # Deterministic failure or threshold chain breach overrides any statistical accept
    hard_reject = (
        not digest_result.digest_matches
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
            f"e_upper={e_upper_for_decision:.4f}; "
            f"reason(s): {', '.join(reject_reasons)}"
        )
    else:
        decision = (
            f"ACCEPT — verification_mode={mode.value}, "
            f"threshold={threshold_label}={threshold_for_decision}, "
            f"mismatch_rate={rate_for_decision:.4f}, "
            f"e_upper={e_upper_for_decision:.4f}"
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
        bob_charlie_metrics=bob_charlie_result,
        threat_level=threat_level,
        threat_category=threat_category,
        findings=findings,
        security_decision=decision,
    )
