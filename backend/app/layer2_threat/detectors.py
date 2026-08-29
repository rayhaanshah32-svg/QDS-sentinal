"""
Layer 2 – Individual Threat Detectors

Each detector is a pure function that takes verified Layer 1 data structures
and returns a typed sub-model from layer2_threat.schemas.

Design rules
------------
- Detectors NEVER modify Layer 1 objects.
- Every comparison uses exact Layer 1 field names (validated against actual
  schemas before implementation).
- Deterministic detectors (digest, replay, correction) are authoritative.
- Statistical detectors (QBER, fidelity) return confidence-bounded evidence.
- No threshold is applied without the source documented in Layer2Config.

Field name audit (all fields below verified against real Layer 1 schemas):
    ProtocolSessionResult:
        .session_id, .signature_block_id, .sender_id, .recipient_id,
        .message_digest, .nonce, .sequence_number,
        .signature_positions (list[SignaturePositionRecord]),
        .verification_summary (BasicVerificationSummary)
    SignaturePositionRecord:
        .index, .expected_correction, .actual_correction,
        .fidelity, .is_match, .final_measured_bit, .expected_bit
    BasicVerificationSummary:
        .mismatch_rate, .total_positions, .mismatch_count, .digest_matches
"""

from __future__ import annotations

import math
from typing import Sequence

from app.schemas.telemetry import ProtocolSessionResult
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.schemas import (
    DigestCheckResult,
    QBERAnalysisResult,
    CorrectionConsistencyResult,
    FidelityAnalysisResult,
    ReplayDetectionResult,
    BobCharlieMetrics,
)


# ---------------------------------------------------------------------------
# 1. Digest Check (deterministic, authoritative)
# ---------------------------------------------------------------------------

def run_digest_check(session: ProtocolSessionResult) -> DigestCheckResult:
    """
    Verify the SHA-256 message digest from Layer 1's BasicVerificationSummary.

    Sources:
        - digest_matches: BasicVerificationSummary.digest_matches
        - recorded_digest: ProtocolSessionResult.message_digest

    This is a deterministic check.  A False result is authoritative evidence
    of forgery regardless of statistical findings.
    """
    return DigestCheckResult(
        digest_matches=session.verification_summary.digest_matches,
        recorded_digest=session.message_digest,
        is_authoritative=True,
    )


# ---------------------------------------------------------------------------
# 2. QBER Analysis (statistical, confidence-bounded)
# ---------------------------------------------------------------------------

def run_qber_analysis(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> QBERAnalysisResult:
    """
    Compute QBER from Layer 1's BasicVerificationSummary.mismatch_rate.

    The Hoeffding false-positive bound quantifies how likely this rate could
    arise from honest channel noise at e_honest rather than an adversary.
        P(rate > q_alert | true_rate = e_honest) ≤ exp(-2n(rate - e_honest)²)

    Sources:
        - observed_mismatch_rate: BasicVerificationSummary.mismatch_rate
        - n_positions: BasicVerificationSummary.total_positions
        - alert_threshold: Layer2Config.q_alert
        - e_honest: Layer2Config.e_honest
    """
    from app.layer2_threat.bounds import hoeffding_tail_bound

    observed = session.verification_summary.mismatch_rate
    n = session.verification_summary.total_positions

    hoeffding = hoeffding_tail_bound(observed, config.e_honest, n)

    return QBERAnalysisResult(
        observed_mismatch_rate=observed,
        alert_threshold=config.q_alert,
        exceeds_threshold=(observed > config.q_alert),
        hoeffding_false_positive_bound=hoeffding,
        n_positions=n,
    )


# ---------------------------------------------------------------------------
# 3. Correction Consistency (deterministic, authoritative)
# ---------------------------------------------------------------------------

def run_correction_consistency_check(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> CorrectionConsistencyResult:
    """
    Detect positions where expected_correction != actual_correction.

    In Layer 1's teleportation model, expected_correction and
    actual_correction are always identical (applied_correction = expected
    in teleportation.py line 85).  Any divergence in real telemetry
    indicates post-teleportation channel tampering in the simulated scenario.

    Sources:
        - SignaturePositionRecord.expected_correction
        - SignaturePositionRecord.actual_correction
        - Layer2Config.c_tamper_rate (zero-tolerance threshold)

    This is a deterministic check. Any inconsistency at rate > c_tamper_rate
    is treated as authoritative evidence of tampering.
    """
    positions = session.signature_positions
    total = len(positions)
    inconsistent: list[int] = []

    for pos in positions:
        # Normalize both sides to upper-case for comparison
        if pos.expected_correction.upper().strip() != pos.actual_correction.upper().strip():
            inconsistent.append(pos.index)

    count = len(inconsistent)
    rate = count / total if total > 0 else 0.0

    return CorrectionConsistencyResult(
        inconsistent_positions=inconsistent,
        inconsistency_count=count,
        inconsistency_rate=rate,
        tamper_threshold=config.c_tamper_rate,
        flag_raised=(rate > config.c_tamper_rate),
    )


# ---------------------------------------------------------------------------
# 4. Fidelity Analysis (statistical)
# ---------------------------------------------------------------------------

def run_fidelity_analysis(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> FidelityAnalysisResult:
    """
    Examine per-position teleportation fidelity.

    Sources:
        - SignaturePositionRecord.fidelity (primary source)
        - Layer2Config.f_floor

    Note: fidelity is repeated in TeleportationEvent.fidelity but
    SignaturePositionRecord.fidelity is the authoritative record-level value.
    """
    positions = session.signature_positions
    if not positions:
        return FidelityAnalysisResult(
            average_fidelity=0.0,
            min_fidelity=0.0,
            fidelity_floor=config.f_floor,
            low_fidelity_positions=[],
            flag_raised=False,
        )

    fidelities = [p.fidelity for p in positions]
    avg_fidelity = sum(fidelities) / len(fidelities)
    min_fidelity = min(fidelities)
    low_positions = [p.index for p in positions if p.fidelity < config.f_floor]

    return FidelityAnalysisResult(
        average_fidelity=avg_fidelity,
        min_fidelity=min_fidelity,
        fidelity_floor=config.f_floor,
        low_fidelity_positions=low_positions,
        flag_raised=len(low_positions) > 0,
    )


# ---------------------------------------------------------------------------
# 5. Replay Detection (deterministic, authoritative)
# ---------------------------------------------------------------------------

def run_replay_detection(
    session: ProtocolSessionResult,
    ledger: ReplayLedger,
) -> ReplayDetectionResult:
    """
    Check and record the session fingerprint in the replay ledger.

    Fingerprint = session_id | signature_block_id | nonce | sequence_number

    Sources:
        - ProtocolSessionResult.session_id
        - ProtocolSessionResult.signature_block_id
        - ProtocolSessionResult.nonce
        - ProtocolSessionResult.sequence_number

    A fingerprint match is a deterministic, authoritative replay flag.
    """
    is_replay, fingerprint = ledger.check_and_record(
        session_id=session.session_id,
        block_id=session.signature_block_id,
        nonce=session.nonce,
        sequence_number=session.sequence_number,
    )

    return ReplayDetectionResult(
        fingerprint=fingerprint,
        is_replay=is_replay,
        ledger_size=len(ledger),
    )


# ---------------------------------------------------------------------------
# 6. Bob / Charlie Symmetrization Split (explicit Layer 2 simplification)
# ---------------------------------------------------------------------------

def run_bob_charlie_split(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> BobCharlieMetrics:
    """
    Split signature positions into Bob (direct) and Charlie (forwarded) halves
    and evaluate mismatch rates against s_a and s_v respectively.

    EXPLICIT SIMPLIFICATION (documented per spec requirement):
        Layer 1 produces a single sender → recipient packet.  The QDS
        symmetrization/forwarding step (Amiri et al. 2016, Chapman et al.)
        is modeled here in Layer 2 as a position-index split:
            - positions[0 : ceil(n * forwarding_split)] → Bob (direct)
            - positions[ceil(n * forwarding_split) : n] → Charlie (forwarded)
        This is a documented approximation of the two-recipient architecture,
        NOT a claim that Layer 1 modeled it.  See docs/layer2-security-claims.md.

    Threshold assignment (MUST NOT be cross-wired):
        - Bob's half is evaluated against s_a (direct threshold).
        - Charlie's half is evaluated against s_v (forwarded threshold).
        Applying s_a to Charlie's half or s_v to Bob's half is a documented
        QDS security bug class (Amiri et al. Eq. 20-24).

    Sources:
        - SignaturePositionRecord.is_match for each position
        - Layer2Config.s_a, Layer2Config.s_v, Layer2Config.forwarding_split
    """
    from app.layer2_threat.bounds import hoeffding_upper_bound

    positions = session.signature_positions
    n = len(positions)

    # Compute split index using ceiling so Bob gets >= half on odd n
    split_idx = math.ceil(n * config.forwarding_split)

    bob_positions = positions[:split_idx]
    charlie_positions = positions[split_idx:]

    def _mismatch(subset: list[SignaturePositionRecord]) -> tuple[int, float]:
        count = sum(1 for p in subset if not p.is_match)
        rate = count / len(subset) if subset else 0.0
        return count, rate

    bob_mismatch_count, bob_mismatch_rate = _mismatch(bob_positions)
    charlie_mismatch_count, charlie_mismatch_rate = _mismatch(charlie_positions)

    # Independent confidence-adjusted upper error rates using finite-sample upper bounds
    direct_e_upper = hoeffding_upper_bound(bob_mismatch_rate, len(bob_positions))
    forwarded_e_upper = hoeffding_upper_bound(charlie_mismatch_rate, len(charlie_positions))

    return BobCharlieMetrics(
        direct_positions_count=len(bob_positions),
        direct_mismatch_count=bob_mismatch_count,
        direct_mismatch_rate=bob_mismatch_rate,
        direct_e_upper=direct_e_upper,
        direct_threshold_s_a=config.s_a,
        direct_exceeds_threshold=(bob_mismatch_rate > config.s_a),
        forwarded_positions_count=len(charlie_positions),
        forwarded_mismatch_count=charlie_mismatch_count,
        forwarded_mismatch_rate=charlie_mismatch_rate,
        forwarded_e_upper=forwarded_e_upper,
        forwarded_threshold_s_v=config.s_v,
        forwarded_exceeds_threshold=(charlie_mismatch_rate > config.s_v),
        splitting_method="first_half_bob_second_half_charlie",
    )
