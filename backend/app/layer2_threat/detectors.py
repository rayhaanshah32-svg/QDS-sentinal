from __future__ import annotations

import hashlib
import math
from typing import Sequence

from app.schemas.telemetry import ProtocolSessionResult
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.schemas import (
    DigestCheckResult,
    BasisQBERMetrics,
    QBERAnalysisResult,
    CorrectionConsistencyResult,
    FidelityAnalysisResult,
    ReplayDetectionResult,
    BobCharlieMetrics,
)


def run_digest_check(session: ProtocolSessionResult) -> DigestCheckResult:
    recomputed_digest = hashlib.sha256(session.message.encode("utf-8")).hexdigest()
    digest_matches = bool(recomputed_digest == session.message_digest)
    return DigestCheckResult(
        digest_matches=digest_matches,
        recorded_digest=session.message_digest,
        recomputed_digest=recomputed_digest,
        is_authoritative=True,
    )


def run_qber_analysis(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> QBERAnalysisResult:
    from app.layer2_threat.bounds import hoeffding_tail_bound

    positions = session.signature_positions
    total_positions = len(positions)
    total_mismatches = sum(1 for p in positions if not p.is_match)
    global_mismatch_rate = (total_mismatches / total_positions) if total_positions > 0 else 0.0

    basis_metrics_map = {}
    for basis_name in ["X", "Y", "Z"]:
        basis_positions = [p for p in positions if p.pauli_basis.upper() == basis_name]
        sample_count = len(basis_positions)
        mismatch_count = sum(1 for p in basis_positions if not p.is_match)
        rate = (mismatch_count / sample_count) if sample_count > 0 else 0.0
        insufficient_samples = bool(sample_count < config.min_basis_samples)
        basis_metrics_map[basis_name] = BasisQBERMetrics(
            basis=basis_name,
            sample_count=sample_count,
            mismatch_count=mismatch_count,
            rate=rate,
            insufficient_samples=insufficient_samples,
        )

    hoeffding = hoeffding_tail_bound(global_mismatch_rate, config.e_honest, total_positions)

    return QBERAnalysisResult(
        global_mismatch_rate=global_mismatch_rate,
        observed_mismatch_rate=global_mismatch_rate,
        alert_threshold=config.q_alert,
        exceeds_threshold=bool(global_mismatch_rate > config.q_alert),
        hoeffding_false_positive_bound=hoeffding,
        total_positions=total_positions,
        n_positions=total_positions,
        qber_x=basis_metrics_map["X"],
        qber_y=basis_metrics_map["Y"],
        qber_z=basis_metrics_map["Z"],
        basis_wise=basis_metrics_map,
    )


def run_correction_consistency_check(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> CorrectionConsistencyResult:
    positions = session.signature_positions
    total = len(positions)
    inconsistent: list[int] = []

    for pos in positions:
        if pos.expected_correction.upper().strip() != pos.actual_correction.upper().strip():
            inconsistent.append(pos.index)

    count = len(inconsistent)
    rate = count / total if total > 0 else 0.0

    return CorrectionConsistencyResult(
        inconsistent_positions=inconsistent,
        inconsistency_count=count,
        inconsistency_rate=rate,
        tamper_threshold=config.c_tamper_rate,
        flag_raised=bool(rate > config.c_tamper_rate),
    )


def run_fidelity_analysis(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> FidelityAnalysisResult:
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


def run_replay_detection(
    session: ProtocolSessionResult,
    ledger: ReplayLedger,
) -> ReplayDetectionResult:
    is_replay, fingerprint = ledger.check_and_record(
        session_id=session.session_id,
        block_id=session.signature_block_id,
        nonce=session.nonce,
        sequence_number=session.sequence_number,
        sender_id=session.sender_id,
        recipient_id=session.recipient_id,
    )

    return ReplayDetectionResult(
        fingerprint=fingerprint,
        is_replay=is_replay,
        ledger_size=len(ledger),
    )


def run_bob_charlie_split(
    session: ProtocolSessionResult,
    config: Layer2Config,
) -> BobCharlieMetrics:
    from app.layer2_threat.bounds import hoeffding_upper_bound

    positions = session.signature_positions
    n = len(positions)

    split_idx = math.ceil(n * config.forwarding_split)

    bob_positions = positions[:split_idx]
    charlie_positions = positions[split_idx:]

    def _mismatch(subset: list[SignaturePositionRecord]) -> tuple[int, float]:
        count = sum(1 for p in subset if not p.is_match)
        rate = count / len(subset) if subset else 0.0
        return count, rate

    bob_mismatch_count, bob_mismatch_rate = _mismatch(bob_positions)
    charlie_mismatch_count, charlie_mismatch_rate = _mismatch(charlie_positions)

    direct_confidence_upper_bound = hoeffding_upper_bound(bob_mismatch_rate, len(bob_positions))
    forwarded_confidence_upper_bound = hoeffding_upper_bound(charlie_mismatch_rate, len(charlie_positions))

    return BobCharlieMetrics(
        direct_positions_count=len(bob_positions),
        direct_mismatch_count=bob_mismatch_count,
        direct_mismatch_rate=bob_mismatch_rate,
        direct_confidence_upper_bound=direct_confidence_upper_bound,
        direct_e_upper=direct_confidence_upper_bound,
        direct_threshold_s_a=config.s_a,
        direct_exceeds_threshold=bool(bob_mismatch_rate > config.s_a),
        forwarded_positions_count=len(charlie_positions),
        forwarded_mismatch_count=charlie_mismatch_count,
        forwarded_mismatch_rate=charlie_mismatch_rate,
        forwarded_confidence_upper_bound=forwarded_confidence_upper_bound,
        forwarded_e_upper=forwarded_confidence_upper_bound,
        forwarded_threshold_s_v=config.s_v,
        forwarded_exceeds_threshold=bool(charlie_mismatch_rate > config.s_v),
        splitting_method="first_half_bob_second_half_charlie",
    )
