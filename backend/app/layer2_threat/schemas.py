from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    CLEAN = "CLEAN"
    ADVISORY = "ADVISORY"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    NONE = "NONE"
    QBER_ANOMALY = "QBER_ANOMALY"
    CORRECTION_TAMPERING = "CORRECTION_TAMPERING"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    PAYLOAD_DIGEST_MISMATCH = "PAYLOAD_DIGEST_MISMATCH"
    IMPERSONATION = "IMPERSONATION"
    UNAUTHORIZED_VERIFICATION = "UNAUTHORIZED_VERIFICATION"
    BELL_INTEGRITY_VIOLATION = "BELL_INTEGRITY_VIOLATION"
    COMBINED = "COMBINED"


class VerificationMode(str, Enum):
    DIRECT = "direct"
    FORWARDED = "forwarded"


class DigestCheckResult(BaseModel):
    digest_matches: bool = Field(
        ...,
        description="Whether the SHA-256 digest in the packet matches the plaintext message",
    )
    recorded_digest: str = Field(
        ...,
        description="SHA-256 digest as recorded in the Layer 1 packet",
    )
    recomputed_digest: str = Field(
        ...,
        description="SHA-256 digest recomputed from the plaintext message by Layer 2",
    )
    is_authoritative: bool = Field(
        default=True,
        description="Digest check is deterministic and authoritative",
    )


class BasisQBERMetrics(BaseModel):
    basis: str = Field(..., description="Pauli basis name (X, Y, or Z)")
    sample_count: int = Field(..., description="Number of positions in this basis")
    mismatch_count: int = Field(..., description="Number of bit mismatches in this basis")
    rate: float = Field(..., description="Mismatch rate for this basis")
    insufficient_samples: bool = Field(..., description="True if sample count is below required minimum")


class QBERAnalysisResult(BaseModel):
    global_mismatch_rate: float = Field(
        ...,
        description="Global mismatch rate across all positions",
    )
    observed_mismatch_rate: float = Field(
        ...,
        description="Global mismatch rate across all positions",
    )
    alert_threshold: float = Field(
        ...,
        description="Configurable advisory alert threshold q_alert",
    )
    exceeds_threshold: bool = Field(
        ...,
        description="True if global_mismatch_rate > alert_threshold",
    )
    hoeffding_false_positive_bound: float = Field(
        ...,
        description="Hoeffding bound on false positive probability",
    )
    total_positions: int = Field(
        ...,
        description="Total signature positions evaluated",
    )
    n_positions: int = Field(
        ...,
        description="Total signature positions evaluated",
    )
    qber_x: BasisQBERMetrics = Field(..., description="QBER metrics for X basis")
    qber_y: BasisQBERMetrics = Field(..., description="QBER metrics for Y basis")
    qber_z: BasisQBERMetrics = Field(..., description="QBER metrics for Z basis")
    basis_wise: dict[str, BasisQBERMetrics] = Field(
        default_factory=dict,
        description="Basis-wise QBER breakdown dictionary",
    )


class CorrectionConsistencyResult(BaseModel):
    inconsistent_positions: list[int] = Field(
        default_factory=list,
        description="Indices of positions where expected_correction != actual_correction",
    )
    inconsistency_count: int = Field(
        ...,
        description="Number of positions with correction mismatch",
    )
    inconsistency_rate: float = Field(
        ...,
        description="Fraction of positions with correction mismatch",
    )
    tamper_threshold: float = Field(
        ...,
        description="c_tamper_rate threshold used",
    )
    flag_raised: bool = Field(
        ...,
        description="True if inconsistency_rate > c_tamper_rate",
    )


class FidelityAnalysisResult(BaseModel):
    average_fidelity: float = Field(
        ...,
        description="Mean fidelity across all signature positions",
    )
    min_fidelity: float = Field(
        ...,
        description="Lowest per-position fidelity observed",
    )
    fidelity_floor: float = Field(
        ...,
        description="f_floor threshold used",
    )
    low_fidelity_positions: list[int] = Field(
        default_factory=list,
        description="Indices of positions with fidelity < f_floor",
    )
    flag_raised: bool = Field(
        ...,
        description="True if any position fidelity < f_floor",
    )


class ReplayDetectionResult(BaseModel):
    fingerprint: str = Field(
        ...,
        description="Fingerprint string used as ledger key",
    )
    is_replay: bool = Field(
        ...,
        description="True if the fingerprint was already seen in the replay ledger",
    )
    ledger_size: int = Field(
        ...,
        description="Current number of entries in the in-memory replay ledger",
    )


class IdentityAuthorizationResult(BaseModel):
    is_authorized: bool = Field(
        default=True,
        description="True if all identity and verifier authorization checks passed",
    )
    expected_sender_id: Optional[str] = Field(
        default=None,
        description="Expected sender ID from verifier context",
    )
    expected_recipient_id: Optional[str] = Field(
        default=None,
        description="Expected recipient ID from verifier context",
    )
    requested_verifier_id: Optional[str] = Field(
        default=None,
        description="Requested verifier ID from verifier context",
    )
    actual_sender_id: str = Field(
        ...,
        description="Actual sender ID in packet",
    )
    actual_recipient_id: str = Field(
        ...,
        description="Actual recipient ID in packet",
    )
    impersonation_detected: bool = Field(
        default=False,
        description="True if sender or recipient mismatch was detected",
    )
    unauthorized_verifier_detected: bool = Field(
        default=False,
        description="True if verifier is not the intended packet recipient",
    )


class BobCharlieMetrics(BaseModel):
    direct_positions_count: int = Field(
        ...,
        description="Number of signature positions assigned to Bob",
    )
    direct_mismatch_count: int = Field(
        ...,
        description="Number of mismatches in Bob's direct half",
    )
    direct_mismatch_rate: float = Field(
        ...,
        description="Raw mismatch rate in Bob's direct half",
    )
    direct_confidence_upper_bound: float = Field(
        ...,
        description="Confidence upper bound on Bob's error rate (uncertainty estimate)",
    )
    direct_e_upper: float = Field(
        ...,
        description="Confidence upper bound on Bob's error rate",
    )
    direct_threshold_s_a: float = Field(
        ...,
        description="s_a threshold applied to Bob's half",
    )
    direct_exceeds_threshold: bool = Field(
        ...,
        description="True if direct_mismatch_rate > s_a",
    )
    forwarded_positions_count: int = Field(
        ...,
        description="Number of signature positions assigned to Charlie",
    )
    forwarded_mismatch_count: int = Field(
        ...,
        description="Number of mismatches in Charlie's forwarded half",
    )
    forwarded_mismatch_rate: float = Field(
        ...,
        description="Raw mismatch rate in Charlie's forwarded half",
    )
    forwarded_confidence_upper_bound: float = Field(
        ...,
        description="Confidence upper bound on Charlie's error rate (uncertainty estimate)",
    )
    forwarded_e_upper: float = Field(
        ...,
        description="Confidence upper bound on Charlie's error rate",
    )
    forwarded_threshold_s_v: float = Field(
        ...,
        description="s_v threshold applied to Charlie's half",
    )
    forwarded_exceeds_threshold: bool = Field(
        ...,
        description="True if forwarded_mismatch_rate > s_v",
    )
    splitting_method: str = Field(
        default="first_half_bob_second_half_charlie",
        description="How positions were split between Bob and Charlie",
    )


class ThreatAssessment(BaseModel):
    session_id: str = Field(
        ...,
        description="Forwarded from ProtocolSessionResult.session_id",
    )
    signature_block_id: str = Field(
        ...,
        description="Forwarded from ProtocolSessionResult.signature_block_id",
    )
    sender_id: str = Field(
        ...,
        description="Forwarded from ProtocolSessionResult.sender_id",
    )
    recipient_id: str = Field(
        ...,
        description="Forwarded from ProtocolSessionResult.recipient_id",
    )
    sequence_number: int = Field(
        ...,
        description="Forwarded from ProtocolSessionResult.sequence_number",
    )
    assessed_at: str = Field(
        ...,
        description="ISO 8601 UTC timestamp of this assessment",
    )
    verification_mode: VerificationMode = Field(
        ...,
        description="Verification role evaluated (direct or forwarded)",
    )
    s_a_used: float = Field(
        ...,
        description="s_a threshold value used in this assessment",
    )
    s_v_used: float = Field(
        ...,
        description="s_v threshold value used in this assessment",
    )
    p_E_used: float = Field(
        ...,
        description="p_E threshold value used in this assessment",
    )
    e_honest_used: float = Field(
        ...,
        description="Configured honest background error rate used for calibration",
    )
    digest_check: DigestCheckResult = Field(
        ..., description="Deterministic SHA-256 digest verification"
    )
    qber_analysis: QBERAnalysisResult = Field(
        ..., description="QBER statistical analysis and basis-wise breakdown"
    )
    correction_consistency: CorrectionConsistencyResult = Field(
        ..., description="Pauli correction consistency check"
    )
    fidelity_analysis: FidelityAnalysisResult = Field(
        ..., description="Teleportation fidelity analysis"
    )
    replay_detection: ReplayDetectionResult = Field(
        ..., description="Replay attack detection via session ledger"
    )
    identity_authorization: IdentityAuthorizationResult = Field(
        ..., description="Identity and verifier authorization check results"
    )
    bob_charlie_metrics: BobCharlieMetrics = Field(
        ..., description="Direct vs forwarded mismatch metrics"
    )
    threat_level: ThreatLevel = Field(
        ...,
        description="Overall threat severity level for this session",
    )
    threat_category: ThreatCategory = Field(
        ...,
        description="Primary threat category identified",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="List of all anomalies detected",
    )
    security_decision: str = Field(
        ...,
        description="ACCEPT or REJECT with mode, threshold, mismatch rate, and confidence upper bound",
    )
    simulation_disclaimer: str = Field(
        default=(
            "This is a software simulation of QDS protocol mechanics. "
            "Results do not constitute information-theoretic security proofs "
            "under coherent attacks, nor claims of physical composable security. "
            "Confidence upper bounds are statistical uncertainty estimates that "
            "become more informative as signature length increases."
        ),
        description="Mandatory scientific integrity disclaimer",
    )
