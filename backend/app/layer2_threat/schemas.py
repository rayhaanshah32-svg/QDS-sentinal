"""
Layer 2 Threat Detection Engine – Output Schemas (ThreatAssessment)

All field names are verified against the actual Layer 1 schemas before use.
This module defines ONLY Layer 2 output types; it never alters Layer 1 models.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ThreatLevel(str, Enum):
    """Ordered severity levels for threat findings."""
    CLEAN = "CLEAN"
    ADVISORY = "ADVISORY"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    """Classification of the threat type detected."""
    NONE = "NONE"
    QBER_ANOMALY = "QBER_ANOMALY"
    CORRECTION_TAMPERING = "CORRECTION_TAMPERING"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    DIGEST_FORGERY = "DIGEST_FORGERY"
    BELL_INTEGRITY_VIOLATION = "BELL_INTEGRITY_VIOLATION"
    COMBINED = "COMBINED"


class VerificationMode(str, Enum):
    """Which verification role was evaluated (Bob = direct, Charlie = forwarded)."""
    DIRECT = "direct"
    FORWARDED = "forwarded"


# ---------------------------------------------------------------------------
# Per-detector sub-models
# ---------------------------------------------------------------------------

class DigestCheckResult(BaseModel):
    """Result of the deterministic SHA-256 digest verification.

    Deterministic verification always wins over statistical evidence.
    Fields sourced from ProtocolSessionResult.message_digest and
    BasicVerificationSummary.digest_matches.
    """
    digest_matches: bool = Field(
        ...,
        description="Whether the SHA-256 digest in the packet matches the plaintext message",
    )
    recorded_digest: str = Field(
        ...,
        description="SHA-256 digest as recorded in the Layer 1 packet",
    )
    is_authoritative: bool = Field(
        default=True,
        description="Digest check is deterministic and authoritative; it overrides statistical findings",
    )


class QBERAnalysisResult(BaseModel):
    """Quantum Bit Error Rate analysis.

    Provides confidence-bounded evidence of channel interference; does NOT
    constitute a standalone security guarantee.
    Source: mismatch_rate from BasicVerificationSummary.
    """
    observed_mismatch_rate: float = Field(
        ...,
        description="Raw mismatch fraction from Layer 1 verification_summary.mismatch_rate",
    )
    alert_threshold: float = Field(
        ...,
        description="q_alert threshold used (source: Layer2Config.q_alert)",
    )
    exceeds_threshold: bool = Field(
        ...,
        description="True if observed_mismatch_rate > alert_threshold",
    )
    hoeffding_false_positive_bound: float = Field(
        ...,
        description=(
            "Upper bound on false-positive probability: exp(-2 * n * (observed_rate - e_honest)^2). "
            "Only meaningful when observed_rate > e_honest. Set to 1.0 when rate <= e_honest."
        ),
    )
    n_positions: int = Field(
        ...,
        description="Total signature positions evaluated (source: BasicVerificationSummary.total_positions)",
    )


class CorrectionConsistencyResult(BaseModel):
    """Pauli correction consistency check.

    Deterministic: any expected_correction != actual_correction at a position
    indicates post-teleportation tampering in the simulated channel.
    Source: SignaturePositionRecord.expected_correction and .actual_correction.
    """
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
        description="c_tamper_rate threshold used (source: Layer2Config.c_tamper_rate)",
    )
    flag_raised: bool = Field(
        ...,
        description="True if inconsistency_rate > c_tamper_rate",
    )


class FidelityAnalysisResult(BaseModel):
    """Per-position teleportation fidelity analysis.

    Source: SignaturePositionRecord.fidelity and TeleportationEvent.fidelity.
    """
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
        description="f_floor threshold used (source: Layer2Config.f_floor)",
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
    """Replay attack detection via session-fingerprint ledger.

    Fingerprint = (session_id, signature_block_id, nonce, sequence_number).
    Deterministic check; a match is authoritative evidence of replay.
    """
    fingerprint: str = Field(
        ...,
        description="Tuple string used as ledger key: session_id|block_id|nonce|seq",
    )
    is_replay: bool = Field(
        ...,
        description="True if the fingerprint was already seen in the replay ledger",
    )
    ledger_size: int = Field(
        ...,
        description="Current number of entries in the in-memory replay ledger",
    )


class BobCharlieMetrics(BaseModel):
    """Bob vs. Charlie (direct vs. forwarded) mismatch rates.

    IMPORTANT: Direct and forwarded metrics must NEVER be collapsed into a
    single number (Amiri et al. 2016, Eq. 20-24 repudiation analysis).

    Layer 2 explicitly implements the symmetrization/forwarding split because
    Layer 1 produces a single sender→recipient packet.  See
    docs/layer2-security-claims.md for the documented simplification.
    """
    # Bob (direct authenticator)
    direct_positions_count: int = Field(
        ...,
        description="Number of signature positions assigned to Bob (direct verification half)",
    )
    direct_mismatch_count: int = Field(
        ...,
        description="Number of mismatches in Bob's half",
    )
    direct_mismatch_rate: float = Field(
        ...,
        description="Mismatch rate in Bob's direct half",
    )
    direct_e_upper: float = Field(
        ...,
        description="Confidence-adjusted (upper bound) mismatch rate in Bob's direct half using finite-sample bound",
    )
    direct_threshold_s_a: float = Field(
        ...,
        description="s_a threshold applied to Bob's half (source: Layer2Config.s_a)",
    )
    direct_exceeds_threshold: bool = Field(
        ...,
        description="True if direct_e_upper >= s_a (or direct_mismatch_rate > s_a)",
    )

    # Charlie (forwarded verifier)
    forwarded_positions_count: int = Field(
        ...,
        description="Number of signature positions assigned to Charlie (forwarded half)",
    )
    forwarded_mismatch_count: int = Field(
        ...,
        description="Number of mismatches in Charlie's half",
    )
    forwarded_mismatch_rate: float = Field(
        ...,
        description="Mismatch rate in Charlie's forwarded half",
    )
    forwarded_e_upper: float = Field(
        ...,
        description="Confidence-adjusted (upper bound) mismatch rate in Charlie's forwarded half using finite-sample bound",
    )
    forwarded_threshold_s_v: float = Field(
        ...,
        description="s_v threshold applied to Charlie's half (source: Layer2Config.s_v)",
    )
    forwarded_exceeds_threshold: bool = Field(
        ...,
        description="True if forwarded_e_upper >= s_v (or forwarded_mismatch_rate > s_v)",
    )

    splitting_method: str = Field(
        default="first_half_bob_second_half_charlie",
        description=(
            "How positions were split. Layer 2 explicit simplification: "
            "positions[:n//2] → Bob, positions[n//2:] → Charlie. "
            "See docs/layer2-security-claims.md."
        ),
    )


# ---------------------------------------------------------------------------
# Top-level ThreatAssessment
# ---------------------------------------------------------------------------

class ThreatAssessment(BaseModel):
    """
    Layer 2 Threat Detection Engine output.

    Consumes a ProtocolSessionResult and produces a structured threat
    classification with per-detector evidence and a final security decision.

    Scientific integrity notice
    ---------------------------
    - This is a software simulation.  It does NOT prove physical composable
      security or claim to detect every quantum attack.
    - Deterministic checks (digest, replay, correction consistency) are
      authoritative.
    - Statistical checks (QBER, fidelity) are confidence-bounded indicators.
    - Every emitted number is traceable to a field in ProtocolSessionResult,
      a threshold in Layer2Config, or a formula documented in this module.
    - All results are reproducible from a fixed seed via Layer 1's seed field.
    """

    # Session provenance
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

    # Configuration snapshot (for audit reproducibility)
    verification_mode: VerificationMode = Field(
        ...,
        description=(
            "Which verification role was evaluated. MUST be declared so the "
            "security decision is never cross-wired (Amiri et al. Eq. 20-24)."
        ),
    )
    s_a_used: float = Field(
        ...,
        description="s_a threshold value used in this assessment (source: Layer2Config)",
    )
    s_v_used: float = Field(
        ...,
        description="s_v threshold value used in this assessment (source: Layer2Config)",
    )
    p_E_used: float = Field(
        ...,
        description="p_E threshold value used in this assessment (source: Layer2Config)",
    )
    e_honest_used: float = Field(
        ...,
        description="Configured honest background error rate used for calibration",
    )

    # Per-detector results
    digest_check: DigestCheckResult = Field(
        ..., description="Deterministic SHA-256 digest verification"
    )
    qber_analysis: QBERAnalysisResult = Field(
        ..., description="QBER statistical analysis"
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
    bob_charlie_metrics: BobCharlieMetrics = Field(
        ..., description="Direct vs. forwarded mismatch metrics (must never be collapsed)"
    )

    # Final security decision
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
        description="Human-readable list of all anomalies detected, referencing the detector that raised them",
    )
    security_decision: str = Field(
        ...,
        description=(
            "ACCEPT or REJECT with mandatory reference to which verification_mode "
            "and threshold (s_a or s_v) was evaluated. Cannot cross-wire modes."
        ),
    )
    simulation_disclaimer: str = Field(
        default=(
            "This is a software simulation of QDS protocol mechanics. "
            "Results do not constitute information-theoretic security proofs "
            "under coherent attacks, nor claims of physical composable security."
        ),
        description="Mandatory scientific integrity disclaimer",
    )
