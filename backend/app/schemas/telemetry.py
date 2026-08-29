from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary


class AttackType(str, Enum):
    """Enumeration of simulated QDS attack types."""
    REPLAY = "REPLAY"
    FULL_FORGERY = "FULL_FORGERY"
    PARTIAL_FORGERY = "PARTIAL_FORGERY"
    CORRECTION_TAMPERING = "CORRECTION_TAMPERING"
    INTERCEPT_RESEND = "INTERCEPT_RESEND"
    CHANNEL_MANIPULATION = "CHANNEL_MANIPULATION"
    FIDELITY_DEGRADATION = "FIDELITY_DEGRADATION"
    BOB_REPUDIATION = "BOB_REPUDIATION"


class AttackMetadata(BaseModel):
    """Ground-truth metadata attached to injected packets for evaluation/benchmarking."""
    attack_id: str = Field(..., description="Unique attack instance ID")
    attack_type: AttackType = Field(..., description="Type of attack injected")
    intensity: float = Field(default=1.0, ge=0.0, le=1.0, description="Attack intensity q in [0, 1]")
    target_basis: Optional[str] = Field(default=None, description="Target basis for basis-specific attacks")
    seed: int = Field(default=42, description="Random seed used for deterministic injection")
    description: str = Field(..., description="Human-readable description of the injected attack")


class TeleportationEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    position_index: int = Field(..., description="Signature position index")
    bell_state: str = Field(..., description="Bell state label used for channel")
    bell_measurement_bits: str = Field(..., description="Bell measurement outcome string")
    expected_correction: str = Field(..., description="Expected Pauli correction operator")
    applied_correction: str = Field(..., description="Applied Pauli correction operator")
    fidelity: float = Field(..., description="Teleportation fidelity")
    step_trace: list[str] = Field(default_factory=list, description="Descriptive trace of circuit operations")


class MeasurementEvent(BaseModel):
    event_id: str = Field(..., description="Unique event identifier")
    position_index: int = Field(..., description="Signature position index")
    basis: str = Field(..., description="Measurement basis")
    outcome_bit: int = Field(..., description="Measured bit outcome")
    probabilities: dict[str, float] = Field(..., description="Exact Born rule probabilities")
    is_deterministic: bool = Field(..., description="Whether measurement outcome was deterministic")


class ProtocolSessionResult(BaseModel):
    protocol_version: str = Field(default="1.0.0", description="Protocol engine version")
    session_id: str = Field(..., description="Session identifier")
    signature_block_id: str = Field(..., description="Signature block identifier")
    sender_id: str = Field(..., description="Sender node ID")
    recipient_id: str = Field(..., description="Recipient node ID")
    message: str = Field(..., description="Plaintext message")
    message_digest: str = Field(..., description="SHA-256 digest of message")
    nonce: str = Field(..., description="Nonce value")
    sequence_number: int = Field(..., description="Packet sequence number")
    created_at: str = Field(..., description="ISO 8601 UTC timestamp")
    configuration: dict[str, Any] = Field(default_factory=dict, description="Session configuration parameters")
    signature_positions: list[SignaturePositionRecord] = Field(..., description="Signature position records")
    teleportation_events: list[TeleportationEvent] = Field(..., description="List of teleportation telemetry events")
    measurement_events: list[MeasurementEvent] = Field(..., description="List of measurement telemetry events")
    verification_summary: BasicVerificationSummary = Field(..., description="Basic verification summary")
    attack_metadata: Optional[AttackMetadata] = Field(
        default=None, description="Optional ground-truth attack metadata (never read by Layer 2 detectors)"
    )
