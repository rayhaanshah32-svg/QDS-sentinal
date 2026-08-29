from typing import Any
from pydantic import BaseModel, Field
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary


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
