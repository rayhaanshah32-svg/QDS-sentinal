from typing import Optional
from pydantic import BaseModel, Field


class QuantumStateRecord(BaseModel):
    name: str = Field(..., description="Label or ket representation of the state")
    num_qubits: int = Field(default=1, description="Number of qubits in state")
    amplitudes: list[list[float]] = Field(
        ..., description="List of [real, imag] amplitude pairs"
    )
    norm: float = Field(default=1.0, description="Norm of statevector")


class SignaturePositionRecord(BaseModel):
    index: int = Field(..., description="Index in signature sequence")
    pauli_basis: str = Field(..., description="Pauli basis label (X, Y, or Z)")
    encoded_bit: int = Field(..., description="Bit value prepared by sender (0 or 1)")
    prepared_state_label: str = Field(..., description="Ket label of prepared Pauli eigenstate")
    bell_state: str = Field(..., description="Bell state used for the teleportation channel")
    bell_measurement_bits: str = Field(..., description="Bell measurement outcome string")
    expected_correction: str = Field(..., description="Expected Pauli correction operator")
    actual_correction: str = Field(..., description="Applied Pauli correction operator")
    final_measured_bit: int = Field(..., description="Final bit measured by recipient")
    expected_bit: int = Field(..., description="Expected bit value from sender")
    fidelity: float = Field(..., description="Teleportation state fidelity")
    is_match: bool = Field(..., description="Whether expected and measured bits match")


class SignaturePacket(BaseModel):
    protocol_version: str = Field(default="1.0.0", description="Protocol version")
    message_digest: str = Field(..., description="SHA-256 hash of message")
    sender_id: str = Field(..., description="Identifier of sender")
    recipient_id: str = Field(..., description="Identifier of recipient")
    session_id: str = Field(..., description="Session identifier")
    signature_block_id: str = Field(..., description="Unique identifier for signature block")
    nonce: str = Field(..., description="Nonce value")
    sequence_number: int = Field(..., description="Sequence number of packet")
    timestamp: str = Field(..., description="ISO 8601 UTC creation timestamp")
    signature_length: int = Field(..., description="Number of positions in signature")
    positions: list[SignaturePositionRecord] = Field(..., description="Ordered list of signature positions")


class BasicVerificationSummary(BaseModel):
    total_positions: int = Field(..., description="Total signature elements evaluated")
    matching_positions: int = Field(..., description="Number of matching positions")
    mismatching_positions: int = Field(..., description="Number of mismatching positions")
    mismatch_count: int = Field(..., description="Number of mismatching positions")
    mismatch_rate: float = Field(..., description="Fraction of mismatching positions")
    average_fidelity: float = Field(..., description="Mean teleportation fidelity across all positions")
    basis_distribution: dict[str, int] = Field(..., description="Count of occurrences for each Pauli basis")
    correction_distribution: dict[str, int] = Field(..., description="Count of occurrences for each applied correction")
    digest_matches: bool = Field(default=True, description="Whether message digest matches payload")
    is_perfect_match: bool = Field(..., description="True if no bit mismatches and digest is valid")
