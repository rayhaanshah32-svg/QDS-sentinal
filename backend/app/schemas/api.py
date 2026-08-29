from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class BellStateEnum(str, Enum):
    PHI_PLUS = "PHI_PLUS"
    PHI_MINUS = "PHI_MINUS"
    PSI_PLUS = "PSI_PLUS"
    PSI_MINUS = "PSI_MINUS"


class PauliBasisEnum(str, Enum):
    X = "X"
    Y = "Y"
    Z = "Z"


class SimulationRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="Non-empty message string to be signed",
        json_schema_extra={"example": "FINANCIAL_TRANSFER_ORDER_456"},
    )
    sender_id: str = Field(
        default="alice",
        min_length=1,
        description="Sender node identifier",
        json_schema_extra={"example": "alice"},
    )
    recipient_id: str = Field(
        default="bob",
        min_length=1,
        description="Recipient node identifier",
        json_schema_extra={"example": "bob"},
    )
    signature_length: int = Field(
        default=16,
        ge=1,
        le=4096,
        description="Number of signature positions (between 1 and 4096)",
        json_schema_extra={"example": 16},
    )
    seed: Optional[int] = Field(
        default=None,
        description="Optional seed for pseudo-random number generator for deterministic reproduction",
        json_schema_extra={"example": 42},
    )
    bell_state: BellStateEnum = Field(
        default=BellStateEnum.PHI_PLUS,
        description="Bell state label used for teleportation channel",
        json_schema_extra={"example": "PHI_PLUS"},
    )
    bases_allowed: list[PauliBasisEnum] = Field(
        default=[PauliBasisEnum.X, PauliBasisEnum.Y, PauliBasisEnum.Z],
        min_length=1,
        description="Non-empty list of allowed Pauli bases (X, Y, Z)",
        json_schema_extra={"example": ["X", "Y", "Z"]},
    )
    session_id: Optional[str] = Field(
        default=None,
        description="Optional custom session identifier",
        json_schema_extra={"example": "session-custom-001"},
    )
    nonce: Optional[str] = Field(
        default=None,
        description="Optional nonce string",
        json_schema_extra={"example": "nonce-custom-42"},
    )
    sequence_number: Optional[int] = Field(
        default=1,
        ge=1,
        description="Positive packet sequence number",
        json_schema_extra={"example": 1},
    )


class HealthResponse(BaseModel):
    status: str = Field(default="ok", description="Service operational status")
    app_name: str = Field(default="QDS Sentinel", description="Application name")
    version: str = Field(default="0.1.0", description="Application semantic version")
    layer: str = Field(default="Layer 1: Protocol Simulation Engine", description="Active architecture layer")
