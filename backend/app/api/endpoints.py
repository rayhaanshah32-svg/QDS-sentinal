from fastapi import APIRouter, HTTPException
from app.schemas.api import SimulationRequest, HealthResponse
from app.schemas.telemetry import ProtocolSessionResult
from app.layer1_protocol.protocol_session import run_protocol_session

router = APIRouter(prefix="/api/v1/layer1", tags=["Layer 1 Protocol Simulation"])


@router.post(
    "/simulate",
    response_model=ProtocolSessionResult,
    summary="Simulate QDS Protocol Session",
    description="Simulates a complete teleportation-mediated Quantum Digital Signature session, executing state preparation, Bell entanglement, quantum teleportation, feedforward Pauli correction, basis measurements, and structured telemetry emission.",
)
def simulate_protocol_endpoint(request: SimulationRequest) -> ProtocolSessionResult:
    try:
        allowed_bases_str = [b.value if hasattr(b, "value") else str(b) for b in request.bases_allowed]
        bell_state_str = request.bell_state.value if hasattr(request.bell_state, "value") else str(request.bell_state)

        result = run_protocol_session(
            message=request.message,
            sender_id=request.sender_id,
            recipient_id=request.recipient_id,
            signature_length=request.signature_length,
            seed=request.seed,
            bell_state_label=bell_state_str,
            allowed_bases=allowed_bases_str,
            session_id=request.session_id,
            nonce=request.nonce,
            sequence_number=request.sequence_number,
        )
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Internal simulation error: {str(error)}")


@router.get(
    "/example-session",
    response_model=ProtocolSessionResult,
    summary="Get Preconfigured Example Session",
    description="Returns a deterministic, preconfigured 8-position clean QDS simulation session with seed 42 and default PHI_PLUS Bell state.",
)
def example_session_endpoint() -> ProtocolSessionResult:
    result = run_protocol_session(
        message="AUTHENTICATED_TRANSACTION_PAYLOAD_001",
        sender_id="alice",
        recipient_id="bob",
        signature_length=8,
        seed=42,
        bell_state_label="PHI_PLUS",
        allowed_bases=["X", "Y", "Z"],
        session_id="example-session-001",
        nonce="nonce-deterministic-42",
        sequence_number=1,
    )
    return result
