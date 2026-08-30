from fastapi import APIRouter, HTTPException
from app.schemas.api import SimulationRequest, HealthResponse
from app.schemas.telemetry import ProtocolSessionResult, BlochStateResponse, BlochCoordinate
from app.layer1_protocol.protocol_session import run_protocol_session
from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate
from app.layer1_protocol.bloch_visualization import (
    bloch_coordinates_for_basis_bit,
    simulate_measurement_collapse,
)

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


@router.get(
    "/bloch-state/{basis}/{bit}",
    response_model=BlochStateResponse,
    summary="Get Bare Pauli Eigenstate Bloch Vector",
    description="Returns analytical Bloch sphere coordinates for an unperturbed Pauli eigenstate (basis in X, Y, Z and bit in 0, 1).",
)
def get_bloch_state_endpoint(basis: str, bit: int) -> BlochStateResponse:
    try:
        coords = bloch_coordinates_for_basis_bit(basis=basis, bit=bit)
        state = prepare_pauli_eigenstate(basis=basis.upper(), bit=bit)
        return BlochStateResponse(
            basis=basis.upper(),
            bit=bit,
            prepared_label=state.name,
            coordinates=BlochCoordinate(x=coords[0], y=coords[1], z=coords[2]),
            is_collapsed=False,
            collapsed_coordinates=None,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Internal Bloch state computation error: {str(error)}")


@router.post(
    "/bloch-trace",
    response_model=list[BlochStateResponse],
    summary="Get Session Bloch Vector Trace",
    description="Simulates a complete QDS protocol session and returns exact Bloch sphere coordinates for every signature position, deriving state collapse from real measurement outcomes.",
)
def get_bloch_trace_endpoint(request: SimulationRequest) -> list[BlochStateResponse]:
    try:
        allowed_bases_str = [b.value if hasattr(b, "value") else str(b) for b in request.bases_allowed]
        bell_state_str = request.bell_state.value if hasattr(request.bell_state, "value") else str(request.bell_state)

        session_result = run_protocol_session(
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

        trace: list[BlochStateResponse] = []
        for pos in session_result.signature_positions:
            collapse_data = simulate_measurement_collapse(
                basis=pos.pauli_basis,
                bit=pos.encoded_bit,
                measured_bit=pos.final_measured_bit,
            )
            trace.append(BlochStateResponse(**collapse_data))

        return trace
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Internal Bloch trace computation error: {str(error)}")

