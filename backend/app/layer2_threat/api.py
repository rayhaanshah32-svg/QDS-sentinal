"""
Layer 2 – REST API Endpoints

Routes:
    POST  /api/v1/layer2/assess          – run Layer 1 simulation + Layer 2 assessment
    POST  /api/v1/layer2/assess-existing – assess an already-computed ProtocolSessionResult
    POST  /api/v1/layer2/attack-simulate – inject attack + run Layer 2 assessment
    GET   /api/v1/layer2/example-clean   – deterministic clean example
    GET   /api/v1/layer2/example-replay  – deterministic replay example (second call)
    GET   /api/v1/layer2/example-forgery – deterministic digest-forgery example

Verification mode cross-wire protection
-----------------------------------------
Each endpoint accepts an optional `verification_mode` parameter and validates
that s_a is ONLY applied when mode=direct and s_v ONLY when mode=forwarded.
This is enforced by the engine, not just by convention.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel, Field

from app.schemas.api import SimulationRequest
from app.schemas.telemetry import ProtocolSessionResult, AttackType, AttackMetadata
from app.layer1_protocol.protocol_session import run_protocol_session
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.replay_ledger import default_ledger, ReplayLedger
from app.layer2_threat.engine import assess_session
from app.layer2_threat.schemas import ThreatAssessment, VerificationMode
from app.layer2_threat.attacks import inject_attack

router = APIRouter(prefix="/api/v1/layer2", tags=["Layer 2 Threat Detection"])

# Isolated ledger instance for deterministic example endpoints
_example_ledger = ReplayLedger(max_size=100)


class AssessRequest(BaseModel):
    """Combined Layer 1 simulation + Layer 2 threat assessment request."""

    simulation: SimulationRequest = Field(
        ..., description="Layer 1 simulation parameters"
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description=(
            "Which verification role to evaluate against. "
            "'direct' → Bob, uses s_a threshold. "
            "'forwarded' → Charlie, uses s_v threshold. "
            "MUST NOT be cross-wired."
        ),
    )
    s_a: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override s_a threshold (default from config: 0.10). Derivation: Amiri et al. 2016 Eq.19",
    )
    s_v: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override s_v threshold (default from config: 0.20). Derivation: Amiri et al. 2016 Eq.19",
    )
    e_honest: Optional[float] = Field(
        default=None,
        ge=0.0,
        lt=1.0,
        description="Override honest error rate for calibration (default 0.0 = NoNoise baseline)",
    )


class AssessExistingRequest(BaseModel):
    """Assess an already-computed ProtocolSessionResult without re-running Layer 1."""

    session: ProtocolSessionResult = Field(
        ..., description="Layer 1 ProtocolSessionResult to assess"
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description="Verification role (direct → Bob/s_a, forwarded → Charlie/s_v)",
    )
    s_a: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    s_v: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_honest: Optional[float] = Field(default=None, ge=0.0, lt=1.0)


class AttackSimulateRequest(BaseModel):
    """Combined Layer 1 simulation, attack injection, and Layer 2 threat assessment request."""

    simulation: SimulationRequest = Field(
        ..., description="Layer 1 simulation parameters"
    )
    attack_type: AttackType = Field(
        ..., description="Type of attack to inject into Layer 1 output"
    )
    intensity: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Attack intensity parameter q in [0, 1]",
    )
    target_basis: Optional[str] = Field(
        default=None,
        description="Target basis for basis-specific attacks (e.g. 'Z')",
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description="Verification role (direct -> Bob, forwarded -> Charlie)",
    )
    s_a: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    s_v: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_honest: Optional[float] = Field(default=None, ge=0.0, lt=1.0)


class AttackSimulateResponse(BaseModel):
    """Response containing ground-truth attack metadata and schema-valid ThreatAssessment as separate top-level keys."""

    attack_metadata: AttackMetadata = Field(
        ..., description="Ground-truth attack metadata (never read by Layer 2 detectors)"
    )
    assessment: ThreatAssessment = Field(
        ..., description="Schema-valid ThreatAssessment output"
    )


def _build_config(
    verification_mode: VerificationMode,
    s_a: float | None,
    s_v: float | None,
    e_honest: float | None,
) -> Layer2Config:
    """
    Build a Layer2Config from request overrides, validating threshold ordering.
    Raises HTTPException 422 if s_a >= s_v (violates Amiri et al. requirement).
    """
    cfg = Layer2Config(verification_mode=verification_mode.value)
    if s_a is not None:
        cfg.s_a = s_a
    if s_v is not None:
        cfg.s_v = s_v
    if e_honest is not None:
        cfg.e_honest = e_honest

    # Validate threshold ordering
    if cfg.s_a >= cfg.s_v:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Threshold ordering violated: s_a={cfg.s_a} must be strictly less than "
                f"s_v={cfg.s_v} (Amiri et al. 2016 Eq. 19). "
                "Repudiation exponential hardness requires s_a < s_v."
            ),
        )
    if cfg.e_honest >= cfg.s_a:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Threshold ordering violated: e_honest={cfg.e_honest} must be strictly "
                f"less than s_a={cfg.s_a}. Recalibrate e_honest or increase s_a."
            ),
        )

    return cfg


# OpenAPI Request Examples
ASSESS_EXAMPLES = {
    "clean_session": {
        "summary": "1. Clean Authentic Session",
        "description": "Authentic QDS session. Expected decision: ACCEPT.",
        "value": {
            "simulation": {
                "message": "PAYLOAD_TRANSFER_AUTHENTIC_001",
                "sender_id": "Alice",
                "recipient_id": "Bob",
                "signature_length": 16,
                "seed": 42,
                "bell_state": "PHI_PLUS",
                "bases_allowed": ["X", "Y", "Z"],
                "session_id": "demo-clean-001",
                "nonce": "nonce-demo-42",
                "sequence_number": 1,
            },
            "verification_mode": "direct",
            "s_a": 0.10,
            "s_v": 0.20,
        },
    },
    "replay_session": {
        "summary": "2. Replayed Session Packet",
        "description": "Session submitted with previously recorded sequence fingerprint. Expected decision: REJECT.",
        "value": {
            "simulation": {
                "message": "PAYLOAD_TRANSFER_AUTHENTIC_001",
                "sender_id": "Alice",
                "recipient_id": "Bob",
                "signature_length": 16,
                "seed": 42,
                "bell_state": "PHI_PLUS",
                "bases_allowed": ["X", "Y", "Z"],
                "session_id": "demo-clean-001",
                "nonce": "nonce-demo-42",
                "sequence_number": 1,
            },
            "verification_mode": "direct",
        },
    },
}

ATTACK_SIMULATE_EXAMPLES = {
    "partial_forgery": {
        "summary": "1. Partial Signature Forgery (q=0.25)",
        "description": "Partial bit inversion attack. Expected decision: REJECT.",
        "value": {
            "simulation": {
                "message": "PAYLOAD_TRANSFER_FORGED_002",
                "sender_id": "Alice",
                "recipient_id": "Bob",
                "signature_length": 16,
                "seed": 42,
                "bell_state": "PHI_PLUS",
                "bases_allowed": ["X", "Y", "Z"],
                "session_id": "demo-forgery-002",
                "nonce": "nonce-demo-43",
                "sequence_number": 1,
            },
            "attack_type": "PARTIAL_FORGERY",
            "intensity": 0.25,
            "verification_mode": "direct",
            "s_a": 0.10,
            "s_v": 0.20,
        },
    },
    "correction_tampering": {
        "summary": "2. Pauli Correction Tampering",
        "description": "Feedforward correction tampering. Expected decision: REJECT [CRITICAL].",
        "value": {
            "simulation": {
                "message": "PAYLOAD_TRANSFER_TAMPERED_003",
                "sender_id": "Alice",
                "recipient_id": "Bob",
                "signature_length": 16,
                "seed": 42,
                "bell_state": "PHI_PLUS",
                "bases_allowed": ["X", "Y", "Z"],
                "session_id": "demo-tamper-003",
                "nonce": "nonce-demo-44",
                "sequence_number": 1,
            },
            "attack_type": "CORRECTION_TAMPERING",
            "intensity": 1.0,
            "verification_mode": "direct",
        },
    },
}


@router.post(
    "/assess",
    response_model=ThreatAssessment,
    summary="Simulate + Assess QDS Session",
    description=(
        "Runs a complete Layer 1 QDS protocol simulation and then applies the "
        "Layer 2 Threat Detection Engine to produce a structured ThreatAssessment. "
        "Specify verification_mode='direct' for Bob (s_a threshold) or "
        "'forwarded' for Charlie (s_v threshold). These MUST NOT be cross-wired."
    ),
)
def assess_endpoint(
    request: AssessRequest = Body(..., openapi_examples=ASSESS_EXAMPLES)
) -> ThreatAssessment:
    try:
        sim = request.simulation
        allowed_bases_str = [b.value if hasattr(b, "value") else str(b) for b in sim.bases_allowed]
        bell_state_str = sim.bell_state.value if hasattr(sim.bell_state, "value") else str(sim.bell_state)

        session = run_protocol_session(
            message=sim.message,
            sender_id=sim.sender_id,
            recipient_id=sim.recipient_id,
            signature_length=sim.signature_length,
            seed=sim.seed,
            bell_state_label=bell_state_str,
            allowed_bases=allowed_bases_str,
            session_id=sim.session_id,
            nonce=sim.nonce,
            sequence_number=sim.sequence_number,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 1 simulation error: {exc}")

    try:
        cfg = _build_config(request.verification_mode, request.s_a, request.s_v, request.e_honest)
        return assess_session(session, config=cfg, ledger=default_ledger)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 2 assessment error: {exc}")


@router.post(
    "/assess-existing",
    response_model=ThreatAssessment,
    summary="Assess Existing Layer 1 Session",
    description=(
        "Apply the Layer 2 Threat Detection Engine to an already-computed "
        "ProtocolSessionResult without re-running Layer 1. Useful when the session "
        "result is stored externally or produced by a prior simulation call."
    ),
)
def assess_existing_endpoint(request: AssessExistingRequest) -> ThreatAssessment:
    try:
        cfg = _build_config(request.verification_mode, request.s_a, request.s_v, request.e_honest)
        return assess_session(request.session, config=cfg, ledger=default_ledger)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 2 assessment error: {exc}")


@router.post(
    "/attack-simulate",
    response_model=AttackSimulateResponse,
    summary="Inject Attack & Run Layer 2 Assessment",
    description=(
        "Simulates a Layer 1 QDS session, injects a specified attack (e.g., PARTIAL_FORGERY, "
        "CORRECTION_TAMPERING, REPLAY), and evaluates it through the Layer 2 Threat Detection Engine. "
        "Returns ground-truth 'attack_metadata' and 'assessment' as separate top-level keys."
    ),
)
def attack_simulate_endpoint(
    request: AttackSimulateRequest = Body(..., openapi_examples=ATTACK_SIMULATE_EXAMPLES)
) -> AttackSimulateResponse:
    try:
        sim = request.simulation
        allowed_bases_str = [b.value if hasattr(b, "value") else str(b) for b in sim.bases_allowed]
        bell_state_str = sim.bell_state.value if hasattr(sim.bell_state, "value") else str(sim.bell_state)

        session = run_protocol_session(
            message=sim.message,
            sender_id=sim.sender_id,
            recipient_id=sim.recipient_id,
            signature_length=sim.signature_length,
            seed=sim.seed,
            bell_state_label=bell_state_str,
            allowed_bases=allowed_bases_str,
            session_id=sim.session_id,
            nonce=sim.nonce,
            sequence_number=sim.sequence_number,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Layer 1 simulation error: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 1 simulation error: {exc}")

    # Inject attack into a copy of the session
    injected_session = inject_attack(
        session=session,
        attack_type=request.attack_type,
        intensity=request.intensity,
        target_basis=request.target_basis,
        seed=sim.seed,
    )

    try:
        cfg = _build_config(request.verification_mode, request.s_a, request.s_v, request.e_honest)
        assessment = assess_session(injected_session, config=cfg, ledger=default_ledger)
        return AttackSimulateResponse(
            attack_metadata=injected_session.attack_metadata,
            assessment=assessment,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 2 assessment error: {exc}")


@router.get(
    "/example-clean",
    response_model=ThreatAssessment,
    summary="Example: Clean Session Assessment",
    description=(
        "Returns a deterministic clean ThreatAssessment using Layer 1 seed=42. "
        "Expected result: CLEAN, no findings, security_decision=ACCEPT."
    ),
)
def example_clean_endpoint() -> ThreatAssessment:
    _example_ledger.clear()
    session = run_protocol_session(
        message="AUTHENTICATED_TRANSACTION_PAYLOAD_CLEAN",
        sender_id="alice",
        recipient_id="bob",
        signature_length=16,
        seed=42,
        bell_state_label="PHI_PLUS",
        allowed_bases=["X", "Y", "Z"],
        session_id="example-clean-001",
        nonce="nonce-clean-42",
        sequence_number=1,
    )
    cfg = Layer2Config(verification_mode="direct")
    return assess_session(session, config=cfg, ledger=_example_ledger)


@router.get(
    "/example-replay",
    response_model=ThreatAssessment,
    summary="Example: Replay Attack Detection",
    description=(
        "Submits the same session fingerprint twice to the example ledger. "
        "The second call returns CRITICAL / REPLAY_ATTACK."
    ),
)
def example_replay_endpoint() -> ThreatAssessment:
    _example_ledger.clear()
    session = run_protocol_session(
        message="AUTHENTICATED_TRANSACTION_REPLAY_TEST",
        sender_id="alice",
        recipient_id="bob",
        signature_length=16,
        seed=99,
        bell_state_label="PHI_PLUS",
        allowed_bases=["X", "Y", "Z"],
        session_id="example-replay-001",
        nonce="nonce-replay-99",
        sequence_number=1,
    )
    cfg = Layer2Config(verification_mode="direct")
    assess_session(session, config=cfg, ledger=_example_ledger)
    return assess_session(session, config=cfg, ledger=_example_ledger)


@router.get(
    "/example-forgery",
    response_model=ThreatAssessment,
    summary="Example: Digest Forgery Detection",
    description=(
        "Constructs a ProtocolSessionResult with a corrupted message_digest. "
        "Expected result: CRITICAL / DIGEST_FORGERY, security_decision=REJECT."
    ),
)
def example_forgery_endpoint() -> ThreatAssessment:
    _example_ledger.clear()
    session = run_protocol_session(
        message="AUTHENTIC_MESSAGE",
        sender_id="alice",
        recipient_id="bob",
        signature_length=16,
        seed=77,
        bell_state_label="PHI_PLUS",
        allowed_bases=["X", "Y", "Z"],
        session_id="example-forgery-001",
        nonce="nonce-forgery-77",
        sequence_number=1,
    )

    tampered_summary = session.verification_summary.model_copy(
        update={"digest_matches": False, "is_perfect_match": False}
    )
    tampered_session = session.model_copy(
        update={
            "message_digest": "0" * 64,
            "verification_summary": tampered_summary,
        }
    )

    cfg = Layer2Config(verification_mode="direct")
    return assess_session(tampered_session, config=cfg, ledger=_example_ledger)
