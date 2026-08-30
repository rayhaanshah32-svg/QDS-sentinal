from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, HTTPException, Body
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

_example_ledger = ReplayLedger(max_size=100)


class AssessRequest(BaseModel):
    simulation: SimulationRequest = Field(
        ..., description="Layer 1 simulation parameters"
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description="Verification role to evaluate against (direct or forwarded)",
    )
    s_a: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override s_a threshold",
    )
    s_v: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Override s_v threshold",
    )
    e_honest: Optional[float] = Field(
        default=None,
        ge=0.0,
        lt=1.0,
        description="Override honest error rate",
    )
    expected_sender_id: Optional[str] = Field(
        default=None,
        description="Optional expected sender identifier for verifier authorization check",
    )
    expected_recipient_id: Optional[str] = Field(
        default=None,
        description="Optional expected recipient identifier for verifier authorization check",
    )
    requested_verifier_id: Optional[str] = Field(
        default=None,
        description="Optional requesting verifier identifier for verifier authorization check",
    )


class AssessExistingRequest(BaseModel):
    session: ProtocolSessionResult = Field(
        ..., description="Layer 1 ProtocolSessionResult to assess"
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description="Verification role (direct or forwarded)",
    )
    s_a: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    s_v: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_honest: Optional[float] = Field(default=None, ge=0.0, lt=1.0)
    expected_sender_id: Optional[str] = Field(default=None)
    expected_recipient_id: Optional[str] = Field(default=None)
    requested_verifier_id: Optional[str] = Field(default=None)


class AttackSimulateRequest(BaseModel):
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
        description="Target basis for basis-specific attacks",
    )
    verification_mode: VerificationMode = Field(
        default=VerificationMode.DIRECT,
        description="Verification role",
    )
    s_a: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    s_v: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_honest: Optional[float] = Field(default=None, ge=0.0, lt=1.0)
    expected_sender_id: Optional[str] = Field(default=None)
    expected_recipient_id: Optional[str] = Field(default=None)
    requested_verifier_id: Optional[str] = Field(default=None)


class AttackSimulateResponse(BaseModel):
    attack_metadata: AttackMetadata = Field(
        ..., description="Ground-truth attack metadata"
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
    cfg = Layer2Config(verification_mode=verification_mode.value)
    if s_a is not None:
        cfg.s_a = s_a
    if s_v is not None:
        cfg.s_v = s_v
    if e_honest is not None:
        cfg.e_honest = e_honest

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
    "unauthorized_verifier": {
        "summary": "3. Unauthorized Verifier Attempt",
        "description": "Verifier Eve tries to verify packet addressed to Bob. Expected decision: REJECT.",
        "value": {
            "simulation": {
                "message": "PAYLOAD_TRANSFER_PRIVATE_001",
                "sender_id": "Alice",
                "recipient_id": "Bob",
                "signature_length": 16,
                "seed": 42,
                "session_id": "demo-auth-001",
                "nonce": "nonce-auth-42",
                "sequence_number": 1,
            },
            "requested_verifier_id": "Eve",
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
    description="Runs Layer 1 simulation and Layer 2 assessment with optional verifier identity checks.",
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
        return assess_session(
            session,
            config=cfg,
            ledger=default_ledger,
            expected_sender_id=request.expected_sender_id,
            expected_recipient_id=request.expected_recipient_id,
            requested_verifier_id=request.requested_verifier_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 2 assessment error: {exc}")


@router.post(
    "/assess-existing",
    response_model=ThreatAssessment,
    summary="Assess Existing Layer 1 Session",
    description="Assess an existing ProtocolSessionResult without re-running Layer 1.",
)
def assess_existing_endpoint(request: AssessExistingRequest) -> ThreatAssessment:
    try:
        cfg = _build_config(request.verification_mode, request.s_a, request.s_v, request.e_honest)
        return assess_session(
            request.session,
            config=cfg,
            ledger=default_ledger,
            expected_sender_id=request.expected_sender_id,
            expected_recipient_id=request.expected_recipient_id,
            requested_verifier_id=request.requested_verifier_id,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Layer 2 assessment error: {exc}")


@router.post(
    "/attack-simulate",
    response_model=AttackSimulateResponse,
    summary="Inject Attack & Run Layer 2 Assessment",
    description="Simulates session, injects specified attack, and evaluates threat telemetry.",
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

    injected_session = inject_attack(
        session=session,
        attack_type=request.attack_type,
        intensity=request.intensity,
        target_basis=request.target_basis,
        seed=sim.seed,
    )

    try:
        cfg = _build_config(request.verification_mode, request.s_a, request.s_v, request.e_honest)
        assessment = assess_session(
            injected_session,
            config=cfg,
            ledger=default_ledger,
            expected_sender_id=request.expected_sender_id,
            expected_recipient_id=request.expected_recipient_id,
            requested_verifier_id=request.requested_verifier_id,
        )
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
    summary="Example: Payload Digest Mismatch Detection",
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
