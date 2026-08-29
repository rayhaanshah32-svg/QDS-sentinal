import uuid
from datetime import datetime, timezone
import numpy as np

from app.schemas.telemetry import ProtocolSessionResult
from app.layer1_protocol.qds_signature import create_signature_packet, verify_signature_packet_basic
from app.layer1_protocol.noise_models import NoiseModel, NoNoise


def run_protocol_session(
    message: str,
    sender_id: str = "alice",
    recipient_id: str = "bob",
    signature_length: int = 16,
    seed: int = None,
    bell_state_label: str = "PHI_PLUS",
    allowed_bases: list[str] = None,
    session_id: str = None,
    nonce: str = None,
    sequence_number: int = 1,
    noise_model: NoiseModel = None,
    protocol_version: str = "1.0.0",
) -> ProtocolSessionResult:
    if session_id is None:
        session_id = str(uuid.uuid4())

    if nonce is None:
        nonce = str(uuid.uuid4())

    if allowed_bases is None:
        allowed_bases = ["X", "Y", "Z"]

    if noise_model is None:
        noise_model = NoNoise()

    if seed is not None:
        rng = np.random.default_rng(seed)
    else:
        rng = np.random.default_rng()

    packet, teleportation_events, measurement_events = create_signature_packet(
        session_id=session_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        message=message,
        signature_length=signature_length,
        bell_state_label=bell_state_label,
        allowed_bases=allowed_bases,
        noise_model=noise_model,
        rng=rng,
        nonce=nonce,
        sequence_number=sequence_number,
        protocol_version=protocol_version,
    )

    verification_summary = verify_signature_packet_basic(
        packet=packet,
        expected_message=message,
    )

    configuration = {
        "signature_length": signature_length,
        "seed": seed,
        "bell_state": bell_state_label,
        "bases_allowed": allowed_bases,
        "noise_model": noise_model.__class__.__name__,
    }

    return ProtocolSessionResult(
        protocol_version=packet.protocol_version,
        session_id=session_id,
        signature_block_id=packet.signature_block_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        message=message,
        message_digest=packet.message_digest,
        nonce=nonce,
        sequence_number=sequence_number,
        created_at=packet.timestamp,
        configuration=configuration,
        signature_positions=packet.positions,
        teleportation_events=teleportation_events,
        measurement_events=measurement_events,
        verification_summary=verification_summary,
    )
