import uuid
from datetime import datetime, timezone
import numpy as np

from app.schemas.protocol import SignaturePacket, BasicVerificationSummary
from app.schemas.telemetry import TeleportationEvent, MeasurementEvent
from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate
from app.layer1_protocol.teleportation import simulate_teleportation
from app.layer1_protocol.measurement import measure_in_basis
from app.layer1_protocol.qds_keygen import generate_signature_material, compute_message_digest
from app.layer1_protocol.event_factory import (
    create_teleportation_event,
    create_measurement_event,
    create_signature_position_record,
    build_verification_summary,
)
from app.layer1_protocol.noise_models import NoiseModel, NoNoise


def create_signature_packet(
    session_id: str,
    sender_id: str,
    recipient_id: str,
    message: str,
    signature_length: int = 16,
    bell_state_label: str = "PHI_PLUS",
    allowed_bases: list[str] = None,
    noise_model: NoiseModel = None,
    rng: np.random.Generator = None,
    nonce: str = None,
    sequence_number: int = 1,
    protocol_version: str = "1.0.0",
) -> tuple[SignaturePacket, list[TeleportationEvent], list[MeasurementEvent]]:
    if rng is None:
        rng = np.random.default_rng()

    if noise_model is None:
        noise_model = NoNoise()

    if nonce is None:
        nonce = str(uuid.uuid4())

    signature_block_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    key_material = generate_signature_material(
        message=message,
        signature_length=signature_length,
        allowed_bases=allowed_bases,
        rng=rng,
        session_id=session_id,
        nonce=nonce,
        sequence_number=sequence_number,
    )

    position_records = []
    teleportation_events = []
    measurement_events = []

    for element in key_material.signature_elements:
        prepared_state = prepare_pauli_eigenstate(
            basis=element.basis,
            bit=element.bit_value,
        )

        teleportation_result = simulate_teleportation(
            input_state=prepared_state,
            bell_state_label=bell_state_label,
            noise_model=noise_model,
            rng=rng,
        )

        teleport_event = create_teleportation_event(
            position_index=element.position_index,
            teleportation_result=teleportation_result,
        )
        teleportation_events.append(teleport_event)

        received_state = teleportation_result.receiver_state_after_correction
        measurement_result = measure_in_basis(
            state=received_state,
            basis=element.basis,
            rng=rng,
        )

        meas_event = create_measurement_event(
            position_index=element.position_index,
            measurement_result=measurement_result,
        )
        measurement_events.append(meas_event)

        pos_record = create_signature_position_record(
            index=element.position_index,
            pauli_basis=element.basis,
            encoded_bit=element.bit_value,
            prepared_state_label=prepared_state.name,
            bell_state=bell_state_label,
            bell_measurement_bits=teleportation_result.bell_measurement_bits,
            expected_correction=teleportation_result.expected_correction,
            actual_correction=teleportation_result.applied_correction,
            final_measured_bit=measurement_result.outcome_bit,
            expected_bit=element.bit_value,
            fidelity=teleportation_result.fidelity,
        )
        position_records.append(pos_record)

    packet = SignaturePacket(
        protocol_version=protocol_version,
        message_digest=key_material.message_digest,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=session_id,
        signature_block_id=signature_block_id,
        nonce=nonce,
        sequence_number=sequence_number,
        timestamp=timestamp,
        signature_length=signature_length,
        positions=position_records,
    )

    return packet, teleportation_events, measurement_events


def verify_signature_packet_basic(
    packet: SignaturePacket,
    expected_message: str = None,
) -> BasicVerificationSummary:
    digest_matches = True
    if expected_message is not None:
        computed_digest = compute_message_digest(expected_message)
        digest_matches = (computed_digest == packet.message_digest)

    return build_verification_summary(
        positions=packet.positions,
        digest_matches=digest_matches,
    )
