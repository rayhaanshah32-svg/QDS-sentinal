import uuid
from app.schemas.telemetry import TeleportationEvent, MeasurementEvent
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.layer1_protocol.teleportation import TeleportationResult
from app.layer1_protocol.measurement import MeasurementResult


def create_teleportation_event(
    position_index: int,
    teleportation_result: TeleportationResult,
) -> TeleportationEvent:
    event_id = str(uuid.uuid4())
    return TeleportationEvent(
        event_id=event_id,
        position_index=position_index,
        bell_state=teleportation_result.bell_state_label,
        bell_measurement_bits=teleportation_result.bell_measurement_bits,
        expected_correction=teleportation_result.expected_correction,
        applied_correction=teleportation_result.applied_correction,
        fidelity=teleportation_result.fidelity,
        step_trace=teleportation_result.step_trace,
    )


def create_measurement_event(
    position_index: int,
    measurement_result: MeasurementResult,
) -> MeasurementEvent:
    event_id = str(uuid.uuid4())
    return MeasurementEvent(
        event_id=event_id,
        position_index=position_index,
        basis=measurement_result.basis,
        outcome_bit=measurement_result.outcome_bit,
        probabilities=measurement_result.probabilities,
        is_deterministic=measurement_result.is_deterministic,
    )


def create_signature_position_record(
    index: int,
    pauli_basis: str,
    encoded_bit: int,
    prepared_state_label: str,
    bell_state: str,
    bell_measurement_bits: str,
    expected_correction: str,
    actual_correction: str,
    final_measured_bit: int,
    expected_bit: int,
    fidelity: float,
) -> SignaturePositionRecord:
    is_match = (expected_bit == final_measured_bit)
    return SignaturePositionRecord(
        index=index,
        pauli_basis=pauli_basis,
        encoded_bit=encoded_bit,
        prepared_state_label=prepared_state_label,
        bell_state=bell_state,
        bell_measurement_bits=bell_measurement_bits,
        expected_correction=expected_correction,
        actual_correction=actual_correction,
        final_measured_bit=final_measured_bit,
        expected_bit=expected_bit,
        fidelity=fidelity,
        is_match=is_match,
    )


def build_verification_summary(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
) -> BasicVerificationSummary:
    total_positions = len(positions)
    basis_distribution = {"X": 0, "Y": 0, "Z": 0}
    correction_distribution = {"I": 0, "X": 0, "Z": 0, "XZ": 0}

    for pos in positions:
        basis_key = pos.pauli_basis.upper()
        basis_distribution[basis_key] = basis_distribution.get(basis_key, 0) + 1

        corr_key = pos.actual_correction.upper()
        correction_distribution[corr_key] = correction_distribution.get(corr_key, 0) + 1

    if total_positions == 0:
        return BasicVerificationSummary(
            total_positions=0,
            matching_positions=0,
            mismatching_positions=0,
            mismatch_count=0,
            mismatch_rate=0.0,
            average_fidelity=0.0,
            basis_distribution=basis_distribution,
            correction_distribution=correction_distribution,
            digest_matches=digest_matches,
            is_perfect_match=digest_matches,
        )

    matching_positions = sum(1 for p in positions if p.is_match)
    mismatching_positions = total_positions - matching_positions
    mismatch_rate = mismatching_positions / total_positions
    average_fidelity = sum(p.fidelity for p in positions) / total_positions
    is_perfect_match = (mismatching_positions == 0) and digest_matches

    return BasicVerificationSummary(
        total_positions=total_positions,
        matching_positions=matching_positions,
        mismatching_positions=mismatching_positions,
        mismatch_count=mismatching_positions,
        mismatch_rate=mismatch_rate,
        average_fidelity=average_fidelity,
        basis_distribution=basis_distribution,
        correction_distribution=correction_distribution,
        digest_matches=digest_matches,
        is_perfect_match=is_perfect_match,
    )
