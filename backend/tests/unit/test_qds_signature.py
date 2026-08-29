import json
import pytest
import numpy as np

from app.layer1_protocol.qds_signature import create_signature_packet, verify_signature_packet_basic
from app.layer1_protocol.noise_models import NoNoise


def test_signature_packet_binds_all_required_metadata():
    message = "PAYLOAD_WITH_BOUND_METADATA"
    rng = np.random.default_rng(42)

    packet, teleport_events, meas_events = create_signature_packet(
        session_id="session-bind-test",
        sender_id="alice_node",
        recipient_id="bob_node",
        message=message,
        signature_length=8,
        bell_state_label="PHI_PLUS",
        nonce="nonce-987",
        sequence_number=5,
        protocol_version="1.0.0",
        noise_model=NoNoise(),
        rng=rng,
    )

    assert packet.protocol_version == "1.0.0"
    assert len(packet.message_digest) == 64
    assert packet.sender_id == "alice_node"
    assert packet.recipient_id == "bob_node"
    assert packet.session_id == "session-bind-test"
    assert len(packet.signature_block_id) > 0
    assert packet.nonce == "nonce-987"
    assert packet.sequence_number == 5
    assert len(packet.timestamp) > 0
    assert packet.signature_length == 8
    assert len(packet.positions) == 8


def test_signature_position_records_all_telemetry_fields():
    message = "TELEMETRY_POSITION_TEST"
    rng = np.random.default_rng(100)

    packet, _, _ = create_signature_packet(
        session_id="session-pos-test",
        sender_id="alice",
        recipient_id="bob",
        message=message,
        signature_length=4,
        bell_state_label="PHI_PLUS",
        rng=rng,
    )

    for pos in packet.positions:
        assert isinstance(pos.index, int)
        assert pos.pauli_basis in ["X", "Y", "Z"]
        assert pos.encoded_bit in [0, 1]
        assert pos.prepared_state_label in ["|0>", "|1>", "|+>", "|->", "|+i>", "|-i>"]
        assert pos.bell_state == "PHI_PLUS"
        assert pos.bell_measurement_bits in ["00", "01", "10", "11"]
        assert pos.expected_correction in ["I", "X", "Z", "XZ"]
        assert pos.actual_correction in ["I", "X", "Z", "XZ"]
        assert pos.final_measured_bit in [0, 1]
        assert pos.expected_bit == pos.encoded_bit
        assert pos.fidelity >= 0.999999
        assert pos.is_match is True


def test_packet_clean_json_serialization():
    message = "SERIALIZE_ME_TO_JSON"
    rng = np.random.default_rng(42)

    packet, _, _ = create_signature_packet(
        session_id="session-json",
        sender_id="alice",
        recipient_id="bob",
        message=message,
        signature_length=6,
        rng=rng,
    )

    json_str = packet.model_dump_json()
    assert isinstance(json_str, str)

    parsed_dict = json.loads(json_str)
    assert parsed_dict["sender_id"] == "alice"
    assert parsed_dict["signature_length"] == 6
    assert len(parsed_dict["positions"]) == 6


def test_basic_verification_summary_distributions():
    message = "DISTRIBUTION_TEST_PAYLOAD"
    rng = np.random.default_rng(42)

    packet, _, _ = create_signature_packet(
        session_id="session-dist",
        sender_id="alice",
        recipient_id="bob",
        message=message,
        signature_length=15,
        rng=rng,
    )

    summary = verify_signature_packet_basic(packet, expected_message=message)

    assert summary.total_positions == 15
    assert summary.matching_positions == 15
    assert summary.mismatching_positions == 0
    assert summary.mismatch_rate == 0.0
    assert summary.average_fidelity >= 0.999999
    assert summary.digest_matches is True
    assert summary.is_perfect_match is True

    total_basis_count = sum(summary.basis_distribution.values())
    assert total_basis_count == 15
    assert set(summary.basis_distribution.keys()) == {"X", "Y", "Z"}

    total_corr_count = sum(summary.correction_distribution.values())
    assert total_corr_count == 15
    assert set(summary.correction_distribution.keys()) == {"I", "X", "Z", "XZ"}


def test_message_change_invalidates_packet_digest_verification():
    original_message = "ORIGINAL_AUTHENTICATED_COMMAND"
    tampered_message = "TAMPERED_FRAUDULENT_COMMAND"
    rng = np.random.default_rng(42)

    packet, _, _ = create_signature_packet(
        session_id="session-tamper",
        sender_id="alice",
        recipient_id="bob",
        message=original_message,
        signature_length=8,
        rng=rng,
    )

    valid_summary = verify_signature_packet_basic(packet, expected_message=original_message)
    assert valid_summary.digest_matches is True
    assert valid_summary.is_perfect_match is True

    invalid_summary = verify_signature_packet_basic(packet, expected_message=tampered_message)
    assert invalid_summary.digest_matches is False
    assert invalid_summary.is_perfect_match is False
