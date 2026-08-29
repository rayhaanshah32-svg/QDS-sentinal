import hashlib
import pytest
import numpy as np

from app.layer1_protocol.qds_keygen import generate_signature_material, compute_message_digest


def test_compute_message_digest():
    message = "Hello Quantum World"
    digest = compute_message_digest(message)
    expected = hashlib.sha256(message.encode("utf-8")).hexdigest()
    assert digest == expected


def test_seeded_keygen_is_deterministic():
    message = "TEST_PAYLOAD"
    seed = 12345

    rng1 = np.random.default_rng(seed)
    key_material_1 = generate_signature_material(
        message=message,
        signature_length=16,
        rng=rng1,
    )

    rng2 = np.random.default_rng(seed)
    key_material_2 = generate_signature_material(
        message=message,
        signature_length=16,
        rng=rng2,
    )

    assert key_material_1.message_digest == key_material_2.message_digest
    assert len(key_material_1.signature_elements) == 16
    assert len(key_material_2.signature_elements) == 16

    for el1, el2 in zip(key_material_1.signature_elements, key_material_2.signature_elements):
        assert el1.position_index == el2.position_index
        assert el1.basis == el2.basis
        assert el1.bit_value == el2.bit_value


def test_keygen_invalid_signature_length():
    with pytest.raises(ValueError):
        generate_signature_material("test", signature_length=0)


def test_keygen_invalid_bases():
    with pytest.raises(ValueError):
        generate_signature_material("test", signature_length=8, allowed_bases=["INVALID"])
