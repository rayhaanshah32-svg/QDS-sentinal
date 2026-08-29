import pytest
import numpy as np

from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate
from app.layer1_protocol.pauli_corrections import get_expected_pauli_correction, apply_pauli_correction
from app.layer1_protocol.statevector import calculate_fidelity


def test_pauli_correction_mapping_phi_plus():
    assert get_expected_pauli_correction("00", "PHI_PLUS") == "I"
    assert get_expected_pauli_correction("01", "PHI_PLUS") == "X"
    assert get_expected_pauli_correction("10", "PHI_PLUS") == "Z"
    assert get_expected_pauli_correction("11", "PHI_PLUS") == "XZ"


def test_pauli_correction_mapping_other_bell_states():
    assert get_expected_pauli_correction("00", "PHI_MINUS") == "Z"
    assert get_expected_pauli_correction("01", "PHI_MINUS") == "XZ"
    assert get_expected_pauli_correction("10", "PHI_MINUS") == "I"
    assert get_expected_pauli_correction("11", "PHI_MINUS") == "X"

    assert get_expected_pauli_correction("00", "PSI_PLUS") == "X"
    assert get_expected_pauli_correction("01", "PSI_PLUS") == "I"
    assert get_expected_pauli_correction("10", "PSI_PLUS") == "XZ"
    assert get_expected_pauli_correction("11", "PSI_PLUS") == "Z"

    assert get_expected_pauli_correction("00", "PSI_MINUS") == "XZ"
    assert get_expected_pauli_correction("01", "PSI_MINUS") == "Z"
    assert get_expected_pauli_correction("10", "PSI_MINUS") == "X"
    assert get_expected_pauli_correction("11", "PSI_MINUS") == "I"


def test_invalid_measurement_bits_raises_error():
    with pytest.raises(ValueError):
        get_expected_pauli_correction("02")

    with pytest.raises(ValueError):
        get_expected_pauli_correction("0")


def test_invalid_bell_state_in_correction():
    with pytest.raises(ValueError):
        get_expected_pauli_correction("00", "UNKNOWN_BELL")


def test_apply_pauli_corrections_reconstruction():
    state_0 = prepare_pauli_eigenstate("Z", 0)
    state_1 = prepare_pauli_eigenstate("Z", 1)

    corrected_x = apply_pauli_correction(state_0, "X")
    assert calculate_fidelity(corrected_x, state_1) >= 0.999999

    corrected_z = apply_pauli_correction(state_1, "Z")
    assert np.allclose(corrected_z.vector, [0.0 + 0j, -1.0 + 0j])
    assert calculate_fidelity(corrected_z, state_1) >= 0.999999

    corrected_i = apply_pauli_correction(state_0, "I")
    assert calculate_fidelity(corrected_i, state_0) >= 0.999999


def test_invalid_correction_name():
    state = prepare_pauli_eigenstate("Z", 0)
    with pytest.raises(ValueError):
        apply_pauli_correction(state, "INVALID")
