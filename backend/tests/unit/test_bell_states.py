import math
import pytest
import numpy as np

from app.layer1_protocol.bell_states import create_bell_state


def test_every_bell_state_is_normalized():
    labels = ["PHI_PLUS", "PHI_MINUS", "PSI_PLUS", "PSI_MINUS"]

    for label in labels:
        state = create_bell_state(label=label)
        norm = np.linalg.norm(state.vector)
        assert math.isclose(norm, 1.0, rel_tol=1e-6, abs_tol=1e-6)
        assert state.num_qubits == 2
        assert state.vector.shape == (4,)


def test_bell_state_correlations():
    phi_plus = create_bell_state("PHI_PLUS")
    assert math.isclose(abs(phi_plus.vector[0]) ** 2, 0.5, rel_tol=1e-6)
    assert math.isclose(abs(phi_plus.vector[1]) ** 2, 0.0, abs_tol=1e-6)
    assert math.isclose(abs(phi_plus.vector[2]) ** 2, 0.0, abs_tol=1e-6)
    assert math.isclose(abs(phi_plus.vector[3]) ** 2, 0.5, rel_tol=1e-6)

    psi_plus = create_bell_state("PSI_PLUS")
    assert math.isclose(abs(psi_plus.vector[0]) ** 2, 0.0, abs_tol=1e-6)
    assert math.isclose(abs(psi_plus.vector[1]) ** 2, 0.5, rel_tol=1e-6)
    assert math.isclose(abs(psi_plus.vector[2]) ** 2, 0.5, rel_tol=1e-6)
    assert math.isclose(abs(psi_plus.vector[3]) ** 2, 0.0, abs_tol=1e-6)


def test_invalid_bell_state_label():
    with pytest.raises(ValueError):
        create_bell_state("INVALID_LABEL")
