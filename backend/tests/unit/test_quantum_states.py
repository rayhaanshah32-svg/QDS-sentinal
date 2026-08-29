import math
import pytest
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState, prepare_pauli_eigenstate


def test_every_pauli_eigenstate_is_normalized():
    bases = ["X", "Y", "Z"]
    bits = [0, 1]

    for basis in bases:
        for bit in bits:
            state = prepare_pauli_eigenstate(basis=basis, bit=bit)
            norm = np.linalg.norm(state.vector)
            assert math.isclose(norm, 1.0, rel_tol=1e-6, abs_tol=1e-6)
            assert state.num_qubits == 1
            assert state.vector.shape == (2,)


def test_pauli_eigenstates_exact_vectors():
    sqrt2_inv = 1.0 / math.sqrt(2.0)

    z0 = prepare_pauli_eigenstate("Z", 0)
    assert np.allclose(z0.vector, [1.0 + 0j, 0.0 + 0j])

    z1 = prepare_pauli_eigenstate("Z", 1)
    assert np.allclose(z1.vector, [0.0 + 0j, 1.0 + 0j])

    x0 = prepare_pauli_eigenstate("X", 0)
    assert np.allclose(x0.vector, [sqrt2_inv + 0j, sqrt2_inv + 0j])

    x1 = prepare_pauli_eigenstate("X", 1)
    assert np.allclose(x1.vector, [sqrt2_inv + 0j, -sqrt2_inv + 0j])

    y0 = prepare_pauli_eigenstate("Y", 0)
    assert np.allclose(y0.vector, [sqrt2_inv + 0j, 1j * sqrt2_inv])

    y1 = prepare_pauli_eigenstate("Y", 1)
    assert np.allclose(y1.vector, [sqrt2_inv + 0j, -1j * sqrt2_inv])


def test_invalid_basis_raises_error():
    with pytest.raises(ValueError):
        prepare_pauli_eigenstate("W", 0)


def test_invalid_bit_raises_error():
    with pytest.raises(ValueError):
        prepare_pauli_eigenstate("Z", 2)


def test_unnormalized_state_vector_raises_error():
    unnormalized = np.array([2.0 + 0j, 0.0 + 0j], dtype=np.complex128)
    with pytest.raises(ValueError):
        QuantumState(name="invalid", vector=unnormalized, num_qubits=1)


def test_invalid_dimension_raises_error():
    wrong_dim = np.array([1.0 + 0j, 0.0 + 0j, 0.0 + 0j], dtype=np.complex128)
    with pytest.raises(ValueError):
        QuantumState(name="invalid_dim", vector=wrong_dim, num_qubits=1)
