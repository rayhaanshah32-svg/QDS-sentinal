import math
import pytest
import numpy as np

from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate
from app.layer1_protocol.measurement import measure_in_basis, measure_two_qubits_computational


def test_measurement_of_pauli_eigenstate_in_own_basis():
    rng = np.random.default_rng(12345)
    bases = ["X", "Y", "Z"]

    for basis in bases:
        for bit in [0, 1]:
            state = prepare_pauli_eigenstate(basis=basis, bit=bit)
            result = measure_in_basis(state=state, basis=basis, rng=rng)

            assert result.outcome_bit == bit
            assert result.basis == basis
            assert result.is_deterministic is True
            expected_key = str(bit)
            assert math.isclose(result.probabilities[expected_key], 1.0, rel_tol=1e-6)


def test_measurement_probabilities_across_bases():
    rng = np.random.default_rng(42)
    state_z0 = prepare_pauli_eigenstate(basis="Z", bit=0)

    result_x = measure_in_basis(state=state_z0, basis="X", rng=rng)
    assert math.isclose(result_x.probabilities["0"], 0.5, rel_tol=1e-6)
    assert math.isclose(result_x.probabilities["1"], 0.5, rel_tol=1e-6)
    assert result_x.is_deterministic is False

    result_y = measure_in_basis(state=state_z0, basis="Y", rng=rng)
    assert math.isclose(result_y.probabilities["0"], 0.5, rel_tol=1e-6)
    assert math.isclose(result_y.probabilities["1"], 0.5, rel_tol=1e-6)
    assert result_y.is_deterministic is False


def test_invalid_measurement_basis():
    state = prepare_pauli_eigenstate("Z", 0)
    with pytest.raises(ValueError):
        measure_in_basis(state, "INVALID")


def test_measure_two_qubits_computational():
    rng = np.random.default_rng(99)
    state_3qubit = np.array([0.5, 0.0, 0.5, 0.0, 0.5, 0.0, 0.5, 0.0], dtype=np.complex128)

    branch, collapsed_vec, probs = measure_two_qubits_computational(
        statevector=state_3qubit,
        qubit_a=0,
        qubit_b=1,
        total_qubits=3,
        rng=rng,
    )

    assert branch in ["00", "01", "10", "11"]
    assert len(collapsed_vec) == 2
    assert math.isclose(np.linalg.norm(collapsed_vec), 1.0, rel_tol=1e-6)
    assert len(probs) == 4
