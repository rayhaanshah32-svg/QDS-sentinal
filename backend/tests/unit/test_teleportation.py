import math
import pytest
import numpy as np

from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate, QuantumState
from app.layer1_protocol.teleportation import simulate_teleportation
from app.layer1_protocol.noise_models import NoNoise
from app.layer1_protocol.statevector import calculate_fidelity
from app.layer1_protocol.pauli_corrections import get_expected_pauli_correction, apply_pauli_correction
from app.layer1_protocol.measurement import measure_two_qubits_computational
from app.layer1_protocol.quantum_gates import GATE_H, apply_single_qubit_gate, apply_cnot_gate
from app.layer1_protocol.bell_states import create_bell_state


def test_teleportation_fidelity_all_six_pauli_eigenstates():
    bases = ["X", "Y", "Z"]
    bits = [0, 1]

    for basis in bases:
        for bit in bits:
            for seed in [1, 2, 3, 4, 5, 42, 100, 2024]:
                rng = np.random.default_rng(seed)
                input_state = prepare_pauli_eigenstate(basis=basis, bit=bit)
                result = simulate_teleportation(
                    input_state=input_state,
                    bell_state_label="PHI_PLUS",
                    noise_model=NoNoise(),
                    rng=rng,
                )

                assert result.fidelity >= 0.999999
                assert result.bell_measurement_bits in ["00", "01", "10", "11"]
                assert result.applied_correction in ["I", "X", "Z", "XZ"]
                assert len(result.step_trace) > 0


def test_all_four_bell_measurement_branches_explicitly():
    bases = ["X", "Y", "Z"]
    bits = [0, 1]
    branches = ["00", "01", "10", "11"]

    for basis in bases:
        for bit in bits:
            input_state = prepare_pauli_eigenstate(basis=basis, bit=bit)
            bell_state = create_bell_state("PHI_PLUS")

            composite_vector = np.kron(input_state.vector, bell_state.vector)
            after_cnot = apply_cnot_gate(composite_vector, 0, 1, 3)
            after_hadamard = apply_single_qubit_gate(after_cnot, GATE_H, 0, 3)

            for target_branch in branches:
                class DeterministicChoiceRNG:
                    def choice(self, items, p=None):
                        return target_branch

                    def random(self):
                        return 0.0

                mock_rng = DeterministicChoiceRNG()

                branch, collapsed_vec, _ = measure_two_qubits_computational(
                    statevector=after_hadamard,
                    qubit_a=0,
                    qubit_b=1,
                    total_qubits=3,
                    rng=mock_rng,
                )

                assert branch == target_branch
                raw_receiver = QuantumState(
                    name=f"collapsed_{branch}",
                    vector=collapsed_vec,
                    num_qubits=1,
                )
                correction = get_expected_pauli_correction(branch, "PHI_PLUS")
                corrected_receiver = apply_pauli_correction(raw_receiver, correction)
                fidelity = calculate_fidelity(input_state, corrected_receiver)
                assert fidelity >= 0.999999


def test_teleportation_across_all_four_bell_states():
    bell_labels = ["PHI_PLUS", "PHI_MINUS", "PSI_PLUS", "PSI_MINUS"]
    bases = ["X", "Y", "Z"]
    bits = [0, 1]

    for bell_label in bell_labels:
        for basis in bases:
            for bit in bits:
                rng = np.random.default_rng(77)
                input_state = prepare_pauli_eigenstate(basis=basis, bit=bit)
                result = simulate_teleportation(
                    input_state=input_state,
                    bell_state_label=bell_label,
                    noise_model=NoNoise(),
                    rng=rng,
                )
                assert result.fidelity >= 0.999999


def test_fidelity_phase_invariance():
    state = prepare_pauli_eigenstate("Z", 0)
    for angle in [0.0, math.pi / 4, math.pi / 2, math.pi, 3 * math.pi / 2, 2 * math.pi]:
        phase_factor = np.exp(1j * angle)
        phased_vector = state.vector * phase_factor
        phased_state = QuantumState(name="phased", vector=phased_vector, num_qubits=1)
        fidelity = calculate_fidelity(state, phased_state)
        assert math.isclose(fidelity, 1.0, rel_tol=1e-6, abs_tol=1e-6)


def test_teleportation_seeded_determinism():
    state = prepare_pauli_eigenstate("Y", 1)

    rng1 = np.random.default_rng(999)
    result1 = simulate_teleportation(state, "PHI_PLUS", rng=rng1)

    rng2 = np.random.default_rng(999)
    result2 = simulate_teleportation(state, "PHI_PLUS", rng=rng2)

    assert result1.bell_measurement_bits == result2.bell_measurement_bits
    assert result1.applied_correction == result2.applied_correction
    assert np.allclose(result1.receiver_state_after_correction.vector, result2.receiver_state_after_correction.vector)
    assert math.isclose(result1.fidelity, result2.fidelity)


def test_teleportation_with_invalid_state():
    class DummyInvalidState:
        num_qubits = 2

    with pytest.raises(ValueError):
        simulate_teleportation(input_state=DummyInvalidState())
