from dataclasses import dataclass
from typing import Literal
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState
from app.layer1_protocol.quantum_gates import GATE_H, apply_single_qubit_gate, apply_cnot_gate
from app.layer1_protocol.bell_states import create_bell_state
from app.layer1_protocol.measurement import measure_two_qubits_computational
from app.layer1_protocol.pauli_corrections import get_expected_pauli_correction, apply_pauli_correction
from app.layer1_protocol.statevector import calculate_fidelity
from app.layer1_protocol.noise_models import NoiseModel, NoNoise


@dataclass
class TeleportationResult:
    input_state: QuantumState
    bell_state_label: str
    bell_measurement_bits: str
    measurement_probabilities: dict[str, float]
    expected_correction: str
    applied_correction: str
    receiver_state_before_correction: QuantumState
    receiver_state_after_correction: QuantumState
    fidelity: float
    step_trace: list[str]


def simulate_teleportation(
    input_state: QuantumState,
    bell_state_label: Literal["PHI_PLUS", "PHI_MINUS", "PSI_PLUS", "PSI_MINUS"] = "PHI_PLUS",
    noise_model: NoiseModel = None,
    rng: np.random.Generator = None,
) -> TeleportationResult:
    if input_state.num_qubits != 1:
        raise ValueError(f"Input state must be 1 qubit, got {input_state.num_qubits}")

    if noise_model is None:
        noise_model = NoNoise()

    if rng is None:
        rng = np.random.default_rng()

    step_trace = []

    bell_state = create_bell_state(bell_state_label)
    step_trace.append(f"Prepared Bell state {bell_state_label} on qubits (q1, q2)")

    three_qubit_vector = np.kron(input_state.vector, bell_state.vector)
    step_trace.append(f"Formed composite 3-qubit state |q0> (x) |q1,q2> with input {input_state.name}")

    state_after_cnot = apply_cnot_gate(
        statevector=three_qubit_vector,
        control_qubit=0,
        target_qubit=1,
        total_qubits=3,
    )
    step_trace.append("Applied CNOT gate with control q0 and target q1")

    state_after_hadamard = apply_single_qubit_gate(
        statevector=state_after_cnot,
        gate_matrix=GATE_H,
        target_qubit=0,
        total_qubits=3,
    )
    step_trace.append("Applied Hadamard gate on qubit q0")

    measurement_bits, collapsed_q2_vector, branch_probs = measure_two_qubits_computational(
        statevector=state_after_hadamard,
        qubit_a=0,
        qubit_b=1,
        total_qubits=3,
        rng=rng,
    )
    step_trace.append(f"Measured qubits (q0, q1) in computational basis, outcome bits: '{measurement_bits}'")

    raw_receiver_state = QuantumState(
        name=f"q2_collapsed_{measurement_bits}",
        vector=collapsed_q2_vector,
        num_qubits=1,
    )

    noisy_receiver_state = noise_model.apply_noise(raw_receiver_state, rng=rng)

    expected_correction = get_expected_pauli_correction(measurement_bits, bell_state_label=bell_state_label)
    applied_correction = expected_correction

    corrected_receiver_state = apply_pauli_correction(
        state=noisy_receiver_state,
        correction_name=applied_correction,
    )
    step_trace.append(f"Applied Pauli correction '{applied_correction}' to receiver qubit q2")

    fidelity_value = calculate_fidelity(input_state, corrected_receiver_state)
    step_trace.append(f"Calculated state fidelity: {fidelity_value:.8f}")

    return TeleportationResult(
        input_state=input_state,
        bell_state_label=bell_state_label,
        bell_measurement_bits=measurement_bits,
        measurement_probabilities=branch_probs,
        expected_correction=expected_correction,
        applied_correction=applied_correction,
        receiver_state_before_correction=raw_receiver_state,
        receiver_state_after_correction=corrected_receiver_state,
        fidelity=fidelity_value,
        step_trace=step_trace,
    )
