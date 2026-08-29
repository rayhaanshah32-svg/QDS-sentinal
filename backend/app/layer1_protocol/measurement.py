from dataclasses import dataclass
from typing import Literal
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState, prepare_pauli_eigenstate


@dataclass
class MeasurementResult:
    basis: str
    outcome_bit: int
    probabilities: dict[str, float]
    post_measurement_state: QuantumState
    is_deterministic: bool


def measure_in_basis(
    state: QuantumState,
    basis: Literal["X", "Y", "Z"],
    rng: np.random.Generator = None,
) -> MeasurementResult:
    if state.num_qubits != 1:
        raise ValueError(f"measure_in_basis only supports 1-qubit states, got {state.num_qubits} qubits")

    normalized_basis = basis.upper()
    if normalized_basis not in ["X", "Y", "Z"]:
        raise ValueError(f"Invalid basis '{basis}'. Allowed bases are 'X', 'Y', 'Z'")

    if rng is None:
        rng = np.random.default_rng()

    state_zero = prepare_pauli_eigenstate(normalized_basis, 0)
    state_one = prepare_pauli_eigenstate(normalized_basis, 1)

    inner_product_0 = np.vdot(state_zero.vector, state.vector)
    inner_product_1 = np.vdot(state_one.vector, state.vector)

    probability_0 = float(np.abs(inner_product_0) ** 2)
    probability_1 = float(np.abs(inner_product_1) ** 2)

    total_prob = probability_0 + probability_1
    if total_prob > 0.0:
        probability_0 = probability_0 / total_prob
        probability_1 = probability_1 / total_prob

    random_sample = float(rng.random())
    if random_sample < probability_0:
        outcome_bit = 0
        post_state = state_zero
    else:
        outcome_bit = 1
        post_state = state_one

    is_deterministic = (probability_0 >= 0.999999) or (probability_1 >= 0.999999)

    return MeasurementResult(
        basis=normalized_basis,
        outcome_bit=outcome_bit,
        probabilities={"0": probability_0, "1": probability_1},
        post_measurement_state=post_state,
        is_deterministic=is_deterministic,
    )


def measure_two_qubits_computational(
    statevector: np.ndarray,
    qubit_a: int,
    qubit_b: int,
    total_qubits: int,
    rng: np.random.Generator = None,
) -> tuple[str, np.ndarray, dict[str, float]]:
    if rng is None:
        rng = np.random.default_rng()

    branch_probabilities = {"00": 0.0, "01": 0.0, "10": 0.0, "11": 0.0}
    num_amplitudes = len(statevector)

    for index in range(num_amplitudes):
        bit_a = (index >> (total_qubits - 1 - qubit_a)) & 1
        bit_b = (index >> (total_qubits - 1 - qubit_b)) & 1
        branch_key = f"{bit_a}{bit_b}"
        amplitude = statevector[index]
        branch_probabilities[branch_key] += float(np.abs(amplitude) ** 2)

    branches = ["00", "01", "10", "11"]
    prob_values = [branch_probabilities[k] for k in branches]
    prob_sum = sum(prob_values)
    normalized_probs = [p / prob_sum for p in prob_values]

    selected_branch = rng.choice(branches, p=normalized_probs)

    target_qubit = None
    for q_idx in range(total_qubits):
        if q_idx != qubit_a and q_idx != qubit_b:
            target_qubit = q_idx
            break

    target_amplitudes = [0.0 + 0.0j, 0.0 + 0.0j]
    selected_bit_a = int(selected_branch[0])
    selected_bit_b = int(selected_branch[1])

    for target_val in [0, 1]:
        index = 0
        for q_idx in range(total_qubits):
            if q_idx == qubit_a:
                bit_val = selected_bit_a
            elif q_idx == qubit_b:
                bit_val = selected_bit_b
            else:
                bit_val = target_val
            index = (index << 1) | bit_val
        target_amplitudes[target_val] = statevector[index]

    collapsed_vector = np.array(target_amplitudes, dtype=np.complex128)
    norm = np.linalg.norm(collapsed_vector)
    if norm > 0:
        collapsed_vector = collapsed_vector / norm

    return selected_branch, collapsed_vector, branch_probabilities
