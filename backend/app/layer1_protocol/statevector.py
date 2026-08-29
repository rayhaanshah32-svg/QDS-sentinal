import math
from typing import Union
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState


def tensor_product_states(states: list[QuantumState]) -> QuantumState:
    if not states:
        raise ValueError("State list cannot be empty")

    combined_vector = states[0].vector
    total_qubits = states[0].num_qubits
    name_parts = [states[0].name]

    for current_state in states[1:]:
        combined_vector = np.kron(combined_vector, current_state.vector)
        total_qubits += current_state.num_qubits
        name_parts.append(current_state.name)

    combined_name = " (x) ".join(name_parts)
    return QuantumState(name=combined_name, vector=combined_vector, num_qubits=total_qubits)


def calculate_fidelity(
    state_a: Union[QuantumState, np.ndarray],
    state_b: Union[QuantumState, np.ndarray],
) -> float:
    vector_a = state_a.vector if isinstance(state_a, QuantumState) else np.asarray(state_a, dtype=np.complex128)
    vector_b = state_b.vector if isinstance(state_b, QuantumState) else np.asarray(state_b, dtype=np.complex128)

    if vector_a.shape != vector_b.shape:
        raise ValueError(
            f"State dimensions do not match for fidelity calculation: {vector_a.shape} vs {vector_b.shape}"
        )

    inner_product = np.vdot(vector_a, vector_b)
    fidelity_value = float(np.abs(inner_product) ** 2)
    return fidelity_value


def validate_statevector(vector: np.ndarray, num_qubits: int) -> bool:
    expected_dim = 2 ** num_qubits
    if vector.shape != (expected_dim,):
        raise ValueError(f"Vector shape {vector.shape} does not match expected dimension {expected_dim}")
    norm = float(np.linalg.norm(vector))
    if not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
        raise ValueError(f"Statevector norm is {norm}, expected 1.0")
    return True
