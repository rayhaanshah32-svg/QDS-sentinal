import math
import numpy as np


GATE_I = np.array([[1.0 + 0.0j, 0.0 + 0.0j], [0.0 + 0.0j, 1.0 + 0.0j]], dtype=np.complex128)

GATE_X = np.array([[0.0 + 0.0j, 1.0 + 0.0j], [1.0 + 0.0j, 0.0 + 0.0j]], dtype=np.complex128)

GATE_Y = np.array([[0.0 + 0.0j, 0.0 - 1.0j], [0.0 + 1.0j, 0.0 + 0.0j]], dtype=np.complex128)

GATE_Z = np.array([[1.0 + 0.0j, 0.0 + 0.0j], [0.0 + 0.0j, -1.0 + 0.0j]], dtype=np.complex128)

SQRT2_INV = 1.0 / math.sqrt(2.0)
GATE_H = np.array(
    [
        [SQRT2_INV + 0.0j, SQRT2_INV + 0.0j],
        [SQRT2_INV + 0.0j, -SQRT2_INV + 0.0j],
    ],
    dtype=np.complex128,
)

GATE_CNOT = np.array(
    [
        [1.0 + 0.0j, 0.0 + 0.0j, 0.0 + 0.0j, 0.0 + 0.0j],
        [0.0 + 0.0j, 1.0 + 0.0j, 0.0 + 0.0j, 0.0 + 0.0j],
        [0.0 + 0.0j, 0.0 + 0.0j, 0.0 + 0.0j, 1.0 + 0.0j],
        [0.0 + 0.0j, 0.0 + 0.0j, 1.0 + 0.0j, 0.0 + 0.0j],
    ],
    dtype=np.complex128,
)


def get_gate_by_name(gate_name: str) -> np.ndarray:
    normalized_name = gate_name.upper()
    if normalized_name == "I":
        return GATE_I
    elif normalized_name == "X":
        return GATE_X
    elif normalized_name == "Y":
        return GATE_Y
    elif normalized_name == "Z":
        return GATE_Z
    elif normalized_name == "H":
        return GATE_H
    elif normalized_name == "CNOT":
        return GATE_CNOT
    else:
        raise ValueError(f"Unknown gate name '{gate_name}'")


def tensor_product_matrices(matrix_list: list[np.ndarray]) -> np.ndarray:
    if not matrix_list:
        raise ValueError("Matrix list cannot be empty")
    result = matrix_list[0]
    for current_matrix in matrix_list[1:]:
        result = np.kron(result, current_matrix)
    return result


def apply_single_qubit_gate(
    statevector: np.ndarray,
    gate_matrix: np.ndarray,
    target_qubit: int,
    total_qubits: int,
) -> np.ndarray:
    if target_qubit < 0 or target_qubit >= total_qubits:
        raise ValueError(f"Target qubit index {target_qubit} out of range for {total_qubits} qubits")

    operator_list = []
    for qubit_index in range(total_qubits):
        if qubit_index == target_qubit:
            operator_list.append(gate_matrix)
        else:
            operator_list.append(GATE_I)

    full_operator = tensor_product_matrices(operator_list)
    new_statevector = np.dot(full_operator, statevector)
    return new_statevector


def apply_cnot_gate(
    statevector: np.ndarray,
    control_qubit: int,
    target_qubit: int,
    total_qubits: int,
) -> np.ndarray:
    if control_qubit < 0 or control_qubit >= total_qubits:
        raise ValueError(f"Control qubit {control_qubit} out of range for {total_qubits} qubits")
    if target_qubit < 0 or target_qubit >= total_qubits:
        raise ValueError(f"Target qubit {target_qubit} out of range for {total_qubits} qubits")
    if control_qubit == target_qubit:
        raise ValueError("Control and target qubits cannot be the same")

    projector_0 = np.array([[1.0 + 0.0j, 0.0 + 0.0j], [0.0 + 0.0j, 0.0 + 0.0j]], dtype=np.complex128)
    projector_1 = np.array([[0.0 + 0.0j, 0.0 + 0.0j], [0.0 + 0.0j, 1.0 + 0.0j]], dtype=np.complex128)

    term0_operators = []
    term1_operators = []

    for qubit_index in range(total_qubits):
        if qubit_index == control_qubit:
            term0_operators.append(projector_0)
            term1_operators.append(projector_1)
        elif qubit_index == target_qubit:
            term0_operators.append(GATE_I)
            term1_operators.append(GATE_X)
        else:
            term0_operators.append(GATE_I)
            term1_operators.append(GATE_I)

    operator_term0 = tensor_product_matrices(term0_operators)
    operator_term1 = tensor_product_matrices(term1_operators)
    cnot_full_operator = operator_term0 + operator_term1

    new_statevector = np.dot(cnot_full_operator, statevector)
    return new_statevector
