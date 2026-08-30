import numpy as np

from app.layer1_protocol.quantum_states import QuantumState, prepare_pauli_eigenstate


def statevector_to_bloch_coordinates(state: QuantumState) -> tuple[float, float, float]:
    if state.num_qubits != 1:
        raise ValueError(f"Bloch coordinates are only defined for 1-qubit states, got {state.num_qubits} qubits")

    alpha = state.vector[0]
    beta = state.vector[1]

    alpha_conj_beta = alpha * np.conj(beta)
    x = float(2.0 * np.real(alpha_conj_beta))
    y = float(2.0 * np.imag(np.conj(alpha) * beta))
    z = float(np.abs(alpha) ** 2 - np.abs(beta) ** 2)

    x = 0.0 if abs(x) < 1e-12 else round(x, 10)
    y = 0.0 if abs(y) < 1e-12 else round(y, 10)
    z = 0.0 if abs(z) < 1e-12 else round(z, 10)

    return (x, y, z)



def bloch_coordinates_for_basis_bit(basis: str, bit: int) -> tuple[float, float, float]:
    normalized_basis = basis.upper()
    if normalized_basis not in ["X", "Y", "Z"]:
        raise ValueError(f"Invalid basis '{basis}'. Allowed bases are 'X', 'Y', 'Z'")
    if bit not in [0, 1]:
        raise ValueError(f"Invalid bit '{bit}'. Bit must be 0 or 1")

    state = prepare_pauli_eigenstate(normalized_basis, bit)
    return statevector_to_bloch_coordinates(state)


def simulate_measurement_collapse(basis: str, bit: int, measured_bit: int) -> dict:
    normalized_basis = basis.upper()
    if normalized_basis not in ["X", "Y", "Z"]:
        raise ValueError(f"Invalid basis '{basis}'. Allowed bases are 'X', 'Y', 'Z'")
    if bit not in [0, 1]:
        raise ValueError(f"Invalid bit '{bit}'. Bit must be 0 or 1")
    if measured_bit not in [0, 1]:
        raise ValueError(f"Invalid measured_bit '{measured_bit}'. Bit must be 0 or 1")

    prepared_state = prepare_pauli_eigenstate(normalized_basis, bit)
    pre_coords = statevector_to_bloch_coordinates(prepared_state)

    post_state = prepare_pauli_eigenstate("Z", measured_bit)
    post_coords = statevector_to_bloch_coordinates(post_state)

    is_collapsed = (normalized_basis != "Z") or (bit != measured_bit)

    return {
        "basis": normalized_basis,
        "bit": bit,
        "prepared_label": prepared_state.name,
        "coordinates": {"x": pre_coords[0], "y": pre_coords[1], "z": pre_coords[2]},
        "is_collapsed": is_collapsed,
        "collapsed_coordinates": (
            {"x": post_coords[0], "y": post_coords[1], "z": post_coords[2]} if is_collapsed else None
        ),
    }
