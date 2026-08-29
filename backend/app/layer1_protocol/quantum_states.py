import math
from dataclasses import dataclass
from typing import Literal
import numpy as np


@dataclass
class QuantumState:
    name: str
    vector: np.ndarray
    num_qubits: int = 1

    def __post_init__(self) -> None:
        self.vector = np.asarray(self.vector, dtype=np.complex128)
        expected_dimension = 2 ** self.num_qubits
        if self.vector.shape != (expected_dimension,):
            raise ValueError(
                f"State vector dimension {self.vector.shape} does not match expected dimension {expected_dimension} for {self.num_qubits} qubits"
            )
        norm_value = np.linalg.norm(self.vector)
        if not math.isclose(norm_value, 1.0, rel_tol=1e-5, abs_tol=1e-5):
            raise ValueError(
                f"State vector is not normalized. Calculated norm is {norm_value}"
            )

    def to_complex_list(self) -> list[list[float]]:
        result = []
        for amplitude in self.vector:
            real_part = float(np.real(amplitude))
            imag_part = float(np.imag(amplitude))
            result.append([real_part, imag_part])
        return result


def prepare_pauli_eigenstate(basis: Literal["X", "Y", "Z"], bit: int) -> QuantumState:
    normalized_basis = basis.upper()
    if normalized_basis not in ["X", "Y", "Z"]:
        raise ValueError(f"Invalid basis '{basis}'. Allowed bases are 'X', 'Y', 'Z'")

    if bit not in [0, 1]:
        raise ValueError(f"Invalid bit '{bit}'. Bit must be 0 or 1")

    sqrt2_inv = 1.0 / math.sqrt(2.0)

    if normalized_basis == "Z":
        if bit == 0:
            vector = np.array([1.0 + 0.0j, 0.0 + 0.0j], dtype=np.complex128)
            name = "|0>"
        else:
            vector = np.array([0.0 + 0.0j, 1.0 + 0.0j], dtype=np.complex128)
            name = "|1>"

    elif normalized_basis == "X":
        if bit == 0:
            vector = np.array([sqrt2_inv + 0.0j, sqrt2_inv + 0.0j], dtype=np.complex128)
            name = "|+>"
        else:
            vector = np.array([sqrt2_inv + 0.0j, -sqrt2_inv + 0.0j], dtype=np.complex128)
            name = "|->"

    elif normalized_basis == "Y":
        if bit == 0:
            vector = np.array([sqrt2_inv + 0.0j, 0.0 + 1j * sqrt2_inv], dtype=np.complex128)
            name = "|+i>"
        else:
            vector = np.array([sqrt2_inv + 0.0j, 0.0 - 1j * sqrt2_inv], dtype=np.complex128)
            name = "|-i>"

    return QuantumState(name=name, vector=vector, num_qubits=1)
