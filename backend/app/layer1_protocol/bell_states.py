import math
from typing import Literal
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState


def create_bell_state(
    label: Literal["PHI_PLUS", "PHI_MINUS", "PSI_PLUS", "PSI_MINUS"] = "PHI_PLUS",
) -> QuantumState:
    normalized_label = label.upper()
    sqrt2_inv = 1.0 / math.sqrt(2.0)

    if normalized_label == "PHI_PLUS":
        vector = np.array([sqrt2_inv, 0.0, 0.0, sqrt2_inv], dtype=np.complex128)
        name = "|Phi+>"
    elif normalized_label == "PHI_MINUS":
        vector = np.array([sqrt2_inv, 0.0, 0.0, -sqrt2_inv], dtype=np.complex128)
        name = "|Phi->"
    elif normalized_label == "PSI_PLUS":
        vector = np.array([0.0, sqrt2_inv, sqrt2_inv, 0.0], dtype=np.complex128)
        name = "|Psi+>"
    elif normalized_label == "PSI_MINUS":
        vector = np.array([0.0, sqrt2_inv, -sqrt2_inv, 0.0], dtype=np.complex128)
        name = "|Psi->"
    else:
        raise ValueError(
            f"Invalid Bell state label '{label}'. Allowed: 'PHI_PLUS', 'PHI_MINUS', 'PSI_PLUS', 'PSI_MINUS'"
        )

    return QuantumState(name=name, vector=vector, num_qubits=2)
