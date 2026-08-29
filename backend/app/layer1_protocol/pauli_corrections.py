import numpy as np

from app.layer1_protocol.quantum_states import QuantumState
from app.layer1_protocol.quantum_gates import GATE_I, GATE_X, GATE_Y, GATE_Z


def get_expected_pauli_correction(
    measurement_bits: str,
    bell_state_label: str = "PHI_PLUS",
) -> str:
    cleaned_bits = measurement_bits.strip()
    normalized_bell_label = bell_state_label.upper().strip()

    if normalized_bell_label == "PHI_PLUS":
      mapping = {"00": "I", "01": "X", "10": "Z", "11": "XZ"}
    elif normalized_bell_label == "PHI_MINUS":
      mapping = {"00": "Z", "01": "XZ", "10": "I", "11": "X"}
    elif normalized_bell_label == "PSI_PLUS":
      mapping = {"00": "X", "01": "I", "10": "XZ", "11": "Z"}
    elif normalized_bell_label == "PSI_MINUS":
      mapping = {"00": "XZ", "01": "Z", "10": "X", "11": "I"}
    else:
      raise ValueError(f"Invalid Bell state label '{bell_state_label}'")

    if cleaned_bits not in mapping:
      raise ValueError(
          f"Invalid measurement bits '{measurement_bits}'. Expected '00', '01',"
          " '10', or '11'"
      )

    return mapping[cleaned_bits]


def apply_pauli_correction(state: QuantumState, correction_name: str) -> QuantumState:
    if state.num_qubits != 1:
      raise ValueError(
          f"apply_pauli_correction only supports 1-qubit states, got"
          f" {state.num_qubits}"
      )

    normalized_name = correction_name.upper().strip()

    if normalized_name == "I":
      corrected_vector = np.dot(GATE_I, state.vector)
    elif normalized_name == "X":
      corrected_vector = np.dot(GATE_X, state.vector)
    elif normalized_name == "Y":
      corrected_vector = np.dot(GATE_Y, state.vector)
    elif normalized_name == "Z":
      corrected_vector = np.dot(GATE_Z, state.vector)
    elif normalized_name == "XZ":
      temp_vector = np.dot(GATE_X, state.vector)
      corrected_vector = np.dot(GATE_Z, temp_vector)
    elif normalized_name == "ZX":
      temp_vector = np.dot(GATE_Z, state.vector)
      corrected_vector = np.dot(GATE_X, temp_vector)
    else:
      raise ValueError(
          f"Unknown Pauli correction '{correction_name}'. Allowed: 'I', 'X',"
          " 'Y', 'Z', 'XZ', 'ZX'"
      )

    return QuantumState(
        name=f"{normalized_name}({state.name})",
        vector=corrected_vector,
        num_qubits=1,
    )
