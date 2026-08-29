from abc import ABC, abstractmethod
import numpy as np

from app.layer1_protocol.quantum_states import QuantumState


class NoiseModel(ABC):
    @abstractmethod
    def apply_noise(self, state: QuantumState, rng: np.random.Generator = None) -> QuantumState:
        pass


class NoNoise(NoiseModel):
    def apply_noise(self, state: QuantumState, rng: np.random.Generator = None) -> QuantumState:
        return QuantumState(name=state.name, vector=np.copy(state.vector), num_qubits=state.num_qubits)


class DepolarizingNoise(NoiseModel):
    def __init__(self, error_probability: float = 0.0) -> None:
        if not (0.0 <= error_probability <= 1.0):
            raise ValueError(f"Error probability must be in [0.0, 1.0], got {error_probability}")
        self.error_probability = error_probability

    def apply_noise(self, state: QuantumState, rng: np.random.Generator = None) -> QuantumState:
        if self.error_probability == 0.0:
            return QuantumState(name=state.name, vector=np.copy(state.vector), num_qubits=state.num_qubits)
        if rng is None:
            rng = np.random.default_rng()
        if rng.random() > self.error_probability:
            return QuantumState(name=state.name, vector=np.copy(state.vector), num_qubits=state.num_qubits)
        random_choice = rng.integers(0, 3)
        if random_choice == 0:
            from app.layer1_protocol.quantum_gates import GATE_X
            new_vec = np.dot(GATE_X, state.vector)
        elif random_choice == 1:
            from app.layer1_protocol.quantum_gates import GATE_Y
            new_vec = np.dot(GATE_Y, state.vector)
        else:
            from app.layer1_protocol.quantum_gates import GATE_Z
            new_vec = np.dot(GATE_Z, state.vector)
        return QuantumState(name=f"Noisy({state.name})", vector=new_vec, num_qubits=state.num_qubits)


class PauliFlipNoise(NoiseModel):
    def __init__(self, flip_probability: float = 0.0, flip_type: str = "X") -> None:
        if not (0.0 <= flip_probability <= 1.0):
            raise ValueError(f"Flip probability must be in [0.0, 1.0], got {flip_probability}")
        self.flip_probability = flip_probability
        self.flip_type = flip_type.upper()

    def apply_noise(self, state: QuantumState, rng: np.random.Generator = None) -> QuantumState:
        if self.flip_probability == 0.0:
            return QuantumState(name=state.name, vector=np.copy(state.vector), num_qubits=state.num_qubits)
        if rng is None:
            rng = np.random.default_rng()
        if rng.random() > self.flip_probability:
            return QuantumState(name=state.name, vector=np.copy(state.vector), num_qubits=state.num_qubits)
        from app.layer1_protocol.quantum_gates import get_gate_by_name
        gate_matrix = get_gate_by_name(self.flip_type)
        new_vec = np.dot(gate_matrix, state.vector)
        return QuantumState(name=f"Flipped({state.name})", vector=new_vec, num_qubits=state.num_qubits)
