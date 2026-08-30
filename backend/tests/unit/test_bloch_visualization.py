import math
import pytest
import numpy as np
from fastapi.testclient import TestClient

from app.main import app
from app.layer1_protocol.quantum_states import QuantumState, prepare_pauli_eigenstate
from app.layer1_protocol.bloch_visualization import (
    statevector_to_bloch_coordinates,
    bloch_coordinates_for_basis_bit,
    simulate_measurement_collapse,
)
from app.layer1_protocol.protocol_session import run_protocol_session
from app.layer2_threat.attacks import inject_attack
from app.schemas.telemetry import AttackType


client = TestClient(app)


def test_every_pauli_eigenstate_bloch_norm_is_one():
    bases = ["X", "Y", "Z"]
    bits = [0, 1]

    for basis in bases:
        for bit in bits:
            coords = bloch_coordinates_for_basis_bit(basis=basis, bit=bit)
            x, y, z = coords
            norm = math.sqrt(x**2 + y**2 + z**2)
            assert math.isclose(norm, 1.0, rel_tol=1e-6, abs_tol=1e-6)


def test_pauli_eigenstates_exact_bloch_coordinates():
    # |0> -> (0, 0, 1)
    z0 = bloch_coordinates_for_basis_bit("Z", 0)
    assert np.allclose(z0, (0.0, 0.0, 1.0), atol=1e-6)

    # |1> -> (0, 0, -1)
    z1 = bloch_coordinates_for_basis_bit("Z", 1)
    assert np.allclose(z1, (0.0, 0.0, -1.0), atol=1e-6)

    # |+> -> (1, 0, 0)
    x0 = bloch_coordinates_for_basis_bit("X", 0)
    assert np.allclose(x0, (1.0, 0.0, 0.0), atol=1e-6)

    # |-> -> (-1, 0, 0)
    x1 = bloch_coordinates_for_basis_bit("X", 1)
    assert np.allclose(x1, (-1.0, 0.0, 0.0), atol=1e-6)

    # |+i> -> (0, 1, 0)
    y0 = bloch_coordinates_for_basis_bit("Y", 0)
    assert np.allclose(y0, (0.0, 1.0, 0.0), atol=1e-6)

    # |-i> -> (0, -1, 0)
    y1 = bloch_coordinates_for_basis_bit("Y", 1)
    assert np.allclose(y1, (0.0, -1.0, 0.0), atol=1e-6)


def test_invalid_qubits_raises_error():
    two_qubit_state = QuantumState(
        name="bell",
        vector=np.array([1.0 / math.sqrt(2.0), 0.0, 0.0, 1.0 / math.sqrt(2.0)], dtype=np.complex128),
        num_qubits=2,
    )
    with pytest.raises(ValueError):
        statevector_to_bloch_coordinates(two_qubit_state)


def test_invalid_basis_and_bit_raises_error():
    with pytest.raises(ValueError):
        bloch_coordinates_for_basis_bit("INVALID", 0)

    with pytest.raises(ValueError):
        bloch_coordinates_for_basis_bit("Z", 2)

    with pytest.raises(ValueError):
        simulate_measurement_collapse("INVALID", 0, 0)

    with pytest.raises(ValueError):
        simulate_measurement_collapse("Z", 2, 0)

    with pytest.raises(ValueError):
        simulate_measurement_collapse("Z", 0, 2)


def test_simulate_measurement_collapse_clean_z():
    res = simulate_measurement_collapse("Z", 0, 0)
    assert res["basis"] == "Z"
    assert res["bit"] == 0
    assert res["prepared_label"] == "|0>"
    assert res["is_collapsed"] is False
    assert res["collapsed_coordinates"] is None
    assert np.allclose(list(res["coordinates"].values()), [0.0, 0.0, 1.0])

    res1 = simulate_measurement_collapse("Z", 1, 1)
    assert res1["is_collapsed"] is False
    assert res1["collapsed_coordinates"] is None
    assert np.allclose(list(res1["coordinates"].values()), [0.0, 0.0, -1.0])


def test_simulate_measurement_collapse_superposition_x_and_y():
    res_x = simulate_measurement_collapse("X", 0, 0)
    assert res_x["is_collapsed"] is True
    assert res_x["collapsed_coordinates"] == {"x": 0.0, "y": 0.0, "z": 1.0}

    res_y = simulate_measurement_collapse("Y", 1, 1)
    assert res_y["is_collapsed"] is True
    assert res_y["collapsed_coordinates"] == {"x": 0.0, "y": 0.0, "z": -1.0}


def test_simulate_measurement_collapse_bit_mismatch():
    res_mismatch = simulate_measurement_collapse("Z", 0, 1)
    assert res_mismatch["is_collapsed"] is True
    assert res_mismatch["collapsed_coordinates"] == {"x": 0.0, "y": 0.0, "z": -1.0}


def test_attack_injected_session_collapsed_positions():
    clean_session = run_protocol_session(
        message="AUTHENTICATED_TEST_PAYLOAD",
        signature_length=32,
        seed=42,
    )

    injected = inject_attack(
        clean_session,
        attack_type=AttackType.CORRECTION_TAMPERING,
        intensity=1.0,
        seed=42,
    )

    mismatch_count = 0
    for pos in injected.signature_positions:
        collapse_info = simulate_measurement_collapse(
            basis=pos.pauli_basis,
            bit=pos.encoded_bit,
            measured_bit=pos.final_measured_bit,
        )

        if not pos.is_match:
            mismatch_count += 1
            assert collapse_info["is_collapsed"] is True
            assert collapse_info["collapsed_coordinates"] is not None
            expected_z = 1.0 if pos.final_measured_bit == 0 else -1.0
            assert math.isclose(collapse_info["collapsed_coordinates"]["z"], expected_z, abs_tol=1e-6)

    assert mismatch_count > 0


def test_bloch_state_endpoint():
    response = client.get("/api/v1/layer1/bloch-state/X/0")
    assert response.status_code == 200
    data = response.json()
    assert data["basis"] == "X"
    assert data["bit"] == 0
    assert data["prepared_label"] == "|+>"
    assert data["coordinates"] == {"x": 1.0, "y": 0.0, "z": 0.0}
    assert data["is_collapsed"] is False
    assert data["collapsed_coordinates"] is None


def test_bloch_trace_endpoint():
    payload = {
        "message": "FINANCIAL_TRANSFER_ORDER_456",
        "sender_id": "alice",
        "recipient_id": "bob",
        "signature_length": 8,
        "seed": 42,
        "bell_state": "PHI_PLUS",
        "bases_allowed": ["X", "Y", "Z"],
    }
    response = client.post("/api/v1/layer1/bloch-trace", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 8
    for item in data:
        assert item["basis"] in ["X", "Y", "Z"]
        assert item["bit"] in [0, 1]
        assert "coordinates" in item
        assert "is_collapsed" in item
