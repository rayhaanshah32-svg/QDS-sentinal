from fastapi.testclient import TestClient
from app.main import app
from app.layer1_protocol.protocol_session import run_protocol_session

client = TestClient(app)


def test_protocol_session_direct_execution():
    session_result = run_protocol_session(
        message="AUTHENTICATED_COMMAND_123",
        sender_id="alice",
        recipient_id="bob",
        signature_length=12,
        seed=100,
    )

    assert session_result.protocol_version == "1.0.0"
    assert session_result.message == "AUTHENTICATED_COMMAND_123"
    assert len(session_result.signature_positions) == 12
    assert len(session_result.teleportation_events) == 12
    assert len(session_result.measurement_events) == 12
    assert session_result.verification_summary.total_positions == 12
    assert session_result.verification_summary.mismatching_positions == 0
    assert session_result.verification_summary.mismatch_count == 0
    assert session_result.verification_summary.mismatch_rate == 0.0
    assert session_result.verification_summary.is_perfect_match is True


def test_api_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "QDS Sentinel"
    assert data["version"] == "0.1.0"
    assert "Layer 1" in data["layer"]


def test_api_example_session_endpoint():
    response = client.get("/api/v1/layer1/example-session")
    assert response.status_code == 200
    data = response.json()
    assert data["protocol_version"] == "1.0.0"
    assert data["message"] == "AUTHENTICATED_TRANSACTION_PAYLOAD_001"
    assert len(data["signature_positions"]) == 8
    assert data["verification_summary"]["is_perfect_match"] is True


def test_api_simulate_endpoint_valid():
    payload = {
        "message": "FINANCIAL_TRANSFER_ORDER_456",
        "sender_id": "alice_node",
        "recipient_id": "bob_node",
        "signature_length": 16,
        "seed": 42,
        "bell_state": "PHI_PLUS",
        "bases_allowed": ["X", "Y", "Z"],
        "session_id": "session-test-01",
        "nonce": "nonce-test-01",
        "sequence_number": 1,
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["sender_id"] == "alice_node"
    assert data["recipient_id"] == "bob_node"
    assert data["session_id"] == "session-test-01"
    assert len(data["signature_positions"]) == 16
    assert data["verification_summary"]["mismatch_count"] == 0
    assert data["verification_summary"]["is_perfect_match"] is True


def test_api_simulate_invalid_empty_message():
    payload = {
        "message": "",
        "signature_length": 16,
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_invalid_signature_length_zero():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 0,
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_invalid_signature_length_too_large():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 5000,
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_invalid_bases():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 8,
        "bases_allowed": ["W"],
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_empty_bases_list():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 8,
        "bases_allowed": [],
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_invalid_bell_state():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 8,
        "bell_state": "INVALID_BELL",
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422


def test_api_simulate_invalid_sequence_number():
    payload = {
        "message": "TEST_MESSAGE",
        "signature_length": 8,
        "sequence_number": 0,
    }
    response = client.post("/api/v1/layer1/simulate", json=payload)
    assert response.status_code == 422
