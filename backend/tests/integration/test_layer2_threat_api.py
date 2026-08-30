"""
Integration tests – Layer 2 API Endpoints

Tests the full HTTP flow: Layer 1 simulation → Layer 2 assessment → HTTP response.
Uses FastAPI's TestClient (synchronous, no real server needed).
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.layer2_threat.replay_ledger import default_ledger

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_ledger():
    """Reset the shared replay ledger between tests."""
    default_ledger.clear()
    yield
    default_ledger.clear()


# ---------------------------------------------------------------------------
# /assess endpoint
# ---------------------------------------------------------------------------

CLEAN_REQUEST = {
    "simulation": {
        "message": "INTEGRATION_TEST_CLEAN",
        "sender_id": "alice",
        "recipient_id": "bob",
        "signature_length": 16,
        "seed": 42,
        "bell_state": "PHI_PLUS",
        "bases_allowed": ["X", "Y", "Z"],
        "session_id": "int-test-clean-001",
        "nonce": "nonce-int-42",
        "sequence_number": 1,
    },
    "verification_mode": "direct",
}


def test_assess_clean_session_returns_200():
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    assert response.status_code == 200


def test_assess_clean_session_is_clean():
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    data = response.json()
    assert data["threat_level"] == "CLEAN"
    assert data["threat_category"] == "NONE"
    assert data["findings"] == []
    assert "ACCEPT" in data["security_decision"]


def test_assess_clean_declares_verification_mode_in_decision():
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    data = response.json()
    assert "verification_mode=direct" in data["security_decision"]
    assert "s_a=" in data["security_decision"]


def test_assess_forwarded_mode_uses_s_v_in_decision():
    req = {**CLEAN_REQUEST, "verification_mode": "forwarded"}
    response = client.post("/api/v1/layer2/assess", json=req)
    data = response.json()
    assert "verification_mode=forwarded" in data["security_decision"]
    assert "s_v=" in data["security_decision"]
    # Must NOT have s_a as primary threshold
    assert "threshold=s_a" not in data["security_decision"]


def test_assess_invalid_threshold_order_returns_422():
    req = {**CLEAN_REQUEST, "s_a": 0.25, "s_v": 0.10}  # s_a > s_v — invalid
    response = client.post("/api/v1/layer2/assess", json=req)
    assert response.status_code == 422


def test_assess_returns_session_provenance():
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    data = response.json()
    assert data["session_id"] == "int-test-clean-001"
    assert data["sender_id"] == "alice"
    assert data["recipient_id"] == "bob"


def test_assess_response_has_all_required_fields():
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    data = response.json()
    required = [
        "threat_level", "threat_category", "findings", "security_decision",
        "digest_check", "qber_analysis", "correction_consistency",
        "fidelity_analysis", "replay_detection", "bob_charlie_metrics",
        "s_a_used", "s_v_used", "e_honest_used", "simulation_disclaimer",
        "verification_mode",
    ]
    for field in required:
        assert field in data, f"Missing field: {field}"


def test_assess_bob_charlie_metrics_never_collapsed():
    """direct_mismatch_rate and forwarded_mismatch_rate must be separate fields."""
    response = client.post("/api/v1/layer2/assess", json=CLEAN_REQUEST)
    data = response.json()
    bc = data["bob_charlie_metrics"]
    assert "direct_mismatch_rate" in bc
    assert "forwarded_mismatch_rate" in bc
    # They must be separate — verify both keys exist independently
    assert bc["direct_threshold_s_a"] != bc["forwarded_threshold_s_v"]


# ---------------------------------------------------------------------------
# /assess-existing endpoint
# ---------------------------------------------------------------------------

def test_assess_existing_returns_200():
    """First fetch a Layer 1 session, then assess it via assess-existing."""
    # Get a Layer 1 session
    sim_resp = client.get("/api/v1/layer1/example-session")
    assert sim_resp.status_code == 200
    session_data = sim_resp.json()

    # Now assess it
    assess_req = {
        "session": session_data,
        "verification_mode": "direct",
    }
    response = client.post("/api/v1/layer2/assess-existing", json=assess_req)
    assert response.status_code == 200


def test_assess_existing_clean_session():
    sim_resp = client.get("/api/v1/layer1/example-session")
    session_data = sim_resp.json()

    assess_req = {"session": session_data, "verification_mode": "direct"}
    response = client.post("/api/v1/layer2/assess-existing", json=assess_req)
    data = response.json()
    assert data["threat_level"] == "CLEAN"
    assert "ACCEPT" in data["security_decision"]


# ---------------------------------------------------------------------------
# Example endpoints
# ---------------------------------------------------------------------------

def test_example_clean_endpoint():
    response = client.get("/api/v1/layer2/example-clean")
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] == "CLEAN"
    assert "ACCEPT" in data["security_decision"]


def test_example_replay_endpoint_returns_critical():
    response = client.get("/api/v1/layer2/example-replay")
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] == "CRITICAL"
    assert data["replay_detection"]["is_replay"] is True
    assert "REJECT" in data["security_decision"]
    assert any("REPLAY" in f for f in data["findings"])


def test_example_forgery_endpoint_returns_critical():
    response = client.get("/api/v1/layer2/example-forgery")
    assert response.status_code == 200
    data = response.json()
    assert data["threat_level"] == "CRITICAL"
    assert data["digest_check"]["digest_matches"] is False
    assert "REJECT" in data["security_decision"]
    assert any("PAYLOAD_DIGEST_MISMATCH" in f for f in data["findings"])


def test_example_clean_has_disclaimer():
    response = client.get("/api/v1/layer2/example-clean")
    data = response.json()
    assert "software simulation" in data["simulation_disclaimer"].lower()


# ---------------------------------------------------------------------------
# Correction-tampering via assess-existing (Layer 2 modifies copy, not L1)
# ---------------------------------------------------------------------------

def test_assess_existing_correction_tampering():
    """
    Submit a session with manually mismatched corrections via assess-existing.
    This tests that correction_consistency correctly flags the tampered field.
    """
    # Build a clean session then tamper one position's actual_correction
    sim_resp = client.get("/api/v1/layer1/example-session")
    session_data = sim_resp.json()

    # Tamper position 0: change actual_correction to something wrong
    session_data["signature_positions"][0]["actual_correction"] = "X"
    session_data["signature_positions"][0]["expected_correction"] = "I"

    assess_req = {"session": session_data, "verification_mode": "direct"}
    response = client.post("/api/v1/layer2/assess-existing", json=assess_req)
    assert response.status_code == 200
    data = response.json()

    assert data["correction_consistency"]["flag_raised"] is True
    assert data["threat_level"] == "CRITICAL"
    assert any("CORRECTION_TAMPERING" in f for f in data["findings"])


# ---------------------------------------------------------------------------
# Replay via /assess Endpoint Live Statefulness Test
# ---------------------------------------------------------------------------

def test_assess_replay_same_packet_twice_rejected():
    """
    Submitting the exact same simulation payload twice to /assess MUST cause
    the second call to be flagged as REJECT / REPLAY_ATTACK.
    """
    req = {
        "simulation": {
            "message": "REPLAY_DEMO_PAYLOAD",
            "sender_id": "alice",
            "recipient_id": "bob",
            "signature_length": 16,
            "seed": 55,
            "bell_state": "PHI_PLUS",
            "bases_allowed": ["X", "Y", "Z"],
            "session_id": "assess-replay-demo-001",
            "nonce": "nonce-assess-replay-55",
            "sequence_number": 1,
        },
        "verification_mode": "direct",
    }

    # First call -> ACCEPT
    resp1 = client.post("/api/v1/layer2/assess", json=req)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "ACCEPT" in data1["security_decision"]
    assert data1["replay_detection"]["is_replay"] is False

    # Second call with identical session_id & nonce -> REJECT
    resp2 = client.post("/api/v1/layer2/assess", json=req)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert "REJECT" in data2["security_decision"]
    assert data2["threat_level"] == "CRITICAL"
    assert data2["replay_detection"]["is_replay"] is True
    assert any("REPLAY_ATTACK" in f for f in data2["findings"])


# ---------------------------------------------------------------------------
# /attack-simulate Endpoint Top-Level Key Separation Test
# ---------------------------------------------------------------------------

def test_attack_simulate_top_level_keys_separate():
    req = {
        "simulation": {
            "message": "ATTACK_SIMULATION_PAYLOAD",
            "sender_id": "alice",
            "recipient_id": "bob",
            "signature_length": 16,
            "seed": 42,
            "bell_state": "PHI_PLUS",
            "bases_allowed": ["X", "Y", "Z"],
            "session_id": "atk-sim-001",
            "nonce": "nonce-atk-42",
            "sequence_number": 1,
        },
        "attack_type": "PARTIAL_FORGERY",
        "intensity": 0.25,
        "verification_mode": "direct",
    }

    response = client.post("/api/v1/layer2/attack-simulate", json=req)
    assert response.status_code == 200
    data = response.json()

    # Top-level keys MUST be separate, never merged
    assert "attack_metadata" in data
    assert "assessment" in data
    assert len(data.keys()) == 2

    # Assessment section alone MUST be schema-valid ThreatAssessment
    assessment = data["assessment"]
    assert "threat_level" in assessment
    assert "security_decision" in assessment
    assert "digest_check" in assessment
    assert "qber_analysis" in assessment
    assert "bob_charlie_metrics" in assessment

    # Ground truth metadata section
    meta = data["attack_metadata"]
    assert meta["attack_type"] == "PARTIAL_FORGERY"
    assert meta["intensity"] == 0.25
    assert meta["seed"] == 42


def test_invalid_threshold_chain_human_readable_422():
    req = {
        "simulation": {
            "message": "TEST_INVALID_ORDER",
            "sender_id": "alice",
            "recipient_id": "bob",
            "signature_length": 16,
            "seed": 42,
            "bell_state": "PHI_PLUS",
            "bases_allowed": ["X", "Y", "Z"],
            "session_id": "inv-001",
            "nonce": "nonce-inv-42",
            "sequence_number": 1,
        },
        "s_a": 0.30,
        "s_v": 0.20,  # s_a > s_v is invalid
    }
    response = client.post("/api/v1/layer2/assess", json=req)
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert "Threshold ordering violated" in detail
    assert "must be strictly less than" in detail
