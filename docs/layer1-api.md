# QDS Sentinel - Layer 1 REST API Reference

## Base URL
Default local server address: `http://127.0.0.1:8000`

---

## Endpoints

### 1. Health Check
- **Method**: `GET`
- **Path**: `/health`
- **Description**: Returns engine health status, application version, and layer designation.

#### Response Example (`200 OK`)
```json
{
  "status": "ok",
  "app_name": "QDS Sentinel",
  "version": "0.1.0",
  "layer": "Layer 1: Protocol Simulation Engine"
}
```

---

### 2. Get Example Simulation Session
- **Method**: `GET`
- **Path**: `/api/v1/layer1/example-session`
- **Description**: Runs and returns a predefined deterministic 8-position QDS simulation session.

#### Response Example (`200 OK`)
```json
{
  "protocol_version": "1.0.0",
  "session_id": "example-session-001",
  "signature_block_id": "8f3b2072-4a1e-450a-9ceb-788b14a08159",
  "sender_id": "alice",
  "recipient_id": "bob",
  "message": "AUTHENTICATED_TRANSACTION_PAYLOAD_001",
  "message_digest": "4a72d3f9e984950e1ef0b40e34c979d39e802a488e0e64c3ecf30b91e920dbe4",
  "nonce": "nonce-deterministic-42",
  "sequence_number": 1,
  "created_at": "2026-08-30T01:40:00.000000+00:00",
  "configuration": {
    "signature_length": 8,
    "seed": 42,
    "bell_state": "PHI_PLUS",
    "bases_allowed": ["X", "Y", "Z"],
    "noise_model": "NoNoise"
  },
  "signature_positions": [
    {
      "index": 0,
      "pauli_basis": "Y",
      "encoded_bit": 1,
      "prepared_state_label": "|-i>",
      "bell_state": "PHI_PLUS",
      "bell_measurement_bits": "11",
      "expected_correction": "XZ",
      "actual_correction": "XZ",
      "final_measured_bit": 1,
      "expected_bit": 1,
      "fidelity": 1.0,
      "is_match": true
    }
  ],
  "teleportation_events": [],
  "measurement_events": [],
  "verification_summary": {
    "total_positions": 8,
    "matching_positions": 8,
    "mismatching_positions": 0,
    "mismatch_count": 0,
    "mismatch_rate": 0.0,
    "average_fidelity": 1.0,
    "basis_distribution": {
      "X": 3,
      "Y": 3,
      "Z": 2
    },
    "correction_distribution": {
      "I": 2,
      "X": 2,
      "Z": 2,
      "XZ": 2
    },
    "digest_matches": true,
    "is_perfect_match": true
  }
}
```

---

### 3. Run Protocol Simulation Session
- **Method**: `POST`
- **Path**: `/api/v1/layer1/simulate`
- **Description**: Simulates a complete teleportation-mediated QDS signature session based on user parameters.

#### Request Body
```json
{
  "message": "TRANSFER_AMOUNT_1000_USD",
  "sender_id": "alice",
  "recipient_id": "bob",
  "signature_length": 16,
  "seed": 42,
  "bell_state": "PHI_PLUS",
  "bases_allowed": ["X", "Y", "Z"],
  "session_id": "session-custom-123",
  "nonce": "nonce-custom-456",
  "sequence_number": 1
}
```
