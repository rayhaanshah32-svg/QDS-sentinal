# QDS Sentinel

**QDS Sentinel** is a research-grade cybersecurity software system designed to simulate teleportation-based Quantum Digital Signatures (QDS) and detect forgery, replay, impersonation, and quantum-channel tampering using quantum measurement statistics and deterministic mathematical rules.

---

## Architectural Scope & Boundaries

- **Layer 1: Protocol Simulation Engine** *(Current Implementation)*
  - Pure statevector simulation of Pauli eigenstates ($X, Y, Z$) and Bell pairs ($\Phi^+, \Phi^-, \Psi^+, \Psi^-$)
  - Full 3-qubit quantum teleportation circuit simulation
  - Bell measurements and feedforward Pauli corrections ($I, X, Z, XZ$)
  - Teleportation-mediated QDS signature block creation and basic packet verification primitive
  - Auditable telemetry logging and JSON serialization
  - Pluggable noise interface (`NoNoise`, `DepolarizingNoise`, `PauliFlipNoise`)
  - Strict input validation via Pydantic schemas and FastAPI REST endpoints
- **Layer 2: Threat Detection Engine** *(Next Phase)*
  - Finite-sample thresholding ($s_a < s_v < p_E$), multi-verifier Bob/Charlie arbitration, attack classification, and replay checks
- **Layer 3: Dashboard and Security Reporting** *(Final Phase)*
  - Real-time visualization and audit reports

> **Explicit Scope Statement**: Layer 1 does **not** implement threat detection decisions, attack classification, finite-sample thresholding, or replay detection. Layer 1 strictly models the underlying quantum protocol physics, packet binding, and telemetry generation.

---

## Getting Started

### 1. Requirements
- Python 3.11+
- Dependencies: `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`, `numpy`, `pytest`, `httpx`

### 2. Setup & Installation

Install dependencies with pip:
```powershell
pip install fastapi uvicorn pydantic pydantic-settings numpy pytest httpx
```

### 3. Running the Backend Server

Start the FastAPI application with uvicorn:
```powershell
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

Interactive OpenAPI / Swagger documentation will be available at:
`http://127.0.0.1:8000/docs`

---

## Running Tests

Execute the complete pytest suite (45 unit and integration tests):
```powershell
python -m pytest backend/tests -v
```

---

## REST API cURL Examples

### 1. Health Check
```powershell
curl -X GET "http://127.0.0.1:8000/health"
```

### 2. Deterministic Preconfigured Example Session
```powershell
curl -X GET "http://127.0.0.1:8000/api/v1/layer1/example-session"
```

### 3. Run Custom Simulation Session
```powershell
curl -X POST "http://127.0.0.1:8000/api/v1/layer1/simulate" `
  -H "Content-Type: application/json" `
  -d '{
    "message": "FINANCIAL_TRANSACTION_PAYLOAD_001",
    "sender_id": "alice",
    "recipient_id": "bob",
    "signature_length": 16,
    "seed": 42,
    "bell_state": "PHI_PLUS",
    "bases_allowed": ["X", "Y", "Z"],
    "session_id": "session-custom-001",
    "nonce": "nonce-custom-42",
    "sequence_number": 1
  }'
```

---

## Sample Response Structure

```json
{
  "protocol_version": "1.0.0",
  "session_id": "session-custom-001",
  "signature_block_id": "61ef5b66-42ca-443c-afe2-b1d546524eb0",
  "sender_id": "alice",
  "recipient_id": "bob",
  "message": "FINANCIAL_TRANSACTION_PAYLOAD_001",
  "message_digest": "e2e6be5670a0e7eecef264e9e6806ad49352893c5e334313ed1444200e494068",
  "nonce": "nonce-custom-42",
  "sequence_number": 1,
  "created_at": "2026-08-30T01:40:00.000000+00:00",
  "configuration": {
    "signature_length": 16,
    "seed": 42,
    "bell_state": "PHI_PLUS",
    "bases_allowed": ["X", "Y", "Z"],
    "noise_model": "NoNoise"
  },
  "signature_positions": [
    {
      "index": 0,
      "pauli_basis": "X",
      "encoded_bit": 1,
      "prepared_state_label": "|->",
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
  "teleportation_events": [
    {
      "event_id": "14c98354-37c4-4c90-a158-4b188e05cf53",
      "position_index": 0,
      "bell_state": "PHI_PLUS",
      "bell_measurement_bits": "11",
      "expected_correction": "XZ",
      "applied_correction": "XZ",
      "fidelity": 1.0,
      "step_trace": [
        "Prepared Bell state PHI_PLUS on qubits (q1, q2)",
        "Formed composite 3-qubit state |q0> (x) |q1,q2> with input |->",
        "Applied CNOT gate with control q0 and target q1",
        "Applied Hadamard gate on qubit q0",
        "Measured qubits (q0, q1) in computational basis, outcome bits: '11'",
        "Applied Pauli correction 'XZ' to receiver qubit q2",
        "Calculated state fidelity: 1.00000000"
      ]
    }
  ],
  "measurement_events": [
    {
      "event_id": "c1030b3c-2a75-41b9-9860-dbf0af00f58d",
      "position_index": 0,
      "basis": "X",
      "outcome_bit": 1,
      "probabilities": {
        "0": 0.0,
        "1": 1.0
      },
      "is_deterministic": true
    }
  ],
  "verification_summary": {
    "total_positions": 16,
    "matching_positions": 16,
    "mismatching_positions": 0,
    "mismatch_count": 0,
    "mismatch_rate": 0.0,
    "average_fidelity": 1.0,
    "basis_distribution": {
      "X": 5,
      "Y": 6,
      "Z": 5
    },
    "correction_distribution": {
      "I": 4,
      "X": 4,
      "Z": 4,
      "XZ": 4
    },
    "digest_matches": true,
    "is_perfect_match": true
  }
}
```

---

## Documentation Links

- [Protocol Specification](docs/protocol-spec.md)
- [Layer 1 Scope & Assumptions](docs/layer1-assumptions.md)
- [Layer 1 REST API Reference](docs/layer1-api.md)
