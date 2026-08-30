# QDS Sentinel – Layer 2 API Specification

**Base URL**: `/api/v1/layer2`  
**Version**: 1.0.0

---

## 1. Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/assess` | Run Layer 2 threat assessment on a simulation request. |
| `POST` | `/assess-existing` | Run Layer 2 threat assessment on an existing `ProtocolSessionResult` telemetry object. |
| `POST` | `/attack-simulate` | Simulate Layer 1 session, inject attack, and return separate top-level `attack_metadata` and `assessment`. |
| `GET` | `/example-clean` | Clean session demonstration assessment (`ACCEPT`). |
| `GET` | `/example-replay` | Replay attack demonstration assessment (`REJECT`). |
| `GET` | `/example-forgery` | Signature forgery demonstration assessment (`REJECT`). |

---

## 2. Detailed Schemas

### `POST /assess`
- **Request Body**: `Layer2AssessRequest`
  - `simulation` (`ProtocolSessionRequest`): Layer 1 session parameters.
  - `verification_mode` (`"direct"` \| `"forwarded"`): Defaults to `"direct"`.
  - `s_a` (`float`): Bob threshold (default `0.10`).
  - `s_v` (`float`): Charlie threshold (default `0.20`).
- **Response**: `ThreatAssessment` (HTTP 200)

### `POST /attack-simulate`
- **Request Body**: `Layer2AttackSimulateRequest`
  - `simulation` (`ProtocolSessionRequest`): Baseline session parameters.
  - `attack_type` (`AttackType`): One of 8 supported attack types.
  - `intensity` (`float`): Attack parameter in `[0.0, 1.0]`.
  - `target_basis` (`str`, optional): Targeted basis for `CHANNEL_MANIPULATION`.
- **Response**: `Layer2AttackSimulateResponse` (HTTP 200)
  ```json
  {
    "attack_metadata": {
      "attack_type": "PARTIAL_FORGERY",
      "intensity": 0.25,
      "description": "Partial signature forgery: 4/16 positions inverted (q=0.25)"
    },
    "assessment": {
      "threat_level": "SUSPICIOUS",
      "threat_category": "QBER_ANOMALY",
      "security_decision": "REJECT — ...",
      "findings": [...]
    }
  }
  ```

---

## 3. Error Responses

- **HTTP 422 Unprocessable Entity**: Returned when threshold ordering $e_{\text{upper}} < s_a < s_v < p_E$ is violated (e.g. $s_a \ge s_v$).
- **HTTP 400 Bad Request**: Invalid attack type or parameters.
