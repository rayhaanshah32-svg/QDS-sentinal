# QDS Sentinel – Layer 2 Live Demo Script Walkthrough

This document outlines the exact 4-minute demonstration narrative for presenting the **Layer 2 Threat Detection Engine** live to judges.

---

## 📋 Overview of 4-Minute Demo Narrative

| Minute | Phase | Action / Vector | Expected Outcome & Commentary |
| :--- | :--- | :--- | :--- |
| **0:00 - 1:00** | **Phase 1: Clean Baseline** | Authenticated QDS Signature Packet | `CLEAN` / `ACCEPT`. Mismatch rate `0.0000` under $s_a=0.10$. |
| **1:00 - 2:00** | **Phase 2: Signature Forgery** | Partial Signature Forgery ($q=0.25$) | `SUSPICIOUS` / `REJECT`. Exact mismatch rate `0.2500` reported. |
| **2:00 - 3:00** | **Phase 3: Replay Attack** | Replay of Phase 1 Packet | `CRITICAL` / `REJECT`. Fingerprint replay detected by in-memory `ReplayGuard`. |
| **3:00 - 4:00** | **Phase 4: Feedforward Tampering** | Pauli Correction Tampering ($q=1.0$) | `CRITICAL` / `REJECT`. Deterministic `expected_correction != actual_correction` flag. |

---

## 🚀 Environment Setup

Start the Sentinel backend server:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

---

## ⚡ Live Execution Steps & Curl Commands

### Phase 1: Authentic QDS Signature Packet (`ACCEPT`)

**Objective**: Show that an uncorrupted Quantum Digital Signature packet passes all Layer 2 statistical and deterministic checks.

**Live Command**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/layer2/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "simulation": {
      "message": "FINANCIAL_TRANSACTION_AUTHORIZATION_001",
      "sender_id": "alice",
      "recipient_id": "bob",
      "signature_length": 16,
      "seed": 42,
      "bell_state": "PHI_PLUS",
      "bases_allowed": ["X", "Y", "Z"],
      "session_id": "demo-session-100",
      "nonce": "nonce-demo-100",
      "sequence_number": 1
    },
    "verification_mode": "direct",
    "s_a": 0.10,
    "s_v": 0.20
  }'
```

**Expected JSON Response (Key Fields)**:
```json
{
  "session_id": "demo-session-100",
  "threat_level": "CLEAN",
  "threat_category": "NONE",
  "security_decision": "ACCEPT — verification_mode=direct, threshold=s_a=0.1, mismatch_rate=0.0000, e_upper=0.4870",
  "findings": [],
  "bob_charlie_metrics": {
    "direct_mismatch_rate": 0.0,
    "direct_mismatch_count": 0,
    "forwarded_mismatch_rate": 0.0,
    "forwarded_mismatch_count": 0
  },
  "replay_detection": {
    "is_replay": false
  }
}
```

*Speaker Note*: "Notice that for an authentic signature, the direct mismatch rate is exactly 0.0000. All Hoeffding bounds are satisfied, no replay fingerprint is registered, and the security decision is ACCEPT."

---

### Phase 2: Adversarial Partial Signature Forgery Attack ($q=0.25$) (`REJECT`)

**Objective**: Inject a partial signature forgery ($q=0.25$) and show that Layer 2 detects the elevated mismatch rate and rejects the packet with exact telemetry calculations.

**Live Command**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/layer2/attack-simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "simulation": {
      "message": "FINANCIAL_TRANSACTION_FORGED_002",
      "sender_id": "alice",
      "recipient_id": "bob",
      "signature_length": 16,
      "seed": 42,
      "bell_state": "PHI_PLUS",
      "bases_allowed": ["X", "Y", "Z"],
      "session_id": "demo-session-101",
      "nonce": "nonce-demo-101",
      "sequence_number": 1
    },
    "attack_type": "PARTIAL_FORGERY",
    "intensity": 0.25,
    "verification_mode": "direct",
    "s_a": 0.10,
    "s_v": 0.20
  }'
```

**Expected JSON Response (Key Fields)**:
```json
{
  "attack_metadata": {
    "attack_type": "PARTIAL_FORGERY",
    "intensity": 0.25,
    "target_basis": null,
    "description": "Partial signature forgery: 4/16 positions inverted (q=0.25)",
    "seed": 42
  },
  "assessment": {
    "threat_level": "SUSPICIOUS",
    "threat_category": "QBER_ANOMALY",
    "security_decision": "REJECT — verification_mode=direct, threshold=s_a=0.1, mismatch_rate=0.5000, e_upper=0.9870; reason(s): QBER_ANOMALY, BOB_THRESHOLD_BREACH",
    "findings": [
      "QBER_ANOMALY [SUSPICIOUS] — observed mismatch rate 0.2500 exceeds q_alert threshold 0.1100. Hoeffding false-positive bound: 1.5768e-01.",
      "BOB_THRESHOLD_BREACH [ADVISORY] — Bob (direct) mismatch rate 0.5000 > s_a=0.1. (4/8 positions). verification_mode=direct evaluated against s_a."
    ]
  }
}
```

*Speaker Note*: "Notice ground-truth attack metadata and Layer 2 threat assessment are returned as separate top-level keys. The Layer 2 engine evaluates telemetry strictly without reading ground truth. The direct mismatch rate breached threshold $s_a=0.10$, triggering an immediate REJECT."

---

### Phase 3: Stateful Replay Attack Detection (`REJECT [CRITICAL]`)

**Objective**: Re-submit the exact Phase 1 authentic session packet (`demo-session-100`) and prove that the stateful `ReplayGuard` flags the duplicate sequence fingerprint.

**Live Command**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/layer2/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "simulation": {
      "message": "FINANCIAL_TRANSACTION_AUTHORIZATION_001",
      "sender_id": "alice",
      "recipient_id": "bob",
      "signature_length": 16,
      "seed": 42,
      "bell_state": "PHI_PLUS",
      "bases_allowed": ["X", "Y", "Z"],
      "session_id": "demo-session-100",
      "nonce": "nonce-demo-100",
      "sequence_number": 1
    },
    "verification_mode": "direct"
  }'
```

**Expected JSON Response (Key Fields)**:
```json
{
  "session_id": "demo-session-100",
  "threat_level": "CRITICAL",
  "threat_category": "REPLAY_ATTACK",
  "security_decision": "REJECT — verification_mode=direct, threshold=s_a=0.1, mismatch_rate=0.0000, e_upper=0.4870; reason(s): REPLAY_ATTACK",
  "findings": [
    "REPLAY_ATTACK [CRITICAL] — fingerprint 'demo-session-100|...|nonce-demo-100|1' already recorded in the replay ledger. Deterministic check."
  ],
  "replay_detection": {
    "is_replay": true,
    "recorded_fingerprint": "demo-session-100|...|nonce-demo-100|1"
  }
}
```

*Speaker Note*: "Even though the underlying telemetry was clean, the in-memory ReplayGuard recognized that fingerprint 'demo-session-100|...|nonce-demo-100|1' was already processed. The threat level escalates to CRITICAL and the decision flips to REJECT."

---

### Phase 4: Classical Feedforward Pauli Correction Tampering (`REJECT [CRITICAL]`)

**Objective**: Simulate tampering with classical feedforward Pauli corrections and verify that Layer 2 raises an authoritative deterministic `CORRECTION_TAMPERING` finding.

**Live Command**:
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/layer2/attack-simulate" \
  -H "Content-Type: application/json" \
  -d '{
    "simulation": {
      "message": "FINANCIAL_TRANSACTION_TAMPERED_004",
      "sender_id": "alice",
      "recipient_id": "bob",
      "signature_length": 16,
      "seed": 42,
      "bell_state": "PHI_PLUS",
      "bases_allowed": ["X", "Y", "Z"],
      "session_id": "demo-session-104",
      "nonce": "nonce-demo-104",
      "sequence_number": 1
    },
    "attack_type": "CORRECTION_TAMPERING",
    "intensity": 1.0,
    "verification_mode": "direct"
  }'
```

**Expected JSON Response (Key Fields)**:
```json
{
  "attack_metadata": {
    "attack_type": "CORRECTION_TAMPERING",
    "intensity": 1.0,
    "description": "Pauli correction tampering: 16/16 positions tampered"
  },
  "assessment": {
    "threat_level": "CRITICAL",
    "threat_category": "CORRECTION_TAMPERING",
    "security_decision": "REJECT — verification_mode=direct, threshold=s_a=0.1, mismatch_rate=0.0000, e_upper=0.4870; reason(s): CORRECTION_TAMPERING",
    "findings": [
      "CORRECTION_TAMPERING [CRITICAL] — 16 position(s) have expected_correction != actual_correction (rate=1.0000 > threshold=0.0). Affected indices: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]. Deterministic check."
    ],
    "correction_consistency": {
      "tampered_positions_count": 16,
      "flag_raised": true
    }
  }
}
```

*Speaker Note*: "This demonstrates Layer 2's deterministic check for feedforward integrity. By comparing the calculated Bell measurement outcome against the actual applied Pauli operator, all 16 tampered positions are identified, resulting in a CRITICAL verdict."

---

## 🛡️ Error Response Examples (Judges Reference)

### Invalid Threshold Ordering (`422 Unprocessable Entity`)
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/layer2/assess" \
  -H "Content-Type: application/json" \
  -d '{
    "simulation": {"message": "TEST", "sender_id": "a", "recipient_id": "b"},
    "s_a": 0.30,
    "s_v": 0.20
  }'
```
**HTTP 422 Response**:
```json
{
  "detail": "Threshold ordering violated: s_a=0.3 must be strictly less than s_v=0.2 (Amiri et al. 2016 Eq. 19). Repudiation exponential hardness requires s_a < s_v."
}
```

---

## ✅ Summary & Conclusion

This 4-minute narrative demonstrates:
1. **Accurate Baseline Assessment**: Zero false-positive rates on authentic quantum signatures.
2. **Quantitative Sensitivity**: Clear mismatch rate reporting against mathematically calibrated thresholds ($s_a$, $s_v$).
3. **Stateful Anti-Replay Security**: Authoritative rejection of repeated session fingerprints.
4. **Deterministic Classical Feedforward Integrity**: Detection of tampered Pauli correction operators.
