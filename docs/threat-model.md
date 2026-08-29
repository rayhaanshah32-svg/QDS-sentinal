# QDS Sentinel – Layer 2 Threat Model

**Layer**: 2 – Threat Detection Engine  
**Version**: 1.0.0  
**Status**: Pre-Layer 3 Release

---

## 1. Threat Actors & Attack Scenarios

### 1.1 Eve (Intercept-Resend Eavesdropper)
**Attack**: Eve intercepts the quantum channel between Alice and Bob,
measures qubits (collapsing state), and re-sends reconstructed states.
**Simulated indicator**: Elevated mismatch rate (QBER) above `q_alert`.
**Detector**: `QBERAnalysisResult` — statistical; not a standalone guarantee.
**Limitation**: Intercept-resend introduces ~25% QBER for BB84; this simulation
operates at the Layer 1 bit-comparison level, not raw qubit counts.

### 1.2 Forger
**Attack**: A third party constructs a plausible signature packet for a message
Alice did not sign.
**Simulated indicator**: SHA-256 digest mismatch (`digest_matches = False`).
**Detector**: `DigestCheckResult` — deterministic, authoritative.
**Limitation**: Only the classical digest binding is verified. The quantum key
distribution binding (which makes QDS informationally secure) is approximated
by the Layer 1 teleportation model, not formally proven.

### 1.3 Replaying Attacker
**Attack**: An attacker captures a valid past signature packet and resubmits it
to impersonate a fresh transaction.
**Simulated indicator**: Fingerprint `session_id|block_id|nonce|seq` already
in the replay ledger.
**Detector**: `ReplayDetectionResult` — deterministic, authoritative.
**Limitation**: In-memory ledger only; does not persist across process restarts.
Distributed replay prevention is out of scope for Layer 2.

### 1.4 Bob Repudiator
**Attack**: Bob claims he never sent a message that he did send, or claims a
message was forged by Alice.
**Simulated indicator**: Bob's direct mismatch rate exceeds `s_a` while
Charlie's forwarded rate remains below `s_v` (or vice versa).
**Detector**: `BobCharlieMetrics` — advisory.
**Limitation**: Layer 1 does not model the two-recipient symmetrization step.
Layer 2 applies a position-split approximation. See
`docs/layer2-security-claims.md` Section 3.

### 1.5 Channel Tamperer
**Attack**: An attacker modifies the Pauli corrections after the Bell measurement
but before Bob applies them, altering the received bit.
**Simulated indicator**: `expected_correction != actual_correction` for one or
more signature positions.
**Detector**: `CorrectionConsistencyResult` — deterministic, authoritative.
**Limitation**: In Layer 1's model, `applied_correction` always equals
`expected_correction` (feedforward is perfect). Any divergence in submitted
telemetry is therefore a definitive tampering signal in this simulation.

### 1.6 Low-Fidelity Channel (Environmental Decoherence)
**Attack**: Not adversarial — environmental noise or decoherence reduces
teleportation fidelity below the Layer 1 specified floor.
**Simulated indicator**: `fidelity < f_floor` for one or more positions.
**Detector**: `FidelityAnalysisResult` — statistical advisory.
**Limitation**: Layer 1's `NoNoise` model produces fidelity = 1.0 exactly.
A non-trivial fidelity floor finding requires a noise model (e.g.,
`DepolarizingNoise`) to be set in Layer 1.

---

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                        QDS Sentinel                             │
│                                                                 │
│  ┌─────────────────────────┐    ┌──────────────────────────┐   │
│  │  Layer 1 (Trusted)      │───▶│  Layer 2 (This Layer)    │   │
│  │  Protocol Simulation    │    │  Threat Detection        │   │
│  │  - State vectors        │    │  - Digest check          │   │
│  │  - Teleportation        │    │  - QBER analysis         │   │
│  │  - Measurement          │    │  - Correction check      │   │
│  │  - Telemetry emission   │    │  - Replay ledger         │   │
│  └─────────────────────────┘    │  - Fidelity analysis     │   │
│                                 │  - Bob/Charlie split     │   │
│           Adversary can         └──────────────────────────┘   │
│           tamper ONLY with          │                           │
│           the submitted             ▼                           │
│           ProtocolSessionResult  ThreatAssessment (output)      │
└─────────────────────────────────────────────────────────────────┘
```

Layer 2 trusts Layer 1's internal computation but is designed to detect
when a caller submits tampered `ProtocolSessionResult` data via the
`/assess-existing` endpoint (e.g., modified digest, correction fields).

---

## 3. Non-Threats (Out of Scope)

- **Denial of service**: Layer 2 does not rate-limit or queue requests.
- **Side-channel attacks**: Timing or power analysis on the server.
- **Implementation bugs in Layer 1**: Layer 2 consumes Layer 1 output as-is.
- **Cryptographic agility attacks**: SHA-256 is the fixed digest algorithm.
- **AI/ML-based adversaries**: No adaptive adversary modeling.
- **Post-quantum migration**: Out of scope per product boundary.

---

## 4. Relationship to Amiri et al. 2016 and Gottesman-Chuang 2001 Security Definitions

> See `docs/layer2-security-claims.md` for the full technical treatment.

**Short summary**:

| QDS Property | Formal Definition Source | Layer 2 Coverage |
|---|---|---|
| Unforgeability | Amiri et al. 2016, Def. 1; GC 2001 | SHA-256 digest check (classical approximation only) |
| Non-repudiation | Amiri et al. 2016, Eq. 20-24 | Bob/Charlie threshold split (documented approximation) |
| Robustness | Amiri et al. 2016, Def. 3 | Noiseless verification: mismatch_rate = 0 → ACCEPT |
| Composable security | UC framework | **NOT reproduced** |
| Coherent-attack bounds | Information-theoretic | **NOT reproduced** |

**Information-theoretic bounds under coherent attacks are NOT reproduced by
this software simulation.** The detectors operate on classical bit-comparison
telemetry emitted by Layer 1, not on raw qubit states, density matrices, or
full quantum circuit traces.

---

## 5. Honest-Noise Calibration

Layer 2 includes a `HonestNoiseCalibrator` utility (see
`backend/app/layer2_threat/calibration.py`) that perturbs *copies* of Layer 1
position records for threshold calibration and testing.

**This utility is NEVER called on the live detection path.** It is a
testing/calibration tool only. It does not alter any Layer 1 telemetry.

Usage: Set `e_honest` to match your physical channel's measured background
error rate before relying on the Hoeffding false-positive bound in
`QBERAnalysisResult`.

---

## 6. Known Limitations Summary

1. **In-memory replay ledger**: State is lost on process restart. No distributed
   replay protection.
2. **Position-split approximation**: The Bob/Charlie split is a Layer 2
   simplification; real QDS uses a separate symmetrization protocol round.
3. **NoNoise baseline**: Default Layer 1 sessions produce zero honest errors,
   making statistical detectors vacuous without calibration.
4. **Single-digest binding**: Only one SHA-256 digest per session; no
   per-position classical hash.
5. **No network adversary modeling**: Assumes the HTTP transport is trusted.
6. **Fidelity source**: Layer 2 uses `SignaturePositionRecord.fidelity` as
   the authoritative record; `TeleportationEvent.fidelity` is identical in
   Layer 1 but not separately cross-validated by Layer 2.
