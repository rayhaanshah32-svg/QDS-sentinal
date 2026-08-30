# QDS Sentinel – Layer 2 Threat Detection Specification

**Layer**: 2 – Threat Detection Engine  
**Version**: 1.0.0  
**Status**: Release Candidate

---

## 1. Specification Overview

The Layer 2 Threat Detection Engine consumes Layer 1 `ProtocolSessionResult` objects and produces a structured `ThreatAssessment`.

### Key Design Principles:
1. **Strict Layer Boundary**: Layer 2 evaluates telemetry emitted by Layer 1. It never modifies Layer 1 packets or executes quantum operations.
2. **Detector Blindness**: Detectors read ONLY `ProtocolSessionResult` fields. They never inspect `AttackMetadata` or ground truth.
3. **Priority Ordering**: Deterministic security checks (Replay, SHA-256 Digest Forgery, Pauli Correction Tampering) take priority over statistical indicators (QBER, Bell Fidelity).
4. **Bob/Charlie Threshold Symmetrization**: Direct verification ($s_a$) and forwarded verification ($s_v$) are evaluated and reported separately, enforcing $s_a < s_v < p_E$.

---

## 2. Detectors & Security Thresholds

| Detector | Type | Authoritative? | Config / Formula | Priority |
| :--- | :--- | :--- | :--- | :--- |
| **Replay Guard** | Deterministic | **Yes** | In-memory `ReplayLedger` fingerprint (`session\|block\|nonce\|seq`) | 1 |
| **Digest Check** | Deterministic | **Yes** | SHA-256 digest match (`BasicVerificationSummary.digest_matches`) | 2 |
| **Correction Consistency** | Deterministic | **Yes** | Pauli correction match (`expected_correction == actual_correction`) | 3 |
| **QBER Analysis** | Statistical | No | Hoeffding bound: $P(\text{mismatch} \ge q_{\text{alert}} \mid e_{\text{honest}})$, $q_{\text{alert}} = 0.11$ | 4 |
| **Bell Integrity** | Statistical | No | Fidelity floor $f_{\text{floor}} = 0.999$ | 5 |
| **Bob/Charlie Metrics** | Statistical | No | Position split $s_a = 0.10, s_v = 0.20, p_E = 0.25$ | 6 |

---

## 3. Mathematical Bounds

### 3.1 Hoeffding Bound (Infinite/Independent Population)
For sample size $n$, observed mismatch rate $p_{\text{obs}}$, and confidence parameter $\epsilon$:
$$e_{\text{upper}} = \min\left(1.0, \max\left(0.0, p_{\text{obs}} + \sqrt{\frac{\ln(1/\epsilon)}{2n}}\right)\right)$$

False-positive tail probability under honest error rate $e_{\text{honest}}$:
$$P(\text{rate} \ge p_{\text{obs}} \mid e_{\text{honest}}) \le \exp\left(-2n(p_{\text{obs}} - e_{\text{honest}})^2\right)$$

### 3.2 Serfling Bound (Finite-Population Sampling without Replacement)
For sample size $k$ out of population size $n$ ($k \le n$):
$$\text{fpc} = 1 - \frac{k-1}{n}$$
$$e_{\text{upper}} = \min\left(1.0, \max\left(0.0, p_{\text{obs}} + \sqrt{\frac{\ln(1/\epsilon) \cdot \text{fpc}}{2k}}\right)\right)$$

### 3.3 Security Threshold Chain Enforcer
Programmatically validates $e_{\text{upper}} < s_a < s_v < p_E$. If violated, emits a `ConfigurationWarning` and forces a `CRITICAL` / `REJECT` verdict.

---

## 4. Ground Truth Isolation

Ground truth metadata (`AttackMetadata`) generated during attack injection is strictly isolated from threat evaluation:
- Endpoint `/api/v1/layer2/attack-simulate` returns `attack_metadata` and `assessment` as separate top-level keys.
- Detector functions (`run_qber_analysis`, `run_digest_check`, etc.) take only `ProtocolSessionResult` without reference to attack ground truth.
