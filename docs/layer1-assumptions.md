# QDS Sentinel - Layer 1 Scope & Assumptions

## 1. Architectural Scope of Layer 1

Layer 1 is the **Protocol Simulation Engine** for QDS Sentinel. Its sole responsibility is the mathematically rigorous, deterministic execution of quantum states, gates, projective measurements, quantum teleportation, and structured telemetry generation.

---

## 2. What Layer 1 Does

- **Exact Statevector Simulation**: Simulates pure quantum statevectors using NumPy complex arrays with strict normalization validation ($\|v\| \approx 1.0$).
- **Pauli Eigenstate Generation**: Prepares exact basis states in the $X$, $Y$, and $Z$ bases.
- **Bell-State Generation & Entanglement**: Implements 2-qubit maximally entangled Bell pairs ($\Phi^+, \Phi^-, \Psi^+, \Psi^-$).
- **Full 3-Qubit Quantum Teleportation**: Simulates sender Bell measurements, feedforward Pauli correction ($I, X, Z, XZ$), and fidelity calculation.
- **Projective Measurements**: Calculates exact Born-rule probabilities and samples deterministic/probabilistic outcomes.
- **QDS-Style Signature Block Generation**: Binds SHA-256 message digests with teleportation-mediated Pauli state transmissions.
- **Auditable Structured Telemetry**: Emits complete telemetry events (teleportation events, measurement events, position records, distributions, and basic mismatch summaries).
- **Pluggable Noise Interface**: Defines extensible noise models (`NoNoise`, `DepolarizingNoise`, `PauliFlipNoise`) providing honest baseline mechanics for subsequent layers.

---

## 3. What Layer 1 Does NOT Do / Does NOT Prove

- **No Threat Decisions or Classification**: Layer 1 does not classify security events, detect active adversaries, or make allow/deny authorization decisions.
- **No Replay or Finite-Sample Thresholding**: Layer 1 computes raw mismatch counts and rates; it does not set security thresholds ($s_a, s_v$) or detect replay attacks.
- **No Machine Learning or AI**: All simulation mechanics are deterministic and mathematical.
- **Bounded-Verification Property Out of Scope**: In classical optical QDS literature, public keys become insecure after a bounded number of verifications. Modeling state degradation over repeated verifications is intentionally out of scope for the Layer 1 simulation engine.
- **No Composable Security Proof**: Layer 1 is a simulation model and does not claim full composable information-theoretic security proofs for real-world optical hardware implementations.

---

## 4. Why Layer 2 (Threat Detection Engine) is Required

Layer 2 consumes the structured telemetry records emitted by Layer 1 and applies:
1. **Multi-Verifier Threshold Analysis**: Applying Bob-vs-Charlie thresholds ($s_a < s_v < p_E$) on transmitted quantum signature blocks.
2. **Threat Classification**: Distinguishing between honest channel noise, Eve intercept-resend attacks, recipient repudiation, forgery, and replay attempts.
3. **Security Scoring & Alerting**: Computing confidence scores and triggering mitigation protocols.
