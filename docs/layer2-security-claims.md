# QDS Sentinel – Layer 2 Security Claims & Limitations

**Document status**: Required companion to the Layer 2 Threat Detection Engine.  
**Scientific integrity policy**: This document is mandatory reading before
interpreting any ThreatAssessment output.

---

## 1. What This Software Simulates

QDS Sentinel Layer 2 is a **deterministic software simulation** of threat
detection heuristics derived from the quantum digital signature literature.

It does **not**:
- Operate on real quantum hardware or photonic channels.
- Execute quantum algorithms or quantum circuits at this layer.
- Reproduce full information-theoretic security proofs under coherent attacks.
- Guarantee detection of every attack variant or adversarial strategy.
- Prove composable security in the sense of universal composability (UC) frameworks.

---

## 2. Relationship to Amiri et al. (2016) and Gottesman-Chuang (2001)

### 2.1 Forging

**Formal definition** (Amiri et al. 2016, Section II):  
A signature scheme is *unforgeable* if no computationally or
information-theoretically bounded adversary can create a valid signature on
a message that was not signed by the legitimate sender, with success
probability exponentially small in the security parameter.

**What this simulation approximates**:  
The Layer 2 `DigestCheckResult` detector checks whether the SHA-256 message
digest recorded in the Layer 1 packet matches the expected digest. A mismatch
(`digest_matches = False`) is flagged as `DIGEST_FORGERY`. This approximates
the classical authentication component of QDS; it does **not** simulate the
full quantum key-binding or the information-theoretic hardness of forging a
quantum-encoded signature element.

### 2.2 Repudiation

**Formal definition** (Amiri et al. 2016, Eq. 20-24, Gottesman-Chuang 2001):  
A QDS scheme is *non-repudiable* if the direct recipient (Bob) and the
forwarded recipient (Charlie) accept/reject signatures consistently, with
the threshold gap `s_a < s_v` making the probability that Bob accepts but
Charlie rejects (or vice versa) exponentially small in the security parameter.

**What this simulation approximates**:  
Layer 2 implements the `BobCharlieMetrics` detector, which applies the
threshold pair `s_a < s_v` to separate halves of the signature positions.
The gap is enforced by configuration validation (API returns 422 if
`s_a >= s_v`). The exponential-hardness argument from the formal proof
requires a full protocol execution with real quantum state transmission;
this simulation **approximates the threshold logic only**, not the
information-theoretic bound.

### 2.3 Robustness

**Formal definition**:  
An honest sender's valid signature is accepted by all intended recipients with
overwhelmingly high probability.

**What this simulation approximates**:  
Under Layer 1 `NoNoise` conditions, all positions have `is_match = True` and
`fidelity = 1.0`, producing `mismatch_rate = 0.0`. The QBER detector and
Bob/Charlie split will produce no alerts, and the security decision will be
`ACCEPT`. This is a correct simulation of the noiseless-channel robust case;
it does **not** derive robustness bounds from finite-sample analysis with a
real quantum channel.

---

## 3. Explicit Simplification: Bob/Charlie Symmetrization

**Formal context**: In both Amiri et al. (2016) and Chapman et al., the QDS
protocol involves a symmetrization step where the sender distributes key
material to multiple recipients. Specifically:
- Bob (authenticator, direct recipient) receives the signature element directly.
- Charlie (verifier, forwarded recipient) receives a forwarded copy after
  symmetrization.
Both apply different error thresholds (`s_a` for Bob, `s_v` for Charlie).

**Layer 1 limitation**: Layer 1 produces a single
`sender → recipient` signature packet (see `protocol_session.py`). It does
not model the two-recipient architecture or the symmetrization/forwarding step.

**Layer 2 documented workaround**:  
Layer 2 explicitly implements a position-index split as a documented
simplification:
```
positions[0 : ceil(n * forwarding_split)] → Bob (direct verification)
positions[ceil(n * forwarding_split) : n] → Charlie (forwarded verification)
```
This split is **not** claimed to be physically equivalent to running the full
two-recipient QDS protocol. It is a software approximation that allows the
threshold logic (`s_a` vs. `s_v`) to be exercised and tested in isolation.

**Direct rates and forwarded rates are NEVER collapsed into one number.**
This is a hard implementation constraint tracked by unit test
`test_bob_charlie_separate_rates_never_collapsed`. Collapsing these rates
into a single metric is a documented QDS security bug class
(Amiri et al. Eq. 20-24 on repudiation).

---

## 4. Threshold Derivation Audit Trail

All thresholds in `Layer2Config` are documented with their derivation source.
No threshold is emitted in a `ThreatAssessment` without being traceable to
one of:
- A fixed configuration constant (with source reference).
- A finite-sample formula (Hoeffding bound: `exp(-2n(rate - e_honest)²)`).
- An adversarial-separation constraint (Amiri et al. Eq. 19: `s_a < s_v < p_E`).

See `backend/app/layer2_threat/config.py` for the complete derivation
comments on each parameter.

---

## 5. Detector Classification

| Detector | Type | Authoritative? | Scientific basis |
|---|---|---|---|
| Digest check | Deterministic | **Yes** | SHA-256 identity binding |
| Replay detection | Deterministic | **Yes** | Session fingerprint ledger |
| Correction consistency | Deterministic | **Yes** | Layer 1 teleportation model |
| QBER analysis | Statistical | No | Hoeffding bound, q_alert = 0.11 |
| Fidelity analysis | Statistical | No | f_floor = 0.999 (Layer 1 spec) |
| Bob/Charlie split | Mixed | No | Position-split simplification |

"Authoritative" means the finding is conclusive and overrides statistical
evidence. Statistical detectors provide confidence-bounded **indicators**, not
standalone security guarantees.

---

## 6. Reproducibility Guarantee

All results are reproducible from a fixed `seed` value passed to Layer 1's
`run_protocol_session`. The `ThreatAssessment` inherits determinism from the
seeded PRNG and uses only deterministic arithmetic (SHA-256, exact mismatch
counts, Hoeffding formula). The `assessed_at` timestamp field varies by
wall-clock time but does not affect any security verdict.

---

## 7. Formal Guarantees NOT Reproduced

The following properties from the QDS literature are **explicitly not**
reproduced by this simulation:
- Information-theoretic security bounds under coherent attacks.
- Composable security proofs (UC framework).
- Physical channel noise modeling (Layer 1's `NoNoise` produces exactly 0
  honest errors; real photonic channels have background error rates).
- Quantum memory decoherence and repetition-based robustness.
- Multi-party key distribution security (only two-party sender/recipient
  modeled in Layer 1).
- State degradation over repeated verifications (intentionally out of scope
  per `docs/layer1-assumptions.md`).
