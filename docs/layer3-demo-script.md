# QDS Sentinel – Layer 3 Live Judge Walkthrough & Demo Script

This document provides the click-by-click presentation script for demonstrating the **Layer 3 Security Visualization & Telemetry Dashboard** live to judges. It pairs directly with the Layer 2 detection engine specification and audit documents.

---

## Overview of the 4-Beat Demo Narrative

| Beat | Phase | Action in UI | Primary Screen / View | Expected Outcome & Key Callouts |
| :--- | :--- | :--- | :--- | :--- |
| **Beat 1** | **Clean Baseline** | Run clean simulation ($N=16$, seed=42) | **Control Panel** $\to$ **Threat Feed** $\to$ **Circuit Trace** | `CLEAN` / `ACCEPT`. Telemetry shows 0% mismatch, 1.0000 fidelity across all 16 positions, 0 findings. |
| **Beat 2** | **Signature Forgery** | Inject `PARTIAL_FORGERY` ($q=0.25$) or `FULL_FORGERY` | **Threat Feed** $\to$ **Security Metrics** | `SUSPICIOUS` / `REJECT` or `CRITICAL`. QBER and mismatch rate jump to exactly 0.2500, breaching alert threshold. |
| **Beat 3** | **Replay Attack** | Resubmit identical packet parameters | **Threat Feed** $\to$ **Security Metrics** | `CRITICAL` / `REJECT`. Deterministic `Replay Detection` badge triggers; outranks statistical metrics. |
| **Beat 4** | **Feedforward Tampering** | Inject `CORRECTION_TAMPERING` ($q=1.0$) | **Circuit Trace** $\to$ **Threat Feed** | `CRITICAL` / `REJECT`. Visual `!` mismatch on Pauli correction operators; rows tinted terracotta. |

---

## Environment Verification Before Presentation

1. **Backend Server** (Port 8000):
   ```bash
   cd backend
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
2. **Frontend Dashboard** (Port 5173):
   ```bash
   cd frontend
   npm run dev
   ```
3. Open browser at: `http://localhost:5173/`

---

## Click-by-Click Presentation Steps

### Beat 1: Baseline Authentic Transmission (`ACCEPT`)

1. **Navigate to**: `Control Panel` tab.
2. **Set Parameters** (or click **Clean session** under Quick examples):
   - Message: `PAYLOAD_TRANSFER_AUTHENTIC_001`
   - Sender ID: `alice`, Recipient ID: `bob`
   - Signature Length: `16`, Seed: `42`, Bell State: `PHI_PLUS`
   - Bases Allowed: `[X, Y, Z]` checked
   - Attack Type: `None (clean assessment)`
3. **Click**: `Run Assessment`.
4. **Transition**: App automatically navigates to **Threat Feed**.
   - *Point out*: Top decision banner displays `ACCEPT — verification_mode=direct, threshold=s_a=0.1, mismatch_rate=0.0000`.
   - *Point out*: Threat Feed displays `NO_FINDINGS` with a muted sage color bar.
5. **Switch to**: `Circuit Trace` tab.
   - *Point out*: All 16 positions show `fidelity = 1.0000`, `Exp. Corr. == Act. Corr.`, and `Match = OK`.
6. **Switch to**: `Security Metrics` tab.
   - *Point out*: Both deterministic indicators (`SHA-256 Digest` and `Replay Detection`) show green `MATCH` and `UNIQUE`. Bob's direct mismatch rate is `0.0000`.

*Speaker Script*:
> "Here we establish our trusted quantum baseline. Alice prepares 16 single-qubit Pauli eigenstates teleported through Bell pairs. Bob receives the photons, applies feedforward Pauli corrections, and observes zero bit mismatches and unit fidelity. Layer 2 confirms acceptance under our threshold."

---

### Beat 2: Partial Signature Forgery Attack ($q=0.25$) (`REJECT`)

1. **Navigate to**: `Control Panel` tab.
2. **Set Parameters**:
   - Keep message and sender/recipient as is.
   - Attack Type: Select `PARTIAL_FORGERY`.
   - Intensity slider ($q$): `0.25` ($25\%$ of signature bits corrupted).
3. **Click**: `Run Attack Simulation`.
4. **Inspect Threat Feed**:
   - *Point out*: Decision banner turns terracotta: `REJECT — mismatch_rate=0.2500`.
   - *Point out*: Finding item appears with quantitative metric: `QBER_ANOMALY [SUSPICIOUS] — observed mismatch rate 0.2500 exceeds q_alert threshold 0.1100`.
5. **Switch to**: `Security Metrics` tab.
   - *Point out*: `global_mismatch_rate` is `0.2500` (flagged in red). Bob's direct half reflects the error rate, exceeding $s_a=0.10$.

*Speaker Script*:
> "Now Eve attempts a partial forgery by flipping 25% of the quantum signature positions. The dashboard immediately alerts with a SUSPICIOUS verdict. Notice that the finding is not a vague warning—it outputs the exact measured QBER of 0.2500 against the 0.1100 alert threshold."

---

### Beat 3: Replay Attack Injection (`REJECT`)

1. **Navigate to**: `Control Panel` tab.
2. **Action**: Resubmit the exact same session parameters without changing the sequence number (or click the **Replay attack** button).
3. **Click**: `Run Assessment`.
4. **Inspect Threat Feed**:
   - *Point out*: Threat Level elevates to `CRITICAL`.
   - *Point out*: Finding says `REPLAY_ATTACK [CRITICAL] — fingerprint ... already recorded in the replay ledger.`
5. **Switch to**: `Security Metrics` tab.
   - *Point out*: The **Replay Detection** badge prominently displays `REPLAY DETECTED — AUTHORITATIVE REJECT` alongside the active fingerprint and ledger size.
   - *Point out*: Explain to judges that deterministic checks outrank statistical thresholds in the Layer 2 decision hierarchy.

*Speaker Script*:
> "If an adversary captures an authentic signature packet and replays it, Layer 2's session ledger catches the duplicate fingerprint. Even if the quantum bit error rate were zero, the deterministic replay check triggers an immediate, authoritative REJECT."

---

### Beat 4: Feedforward Pauli Correction Tampering (`REJECT`)

1. **Navigate to**: `Control Panel` tab.
2. **Set Parameters**:
   - Attack Type: Select `CORRECTION_TAMPERING`.
   - Intensity: `1.0`.
3. **Click**: `Run Attack Simulation`.
4. **Switch to**: `Circuit Trace` tab.
   - *Point out*: The per-position hardware register table.
   - *Point out*: Flagged rows with terracotta background: expected correction (e.g. `X`) vs actual tampered correction (e.g. `I!`).
   - *Point out*: Teleportation fidelity dips to `0.5000` on tampered positions, and final bit measurements mismatch.
5. **Switch to**: `Threat Feed` tab:
   - *Point out*: `CORRECTION_TAMPERING [CRITICAL] — ... position(s) have expected_correction != actual_correction.`

*Speaker Script*:
> "In quantum teleportation, the recipient must apply a feedforward Pauli correction based on the Bell measurement outcome. Here we simulate an adversary tampering with the classical correction channel. The Circuit Trace pinpoints the exact position indices where expected correction differs from actual correction."

---

### Beat 5: Scientific Integrity & Experiment Sweep

1. **Navigate to**: `Experiment Report` tab.
2. **Show Chart**:
   - Pre-loaded points from `partial_forgery_sweep.csv` (blue circles).
   - Horizontal reference lines at $s_a=0.10$ and $s_v=0.20$.
3. **Run Live Sweep**:
   - Click **Run New Sweep**.
   - Watch the live progress indicator update ($0\% \to 100\%$) and live points (amber squares, dashed line) render sequentially without UI freezing.
4. **Export Data**:
   - Click **Export CSV** or **Export JSON** to verify file download.
5. **Footer Callout**:
   - Point out the mandatory scientific integrity disclaimer at the bottom of the screen.

---

## 5-Minute Pre-Presentation Rehearsal Checklist

- [ ] Restart backend server to initialize a clean in-memory replay ledger.
- [ ] Open frontend in browser; confirm `Layer 1 & Layer 2 Active` status chip in top bar.
- [ ] Click **Clean session** $\to$ Confirm `ACCEPT` banner.
- [ ] Select `CORRECTION_TAMPERING` $\to$ Confirm red highlighted rows in `Circuit Trace`.
- [ ] Re-run identical session $\to$ Confirm `REPLAY_ATTACK` trigger.
- [ ] Open `Experiment Report` $\to$ Confirm chart renders with reference lines.
