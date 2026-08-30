# QDS Sentinel Layer 3 — Final Release Audit Report

**Scope**: Layer 3 Dashboard, Telemetry Visualization, and Experiment Reporting.
**Date**: August 2026
**Evaluator**: Principal Frontend / Security Visualization Engineer

---

## 1. Executive Summary & Verdict

| Category | Status | Evaluation Summary |
|---|:---:|---|
| **A. Data Integrity** | **PASS** | 100% of telemetry traces to real backend fields. No client-side threshold re-derivation. Bob/Charlie metrics are strictly separated. Deterministic checks outrank statistical detectors. |
| **B. Visual Direction Compliance** | **PASS** | 0 gradients, no glassmorphism, 0 emoji icons, restrained 2–4px border radii, muted pastel palette, full monospace tabular telemetry. |
| **C. Functional Completeness** | **PASS** | All 6 required views fully implemented, simulation disclaimer present on all decision screens, graceful backend offline handling, and experiment sweep charting with export. |
| **D. Demo Readiness** | **PASS** | 4-beat narrative (Clean $\to$ Forgery $\to$ Replay $\to$ Correction Tampering) executes cleanly with no stale flashes, zero console errors, and pairing demo script provided. |

**Final Readiness Verdict**: **READY FOR DEMO**

---

## 2. Detailed Audit Matrix

### A. Data Integrity

| Requirement | Status | Evidence / File Citation |
|---|:---:|---|
| **1. Zero Hardcoded / Mocked Telemetry** | **PASS** | `MetricsPanel.jsx`, `ThreatFeed.jsx`, `CircuitTrace.jsx`. All telemetry fields (`global_mismatch_rate`, `inconsistency_count`, `fidelity`, `confidence_upper_bound`) map 1:1 to `ThreatAssessment` or `ProtocolSessionResult`. Regex audit of codebase verified no synthetic constants replacing API fields. |
| **2. No Client-Side Verdict Logic** | **PASS** | `ControlPanel.jsx`, `DecisionBanner.jsx`. The dashboard renders `assessment.security_decision` and `assessment.threat_level` directly as computed by Layer 2's `engine.py`. No `if (mismatch > threshold)` client-side decision logic exists. |
| **3. Independent Bob / Charlie Metrics** | **PASS** | `MetricsPanel.jsx` (lines 144–198) and `MetricsPanel.module.css` (lines 198–225). Direct (`direct_*`) and forwarded (`forwarded_*`) metrics are rendered in structurally separated columns divided by `.bcDivider`. No sum or average is computed. |
| **4. Precedence of Deterministic Badges** | **PASS** | `MetricsPanel.jsx` (lines 48–51), `DigestBadge.jsx`, `ReplayBadge.jsx`. SHA-256 Digest and Replay Detection are rendered at the top of the metrics view with high-prominence status blocks before statistical panels. |

---

### B. Visual Direction Compliance

| Requirement | Status | Evidence / File Citation |
|---|:---:|---|
| **1. Zero Gradient Fills** | **PASS** | Grep audit for `gradient`, `from-`, `to-`, `via-` across `frontend/src/` yielded **0 hits**. Replaced dashed legend gradients in `ExperimentReport.module.css` with clean `border-top: 2px dashed`. |
| **2. Genuinely Pastel Color Palette** | **PASS** | `tokens.css`: Muted Sage (`hsl(142, 26%, 38%)` / `#477B56`), Dusty Terracotta (`hsl(6, 52%, 42%)` / `#A33833`), Soft Amber (`hsl(38, 62%, 44%)` / `#B57B2B`), Warm Stone (`hsl(40, 8%, 93%)` / `#EDECE8`). No generic primary reds/greens. |
| **3. Monospace Numeric Telemetry** | **PASS** | `global.css`, `tokens.css`, `CircuitTrace.module.css`, `MetricsPanel.module.css`. Font stack `'JetBrains Mono', 'Fira Code', monospace` applied to all numerics with `text-align: right` on table data columns. |
| **4. No Emoji as Icons** | **PASS** | Grep audit for Unicode emoji yielded **0 hits**. Clean SVG icons from `lucide-react` used at uniform `strokeWidth={1.5}`. |
| **5. Restrained Border-Radius (2–6px)** | **PASS** | Tokens `--radius-sm: 2px`, `--radius-md: 4px`, `--radius-lg: 6px`. Audited all module stylesheets; no card has oversized rounding (>6px) or pill shapes. |
| **6. Severity Accent Bars** | **PASS** | `ThreatFeed.module.css` (`.findingBar { width: 4px; }`), `DecisionBanner.module.css` (`border-left-width: 4px;`). Severity is communicated via 4px left-edge bars rather than full card fills. |

---

### C. Functional Completeness

| View / Feature | Status | Evidence / File Citation |
|---|:---:|---|
| **View 2.1: Simulation Control Panel** | **PASS** | `ControlPanel.jsx`. Maps all `SimulationRequest` and `AttackSimulateRequest` inputs. Collapsible advanced threshold overrides, 8-attack type dropdown, and real-time execution buttons. |
| **View 2.2: Teleportation & Circuit Trace** | **PASS** | `CircuitTrace.jsx`. Per-position hardware register table showing prepared state, Bell outcome, expected vs actual correction with `!` mismatch markers, and 4-decimal fidelity gauges. |
| **View 2.3: Threat Feed** | **PASS** | `ThreatFeed.jsx`. Scrollable finding cards with severity color bars, verbatim mathematical inequalities from Layer 2, and identity authorization matrix. |
| **View 2.4: Security Metrics Panel** | **PASS** | `MetricsPanel.jsx`. Side-by-side QBER basis breakdown (X/Y/Z), correction tampering rate, fidelity floor analysis, and separate Bob/Charlie columns. |
| **View 2.5: Experiment Report** | **PASS** | `ExperimentReport.jsx`. Recharts visualization of `partial_forgery_sweep.csv` with live multi-point sweep execution and CSV/JSON export. |
| **View 2.6: Scientific Integrity Footer** | **PASS** | `SimDisclaimer.jsx`, `App.jsx`. Unobtrusive disclaimer rendered on every view displaying a security decision. |
| **Error Handling & Offline State** | **PASS** | `ErrorBanner.jsx`, `App.jsx`. Displays formatted banners for 422 threshold ordering violations and live backend offline status indicators. |

---

### D. Demo Readiness

| Requirement | Status | Evidence / File Citation |
|---|:---:|---|
| **Full 4-Beat Narrative Execution** | **PASS** | Clean $\to$ Forgery $\to$ Replay $\to$ Correction Tampering flow verified with zero console errors and atomic React 18 state updates (no stale flashes). |
| **Paired Demo Script** | **PASS** | `docs/layer3-demo-script.md` produced with exact click-by-click instructions, speaker notes, and screen transitions. |

---

## 3. Issues Found and Resolved During Hardening

1. **Legend Gradient Removal**: `ExperimentReport.module.css` previously utilized `repeating-linear-gradient` to simulate dashed lines in the custom legend. Replaced with standard `border-top: 2px dashed` to ensure 0 gradient rules across the entire stylesheet.
2. **Badge Corner Radius Normalization**: `App.module.css` had a finding count badge with `border-radius: 8px`. Normalized to `var(--radius-sm)` (2px) to conform strictly to the 2–6px restrained geometry rule.
3. **Recharts Multi-Series Data Alignment**: In `ExperimentReport.jsx`, unified pre-loaded CSV and live sweep results into a single dataset with independent keys (`csv_rate` vs `live_rate`) to ensure Recharts handles dual-series line rendering without data collision.
4. **Backend Connectivity Awareness**: Added automatic backend health pinging (`checkHealth()`) to display an offline banner and disable stale assumptions if port 8000 is down.

---

## 4. Known Limitations & Expected Behaviors

1. **In-Memory Replay Ledger Persistence**: The backend `default_ledger` resides in server memory. Submitting the exact same session parameters twice without modifying the sequence number will correctly trigger `REPLAY_ATTACK`. Restarting the backend clears this ledger.
2. **GET Example Endpoints Circuit Telemetry**: `GET /api/v1/layer2/example-*` endpoints return only `ThreatAssessment` (no session telemetry). The Circuit Trace view cleanly notifies the user that full per-position telemetry is available when running a simulation via the Control Panel.

---

## 5. Pre-Presentation Live Checklist

Before walking into the live judge presentation, execute these steps once:

1. **Cold Backend Restart**:
   ```bash
   # In terminal 1
   cd backend
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
2. **Launch Frontend Dashboard**:
   ```bash
   # In terminal 2
   cd frontend
   npm run dev
   ```
3. Open `http://localhost:5173/` and confirm `Layer 1 & Layer 2 Active` is green in the top header.
4. Click **Clean session** $\to$ Confirm `ACCEPT` verdict.
5. In Control Panel, select Attack Type: `PARTIAL_FORGERY` ($q=0.25$) $\to$ Click `Run Attack Simulation` $\to$ Confirm `REJECT` with `QBER_ANOMALY`.
6. In Control Panel, resubmit the clean session without changing sequence number $\to$ Confirm `REJECT` with `REPLAY_ATTACK`.
7. In Control Panel, select Attack Type: `CORRECTION_TAMPERING` $\to$ Click `Run Attack Simulation` $\to$ Switch to `Circuit Trace` and confirm terracotta highlighted rows.
8. Switch to `Experiment Report` $\to$ Click `Run New Sweep` $\to$ Confirm progress reaches 100% and points render.
