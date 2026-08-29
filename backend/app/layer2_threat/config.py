"""
Layer 2 Threat Detection Engine – Configuration

All thresholds are recorded here with their derivation source.
SCIENTIFIC INTEGRITY: No threshold is emitted without an audit trail.

Threshold derivation notes
--------------------------
s_a (direct / authenticator threshold):
    Source: Amiri et al. (2016) Eq. (19). In their finite-sample protocol,
    the authenticator Bob applies a lower error-tolerance threshold s_a < s_v.
    For this simulation we set s_a = 0.10 (10 %).
    Rationale: With n = 16 (default signature length) and e_honest = 0.0
    (NoNoise baseline), any observed mismatch rate > s_a is anomalous.
    At n >= 16 the Hoeffding bound places the false-positive rate at
    exp(-2 * n * (s_a - e_honest)^2) = exp(-2*16*0.01) ≈ 0.724 for the
    noiseless case, which is by design non-trivial so Layer 3 can display
    real confidence bands.  Operators MUST recalibrate s_a via
    honest_error_rate in HonestNoiseCalibration if their channel has real
    background error.

s_v (forwarded / verifier threshold):
    Source: Amiri et al. (2016) Eq. (19).  s_v > s_a ensures repudiation is
    exponentially hard (Eq. 20-24).  We set s_v = 0.20 (20 %).
    The gap s_v - s_a = 0.10 must satisfy p_E > s_v where p_E is the
    adversarial error rate for eavesdropping strategies, which in the
    QKD-based QDS literature is typically p_E ≥ 0.25 for intercept-resend.

QBER alert threshold (q_alert):
    Source: standard BB84 QKD security analysis.  QBER > 0.11 (11 %) is
    the commonly cited threshold above which unconditional security of BB84
    cannot be guaranteed under the most conservative independent-errors
    assumption.  Here we use it as an advisory indicator, not a hard block.

Correction-consistency alert threshold (c_tamper_rate):
    Source: fixed engineering constant.  In a noiseless simulation, any
    position where expected_correction != actual_correction (normalised to a
    rate) is a direct indicator of post-teleportation tampering.  Threshold
    = 0.0 (zero-tolerance deterministic check).

Fidelity floor (f_floor):
    Source: Layer 1 teleportation specification (docs/layer1-audit-report.md,
    row "Noiseless teleportation fidelity ≥ 0.999999").  Any fidelity below
    0.999 without an explicit noise model is a flag.

Replay ledger window:
    Source: fixed config.  A session (session_id, signature_block_id,
    nonce, sequence_number) that matches a previously seen tuple is a replay.
    Window size is in-memory per process; persistence is out of scope.

Honest-noise calibration rate (e_honest):
    Source: user-configurable.  Defaults to 0.0 (NoNoise matches Layer 1's
    NoNoise baseline exactly).  Set to a real measured channel error rate
    before running statistical detectors on real hardware output.
"""

from dataclasses import dataclass, field


@dataclass
class Layer2Config:
    # -----------------------------------------------------------------------
    # QDS Bob/Charlie threshold pair
    # -----------------------------------------------------------------------
    # s_a: direct recipient (Bob) mismatch-rate threshold.
    # Derivation: Amiri et al. 2016 Eq.(19); fixed constant 0.10 for noiseless
    # simulation. Must be recalibrated against e_honest if channel has noise.
    s_a: float = 0.10

    # s_v: forwarded recipient (Charlie) mismatch-rate threshold.
    # Derivation: Amiri et al. 2016 Eq.(19). Must satisfy s_a < s_v < p_E.
    # Fixed constant 0.20 for noiseless simulation.
    s_v: float = 0.20

    # p_E: adversarial error rate for eavesdropping strategies (e.g. intercept-resend).
    # Derivation: Amiri et al. 2016 Eq.(19). Standard intercept-resend in QKD gives p_E >= 0.25.
    # Must satisfy e_upper < s_a < s_v < p_E.
    p_E: float = 0.25

    # -----------------------------------------------------------------------
    # QBER advisory threshold
    # -----------------------------------------------------------------------
    # q_alert: QBER fraction above which channel security cannot be
    # unconditionally guaranteed under BB84 analysis.
    # Source: standard QKD literature; fixed constant 0.11.
    q_alert: float = 0.11

    # -----------------------------------------------------------------------
    # Correction consistency
    # -----------------------------------------------------------------------
    # c_tamper_rate: correction-inconsistency rate above which tampering is
    # flagged.  Zero-tolerance in noiseless simulation.
    # Source: fixed constant derived from Layer 1 deterministic correction rule.
    c_tamper_rate: float = 0.0

    # -----------------------------------------------------------------------
    # Fidelity floor
    # -----------------------------------------------------------------------
    # f_floor: teleportation fidelity below which a position is flagged.
    # Source: Layer 1 audit specification (fidelity ≥ 0.999999 for NoNoise).
    f_floor: float = 0.999

    # -----------------------------------------------------------------------
    # Honest-noise calibration (Layer 2 calibration tool, NOT Layer 1 noise)
    # -----------------------------------------------------------------------
    # e_honest: configured honest background mismatch rate used ONLY for
    # calibrating s_a/s_v against finite-sample bounds.
    # Default 0.0 matches Layer 1 NoNoise baseline.
    # NEVER applied to alter Layer 1 telemetry.
    e_honest: float = 0.0

    # -----------------------------------------------------------------------
    # Forwarding / symmetrization split
    # -----------------------------------------------------------------------
    # forwarding_split: fraction of signature positions assigned to Bob
    # (direct verification half).  The remainder (1 - forwarding_split) is
    # the Charlie (forwarded) half.
    # Source: Amiri et al. 2016 symmetrization step. This is an EXPLICIT
    # Layer 2 simplification — Layer 1 does not model the two-recipient
    # symmetrization step.  See docs/layer2-security-claims.md.
    forwarding_split: float = 0.5

    # -----------------------------------------------------------------------
    # Replay ledger
    # -----------------------------------------------------------------------
    # max_replay_window: maximum number of past session fingerprints held in
    # the in-memory replay ledger.  Oldest entries are evicted when exceeded.
    max_replay_window: int = 1000

    # -----------------------------------------------------------------------
    # Verification mode
    # -----------------------------------------------------------------------
    # verification_mode: controls which recipient role is being evaluated.
    # "direct"   – evaluate as Bob (authenticator), threshold = s_a
    # "forwarded" – evaluate as Charlie (verifier), threshold = s_v
    # The security decision MUST always declare which mode was used.
    # Cross-wiring s_a into a Charlie check or vice versa is a security bug
    # (see Amiri et al. Eq. 20-24).
    verification_mode: str = "direct"


# Module-level default instance.  Endpoints and detectors import this.
default_config = Layer2Config()
