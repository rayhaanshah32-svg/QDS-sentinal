"""
Layer 2 – Honest-Noise Calibration Utility

PURPOSE: A Layer 2 calibration tool for testing and threshold validation.
This is NOT a physical noise model and does NOT modify Layer 1 telemetry.

Motivation
----------
Layer 1's NoNoise model produces exactly 0 mismatches, which means s_a and
s_v cannot be calibrated against a realistic adversarial separation p_E when
e_honest = 0.  This utility perturbs a *copy* of the Layer 1 mismatch data
by a configured honest error rate so that:
    1. Finite-sample Hoeffding bounds can be computed meaningfully.
    2. Threshold separation (s_v - s_a > 2 * e_honest) can be validated.
    3. Unit tests can verify detectors react correctly to noisy-but-honest
       channels without re-running Layer 1.

This file is ONLY imported by Layer 2 test code and the calibration helper.
It is NEVER called from the main threat-detection path on real Layer 1 output.

Usage
-----
    from app.layer2_threat.calibration import HonestNoiseCalibrator

    calibrator = HonestNoiseCalibrator(e_honest=0.05, seed=42)
    perturbed_positions = calibrator.perturb_positions(session_result.signature_positions)
    # Use perturbed_positions ONLY for threshold-sensitivity analysis.
"""

from __future__ import annotations

import copy
import math
import numpy as np
from typing import Sequence

from app.schemas.protocol import SignaturePositionRecord


class HonestNoiseCalibrator:
    """
    Perturbs a copy of Layer 1 SignaturePositionRecord list by flipping
    is_match / final_measured_bit independently at rate e_honest.

    Parameters
    ----------
    e_honest : float
        Configured honest background mismatch rate.  Must be in [0, 1).
        Set to match the expected physical channel error rate before using
        statistical detectors.  Default 0.0 reproduces Layer 1 NoNoise output.
    seed : int, optional
        RNG seed for reproducibility.

    Notes
    -----
    - Returns NEW SignaturePositionRecord objects; the originals are unchanged.
    - Never called on the live detection path.
    - e_honest must satisfy e_honest < s_a < s_v < p_E for thresholds to be
      meaningful (Amiri et al. 2016, Section III).
    """

    def __init__(self, e_honest: float = 0.0, seed: int | None = None) -> None:
        if not (0.0 <= e_honest < 1.0):
            raise ValueError(
                f"e_honest must be in [0.0, 1.0), got {e_honest}. "
                "An honest error rate of 1.0 would make verification impossible."
            )
        self.e_honest = e_honest
        self._rng = np.random.default_rng(seed)

    def perturb_positions(
        self,
        positions: Sequence[SignaturePositionRecord],
    ) -> list[SignaturePositionRecord]:
        """
        Return a copy of `positions` with each record independently flipped
        with probability e_honest.

        The flip inverts `is_match` and `final_measured_bit`.  All other
        fields (fidelity, corrections, bases) are unchanged because those
        reflect the teleportation physics, not the classical bit comparison.

        Returns
        -------
        list[SignaturePositionRecord]
            Perturbed copies.  Originals are unmodified.
        """
        perturbed: list[SignaturePositionRecord] = []
        for pos in positions:
            new_pos = pos.model_copy()  # Pydantic v2 deep copy
            if self._rng.random() < self.e_honest:
                # Flip the bit comparison outcome
                flipped_bit = 1 - new_pos.final_measured_bit
                new_pos = SignaturePositionRecord(
                    index=pos.index,
                    pauli_basis=pos.pauli_basis,
                    encoded_bit=pos.encoded_bit,
                    prepared_state_label=pos.prepared_state_label,
                    bell_state=pos.bell_state,
                    bell_measurement_bits=pos.bell_measurement_bits,
                    expected_correction=pos.expected_correction,
                    actual_correction=pos.actual_correction,
                    final_measured_bit=flipped_bit,
                    expected_bit=pos.expected_bit,
                    fidelity=pos.fidelity,
                    is_match=(flipped_bit == pos.expected_bit),
                )
            else:
                new_pos = SignaturePositionRecord(**pos.model_dump())
            perturbed.append(new_pos)
        return perturbed

    def hoeffding_bound(self, n: int, observed_rate: float) -> float:
        """
        Compute Hoeffding upper bound on false-positive probability using bounds module.
        """
        from app.layer2_threat.bounds import hoeffding_tail_bound
        return hoeffding_tail_bound(observed_rate, self.e_honest, n)

    def validate_threshold_separation(
        self,
        s_a: float,
        s_v: float,
        p_E: float = 0.25,
    ) -> tuple[bool, str]:
        """
        Check that thresholds satisfy e_honest < s_a < s_v < p_E.
        """
        from app.layer2_threat.bounds import validate_threshold_chain
        # Calibrator's e_honest represents e_upper baseline
        return validate_threshold_chain(
            e_upper=self.e_honest,
            s_a=s_a,
            s_v=s_v,
            p_E=p_E,
        )
