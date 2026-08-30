from __future__ import annotations

import math
import random
from typing import Optional
from pydantic import BaseModel, Field

from app.schemas.telemetry import (
    ProtocolSessionResult,
    AttackType,
    AttackMetadata,
    TeleportationEvent,
    MeasurementEvent,
)
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary
from app.layer1_protocol.quantum_states import prepare_pauli_eigenstate
from app.layer1_protocol.pauli_corrections import apply_pauli_correction
from app.layer1_protocol.measurement import measure_in_basis
from app.layer1_protocol.statevector import calculate_fidelity


def _recompute_verification_summary(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
) -> BasicVerificationSummary:
    total = len(positions)
    matching = sum(1 for p in positions if p.is_match)
    mismatching = total - matching
    mismatch_rate = mismatching / total if total > 0 else 0.0
    avg_fidelity = (
        sum(p.fidelity for p in positions) / total if total > 0 else 0.0
    )

    basis_dist: dict[str, int] = {}
    corr_dist: dict[str, int] = {}
    for p in positions:
        basis_dist[p.pauli_basis] = basis_dist.get(p.pauli_basis, 0) + 1
        corr_dist[p.actual_correction] = corr_dist.get(p.actual_correction, 0) + 1

    return BasicVerificationSummary(
        total_positions=total,
        matching_positions=matching,
        mismatching_positions=mismatching,
        mismatch_count=mismatching,
        mismatch_rate=mismatch_rate,
        average_fidelity=avg_fidelity,
        basis_distribution=basis_dist,
        correction_distribution=corr_dist,
        digest_matches=digest_matches,
        is_perfect_match=(mismatching == 0) and digest_matches,
    )


def inject_attack(
    session: ProtocolSessionResult,
    attack_type: AttackType,
    intensity: float = 1.0,
    target_basis: Optional[str] = None,
    seed: int = 42,
) -> ProtocolSessionResult:
    intensity = max(0.0, min(1.0, intensity))
    rng = random.Random(seed)
    import numpy as np
    np_rng = np.random.default_rng(seed)

    injected_session = session.model_copy(deep=True)
    positions = [p.model_copy(deep=True) for p in injected_session.signature_positions]
    teleportation_events = [t.model_copy(deep=True) for t in injected_session.teleportation_events]
    measurement_events = [m.model_copy(deep=True) for m in injected_session.measurement_events]

    meta_desc = ""
    digest_matches = injected_session.verification_summary.digest_matches

    if attack_type == AttackType.REPLAY:
        meta_desc = "Replay attack: session fingerprint reused"

    elif attack_type == AttackType.FULL_FORGERY:
        injected_session = injected_session.model_copy(
            update={
                "message_digest": "0" * 64,
                "message": "FORGED_MESSAGE_PAYLOAD",
            }
        )
        digest_matches = False
        meta_desc = "Full digest forgery: classical SHA-256 digest corrupted"

    elif attack_type == AttackType.PARTIAL_FORGERY:
        n = len(positions)
        k = round(n * intensity)
        indices = rng.sample(range(n), k) if k <= n else list(range(n))
        for idx in indices:
            p = positions[idx]
            flipped_bit = 1 - p.final_measured_bit
            positions[idx] = p.model_copy(
                update={"is_match": False, "final_measured_bit": flipped_bit}
            )
        meta_desc = f"Partial signature forgery: {k}/{n} positions inverted (q={intensity:.2f})"

    elif attack_type == AttackType.CORRECTION_TAMPERING:
        n = len(positions)
        k = max(1, round(n * (intensity if intensity > 0 else 0.25)))
        indices = rng.sample(range(n), k) if k <= n else list(range(n))
        for idx in indices:
            p = positions[idx]
            if p.expected_correction == "I":
                tampered_corr = "X"
            elif p.expected_correction == "X":
                tampered_corr = "I"
            elif p.expected_correction == "Z":
                tampered_corr = "X"
            else:
                tampered_corr = "I"

            input_state = prepare_pauli_eigenstate(basis=p.pauli_basis, bit=p.encoded_bit)
            if p.expected_correction == "I":
                raw_state = input_state
            elif p.expected_correction == "X":
                raw_state = apply_pauli_correction(input_state, "X")
            elif p.expected_correction == "Y":
                raw_state = apply_pauli_correction(input_state, "Y")
            elif p.expected_correction == "Z":
                raw_state = apply_pauli_correction(input_state, "Z")
            elif p.expected_correction == "XZ":
                raw_state = apply_pauli_correction(input_state, "ZX")
            else:
                raw_state = input_state

            output_state = apply_pauli_correction(raw_state, tampered_corr)
            new_fidelity = float(calculate_fidelity(input_state, output_state))
            meas_res = measure_in_basis(state=output_state, basis=p.pauli_basis, rng=np_rng)
            new_measured_bit = int(meas_res.outcome_bit)
            new_is_match = bool(new_measured_bit == p.expected_bit)

            positions[idx] = p.model_copy(
                update={
                    "actual_correction": tampered_corr,
                    "fidelity": new_fidelity,
                    "final_measured_bit": new_measured_bit,
                    "is_match": new_is_match,
                }
            )

            for tel_idx, tel_ev in enumerate(teleportation_events):
                if tel_ev.position_index == p.index:
                    teleportation_events[tel_idx] = tel_ev.model_copy(
                        update={
                            "applied_correction": tampered_corr,
                            "fidelity": new_fidelity,
                        }
                    )

            for meas_idx, meas_ev in enumerate(measurement_events):
                if meas_ev.position_index == p.index:
                    measurement_events[meas_idx] = meas_ev.model_copy(
                        update={
                            "outcome_bit": new_measured_bit,
                            "probabilities": meas_res.probabilities,
                            "is_deterministic": meas_res.is_deterministic,
                        }
                    )

        meta_desc = f"Pauli correction tampering: {k}/{n} positions tampered"

    elif attack_type == AttackType.INTERCEPT_RESEND:
        n = len(positions)
        for idx in range(n):
            if rng.random() < 0.25:
                p = positions[idx]
                flipped_bit = 1 - p.final_measured_bit
                positions[idx] = p.model_copy(
                    update={"is_match": False, "final_measured_bit": flipped_bit}
                )
        meta_desc = "Intercept-resend attack: ~25% QBER introduced across channel"

    elif attack_type == AttackType.CHANNEL_MANIPULATION:
        target = target_basis or "Z"
        matching_indices = [i for i, p in enumerate(positions) if p.pauli_basis == target]
        k = round(len(matching_indices) * (intensity if intensity > 0 else 0.5))
        selected_indices = rng.sample(matching_indices, k) if k <= len(matching_indices) else matching_indices
        for idx in selected_indices:
            p = positions[idx]
            flipped_bit = 1 - p.final_measured_bit
            positions[idx] = p.model_copy(
                update={"is_match": False, "final_measured_bit": flipped_bit}
            )
        meta_desc = f"Basis-specific channel manipulation: targeted basis '{target}' with {len(selected_indices)} bit flips"

    elif attack_type == AttackType.FIDELITY_DEGRADATION:
        n = len(positions)
        degraded_fid = max(0.5, 1.0 - 0.3 * (intensity if intensity > 0 else 1.0))
        for idx in range(n):
            p = positions[idx]
            positions[idx] = p.model_copy(update={"fidelity": degraded_fid})
        meta_desc = f"Teleportation fidelity degradation: fidelity dropped to {degraded_fid:.2f}"

    elif attack_type == AttackType.BOB_REPUDIATION:
        n = len(positions)
        split_idx = math.ceil(n * 0.5)
        bob_indices = list(range(split_idx))
        k = max(1, round(len(bob_indices) * (intensity if intensity > 0 else 0.5)))
        selected = rng.sample(bob_indices, k) if k <= len(bob_indices) else bob_indices
        for idx in selected:
            p = positions[idx]
            flipped_bit = 1 - p.final_measured_bit
            positions[idx] = p.model_copy(
                update={"is_match": False, "final_measured_bit": flipped_bit}
            )
        meta_desc = f"Bob repudiation attack: {len(selected)} bit flips on Bob's half only"

    else:
        raise ValueError(f"Unknown AttackType: {attack_type!r}")

    pos_map = {p.index: p for p in positions}
    for i, m in enumerate(measurement_events):
        if m.position_index in pos_map:
            p = pos_map[m.position_index]
            measurement_events[i] = m.model_copy(update={"outcome_bit": p.final_measured_bit})

    for i, t in enumerate(teleportation_events):
        if t.position_index in pos_map:
            p = pos_map[t.position_index]
            teleportation_events[i] = t.model_copy(update={
                "applied_correction": p.actual_correction,
                "fidelity": p.fidelity,
            })

    new_summary = _recompute_verification_summary(positions, digest_matches=digest_matches)

    attack_meta = AttackMetadata(
        attack_id=f"attack-{attack_type.value.lower()}-{seed}",
        attack_type=attack_type,
        intensity=intensity,
        target_basis=target_basis,
        seed=seed,
        description=meta_desc,
    )

    return injected_session.model_copy(
        update={
            "signature_positions": positions,
            "teleportation_events": teleportation_events,
            "measurement_events": measurement_events,
            "verification_summary": new_summary,
            "attack_metadata": attack_meta,
        }
    )

