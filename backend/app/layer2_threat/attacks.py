"""
Layer 2 Threat Detection Engine – Attack Injection Module

This module implements deterministic attack injection on Layer 1 ProtocolSessionResult
objects to enable systematic threat detection benchmarking.

CRITICAL DESIGN REQUIREMENTS:
1. Ground truth metadata (AttackMetadata) is attached to injected packets.
2. Layer 2 threat detectors (detectors.py, engine.py) NEVER read AttackMetadata.
3. Original ProtocolSessionResult objects are NEVER mutated (all operations use deep copy).
4. All injection logic is strictly deterministic under a fixed random seed.
"""

from __future__ import annotations

import math
import random
from typing import Optional
from pydantic import BaseModel, Field

from app.schemas.telemetry import (
    ProtocolSessionResult,
    AttackType,
    AttackMetadata,
)
from app.schemas.protocol import SignaturePositionRecord, BasicVerificationSummary


def _recompute_verification_summary(
    positions: list[SignaturePositionRecord],
    digest_matches: bool = True,
) -> BasicVerificationSummary:
    """Recompute BasicVerificationSummary telemetry fields from updated signature positions."""
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
    """
    Inject a specific attack into a copy of a ProtocolSessionResult.

    Parameters
    ----------
    session : ProtocolSessionResult
        Original Layer 1 session (NEVER mutated).
    attack_type : AttackType
        Which attack to simulate (REPLAY, FULL_FORGERY, PARTIAL_FORGERY, etc.).
    intensity : float, optional
        Attack intensity parameter q in [0, 1] (default 1.0).
    target_basis : str, optional
        Target basis for basis-specific attacks (e.g. 'Z').
    seed : int, optional
        Random seed for deterministic injection (default 42).

    Returns
    -------
    ProtocolSessionResult
        A new, injected ProtocolSessionResult instance with Ground-Truth AttackMetadata.
    """
    intensity = max(0.0, min(1.0, intensity))
    rng = random.Random(seed)

    # STRICT IMMUTABILITY REQUIREMENT: deep copy original session
    injected_session = session.model_copy(deep=True)
    positions = [p.model_copy(deep=True) for p in injected_session.signature_positions]

    meta_desc = ""
    digest_matches = injected_session.verification_summary.digest_matches

    if attack_type == AttackType.REPLAY:
        # Replay attack: session fingerprint is identical, but sequence number or timestamp indicates reuse
        meta_desc = "Replay attack: session fingerprint reused"
        # No signature bit changes, same fingerprint

    elif attack_type == AttackType.FULL_FORGERY:
        # Full forgery: message or digest tampered
        injected_session = injected_session.model_copy(
            update={
                "message_digest": "0" * 64,
                "message": "FORGED_MESSAGE_PAYLOAD",
            }
        )
        digest_matches = False
        meta_desc = "Full digest forgery: classical SHA-256 digest corrupted"

    elif attack_type == AttackType.PARTIAL_FORGERY:
        # Partial forgery: flip a fraction q of signature bit outcomes
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
        # Correction tampering: alter Pauli corrections after Bell measurement
        n = len(positions)
        k = max(1, round(n * (intensity if intensity > 0 else 0.25)))
        indices = rng.sample(range(n), k) if k <= n else list(range(n))
        for idx in indices:
            p = positions[idx]
            tampered_corr = "X" if p.expected_correction == "I" else "I"
            positions[idx] = p.model_copy(
                update={"actual_correction": tampered_corr}
            )
        meta_desc = f"Pauli correction tampering: {k}/{n} positions tampered"

    elif attack_type == AttackType.INTERCEPT_RESEND:
        # Intercept-resend: Eve measures qubits in random bases (~25% QBER)
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
        # Channel manipulation: target a specific basis (e.g. Z basis)
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
        # Environmental decoherence / fidelity degradation floor breach
        n = len(positions)
        degraded_fid = max(0.5, 1.0 - 0.3 * (intensity if intensity > 0 else 1.0))
        for idx in range(n):
            p = positions[idx]
            positions[idx] = p.model_copy(update={"fidelity": degraded_fid})
        meta_desc = f"Teleportation fidelity degradation: fidelity dropped to {degraded_fid:.2f}"

    elif attack_type == AttackType.BOB_REPUDIATION:
        # Bob repudiation: selective bit corruption on Bob's half (first half)
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

    # Recompute verification summary telemetry
    new_summary = _recompute_verification_summary(positions, digest_matches=digest_matches)

    # Attach ground-truth AttackMetadata
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
            "verification_summary": new_summary,
            "attack_metadata": attack_meta,
        }
    )
