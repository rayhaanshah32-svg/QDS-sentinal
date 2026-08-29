"""
Layer 2 Threat Detection Engine – Attack Injection & Blindness Tests

Tests:
1. 8 Worked Examples: original summary, injected summary, resulting ThreatAssessment,
   and verification that REJECT/ALERT reasoning references ONLY telemetry, never AttackMetadata.
2. Deterministic attack injection under fixed seed (byte-identical JSON dumps).
3. Packet immutability (original Layer 1 packet is never mutated).
4. PARTIAL_FORGERY intensity sweep generating the "minimum detectable q" CSV.
5. CHANNEL_MANIPULATION basis-specificity (only targeted basis moves).
"""

import os
import csv
import json
import pytest

from app.schemas.telemetry import ProtocolSessionResult, AttackType
from app.layer1_protocol.protocol_session import run_protocol_session
from app.layer2_threat.config import Layer2Config
from app.layer2_threat.engine import assess_session
from app.layer2_threat.replay_ledger import ReplayLedger
from app.layer2_threat.attacks import inject_attack


@pytest.fixture
def clean_session() -> ProtocolSessionResult:
    """Generate a deterministic baseline Layer 1 protocol session."""
    return run_protocol_session(
        message="AUTHENTICATED_QDS_TELEMETRY_PAYLOAD_ORIGINAL",
        sender_id="Alice",
        recipient_id="Bob",
        signature_length=20,
        seed=100,
        bell_state_label="PHI_PLUS",
        allowed_bases=["X", "Y", "Z"],
        session_id="session-orig-100",
        nonce="nonce-orig-100",
        sequence_number=1,
    )


# ---------------------------------------------------------------------------
# 1. 8 Worked Examples & Detector Telemetry-Only Verification
# ---------------------------------------------------------------------------

def test_8_worked_examples_and_telemetry_reasoning(clean_session):
    ledger = ReplayLedger()
    cfg = Layer2Config(verification_mode="direct")

    attack_types = list(AttackType)
    assert len(attack_types) == 8, f"Expected 8 attack types, found {len(attack_types)}"

    print("\n" + "=" * 80)
    print("LAYER 2 ATTACK INJECTION MODULE — 8 WORKED EXAMPLES AUDIT REPORT")
    print("=" * 80)

    for i, at in enumerate(attack_types, 1):
        example_ledger = ReplayLedger()
        target_basis = "Z" if at == AttackType.CHANNEL_MANIPULATION else None
        intensity = 0.25 if at in (AttackType.PARTIAL_FORGERY, AttackType.CHANNEL_MANIPULATION, AttackType.BOB_REPUDIATION) else 1.0

        # For replay attack, we first register the original session in the ledger
        if at == AttackType.REPLAY:
            assess_session(clean_session, config=cfg, ledger=example_ledger)

        injected = inject_attack(
            clean_session,
            attack_type=at,
            intensity=intensity,
            target_basis=target_basis,
            seed=42,
        )

        assessment = assess_session(injected, config=cfg, ledger=example_ledger)

        # Confirm assessment's REJECT/ALERT reasoning NEVER references AttackMetadata
        for finding in assessment.findings:
            assert "AttackMetadata" not in finding
            assert "attack_type" not in finding
            assert "attack_id" not in finding

        assert "AttackMetadata" not in assessment.security_decision

        print(f"\n--- WORKED EXAMPLE {i}: {at.value} ---")
        print("Original Packet Summary:")
        print(f"  Digest: {clean_session.message_digest[:16]}...")
        print(f"  Positions: {clean_session.verification_summary.total_positions}, Mismatches: {clean_session.verification_summary.mismatch_count}, QBER: {clean_session.verification_summary.mismatch_rate:.4f}, Avg Fidelity: {clean_session.verification_summary.average_fidelity:.4f}")

        print("Injected Packet Summary:")
        print(f"  Digest: {injected.message_digest[:16]}...")
        print(f"  Positions: {injected.verification_summary.total_positions}, Mismatches: {injected.verification_summary.mismatch_count}, QBER: {injected.verification_summary.mismatch_rate:.4f}, Avg Fidelity: {injected.verification_summary.average_fidelity:.4f}")
        print(f"  Injected Ground Truth: {injected.attack_metadata.description if injected.attack_metadata else 'None'}")

        print("ThreatAssessment Verdict:")
        print(f"  Threat Level:    {assessment.threat_level.value}")
        print(f"  Threat Category: {assessment.threat_category.value}")
        print(f"  Decision String: {assessment.security_decision}")
        print(f"  Findings:        {assessment.findings}")
        print("-" * 80)


# ---------------------------------------------------------------------------
# 2. Deterministic Attack Injection Under Fixed Seed
# ---------------------------------------------------------------------------

def test_attack_injection_is_strictly_deterministic(clean_session):
    seed = 12345
    for at in AttackType:
        target_basis = "X" if at == AttackType.CHANNEL_MANIPULATION else None
        
        injected1 = inject_attack(clean_session, attack_type=at, intensity=0.20, target_basis=target_basis, seed=seed)
        injected2 = inject_attack(clean_session, attack_type=at, intensity=0.20, target_basis=target_basis, seed=seed)

        json1 = injected1.model_dump_json()
        json2 = injected2.model_dump_json()

        assert json1 == json2, f"Injection for {at.value} failed determinism under seed {seed}"


# ---------------------------------------------------------------------------
# 3. Packet Immutability (Identity and Hash Check)
# ---------------------------------------------------------------------------

def test_original_packet_is_never_mutated(clean_session):
    orig_json_before = clean_session.model_dump_json()
    orig_id = id(clean_session)

    for at in AttackType:
        injected = inject_attack(clean_session, attack_type=at, intensity=0.30, seed=42)

        # Identity check: must be separate Python objects
        assert id(injected) != orig_id

        # Hash/Content check: original packet JSON dump must be unchanged
        orig_json_after = clean_session.model_dump_json()
        assert orig_json_before == orig_json_after, f"Original session mutated during injection of {at.value}"


# ---------------------------------------------------------------------------
# 4. PARTIAL_FORGERY Intensity Sweep & CSV Export
# ---------------------------------------------------------------------------

def test_partial_forgery_intensity_sweep(clean_session):
    cfg = Layer2Config(verification_mode="direct", s_a=0.10, s_v=0.20)

    sweep_intensities = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30]
    sweep_results = []

    print("\n--- PARTIAL FORGERY INTENSITY SWEEP (MINIMUM DETECTABLE Q CURVE) ---")
    print(f"{'Intensity q':<12} {'Mismatch Rate':<15} {'Threat Level':<15} {'Decision':<10}")
    print("-" * 55)

    for q in sweep_intensities:
        injected = inject_attack(clean_session, attack_type=AttackType.PARTIAL_FORGERY, intensity=q, seed=42)
        ledger = ReplayLedger()
        assessment = assess_session(injected, config=cfg, ledger=ledger)

        mismatch_rate = injected.verification_summary.mismatch_rate
        verdict = "REJECT" if "REJECT" in assessment.security_decision else "ACCEPT"

        print(f"{q:<12.2f} {mismatch_rate:<15.4f} {assessment.threat_level.value:<15} {verdict:<10}")

        sweep_results.append({
            "intensity_q": q,
            "mismatch_rate": round(mismatch_rate, 4),
            "threat_level": assessment.threat_level.value,
            "security_decision_verdict": verdict,
            "findings_count": len(assessment.findings),
        })

    # Save to CSV for Layer 3 charting
    csv_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "layer2_threat")
    os.makedirs(csv_dir, exist_ok=True)
    csv_path = os.path.abspath(os.path.join(csv_dir, "partial_forgery_sweep.csv"))

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["intensity_q", "mismatch_rate", "threat_level", "security_decision_verdict", "findings_count"])
        writer.writeheader()
        writer.writerows(sweep_results)

    assert os.path.exists(csv_path)
    assert len(sweep_results) == 7


# ---------------------------------------------------------------------------
# 5. CHANNEL_MANIPULATION Basis-Specific QBER Check
# ---------------------------------------------------------------------------

def test_channel_manipulation_basis_specificity(clean_session):
    # Target basis Z specifically
    target_basis = "Z"
    injected = inject_attack(
        clean_session,
        attack_type=AttackType.CHANNEL_MANIPULATION,
        intensity=0.50,
        target_basis=target_basis,
        seed=42,
    )

    # Group mismatch rates by basis
    def _basis_mismatch_rates(session: ProtocolSessionResult) -> dict[str, float]:
        counts: dict[str, int] = {}
        mismatches: dict[str, int] = {}
        for p in session.signature_positions:
            b = p.pauli_basis
            counts[b] = counts.get(b, 0) + 1
            if not p.is_match:
                mismatches[b] = mismatches.get(b, 0) + 1
        return {b: (mismatches.get(b, 0) / counts[b]) if counts[b] > 0 else 0.0 for b in counts}

    orig_rates = _basis_mismatch_rates(clean_session)
    injected_rates = _basis_mismatch_rates(injected)

    print("\n--- CHANNEL MANIPULATION BASIS SPECIFICITY REPORT ---")
    print(f"Target Basis: '{target_basis}'")
    print(f"Original Basis Mismatch Rates: {orig_rates}")
    print(f"Injected Basis Mismatch Rates: {injected_rates}")
    print("-----------------------------------------------------")

    # Confirm ONLY targeted basis moved!
    assert injected_rates.get("Z", 0.0) > 0.0, "Targeted basis Z should have elevated mismatch rate"
    assert injected_rates.get("X", 0.0) == 0.0, "Non-targeted basis X must remain exactly 0.0"
    assert injected_rates.get("Y", 0.0) == 0.0, "Non-targeted basis Y must remain exactly 0.0"
