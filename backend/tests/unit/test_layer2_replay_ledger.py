"""
Unit tests – Layer 2 Replay Ledger
"""

import pytest
from app.layer2_threat.replay_ledger import ReplayLedger


def _fp(n: int) -> dict:
    return dict(session_id=f"s{n}", block_id=f"b{n}", nonce=f"n{n}", sequence_number=n)


def test_first_entry_is_not_replay():
    ledger = ReplayLedger(max_size=10)
    is_replay, _ = ledger.check_and_record(**_fp(1))
    assert is_replay is False


def test_second_identical_entry_is_replay():
    ledger = ReplayLedger(max_size=10)
    ledger.check_and_record(**_fp(1))
    is_replay, _ = ledger.check_and_record(**_fp(1))
    assert is_replay is True


def test_different_entries_are_not_replays():
    ledger = ReplayLedger(max_size=10)
    for i in range(5):
        is_replay, _ = ledger.check_and_record(**_fp(i))
        assert is_replay is False


def test_fingerprint_format():
    ledger = ReplayLedger(max_size=10)
    _, fp = ledger.check_and_record(
        session_id="s1", block_id="b1", nonce="n1", sequence_number=1
    )
    assert fp == "s1|b1|n1|1"


def test_ledger_evicts_oldest_when_full():
    """After capacity is reached, oldest entry is evicted and can be re-inserted."""
    ledger = ReplayLedger(max_size=3)
    ledger.check_and_record(**_fp(1))
    ledger.check_and_record(**_fp(2))
    ledger.check_and_record(**_fp(3))
    assert len(ledger) == 3

    # Adding fp(4) should evict fp(1)
    ledger.check_and_record(**_fp(4))
    assert len(ledger) == 3

    # fp(1) was evicted; re-inserting is NOT flagged as replay
    is_replay, _ = ledger.check_and_record(**_fp(1))
    assert is_replay is False


def test_ledger_clear_resets_state():
    ledger = ReplayLedger(max_size=10)
    ledger.check_and_record(**_fp(1))
    ledger.clear()
    assert len(ledger) == 0
    is_replay, _ = ledger.check_and_record(**_fp(1))
    assert is_replay is False


def test_ledger_invalid_max_size():
    with pytest.raises(ValueError):
        ReplayLedger(max_size=0)


def test_sequence_number_difference_is_not_replay():
    """Same session/block but fresh nonce and increasing sequence_number must NOT be replay."""
    ledger = ReplayLedger()
    ledger.check_and_record(session_id="s", block_id="b", nonce="n1", sequence_number=1)
    is_replay, _ = ledger.check_and_record(session_id="s", block_id="b", nonce="n2", sequence_number=2)
    assert is_replay is False


def test_duplicate_nonce_same_session_is_replay():
    ledger = ReplayLedger()
    ledger.check_and_record(session_id="s1", block_id="b1", nonce="n1", sequence_number=1)
    is_replay, _ = ledger.check_and_record(session_id="s1", block_id="b2", nonce="n1", sequence_number=2)
    assert is_replay is True


def test_duplicate_sequence_number_same_session_is_replay():
    ledger = ReplayLedger()
    ledger.check_and_record(session_id="s1", block_id="b1", nonce="n1", sequence_number=5)
    is_replay, _ = ledger.check_and_record(session_id="s1", block_id="b2", nonce="n2", sequence_number=5)
    assert is_replay is True


def test_sequence_number_lower_than_latest_is_replay():
    ledger = ReplayLedger()
    ledger.check_and_record(session_id="s1", block_id="b1", nonce="n1", sequence_number=5)
    is_replay, _ = ledger.check_and_record(session_id="s1", block_id="b2", nonce="n2", sequence_number=3)
    assert is_replay is True
