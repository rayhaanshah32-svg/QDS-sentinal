"""
Layer 2 – Replay Ledger

An in-memory singleton that records session fingerprints to detect replay
attacks.  A fingerprint is the tuple:
    (session_id, signature_block_id, nonce, sequence_number)

All four fields must match for a replay to be flagged.  This is a
deterministic check; a fingerprint match is authoritative evidence of replay.

Scope and limitations
---------------------
- In-memory only; state is lost on process restart.
- Persistence (database, distributed cache) is out of scope for Layer 2.
- The ledger is bounded by max_replay_window (Layer2Config) to prevent
  unbounded memory growth; oldest entries are evicted first (FIFO).
"""

from __future__ import annotations

from collections import OrderedDict
from threading import Lock


class ReplayLedger:
    """
    Thread-safe, bounded in-memory replay fingerprint store.

    Enforces:
    (a) Exact duplicate nonce/signature-block or fingerprint match
    (b) Duplicate sequence number within the same session
    (c) Sequence number regression (lower than latest accepted sequence_number)
    """

    def __init__(self, max_size: int = 1000) -> None:
        if max_size < 1:
            raise ValueError(f"max_size must be >= 1, got {max_size}")
        self._max_size = max_size
        self._store: OrderedDict[str, None] = OrderedDict()
        self._latest_seq: dict[str, int] = {}
        self._session_nonces: dict[str, set[str]] = {}
        self._lock = Lock()

    @staticmethod
    def make_fingerprint(
        session_id: str,
        block_id: str,
        nonce: str,
        sequence_number: int,
    ) -> str:
        """
        Build the canonical fingerprint string.
        Format: "session_id|block_id|nonce|seq"
        """
        return f"{session_id}|{block_id}|{nonce}|{sequence_number}"

    def check_and_record(
        self,
        session_id: str,
        block_id: str,
        nonce: str,
        sequence_number: int,
    ) -> tuple[bool, str]:
        """
        Check whether this fingerprint already exists or violates sequence progression, then record it.

        Returns
        -------
        (is_replay, fingerprint)
            is_replay: True if already seen or sequence regression detected.
            fingerprint: the canonical fingerprint string.
        """
        fp = self.make_fingerprint(session_id, block_id, nonce, sequence_number)
        with self._lock:
            # (a) Exact duplicate fingerprint match
            if fp in self._store:
                return True, fp

            # (a) Nonce reuse within the same session
            if session_id in self._session_nonces and nonce in self._session_nonces[session_id]:
                return True, fp

            # (b) & (c) Duplicate sequence number or lower sequence number regression
            if session_id in self._latest_seq and sequence_number <= self._latest_seq[session_id]:
                return True, fp

            # Record entry and maintain capacity limit
            while len(self._store) >= self._max_size:
                evicted_fp, _ = self._store.popitem(last=False)
                parts = evicted_fp.split("|")
                if len(parts) >= 4:
                    evicted_session = parts[0]
                    evicted_nonce = parts[2]
                    if evicted_session in self._session_nonces:
                        self._session_nonces[evicted_session].discard(evicted_nonce)
                    # If no remaining entries exist for this session, clear latest_seq and session_nonces
                    has_remaining = any(k.startswith(f"{evicted_session}|") for k in self._store)
                    if not has_remaining:
                        self._latest_seq.pop(evicted_session, None)
                        self._session_nonces.pop(evicted_session, None)

            self._store[fp] = None

            if session_id not in self._session_nonces:
                self._session_nonces[session_id] = set()
            self._session_nonces[session_id].add(nonce)

            self._latest_seq[session_id] = max(self._latest_seq.get(session_id, -1), sequence_number)
            return False, fp

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        """Clear all ledger entries (for testing)."""
        with self._lock:
            self._store.clear()
            self._latest_seq.clear()
            self._session_nonces.clear()


# Module-level default ledger instance shared across the process.
default_ledger = ReplayLedger()
