from __future__ import annotations

from collections import OrderedDict
from threading import Lock


class ReplayLedger:
    def __init__(self, max_size: int = 1000) -> None:
        if max_size < 1:
            raise ValueError(f"max_size must be >= 1, got {max_size}")
        self._max_size = max_size
        self._store: OrderedDict[str, dict] = OrderedDict()
        self._seen_block_ids: set[str] = set()
        self._sender_recipient_nonces: dict[tuple[str, str], set[str]] = {}
        self._latest_sequence_numbers: dict[tuple[str, str], int] = {}
        self._lock = Lock()

    @staticmethod
    def make_fingerprint(
        session_id: str,
        block_id: str,
        nonce: str,
        sequence_number: int,
    ) -> str:
        return f"{session_id}|{block_id}|{nonce}|{sequence_number}"

    def check_and_record(
        self,
        session_id: str,
        block_id: str,
        nonce: str,
        sequence_number: int,
        sender_id: str = "alice",
        recipient_id: str = "bob",
    ) -> tuple[bool, str]:
        fp = self.make_fingerprint(session_id, block_id, nonce, sequence_number)
        pair_key = (sender_id, recipient_id)
        session_key = (sender_id, session_id)

        with self._lock:
            if fp in self._store:
                return True, fp

            if block_id in self._seen_block_ids:
                return True, fp

            if pair_key in self._sender_recipient_nonces and nonce in self._sender_recipient_nonces[pair_key]:
                return True, fp

            if session_key in self._latest_sequence_numbers and sequence_number <= self._latest_sequence_numbers[session_key]:
                return True, fp

            while len(self._store) >= self._max_size:
                evicted_fp, evicted_metadata = self._store.popitem(last=False)
                evicted_block = evicted_metadata.get("block_id")
                evicted_pair = evicted_metadata.get("pair_key")
                evicted_nonce = evicted_metadata.get("nonce")
                evicted_session_key = evicted_metadata.get("session_key")

                if evicted_block and evicted_block in self._seen_block_ids:
                    self._seen_block_ids.discard(evicted_block)

                if evicted_pair and evicted_pair in self._sender_recipient_nonces:
                    self._sender_recipient_nonces[evicted_pair].discard(evicted_nonce)

                has_remaining_session = any(
                    meta.get("session_key") == evicted_session_key
                    for meta in self._store.values()
                )
                if not has_remaining_session and evicted_session_key in self._latest_sequence_numbers:
                    self._latest_sequence_numbers.pop(evicted_session_key, None)

            self._store[fp] = {
                "block_id": block_id,
                "pair_key": pair_key,
                "nonce": nonce,
                "session_key": session_key,
            }
            self._seen_block_ids.add(block_id)

            if pair_key not in self._sender_recipient_nonces:
                self._sender_recipient_nonces[pair_key] = set()
            self._sender_recipient_nonces[pair_key].add(nonce)

            current_highest = self._latest_sequence_numbers.get(session_key, -1)
            if sequence_number > current_highest:
                self._latest_sequence_numbers[session_key] = sequence_number

            return False, fp

    def __len__(self) -> int:
        with self._lock:
            return len(self._store)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._seen_block_ids.clear()
            self._sender_recipient_nonces.clear()
            self._latest_sequence_numbers.clear()


default_ledger = ReplayLedger()
