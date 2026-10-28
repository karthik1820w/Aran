"""Tamper-evident audit chain and receipt signing (standard library only)."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Iterable, Optional, Tuple

from .util import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64
RECEIPT_ALGORITHM = "HMAC-SHA256"


def entry_hash(prev_hash: str, seq: int, ts: str, actor: str, action: str, payload_json: str) -> str:
    return sha256_hex(canonical_json([prev_hash, seq, ts, actor, action, payload_json]))


def verify_chain(entries: Iterable[Dict[str, Any]]) -> Tuple[bool, Optional[int]]:
    """Return (ok, first_bad_seq). Entries must be in sequence order starting at 1."""
    prev = GENESIS_HASH
    expected_seq = 1
    for e in entries:
        if e["seq"] != expected_seq or e["prev_hash"] != prev:
            return False, e["seq"]
        if entry_hash(e["prev_hash"], e["seq"], e["ts"], e["actor"], e["action"], e["payload"]) != e["hash"]:
            return False, e["seq"]
        prev = e["hash"]
        expected_seq += 1
    return True, None


def sign_body(body: Dict[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(body: Dict[str, Any], signature: str, key: str) -> bool:
    return hmac.compare_digest(sign_body(body, key), signature)
