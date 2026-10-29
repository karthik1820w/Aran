"""Tamper-evident audit chain, public-key receipt signing (Ed25519) and external anchor proofs."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any, Dict, Iterable, Optional, Tuple

from .util import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64
RECEIPT_ALGORITHM = "Ed25519"
LEGACY_ALGORITHM = "HMAC-SHA256"

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAS_ED25519 = True
except ImportError:
    _HAS_ED25519 = False


def generate_key_pair() -> Tuple[str, str]:
    """Generate (private_key_hex, public_key_hex). Falls back to symmetric secret if cryptography is unavailable."""
    if _HAS_ED25519:
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_hex = priv.private_bytes_raw().hex()
        pub_hex = priv.public_key().public_bytes_raw().hex()
        return priv_hex, pub_hex
    sec = secrets.token_hex(32)
    return sec, sec


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


def sign_body(body: Dict[str, Any], key: str, algorithm: Optional[str] = None) -> str:
    """Sign a receipt body using Ed25519 or HMAC-SHA256."""
    algo = algorithm or body.get("algorithm", RECEIPT_ALGORITHM)
    payload = canonical_json(body).encode("utf-8")
    if algo == "Ed25519" and _HAS_ED25519:
        try:
            priv_bytes = bytes.fromhex(key)
            if len(priv_bytes) >= 32:
                priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes[:32])
                return priv.sign(payload).hex()
        except Exception:
            pass  # Fall back to HMAC if key format was non-Ed25519
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_signature(body: Dict[str, Any], signature: str, key: str) -> bool:
    """Verify signature using Ed25519 public key or HMAC secret."""
    algo = body.get("algorithm", RECEIPT_ALGORITHM)
    payload = canonical_json(body).encode("utf-8")
    if algo == "Ed25519" and _HAS_ED25519:
        try:
            sig_bytes = bytes.fromhex(signature)
            # Try public key from body or argument
            pub_hex = body.get("public_key") or key
            pub_bytes = bytes.fromhex(pub_hex)
            if len(pub_bytes) == 64:  # If caller passed private key, extract public
                pub = ed25519.Ed25519PrivateKey.from_private_bytes(pub_bytes[:32]).public_key()
            else:
                pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes[:32])
            pub.verify(sig_bytes, payload)
            return True
        except Exception:
            pass
    # HMAC fallback
    expected = sign_body(body, key, algorithm="HMAC-SHA256")
    return hmac.compare_digest(expected, signature)


def verify_public_signature(body: Dict[str, Any], signature: str, public_key_hex: str) -> bool:
    """Third-party verification function: requires ONLY the public key."""
    payload = canonical_json(body).encode("utf-8")
    if _HAS_ED25519:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            pub.verify(bytes.fromhex(signature), payload)
            return True
        except Exception:
            return False
    return False


def create_anchor_proof(seq: int, head_hash: str, ts: str, signing_key: str) -> Dict[str, Any]:
    """Create a signed external anchor proof for the audit chain's head hash."""
    anchor_id = sha256_hex(f"{seq}:{head_hash}:{ts}")[:16]
    proof = {
        "anchor_id": anchor_id,
        "seq": seq,
        "head_hash": head_hash,
        "anchored_at": ts,
        "witness": "external-audit-anchor-service",
        "algorithm": RECEIPT_ALGORITHM if _HAS_ED25519 else LEGACY_ALGORITHM,
    }
    proof["witness_signature"] = sign_body(proof, signing_key)
    return proof
