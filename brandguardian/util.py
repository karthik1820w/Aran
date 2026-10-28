"""Small shared helpers (no third-party dependencies)."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, List, Tuple

_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def match_case(source: str, replacement: str) -> str:
    """Give *replacement* the capitalisation style of *source*."""
    if source.isupper() and len(source) > 1:
        return replacement.upper()
    if source[:1].isupper():
        return replacement[:1].upper() + replacement[1:]
    return replacement


def split_sentences(text: str) -> List[Tuple[int, int]]:
    """Return (start, end) offsets of sentences, ignoring blank segments."""
    spans: List[Tuple[int, int]] = []
    pos = 0
    for m in _SENTENCE_END.finditer(text):
        end = m.start()
        if text[pos:end].strip():
            spans.append((pos, end))
        pos = m.end()
    if text[pos:].strip():
        spans.append((pos, len(text.rstrip())))
    return spans


def word_count(fragment: str) -> int:
    return len(re.findall(r"\b[\w'’-]+\b", fragment))


def resolve_overlaps(items: list, key_start: str = "start", key_end: str = "end") -> list:
    """Keep the longest item among overlapping spans; return sorted by start."""
    ordered = sorted(items, key=lambda i: (getattr(i, key_start), -(getattr(i, key_end) - getattr(i, key_start))))
    kept: list = []
    for item in ordered:
        if kept and getattr(item, key_start) < getattr(kept[-1], key_end):
            continue
        kept.append(item)
    return kept
