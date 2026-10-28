"""Personal-data and credential detector, plus redaction used before any external call."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

from ..models import Flag, Suggestion
from ..util import resolve_overlaps
from .base import Context, DetectorOutput, limited


@dataclass(frozen=True)
class PiiHit:
    kind: str
    label: str
    start: int
    end: int
    text: str


_PATTERNS: List[Tuple[str, str, "re.Pattern[str]"]] = [
    ("card", "a payment card number", re.compile(r"(?<![\w-])(?:\d[ -]?){13,19}(?![\w-])")),
    ("api_key", "an API key or secret", re.compile(r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b")),
    ("email", "an email address", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("phone", "a phone number", re.compile(r"(?<![\w])(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?![\w])")),
    ("phone", "a phone number", re.compile(r"(?<![\w])\+\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{3,4}(?![\w])")),
    ("gov_id", "a 12-digit identification number", re.compile(r"(?<![\w])(?<!\d\s)\d{4}\s\d{4}\s\d{4}(?!\s?\d)(?![\w])")),
]


def luhn_valid(number: str) -> bool:
    """Luhn checksum, used to avoid flagging ordinary long numbers as cards."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def find_pii(text: str) -> List[PiiHit]:
    """Return non-overlapping PII hits; card matches must pass the Luhn check."""
    hits: List[PiiHit] = []
    for kind, label, pattern in _PATTERNS:
        for m in limited(pattern.finditer(text)):
            if kind == "card" and not luhn_valid(m.group(0)):
                continue
            hits.append(PiiHit(kind, label, m.start(), m.end(), m.group(0)))
    return resolve_overlaps(hits)


def redact(text: str) -> Tuple[str, Dict[str, str]]:
    """Replace PII with stable tokens like [EMAIL_1]. Returns (redacted_text, token -> original)."""
    hits = find_pii(text)
    mapping: Dict[str, str] = {}
    counters: Dict[str, int] = {}
    pieces: List[str] = []
    cursor = 0
    for hit in hits:
        counters[hit.kind] = counters.get(hit.kind, 0) + 1
        token = f"[{hit.kind.upper()}_{counters[hit.kind]}]"
        mapping[token] = hit.text
        pieces.append(text[cursor:hit.start])
        pieces.append(token)
        cursor = hit.end
    pieces.append(text[cursor:])
    return "".join(pieces), mapping


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb
    rule = kb.rule(kb.pii_rule)
    for hit in find_pii(ctx.text):
        out.flags.append(Flag(
            detector="pii", issue_type="personal_data", rule_id=rule.id, start=hit.start, end=hit.end,
            text=hit.text, severity=rule.severity,
            explanation=f"This looks like {hit.label}. Published copy must not contain it.",
            evidence_quote=rule.text, source=kb.source_label(rule.id),
            suggestions=(Suggestion(style="remove", action="delete", note="Remove it, or link to an official contact page."),),
        ))
    return out
