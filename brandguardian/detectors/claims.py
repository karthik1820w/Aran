"""Claim detector: checks promotional and factual claims against the Claim Ledger.

Verdicts never come from model memory. A claim is SUPPORTED, CONTRADICTED or EXPIRED only against a
ledger entry. With no entry the verdict is UNSUPPORTED ("no approved source"), which is not the same
as saying the claim is false.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import List, Optional

from ..knowledge import ClaimRule, LedgerEntry
from ..models import ClaimResult, Flag, Suggestion
from ..util import resolve_overlaps
from .base import Context, DetectorOutput, limited


@dataclass(frozen=True)
class _Hit:
    start: int
    end: int
    text: str
    rule: ClaimRule


def _same_number(a: str, b: str) -> bool:
    try:
        return Decimal(a) == Decimal(b)
    except InvalidOperation:
        return a.strip().lower() == b.strip().lower()


def _supporting_entries(ctx: Context, phrase: str) -> List[LedgerEntry]:
    return [e for e in ctx.kb.ledger.values() if any(p.search(phrase) for p in e.matches)]


def _unsupported_suggestions(ctx: Context, hit: _Hit) -> tuple:
    """Order matters: the first applicable suggestion is the one-click default, so it must never produce garbled copy.
    Removing an unsupported claim is always safe; swapping in an approved statement may not read well in context."""
    kb = ctx.kb
    suggestions: List[Suggestion] = [Suggestion(style="remove", action="delete", note="Remove the claim.")]
    for entry in kb.ledger_for_topic(hit.rule.topic, ctx.today):
        suggestions.append(Suggestion(
            style="approved_claim", action="replace", text=entry.statement, uses=(entry.id,),
            note="An approved statement on the same topic. Check the sentence still reads well.",
        ))
    suggestions.append(Suggestion(
        style="request_evidence", action="request_evidence",
        note="Ask product or legal to add an approved, dated source to the Claim Ledger.",
    ))
    return tuple(suggestions)


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb

    # (a) claims found by claim rules (rankings, health and time-bound statements)
    found: List[_Hit] = []
    for rule in kb.claim_rules:
        for pattern in rule.patterns:
            for m in limited(pattern.finditer(ctx.text)):
                found.append(_Hit(m.start(), m.end(), m.group(0), rule))
    for hit in resolve_overlaps(found):
        rule = kb.rule(hit.rule.rule_id)
        entries = _supporting_entries(ctx, hit.text)
        valid = [e for e in entries if e.is_valid_on(ctx.today)]
        if valid:
            entry = valid[0]
            out.claims.append(ClaimResult(hit.text, hit.start, hit.end, "SUPPORTED", rule.id, entry.id,
                                          f"Supported by {entry.id} ({entry.source})."))
            continue
        if entries:
            entry = max(entries, key=lambda e: e.valid_until)
            detail = f"Matches {entry.id} but its approval expired on {entry.valid_until.isoformat()}."
            out.claims.append(ClaimResult(hit.text, hit.start, hit.end, "EXPIRED", rule.id, entry.id, detail))
            out.flags.append(Flag(
                detector="claims", issue_type="expired_claim", rule_id=rule.id, start=hit.start, end=hit.end,
                text=hit.text, severity="blocker", verdict="EXPIRED", ledger_id=entry.id,
                explanation=f'"{hit.text}" relies on {entry.id} ("{entry.statement}"), but that approval expired on '
                            f"{entry.valid_until.isoformat()}. Owner: {entry.owner}.",
                evidence_quote=entry.statement, source=f"Claim Ledger {entry.id}: {entry.source}",
                suggestions=(
                    Suggestion(style="request_evidence", action="request_evidence", uses=(entry.id,),
                               note=f"Ask {entry.owner} to renew {entry.id} or confirm it is no longer valid."),
                    Suggestion(style="remove", action="delete", note="Remove the claim until it is renewed."),
                ),
            ))
            continue
        out.claims.append(ClaimResult(hit.text, hit.start, hit.end, "UNSUPPORTED", rule.id, None,
                                      "No approved source in the Claim Ledger."))
        out.flags.append(Flag(
            detector="claims", issue_type="unsupported_claim", rule_id=rule.id, start=hit.start, end=hit.end,
            text=hit.text, severity=hit.rule.severity, verdict="UNSUPPORTED",
            explanation=f'"{hit.text}" is a {hit.rule.kind} claim with no approved source in the Claim Ledger. '
                        "That does not mean it is false; it means nobody has recorded evidence for it.",
            evidence_quote=rule.text, source=kb.source_label(rule.id),
            suggestions=_unsupported_suggestions(ctx, hit),
        ))

    # (b) numeric facts extracted by ledger entries (for example nutrition values)
    for entry in kb.ledger.values():
        if entry.extract is None or entry.expected is None:
            continue
        rule_id = entry.rule_id or ""
        for m in limited(entry.extract.finditer(ctx.text)):
            value = m.group("value")
            vs, ve = m.span("value")
            if _same_number(value, entry.expected):
                if entry.is_valid_on(ctx.today):
                    out.claims.append(ClaimResult(m.group(0), m.start(), m.end(), "SUPPORTED", rule_id, entry.id,
                                                  f"Matches {entry.id} ({entry.source})."))
                else:
                    out.claims.append(ClaimResult(m.group(0), m.start(), m.end(), "EXPIRED", rule_id, entry.id,
                                                  f"Matches {entry.id} but its approval expired on {entry.valid_until.isoformat()}."))
                    out.flags.append(Flag(
                        detector="claims", issue_type="expired_claim", rule_id=rule_id, start=m.start(), end=m.end(),
                        text=m.group(0), severity="blocker", verdict="EXPIRED", ledger_id=entry.id,
                        explanation=f"{entry.id} expired on {entry.valid_until.isoformat()}. Owner: {entry.owner}.",
                        evidence_quote=entry.statement, source=f"Claim Ledger {entry.id}: {entry.source}",
                        suggestions=(Suggestion(style="request_evidence", action="request_evidence", uses=(entry.id,),
                                                note=f"Ask {entry.owner} to renew {entry.id}."),),
                    ))
                continue
            out.claims.append(ClaimResult(m.group(0), m.start(), m.end(), "CONTRADICTED", rule_id, entry.id,
                                          f"Draft says {value}; approved value is {entry.expected}."))
            out.flags.append(Flag(
                detector="claims", issue_type="contradicted_fact", rule_id=rule_id, start=m.start(), end=m.end(),
                text=m.group(0), severity="blocker", verdict="CONTRADICTED", ledger_id=entry.id,
                explanation=f'The draft says {value}, but the approved value is {entry.expected} '
                            f'("{entry.statement}", source: {entry.source}).',
                evidence_quote=entry.statement, source=f"Claim Ledger {entry.id}: {entry.source}",
                suggestions=(Suggestion(style="approved_value", action="replace", text=entry.expected,
                                        start=vs, end=ve, uses=(entry.id,),
                                        note="Replaces only the number with the approved value."),),
            ))
    out.claims.sort(key=lambda c: c.start)
    return out
