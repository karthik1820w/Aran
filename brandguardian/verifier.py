"""Evidence-or-Abstain verifier.

A finding from a language model becomes a Flag only if code can confirm, from the organisation's own
material, that its rule exists, its quote is verbatim, and its text span is really in the draft. Anything
else is rejected with a recorded reason. The model never gets to be the judge of its own citations.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .knowledge import KnowledgeBase
from .models import SEVERITY_RANK, SEVERITIES, Flag, Suggestion

MIN_QUOTE_CHARS = 12
MAX_SPAN_CHARS = 300
MAX_EXPLANATION_CHARS = 600
LOW_CONFIDENCE = 0.5

_WS = re.compile(r"\s+")
_NUMBER = re.compile(r"\d+(?:[.,]\d+)?")
_CAPITALISED = re.compile(r"\b[A-Z][a-z]{2,}\b")
_WORD = re.compile(r"[A-Za-z][A-Za-z'’-]*")


def normalise(text: str) -> str:
    """Whitespace- and case-insensitive form used only to compare quotes."""
    return _WS.sub(" ", text).strip().strip("\"'“”‘’").casefold()


def rewrite_is_safe(original: str, rewrite: str, context: str) -> Tuple[bool, str]:
    """A rewrite may not add numbers or proper names that appear nowhere in the draft or approved sources."""
    if not rewrite.strip():
        return False, "empty_rewrite"
    if len(rewrite) > 3 * len(original) + 80:
        return False, "rewrite_too_long"
    allowed_numbers = set(_NUMBER.findall(context))
    for number in _NUMBER.findall(rewrite):
        if number not in allowed_numbers:
            return False, "rewrite_adds_number"
    vocabulary = {w.casefold() for w in _WORD.findall(context)}
    for match in _CAPITALISED.finditer(rewrite):
        # Strict on purpose, including at the start of the rewrite: a capitalised word that appears in neither the draft
        # nor the approved sources could be an invented name. Rejecting a harmless rewrite only drops the optional
        # suggestion; the flag itself is kept.
        if match.group(0).casefold() not in vocabulary:
            return False, "rewrite_adds_name"
    return True, ""


@dataclass
class VerifierStats:
    accepted: int = 0
    rejected: int = 0
    reasons: Counter = field(default_factory=Counter)

    def to_dict(self) -> Dict[str, Any]:
        return {"accepted": self.accepted, "rejected": self.rejected, "reasons": dict(self.reasons)}


class Verifier:
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self._quotes: Dict[str, str] = {rid: normalise(r.text) for rid, r in kb.rules.items()}
        self._ledger_quotes: Dict[str, str] = {lid: normalise(e.statement) for lid, e in kb.ledger.items()}

    def verify(self, finding: Any, draft: str, existing: Sequence[Flag], today: date,
               stats: Optional[VerifierStats] = None) -> Tuple[Optional[Flag], str]:
        flag, reason = self._verify(finding, draft, existing, today)
        if stats is not None:
            if flag is None:
                stats.rejected += 1
                stats.reasons[reason] += 1
            else:
                stats.accepted += 1
                if reason:
                    stats.reasons[reason] += 1  # accepted with a note, e.g. rewrite_dropped
        return flag, reason

    def _verify(self, finding: Any, draft: str, existing: Sequence[Flag], today: date) -> Tuple[Optional[Flag], str]:
        if not isinstance(finding, Mapping):
            return None, "not_an_object"
        rule_id, span_text, quote = finding.get("rule_id"), finding.get("span_text"), finding.get("evidence_quote")
        explanation, issue_type = finding.get("explanation"), finding.get("issue_type")
        if not all(isinstance(v, str) and v.strip() for v in (rule_id, span_text, quote, explanation, issue_type)):
            return None, "missing_or_wrong_type_fields"
        if rule_id not in self.kb.rules:
            return None, "unknown_rule"
        if len(span_text) > MAX_SPAN_CHARS or len(explanation) > MAX_EXPLANATION_CHARS:
            return None, "field_too_long"

        nq = normalise(quote)
        if len(nq) < MIN_QUOTE_CHARS:
            return None, "quote_too_short"
        ledger_id = finding.get("ledger_id")
        source_text = self._quotes[rule_id]
        source_label = self.kb.source_label(rule_id)
        evidence = self.kb.rule(rule_id).text
        if isinstance(ledger_id, str) and ledger_id:
            if ledger_id not in self.kb.ledger:
                return None, "unknown_ledger_entry"
            if nq in self._ledger_quotes[ledger_id]:
                entry = self.kb.ledger[ledger_id]
                source_text, evidence = self._ledger_quotes[ledger_id], entry.statement
                source_label = f"Claim Ledger {entry.id}: {entry.source}"
        if nq not in source_text:
            return None, "quote_not_in_source"

        start = draft.find(span_text)
        if start < 0:
            return None, "span_not_in_draft"
        end = start + len(span_text)
        if any(f.start < end and start < f.end for f in existing):
            return None, "duplicate_of_existing_flag"

        confidence = finding.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            return None, "bad_confidence"

        claimed = finding.get("severity")
        if claimed not in SEVERITIES:
            return None, "bad_severity"
        # A model can lower severity but never raise it above what the rule itself allows.
        severity = SEVERITIES[max(SEVERITY_RANK[claimed], SEVERITY_RANK[self.kb.rule(rule_id).severity])]

        note = ""
        suggestions: Tuple[Suggestion, ...] = ()
        rewrite = finding.get("suggested_rewrite")
        if isinstance(rewrite, str) and rewrite.strip():
            context = draft + " " + " ".join(e.statement for e in self.kb.ledger.values()) + " " + \
                " ".join(r.text for r in self.kb.rules.values())
            safe, why = rewrite_is_safe(span_text, rewrite, context)
            if safe:
                suggestions = (Suggestion(style="ai_rewrite", action="replace", text=rewrite,
                                          note="AI-suggested. Checked: adds no new numbers or names."),)
            else:
                note = f"rewrite_dropped:{why}"

        if confidence < LOW_CONFIDENCE:
            issue_type, severity = "needs_human_review", "info"
            explanation = "Low confidence; a person should decide. " + explanation

        flag = Flag(
            detector="ai_judge", issue_type=issue_type.strip()[:60], rule_id=rule_id, start=start, end=end,
            text=span_text, severity=severity, explanation=explanation.strip(), evidence_quote=evidence,
            source=source_label, method="ai", confidence=round(float(confidence), 2),
            ledger_id=ledger_id if isinstance(ledger_id, str) and ledger_id in self.kb.ledger else None,
            suggestions=suggestions,
        )
        return flag, note
