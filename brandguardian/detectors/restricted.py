"""Restricted-phrase detector: words the guidelines never permit (exact, no AI)."""
from __future__ import annotations

from ..models import Flag, Suggestion
from ..util import match_case, resolve_overlaps
from .base import Context, DetectorOutput, limited


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb
    flags = []
    for entry in kb.restricted:
        rule = kb.rule(entry.rule_id)
        for m in limited(entry.pattern.finditer(ctx.text)):
            found = m.group(0)
            if entry.alternatives:
                suggestions = tuple(
                    Suggestion(style="alternative", action="replace", text=match_case(found, alt),
                               note="Softer wording that does not promise an outcome.")
                    for alt in entry.alternatives
                )
            else:
                suggestions = (Suggestion(style="manual", action="manual",
                                          note="Rephrase without promising an outcome."),)
            flags.append(Flag(
                detector="restricted", issue_type="restricted_phrase", rule_id=rule.id,
                start=m.start(), end=m.end(), text=found, severity=rule.severity,
                explanation=f'"{found}" promises an outcome and is not permitted in Nova copy.',
                evidence_quote=rule.text, source=kb.source_label(rule.id), suggestions=suggestions,
            ))
    out.flags = resolve_overlaps(flags)
    return out
