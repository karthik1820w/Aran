"""Approved-terminology detector (exact, no AI)."""
from __future__ import annotations

from ..models import Flag, Suggestion
from ..util import match_case
from .base import Context, DetectorOutput, limited


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb
    for entry in kb.glossary:
        rule = kb.rule(entry.rule_id)
        for m in limited(entry.pattern.finditer(ctx.text)):
            found = m.group(0)
            replacement = entry.preferred if entry.case_sensitive else match_case(found, entry.preferred)
            out.flags.append(Flag(
                detector="terminology", issue_type="wrong_term", rule_id=rule.id,
                start=m.start(), end=m.end(), text=found, severity=rule.severity,
                explanation=f'"{found}" is not the approved term. Use "{replacement}" instead.',
                evidence_quote=rule.text, source=kb.source_label(rule.id),
                suggestions=(Suggestion(style="minimal", action="replace", text=replacement,
                                        note="Direct swap to the approved term."),),
            ))
    return out
