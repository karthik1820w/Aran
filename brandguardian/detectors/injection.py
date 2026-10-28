"""Detects wording that looks like instructions to an AI system or reviewer.

Such text is only ever treated as content. This detector makes the attempt visible; it does not
change how checks or approvals behave.
"""
from __future__ import annotations

from ..models import Flag, Suggestion
from ..util import resolve_overlaps
from .base import Context, DetectorOutput, limited


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb
    policy = kb.injection
    if not policy.patterns or not policy.rule_id:
        return out
    rule = kb.rule(policy.rule_id)
    flags = []
    for pattern in policy.patterns:
        for m in limited(pattern.finditer(ctx.text)):
            flags.append(Flag(
                detector="injection", issue_type="content_instruction", rule_id=rule.id, start=m.start(), end=m.end(),
                text=m.group(0), severity=rule.severity,
                explanation="This wording looks like an instruction to an AI system or reviewer. "
                            "It is treated as ordinary content and has no effect on checks or approvals.",
                evidence_quote=rule.text, source=kb.source_label(rule.id),
                suggestions=(Suggestion(style="remove", action="delete", note="Remove the instruction from the copy."),),
            ))
    out.flags = resolve_overlaps(flags)
    return out
