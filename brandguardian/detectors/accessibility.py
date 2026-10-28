"""Accessibility detector for Markdown and HTML content: alt text and link text (exact, no AI)."""
from __future__ import annotations

import re

from ..models import Flag, Suggestion
from .base import Context, DetectorOutput, limited

_MD_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<url>[^)\s]*)[^)]*\)")
_HTML_IMG = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_HTML_ALT = re.compile(r"\balt\s*=", re.IGNORECASE)
_CLICK_HERE = re.compile(r"\bclick\s+here\b", re.IGNORECASE)
_WEAK_ALT = re.compile(r"^(?:image|photo|picture|img|graphic|screenshot)?\s*\d*$|\.(?:png|jpe?g|gif|webp|svg)$", re.IGNORECASE)


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb = ctx.kb
    alt_rule = kb.rule(kb.alt_text_rule)
    link_rule = kb.rule(kb.link_text_rule)

    for m in limited(_MD_IMAGE.finditer(ctx.text)):
        alt = m.group("alt").strip()
        if not alt:
            out.flags.append(Flag(
                detector="accessibility", issue_type="missing_alt_text", rule_id=alt_rule.id, start=m.start(), end=m.end(),
                text=m.group(0), severity=alt_rule.severity,
                explanation="This image has no alternative text, so screen-reader users cannot tell what it shows.",
                evidence_quote=alt_rule.text, source=kb.source_label(alt_rule.id),
                suggestions=(Suggestion(style="manual", action="manual",
                                        note="Write a short description of what the image shows between the square brackets."),),
            ))
        elif _WEAK_ALT.search(alt):
            out.flags.append(Flag(
                detector="accessibility", issue_type="uninformative_alt_text", rule_id=alt_rule.id, start=m.start(), end=m.end(),
                text=m.group(0), severity="info",
                explanation=f'The alternative text "{alt}" does not describe the image.',
                evidence_quote=alt_rule.text, source=kb.source_label(alt_rule.id),
                suggestions=(Suggestion(style="manual", action="manual", note="Describe what the image shows."),),
            ))

    for m in limited(_HTML_IMG.finditer(ctx.text)):
        if not _HTML_ALT.search(m.group(0)):
            out.flags.append(Flag(
                detector="accessibility", issue_type="missing_alt_text", rule_id=alt_rule.id, start=m.start(), end=m.end(),
                text=m.group(0), severity=alt_rule.severity,
                explanation="This <img> element has no alt attribute. Use alt=\"\" only for purely decorative images.",
                evidence_quote=alt_rule.text, source=kb.source_label(alt_rule.id),
                suggestions=(Suggestion(style="manual", action="manual", note="Add an alt attribute that describes the image."),),
            ))

    for m in limited(_CLICK_HERE.finditer(ctx.text)):
        out.flags.append(Flag(
            detector="accessibility", issue_type="vague_link_text", rule_id=link_rule.id, start=m.start(), end=m.end(),
            text=m.group(0), severity=link_rule.severity,
            explanation='"Click here" tells people nothing about where the link goes.',
            evidence_quote=link_rule.text, source=kb.source_label(link_rule.id),
            suggestions=(Suggestion(style="manual", action="manual",
                                    note='Name the destination, for example "Order Nova Bar".'),),
        ))
    return out
