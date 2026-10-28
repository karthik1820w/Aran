"""Voice detector: transparent, measurable tone dimensions (exact, no AI)."""
from __future__ import annotations

import re
from typing import Any, Dict, List

from ..models import Flag, Suggestion
from ..util import split_sentences, word_count
from .base import Context, DetectorOutput

# A "!" that opens Markdown image syntax (![alt](url)) is not an exclamation mark.
_EXCLAIM_RUN = re.compile(r"!+(?!\[)")
_CAPS_WORD = re.compile(r"\b[A-Z]{4,}\b")


def profile(text: str) -> Dict[str, Any]:
    """Measurable tone dimensions shown to the user instead of an opaque score."""
    sentences = split_sentences(text)
    counts = [word_count(text[s:e]) for s, e in sentences]
    return {
        "sentences": len(sentences),
        "avg_sentence_words": round(sum(counts) / len(counts), 1) if counts else 0.0,
        "longest_sentence_words": max(counts) if counts else 0,
        "exclamation_marks": sum(len(m.group(0)) for m in _EXCLAIM_RUN.finditer(text)),
        "caps_words": len(_CAPS_WORD.findall(text)),
        "words": word_count(text),
    }


def run(ctx: Context) -> DetectorOutput:
    out = DetectorOutput()
    kb, text, policy = ctx.kb, ctx.text, ctx.kb.voice

    # Exclamation marks: the first `max_exclamations` runs are allowed; repeated marks inside a run are not.
    rule = kb.rule(policy.exclamation_rule)
    used = 0
    for m in _EXCLAIM_RUN.finditer(text):
        run_len = m.end() - m.start()
        if used < policy.max_exclamations:
            used += 1
            if run_len > 1:
                out.flags.append(Flag(
                    detector="voice", issue_type="repeated_exclamation", rule_id=rule.id, start=m.start(), end=m.end(),
                    text=m.group(0), severity=rule.severity,
                    explanation="Repeated exclamation marks read as shouting. One is enough.",
                    evidence_quote=rule.text, source=kb.source_label(rule.id),
                    suggestions=(Suggestion(style="minimal", action="replace", text="!", note="Keep a single mark."),),
                ))
            continue
        out.flags.append(Flag(
            detector="voice", issue_type="too_many_exclamations", rule_id=rule.id, start=m.start(), end=m.end(),
            text=m.group(0), severity=rule.severity,
            explanation=f"This copy already uses its allowed {policy.max_exclamations} exclamation mark(s).",
            evidence_quote=rule.text, source=kb.source_label(rule.id),
            suggestions=(Suggestion(style="minimal", action="replace", text=".", note="End the sentence calmly."),),
        ))

    # ALL-CAPS words beyond the allowed number, excluding approved acronyms.
    caps_rule = kb.rule(policy.caps_rule)
    caps_seen = 0
    for m in _CAPS_WORD.finditer(text):
        if m.group(0) in policy.allowed_acronyms:
            continue
        caps_seen += 1
        if caps_seen > policy.max_caps_words:
            out.flags.append(Flag(
                detector="voice", issue_type="all_caps", rule_id=caps_rule.id, start=m.start(), end=m.end(),
                text=m.group(0), severity=caps_rule.severity,
                explanation=f'"{m.group(0)}" is written in capitals and is not an approved acronym.',
                evidence_quote=caps_rule.text, source=kb.source_label(caps_rule.id),
                suggestions=(Suggestion(style="minimal", action="replace", text=m.group(0).capitalize(),
                                        note="Sentence case."),),
            ))

    # Average sentence length.
    sentence_rule = kb.rule(policy.sentence_rule)
    spans = split_sentences(text)
    if spans:
        lengths: List[int] = [word_count(text[s:e]) for s, e in spans]
        avg = sum(lengths) / len(lengths)
        if avg > policy.max_avg_sentence_words:
            idx = max(range(len(lengths)), key=lambda i: lengths[i])
            s, e = spans[idx]
            out.flags.append(Flag(
                detector="voice", issue_type="long_sentences", rule_id=sentence_rule.id, start=s, end=e,
                text=text[s:e], severity=sentence_rule.severity,
                explanation=f"Average sentence length is {avg:.1f} words (limit {policy.max_avg_sentence_words}). "
                            f"This is the longest, at {lengths[idx]} words.",
                evidence_quote=sentence_rule.text, source=kb.source_label(sentence_rule.id),
                suggestions=(Suggestion(style="manual", action="manual", note="Split it into two sentences."),),
            ))
    return out
