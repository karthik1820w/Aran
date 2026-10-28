"""Applying accepted suggestions to text. Nothing here runs unless a person accepted a suggestion."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .models import Flag, Suggestion


class EditError(ValueError):
    pass


@dataclass(frozen=True)
class Edit:
    start: int
    end: int
    replacement: str


def suggestion_to_edit(flag: Flag, suggestion: Suggestion) -> Optional[Edit]:
    """Translate a suggestion into a text edit, or None when it needs a human (manual, evidence request)."""
    start = flag.start if suggestion.start is None else suggestion.start
    end = flag.end if suggestion.end is None else suggestion.end
    if suggestion.action == "replace" and suggestion.text is not None:
        return Edit(start, end, suggestion.text)
    if suggestion.action == "delete":
        return Edit(start, end, "")
    return None


def apply_edits(text: str, edits: Sequence[Edit]) -> str:
    """Apply non-overlapping edits. Raises EditError for out-of-range or overlapping edits."""
    ordered: List[Edit] = sorted(edits, key=lambda e: (e.start, e.end))
    previous_end = 0
    for e in ordered:
        if not 0 <= e.start <= e.end <= len(text):
            raise EditError(f"edit range {e.start}..{e.end} is outside the text")
        if e.start < previous_end:
            raise EditError("edits overlap")
        previous_end = e.end
    out = text
    for e in reversed(ordered):
        start, end = e.start, e.end
        if e.replacement == "":
            # Deleting a phrase between two spaces would leave a double space; swallow one.
            if start > 0 and end < len(out) and out[start - 1] == " " and out[end] == " ":
                end += 1
            elif start > 0 and out[start - 1] == " " and (end >= len(out) or out[end] in ".,!?;:"):
                start -= 1
        out = out[:start] + e.replacement + out[end:]
    return out
