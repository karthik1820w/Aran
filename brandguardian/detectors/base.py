"""Shared types for detectors, plus per-request time budget enforcement."""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Iterator, List

from ..knowledge import KnowledgeBase
from ..models import ClaimResult, Flag

MAX_MATCHES_PER_PATTERN = 500
# Default time budget for the entire detector pipeline per request (seconds).
_DEFAULT_BUDGET_SECS = 8.0
# Thread-local storage for the per-request deadline.
_tls = threading.local()


def set_budget(seconds: float = _DEFAULT_BUDGET_SECS) -> None:
    """Set a deadline for the current thread (called once per request, before detectors run)."""
    _tls.deadline = time.monotonic() + seconds


def budget_remaining() -> float:
    """Return seconds remaining in the current budget, or a large positive number if no budget set."""
    deadline = getattr(_tls, "deadline", None)
    if deadline is None:
        return _DEFAULT_BUDGET_SECS
    return max(0.0, deadline - time.monotonic())


def budget_exceeded() -> bool:
    """True if the per-request time budget has been exhausted."""
    deadline = getattr(_tls, "deadline", None)
    if deadline is None:
        return False
    return time.monotonic() >= deadline


@dataclass
class Context:
    text: str
    kb: KnowledgeBase
    today: date


@dataclass
class DetectorOutput:
    flags: List[Flag] = field(default_factory=list)
    claims: List[ClaimResult] = field(default_factory=list)


@dataclass(frozen=True)
class Detector:
    id: str
    name: str
    run: Callable[[Context], DetectorOutput]


def limited(iterator: Iterator, limit: int = MAX_MATCHES_PER_PATTERN) -> Iterator:
    """Yield at most *limit* items, and stop early if the time budget is exhausted."""
    for index, item in enumerate(iterator):
        if index >= limit or budget_exceeded():
            return
        yield item
