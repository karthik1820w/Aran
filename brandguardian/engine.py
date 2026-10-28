"""Review engine: runs every detector and assembles one explained, cited result."""
from __future__ import annotations

import time
from datetime import date
from typing import Any, Dict, Iterator, List, Optional

from . import ENGINE_VERSION
from .detectors import DETECTORS, Context
from .detectors.base import set_budget
from .detectors.voice import profile as voice_profile
from .knowledge import KnowledgeBase
from .models import SEVERITY_RANK, ClaimResult, Flag, ReviewResult
from .util import sha256_hex


class ReviewError(ValueError):
    """The input cannot be reviewed (wrong type or too large)."""


class ReviewEngine:
    def __init__(self, kb: KnowledgeBase, max_chars: int = 50_000):
        self.kb = kb
        self.max_chars = max_chars

    def _validate(self, text: Any) -> str:
        if not isinstance(text, str):
            raise ReviewError("text must be a string")
        if len(text) > self.max_chars:
            raise ReviewError(f"text is longer than the {self.max_chars} character limit")
        return text

    def iter_review(self, text: str, today: Optional[date] = None) -> Iterator[Dict[str, Any]]:
        """Yield one event per detector as it finishes, then a final 'done' event.

        Streaming lets the UI show the fast exact checks immediately instead of waiting for all of them.
        A per-request time budget is set before running any detector so that adversarial large inputs
        cannot freeze the server.
        """
        text = self._validate(text)
        ctx = Context(text=text, kb=self.kb, today=today or date.today())
        set_budget(8.0)  # 8-second wall-clock budget for the full detector pipeline
        started = time.perf_counter()
        flags: List[Flag] = []
        claims: List[ClaimResult] = []
        checks: List[Dict[str, Any]] = []
        seen_flag_ids = set()
        for detector in DETECTORS:
            t0 = time.perf_counter()
            output = detector.run(ctx)
            ms = (time.perf_counter() - t0) * 1000
            fresh = []
            for flag in output.flags:
                if flag.id not in seen_flag_ids:
                    seen_flag_ids.add(flag.id)
                    fresh.append(flag)
            flags.extend(fresh)
            claims.extend(output.claims)
            checks.append({"id": detector.id, "name": detector.name, "status": "ran",
                           "flags": len(fresh), "ms": round(ms, 2)})
            yield {"type": "detector", "id": detector.id, "name": detector.name, "ms": round(ms, 2),
                   "flags": [f.to_dict() for f in fresh], "claims": [c.to_dict() for c in output.claims]}
        flags.sort(key=lambda f: (f.start, SEVERITY_RANK[f.severity], f.detector))
        claims.sort(key=lambda c: c.start)
        result = ReviewResult(
            content_hash=sha256_hex(text), kb_version=self.kb.version_label, kb_fingerprint=self.kb.fingerprint,
            engine_version=ENGINE_VERSION, flags=flags, claims=claims, checks=checks,
            profile=voice_profile(text), elapsed_ms=(time.perf_counter() - started) * 1000,
        )
        yield {"type": "done", "result": result}

    def review(self, text: str, today: Optional[date] = None) -> ReviewResult:
        result: Optional[ReviewResult] = None
        for event in self.iter_review(text, today):
            if event["type"] == "done":
                result = event["result"]
        assert result is not None
        return result
