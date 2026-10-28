"""ReviewService: exact checks first, then the optional AI judge, always behind the verifier."""
from __future__ import annotations

from datetime import date
from typing import Any, Dict, Iterator, List, Optional

from .engine import ReviewEngine
from .judge import DataFlowLog, Judge, JudgeOutcome
from .llm import LLMProvider, UnreliableSimulator
from .models import SEVERITY_RANK, ReviewResult


class ReviewService:
    def __init__(self, engine: ReviewEngine, provider: Optional[LLMProvider] = None, simulator_allowed: bool = False,
                 log: Optional[DataFlowLog] = None):
        self.engine = engine
        self.provider = provider
        self.simulator_allowed = simulator_allowed
        self.log = log or DataFlowLog()
        self.judge = Judge(engine.kb, self.log)

    @property
    def ai_mode(self) -> Dict[str, Any]:
        if self.provider is None:
            return {"enabled": False, "provider": None, "model": None, "external": False}
        return {"enabled": True, "provider": self.provider.name, "model": self.provider.model,
                "external": self.provider.external}

    def _provider_for(self, use_ai: bool, simulate: bool) -> Optional[LLMProvider]:
        if simulate:
            if not self.simulator_allowed:
                raise PermissionError("the model simulator is only available in demo mode")
            return UnreliableSimulator()
        return self.provider if use_ai else None

    def _merge(self, result: ReviewResult, outcome: JudgeOutcome) -> ReviewResult:
        if outcome.flags:
            result.flags = sorted(result.flags + outcome.flags,
                                  key=lambda f: (f.start, SEVERITY_RANK[f.severity], f.detector))
        return result

    def iter_review(self, text: str, today: Optional[date] = None, use_ai: bool = True,
                    simulate: bool = False, user_id: Optional[str] = None) -> Iterator[Dict[str, Any]]:
        today = today or date.today()
        provider = self._provider_for(use_ai, simulate)  # fail fast on a forbidden simulator request
        result: Optional[ReviewResult] = None
        for event in self.engine.iter_review(text, today):
            if event["type"] == "done":
                result = event["result"]
            else:
                yield event
        assert result is not None
        outcome = self.judge.run(text, result.flags, provider, today, user_id=user_id)
        yield {"type": "ai", "ai": outcome.to_dict(), "flags": [f.to_dict() for f in outcome.flags]}
        self._merge(result, outcome)
        yield {"type": "done", "result": result, "ai": outcome.to_dict()}

    def review(self, text: str, today: Optional[date] = None, use_ai: bool = True,
               simulate: bool = False, user_id: Optional[str] = None) -> Dict[str, Any]:
        done: Dict[str, Any] = {}
        for event in self.iter_review(text, today, use_ai, simulate, user_id=user_id):
            if event["type"] == "done":
                done = event
        payload = done["result"].to_dict()
        payload["ai"] = done["ai"]
        return payload

    def dataflow(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        entries: List[Dict[str, Any]] = self.log.entries()
        if user_id is not None:
            entries = [e for e in entries if e.get("user_id") == user_id]
        return {"ai": self.ai_mode, "external_bytes_sent": self.log.external_bytes(),
                "entries": entries[-10:]}
