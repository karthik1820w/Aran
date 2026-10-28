"""Plain data models shared by the engine, the workflow and the API."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("blocker", "warning", "info")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
CLAIM_VERDICTS = ("SUPPORTED", "CONTRADICTED", "EXPIRED", "UNSUPPORTED")


@dataclass(frozen=True)
class Suggestion:
    """A proposed correction. It never applies itself; a person accepts it."""

    style: str
    action: str  # replace | delete | request_evidence | manual
    text: Optional[str] = None
    start: Optional[int] = None
    end: Optional[int] = None
    uses: Tuple[str, ...] = ()
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "style": self.style,
            "action": self.action,
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "uses": list(self.uses),
            "note": self.note,
        }


@dataclass(frozen=True)
class Flag:
    """One explained, cited issue found in a draft."""

    detector: str
    issue_type: str
    rule_id: str
    start: int
    end: int
    text: str
    severity: str
    explanation: str
    evidence_quote: str
    source: str
    method: str = "rule"  # rule | ai
    confidence: float = 1.0
    verdict: Optional[str] = None
    ledger_id: Optional[str] = None
    suggestions: Tuple[Suggestion, ...] = ()

    @property
    def id(self) -> str:
        raw = f"{self.detector}|{self.issue_type}|{self.rule_id}|{self.start}|{self.end}|{self.text}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "detector": self.detector,
            "issue_type": self.issue_type,
            "rule_id": self.rule_id,
            "start": self.start,
            "end": self.end,
            "text": self.text,
            "severity": self.severity,
            "explanation": self.explanation,
            "evidence_quote": self.evidence_quote,
            "source": self.source,
            "method": self.method,
            "confidence": self.confidence,
            "verdict": self.verdict,
            "ledger_id": self.ledger_id,
            "suggestions": [s.to_dict() for s in self.suggestions],
        }

    def with_suggestions(self, suggestions: Tuple[Suggestion, ...]) -> "Flag":
        return replace(self, suggestions=suggestions)


@dataclass(frozen=True)
class ClaimResult:
    """The verdict for one checkable claim found in a draft."""

    text: str
    start: int
    end: int
    verdict: str
    rule_id: Optional[str]
    ledger_id: Optional[str]
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "start": self.start,
            "end": self.end,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "ledger_id": self.ledger_id,
            "detail": self.detail,
        }


@dataclass
class ReviewResult:
    content_hash: str
    kb_version: str
    kb_fingerprint: str
    engine_version: str
    flags: List[Flag] = field(default_factory=list)
    claims: List[ClaimResult] = field(default_factory=list)
    checks: List[Dict[str, Any]] = field(default_factory=list)
    profile: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    @property
    def counts(self) -> Dict[str, int]:
        out = {name: 0 for name in SEVERITIES}
        for f in self.flags:
            out[f.severity] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "kb_version": self.kb_version,
            "kb_fingerprint": self.kb_fingerprint,
            "engine_version": self.engine_version,
            "flags": [f.to_dict() for f in self.flags],
            "claims": [c.to_dict() for c in self.claims],
            "checks": self.checks,
            "profile": self.profile,
            "counts": self.counts,
            "elapsed_ms": round(self.elapsed_ms, 2),
        }
