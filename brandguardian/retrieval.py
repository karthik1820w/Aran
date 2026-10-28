"""Small lexical retriever (BM25) over the organisation's rules. Standard library only."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Sequence, Tuple

from .knowledge import KnowledgeBase, Rule

_TOKEN = re.compile(r"[a-z0-9]+")
_STOP = frozenset("a an and are as at be by for from in is it of on or that the this to with your our we you".split())


def tokenize(text: str) -> List[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


class RuleRetriever:
    def __init__(self, kb: KnowledgeBase, k1: float = 1.5, b: float = 0.75):
        self._rules: List[Rule] = list(kb.rules.values())
        self._docs: List[Counter] = [Counter(tokenize(f"{r.title} {r.text}")) for r in self._rules]
        self._lengths = [sum(d.values()) for d in self._docs]
        self._avg = (sum(self._lengths) / len(self._lengths)) if self._lengths else 1.0
        n = len(self._docs)
        df: Counter = Counter()
        for doc in self._docs:
            df.update(doc.keys())
        self._idf: Dict[str, float] = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}
        self._k1, self._b = k1, b

    def top_k(self, query: str, k: int = 6) -> List[Tuple[Rule, float]]:
        terms = tokenize(query)
        scored: List[Tuple[Rule, float]] = []
        for rule, doc, length in zip(self._rules, self._docs, self._lengths):
            score = 0.0
            for term in set(terms):
                freq = doc.get(term, 0)
                if not freq:
                    continue
                denom = freq + self._k1 * (1 - self._b + self._b * length / self._avg)
                score += self._idf.get(term, 0.0) * freq * (self._k1 + 1) / denom
            if score > 0:
                scored.append((rule, score))
        scored.sort(key=lambda pair: (-pair[1], pair[0].id))
        return scored[:k]


def rules_for_draft(retriever: RuleRetriever, kb: KnowledgeBase, text: str, k: int = 6) -> List[Rule]:
    """Pick the rules most relevant to the draft; fall back to all rules when nothing matches."""
    hits = retriever.top_k(text, k)
    return [r for r, _ in hits] if hits else list(kb.rules.values())[:k]


__all__ = ["RuleRetriever", "rules_for_draft", "tokenize", "Sequence"]
