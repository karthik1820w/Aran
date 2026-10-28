"""Shared test helpers."""
import copy
import json
import os
import sys
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from brandguardian.engine import ReviewEngine  # noqa: E402
from brandguardian.knowledge import KnowledgeBase  # noqa: E402

TODAY = date(2026, 10, 26)
KB_PATH = os.path.join(ROOT, "data", "demo_brand.json")


def raw_kb():
    with open(KB_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_kb():
    return KnowledgeBase.from_dict(raw_kb())


def make_engine(max_chars=50_000):
    return ReviewEngine(load_kb(), max_chars=max_chars)


def mutated(fn):
    """Return a deep copy of the raw demo knowledge dict after applying *fn* to it."""
    data = copy.deepcopy(raw_kb())
    fn(data)
    return data
