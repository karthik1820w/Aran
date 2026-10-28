"""Knowledge base: the organisation's own guidelines, glossary, claim rules and Claim Ledger.

Everything the product says about a draft must trace back to an entry loaded here. The loader
validates strictly so that a malformed or unsafe knowledge file fails loudly at start-up.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Pattern, Sequence, Tuple

from .models import SEVERITIES
from .util import canonical_json, sha256_hex

MAX_PATTERN_LENGTH = 200
# Heuristic guard against catastrophic backtracking: a quantified group that itself contains a quantifier.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


class KnowledgeError(ValueError):
    """Raised with every problem found in a knowledge file, not just the first."""

    def __init__(self, problems: Sequence[str]):
        super().__init__("; ".join(problems))
        self.problems = list(problems)


@dataclass(frozen=True)
class Rule:
    id: str
    clause: str
    title: str
    text: str
    severity: str = "warning"


@dataclass(frozen=True)
class GlossaryEntry:
    rule_id: str
    preferred: str
    avoid: Tuple[str, ...]
    case_sensitive: bool
    pattern: Pattern[str]


@dataclass(frozen=True)
class RestrictedPattern:
    rule_id: str
    pattern: Pattern[str]
    alternatives: Tuple[str, ...]


@dataclass(frozen=True)
class ClaimRule:
    id: str
    rule_id: str
    kind: str
    topic: str
    severity: str
    patterns: Tuple[Pattern[str], ...]


@dataclass(frozen=True)
class LedgerEntry:
    id: str
    statement: str
    source: str
    owner: str
    valid_from: date
    valid_until: date
    topics: Tuple[str, ...]
    matches: Tuple[Pattern[str], ...]
    extract: Optional[Pattern[str]] = None
    expected: Optional[str] = None
    rule_id: Optional[str] = None

    def is_valid_on(self, day: date) -> bool:
        return self.valid_from <= day <= self.valid_until


@dataclass(frozen=True)
class VoicePolicy:
    exclamation_rule: str
    caps_rule: str
    sentence_rule: str
    max_exclamations: int
    max_caps_words: int
    max_avg_sentence_words: int
    allowed_acronyms: Tuple[str, ...]


@dataclass(frozen=True)
class SimplePolicy:
    rule_id: str
    patterns: Tuple[Pattern[str], ...] = ()


@dataclass
class KnowledgeBase:
    brand: str
    guideline_name: str
    guideline_version: str
    rules: Dict[str, Rule]
    glossary: List[GlossaryEntry]
    restricted: List[RestrictedPattern]
    claim_rules: List[ClaimRule]
    ledger: Dict[str, LedgerEntry]
    voice: VoicePolicy
    pii_rule: str
    alt_text_rule: str
    link_text_rule: str
    injection: SimplePolicy
    fingerprint: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    # -- convenience -------------------------------------------------------------------------
    @property
    def version_label(self) -> str:
        return f"{self.guideline_name} v{self.guideline_version}"

    def rule(self, rule_id: str) -> Rule:
        return self.rules[rule_id]

    def source_label(self, rule_id: str) -> str:
        rule = self.rules[rule_id]
        return f"{self.version_label}, section {rule.clause}"

    def ledger_for_topic(self, topic: str, today: date) -> List[LedgerEntry]:
        return [e for e in self.ledger.values() if topic in e.topics and e.is_valid_on(today)]

    def public_summary(self) -> Dict[str, Any]:
        """What the UI may show: rules and ledger statements, never raw regexes."""
        return {
            "brand": self.brand,
            "guideline": self.version_label,
            "fingerprint": self.fingerprint,
            "rules": [
                {"id": r.id, "clause": r.clause, "title": r.title, "text": r.text, "severity": r.severity}
                for r in self.rules.values()
            ],
            "ledger": [
                {
                    "id": e.id,
                    "statement": e.statement,
                    "source": e.source,
                    "owner": e.owner,
                    "valid_from": e.valid_from.isoformat(),
                    "valid_until": e.valid_until.isoformat(),
                }
                for e in self.ledger.values()
            ],
        }

    # -- construction ------------------------------------------------------------------------
    @classmethod
    def from_file(cls, path: str | Path) -> "KnowledgeBase":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "KnowledgeBase":
        return _Builder(data).build()


class _Builder:
    def __init__(self, data: Mapping[str, Any]):
        self.data = data
        self.problems: List[str] = []

    # helpers
    def _need(self, mapping: Mapping[str, Any], key: str, where: str) -> Any:
        if key not in mapping or mapping[key] in (None, ""):
            self.problems.append(f"{where}: missing '{key}'")
            return None
        return mapping[key]

    def _regex(self, pattern: Any, where: str, flags: int = re.IGNORECASE) -> Optional[Pattern[str]]:
        if not isinstance(pattern, str) or not pattern:
            self.problems.append(f"{where}: pattern must be a non-empty string")
            return None
        if len(pattern) > MAX_PATTERN_LENGTH:
            self.problems.append(f"{where}: pattern longer than {MAX_PATTERN_LENGTH} characters")
            return None
        if _NESTED_QUANTIFIER.search(pattern):
            self.problems.append(f"{where}: pattern risks catastrophic backtracking: {pattern!r}")
            return None
        try:
            return re.compile(pattern, flags)
        except re.error as exc:
            self.problems.append(f"{where}: invalid regex {pattern!r} ({exc})")
            return None

    def _date(self, value: Any, where: str) -> Optional[date]:
        try:
            return date.fromisoformat(str(value))
        except ValueError:
            self.problems.append(f"{where}: invalid ISO date {value!r}")
            return None

    def _check_rule_ref(self, rule_id: Any, rules: Mapping[str, Rule], where: str) -> None:
        if rule_id not in rules:
            self.problems.append(f"{where}: unknown rule_id {rule_id!r}")

    # build
    def build(self) -> KnowledgeBase:
        d = self.data
        guideline = d.get("guideline") or {}
        brand = self._need(d, "brand", "root")
        g_name = self._need(guideline, "name", "guideline")
        g_version = self._need(guideline, "version", "guideline")

        rules: Dict[str, Rule] = {}
        for i, r in enumerate(d.get("rules") or []):
            where = f"rules[{i}]"
            rid = self._need(r, "id", where)
            clause = self._need(r, "clause", where)
            title = self._need(r, "title", where)
            text = self._need(r, "text", where)
            severity = r.get("severity", "warning")
            if severity not in SEVERITIES:
                self.problems.append(f"{where}: severity must be one of {SEVERITIES}")
            if rid in rules:
                self.problems.append(f"{where}: duplicate rule id {rid!r}")
            if rid and clause and title and text:
                rules[rid] = Rule(rid, str(clause), title, text, severity)
        if not rules:
            self.problems.append("rules: at least one rule is required")

        glossary: List[GlossaryEntry] = []
        for i, g in enumerate(d.get("glossary") or []):
            where = f"glossary[{i}]"
            rid = self._need(g, "rule_id", where)
            preferred = self._need(g, "preferred", where)
            avoid = g.get("avoid") or []
            if not avoid:
                self.problems.append(f"{where}: 'avoid' must list at least one term")
            self._check_rule_ref(rid, rules, where)
            case_sensitive = bool(g.get("case_sensitive", False))
            if avoid:
                joined = "|".join(re.escape(a) for a in sorted(avoid, key=len, reverse=True))
                compiled = self._regex(rf"(?<![\w]){'(?:' + joined + ')'}(?![\w])", where, 0 if case_sensitive else re.IGNORECASE)
                if compiled and preferred:
                    glossary.append(GlossaryEntry(rid, preferred, tuple(avoid), case_sensitive, compiled))

        restricted: List[RestrictedPattern] = []
        for i, entry in enumerate(d.get("restricted") or []):
            where = f"restricted[{i}]"
            rid = self._need(entry, "rule_id", where)
            self._check_rule_ref(rid, rules, where)
            for j, p in enumerate(entry.get("patterns") or []):
                compiled = self._regex(p.get("pattern"), f"{where}.patterns[{j}]")
                if compiled and rid:
                    restricted.append(RestrictedPattern(rid, compiled, tuple(p.get("alternatives") or ())))

        claim_rules: List[ClaimRule] = []
        seen_claim_ids = set()
        for i, c in enumerate(d.get("claim_rules") or []):
            where = f"claim_rules[{i}]"
            cid = self._need(c, "id", where)
            rid = self._need(c, "rule_id", where)
            self._check_rule_ref(rid, rules, where)
            if cid in seen_claim_ids:
                self.problems.append(f"{where}: duplicate claim rule id {cid!r}")
            seen_claim_ids.add(cid)
            severity = c.get("severity", "blocker")
            if severity not in SEVERITIES:
                self.problems.append(f"{where}: invalid severity {severity!r}")
            compiled_patterns = tuple(
                p for p in (self._regex(x, f"{where}.patterns") for x in (c.get("patterns") or [])) if p
            )
            if not compiled_patterns:
                self.problems.append(f"{where}: needs at least one valid pattern")
            if cid and rid:
                claim_rules.append(ClaimRule(cid, rid, c.get("kind", "claim"), c.get("topic", ""), severity, compiled_patterns))

        ledger: Dict[str, LedgerEntry] = {}
        for i, e in enumerate(d.get("ledger") or []):
            where = f"ledger[{i}]"
            lid = self._need(e, "id", where)
            statement = self._need(e, "statement", where)
            source = self._need(e, "source", where)
            owner = self._need(e, "owner", where)
            vf = self._date(e.get("valid_from"), where)
            vu = self._date(e.get("valid_until"), where)
            if vf and vu and vf > vu:
                self.problems.append(f"{where}: valid_from is after valid_until")
            if lid in ledger:
                self.problems.append(f"{where}: duplicate ledger id {lid!r}")
            matches = tuple(p for p in (self._regex(x, f"{where}.matches") for x in (e.get("matches") or [])) if p)
            extract = None
            expected = None
            if e.get("extract"):
                extract = self._regex(e["extract"], f"{where}.extract")
                if extract is not None and "value" not in extract.groupindex:
                    self.problems.append(f"{where}: extract pattern needs a named group 'value'")
                expected = e.get("expected")
                if expected in (None, ""):
                    self.problems.append(f"{where}: 'expected' is required when 'extract' is set")
            if not matches and extract is None:
                self.problems.append(f"{where}: needs 'matches' or 'extract'")
            rule_id = e.get("rule_id")
            if rule_id is not None:
                self._check_rule_ref(rule_id, rules, where)
            if extract is not None and not rule_id:
                self.problems.append(f"{where}: 'rule_id' is required when 'extract' is set (flags must cite a rule)")
            if lid and statement and source and owner and vf and vu:
                ledger[lid] = LedgerEntry(
                    lid, statement, source, owner, vf, vu, tuple(e.get("topics") or ()), matches,
                    extract, str(expected) if expected is not None else None, rule_id,
                )

        v = d.get("voice") or {}
        voice = VoicePolicy(
            exclamation_rule=v.get("exclamation_rule", ""),
            caps_rule=v.get("caps_rule", ""),
            sentence_rule=v.get("sentence_rule", ""),
            max_exclamations=int(v.get("max_exclamations", 1)),
            max_caps_words=int(v.get("max_caps_words", 0)),
            max_avg_sentence_words=int(v.get("max_avg_sentence_words", 24)),
            allowed_acronyms=tuple(v.get("allowed_acronyms") or ()),
        )
        for key in ("exclamation_rule", "caps_rule", "sentence_rule"):
            self._check_rule_ref(getattr(voice, key), rules, f"voice.{key}")

        pii_rule = d.get("pii_rule", "")
        alt_rule = d.get("alt_text_rule", "")
        link_rule = d.get("link_text_rule", "")
        for name, rid in (("pii_rule", pii_rule), ("alt_text_rule", alt_rule), ("link_text_rule", link_rule)):
            self._check_rule_ref(rid, rules, name)

        inj = d.get("injection") or {}
        self._check_rule_ref(inj.get("rule_id"), rules, "injection")
        inj_patterns = tuple(
            p for p in (self._regex(x, "injection.patterns") for x in (inj.get("patterns") or [])) if p
        )

        if self.problems:
            raise KnowledgeError(self.problems)
        return KnowledgeBase(
            brand=brand, guideline_name=g_name, guideline_version=str(g_version), rules=rules,
            glossary=glossary, restricted=restricted, claim_rules=claim_rules, ledger=ledger, voice=voice,
            pii_rule=pii_rule, alt_text_rule=alt_rule, link_text_rule=link_rule,
            injection=SimplePolicy(inj.get("rule_id", ""), inj_patterns),
            fingerprint=sha256_hex(canonical_json(d))[:16], raw=dict(d),
        )
