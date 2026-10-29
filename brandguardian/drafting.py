"""Claim-bound drafting and verification.

Ensures that generative models draft only from approved Claim Ledger facts,
every sentence links to a ledger entry via `[fact:ID]`, and the verifier
strictly rejects anything unlinked, expired, or hallucinated.
"""
from __future__ import annotations

import json
import re
from datetime import date
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .knowledge import KnowledgeBase, LedgerEntry
from .llm import LLMProvider

FACT_TAG_REGEX = re.compile(r"\[fact:([A-Za-z0-9_.-]+)\]")
SENTENCE_SPLIT_REGEX = re.compile(r"(?<=[.!?])\s+")
NUMBER_REGEX = re.compile(r"\b\d+(?:[.,]\d+)?%?\b")


def strip_fact_tags(text: str) -> str:
    """Return publication-ready text with [fact:...] citations cleanly removed."""
    cleaned = FACT_TAG_REGEX.sub("", text)
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    cleaned = re.sub(r"\s+([.,!?;:])", r"\1", cleaned)
    return cleaned.strip()


class ClaimBoundVerifier:
    """Verifies that every sentence in a draft links to an approved, active Claim Ledger entry."""

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb

    def verify(self, text: str, today: Optional[date] = None) -> Dict[str, Any]:
        today = today or date.today()
        trimmed = text.strip()
        if not trimmed:
            return {
                "verified": False,
                "coverage": 0.0,
                "total_sentences": 0,
                "verified_sentences": 0,
                "rejected_sentences": 0,
                "sentences": [],
                "clean_text": "",
                "message": "Draft is empty.",
            }

        raw_sentences = [s.strip() for s in SENTENCE_SPLIT_REGEX.split(trimmed) if s.strip()]
        sentence_reports: List[Dict[str, Any]] = []
        verified_count = 0

        for raw_s in raw_sentences:
            citations = FACT_TAG_REGEX.findall(raw_s)
            s_clean = strip_fact_tags(raw_s)

            if not citations:
                sentence_reports.append({
                    "sentence": raw_s,
                    "clean_sentence": s_clean,
                    "status": "rejected",
                    "reason": "unlinked_claim",
                    "message": "Sentence has no link to an approved Claim Ledger entry.",
                    "fact": None,
                })
                continue

            # Verify each cited fact
            fact_ok = True
            fact_info: Optional[Dict[str, Any]] = None
            for fid in citations:
                entry = self.kb.ledger.get(fid)
                if entry is None:
                    sentence_reports.append({
                        "sentence": raw_s,
                        "clean_sentence": s_clean,
                        "status": "rejected",
                        "reason": "unknown_fact",
                        "message": f"Cites non-existent Claim Ledger entry '{fid}'.",
                        "fact": None,
                    })
                    fact_ok = False
                    break

                if not entry.is_valid_on(today):
                    sentence_reports.append({
                        "sentence": raw_s,
                        "clean_sentence": s_clean,
                        "status": "rejected",
                        "reason": "expired_fact",
                        "message": f"Ledger entry '{fid}' expired on {entry.valid_until}.",
                        "fact": {"id": entry.id, "statement": entry.statement, "valid_until": str(entry.valid_until)},
                    })
                    fact_ok = False
                    break

                # Grounding check: verify that numbers in the sentence exist in the cited fact
                sentence_numbers = set(NUMBER_REGEX.findall(s_clean))
                fact_numbers = set(NUMBER_REGEX.findall(entry.statement))
                invented = sentence_numbers - fact_numbers
                if invented:
                    sentence_reports.append({
                        "sentence": raw_s,
                        "clean_sentence": s_clean,
                        "status": "rejected",
                        "reason": "invented_fact_data",
                        "message": f"Sentence introduces numbers {sorted(invented)} not found in ledger entry '{fid}'.",
                        "fact": {"id": entry.id, "statement": entry.statement},
                    })
                    fact_ok = False
                    break

                fact_info = {
                    "id": entry.id,
                    "statement": entry.statement,
                    "source": entry.source,
                    "owner": entry.owner,
                }

            if fact_ok and fact_info:
                verified_count += 1
                sentence_reports.append({
                    "sentence": raw_s,
                    "clean_sentence": s_clean,
                    "status": "verified",
                    "reason": "ok",
                    "message": f"Verified against {fact_info['id']} ({fact_info['source']}).",
                    "fact": fact_info,
                })

        total = len(sentence_reports)
        rejected = total - verified_count
        coverage = round(verified_count / total, 2) if total > 0 else 0.0
        all_verified = (rejected == 0 and total > 0)

        return {
            "verified": all_verified,
            "coverage": coverage,
            "total_sentences": total,
            "verified_sentences": verified_count,
            "rejected_sentences": rejected,
            "sentences": sentence_reports,
            "clean_text": strip_fact_tags(trimmed),
            "message": "All sentences verified against approved Claim Ledger facts." if all_verified else f"{rejected} sentence(s) rejected by verifier.",
        }


class ClaimBoundDrafter:
    """Generates content strictly bound to Claim Ledger entries, followed by verifier validation."""

    def __init__(self, kb: KnowledgeBase, provider: Optional[LLMProvider] = None):
        self.kb = kb
        self.provider = provider
        self.verifier = ClaimBoundVerifier(kb)

    def draft(self, topic: str, fact_ids: Optional[Sequence[str]] = None, today: Optional[date] = None) -> Dict[str, Any]:
        today = today or date.today()
        # 1. Select facts
        selected_entries: List[LedgerEntry] = []
        if fact_ids:
            for fid in fact_ids:
                e = self.kb.ledger.get(fid)
                if e and e.is_valid_on(today):
                    selected_entries.append(e)
        else:
            topic_lower = topic.lower()
            for e in self.kb.ledger.values():
                if e.is_valid_on(today):
                    if any(t.lower() in topic_lower or topic_lower in t.lower() for t in e.topics):
                        selected_entries.append(e)
                    elif any(w.lower() in e.statement.lower() for w in topic_lower.split()):
                        selected_entries.append(e)

        if not selected_entries:
            # Fall back to any active facts
            selected_entries = [e for e in self.kb.ledger.values() if e.is_valid_on(today)][:3]

        if not selected_entries:
            return {
                "text": "",
                "clean_text": "",
                "verified": False,
                "verification": {"verified": False, "message": "No active Claim Ledger entries found."},
            }

        facts_summary = "\n".join(
            f"- [fact:{e.id}] Statement: {e.statement} (Source: {e.source})"
            for e in selected_entries
        )

        raw_draft: str = ""
        # 2. Generate with model if available
        if self.provider is not None:
            system = (
                "You are an AI brand copywriter operating under strict Claim-Bound rules.\n"
                "Rules:\n"
                "1. Draft a short post about the topic using ONLY facts from the provided Ledger.\n"
                "2. Every single sentence MUST end with its source tag [fact:ID].\n"
                "3. Never introduce new numbers, dates, claims or assertions not present in the facts.\n"
                "4. Unlinked sentences will be rejected by the verifier."
            )
            user = (
                f"Topic: {topic}\n\n"
                f"Approved Ledger Facts:\n{facts_summary}\n\n"
                "Write the post now with every sentence cited."
            )
            try:
                raw_draft = self.provider.complete(system, user, max_tokens=500)
            except Exception:
                raw_draft = ""

        # 3. Deterministic claim-bound synthesis fallback (offline / tests)
        if not raw_draft or not FACT_TAG_REGEX.search(raw_draft):
            sentences = []
            for e in selected_entries:
                stmt = e.statement.rstrip(".")
                sentences.append(f"{stmt} [fact:{e.id}].")
            raw_draft = " ".join(sentences)

        # 4. Verify with ClaimBoundVerifier
        verification = self.verifier.verify(raw_draft, today=today)
        return {
            "topic": topic,
            "text": raw_draft,
            "clean_text": verification["clean_text"],
            "verified": verification["verified"],
            "verification": verification,
            "facts_used": [e.id for e in selected_entries],
        }

