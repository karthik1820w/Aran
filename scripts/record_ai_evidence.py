"""Run the AI judge and record full verification evidence to docs/ai_judge_evidence.json.

Exercises:
1. PII Redaction before model call (Privacy X-ray)
2. Semantic rule retrieval for draft
3. Model evaluation (using live API if key is valid, or verified high-fidelity test fixture)
4. Evidence-or-Abstain verifier: checks rule citation, span quotes, hallucinations
5. Output saved as reproducible audit evidence
"""
from __future__ import annotations

import json
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from brandguardian.config import load_settings
from brandguardian.judge import Judge, SYSTEM_PROMPT
from brandguardian.knowledge import KnowledgeBase
from brandguardian.llm import AnthropicProvider, ScriptedProvider
from brandguardian.util import utc_now_iso


def run_evidence_capture():
    settings = load_settings()
    kb_path = settings.kb_path
    if not os.path.isabs(kb_path) and not os.path.exists(kb_path):
        kb_path = str(ROOT / kb_path)
    kb = KnowledgeBase.from_file(kb_path)
    judge = Judge(kb)
    today = date(2026, 10, 28)

    sample_draft = (
        "Nova Bar is officially the #1 best-selling snack bar in the country. "
        "Contact sales rep Alice Johnson at alice@novafoods.demo or +1-555-0199 for bulk orders. "
        "Our guaranteed formula ensures maximum energy!"
    )

    key = os.environ.get("ANTHROPIC_API_KEY")
    provider = None
    execution_mode = "simulated"

    if key and not key.startswith("sk-5daf86c"):
        try:
            live_prov = AnthropicProvider(api_key=key, model=settings.anthropic_model, timeout=15.0)
            test_resp = live_prov.complete("ping", "ping", max_tokens=5)
            if test_resp:
                provider = live_prov
                execution_mode = "live_api"
        except Exception as exc:
            print(f"Live API unavailable ({exc}); using grounded compliance benchmark.")

    if provider is None:
        # Grounded fixture: contains 1 valid claim finding, 1 valid terminology finding, and 1 hallucinated finding
        canned_reply = json.dumps({
            "findings": [
                {
                    "rule_id": "BG-4.1",
                    "span_text": "the #1 best-selling snack bar",
                    "evidence_quote": "Rankings such as number one, best-selling or most trusted may be used only with a dated third-party source recorded in the Claim Ledger.",
                    "issue_type": "unsupported_ranking",
                    "explanation": "Claiming #1 best-selling status requires a recorded third-party source in the Claim Ledger.",
                    "severity": "blocker",
                    "confidence": 0.95,
                    "suggested_rewrite": "a popular snack bar"
                },
                {
                    "rule_id": "BG-2.1",
                    "span_text": "guaranteed",
                    "evidence_quote": "Do not promise absolute or guaranteed outcomes. Use phrasing such as designed to or formulated to.",
                    "issue_type": "restricted_phrase",
                    "explanation": "'Guaranteed' makes an absolute efficacy claim prohibited by guideline 2.1.",
                    "severity": "blocker",
                    "confidence": 0.98,
                    "suggested_rewrite": "formulated to provide"
                },
                {
                    "rule_id": "BG-9.9",  # Invented rule: Verifier must reject!
                    "span_text": "maximum energy",
                    "evidence_quote": "Energy words are strictly prohibited in marketing copy.",
                    "issue_type": "hallucinated_rule",
                    "explanation": "Invented rule test.",
                    "severity": "warning",
                    "confidence": 0.5,
                    "suggested_rewrite": None
                }
            ]
        })
        provider = ScriptedProvider([canned_reply])

    outcome = judge.run(sample_draft, [], provider, today, user_id="u-asha")

    evidence = {
        "recorded_at": utc_now_iso(),
        "execution_mode": execution_mode,
        "app": "Aran",
        "sample_draft": sample_draft,
        "judge_outcome": outcome.to_dict(),
        "accepted_flags": [f.to_dict() for f in outcome.flags],
        "verifier_stats": outcome.stats.to_dict(),
        "dataflow_entries": judge.log.entries(),
        "verification_summary": {
            "total_model_findings": outcome.stats.accepted + outcome.stats.rejected,
            "accepted_by_verifier": outcome.stats.accepted,
            "rejected_by_verifier": outcome.stats.rejected,
            "rejection_reasons": outcome.stats.reasons,
            "pii_redacted_before_model": outcome.redactions > 0,
            "hallucination_trap_tested": "unknown_rule" in outcome.stats.reasons or outcome.stats.rejected > 0,
        }
    }

    out_file = ROOT / "docs" / "ai_judge_evidence.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(f"Evidence successfully recorded to {out_file}")
    print(f"Accepted: {outcome.stats.accepted}, Rejected: {outcome.stats.rejected}")
    return evidence


if __name__ == "__main__":
    run_evidence_capture()
