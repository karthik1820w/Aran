"""Honest feature registry: what is built, what is partial, what is planned. Served at /api/status."""
from __future__ import annotations

from typing import Any, Dict, List

FEATURES: List[Dict[str, str]] = [
    {"id": "knowledge", "name": "Knowledge Hub (guidelines, glossary, Claim Ledger)", "status": "partial",
     "note": "Loaded from a strictly validated JSON file. Guideline paste/upload and editing screens are planned."},
    {"id": "review_text", "name": "Review text against rules, with cited and explained flags", "status": "built",
     "note": "Terminology, restricted phrases, claims, voice, personal data, alt text, link text, hidden instructions. "
             "Regex time-budgeted against 50K-char adversarial input."},
    {"id": "claim_ledger", "name": "Claim Ledger verdicts (supported, contradicted, expired, unsupported)", "status": "built",
     "note": "Dates and values checked against approved entries; no verdict comes from model memory."},
    {"id": "verifier", "name": "Evidence-or-Abstain verifier", "status": "built",
     "note": "Every AI finding must quote a real rule and a real text span or it is rejected with a reason."},
    {"id": "trap", "name": "Hallucination Trap demo", "status": "built",
     "note": "A clearly labelled simulated unreliable model whose output is rejected by the verifier."},
    {"id": "suggestions", "name": "Suggestions that keep the creator's intent", "status": "partial",
     "note": "Exact suggestions come from approved sources. AI rewrites are checked for new numbers and names; the live model call is untested offline."},
    {"id": "workflow", "name": "Roles, versions, comments, approval states, diff", "status": "built",
     "note": "Server-enforced permissions, no self-approval, blockers need a fix or a written override. "
             "Approval is atomic (race-safe). Title editing supported."},
    {"id": "audit", "name": "Hash-chained audit log and signed approval receipts", "status": "built",
     "note": "HMAC-SHA256 signatures. Public-key signatures that third parties can verify are planned."},
    {"id": "insights", "name": "Insights and Guideline Health", "status": "built",
     "note": "Per-rule dispute rates flag unclear rules once enough decisions exist."},
    {"id": "privacy", "name": "Privacy X-ray and redaction before any model call", "status": "built",
     "note": "Personal data is masked locally; the exact payload sent is logged. Full log visible to admins only; others see their own entries."},
    {"id": "realtime", "name": "Real-time feedback", "status": "built",
     "note": "Detector results stream as they finish; the editor re-checks shortly after typing stops."},
    {"id": "contrast", "name": "WCAG colour-contrast checker", "status": "built", "note": "Exact formula, with a suggested passing colour."},
    {"id": "replay", "name": "Decision Replay (re-open the exact evidence behind any past flag)", "status": "built",
     "note": "GET /api/content/{id}/flags/{fid}/replay returns the stored rule text, model output, and text at check time."},
    {"id": "session", "name": "Server-side session expiry and logout", "status": "built",
     "note": "Sessions expire automatically (configurable TTL, default 8h). /api/logout invalidates the token immediately."},
    {"id": "formats", "name": "Review of DOCX, PDF and images", "status": "planned", "note": "Round 3 improvement 1."},
    {"id": "simulator", "name": "Guideline simulator and Living Approvals", "status": "planned", "note": "Round 3 improvement 2."},
    {"id": "integrations", "name": "Google Docs, Slack, SSO, local-model mode, public-key receipts", "status": "planned",
     "note": "Round 3 improvement 3."},
]

ROUND3: List[Dict[str, Any]] = [
    {"title": "Multi-format review and Accessibility Lens",
     "why": "Real content arrives as documents and designs, not just text.",
     "scope": "DOCX and PDF text extraction, OCR for images, palette distance and contrast checks on uploaded posters, colour-vision preview.",
     "done_when": "A poster with low-contrast text and an off-palette colour is flagged with exact ratios and the affected regions."},
    {"title": "Guideline simulator and Living Approvals",
     "why": "Guidelines change and facts expire; approvals should not silently go stale.",
     "scope": "Replay stored content against a draft rule change; re-check approved content when a ledger entry expires.",
     "done_when": "Editing one rule shows exact before/after flag counts on stored history; an expired fact marks affected approvals as needing revalidation."},
    {"title": "Integrations and confidential mode",
     "why": "Teams write in Docs and decide in Slack; sensitive teams cannot send text outside.",
     "scope": "Google Docs and Slack hooks, SSO, a local-model mode with zero external calls, Ed25519-signed receipts verifiable by third parties.",
     "done_when": "A Docs add-on submits a draft, Slack approves it, and a confidential workspace shows zero outbound calls in the Privacy X-ray."},
]


def status_payload(demo_mode: bool, ai: Dict[str, Any]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for f in FEATURES:
        counts[f["status"]] = counts.get(f["status"], 0) + 1
    return {"features": FEATURES, "counts": counts, "round3": ROUND3, "demo_mode": demo_mode, "ai": ai}
