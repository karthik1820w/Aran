# Roadmap: 40-hour build plan, status, and what Round 3 adds

Each level shipped something demonstrable with its own tests. The product stayed runnable after every level.
Never cut: the verifier, the human approval gate, AI disclosure.

| Level | Hours | Deliverable | Verified by | Status |
|---|---|---|---|---|
| 0 Foundation | 0-2 | Config, knowledge-base schema with strict validation, demo brand | `test_knowledge.py`, `test_gaps.py` | Built |
| 1 Core review engine (first single feature) | 2-8 | Review text against the organisation's own rules; cited, explained flags; Claim Ledger verdicts | `test_detectors.py`, `test_engine.py` | Built |
| 2 Trust layer | 8-14 | LLM provider interface, retrieval, judge, Evidence-or-Abstain verifier, Hallucination Trap | `test_trust_layer.py` | Built. Live Claude call not exercised (no network in the build environment) |
| 3 Workflow | 14-22 | SQLite store, roles, versions, comments, approvals, hash-chained audit, signed receipts | `test_workflow.py` | Built |
| 4 API, real time, security | 22-28 | HTTP API, streamed results, RBAC, rate limiting, body limits, security headers | `test_api.py`, `test_cli.py` | Built |
| 5 Web UI | 28-34 | Zero-guidance single-page app | `tests/js/logic.test.mjs`, `tests/e2e/journey.cjs` | Built and tested in headless Chromium |
| 6 Insights and hardening | 34-40 | Guideline Health, contrast checker, coverage, benchmark, docs | `test_contrast.py`, `scripts/` | Built |

## Prototype criteria and where each is met

| Criterion (points) | Where |
|---|---|
| Working core workflow (30) | One continuous journey (sign in, load sample, live flags, accept fixes, submit, review, signed receipt, verify) runs in `tests/e2e/journey.cjs` against the real UI, and over HTTP in `test_api.py`. |
| Technical depth and reliability (25) | Verifier, Claim Ledger, streamed review, hash-chained audit, signed receipts, RBAC, rate limiting, 275 Python tests at 95% line coverage, tamper and concurrency tests. |
| Progress from Round 1 (20) | The Status tab in the app lists every Round 1 item as built, partly built or planned. It is generated from `brandguardian/status.py`. |
| Three planned improvements (15) | Below, with acceptance criteria. Also shown in the Status tab. |
| Usability (10) | Demo sign-in switcher, guided path with live hints, one-click sample, plain-language notes with quoted sources, empty states, keyboard and screen-reader support, mobile layout. |

## Round 3: three planned improvements

1. **Multi-format review and Accessibility Lens.** DOCX and PDF text extraction, OCR for images, palette distance and contrast on uploaded posters, colour-vision preview.
   Done when a poster with low-contrast text and an off-palette colour is flagged with exact ratios and the affected regions.
2. **Guideline simulator, Living Approvals and Decision Replay.** Replay stored content against a draft rule change; re-check approved content when a ledger fact expires; reopen the exact evidence behind any past flag.
   Done when editing one rule shows exact before/after flag counts on stored history, and an expired fact marks affected approvals "needs revalidation".
3. **Integrations and confidential mode.** Google Docs and Slack hooks, SSO, a local-model mode with zero external calls, Ed25519 receipts that third parties can verify with a public key.
   Done when a Docs add-on submits a draft, Slack approves it, and a confidential workspace shows zero outbound calls in the Privacy X-ray.
