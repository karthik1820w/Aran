"""Unit and integration tests for Tier 2 differentiators.

1. Claim-bound drafting
2. Third-party-verifiable receipts (Ed25519 & external anchor)
3. Multi-format review & Accessibility Lens
4. Precedent view for reviewers & risk-ranked queue
5. Confidential local-model mode (zero outbound bytes)
6. Guideline Health with suggested clarifications (human approval gate)
"""
from __future__ import annotations

import io
import json
import unittest
import zipfile
import xml.etree.ElementTree as ET
from datetime import date, timedelta

from helpers import TODAY, load_kb, make_engine
from brandguardian.audit import (
    create_anchor_proof,
    generate_key_pair,
    sign_body,
    verify_public_signature,
    verify_signature,
)
from brandguardian.config import Settings
from brandguardian.drafting import (
    ClaimBoundDrafter,
    ClaimBoundVerifier,
    strip_fact_tags,
)
from brandguardian.formats import extract_document
from brandguardian.formats.docx import extract_docx
from brandguardian.formats.html import extract_html
from brandguardian.formats.lens import (
    evaluate_accessibility_lens,
    palette_distance,
    rgb_distance,
)
from brandguardian.formats.pdf import extract_pdf
from brandguardian.judge import DataFlowLog
from brandguardian.knowledge import KnowledgeBase, LedgerEntry
from brandguardian.llm import LocalModelProvider, ScriptedProvider
from brandguardian.service import ReviewService
from brandguardian.store import Store
from brandguardian.workflow import DEMO_USERS, WorkflowError, WorkflowService


def make_test_docx(paragraphs: list[str]) -> bytes:
    """Construct a minimal in-memory .docx file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        root = ET.Element("w:document")
        body = ET.SubElement(root, "w:body")
        for text in paragraphs:
            p = ET.SubElement(body, "w:p")
            r = ET.SubElement(p, "w:r")
            t = ET.SubElement(r, "w:t")
            t.text = text
        xml_data = ET.tostring(root, encoding="utf-8")
        zf.writestr("word/document.xml", xml_data)
    return buf.getvalue()


class ClaimBoundDraftingTests(unittest.TestCase):
    def setUp(self):
        self.kb = load_kb()
        self.verifier = ClaimBoundVerifier(self.kb)
        self.drafter = ClaimBoundDrafter(self.kb)

    def test_strip_fact_tags(self):
        text = "Nova Bar has 20 g of protein [fact:F-PROT-01]. Great taste [fact:F-TASTE-02]!"
        clean = strip_fact_tags(text)
        self.assertEqual(clean, "Nova Bar has 20 g of protein. Great taste!")

    def test_fully_linked_draft_passes_verification(self):
        # Find active fact in demo brand
        valid_fact = next(e for e in self.kb.ledger.values() if e.is_valid_on(TODAY))
        draft = f"Our bar is carefully formulated [fact:{valid_fact.id}]."
        res = self.verifier.verify(draft, today=TODAY)
        self.assertTrue(res["verified"])
        self.assertEqual(res["total_sentences"], 1)
        self.assertEqual(res["verified_sentences"], 1)
        self.assertEqual(res["rejected_sentences"], 0)
        self.assertEqual(res["coverage"], 1.0)

    def test_unlinked_sentence_is_rejected(self):
        valid_fact = next(e for e in self.kb.ledger.values() if e.is_valid_on(TODAY))
        draft = f"Our bar has 20 g of protein [fact:{valid_fact.id}]. This second sentence has no citation."
        res = self.verifier.verify(draft, today=TODAY)
        self.assertFalse(res["verified"])
        self.assertEqual(res["total_sentences"], 2)
        self.assertEqual(res["verified_sentences"], 1)
        self.assertEqual(res["rejected_sentences"], 1)
        self.assertEqual(res["sentences"][1]["status"], "rejected")
        self.assertEqual(res["sentences"][1]["reason"], "unlinked_claim")

    def test_nonexistent_fact_citation_is_rejected(self):
        draft = "Our bar is certified organic [fact:F-NONEXISTENT-99]."
        res = self.verifier.verify(draft, today=TODAY)
        self.assertFalse(res["verified"])
        self.assertEqual(res["sentences"][0]["reason"], "unknown_fact")

    def test_expired_fact_citation_is_rejected(self):
        # Create an expired fact
        expired_entry = LedgerEntry(
            id="F-EXP-01",
            statement="Awarded Best Snack of 2020.",
            source="Snack Weekly 2020",
            owner="Legal",
            valid_from=date(2020, 1, 1),
            valid_until=date(2020, 12, 31),
            topics=("award",),
            matches=(),
        )
        self.kb.ledger["F-EXP-01"] = expired_entry
        draft = "Awarded Best Snack of 2020 [fact:F-EXP-01]."
        res = self.verifier.verify(draft, today=TODAY)
        self.assertFalse(res["verified"])
        self.assertEqual(res["sentences"][0]["reason"], "expired_fact")

    def test_invented_numbers_in_sentence_are_rejected(self):
        valid_fact = next(e for e in self.kb.ledger.values() if e.is_valid_on(TODAY))
        # Add a number that is definitely not in the fact statement
        draft = f"Contains 99999 g of secret ingredient [fact:{valid_fact.id}]."
        res = self.verifier.verify(draft, today=TODAY)
        self.assertFalse(res["verified"])
        self.assertEqual(res["sentences"][0]["reason"], "invented_fact_data")

    def test_drafter_synthesizes_grounded_text(self):
        res = self.drafter.draft("protein", today=TODAY)
        self.assertIn("text", res)
        self.assertIn("clean_text", res)
        self.assertTrue(len(res["facts_used"]) > 0)
        self.assertTrue(res["verified"])


class ThirdPartyVerifiableReceiptsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.engine = make_engine()
        self.reviews = ReviewService(self.engine)
        self.settings = Settings(demo_mode=True, db_path=":memory:")
        self.wf = WorkflowService(self.store, self.reviews, self.settings, today_fn=lambda: TODAY)
        self.wf.seed_demo_users()
        self.creator = self.wf.authenticate(self.wf.login_demo("u-asha")["token"])
        self.reviewer = self.wf.authenticate(self.wf.login_demo("u-meera")["token"])

    def test_ed25519_keypair_and_public_verification(self):
        priv_hex, pub_hex = generate_key_pair()
        self.assertIsNotNone(priv_hex)
        self.assertIsNotNone(pub_hex)
        body = {"content_id": "c123", "decision": "approved", "algorithm": "Ed25519", "public_key": pub_hex}
        sig = sign_body(body, priv_hex, algorithm="Ed25519")
        # Verify with public key only
        ok = verify_public_signature(body, sig, pub_hex)
        self.assertTrue(ok)
        # Tampered body fails verification
        tampered_body = {"content_id": "c123", "decision": "rejected", "algorithm": "Ed25519", "public_key": pub_hex}
        self.assertFalse(verify_public_signature(tampered_body, sig, pub_hex))

    def test_approval_issues_ed25519_receipt_with_external_anchor(self):
        c = self.wf.create_content(self.creator, "Launch Post", "Nova Bar gives customers 20 g of protein per Nova Bar.")
        self.wf.submit(self.creator, c["id"])
        out = self.wf.review(self.reviewer, c["id"], "approve", comment="Looks great")

        receipt = out["receipt"]
        body = receipt["body"]
        self.assertIn("public_key", body)
        self.assertEqual(body["algorithm"], "Ed25519")
        self.assertIn("external_anchor", body)
        self.assertIn("witness_signature", body["external_anchor"])

        # Third-party unauthenticated verification
        pub_verify = self.wf.public_verify(body["receipt_id"])
        self.assertTrue(pub_verify["verified"])
        self.assertEqual(pub_verify["decision"], "approved")
        self.assertTrue(pub_verify["checks"]["public_key_signature_valid"])
        self.assertTrue(pub_verify["checks"]["anchor_recorded"])

    def test_tampered_receipt_fails_public_verify(self):
        c = self.wf.create_content(self.creator, "Post", "Nova Bar gives customers 20 g of protein per Nova Bar.")
        self.wf.submit(self.creator, c["id"])
        out = self.wf.review(self.reviewer, c["id"], "approve")
        rid = out["receipt"]["body"]["receipt_id"]

        # Tamper with stored signature
        self.store._tamper("UPDATE receipts SET signature=? WHERE id=?", ("bad" * 21, rid))
        pub_verify = self.wf.public_verify(rid)
        self.assertFalse(pub_verify["verified"])


class MultiFormatReviewAndLensTests(unittest.TestCase):
    def test_docx_extraction(self):
        docx_bytes = make_test_docx(["Hello world from Brand Guardian.", "NovaBar contains 20g protein."])
        doc = extract_document("brief.docx", docx_bytes)
        self.assertEqual(doc.format, "docx")
        self.assertIn("Hello world from Brand Guardian.", doc.text)
        self.assertIn("NovaBar contains 20g protein.", doc.text)

    def test_html_extraction(self):
        html_bytes = b"<html><body><h1>Launch</h1><p>Our customers love Nova Bar.</p><img src='bar.png' alt='NovaBar package'></body></html>"
        doc = extract_document("page.html", html_bytes)
        self.assertEqual(doc.format, "html")
        self.assertIn("Our customers love Nova Bar", doc.text)
        self.assertEqual(doc.metadata["images_found"], 1)

    def test_pdf_extraction(self):
        pdf_bytes = (
            b"%PDF-1.4\n1 0 obj\n<< /Length 40 >>\nstream\nBT\n/F1 12 Tf\n"
            b"(NovaBar delicious snack) Tj\nET\nendstream\nendobj\n"
            b"xref\n0 2\n0000000000 65535 f \n0000000010 00000 n \n"
            b"trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n110\n%%EOF\n"
        )
        doc = extract_document("flyer.pdf", pdf_bytes)
        self.assertEqual(doc.format, "pdf")
        self.assertIn("NovaBar delicious snack", doc.text)

    def test_palette_distance(self):
        brand_palette = ["#1B365D", "#4A777A", "#D96B43", "#FFFFFF"]
        # Exactly matching color
        dist, nearest = palette_distance("#1B365D", brand_palette)
        self.assertEqual(dist, 0.0)
        self.assertEqual(nearest, "#1B365D")

        # Off-palette bright magenta
        dist_magenta, _ = palette_distance("#FF00FF", brand_palette)
        self.assertGreater(dist_magenta, 50.0)

    def test_accessibility_lens_evaluation(self):
        brand_palette = ["#1B365D", "#FFFFFF"]
        regions = [
            {"id": "hero-text", "label": "Headline", "fg": "#ffffff", "bg": "#1B365D", "large": True},
            {"id": "sub-text", "label": "Low contrast subtitle", "fg": "#777777", "bg": "#ffffff", "large": False},
            {"id": "cta-btn", "label": "Off-palette button", "fg": "#00ff00", "bg": "#ffffff", "large": False},
        ]
        lens = evaluate_accessibility_lens(regions, brand_palette=brand_palette)
        self.assertFalse(lens["compliant"])
        self.assertEqual(len(lens["regions"]), 3)
        self.assertTrue(lens["regions"][0]["passes_wcag_aa"])
        self.assertFalse(lens["regions"][1]["passes_wcag_aa"])
        self.assertTrue(len(lens["contrast_flags"]) >= 1)
        self.assertTrue(len(lens["palette_flags"]) >= 1)


class PrecedentViewAndQueueRankingTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.engine = make_engine()
        self.reviews = ReviewService(self.engine)
        self.settings = Settings(demo_mode=True, db_path=":memory:")
        self.wf = WorkflowService(self.store, self.reviews, self.settings, today_fn=lambda: TODAY)
        self.wf.seed_demo_users()
        self.creator = self.wf.authenticate(self.wf.login_demo("u-asha")["token"])
        self.reviewer = self.wf.authenticate(self.wf.login_demo("u-meera")["token"])

    def test_recording_decisions_builds_precedent_history(self):
        # Create decisions across 2 pieces of content on rule BG-1.3
        self.store.add_decision("c1", 1, "f1", "BG-1.3", "overridden", "u-meera", "Approved industry term")
        self.store.add_decision("c2", 1, "f2", "BG-1.3", "accepted", "u-meera", "Accepted fix")
        self.store.add_decision("c3", 1, "f3", "BG-1.3", "overridden", "u-meera", "Approved industry term")

        prec = self.wf.get_precedent(self.reviewer, "BG-1.3")
        self.assertEqual(prec["total_decisions"], 3)
        self.assertEqual(prec["overridden"], 2)
        self.assertEqual(prec["accepted"], 1)
        self.assertEqual(prec["override_rate"], 0.67)
        self.assertIn("Approved industry term", prec["sample_reasons"])
        self.assertIn("Precedent indicates reviewers frequently permit exceptions", prec["summary"])

    def test_review_queue_ranking_by_risk(self):
        # Item A: Clean draft (0 blockers, low risk)
        cA = self.wf.create_content(self.creator, "Post A Clean", "Nova Bar gives customers 20 g of protein per Nova Bar.")
        self.wf.check(self.creator, cA["id"])
        self.wf.submit(self.creator, cA["id"])

        # Item B: Flawed draft with multiple issues (higher risk)
        cB = self.wf.create_content(self.creator, "Post B Flawed", "Our clients love NovaBar. Each bar has 25 g of protein.")
        self.wf.check(self.creator, cB["id"])
        self.wf.submit(self.creator, cB["id"])

        queue = self.wf.review_queue(self.reviewer)
        self.assertEqual(len(queue), 2)
        # Higher risk item B must be ranked ahead of low risk item A
        self.assertEqual(queue[0]["id"], cB["id"])
        self.assertGreater(queue[0]["risk_score"], queue[1]["risk_score"])
        self.assertEqual(queue[0]["risk_level"], "high")


class ConfidentialLocalModelModeTests(unittest.TestCase):
    def test_local_provider_reports_zero_external_bytes(self):
        provider = LocalModelProvider()
        self.assertFalse(provider.external)
        self.assertEqual(provider.name, "local-confidential")

        log = DataFlowLog()
        log.add(provider, "test sensitive content payload", redactions=2, user_id="u-asha")
        self.assertEqual(log.external_bytes(), 0)
        self.assertFalse(log.entries()[0]["external"])

    def test_local_provider_deterministic_evaluation(self):
        provider = LocalModelProvider()
        prompt = (
            "Review draft against rules.\n"
            "<draft>We love our clients.</draft>\n"
            "Rules:\n[BG-1.1] Terminology: Use customers not clients"
        )
        res_json = provider.complete("system", prompt)
        res = json.loads(res_json)
        self.assertIn("findings", res)


class GuidelineHealthClarificationsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.engine = make_engine()
        self.reviews = ReviewService(self.engine)
        self.settings = Settings(demo_mode=True, db_path=":memory:")
        self.wf = WorkflowService(self.store, self.reviews, self.settings, today_fn=lambda: TODAY)
        self.wf.seed_demo_users()
        self.manager = self.wf.authenticate(self.wf.login_demo("u-ravi")["token"])
        self.creator = self.wf.authenticate(self.wf.login_demo("u-asha")["token"])

    def test_propose_and_approve_clarification(self):
        # Add past disputes on BG-1.3
        self.store.add_decision("c1", 1, "f1", "BG-1.3", "overridden", "u-meera", "Approved developer context")
        self.store.add_decision("c2", 1, "f2", "BG-1.3", "overridden", "u-meera", "Technical whitepaper exception")

        # Propose clarification
        clar = self.wf.propose_clarification(self.manager, "BG-1.3")
        self.assertEqual(clar["status"], "pending")
        self.assertIn("BG-1.3", clar["rule_id"])
        self.assertIn("Approved developer context", clar["rationale"])

        # Creator cannot approve clarification (human gate for reviewers/managers)
        with self.assertRaises(WorkflowError):
            self.wf.review_clarification(self.creator, clar["id"], "approve")

        # Manager approves
        reviewed = self.wf.review_clarification(self.manager, clar["id"], "approve", comment="Clarifies developer copy")
        self.assertEqual(reviewed["status"], "approved")
        self.assertEqual(reviewed["reviewed_by"], "u-ravi")

        # Check listed in insights
        insights = self.wf.insights(self.manager)
        rule_info = next(r for r in insights["rules"] if r["rule_id"] == "BG-1.3")
        self.assertEqual(len(rule_info["clarifications"]), 1)
        self.assertEqual(rule_info["clarifications"][0]["status"], "approved")


if __name__ == "__main__":
    unittest.main()
