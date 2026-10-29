"""Tests that close specific gaps found by the coverage report: config, network transport, rollback, failure paths."""
import http.server
import json
import threading
import time
import unittest
from datetime import date
from unittest import mock

from apiclient import RunningServer
from helpers import TODAY, load_kb, make_engine, mutated
from test_workflow import CLEAN, Env, expect_error
from brandguardian.app import build_app
from brandguardian.config import Settings, load_settings
from brandguardian.knowledge import KnowledgeBase, KnowledgeError
from brandguardian.llm import AnthropicProvider, LLMError, ScriptedProvider, _urllib_transport
from brandguardian.store import Store
from brandguardian.verifier import rewrite_is_safe


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        s = load_settings({})
        self.assertEqual((s.host, s.port, s.db_path, s.demo_mode, s.ai_enabled), ("127.0.0.1", 8000, ":memory:", False, False))

    def test_overrides_and_booleans(self):
        s = load_settings({"BG_HOST": "0.0.0.0", "BG_PORT": "9001", "BG_DEMO": "off", "BG_DB_PATH": "x.db", "ANTHROPIC_API_KEY": "k",
                           "BG_MODEL": "m", "BG_RATE_LIMIT_PER_MINUTE": "10", "BG_MIN_SAMPLES": "3", "BG_HEALTH_THRESHOLD": "0.5"})
        self.assertEqual((s.host, s.port, s.demo_mode, s.db_path, s.anthropic_model), ("0.0.0.0", 9001, False, "x.db", "m"))
        self.assertTrue(s.ai_enabled)
        self.assertEqual((s.rate_limit_per_minute, s.min_samples_for_health, s.health_dispute_threshold), (10, 3, 0.5))
        for truthy in ("1", "true", "YES", " on "):
            self.assertTrue(load_settings({"BG_DEMO": truthy}).demo_mode)
        for falsy in ("0", "false", "no", "banana"):
            self.assertFalse(load_settings({"BG_DEMO": falsy}).demo_mode)

    def test_invalid_numbers_are_rejected_with_a_clear_error(self):
        for key, value in (("BG_PORT", "abc"), ("BG_PORT", "70000"), ("BG_PORT", "-1"), ("BG_MAX_BODY_BYTES", "5"), ("BG_MAX_TEXT_CHARS", "10")):
            with self.assertRaises(ValueError):
                load_settings({key: value})

    def test_blank_values_fall_back_to_defaults(self):
        s = load_settings({"BG_PORT": "  ", "BG_SIGNING_KEY": "", "ANTHROPIC_API_KEY": ""})
        self.assertEqual((s.port, s.signing_key, s.ai_enabled), (8000, None, False))


class _Fake(http.server.BaseHTTPRequestHandler):
    status, body, delay = 200, b"{}", 0.0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        time.sleep(type(self).delay)
        try:
            self.send_response(type(self).status)
            self.send_header("Content-Length", str(len(type(self).body)))
            self.end_headers()
            self.wfile.write(type(self).body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass  # the client gave up (that is what the timeout test does on purpose)

    def log_message(self, *a):
        pass


class NetworkTransportTests(unittest.TestCase):
    """The default transport is exercised against a local server, since the real API cannot be reached offline."""

    def serve(self, status=200, body=b'{"ok":true}', delay=0.0):
        handler = type("H", (_Fake,), {"status": status, "body": body, "delay": delay})
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (httpd.shutdown(), httpd.server_close()))
        return f"http://127.0.0.1:{httpd.server_address[1]}/v1/messages"

    def test_success_and_http_error_statuses_are_returned_not_raised(self):
        self.assertEqual(_urllib_transport(self.serve(), {"a": "b"}, b"{}", 3), (200, b'{"ok":true}'))
        self.assertEqual(_urllib_transport(self.serve(429, b"slow down"), {}, b"{}", 3), (429, b"slow down"))
        self.assertEqual(_urllib_transport(self.serve(500, b"oops"), {}, b"{}", 3)[0], 500)

    def test_connection_refused_becomes_llm_error(self):
        with self.assertRaises(LLMError):
            _urllib_transport("http://127.0.0.1:1/x", {}, b"{}", 2)

    def test_timeout_becomes_llm_error(self):
        with self.assertRaises(LLMError):
            _urllib_transport(self.serve(delay=1.5), {}, b"{}", 0.3)

    def test_provider_survives_a_failing_transport_end_to_end(self):
        provider = AnthropicProvider("k", "m", transport=lambda *a: _urllib_transport("http://127.0.0.1:1/x", *a[1:]))
        with self.assertRaises(LLMError):
            provider.complete("s", "u")


class StoreRollbackTests(unittest.TestCase):
    def test_exception_inside_a_transaction_rolls_everything_back(self):
        store = Store()
        store.upsert_user("u1", "U", "creator", None)
        with self.assertRaises(RuntimeError):
            with store.tx():
                store.create_content("c1", "T", "u1")
                raise RuntimeError("boom")
        self.assertIsNone(store.get_content("c1"))
        store.create_content("c2", "T", "u1")  # the store is still usable
        self.assertIsNotNone(store.get_content("c2"))

    def test_nested_transactions_join_the_outer_one(self):
        store = Store()
        store.upsert_user("u1", "U", "creator", None)
        with self.assertRaises(RuntimeError):
            with store.tx():
                with store.tx():
                    store.create_content("c1", "T", "u1")
                raise RuntimeError("outer fails after inner succeeded")
        self.assertIsNone(store.get_content("c1"))

    def test_token_hash_helpers(self):
        store = Store()
        store.upsert_user("u1", "U", "creator", None)
        store.set_token_hash("u1", "abc")
        self.assertEqual(store.user_by_token_hash("abc")["id"], "u1")
        self.assertIsNone(store.user_by_token_hash("zzz"))


class AppFactoryTests(unittest.TestCase):
    def test_api_key_creates_the_anthropic_provider_without_calling_the_network(self):
        app = build_app(Settings(anthropic_api_key="test-key", anthropic_model="m-1"))
        self.assertEqual(app.reviews.ai_mode, {"enabled": True, "provider": "anthropic", "model": "m-1", "external": True})

    def test_no_key_means_exact_checks_only(self):
        self.assertFalse(build_app(Settings()).reviews.ai_mode["enabled"])

    def test_production_mode_does_not_seed_demo_users(self):
        self.assertEqual(build_app(Settings(demo_mode=False)).store.list_users(), [])


class KnowledgeBranchTests(unittest.TestCase):
    def problem(self, fn, fragment):
        with self.assertRaises(KnowledgeError) as ctx:
            KnowledgeBase.from_dict(mutated(fn))
        self.assertTrue(any(fragment in p for p in ctx.exception.problems), ctx.exception.problems)

    def test_non_string_pattern(self):
        self.problem(lambda d: d["claim_rules"][0].update(patterns=[123]), "non-empty string")

    def test_duplicate_claim_rule_id_and_invalid_severity(self):
        self.problem(lambda d: d["claim_rules"].append(dict(d["claim_rules"][0])), "duplicate claim rule id")
        self.problem(lambda d: d["claim_rules"][0].update(severity="huge"), "invalid severity")

    def test_ledger_needs_matches_or_extract(self):
        def strip(d):
            d["ledger"][1].pop("matches")
        self.problem(strip, "needs 'matches' or 'extract'")


class VerifierRewriteStrictnessTests(unittest.TestCase):
    CTX = "Nova Bar gives customers 20 g of protein."

    def test_invented_name_at_the_start_is_rejected(self):
        self.assertEqual(rewrite_is_safe("x", "Zenith snacks are great", self.CTX), (False, "rewrite_adds_name"))

    def test_known_words_may_start_a_rewrite(self):
        self.assertTrue(rewrite_is_safe("x", "Customers enjoy Nova Bar", self.CTX)[0])


class StreamFailureTests(unittest.TestCase):
    def test_a_failure_mid_stream_is_reported_in_band_without_details(self):
        srv = RunningServer()
        try:
            client = srv.login("u-asha")

            def broken(text, today=None, use_ai=True, simulate=False):
                yield {"type": "detector", "id": "x", "name": "x", "ms": 0, "flags": [], "claims": []}
                raise RuntimeError("secret internal detail")
            with mock.patch.object(srv.app.reviews, "iter_review", side_effect=broken):
                with self.assertLogs("brandguardian", level="ERROR"):
                    status, _, events = client.stream("/api/review/stream", {"text": "hello"})
            self.assertEqual(status, 200)
            self.assertEqual([e["type"] for e in events], ["detector", "error"])
            self.assertNotIn("secret", json.dumps(events))
        finally:
            srv.close()

    def test_remaining_routes_work_over_http(self):
        srv = RunningServer()
        try:
            c = srv.login("u-asha")
            cid = c.post("/api/content", {"title": "T", "text": "Our clients"})[2]["id"]
            self.assertEqual(c.post(f"/api/content/{cid}/versions", {"text": "Our clients again"})[0], 201)
            flag = c.post(f"/api/content/{cid}/check")[2]["review"]["flags"][0]
            self.assertEqual(c.post(f"/api/content/{cid}/flags/{flag['id']}/dismiss", {"reason": "B2B wording is fine"})[0], 200)
            cid2 = c.post("/api/content", {"title": "T2", "text": CLEAN})[2]["id"]
            c.post(f"/api/content/{cid2}/submit")
            rid = srv.login("u-meera").post(f"/api/content/{cid2}/review", {"action": "approve"})[2]["receipt"]["body"]["receipt_id"]
            status, _, rec = c.get(f"/api/receipts/{rid}")
            self.assertEqual((status, rec["body"]["decision"]), (200, "approved"))
        finally:
            srv.close()


class AiBlockerGateTests(unittest.TestCase):
    """A blocking finding from the AI judge must stop approval exactly like a rule-based blocker."""

    FINDING = {"rule_id": "BG-4.3", "span_text": "keeps you full all day",
               "evidence_quote": "Statements about health benefits or results within a timeframe need approved evidence",
               "issue_type": "unsupported_health_claim", "explanation": "A health benefit with no approved evidence.",
               "severity": "blocker", "confidence": 0.9, "suggested_rewrite": None}
    TEXT = "Nova Bar keeps you full all day."

    def env(self):
        return Env(provider=ScriptedProvider(lambda s, u: json.dumps({"findings": [self.FINDING]})))

    def test_ai_blocker_blocks_approval_until_overridden_with_a_reason(self):
        env = self.env()
        c = env.new_content(self.TEXT)
        review = env.wf.check(env.users["creator"], c["id"])["review"]
        self.assertEqual([f["method"] for f in review["flags"]], ["ai"])
        env.wf.submit(env.users["creator"], c["id"])
        err = expect_error(self, 409, env.wf.review, env.users["reviewer"], c["id"], "approve")
        self.assertEqual(err.extra["unresolved_blockers"][0]["rule_id"], "BG-4.3")
        blocker_id = err.extra["unresolved_blockers"][0]["id"]
        out = env.wf.review(env.users["reviewer"], c["id"], "approve", "", [{"flag_id": blocker_id, "reason": "Evidence is on file with legal"}])
        self.assertEqual(out["receipt"]["body"]["ai"]["status"], "ok")
        self.assertEqual(out["receipt"]["body"]["overrides"][0]["rule_id"], "BG-4.3")

    def test_receipt_records_that_an_external_model_was_not_used_for_the_scripted_provider(self):
        env = self.env()
        c = env.new_content(self.TEXT)
        env.wf.check(env.users["creator"], c["id"])
        env.wf.submit(env.users["creator"], c["id"])
        blocker = expect_error(self, 409, env.wf.review, env.users["manager"], c["id"], "approve").extra["unresolved_blockers"][0]
        out = env.wf.review(env.users["manager"], c["id"], "approve", "", [{"flag_id": blocker["id"], "reason": "Reviewed and accepted"}])
        self.assertEqual((out["receipt"]["body"]["ai"]["provider"], out["receipt"]["body"]["ai"]["external"]), ("scripted-test", False))


class WorkflowEdgeTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.wf, self.u = self.env.wf, self.env.users

    def test_accept_works_even_when_the_content_was_never_checked(self):
        c = self.env.new_content("Our clients love it.")
        flag_id = make_engine().review("Our clients love it.", TODAY).flags[0].id
        out = self.wf.accept_suggestion(self.u["creator"], c["id"], flag_id, 0)
        self.assertEqual(out["content"]["latest"]["text"], "Our customers love it.")

    def test_corrupted_stored_offsets_are_refused_not_applied(self):
        c = self.env.new_content("Our clients love it.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        forged = json.loads(self.env.store.get_version(c["id"], 1)["review_json"])
        forged["flags"][0]["end"] = 9999
        forged["flags"][0]["suggestions"][0]["end"] = 9999
        self.env.store.save_review(c["id"], 1, forged)
        expect_error(self, 422, self.wf.accept_suggestion, self.u["creator"], c["id"], flag["id"], 0)
        self.assertEqual(self.wf.get_content(self.u["creator"], c["id"])["latest"]["text"], "Our clients love it.")

    def test_dismiss_unknown_flag_and_overlong_comment(self):
        c = self.env.new_content("Our clients love it.")
        expect_error(self, 404, self.wf.dismiss_flag, self.u["creator"], c["id"], "ffffffffffff", "a good reason")
        cid = self.env.submitted(CLEAN)
        expect_error(self, 400, self.wf.review, self.u["reviewer"], cid, "request_changes", "x" * 2500)

    def test_simulation_is_refused_when_demo_is_off(self):
        env = Env(demo=False)
        token = env.wf.provision_user("u-real", "Real", "creator")
        actor = env.wf.authenticate(token)
        c = env.wf.create_content(actor, "T", CLEAN)
        expect_error(self, 403, env.wf.check, actor, c["id"], True, True)


if __name__ == "__main__":
    unittest.main()
