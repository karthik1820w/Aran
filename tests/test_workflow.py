import json
import os
import tempfile
import threading
import unittest
from dataclasses import replace

from helpers import TODAY, load_kb, make_engine
from brandguardian.audit import verify_chain
from brandguardian.config import Settings
from brandguardian.llm import ScriptedProvider
from brandguardian.service import ReviewService
from brandguardian.store import Store
from brandguardian.workflow import DEMO_USERS, WorkflowError, WorkflowService, hash_token

CLEAN = "Nova Bar gives customers 20 g of protein per Nova Bar. Made with whole oats and almonds."
FLAWED = "Our clients love NovaBar. Each bar has 25 g of protein."


class Env:
    def __init__(self, demo=True, db=":memory:", provider=None, settings=None):
        self.settings = settings or Settings(demo_mode=demo, db_path=db)
        self.store = Store(db)
        self.reviews = ReviewService(make_engine(), provider, simulator_allowed=demo)
        self.wf = WorkflowService(self.store, self.reviews, self.settings, today_fn=lambda: TODAY)
        self.wf.seed_demo_users()
        self.users = {}
        if demo:
            for uid, _, role in DEMO_USERS:
                self.users[role] = self.wf.authenticate(self.wf.login_demo(uid)["token"])

    def new_content(self, text=CLEAN, title="Launch post", who="creator"):
        return self.wf.create_content(self.users[who], title, text)

    def submitted(self, text=CLEAN, who="creator"):
        c = self.new_content(text, who=who)
        self.wf.submit(self.users[who], c["id"])
        return c["id"]

    def error(self, fn, *args, **kwargs):
        with self.assertRaisesHelper(fn, *args, **kwargs) as err:
            pass
        return err

    @staticmethod
    def assertRaisesHelper(fn, *args, **kwargs):
        class Ctx:
            def __enter__(self_inner):
                try:
                    fn(*args, **kwargs)
                except WorkflowError as exc:
                    self_inner.exc = exc
                    self_inner.status, self_inner.code = exc.status, exc.code
                    return self_inner
                raise AssertionError("expected WorkflowError")

            def __exit__(self_inner, *a):
                return False
        return Ctx()


def expect_error(testcase, status, fn, *args, **kwargs):
    with testcase.assertRaises(WorkflowError) as ctx:
        fn(*args, **kwargs)
    testcase.assertEqual(ctx.exception.status, status, ctx.exception.message)
    return ctx.exception


class IdentityTests(unittest.TestCase):
    def test_tokens_authenticate_and_are_stored_hashed(self):
        env = Env()
        login = env.wf.login_demo("u-asha")
        self.assertEqual(env.wf.authenticate(login["token"]).role, "creator")
        raw = json.dumps(env.store.list_users())
        self.assertNotIn(login["token"], raw)
        rows = env.store._all("SELECT token_hash FROM sessions WHERE user_id='u-asha'")
        self.assertIn(hash_token(login["token"]), [r["token_hash"] for r in rows])

    def test_bad_or_missing_tokens(self):
        env = Env()
        for token in (None, "", "nope", "x" * 500):
            self.assertIsNone(env.wf.authenticate(token))

    def test_two_sessions_for_one_user_are_independent(self):
        env = Env()
        first = env.wf.login_demo("u-asha")["token"]
        second = env.wf.login_demo("u-asha")["token"]
        self.assertNotEqual(first, second)
        self.assertEqual(env.wf.authenticate(first).id, "u-asha")
        self.assertEqual(env.wf.authenticate(second).id, "u-asha")

    def test_old_sessions_expire_beyond_the_cap(self):
        env = Env()
        tokens = [env.wf.login_demo("u-asha")["token"] for _ in range(23)]
        self.assertIsNone(env.wf.authenticate(tokens[0]))
        self.assertIsNone(env.wf.authenticate(tokens[2]))
        self.assertIsNotNone(env.wf.authenticate(tokens[3]))
        self.assertIsNotNone(env.wf.authenticate(tokens[-1]))

    def test_session_tokens_are_stored_hashed(self):
        env = Env()
        token = env.wf.login_demo("u-asha")["token"]
        rows = env.store._all("SELECT token_hash FROM sessions")
        self.assertEqual([r["token_hash"] for r in rows if r["token_hash"] == hash_token(token)], [hash_token(token)])
        self.assertNotIn(token, json.dumps(rows))

    def test_demo_login_disabled_outside_demo_mode(self):
        env = Env(demo=False)
        expect_error(self, 403, env.wf.login_demo, "u-asha")

    def test_unknown_demo_user(self):
        expect_error(self, 404, Env().wf.login_demo, "u-nobody")

    def test_provision_user_and_invalid_role(self):
        env = Env(demo=False)
        token = env.wf.provision_user("u-new", "New Person", "reviewer")
        self.assertEqual(env.wf.authenticate(token).id, "u-new")
        expect_error(self, 400, env.wf.provision_user, "u-x", "X", "superuser")


class ContentAccessTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.u = self.env.users

    def test_create_and_read_back(self):
        c = self.env.new_content()
        self.assertEqual((c["status"], c["latest"]["n"], c["latest"]["text"]), ("draft", 1, CLEAN))
        self.assertEqual(c["author_name"], "Asha Rao (Creator)")

    def test_validation(self):
        wf, u = self.env.wf, self.u["creator"]
        expect_error(self, 400, wf.create_content, u, "", CLEAN)
        expect_error(self, 400, wf.create_content, u, "t" * 200, CLEAN)
        expect_error(self, 400, wf.create_content, u, "ok", "   ")
        expect_error(self, 400, wf.create_content, u, "ok", 123)
        expect_error(self, 400, wf.create_content, u, "ok", "x" * 60_000)

    def test_visibility_rules(self):
        c = self.env.new_content()
        wf = self.env.wf
        self.assertEqual(len(wf.list_content(self.u["creator"])), 1)
        self.assertEqual(wf.list_content(self.u["external"]), [])
        self.assertEqual(len(wf.list_content(self.u["reviewer"])), 1)
        self.assertEqual(len(wf.list_content(self.u["admin"])), 1)
        expect_error(self, 404, wf.get_content, self.u["external"], c["id"])  # existence is not revealed
        wf.get_content(self.u["reviewer"], c["id"])

    def test_admin_cannot_create_content(self):
        expect_error(self, 403, self.env.wf.create_content, self.u["admin"], "t", CLEAN)

    def test_only_author_can_edit(self):
        c = self.env.new_content()
        expect_error(self, 403, self.env.wf.add_version, self.u["reviewer"], c["id"], "other text")

    def test_new_version_and_no_change_rejected(self):
        c = self.env.new_content()
        c2 = self.env.wf.add_version(self.u["creator"], c["id"], CLEAN + " More.")
        self.assertEqual(c2["latest"]["n"], 2)
        expect_error(self, 409, self.env.wf.add_version, self.u["creator"], c["id"], CLEAN + " More.")

    def test_unknown_content_is_404(self):
        expect_error(self, 404, self.env.wf.get_content, self.u["creator"], "nope")


class CheckAndDecisionTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.wf, self.u = self.env.wf, self.env.users

    def test_check_stores_review_and_exposures(self):
        c = self.env.new_content(FLAWED)
        out = self.wf.check(self.u["creator"], c["id"])
        self.assertEqual(out["version"], 1)
        self.assertGreater(len(out["review"]["flags"]), 0)
        self.assertEqual(self.env.store.exposure_counts()["BG-3.1"], 1)
        self.assertIsNotNone(self.wf.get_content(self.u["creator"], c["id"])["latest"]["review"])

    def test_same_issue_across_versions_counts_once_for_guideline_health(self):
        c = self.env.new_content("Our clients love it. Click here.")
        self.wf.check(self.u["creator"], c["id"])
        self.wf.add_version(self.u["creator"], c["id"], "Our clients love it today. Click here.")
        self.wf.check(self.u["creator"], c["id"])
        self.wf.add_version(self.u["creator"], c["id"], "Now our clients love it today. Click here.")
        self.wf.check(self.u["creator"], c["id"])
        counts = self.env.store.exposure_counts()
        self.assertEqual((counts["BG-3.1"], counts["BG-6.2"]), (1, 1))

    def test_checking_twice_does_not_double_count_exposures(self):
        c = self.env.new_content(FLAWED)
        self.wf.check(self.u["creator"], c["id"])
        self.wf.check(self.u["creator"], c["id"])
        self.assertEqual(self.env.store.exposure_counts()["BG-3.1"], 1)

    def test_simulator_blocked_outside_demo(self):
        env = Env(demo=True)
        c = env.new_content(FLAWED)
        out = env.wf.check(env.users["creator"], c["id"], simulate=True)
        self.assertEqual(out["review"]["ai"]["verifier"]["accepted"], 0)
        self.assertEqual(out["review"]["ai"]["verifier"]["rejected"], 3)

    def test_accept_suggestion_creates_new_version_and_records_decision(self):
        c = self.env.new_content("Our clients love it.")
        review = self.wf.check(self.u["creator"], c["id"])["review"]
        flag = review["flags"][0]
        out = self.wf.accept_suggestion(self.u["creator"], c["id"], flag["id"], 0)
        self.assertEqual(out["content"]["latest"]["text"], "Our customers love it.")
        self.assertEqual(out["version"], 2)
        self.assertEqual(out["review"]["flags"], [])
        decisions = self.wf.get_content(self.u["creator"], c["id"])["decisions"]
        self.assertEqual([(d["action"], d["rule_id"]) for d in decisions], [("accepted", "BG-3.1")])

    def test_manual_suggestion_cannot_be_applied(self):
        c = self.env.new_content("Click here to order.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        expect_error(self, 422, self.wf.accept_suggestion, self.u["creator"], c["id"], flag["id"], 0)

    def test_bad_flag_and_bad_index(self):
        c = self.env.new_content("Our clients love it.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        expect_error(self, 404, self.wf.accept_suggestion, self.u["creator"], c["id"], "deadbeef", 0)
        for bad in (5, -1, True, "0"):
            expect_error(self, 400, self.wf.accept_suggestion, self.u["creator"], c["id"], flag["id"], bad)

    def test_dismiss_records_reason_and_blocker_stays_blocking(self):
        c = self.env.new_content("It is guaranteed to work.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        expect_error(self, 400, self.wf.dismiss_flag, self.u["creator"], c["id"], flag["id"], "no")
        out = self.wf.dismiss_flag(self.u["creator"], c["id"], flag["id"], "Legal approved this wording")
        self.assertTrue(out["still_blocking"])

    def test_only_author_can_decide(self):
        c = self.env.new_content("Our clients love it.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        expect_error(self, 403, self.wf.accept_suggestion, self.u["reviewer"], c["id"], flag["id"], 0)
        expect_error(self, 403, self.wf.dismiss_flag, self.u["reviewer"], c["id"], flag["id"], "because reasons")


class ReviewFlowTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.wf, self.u = self.env.wf, self.env.users

    def test_full_happy_path_with_receipt(self):
        cid = self.env.submitted(CLEAN)
        self.assertEqual(self.wf.get_content(self.u["creator"], cid)["status"], "in_review")
        out = self.wf.review(self.u["reviewer"], cid, "approve", "Looks good")
        self.assertEqual(out["status"], "approved")
        body = out["receipt"]["body"]
        self.assertEqual((body["approver"]["role"], body["version"], body["decision"]), ("reviewer", 1, "approved"))
        self.assertEqual(body["knowledge_base"]["version"], "Nova Foods Brand Guidelines v3.2")
        verified = self.wf.verify_receipt(self.u["creator"], body["receipt_id"])
        self.assertTrue(verified["valid"], verified)

    def test_cannot_submit_twice_or_by_non_author(self):
        cid = self.env.submitted(CLEAN)
        expect_error(self, 409, self.wf.submit, self.u["creator"], cid)
        c = self.env.new_content(CLEAN)
        expect_error(self, 403, self.wf.submit, self.u["reviewer"], c["id"])

    def test_content_is_locked_while_in_review(self):
        cid = self.env.submitted(CLEAN)
        expect_error(self, 409, self.wf.add_version, self.u["creator"], cid, CLEAN + " edit")

    def test_blockers_stop_approval_and_are_listed(self):
        cid = self.env.submitted(FLAWED)
        err = expect_error(self, 409, self.wf.review, self.u["reviewer"], cid, "approve")
        self.assertEqual(err.code, "blockers_open")
        self.assertEqual(err.extra["unresolved_blockers"][0]["rule_id"], "BG-4.4")

    def test_override_with_reason_allows_approval_and_is_recorded(self):
        cid = self.env.submitted(FLAWED)
        err = expect_error(self, 409, self.wf.review, self.u["reviewer"], cid, "approve")
        overrides = [{"flag_id": b["id"], "reason": "Product confirmed the new label"} for b in err.extra["unresolved_blockers"]]
        out = self.wf.review(self.u["manager"], cid, "approve", "Overridden knowingly", overrides)
        self.assertEqual(out["receipt"]["body"]["overrides"][0]["rule_id"], "BG-4.4")
        actions = [d["action"] for d in self.wf.get_content(self.u["manager"], cid)["decisions"]]
        self.assertEqual(actions, ["overridden"])

    def test_override_validation(self):
        cid = self.env.submitted(FLAWED)
        err = expect_error(self, 409, self.wf.review, self.u["reviewer"], cid, "approve")
        real = err.extra["unresolved_blockers"][0]["id"]
        expect_error(self, 422, self.wf.review, self.u["reviewer"], cid, "approve", "", [{"flag_id": "ghost", "reason": "long enough reason"}])
        expect_error(self, 400, self.wf.review, self.u["reviewer"], cid, "approve", "", [{"flag_id": real, "reason": "short"}])
        expect_error(self, 422, self.wf.review, self.u["reviewer"], cid, "approve", "", ["not a dict"])

    def test_cannot_override_a_non_blocking_flag(self):
        cid = self.env.submitted("Our clients love it.")  # warning only
        out = self.wf.review(self.u["reviewer"], cid, "approve")
        self.assertEqual(out["status"], "approved")

    def test_server_ignores_forged_stored_review(self):
        """A tampered or stale stored review must not let blockers through: approval re-checks the text itself."""
        cid = self.env.submitted(FLAWED)
        forged = {"flags": [], "counts": {"blocker": 0, "warning": 0, "info": 0}, "checks": [], "ai": {}}
        self.env.store.save_review(cid, 1, forged)
        expect_error(self, 409, self.wf.review, self.u["reviewer"], cid, "approve")

    def test_no_self_approval(self):
        cid = self.env.submitted(CLEAN, who="reviewer")
        expect_error(self, 403, self.wf.review, self.u["reviewer"], cid, "approve")
        self.assertEqual(self.wf.review(self.u["manager"], cid, "approve")["status"], "approved")

    def test_roles_without_review_permission_are_refused(self):
        cid = self.env.submitted(CLEAN)
        for role in ("creator", "external", "admin"):
            expect_error(self, 403, self.wf.review, self.u[role], cid, "approve")

    def test_request_changes_requires_comment_and_unlocks_editing(self):
        cid = self.env.submitted(CLEAN)
        expect_error(self, 400, self.wf.review, self.u["reviewer"], cid, "request_changes", "")
        out = self.wf.review(self.u["reviewer"], cid, "request_changes", "Please soften the tone")
        self.assertEqual(out["status"], "changes_requested")
        c = self.wf.add_version(self.u["creator"], cid, CLEAN + " Fresh.")
        self.assertEqual(c["status"], "draft")
        self.wf.submit(self.u["creator"], cid)

    def test_approve_with_conditions_requires_comment(self):
        cid = self.env.submitted(CLEAN)
        expect_error(self, 400, self.wf.review, self.u["reviewer"], cid, "approve_with_conditions", "")
        out = self.wf.review(self.u["reviewer"], cid, "approve_with_conditions", "Add the legal footer")
        self.assertEqual(out["status"], "approved_with_conditions")
        self.assertEqual(out["receipt"]["body"]["conditions"], "Add the legal footer")

    def test_invalid_action_and_wrong_state(self):
        cid = self.env.submitted(CLEAN)
        expect_error(self, 400, self.wf.review, self.u["reviewer"], cid, "publish")
        self.wf.review(self.u["reviewer"], cid, "approve")
        expect_error(self, 409, self.wf.review, self.u["reviewer"], cid, "approve")

    def test_editing_after_approval_returns_to_draft_and_old_receipt_stays_valid(self):
        cid = self.env.submitted(CLEAN)
        rid = self.wf.review(self.u["reviewer"], cid, "approve")["receipt"]["body"]["receipt_id"]
        c = self.wf.add_version(self.u["creator"], cid, CLEAN + " Changed after approval.")
        self.assertEqual(c["status"], "draft")
        self.assertTrue(self.wf.verify_receipt(self.u["creator"], rid)["valid"])  # still describes version 1 truthfully

    def test_fix_then_approve_without_override(self):
        c = self.env.new_content("It is guaranteed to work.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        self.wf.accept_suggestion(self.u["creator"], c["id"], flag["id"], 0)
        self.wf.submit(self.u["creator"], c["id"])
        self.assertEqual(self.wf.review(self.u["reviewer"], c["id"], "approve")["status"], "approved")


class ReceiptAndAuditIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.wf, self.u = self.env.wf, self.env.users
        self.cid = self.env.submitted(CLEAN)
        self.rid = self.wf.review(self.u["reviewer"], self.cid, "approve")["receipt"]["body"]["receipt_id"]

    def test_untampered_receipt_verifies(self):
        result = self.wf.verify_receipt(self.u["reviewer"], self.rid)
        self.assertTrue(all(result["checks"].values()), result)

    def test_changing_the_approved_text_is_detected(self):
        self.env.store._tamper("UPDATE versions SET text='Different text now' WHERE content_id=?", (self.cid,))
        result = self.wf.verify_receipt(self.u["reviewer"], self.rid)
        self.assertFalse(result["valid"])
        self.assertFalse(result["checks"]["content_unchanged"])

    def test_changing_the_receipt_body_is_detected(self):
        row = self.env.store.get_receipt(self.rid)
        body = json.loads(row["body_json"])
        body["decision"] = "approved_with_conditions"
        self.env.store._tamper("UPDATE receipts SET body_json=? WHERE id=?", (json.dumps(body), self.rid))
        result = self.wf.verify_receipt(self.u["reviewer"], self.rid)
        self.assertFalse(result["checks"]["signature_valid"])

    def test_forged_signature_is_detected(self):
        self.env.store._tamper("UPDATE receipts SET signature=? WHERE id=?", ("0" * 64, self.rid))
        self.assertFalse(self.wf.verify_receipt(self.u["reviewer"], self.rid)["checks"]["signature_valid"])

    def test_rewriting_an_audit_entry_breaks_the_chain(self):
        target = next(e for e in self.env.store.list_audit() if e["action"] == "content.created")
        self.env.store._tamper("UPDATE audit SET payload='{\"forged\":true}' WHERE seq=?", (target["seq"],))
        result = self.wf.verify_receipt(self.u["reviewer"], self.rid)
        self.assertFalse(result["checks"]["audit_chain_intact"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_bad_audit_seq"], target["seq"])

    def test_deleting_an_audit_entry_breaks_the_chain(self):
        self.env.store._tamper("DELETE FROM audit WHERE seq=3")
        ok, bad = verify_chain(self.env.store.list_audit())
        self.assertFalse(ok)

    def test_audit_view_reports_integrity(self):
        report = self.wf.audit(self.u["manager"])
        self.assertTrue(report["chain_intact"])
        self.assertIn("review.approved", [e["action"] for e in report["entries"]])
        self.env.store._tamper("UPDATE audit SET actor='someone-else' WHERE seq=1")
        self.assertFalse(self.wf.audit(self.u["manager"])["chain_intact"])

    def test_audit_is_restricted_by_role(self):
        for role in ("creator", "external"):
            expect_error(self, 403, self.wf.audit, self.u[role])

    def test_receipt_visibility_follows_content_visibility(self):
        expect_error(self, 404, self.wf.get_receipt, self.u["external"], self.rid)
        expect_error(self, 404, self.wf.get_receipt, self.u["creator"], "ffffffffffffffff")

    def test_signing_key_persists_across_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bg.db")
            env = Env(db=path)
            cid = env.submitted(CLEAN)
            rid = env.wf.review(env.users["reviewer"], cid, "approve")["receipt"]["body"]["receipt_id"]
            env.store.close()
            again = Env(db=path)
            try:
                user = again.wf.authenticate(again.wf.login_demo("u-meera")["token"])
                self.assertTrue(again.wf.verify_receipt(user, rid)["valid"])
            finally:
                again.store.close()


class CommentDiffInsightTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.wf, self.u = self.env.wf, self.env.users

    def test_comments_are_anchored_and_resolvable(self):
        cid = self.env.submitted(CLEAN)
        out = self.wf.add_comment(self.u["reviewer"], cid, 0, 8, "Check this name")
        comments = self.wf.get_content(self.u["creator"], cid)["comments"]
        self.assertEqual((comments[0]["start"], comments[0]["end"], comments[0]["resolved"]), (0, 8, 0))
        self.wf.resolve_comment(self.u["creator"], cid, out["id"])
        self.assertEqual(self.wf.get_content(self.u["creator"], cid)["comments"][0]["resolved"], 1)

    def test_comment_validation(self):
        cid = self.env.submitted(CLEAN)
        for start, end in ((-1, 3), (5, 2), (0, 10_000), ("a", 3), (True, 3)):
            expect_error(self, 400, self.wf.add_comment, self.u["reviewer"], cid, start, end, "x")
        expect_error(self, 400, self.wf.add_comment, self.u["reviewer"], cid, 0, 3, "   ")
        expect_error(self, 404, self.wf.resolve_comment, self.u["reviewer"], cid, 999)

    def test_diff_between_versions(self):
        c = self.env.new_content("Our clients love it.")
        self.wf.add_version(self.u["creator"], c["id"], "Our customers love it.")
        ops = self.wf.diff(self.u["creator"], c["id"], 1, 2)
        changed = [o for o in ops if o["op"] != "equal"]
        self.assertEqual(changed, [{"op": "replace", "old": "clients", "new": "customers"}])
        expect_error(self, 404, self.wf.diff, self.u["creator"], c["id"], 1, 9)

    def test_guideline_health_flags_a_rule_reviewers_keep_overriding(self):
        for i in range(5):
            c = self.env.new_content("Our clients love it.", title=f"Post {i}")
            flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
            self.wf.dismiss_flag(self.u["creator"], c["id"], flag["id"], "Clients is correct for B2B posts")
        insights = self.wf.insights(self.u["manager"])
        row = next(r for r in insights["rules"] if r["rule_id"] == "BG-3.1")
        self.assertEqual((row["shown"], row["dismissed"], row["dispute_rate"], row["status"]), (5, 5, 1.0, "unclear"))

    def test_few_samples_are_not_judged(self):
        c = self.env.new_content("Our clients love it.")
        flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
        self.wf.dismiss_flag(self.u["creator"], c["id"], flag["id"], "A reason is given here")
        row = next(r for r in self.wf.insights(self.u["manager"])["rules"] if r["rule_id"] == "BG-3.1")
        self.assertEqual(row["status"], "not_enough_data")

    def test_accepted_suggestions_keep_a_rule_healthy(self):
        for i in range(5):
            c = self.env.new_content("Our clients love it.", title=f"P{i}")
            flag = self.wf.check(self.u["creator"], c["id"])["review"]["flags"][0]
            self.wf.accept_suggestion(self.u["creator"], c["id"], flag["id"], 0)
        row = next(r for r in self.wf.insights(self.u["manager"])["rules"] if r["rule_id"] == "BG-3.1")
        self.assertEqual((row["accepted"], row["status"]), (5, "healthy"))

    def test_insights_restricted(self):
        expect_error(self, 403, self.wf.insights, self.u["creator"])


class ConcurrencyTests(unittest.TestCase):
    def test_parallel_writers_keep_the_audit_chain_valid(self):
        env = Env()
        errors = []

        def work(i):
            try:
                c = env.wf.create_content(env.users["creator"], f"T{i}", CLEAN + f" {i}")
                env.wf.check(env.users["creator"], c["id"])
                env.wf.submit(env.users["creator"], c["id"])
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(20)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        entries = env.store.list_audit()
        self.assertEqual([e["seq"] for e in entries], list(range(1, len(entries) + 1)))
        self.assertTrue(verify_chain(entries)[0])
        self.assertEqual(len(env.wf.list_content(env.users["manager"])), 20)


if __name__ == "__main__":
    unittest.main()
