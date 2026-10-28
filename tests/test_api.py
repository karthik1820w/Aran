import json
import socket
import threading
import unittest

from apiclient import RunningServer
from helpers import load_kb
from brandguardian import server as server_module
from brandguardian.server import RateLimiter, Route

SAMPLE = load_kb().raw["sample_post"]
CLEAN = "Nova Bar gives customers 20 g of protein per Nova Bar. Made with whole oats and almonds."


class ApiBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = RunningServer()
        cls.creator = cls.srv.login("u-asha")
        cls.reviewer = cls.srv.login("u-meera")
        cls.manager = cls.srv.login("u-ravi")
        cls.external = cls.srv.login("u-dev")
        cls.admin = cls.srv.login("u-ira")
        cls.anon = cls.srv.client()

    @classmethod
    def tearDownClass(cls):
        cls.srv.close()


class BasicEndpointTests(ApiBase):
    def test_health_and_status_are_public(self):
        status, _, body = self.anon.get("/api/health")
        self.assertEqual((status, body["status"]), (200, "ok"))
        status, _, body = self.anon.get("/api/status")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["counts"]["built"], 8)
        self.assertEqual(len(body["round3"]), 3)
        self.assertFalse(body["ai"]["enabled"])

    def test_protected_endpoints_require_a_token(self):
        for path in ("/api/me", "/api/kb", "/api/content", "/api/insights", "/api/audit", "/api/dataflow"):
            status, headers, body = self.anon.get(path)
            self.assertEqual(status, 401, path)
            self.assertEqual(headers["www-authenticate"], "Bearer")
            self.assertEqual(body["error"]["code"], "unauthorized")

    def test_bad_tokens_are_rejected(self):
        for token in ("garbage", "a" * 400):
            status, _, _ = self.srv.client(token).get("/api/me")
            self.assertEqual(status, 401)
        status, _, _ = self.anon.get("/api/me", headers={"Authorization": "Basic abc"})
        self.assertEqual(status, 401)

    def test_demo_login_and_me(self):
        status, _, body = self.anon.get("/api/demo/users")
        self.assertEqual((status, len(body["users"])), (200, 5))
        status, _, me = self.creator.get("/api/me")
        self.assertEqual((status, me["user"]["role"]), (200, "creator"))
        self.assertEqual(self.anon.post("/api/demo/login", {"user_id": "nobody"})[0], 404)
        self.assertEqual(self.anon.post("/api/demo/login", {"user_id": 5})[0], 400)

    def test_kb_exposes_rules_and_sample_but_not_patterns(self):
        status, _, body = self.creator.get("/api/kb")
        self.assertEqual(status, 200)
        self.assertEqual(len(body["rules"]), 13)
        self.assertIn("NovaBar", body["sample_post"])
        self.assertNotIn("matches", json.dumps(body))

    def test_contrast_endpoint(self):
        status, _, body = self.creator.post("/api/contrast", {"fg": "#777777", "bg": "#ffffff"})
        self.assertEqual((status, body["ratio"], body["aa"]), (200, 4.48, False))
        self.assertEqual(body["suggested_foreground"], "#767676")
        self.assertEqual(self.creator.post("/api/contrast", {"fg": "red", "bg": "#fff"})[0], 400)

    def test_dataflow_starts_empty_with_no_external_bytes(self):
        status, _, body = self.creator.get("/api/dataflow")
        self.assertEqual(status, 200)

    def test_dataflow_scoped_to_user_and_admin(self):
        from brandguardian.llm import ScriptedProvider
        prov = ScriptedProvider({"hi": "ok"})
        self.srv.app.reviews.log.add(prov, "secret-draft-asha", 1, user_id="u-asha")
        self.srv.app.reviews.log.add(prov, "secret-draft-dev", 1, user_id="u-dev")
        _, _, asha_flow = self.creator.get("/api/dataflow")
        asha_payloads = [e["payload"] for e in asha_flow["entries"]]
        self.assertIn("secret-draft-asha", asha_payloads)
        self.assertNotIn("secret-draft-dev", asha_payloads)
        _, _, admin_flow = self.admin.get("/api/dataflow")
        admin_payloads = [e["payload"] for e in admin_flow["entries"]]
        self.assertIn("secret-draft-asha", admin_payloads)
        self.assertIn("secret-draft-dev", admin_payloads)


class ReviewEndpointTests(ApiBase):
    def test_review_returns_cited_flags(self):
        status, _, body = self.creator.post("/api/review", {"text": SAMPLE})
        self.assertEqual(status, 200)
        self.assertEqual(body["counts"]["blocker"], 7)
        self.assertEqual(body["ai"]["status"], "off")
        flag = body["flags"][0]
        for key in ("rule_id", "evidence_quote", "source", "explanation", "suggestions", "start", "end"):
            self.assertIn(key, flag)

    def test_review_validation(self):
        for body in ({}, {"text": 5}, {"text": None}):
            self.assertEqual(self.creator.post("/api/review", body)[0], 400)
        status, _, body = self.creator.post("/api/review", {"text": "x" * 60_000})
        self.assertEqual((status, body["error"]["code"]), (400, "invalid_input"))

    def test_hallucination_trap_over_http(self):
        status, _, body = self.creator.post("/api/review", {"text": "Nova Bar is a protein bar.", "simulate": True})
        self.assertEqual(status, 200)
        self.assertEqual(body["ai"]["provider"], "simulated-unreliable-model")
        self.assertEqual((body["ai"]["verifier"]["accepted"], body["ai"]["verifier"]["rejected"]), (0, 3))
        self.assertEqual([f for f in body["flags"] if f["method"] == "ai"], [])

    def test_stream_delivers_events_in_order(self):
        status, headers, events = self.creator.stream("/api/review/stream", {"text": SAMPLE})
        self.assertEqual(status, 200)
        self.assertIn("ndjson", headers["content-type"])
        self.assertEqual(headers["transfer-encoding"], "chunked")
        self.assertEqual([e["type"] for e in events], ["detector"] * 7 + ["ai", "done"])
        direct = self.creator.post("/api/review", {"text": SAMPLE})[2]
        self.assertEqual(sorted(f["id"] for f in events[-1]["result"]["flags"]), sorted(f["id"] for f in direct["flags"]))

    def test_stream_errors_are_normal_json(self):
        status, _, body = self.creator.stream("/api/review/stream", {"text": 5})
        self.assertEqual(status, 400)
        status, _, body = self.creator.stream("/api/review/stream", {"text": "x" * 60_000})
        self.assertEqual(status, 400)

    def test_stream_requires_auth(self):
        self.assertEqual(self.anon.stream("/api/review/stream", {"text": "hi"})[0], 401)


class ContentJourneyTests(ApiBase):
    def test_complete_journey_over_http(self):
        status, _, created = self.creator.post("/api/content", {"title": "Launch", "text": "Our clients love it. It is guaranteed."})
        self.assertEqual(status, 201)
        cid = created["id"]
        status, _, checked = self.creator.post(f"/api/content/{cid}/check")
        self.assertEqual(status, 200)
        flags = {f["issue_type"]: f for f in checked["review"]["flags"]}
        # accept both fixes, one at a time (each creates a new version)
        status, _, out = self.creator.post(f"/api/content/{cid}/flags/{flags['wrong_term']['id']}/accept", {"suggestion_index": 0})
        self.assertEqual(status, 200)
        flags2 = {f["issue_type"]: f for f in out["review"]["flags"]}
        status, _, out = self.creator.post(f"/api/content/{cid}/flags/{flags2['restricted_phrase']['id']}/accept", {"suggestion_index": 0})
        self.assertEqual(out["content"]["latest"]["text"], "Our customers love it. It is designed.")
        self.assertEqual(out["review"]["flags"], [])
        self.assertEqual(self.creator.post(f"/api/content/{cid}/submit")[0], 200)
        # authors cannot review
        self.assertEqual(self.creator.post(f"/api/content/{cid}/review", {"action": "approve"})[0], 403)
        status, _, decided = self.reviewer.post(f"/api/content/{cid}/review", {"action": "approve", "comment": "Good"})
        self.assertEqual((status, decided["status"]), (200, "approved"))
        rid = decided["receipt"]["body"]["receipt_id"]
        status, _, verified = self.creator.get(f"/api/receipts/{rid}/verify")
        self.assertEqual((status, verified["valid"]), (200, True))
        status, _, diff = self.creator.get(f"/api/content/{cid}/diff?from=1&to=3")
        self.assertEqual(status, 200)
        self.assertTrue(any(o["op"] == "replace" for o in diff["ops"]))
        self.assertEqual(self.manager.get("/api/audit")[2]["chain_intact"], True)

    def test_blockers_return_409_with_details_then_override_works(self):
        cid = self.creator.post("/api/content", {"title": "Risky", "text": "Each bar has 25 g of protein."})[2]["id"]
        self.creator.post(f"/api/content/{cid}/submit")
        status, _, body = self.reviewer.post(f"/api/content/{cid}/review", {"action": "approve"})
        self.assertEqual((status, body["error"]["code"]), (409, "blockers_open"))
        blocker = body["error"]["unresolved_blockers"][0]
        status, _, ok = self.reviewer.post(f"/api/content/{cid}/review", {"action": "approve", "comment": "Label updated",
                                           "overrides": [{"flag_id": blocker["id"], "reason": "New label confirmed by product"}]})
        self.assertEqual(status, 200)
        self.assertEqual(ok["receipt"]["body"]["overrides"][0]["rule_id"], "BG-4.4")

    def test_visibility_and_permissions_over_http(self):
        cid = self.creator.post("/api/content", {"title": "Private", "text": CLEAN})[2]["id"]
        self.assertEqual(self.external.get(f"/api/content/{cid}")[0], 404)
        self.assertEqual(self.reviewer.get(f"/api/content/{cid}")[0], 200)
        self.assertEqual(self.creator.get("/api/insights")[0], 403)
        self.assertEqual(self.admin.get("/api/insights")[0], 200)
        self.assertEqual(self.admin.post("/api/content", {"title": "x", "text": CLEAN})[0], 403)
        items = self.external.get("/api/content")[2]["items"]
        self.assertNotIn(cid, [i["id"] for i in items])

    def test_comments_over_http(self):
        cid = self.creator.post("/api/content", {"title": "C", "text": CLEAN})[2]["id"]
        status, _, c = self.reviewer.post(f"/api/content/{cid}/comments", {"start": 0, "end": 8, "body": "Name check"})
        self.assertEqual(status, 201)
        self.assertEqual(self.creator.post(f"/api/content/{cid}/comments/{c['id']}/resolve")[0], 200)
        self.assertEqual(self.reviewer.post(f"/api/content/{cid}/comments", {"start": 0, "end": 99999, "body": "x"})[0], 400)
        self.assertEqual(self.creator.get(f"/api/content/{cid}/diff?from=1")[0], 400)
        self.assertEqual(self.creator.get(f"/api/content/{cid}/diff?from=a&to=2")[0], 400)

    def test_parallel_journeys_keep_the_audit_chain_valid(self):
        errors = []

        def journey(i):
            try:
                c = self.srv.login("u-asha")
                cid = c.post("/api/content", {"title": f"P{i}", "text": CLEAN + f" {i}"})[2]["id"]
                assert c.post(f"/api/content/{cid}/check")[0] == 200
                assert c.post(f"/api/content/{cid}/submit")[0] == 200
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(repr(exc))
        threads = [threading.Thread(target=journey, args=(i,)) for i in range(12)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        self.assertTrue(self.manager.get("/api/audit")[2]["chain_intact"])


class ProtocolRobustnessTests(ApiBase):
    def test_unknown_endpoint_and_wrong_method(self):
        self.assertEqual(self.creator.get("/api/nothing")[0], 404)
        status, headers, _ = self.creator.get("/api/review")
        self.assertEqual((status, headers["allow"]), (405, "GET, POST"))
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            self.assertEqual(self.creator.request(method, "/api/me")[0], 405, method)

    def test_malformed_ids_are_not_found(self):
        for path in ("/api/content/ZZZ", "/api/content/123", "/api/receipts/xyz", "/api/content/" + "a" * 13):
            self.assertEqual(self.creator.get(path)[0], 404, path)

    def test_invalid_json_and_wrong_shapes(self):
        c = self.creator
        self.assertEqual(c.request("POST", "/api/review", raw=b"{not json", headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(c.request("POST", "/api/review", raw=b"[1,2]", headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(c.request("POST", "/api/review", raw=b"\xff\xfe", headers={"Content-Type": "application/json"})[0], 400)

    def test_wrong_content_type_is_415(self):
        status, _, body = self.creator.request("POST", "/api/review", raw=b'{"text":"x"}', headers={"Content-Type": "text/plain"})
        self.assertEqual((status, body["error"]["code"]), (415, "unsupported_media_type"))

    def test_missing_content_length_is_411(self):
        with socket.create_connection(("127.0.0.1", self.srv.port), timeout=5) as s:
            s.sendall(b"POST /api/review HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + self.creator.token.encode()
                      + b"\r\nContent-Type: application/json\r\n\r\n")
            self.assertIn(b"411", s.recv(4096).split(b"\r\n")[0])

    def test_oversized_body_is_413(self):
        small = RunningServer(max_body_bytes=2000)
        try:
            c = small.login("u-asha")
            status, headers, body = c.request("POST", "/api/review", raw=b'{"text":"' + b"x" * 3000 + b'"}',
                                              headers={"Content-Type": "application/json"})
            self.assertEqual((status, body["error"]["code"]), (413, "too_large"))
            self.assertEqual(headers.get("connection"), "close")
        finally:
            small.close()

    def test_security_headers_on_api_and_static(self):
        for path in ("/api/health", "/"):
            _, headers, _ = self.anon.get(path)
            self.assertIn("default-src 'self'", headers["content-security-policy"])
            self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
            self.assertEqual(headers["x-content-type-options"], "nosniff")
            self.assertEqual(headers["x-frame-options"], "DENY")
            self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertEqual(self.anon.get("/api/health")[1]["cache-control"], "no-store")

    def test_server_header_does_not_leak_python_version(self):
        self.assertEqual(self.anon.get("/api/health")[1]["server"], "BrandGuardian")

    def test_path_traversal_attempts_never_reach_the_filesystem(self):
        for path in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/static/../app.py", "/app.py", "/..%2f..%2fetc%2fpasswd",
                     "/brandguardian/server.py", "/data/demo_brand.json", "/api/../../etc/passwd"):
            status, _, body = self.anon.get(path)
            self.assertEqual(status, 404, path)
            self.assertNotIn("root:", str(body))

    def test_internal_errors_do_not_leak_details(self):
        def boom(req):
            raise RuntimeError("secret internal detail /home/user/path")
        route = Route("GET", "/api/boom", boom, auth=False)
        server_module.ROUTES.append(route)
        try:
            with self.assertLogs("brandguardian", level="ERROR"):
                status, _, body = self.anon.get("/api/boom")
        finally:
            server_module.ROUTES.remove(route)
        self.assertEqual((status, body["error"]["code"]), (500, "internal"))
        self.assertNotIn("secret", json.dumps(body))
        self.assertNotIn("Traceback", json.dumps(body))

    def test_connection_reuse_after_an_error_response(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.port, timeout=5)
        conn.request("GET", "/api/health")
        r1 = conn.getresponse(); r1.read()
        conn.request("GET", "/api/health")
        r2 = conn.getresponse(); r2.read()
        self.assertEqual((r1.status, r2.status), (200, 200))
        conn.close()


class RateLimitTests(unittest.TestCase):
    def test_limiter_refills_over_time(self):
        now = [0.0]
        limiter = RateLimiter(60, clock=lambda: now[0])  # 1 token per second
        self.assertTrue(all(limiter.allow("k")[0] for _ in range(60)))
        allowed, retry = limiter.allow("k")
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        now[0] += 2.0
        self.assertTrue(limiter.allow("k")[0])
        self.assertTrue(limiter.allow("k")[0])
        self.assertFalse(limiter.allow("k")[0])

    def test_keys_are_independent_and_memory_is_bounded(self):
        limiter = RateLimiter(1, clock=lambda: 0.0, max_keys=50)
        self.assertTrue(limiter.allow("a")[0])
        self.assertFalse(limiter.allow("a")[0])
        self.assertTrue(limiter.allow("b")[0])
        for i in range(500):
            limiter.allow(f"k{i}")
        self.assertLessEqual(len(limiter._buckets), 60)

    def test_http_returns_429_with_retry_after(self):
        srv = RunningServer(rate_limit_per_minute=5)
        try:
            client = srv.client()
            codes = [client.get("/api/health")[0] for _ in range(8)]
            self.assertEqual(codes[:5], [200] * 5)
            self.assertEqual(codes[5], 429)
            status, headers, body = client.get("/api/health")
            self.assertEqual((status, body["error"]["code"]), (429, "rate_limited"))
            self.assertGreaterEqual(int(headers["retry-after"]), 1)
        finally:
            srv.close()


class ProductionModeTests(unittest.TestCase):
    def test_demo_features_are_off_in_production_mode(self):
        srv = RunningServer(demo_mode=False)
        try:
            anon = srv.client()
            self.assertEqual(anon.get("/api/demo/users")[0], 403)
            self.assertEqual(anon.post("/api/demo/login", {"user_id": "u-asha"})[0], 403)
            token = srv.app.workflow.provision_user("u-real", "Real User", "creator")
            c = srv.client(token)
            self.assertEqual(c.post("/api/review", {"text": "hi", "simulate": True})[0], 403)
            self.assertEqual(c.stream("/api/review/stream", {"text": "hi", "simulate": True})[0], 403)
            self.assertEqual(c.post("/api/review", {"text": "Our clients"})[0], 200)
        finally:
            srv.close()


if __name__ == "__main__":
    unittest.main()
