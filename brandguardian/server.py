"""HTTP API and static file server (standard library only).

Security properties enforced here: bearer-token authentication, per-client rate limiting, request size and type
limits, a fixed allow-list of static files (no path joining from user input), strict security headers,
JSON depth limiting, per-request time budgets, and error responses that never include stack traces.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from . import __version__
from .app import WEB_DIR, App, build_app
from .config import Settings
from .contrast import ColourError, evaluate
from .engine import ReviewError
from .status import status_payload
from .workflow import User, WorkflowError, hash_token

log = logging.getLogger("brandguardian")

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/logic.js": ("logic.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

CONTENT_ID = r"(?P<cid>[0-9a-f]{12})"
FLAG_ID = r"(?P<fid>[0-9a-f]{12})"


class RateLimiter:
    """Token bucket per client key; thread-safe and bounded in memory."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self.capacity = float(per_minute)
        self.rate = per_minute / 60.0
        self._clock = clock
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def allow(self, key: str) -> Tuple[bool, float]:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                allowed, retry = True, 0.0
            else:
                self._buckets[key] = (tokens, now)
                allowed, retry = False, (1.0 - tokens) / self.rate
            if len(self._buckets) > self._max_keys:
                oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])[: self._max_keys // 10]
                for k, _ in oldest:
                    self._buckets.pop(k, None)
        return allowed, retry


Handler = Callable[["Request"], Any]


class Request:
    def __init__(self, app: App, user: Optional[User], params: Dict[str, str], query: Dict[str, List[str]],
                 body: Dict[str, Any]):
        self.app, self.user, self.params, self.query, self.body = app, user, params, query, body

    @property
    def wf(self):
        return self.app.workflow

    def actor(self) -> User:
        assert self.user is not None
        return self.user

    def int_query(self, name: str) -> int:
        values = self.query.get(name)
        if not values or not re.fullmatch(r"\d{1,6}", values[0]):
            raise WorkflowError(400, "invalid_input", f"query parameter '{name}' must be a positive integer")
        return int(values[0])


class Route:
    def __init__(self, method: str, pattern: str, handler: Handler, auth: bool = True, stream: bool = False):
        self.method, self.regex, self.handler, self.auth, self.stream = method, re.compile(f"^{pattern}$"), handler, auth, stream


def _flag(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _review_args(req: Request) -> Tuple[str, bool, bool]:
    text = req.body.get("text")
    if not isinstance(text, str):
        raise WorkflowError(400, "invalid_input", "text must be a string")
    return text, _flag(req.body.get("use_ai"), True), _flag(req.body.get("simulate"), False)


def _max_depth(obj: Any, limit: int, current: int = 0) -> bool:
    """Return True if obj has nesting depth exceeding limit."""
    if current > limit:
        return True
    if isinstance(obj, dict):
        return any(_max_depth(v, limit, current + 1) for v in obj.values())
    if isinstance(obj, list):
        return any(_max_depth(v, limit, current + 1) for v in obj)
    return False


# ---------------------------------------------------------------------------------------------- handlers
def h_health(req: Request):
    return 200, {"status": "ok", "version": __version__}


def h_status(req: Request):
    return 200, status_payload(req.app.settings.demo_mode, req.app.reviews.ai_mode)


def h_demo_users(req: Request):
    if not req.app.settings.demo_mode:
        raise WorkflowError(403, "forbidden", "demo mode is off")
    return 200, {"users": req.app.store.list_users()}


def h_demo_login(req: Request):
    user_id = req.body.get("user_id")
    if not isinstance(user_id, str):
        raise WorkflowError(400, "invalid_input", "user_id must be a string")
    return 200, req.wf.login_demo(user_id)


def h_logout(req: Request):
    """Server-side logout: invalidate the bearer token immediately."""
    token = req.body.get("token") or getattr(req, "_raw_token", None)
    if token:
        req.wf.logout(token)
    return 200, {"logged_out": True}


def h_me(req: Request):
    return 200, {"user": req.actor().to_dict()}


def h_kb(req: Request):
    req.wf.require(req.actor(), "kb:view")
    summary = req.app.kb.public_summary()
    summary["sample_post"] = req.app.kb.raw.get("sample_post", "")
    return 200, summary


def h_review(req: Request):
    text, use_ai, simulate = _review_args(req)
    try:
        return 200, req.app.reviews.review(text, date.today(), use_ai=use_ai, simulate=simulate)
    except PermissionError as exc:
        raise WorkflowError(403, "forbidden", str(exc)) from exc


def h_review_stream(req: Request):
    text, use_ai, simulate = _review_args(req)

    def events():
        for event in req.app.reviews.iter_review(text, date.today(), use_ai=use_ai, simulate=simulate):
            if event["type"] == "done":
                payload = event["result"].to_dict()
                payload["ai"] = event["ai"]
                yield {"type": "done", "result": payload}
            else:
                yield event
    # Validate eagerly so errors become normal JSON responses rather than a broken stream.
    if len(text) > req.app.settings.max_text_chars:
        raise ReviewError(f"text is longer than the {req.app.settings.max_text_chars} character limit")
    if simulate and not req.app.settings.demo_mode:
        raise WorkflowError(403, "forbidden", "the model simulator is only available in demo mode")
    return events()


def h_contrast(req: Request):
    try:
        return 200, evaluate(req.body.get("fg"), req.body.get("bg"), bool(req.body.get("large", False)))
    except ColourError as exc:
        raise WorkflowError(400, "invalid_input", str(exc)) from exc


def h_dataflow(req: Request):
    """Privacy X-ray: admins see all entries; others see only their own."""
    actor = req.actor()
    if req.wf.can(actor, "dataflow:view_all"):
        flow = req.app.reviews.dataflow()
    else:
        flow = req.app.reviews.dataflow(user_id=actor.id)
    return 200, flow


def h_list_content(req: Request):
    return 200, {"items": req.wf.list_content(req.actor())}


def h_create_content(req: Request):
    return 201, req.wf.create_content(req.actor(), req.body.get("title"), req.body.get("text"))


def h_get_content(req: Request):
    return 200, req.wf.get_content(req.actor(), req.params["cid"])


def h_add_version(req: Request):
    return 201, req.wf.add_version(req.actor(), req.params["cid"], req.body.get("text"))


def h_check(req: Request):
    return 200, req.wf.check(req.actor(), req.params["cid"], _flag(req.body.get("use_ai"), True), _flag(req.body.get("simulate"), False))


def h_accept(req: Request):
    return 200, req.wf.accept_suggestion(req.actor(), req.params["cid"], req.params["fid"], req.body.get("suggestion_index", 0))


def h_dismiss(req: Request):
    return 200, req.wf.dismiss_flag(req.actor(), req.params["cid"], req.params["fid"], req.body.get("reason"))


def h_submit(req: Request):
    return 200, req.wf.submit(req.actor(), req.params["cid"])


def h_review_decision(req: Request):
    return 200, req.wf.review(req.actor(), req.params["cid"], req.body.get("action"), req.body.get("comment", ""), req.body.get("overrides"))


def h_comment(req: Request):
    return 201, req.wf.add_comment(req.actor(), req.params["cid"], req.body.get("start"), req.body.get("end"), req.body.get("body"))


def h_resolve(req: Request):
    return 200, req.wf.resolve_comment(req.actor(), req.params["cid"], int(req.params["comment_id"]))


def h_diff(req: Request):
    return 200, {"ops": req.wf.diff(req.actor(), req.params["cid"], req.int_query("from"), req.int_query("to"))}


def h_receipt(req: Request):
    return 200, req.wf.get_receipt(req.actor(), req.params["rid"])


def h_receipt_verify(req: Request):
    return 200, req.wf.verify_receipt(req.actor(), req.params["rid"])


def h_insights(req: Request):
    return 200, req.wf.insights(req.actor())


def h_audit(req: Request):
    return 200, req.wf.audit(req.actor())


def h_decision_replay(req: Request):
    """Decision Replay: read-only view of the stored evidence behind any past flag."""
    flag_id = req.params.get("fid", "")
    return 200, req.wf.get_decision_replay(req.actor(), req.params["cid"], flag_id)


def h_update_title(req: Request):
    """Patch the title of a saved content item (author only, not while in_review)."""
    return 200, req.wf.update_title(req.actor(), req.params["cid"], req.body.get("title"))


ROUTES: List[Route] = [
    Route("GET", "/api/health", h_health, auth=False),
    Route("GET", "/api/status", h_status, auth=False),
    Route("GET", "/api/demo/users", h_demo_users, auth=False),
    Route("POST", "/api/demo/login", h_demo_login, auth=False),
    Route("POST", "/api/logout", h_logout),
    Route("GET", "/api/me", h_me),
    Route("GET", "/api/kb", h_kb),
    Route("POST", "/api/review", h_review),
    Route("POST", "/api/review/stream", h_review_stream, stream=True),
    Route("POST", "/api/contrast", h_contrast),
    Route("GET", "/api/dataflow", h_dataflow),
    Route("GET", "/api/content", h_list_content),
    Route("POST", "/api/content", h_create_content),
    Route("GET", f"/api/content/{CONTENT_ID}", h_get_content),
    Route("POST", f"/api/content/{CONTENT_ID}/versions", h_add_version),
    Route("POST", f"/api/content/{CONTENT_ID}/check", h_check),
    Route("POST", f"/api/content/{CONTENT_ID}/flags/{FLAG_ID}/accept", h_accept),
    Route("POST", f"/api/content/{CONTENT_ID}/flags/{FLAG_ID}/dismiss", h_dismiss),
    Route("POST", f"/api/content/{CONTENT_ID}/submit", h_submit),
    Route("POST", f"/api/content/{CONTENT_ID}/review", h_review_decision),
    Route("POST", f"/api/content/{CONTENT_ID}/comments", h_comment),
    Route("POST", f"/api/content/{CONTENT_ID}/comments/(?P<comment_id>\\d{{1,9}})/resolve", h_resolve),
    Route("GET", f"/api/content/{CONTENT_ID}/diff", h_diff),
    Route("GET", f"/api/content/{CONTENT_ID}/flags/{FLAG_ID}/replay", h_decision_replay),
    Route("POST", f"/api/content/{CONTENT_ID}/title", h_update_title),
    Route("GET", "/api/receipts/(?P<rid>[0-9a-f]{16})", h_receipt),
    Route("GET", "/api/receipts/(?P<rid>[0-9a-f]{16})/verify", h_receipt_verify),
    Route("GET", "/api/insights", h_insights),
    Route("GET", "/api/audit", h_audit),
]


class BGHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BrandGuardian"
    sys_version = ""

    def version_string(self) -> str:
        return "BrandGuardian"
    timeout = 30  # drop slow or stalled clients

    # --- plumbing -------------------------------------------------------------------------------
    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    @property
    def limiter(self) -> RateLimiter:
        return self.server.limiter  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # keep stderr quiet; use the logging module instead
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _headers(self, status: int, content_type: str, length: Optional[int], cache: str = "no-store",
                 extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", cache)
        if self.close_connection:
            self.send_header("Connection", "close")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status: int, payload: Any, extra: Optional[Dict[str, str]] = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(data), extra=extra)
        self.wfile.write(data)

    def _error(self, status: int, code: str, message: str, extra: Optional[Dict[str, str]] = None, close: bool = False) -> None:
        if close:
            self.close_connection = True
        self._json(status, {"error": {"code": code, "message": message}}, extra)

    def _stream(self, events) -> None:
        self._headers(200, "application/x-ndjson; charset=utf-8", None, extra={"Transfer-Encoding": "chunked", "X-Accel-Buffering": "no"})

        def chunk(data: bytes) -> None:
            self.wfile.write(f"{len(data):X}\r\n".encode("ascii") + data + b"\r\n")
            self.wfile.flush()
        try:
            for event in events:
                chunk((json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8"))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
            return
        except Exception:  # noqa: BLE001 - report generically inside the stream, never leak details
            log.exception("stream failed")
            chunk((json.dumps({"type": "error", "message": "internal error"}) + "\n").encode("utf-8"))
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _client_key(self, user: Optional[User], token: Optional[str]) -> str:
        return ("t:" + hash_token(token)[:16]) if user and token else ("ip:" + self.client_address[0])

    def _bearer(self) -> Optional[str]:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer ") and 0 < len(header) < 300:
            return header[7:].strip() or None
        return None

    def _read_body(self) -> Dict[str, Any]:
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            raise _HttpError(411, "length_required", "Content-Length is required", close=True)
        if not length_header.isdigit():
            raise _HttpError(400, "invalid_input", "bad Content-Length", close=True)
        length = int(length_header)
        if length > self.app.settings.max_body_bytes:
            raise _HttpError(413, "too_large", "request body is too large", close=True)
        ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if length and ctype != "application/json":
            raise _HttpError(415, "unsupported_media_type", "send application/json", close=True)
        raw = self.rfile.read(length) if length else b""
        self._body_consumed = True
        if not raw:
            return {}
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise _HttpError(400, "invalid_json", "body is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise _HttpError(400, "invalid_json", "body must be a JSON object")
        # Reject deeply nested JSON to prevent stack-overflow or DoS exploits
        if _max_depth(parsed, self.app.settings.max_json_depth):
            raise _HttpError(400, "invalid_json",
                             f"JSON nesting exceeds the {self.app.settings.max_json_depth}-level limit")
        return parsed

    # --- dispatch -------------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _method_not_allowed(self) -> None:
        self._error(405, "method_not_allowed", "method not allowed", {"Allow": "GET, POST"}, close=True)

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = lambda self: self._method_not_allowed()  # noqa: E731

    def _dispatch(self, method: str) -> None:
        self._body_consumed = False
        try:
            parts = urlsplit(self.path)
            path = parts.path
            if method == "GET" and path in STATIC_FILES:
                return self._static(path)
            route, params = self._match(method, path)
            if route is None:
                known = any(r.regex.match(path) for r in ROUTES)
                if known:
                    return self._error(405, "method_not_allowed", "method not allowed", {"Allow": "GET, POST"}, close=True)
                return self._error(404, "not_found", "no such endpoint", close=True)
            token = self._bearer()
            user = self.app.workflow.authenticate(token) if token else None
            allowed, retry = self.limiter.allow(self._client_key(user, token))
            if not allowed:
                return self._error(429, "rate_limited", "too many requests",
                                   {"Retry-After": str(max(1, int(retry) + 1))}, close=True)
            if route.auth and user is None:
                return self._error(401, "unauthorized", "sign in first", {"WWW-Authenticate": "Bearer"}, close=True)
            body = self._read_body() if method == "POST" else {}
            # For logout, stash the raw token so the handler can revoke it
            req = Request(self.app, user, params, parse_qs(parts.query, max_num_fields=10), body)
            req._raw_token = token  # type: ignore[attr-defined]
            result = route.handler(req)
            if route.stream:
                return self._stream(result)
            status, payload = result
            self._json(status, payload)
        except _HttpError as exc:
            self._error(exc.status, exc.code, exc.message, close=exc.close)
        except WorkflowError as exc:
            self._json(exc.status, exc.to_dict())
        except ReviewError as exc:
            self._error(400, "invalid_input", str(exc))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - never leak internals to the client
            log.exception("unhandled error for %s %s", method, self.path)
            self._error(500, "internal", "something went wrong", close=True)
        finally:
            if method == "POST" and not self._body_consumed:
                self.close_connection = True  # unread body on the socket: do not reuse the connection

    def _match(self, method: str, path: str) -> Tuple[Optional[Route], Dict[str, str]]:
        for route in ROUTES:
            m = route.regex.match(path)
            if m and route.method == method:
                return route, m.groupdict()
        return None, {}

    def _static(self, path: str) -> None:
        filename, ctype = STATIC_FILES[path]
        try:
            with open(f"{WEB_DIR}/{filename}", "rb") as handle:
                data = handle.read()
        except OSError:
            return self._error(404, "not_found", "file missing")
        self._headers(200, ctype, len(data), cache="no-cache")
        self.wfile.write(data)


class _HttpError(Exception):
    def __init__(self, status: int, code: str, message: str, close: bool = False):
        super().__init__(message)
        self.status, self.code, self.message, self.close = status, code, message, close


class BGServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: Tuple[str, int], app: App):
        super().__init__(address, BGHandler)
        self.app = app
        self.limiter = RateLimiter(app.settings.rate_limit_per_minute)


def create_server(settings: Settings, app: Optional[App] = None) -> BGServer:
    return BGServer((settings.host, settings.port), app or build_app(settings))


def serve(settings: Settings) -> None:  # pragma: no cover - thin runtime wrapper
    server = create_server(settings)
    host, port = server.server_address[:2]
    mode = "demo" if settings.demo_mode else "production"
    ai = server.app.reviews.ai_mode
    print(f"Aran {__version__} ({mode} mode) listening on http://{host}:{port}")
    print("AI judge:", f"{ai['provider']} / {ai['model']}" if ai["enabled"] else "off (set ANTHROPIC_API_KEY to enable)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        server.server_close()
