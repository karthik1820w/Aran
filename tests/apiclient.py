"""A tiny real-socket test client plus a server fixture (no mocking of the HTTP layer)."""
import http.client
import json
import threading

from helpers import ROOT  # noqa: F401
from brandguardian.app import build_app
from brandguardian.config import Settings
from brandguardian.server import BGServer


class RunningServer:
    def __init__(self, **overrides):
        base = dict(host="127.0.0.1", port=0, db_path=":memory:", demo_mode=True, rate_limit_per_minute=100_000)
        base.update(overrides)
        self.settings = Settings(**base)
        self.app = build_app(self.settings)
        self.httpd = BGServer((self.settings.host, 0), self.app)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.app.store.close()

    def client(self, token=None):
        return Client(self.port, token)

    def login(self, user_id):
        status, _, body = Client(self.port).post("/api/demo/login", {"user_id": user_id})
        assert status == 200, body
        return Client(self.port, body["token"])


class Client:
    def __init__(self, port, token=None):
        self.port, self.token = port, token

    def request(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = dict(headers or {})
        if self.token and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {self.token}"
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read()
            ctype = resp.getheader("Content-Type", "")
            parsed = json.loads(payload) if "json" in ctype and payload else payload.decode("utf-8", "replace")
            return resp.status, dict((k.lower(), v) for k, v in resp.getheaders()), parsed
        finally:
            conn.close()

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self.request("POST", path, body=body if body is not None else {}, **kw)

    def stream(self, path, body):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {"Content-Type": "application/json"}
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"
        conn.request("POST", path, body=json.dumps(body).encode(), headers=hdrs)
        resp = conn.getresponse()
        events = []
        if resp.status == 200:
            for line in resp:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        else:
            events = json.loads(resp.read())
        headers = dict((k.lower(), v) for k, v in resp.getheaders())
        conn.close()
        return resp.status, headers, events
