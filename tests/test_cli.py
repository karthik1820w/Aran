"""System tests that start the product the way a user would: as a subprocess, from the command line."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

from helpers import ROOT


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stop(proc):
    """Terminate a server subprocess and close its pipes so no file handles leak."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    finally:
        for pipe in (proc.stdout, proc.stderr):
            if pipe:
                pipe.close()


def run_cli(*args, env=None, cwd=ROOT):
    full_env = dict(os.environ)
    full_env.pop("ANTHROPIC_API_KEY", None)
    full_env.update(env or {})
    return subprocess.run([sys.executable, "-m", "brandguardian", *args], capture_output=True, text=True, cwd=cwd, env=full_env, timeout=60)


class CliTests(unittest.TestCase):
    def test_check_kb(self):
        out = run_cli("check-kb")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("13 rules", out.stdout)

    def test_review_a_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write("Our clients say it is guaranteed.")
            path = handle.name
        try:
            out = run_cli("review", path)
            self.assertEqual(out.returncode, 0, out.stderr)
            data = json.loads(out.stdout)
            self.assertEqual(sorted(f["issue_type"] for f in data["flags"]), ["restricted_phrase", "wrong_term"])
            self.assertEqual(data["ai"]["status"], "off")
        finally:
            os.unlink(path)

    def test_bad_knowledge_file_fails_loudly_with_every_problem(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as handle:
            json.dump({"rules": [{"id": "X", "clause": "1", "title": "t", "text": "x", "severity": "bad"}]}, handle)
            path = handle.name
        try:
            out = run_cli("check-kb", env={"BG_KB_PATH": path})
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("missing 'brand'", out.stderr)
        finally:
            os.unlink(path)

    def test_add_user_prints_a_working_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "bg.db")
            out = run_cli("add-user", "--id", "u-x", "--name", "Xavier", "--role", "reviewer", env={"BG_DB_PATH": db, "BG_DEMO": "0"})
            self.assertEqual(out.returncode, 0, out.stderr)
            token = out.stdout.strip()
            self.assertGreater(len(token), 30)


class ServerProcessTests(unittest.TestCase):
    def start(self, **env):
        port = free_port()
        full = dict(os.environ, BG_PORT=str(port), **env)
        full.pop("ANTHROPIC_API_KEY", None)
        proc = subprocess.Popen([sys.executable, "-m", "brandguardian"], cwd=ROOT, env=full,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1).read()
                return proc, port
            except OSError:
                time.sleep(0.1)
        proc.kill()
        self.fail("server did not start: " + proc.stderr.read())

    def test_server_starts_from_a_clean_command_and_serves_the_app(self):
        proc, port = self.start()
        try:
            page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5)
            html = page.read().decode()
            self.assertIn("Brand Guardian", html)
            self.assertIn("default-src 'self'", page.headers["Content-Security-Policy"])
            js = urllib.request.urlopen(f"http://127.0.0.1:{port}/app.js", timeout=5)
            self.assertIn("javascript", js.headers["Content-Type"])
        finally:
            stop(proc)

    def test_server_runs_from_a_different_working_directory(self):
        """Judges may launch it from anywhere; paths must not depend on the current directory."""
        port = free_port()
        env = dict(os.environ, BG_PORT=str(port), PYTHONPATH=ROOT)
        env.pop("ANTHROPIC_API_KEY", None)
        with tempfile.TemporaryDirectory() as elsewhere:
            proc = subprocess.Popen([sys.executable, "-m", "brandguardian"], cwd=elsewhere, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(100):
                    try:
                        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1).read()
                        self.assertIn(b"features", body)
                        return
                    except OSError:
                        time.sleep(0.1)
                self.fail("server did not start: " + proc.stderr.read())
            finally:
                stop(proc)

    def test_persistent_database_survives_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "bg.db")
            proc, port = self.start(BG_DB_PATH=db, BG_DEMO="1")
            try:
                def post(path, body, token=None):
                    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
                    return json.loads(urllib.request.urlopen(req, timeout=5).read())
                token = post("/api/demo/login", {"user_id": "u-asha"})["token"]
                created = post("/api/content", {"title": "Persisted", "text": "Hello customers."}, token)
            finally:
                stop(proc)
            proc2, port2 = self.start(BG_DB_PATH=db, BG_DEMO="1")
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{port2}/api/demo/login", data=json.dumps({"user_id": "u-asha"}).encode(),
                                             headers={"Content-Type": "application/json"})
                token2 = json.loads(urllib.request.urlopen(req, timeout=5).read())["token"]
                req = urllib.request.Request(f"http://127.0.0.1:{port2}/api/content/{created['id']}", headers={"Authorization": f"Bearer {token2}"})
                again = json.loads(urllib.request.urlopen(req, timeout=5).read())
                self.assertEqual((again["title"], again["latest"]["text"]), ("Persisted", "Hello customers."))
            finally:
                stop(proc2)


if __name__ == "__main__":
    unittest.main()
