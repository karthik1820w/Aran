"""Measure review latency in-process and over HTTP. Numbers depend on the machine; run it where you will demo."""
import http.client
import json
import os
import statistics
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from apiclient import RunningServer  # noqa: E402
from helpers import TODAY, load_kb, make_engine  # noqa: E402


def pct(values, p):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * p))]


def row(label, values_ms):
    print(f"{label:52} p50 {statistics.median(values_ms):8.2f} ms   p95 {pct(values_ms, 0.95):8.2f} ms   max {max(values_ms):8.2f} ms")


def main():
    sample = load_kb().raw["sample_post"]
    engine = make_engine()
    print(f"python {sys.version.split()[0]}, cpus {os.cpu_count()}\n")

    times = []
    for _ in range(500):
        t = time.perf_counter(); engine.review(sample, TODAY); times.append((time.perf_counter() - t) * 1000)
    row(f"engine.review, sample post ({len(sample)} chars), n=500", times)

    big = (sample + " ") * (50_000 // (len(sample) + 1))
    times = []
    for _ in range(5):
        t = time.perf_counter(); engine.review(big, TODAY); times.append((time.perf_counter() - t) * 1000)
    row(f"engine.review, maximum size ({len(big)} chars), n=5", times)

    srv = RunningServer()
    try:
        client = srv.login("u-asha")
        times = []
        for _ in range(200):
            t = time.perf_counter(); client.post("/api/review", {"text": sample}); times.append((time.perf_counter() - t) * 1000)
        row("HTTP POST /api/review (new connection each), n=200", times)

        first, total = [], []
        for _ in range(100):
            conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
            t = time.perf_counter()
            conn.request("POST", "/api/review/stream", body=json.dumps({"text": sample}).encode(),
                         headers={"Content-Type": "application/json", "Authorization": f"Bearer {client.token}"})
            resp = conn.getresponse()
            resp.readline()
            first.append((time.perf_counter() - t) * 1000)
            resp.read()
            total.append((time.perf_counter() - t) * 1000)
            conn.close()
        row("stream: time to FIRST result event, n=100", first)
        row("stream: time to LAST event (complete review), n=100", total)

        times = []
        for i in range(100):
            t = time.perf_counter()
            cid = client.post("/api/content", {"title": f"B{i}", "text": sample})[2]["id"]
            client.post(f"/api/content/{cid}/check"); client.post(f"/api/content/{cid}/submit")
            times.append((time.perf_counter() - t) * 1000)
        row("create + check + submit (3 persisted requests), n=100", times)
    finally:
        srv.close()


if __name__ == "__main__":
    main()
