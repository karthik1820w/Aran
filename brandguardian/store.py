"""SQLite persistence. One connection guarded by a re-entrant lock; all statements are parameterised."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from .audit import GENESIS_HASH, entry_hash
from .util import canonical_json, utc_now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, token_hash TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS content(id TEXT PRIMARY KEY, title TEXT NOT NULL, author_id TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS versions(content_id TEXT NOT NULL, n INTEGER NOT NULL, text TEXT NOT NULL, content_hash TEXT NOT NULL,
  author_id TEXT NOT NULL, created_at TEXT NOT NULL, review_json TEXT, PRIMARY KEY(content_id, n));
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, content_id TEXT NOT NULL, version_n INTEGER NOT NULL,
  flag_id TEXT NOT NULL, rule_id TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL, reason TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT, content_id TEXT NOT NULL, version_n INTEGER NOT NULL,
  start INTEGER NOT NULL, "end" INTEGER NOT NULL, body TEXT NOT NULL, author_id TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS exposures(content_id TEXT NOT NULL, rule_id TEXT NOT NULL, flag_text TEXT NOT NULL, version_n INTEGER NOT NULL,
  flag_id TEXT NOT NULL, PRIMARY KEY(content_id, rule_id, flag_text));
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, prev_hash TEXT NOT NULL, hash TEXT NOT NULL, ts TEXT NOT NULL,
  actor TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, content_id TEXT NOT NULL, version_n INTEGER NOT NULL, body_json TEXT NOT NULL,
  signature TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS anchors(id TEXT PRIMARY KEY, seq INTEGER NOT NULL, head_hash TEXT NOT NULL, anchored_at TEXT NOT NULL, witness_signature TEXT NOT NULL, proof_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rule_clarifications(id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, proposed_do TEXT NOT NULL, proposed_dont TEXT NOT NULL, rationale TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, reviewed_by TEXT, reviewed_at TEXT, review_comment TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


class Store:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._depth = 0
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys=ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def tx(self) -> Iterator[None]:
        """Atomic block; nested use joins the outer transaction."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def _one(self, sql: str, args: tuple = ()) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(sql, args).fetchone()
        return dict(row) if row else None

    def _all(self, sql: str, args: tuple = ()) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def _run(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            return self._conn.execute(sql, args).lastrowid or 0

    # meta
    def get_meta(self, key: str) -> Optional[str]:
        row = self._one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self._run("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    # users
    def upsert_user(self, user_id: str, name: str, role: str, token_hash: Optional[str]) -> None:
        self._run("INSERT INTO users(id,name,role,token_hash) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                  "name=excluded.name, role=excluded.role, token_hash=COALESCE(excluded.token_hash, users.token_hash)",
                  (user_id, name, role, token_hash))

    def set_token_hash(self, user_id: str, token_hash: str) -> None:
        self._run("UPDATE users SET token_hash=? WHERE id=?", (token_hash, user_id))

    def add_session(self, user_id: str, token_hash: str, ttl_hours: int = 8, keep: int = 20) -> None:
        """Create an independent session with expiry; only the newest *keep* sessions per user stay valid."""
        from datetime import datetime, timezone, timedelta
        now = utc_now_iso()
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.tx():
            self._run("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                      (token_hash, user_id, now, expires))
            self._run("DELETE FROM sessions WHERE user_id=? AND token_hash NOT IN "
                      "(SELECT token_hash FROM sessions WHERE user_id=? ORDER BY rowid DESC LIMIT ?)",
                      (user_id, user_id, keep))

    def user_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """Resolve a token to its user; checks both static token_hash and sessions (with TTL)."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        row = self._one("SELECT id,name,role FROM users WHERE token_hash=?", (token_hash,))
        if row:
            return row
        return self._one(
            "SELECT u.id,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token_hash=? AND s.expires_at > ?",
            (token_hash, now)
        )

    def delete_session(self, token_hash: str) -> None:
        """Invalidate a specific session token (server-side logout)."""
        self._run("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def delete_all_user_sessions(self, user_id: str) -> None:
        """Invalidate all sessions for a given user."""
        self._run("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT id,name,role FROM users WHERE id=?", (user_id,))

    def list_users(self) -> List[Dict[str, Any]]:
        return self._all("SELECT id,name,role FROM users ORDER BY id")

    # content and versions
    def create_content(self, content_id: str, title: str, author_id: str) -> None:
        now = utc_now_iso()
        self._run("INSERT INTO content(id,title,author_id,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                  (content_id, title, author_id, "draft", now, now))

    def update_title(self, content_id: str, title: str) -> None:
        self._run("UPDATE content SET title=?, updated_at=? WHERE id=?", (title, utc_now_iso(), content_id))

    def get_content(self, content_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM content WHERE id=?", (content_id,))

    def list_content(self) -> List[Dict[str, Any]]:
        return self._all("SELECT * FROM content ORDER BY updated_at DESC, id")

    def set_status(self, content_id: str, status: str) -> None:
        self._run("UPDATE content SET status=?, updated_at=? WHERE id=?", (status, utc_now_iso(), content_id))

    def add_version(self, content_id: str, text: str, content_hash: str, author_id: str) -> int:
        with self.tx():
            row = self._one("SELECT COALESCE(MAX(n),0)+1 AS n FROM versions WHERE content_id=?", (content_id,))
            n = int(row["n"]) if row else 1
            self._run("INSERT INTO versions(content_id,n,text,content_hash,author_id,created_at) VALUES(?,?,?,?,?,?)",
                      (content_id, n, text, content_hash, author_id, utc_now_iso()))
            self._run("UPDATE content SET updated_at=? WHERE id=?", (utc_now_iso(), content_id))
        return n

    def get_version(self, content_id: str, n: int) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM versions WHERE content_id=? AND n=?", (content_id, n))

    def latest_version(self, content_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM versions WHERE content_id=? ORDER BY n DESC LIMIT 1", (content_id,))

    def list_versions(self, content_id: str) -> List[Dict[str, Any]]:
        return self._all("SELECT n,content_hash,author_id,created_at FROM versions WHERE content_id=? ORDER BY n", (content_id,))

    def save_review(self, content_id: str, n: int, review: Dict[str, Any]) -> None:
        self._run("UPDATE versions SET review_json=? WHERE content_id=? AND n=?", (json.dumps(review), content_id, n))

    # exposures and decisions
    def add_exposure(self, content_id: str, n: int, flag_id: str, rule_id: str, flag_text: str) -> None:
        """Record that an issue was shown. Keyed by (content, rule, flagged text) so the same unresolved issue seen across
        several versions counts once; otherwise long-lived drafts would inflate the denominator of every rule."""
        self._run("INSERT OR IGNORE INTO exposures(content_id,rule_id,flag_text,version_n,flag_id) VALUES(?,?,?,?,?)",
                  (content_id, rule_id, flag_text[:200], n, flag_id))

    def exposure_counts(self) -> Dict[str, int]:
        return {r["rule_id"]: r["c"] for r in self._all("SELECT rule_id, COUNT(*) AS c FROM exposures GROUP BY rule_id")}

    def add_decision(self, content_id: str, n: int, flag_id: str, rule_id: str, action: str, actor_id: str, reason: str) -> None:
        self._run("INSERT INTO decisions(content_id,version_n,flag_id,rule_id,action,actor_id,reason,created_at) VALUES(?,?,?,?,?,?,?,?)",
                  (content_id, n, flag_id, rule_id, action, actor_id, reason, utc_now_iso()))

    def list_decisions(self, content_id: str) -> List[Dict[str, Any]]:
        return self._all("SELECT * FROM decisions WHERE content_id=? ORDER BY id", (content_id,))

    def decision_counts(self) -> List[Dict[str, Any]]:
        return self._all("SELECT rule_id, action, COUNT(*) AS c FROM decisions GROUP BY rule_id, action")

    # comments
    def add_comment(self, content_id: str, n: int, start: int, end: int, body: str, author_id: str) -> int:
        return self._run('INSERT INTO comments(content_id,version_n,start,"end",body,author_id,created_at) VALUES(?,?,?,?,?,?,?)',
                         (content_id, n, start, end, body, author_id, utc_now_iso()))

    def list_comments(self, content_id: str) -> List[Dict[str, Any]]:
        return self._all('SELECT id,version_n,start,"end" AS end,body,author_id,resolved,created_at FROM comments WHERE content_id=? ORDER BY id', (content_id,))

    def resolve_comment(self, content_id: str, comment_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE comments SET resolved=1 WHERE id=? AND content_id=?", (comment_id, content_id))
            return cur.rowcount > 0

    # audit chain
    def append_audit(self, actor: str, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self.tx():
            last = self._one("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1")
            seq = (last["seq"] + 1) if last else 1
            prev = last["hash"] if last else GENESIS_HASH
            ts = utc_now_iso()
            payload_json = canonical_json(payload)
            digest = entry_hash(prev, seq, ts, actor, action, payload_json)
            self._run("INSERT INTO audit(seq,prev_hash,hash,ts,actor,action,payload) VALUES(?,?,?,?,?,?,?)",
                      (seq, prev, digest, ts, actor, action, payload_json))
        return {"seq": seq, "prev_hash": prev, "hash": digest, "ts": ts, "actor": actor, "action": action, "payload": payload_json}

    def list_audit(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        if limit is None:
            return self._all("SELECT * FROM audit ORDER BY seq")
        rows = self._all("SELECT * FROM audit ORDER BY seq DESC LIMIT ?", (limit,))
        return list(reversed(rows))

    # receipts
    def add_receipt(self, receipt_id: str, content_id: str, n: int, body: Dict[str, Any], signature: str) -> None:
        self._run("INSERT INTO receipts(id,content_id,version_n,body_json,signature,created_at) VALUES(?,?,?,?,?,?)",
                  (receipt_id, content_id, n, canonical_json(body), signature, utc_now_iso()))

    def get_receipt(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM receipts WHERE id=?", (receipt_id,))

    def list_receipts(self, content_id: str) -> List[Dict[str, Any]]:
        return self._all("SELECT id,version_n,created_at FROM receipts WHERE content_id=? ORDER BY created_at", (content_id,))

    # anchors
    def add_anchor(self, anchor_id: str, seq: int, head_hash: str, ts: str, signature: str, proof: Dict[str, Any]) -> None:
        self._run("INSERT INTO anchors(id,seq,head_hash,anchored_at,witness_signature,proof_json) VALUES(?,?,?,?,?,?)",
                  (anchor_id, seq, head_hash, ts, signature, json.dumps(proof)))

    def latest_anchor(self) -> Optional[Dict[str, Any]]:
        row = self._one("SELECT * FROM anchors ORDER BY seq DESC LIMIT 1")
        if row and row.get("proof_json"):
            row["proof"] = json.loads(row["proof_json"])
        return row

    def list_anchors(self, limit: int = 20) -> List[Dict[str, Any]]:
        rows = self._all("SELECT * FROM anchors ORDER BY seq DESC LIMIT ?", (limit,))
        for r in rows:
            if r.get("proof_json"):
                r["proof"] = json.loads(r["proof_json"])
        return rows

    # precedents
    def get_precedents_for_rule(self, rule_id: str, limit: int = 5) -> Dict[str, Any]:
        """Precedent view: query how similar flags for this rule were decided before."""
        counts = {r["action"]: r["c"] for r in self._all(
            "SELECT action, COUNT(*) AS c FROM decisions WHERE rule_id=? GROUP BY action", (rule_id,))}
        total = sum(counts.values())
        overridden = counts.get("overridden", 0)
        accepted = counts.get("accepted", 0)
        dismissed = counts.get("dismissed", 0)
        recent_overrides = self._all(
            "SELECT actor_id, reason, created_at, content_id FROM decisions WHERE rule_id=? AND action='overridden' ORDER BY id DESC LIMIT ?",
            (rule_id, limit))
        sample_reasons = [r["reason"] for r in recent_overrides if r.get("reason")]
        rate = round(overridden / total, 2) if total > 0 else 0.0
        if total == 0:
            summary = "No past human decisions recorded for this rule yet."
        elif overridden > 0:
            summary = f"Rule had {total} past decisions: {overridden} overridden ({int(rate*100)}%), {accepted} fixed. Precedent indicates reviewers frequently permit exceptions."
        else:
            summary = f"Rule had {total} past decisions with 0 overrides (100% adherence)."
        return {
            "rule_id": rule_id,
            "total_decisions": total,
            "overridden": overridden,
            "accepted": accepted,
            "dismissed": dismissed,
            "override_rate": rate,
            "recent_overrides": recent_overrides,
            "sample_reasons": sample_reasons,
            "summary": summary,
        }

    # rule clarifications (Guideline Health)
    def add_clarification(self, cid: str, rule_id: str, proposed_do: str, proposed_dont: str, rationale: str) -> None:
        self._run("INSERT INTO rule_clarifications(id,rule_id,proposed_do,proposed_dont,rationale,status,created_at) VALUES(?,?,?,?,?,?,?)",
                  (cid, rule_id, proposed_do, proposed_dont, rationale, "pending", utc_now_iso()))

    def list_clarifications(self, rule_id: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM rule_clarifications WHERE 1=1"
        args: list = []
        if rule_id:
            sql += " AND rule_id=?"
            args.append(rule_id)
        if status:
            sql += " AND status=?"
            args.append(status)
        sql += " ORDER BY created_at DESC"
        return self._all(sql, tuple(args))

    def get_clarification(self, cid: str) -> Optional[Dict[str, Any]]:
        return self._one("SELECT * FROM rule_clarifications WHERE id=?", (cid,))

    def review_clarification(self, cid: str, status: str, reviewed_by: str, comment: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE rule_clarifications SET status=?, reviewed_by=?, reviewed_at=?, review_comment=? WHERE id=?",
                (status, reviewed_by, utc_now_iso(), comment, cid))
            return cur.rowcount > 0

    # test hook: direct SQL used only by tests to simulate tampering
    def _tamper(self, sql: str, args: tuple = ()) -> None:
        self._run(sql, args)
