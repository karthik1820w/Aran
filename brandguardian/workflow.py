"""Workflow: roles, content lifecycle, human decisions, approval gate, audit and signed receipts.

Design rules enforced here (not in the UI):
* Only people approve. The system never approves or publishes.
* Approval is checked server-side against a fresh review of the exact version being approved.
* A blocking flag stays blocking until the text is fixed or a named reviewer overrides it with a written reason.
* Nobody approves their own content.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable, Dict, List, Optional

from . import ENGINE_VERSION
from .audit import RECEIPT_ALGORITHM, sign_body, verify_chain, verify_signature
from .config import Settings
from .edits import EditError, apply_edits, suggestion_to_edit
from .service import ReviewService
from .store import Store
from .util import canonical_json, sha256_hex, utc_now_iso

ROLES = ("creator", "external", "reviewer", "manager", "admin")
STATUSES = ("draft", "in_review", "changes_requested", "approved", "approved_with_conditions")
MIN_REASON = 5
MIN_OVERRIDE_REASON = 10
MAX_TITLE = 120
MAX_COMMENT = 2000

PERMISSIONS: Dict[str, frozenset] = {
    "content:create": frozenset({"creator", "external", "reviewer", "manager"}),
    "content:review": frozenset({"reviewer", "manager"}),
    "content:view_all": frozenset({"reviewer", "manager", "admin"}),
    "insights:view": frozenset({"reviewer", "manager", "admin"}),
    "audit:view": frozenset({"reviewer", "manager", "admin"}),
    "dataflow:view_all": frozenset({"admin"}),  # Privacy X-ray: others see only their own entries
    "kb:view": frozenset(ROLES),
    "users:view": frozenset({"admin", "manager"}),
}

DEMO_USERS = (
    ("u-asha", "Asha Rao (Creator)", "creator"),
    ("u-dev", "Dev Menon (Agency)", "external"),
    ("u-meera", "Meera Iyer (Reviewer)", "reviewer"),
    ("u-ravi", "Ravi Shah (Brand manager)", "manager"),
    ("u-ira", "Ira Khan (Admin)", "admin"),
)


class WorkflowError(Exception):
    def __init__(self, status: int, code: str, message: str, extra: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}

    def to_dict(self) -> Dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, **self.extra}}


@dataclass(frozen=True)
class User:
    id: str
    name: str
    role: str

    def to_dict(self) -> Dict[str, str]:
        return {"id": self.id, "name": self.name, "role": self.role}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _need_text(value: Any, field: str, max_len: int, min_len: int = 1) -> str:
    if not isinstance(value, str):
        raise WorkflowError(400, "invalid_input", f"{field} must be a string")
    cleaned = value.strip()
    if len(cleaned) < min_len:
        raise WorkflowError(400, "invalid_input", f"{field} must be at least {min_len} characters")
    if len(cleaned) > max_len:
        raise WorkflowError(400, "invalid_input", f"{field} must be at most {max_len} characters")
    return cleaned


class WorkflowService:
    def __init__(self, store: Store, reviews: ReviewService, settings: Settings,
                 today_fn: Callable[[], date] = date.today):
        self.store, self.reviews, self.settings = store, reviews, settings
        self.kb = reviews.engine.kb
        self._today = today_fn
        key = settings.signing_key or store.get_meta("signing_key")
        if not key:
            key = secrets.token_hex(32)
            store.set_meta("signing_key", key)
        self._key = key

    # ------------------------------------------------------------------ identity
    def seed_demo_users(self) -> None:
        for user_id, name, role in DEMO_USERS:
            self.store.upsert_user(user_id, name, role, None)

    def provision_user(self, user_id: str, name: str, role: str) -> str:
        if role not in ROLES:
            raise WorkflowError(400, "invalid_input", f"role must be one of {ROLES}")
        token = secrets.token_urlsafe(32)
        self.store.upsert_user(user_id, name, role, hash_token(token))
        self.store.append_audit("system", "user.provisioned", {"user_id": user_id, "role": role})
        return token

    def login_demo(self, user_id: str) -> Dict[str, Any]:
        if not self.settings.demo_mode:
            raise WorkflowError(403, "forbidden", "demo sign-in is disabled")
        row = self.store.get_user(user_id)
        if row is None:
            raise WorkflowError(404, "not_found", "unknown demo user")
        token = secrets.token_urlsafe(32)
        self.store.add_session(user_id, hash_token(token), ttl_hours=self.settings.session_ttl_hours)
        self.store.append_audit(user_id, "auth.demo_login", {})
        return {"token": token, "user": User(**row).to_dict()}

    def logout(self, token: str) -> None:
        """Server-side logout: invalidate the session token immediately."""
        self.store.delete_session(hash_token(token))

    def authenticate(self, token: Optional[str]) -> Optional[User]:
        if not token:
            return None
        row = self.store.user_by_token_hash(hash_token(token))
        return User(**row) if row else None

    def can(self, actor: User, permission: str) -> bool:
        return actor.role in PERMISSIONS[permission]

    def require(self, actor: User, permission: str) -> None:
        if not self.can(actor, permission):
            raise WorkflowError(403, "forbidden", f"your role ({actor.role}) cannot do this")

    # ------------------------------------------------------------------ helpers
    def _content(self, actor: User, content_id: str, *, edit: bool = False) -> Dict[str, Any]:
        row = self.store.get_content(content_id)
        if row is None:
            raise WorkflowError(404, "not_found", "content not found")
        is_author = row["author_id"] == actor.id
        if edit and not is_author:
            raise WorkflowError(403, "forbidden", "only the author can change this content")
        if not is_author and not self.can(actor, "content:view_all"):
            raise WorkflowError(404, "not_found", "content not found")  # do not reveal existence
        return row

    def _version(self, content_id: str, n: Optional[int] = None) -> Dict[str, Any]:
        row = self.store.latest_version(content_id) if n is None else self.store.get_version(content_id, n)
        if row is None:
            raise WorkflowError(404, "not_found", "version not found")
        return row

    def _check_text(self, text: Any) -> str:
        if not isinstance(text, str):
            raise WorkflowError(400, "invalid_input", "text must be a string")
        if not text.strip():
            raise WorkflowError(400, "invalid_input", "text must not be empty")
        if len(text) > self.settings.max_text_chars:
            raise WorkflowError(400, "invalid_input", f"text is longer than {self.settings.max_text_chars} characters")
        return text

    def _locked(self, row: Dict[str, Any]) -> None:
        if row["status"] == "in_review":
            raise WorkflowError(409, "locked", "this content is in review; a reviewer must request changes before it can be edited")

    # ------------------------------------------------------------------ content
    def create_content(self, actor: User, title: Any, text: Any) -> Dict[str, Any]:
        self.require(actor, "content:create")
        title = _need_text(title, "title", MAX_TITLE)
        text = self._check_text(text)
        content_id = secrets.token_hex(6)
        with self.store.tx():
            self.store.create_content(content_id, title, actor.id)
            n = self.store.add_version(content_id, text, sha256_hex(text), actor.id)
            self.store.append_audit(actor.id, "content.created", {"content_id": content_id, "version": n})
        return self.get_content(actor, content_id)

    def list_content(self, actor: User) -> List[Dict[str, Any]]:
        rows = self.store.list_content()
        if not self.can(actor, "content:view_all"):
            rows = [r for r in rows if r["author_id"] == actor.id]
        names = {u["id"]: u["name"] for u in self.store.list_users()}
        return [{**r, "author_name": names.get(r["author_id"], r["author_id"])} for r in rows]

    def get_content(self, actor: User, content_id: str) -> Dict[str, Any]:
        row = self._content(actor, content_id)
        latest = self._version(content_id)
        review = json.loads(latest["review_json"]) if latest["review_json"] else None
        author = self.store.get_user(row["author_id"])
        return {
            **row, "author_name": author["name"] if author else row["author_id"],
            "latest": {"n": latest["n"], "text": latest["text"], "content_hash": latest["content_hash"], "review": review},
            "versions": self.store.list_versions(content_id),
            "comments": self.store.list_comments(content_id),
            "decisions": self.store.list_decisions(content_id),
            "receipts": self.store.list_receipts(content_id),
        }

    def add_version(self, actor: User, content_id: str, text: Any) -> Dict[str, Any]:
        row = self._content(actor, content_id, edit=True)
        self._locked(row)
        text = self._check_text(text)
        latest = self._version(content_id)
        if latest["text"] == text:
            raise WorkflowError(409, "no_change", "the text is identical to the latest version")
        with self.store.tx():
            n = self.store.add_version(content_id, text, sha256_hex(text), actor.id)
            self.store.set_status(content_id, "draft")
            self.store.append_audit(actor.id, "content.version_added", {"content_id": content_id, "version": n})
        return self.get_content(actor, content_id)

    # ------------------------------------------------------------------ checking
    def check(self, actor: User, content_id: str, use_ai: bool = True, simulate: bool = False) -> Dict[str, Any]:
        self._content(actor, content_id)
        version = self._version(content_id)
        try:
            review = self.reviews.review(version["text"], self._today(), use_ai=use_ai, simulate=simulate, user_id=actor.id)
        except PermissionError as exc:
            raise WorkflowError(403, "forbidden", str(exc)) from exc
        with self.store.tx():
            self.store.save_review(content_id, version["n"], review)
            for flag in review["flags"]:
                self.store.add_exposure(content_id, version["n"], flag["id"], flag["rule_id"], flag["text"])
            self.store.append_audit(actor.id, "content.checked", {
                "content_id": content_id, "version": version["n"], "counts": review["counts"], "ai": review["ai"]["status"]})
        return {"version": version["n"], "review": review}

    def _stored_review(self, actor: User, content_id: str, version: Dict[str, Any]) -> Dict[str, Any]:
        if not version["review_json"]:
            self.check(actor, content_id)
            version = self._version(content_id, version["n"])
        return json.loads(version["review_json"])

    def _blockers(self, version: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Blocking flags that must be resolved: a fresh exact re-check plus blocking AI flags saved with the version."""
        fresh = self.reviews.engine.review(version["text"], self._today())
        found = {f.id: f.to_dict() for f in fresh.flags if f.severity == "blocker"}
        if version["review_json"]:
            for flag in json.loads(version["review_json"])["flags"]:
                if flag["method"] == "ai" and flag["severity"] == "blocker":
                    found[flag["id"]] = flag
        return list(found.values())

    # ------------------------------------------------------------------ decisions by the author
    def accept_suggestion(self, actor: User, content_id: str, flag_id: str, suggestion_index: int) -> Dict[str, Any]:
        row = self._content(actor, content_id, edit=True)
        self._locked(row)
        version = self._version(content_id)
        review = self._stored_review(actor, content_id, version)
        flag = next((f for f in review["flags"] if f["id"] == flag_id), None)
        if flag is None:
            raise WorkflowError(404, "not_found", "flag not found on the latest version")
        if not isinstance(suggestion_index, int) or isinstance(suggestion_index, bool) or not 0 <= suggestion_index < len(flag["suggestions"]):
            raise WorkflowError(400, "invalid_input", "suggestion_index is out of range")
        s = flag["suggestions"][suggestion_index]
        start = flag["start"] if s["start"] is None else s["start"]
        end = flag["end"] if s["end"] is None else s["end"]
        from .edits import Edit
        if s["action"] == "replace" and s["text"] is not None:
            edit: Optional[Edit] = Edit(start, end, s["text"])
        elif s["action"] == "delete":
            edit = Edit(start, end, "")
        else:
            edit = None
        if edit is None:
            raise WorkflowError(422, "manual_edit_needed", "this suggestion needs a person to edit the text")
        try:
            new_text = apply_edits(version["text"], [edit])
        except EditError as exc:
            raise WorkflowError(422, "invalid_edit", str(exc)) from exc
        with self.store.tx():
            n = self.store.add_version(content_id, new_text, sha256_hex(new_text), actor.id)
            self.store.set_status(content_id, "draft")
            self.store.add_decision(content_id, version["n"], flag["id"], flag["rule_id"], "accepted", actor.id, s["style"])
            self.store.append_audit(actor.id, "flag.accepted", {"content_id": content_id, "flag": flag["id"], "rule": flag["rule_id"], "version": n})
        checked = self.check(actor, content_id)
        return {"content": self.get_content(actor, content_id), "version": n, "review": checked["review"]}

    def dismiss_flag(self, actor: User, content_id: str, flag_id: str, reason: Any) -> Dict[str, Any]:
        row = self._content(actor, content_id, edit=True)
        self._locked(row)
        reason = _need_text(reason, "reason", MAX_COMMENT, MIN_REASON)
        version = self._version(content_id)
        review = self._stored_review(actor, content_id, version)
        flag = next((f for f in review["flags"] if f["id"] == flag_id), None)
        if flag is None:
            raise WorkflowError(404, "not_found", "flag not found on the latest version")
        with self.store.tx():
            self.store.add_decision(content_id, version["n"], flag["id"], flag["rule_id"], "dismissed", actor.id, reason)
            self.store.append_audit(actor.id, "flag.dismissed", {"content_id": content_id, "flag": flag["id"], "rule": flag["rule_id"]})
        return {"dismissed": flag["id"], "still_blocking": flag["severity"] == "blocker"}

    # ------------------------------------------------------------------ review flow
    def submit(self, actor: User, content_id: str) -> Dict[str, Any]:
        row = self._content(actor, content_id, edit=True)
        if row["status"] not in ("draft", "changes_requested"):
            raise WorkflowError(409, "invalid_state", f"cannot submit content that is {row['status']}")
        version = self._version(content_id)
        if not version["review_json"]:
            self.check(actor, content_id)
        with self.store.tx():
            self.store.set_status(content_id, "in_review")
            self.store.append_audit(actor.id, "content.submitted", {"content_id": content_id, "version": version["n"]})
        return self.get_content(actor, content_id)

    def review(self, actor: User, content_id: str, action: Any, comment: Any = "", overrides: Any = None) -> Dict[str, Any]:
        self.require(actor, "content:review")
        row = self._content(actor, content_id)
        if row["status"] != "in_review":
            raise WorkflowError(409, "invalid_state", f"content is {row['status']}, not in review")
        if row["author_id"] == actor.id:
            raise WorkflowError(403, "forbidden", "you cannot review your own content")
        if action not in ("approve", "approve_with_conditions", "request_changes"):
            raise WorkflowError(400, "invalid_input", "action must be approve, approve_with_conditions or request_changes")
        comment = comment.strip() if isinstance(comment, str) else ""
        if action != "approve" and not comment:
            raise WorkflowError(400, "invalid_input", "a comment is required for this action")
        if len(comment) > MAX_COMMENT:
            raise WorkflowError(400, "invalid_input", "comment is too long")
        version = self._version(content_id)

        if action == "request_changes":
            with self.store.tx():
                self.store.set_status(content_id, "changes_requested")
                self.store.append_audit(actor.id, "review.changes_requested", {"content_id": content_id, "version": version["n"], "comment": comment})
            return {"status": "changes_requested", "content": self.get_content(actor, content_id)}

        blockers = self._blockers(version)
        by_id = {b["id"]: b for b in blockers}
        applied: List[Dict[str, str]] = []
        for item in overrides or []:
            if not isinstance(item, dict) or item.get("flag_id") not in by_id:
                raise WorkflowError(422, "unknown_flag", "an override refers to a flag that is not a current blocker")
            reason = _need_text(item.get("reason"), "override reason", MAX_COMMENT, MIN_OVERRIDE_REASON)
            applied.append({"flag_id": item["flag_id"], "rule_id": by_id[item["flag_id"]]["rule_id"], "reason": reason})
        overridden = {o["flag_id"] for o in applied}
        unresolved = [{"id": b["id"], "rule_id": b["rule_id"], "text": b["text"], "issue_type": b["issue_type"]}
                      for b in blockers if b["id"] not in overridden]
        if unresolved:
            raise WorkflowError(409, "blockers_open", f"{len(unresolved)} blocking issue(s) are unresolved",
                                {"unresolved_blockers": unresolved})

        decision = "approved" if action == "approve" else "approved_with_conditions"
        with self.store.tx():
            # Atomic approval: re-read status inside the transaction to prevent a
            # check-then-act race where two reviewers approve simultaneously.
            current = self.store.get_content(content_id)
            if not current or current["status"] != "in_review":
                raise WorkflowError(409, "invalid_state",
                                    "content status changed while you were deciding; please refresh and try again")
            for o in applied:
                self.store.add_decision(content_id, version["n"], o["flag_id"], o["rule_id"], "overridden", actor.id, o["reason"])
            receipt = self._issue_receipt(actor, row, version, decision, comment, applied)
            self.store.set_status(content_id, decision)
        return {"status": decision, "receipt": receipt, "content": self.get_content(actor, content_id)}

    def _issue_receipt(self, actor: User, row: Dict[str, Any], version: Dict[str, Any], decision: str,
                       comment: str, overrides: List[Dict[str, str]]) -> Dict[str, Any]:
        review = json.loads(version["review_json"]) if version["review_json"] else {"counts": {}, "checks": [], "ai": {}}
        receipt_id = secrets.token_hex(8)
        audit = self.store.append_audit(actor.id, "review.approved", {
            "content_id": row["id"], "version": version["n"], "decision": decision,
            "content_hash": version["content_hash"], "receipt_id": receipt_id})
        body = {
            "receipt_id": receipt_id, "content_id": row["id"], "version": version["n"],
            "content_hash": version["content_hash"], "decision": decision, "conditions": comment,
            "approver": actor.to_dict(), "approved_at": utc_now_iso(),
            "knowledge_base": {"version": self.kb.version_label, "fingerprint": self.kb.fingerprint},
            "engine_version": ENGINE_VERSION,
            "checks_run": [c["id"] for c in review.get("checks", [])],
            "flag_counts_at_check": review.get("counts", {}),
            "overrides": overrides,
            "ai": {k: review.get("ai", {}).get(k) for k in ("status", "provider", "model", "external")},
            "audit_ref": {"seq": audit["seq"], "hash": audit["hash"]},
            "algorithm": RECEIPT_ALGORITHM,
        }
        signature = sign_body(body, self._key)
        self.store.add_receipt(receipt_id, row["id"], version["n"], body, signature)
        return {"body": body, "signature": signature}

    # ------------------------------------------------------------------ receipts
    def get_receipt(self, actor: User, receipt_id: str) -> Dict[str, Any]:
        rec = self.store.get_receipt(receipt_id)
        if rec is None:
            raise WorkflowError(404, "not_found", "receipt not found")
        self._content(actor, rec["content_id"])  # same visibility as the content
        return {"body": json.loads(rec["body_json"]), "signature": rec["signature"]}

    def verify_receipt(self, actor: User, receipt_id: str) -> Dict[str, Any]:
        rec = self.get_receipt(actor, receipt_id)
        body, signature = rec["body"], rec["signature"]
        version = self.store.get_version(body["content_id"], body["version"])
        chain = self.store.list_audit()
        chain_ok, bad_seq = verify_chain(chain)
        ref = body.get("audit_ref", {})
        entry = next((e for e in chain if e["seq"] == ref.get("seq")), None)
        checks = {
            "signature_valid": verify_signature(body, signature, self._key),
            "content_unchanged": bool(version) and sha256_hex(version["text"]) == body["content_hash"],
            "audit_chain_intact": chain_ok,
            "audit_entry_matches": bool(entry) and entry["hash"] == ref.get("hash"),
        }
        return {"valid": all(checks.values()), "checks": checks, "first_bad_audit_seq": bad_seq, "receipt": rec}

    # ------------------------------------------------------------------ Decision Replay
    def get_decision_replay(self, actor: User, content_id: str, flag_id: str) -> Dict[str, Any]:
        """Return the stored evidence (rule text, model output, version) behind any past flag.

        This fulfils the Round 1 promise: every flag's evidence is stored at check time;
        this endpoint exposes it as a read-only replay view.
        """
        self._content(actor, content_id)  # visibility check
        # Find the decision that handled this flag
        decisions = self.store.list_decisions(content_id)
        matching = [d for d in decisions if d["flag_id"] == flag_id]
        if not matching:
            raise WorkflowError(404, "not_found", "no decision found for that flag id")
        decision = matching[-1]  # most recent decision on this flag
        # Find the version that was checked when this flag appeared
        version_row = self.store.get_version(content_id, decision["version_n"])
        review = json.loads(version_row["review_json"]) if version_row and version_row["review_json"] else None
        flag_evidence = None
        if review:
            flag_evidence = next((f for f in review.get("flags", []) if f["id"] == flag_id), None)
        rule = self.kb.rules.get(decision["rule_id"])
        return {
            "flag_id": flag_id,
            "content_id": content_id,
            "version_n": decision["version_n"],
            "decision": {
                "action": decision["action"],
                "actor_id": decision["actor_id"],
                "reason": decision["reason"],
                "decided_at": decision["created_at"],
            },
            "rule": {"id": rule.id, "title": rule.title, "text": rule.text, "clause": rule.clause} if rule else None,
            "flag_evidence": flag_evidence,
            "text_at_check": version_row["text"] if version_row else None,
        }

    # ------------------------------------------------------------------ update title
    def update_title(self, actor: User, content_id: str, title: Any) -> Dict[str, Any]:
        """Allow an author to rename their content item at any time (except while in_review)."""
        row = self._content(actor, content_id, edit=True)
        self._locked(row)
        title = _need_text(title, "title", MAX_TITLE)
        self.store.update_title(content_id, title)
        self.store.append_audit(actor.id, "content.title_updated", {"content_id": content_id, "title": title})
        return {"id": content_id, "title": title}

    def add_comment(self, actor: User, content_id: str, start: Any, end: Any, body: Any) -> Dict[str, Any]:
        self._content(actor, content_id)
        version = self._version(content_id)
        body = _need_text(body, "comment", MAX_COMMENT)
        ok = all(isinstance(v, int) and not isinstance(v, bool) for v in (start, end))
        if not ok or not 0 <= start <= end <= len(version["text"]):
            raise WorkflowError(400, "invalid_input", "comment range is outside the text")
        cid = self.store.add_comment(content_id, version["n"], start, end, body, actor.id)
        self.store.append_audit(actor.id, "comment.added", {"content_id": content_id, "comment": cid})
        return {"id": cid}

    def resolve_comment(self, actor: User, content_id: str, comment_id: int) -> Dict[str, Any]:
        self._content(actor, content_id)
        if not self.store.resolve_comment(content_id, comment_id):
            raise WorkflowError(404, "not_found", "comment not found")
        self.store.append_audit(actor.id, "comment.resolved", {"content_id": content_id, "comment": comment_id})
        return {"resolved": comment_id}

    def diff(self, actor: User, content_id: str, a: int, b: int) -> List[Dict[str, str]]:
        self._content(actor, content_id)
        old, new = self._version(content_id, a)["text"], self._version(content_id, b)["text"]
        split = lambda t: re.findall(r"\s+|[^\s]+", t)  # noqa: E731
        ow, nw = split(old), split(new)
        ops: List[Dict[str, str]] = []
        for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=ow, b=nw, autojunk=False).get_opcodes():
            ops.append({"op": tag, "old": "".join(ow[i1:i2]), "new": "".join(nw[j1:j2])})
        return ops

    # ------------------------------------------------------------------ insights and audit
    def insights(self, actor: User) -> Dict[str, Any]:
        self.require(actor, "insights:view")
        shown = self.store.exposure_counts()
        tallies: Dict[str, Dict[str, int]] = {}
        for row in self.store.decision_counts():
            tallies.setdefault(row["rule_id"], {})[row["action"]] = row["c"]
        rules = []
        for rule in self.kb.rules.values():
            t = tallies.get(rule.id, {})
            n = shown.get(rule.id, 0)
            disputed = t.get("dismissed", 0) + t.get("overridden", 0)
            rate = round(min(1.0, disputed / n), 2) if n else None
            if n < self.settings.min_samples_for_health:
                status = "not_enough_data"
            elif rate is not None and rate >= self.settings.health_dispute_threshold:
                status = "unclear"
            else:
                status = "healthy"
            rules.append({"rule_id": rule.id, "title": rule.title, "clause": rule.clause, "shown": n,
                          "accepted": t.get("accepted", 0), "dismissed": t.get("dismissed", 0),
                          "overridden": t.get("overridden", 0), "dispute_rate": rate, "status": status})
        rules.sort(key=lambda r: (-r["shown"], r["rule_id"]))
        by_status: Dict[str, int] = {}
        for c in self.store.list_content():
            by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        return {"rules": rules, "content_by_status": by_status, "min_samples": self.settings.min_samples_for_health,
                "dispute_threshold": self.settings.health_dispute_threshold}

    def audit(self, actor: User, limit: int = 100) -> Dict[str, Any]:
        self.require(actor, "audit:view")
        ok, bad = verify_chain(self.store.list_audit())
        return {"chain_intact": ok, "first_bad_seq": bad, "entries": self.store.list_audit(limit)}
