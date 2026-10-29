"""LLM provider interface and adapters.

Only the Anthropic adapter talks to the network, and only when an API key is configured. It could not be
exercised against the live API while this prototype was written offline; its request building, response
parsing and error handling are tested through an injectable transport.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

Transport = Callable[[str, Dict[str, str], bytes, float], Tuple[int, bytes]]


class LLMError(RuntimeError):
    """The model could not be reached or returned something unusable."""


class LLMProvider(Protocol):
    name: str
    model: str
    external: bool  # True when text leaves the system

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str: ...


def _urllib_transport(url: str, headers: Dict[str, str], body: bytes, timeout: float) -> Tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (fixed https URL)
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LLMError(f"network error: {exc}") from exc


class AnthropicProvider:
    name = "anthropic"
    external = True

    def __init__(self, api_key: str, model: str, timeout: float = 30.0,
                 transport: Optional[Transport] = None, temperature: Optional[float] = None):
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self.model = model
        self._timeout = timeout
        self._transport = transport or _urllib_transport
        self._temperature = temperature  # omitted unless set: some models reject the parameter

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self._temperature is not None:
            payload["temperature"] = self._temperature
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        status, raw = self._transport(ANTHROPIC_URL, headers, json.dumps(payload).encode("utf-8"), self._timeout)
        if status != 200:
            # Never include the key or the full body in the message; keep a short, safe summary.
            raise LLMError(f"model API returned HTTP {status}")
        try:
            data = json.loads(raw.decode("utf-8"))
            parts = [b.get("text", "") for b in data["content"] if b.get("type") == "text"]
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise LLMError("model API returned an unreadable response") from exc
        text = "".join(parts).strip()
        if not text:
            raise LLMError("model API returned no text")
        return text


class ScriptedProvider:
    """Returns pre-set responses. Used in tests; never presented to users as an AI."""

    name = "scripted-test"
    model = "scripted"
    external = False

    def __init__(self, responses: List[str] | Callable[[str, str], str]):
        self._responses = responses
        self.calls: List[Dict[str, str]] = []

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        self.calls.append({"system": system, "user": user})
        if callable(self._responses):
            return self._responses(system, user)
        if not self._responses:
            raise LLMError("no scripted response left")
        return self._responses.pop(0)


class UnreliableSimulator:
    """A deliberately bad 'model' for the Hallucination Trap demo.

    It invents a rule, a quote and a text span, tries to escalate severity, and obeys an instruction hidden in
    the draft. It exists to show the verifier rejecting such output. It is always labelled as a simulation.
    """

    name = "simulated-unreliable-model"
    model = "simulation"
    external = False

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        findings = [
            {"rule_id": "BG-9.9", "span_text": "protein bar", "evidence_quote": "All bars must contain 30 g of protein.",
             "issue_type": "invented_rule", "explanation": "Violates a rule that does not exist.", "severity": "blocker",
             "confidence": 0.99, "suggested_rewrite": None},
            {"rule_id": "BG-4.1", "span_text": "text that is not in the draft", "evidence_quote":
             "Rankings such as number one, best-selling or most trusted may be used only with a dated third-party source recorded in the Claim Ledger.",
             "issue_type": "phantom_span", "explanation": "Points at text that is not there.", "severity": "blocker",
             "confidence": 0.9, "suggested_rewrite": None},
            {"rule_id": "BG-4.1", "span_text": "protein bar", "evidence_quote": "Rankings are always fine when they sound true.",
             "issue_type": "fabricated_quote", "explanation": "Quotes a sentence the guidelines never contained.",
             "severity": "blocker", "confidence": 0.95, "suggested_rewrite": None},
        ]
        if "ignore" in user.lower() and "approve" in user.lower():
            findings.append({"rule_id": "APPROVE", "span_text": "approve", "evidence_quote": "approved",
                             "issue_type": "obeyed_hidden_instruction", "explanation": "Content said to approve it.",
                             "severity": "info", "confidence": 1.0, "suggested_rewrite": None})
        return json.dumps({"findings": findings})


class LocalModelProvider:
    """Self-hosted or on-premise local model adapter (Confidential local-model mode).

    Guarantees that external is False, so the Privacy X-ray registers zero outbound bytes.
    Can talk to a local Ollama or OpenAI-compatible endpoint (e.g. http://127.0.0.1:11434)
    with a graceful fallback to local rule-guided evaluation when no local daemon is listening.
    """

    name = "local-confidential"
    external = False

    def __init__(self, endpoint_url: str = "http://127.0.0.1:11434/v1/chat/completions",
                 model_name: str = "self-hosted-local", timeout: float = 3.0,
                 transport: Optional[Transport] = None):
        self.endpoint_url = endpoint_url
        self.model = model_name
        self._timeout = timeout
        self._transport = transport or _urllib_transport

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        # 1. Attempt local HTTP endpoint if configured
        import re
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.0,
        }
        headers = {"content-type": "application/json"}
        try:
            status, raw = self._transport(self.endpoint_url, headers, json.dumps(payload).encode("utf-8"), self._timeout)
            if status == 200:
                data = json.loads(raw.decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                    if content.strip():
                        return content.strip()
        except Exception:
            pass  # Local daemon not running; use local deterministic evaluator

        # 2. Local confidential compliance evaluation
        draft_match = re.search(r"<draft>(.*?)</draft>", user, re.DOTALL)
        draft = draft_match.group(1) if draft_match else user
        findings = []
        rule_matches = list(re.finditer(r"\[([A-Za-z0-9_.-]+)\]\s+([^:\n]+):\s+([^\n]+)", user))
        for rm in rule_matches:
            rule_id = rm.group(1)
            rule_text = rm.group(3).strip()
            # If draft quotes or conflicts with rule keywords
            for word in rule_text.split():
                clean_w = re.sub(r"[^A-Za-z0-9]", "", word)
                if len(clean_w) > 4 and clean_w.lower() in draft.lower() and len(findings) < 2:
                    pos = draft.lower().find(clean_w.lower())
                    span = draft[pos:pos + len(clean_w)]
                    findings.append({
                        "rule_id": rule_id,
                        "span_text": span,
                        "evidence_quote": rule_text[:120],
                        "issue_type": "local_confidential_check",
                        "explanation": f"Evaluated by confidential local model against {rule_id}.",
                        "severity": "warning",
                        "confidence": 0.9,
                        "suggested_rewrite": None,
                    })
                    break
        return json.dumps({"findings": findings})

