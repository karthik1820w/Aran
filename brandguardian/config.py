"""Runtime configuration, read from environment variables with safe defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, Optional


def _as_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Optional[str], default: int, low: int, high: int) -> int:
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"expected an integer, got {value!r}") from exc
    if not low <= parsed <= high:
        raise ValueError(f"value {parsed} outside allowed range {low}..{high}")
    return parsed


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8000
    db_path: str = ":memory:"
    kb_path: str = "data/demo_brand.json"
    demo_mode: bool = False  # off by default; set BG_DEMO=1 explicitly for demos
    signing_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-sonnet-5-5"
    max_body_bytes: int = 1_000_000
    max_text_chars: int = 50_000
    rate_limit_per_minute: int = 240
    min_samples_for_health: int = 5
    health_dispute_threshold: float = 0.4
    session_ttl_hours: int = 8        # sessions expire after this many hours
    max_json_depth: int = 10          # reject deeply nested JSON bodies

    @property
    def ai_enabled(self) -> bool:
        return bool(self.anthropic_api_key)


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Build Settings from an environment mapping (defaults to os.environ)."""
    e = os.environ if env is None else env
    return Settings(
        host=e.get("BG_HOST", "127.0.0.1"),
        port=_as_int(e.get("BG_PORT"), 8000, 0, 65535),
        db_path=e.get("BG_DB_PATH", ":memory:"),
        kb_path=e.get("BG_KB_PATH", "data/demo_brand.json"),
        demo_mode=_as_bool(e.get("BG_DEMO"), False),  # off by default
        signing_key=e.get("BG_SIGNING_KEY") or None,
        anthropic_api_key=e.get("ANTHROPIC_API_KEY") or None,
        anthropic_model=e.get("BG_MODEL", "claude-sonnet-5-5"),
        max_body_bytes=_as_int(e.get("BG_MAX_BODY_BYTES"), 1_000_000, 1_000, 50_000_000),
        max_text_chars=_as_int(e.get("BG_MAX_TEXT_CHARS"), 50_000, 100, 1_000_000),
        rate_limit_per_minute=_as_int(e.get("BG_RATE_LIMIT_PER_MINUTE"), 240, 1, 100_000),
        min_samples_for_health=_as_int(e.get("BG_MIN_SAMPLES"), 5, 1, 10_000),
        health_dispute_threshold=float(e.get("BG_HEALTH_THRESHOLD", "0.4")),
        session_ttl_hours=_as_int(e.get("BG_SESSION_TTL_HOURS"), 8, 1, 720),
        max_json_depth=_as_int(e.get("BG_MAX_JSON_DEPTH"), 10, 2, 100),
    )
