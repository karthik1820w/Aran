"""Application factory: wires configuration, knowledge, review service, store and workflow together."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .config import Settings
from .engine import ReviewEngine
from .knowledge import KnowledgeBase
from .llm import AnthropicProvider, LLMProvider
from .service import ReviewService
from .store import Store
from .workflow import WorkflowService

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(PACKAGE_DIR, "web")


@dataclass
class App:
    settings: Settings
    store: Store
    kb: KnowledgeBase
    reviews: ReviewService
    workflow: WorkflowService


def build_app(settings: Settings, provider: Optional[LLMProvider] = None) -> App:
    kb_path = settings.kb_path
    if not os.path.isabs(kb_path) and not os.path.exists(kb_path):
        kb_path = os.path.join(os.path.dirname(PACKAGE_DIR), kb_path)  # resolve relative to the project root
    kb = KnowledgeBase.from_file(kb_path)
    engine = ReviewEngine(kb, max_chars=settings.max_text_chars)
    if provider is None and settings.ai_enabled:
        provider = AnthropicProvider(settings.anthropic_api_key or "", settings.anthropic_model)
    reviews = ReviewService(engine, provider, simulator_allowed=settings.demo_mode)
    store = Store(settings.db_path)
    workflow = WorkflowService(store, reviews, settings)
    if settings.demo_mode:
        workflow.seed_demo_users()
    return App(settings, store, kb, reviews, workflow)
