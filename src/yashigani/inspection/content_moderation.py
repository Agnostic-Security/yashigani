"""
Yashigani Inspection — content moderation / unsafe-topic filtering (A12, 5.0).

Register §A.12: every serious competitor (Cloudflare/Llama-Guard, Lakera,
Portkey, Cisco AI Defense) ships harmful-content / topic / toxicity filtering;
Yashigani did not. This is DISTINCT from injection (A1) and PII — it is safety
filtering: an admin-tunable set of categories, applied to prompts AND responses.

Design constraints:
- Dual-use aware (register): the categories and their action are POLICY, set by
  the operator per deployment — this module ships the mechanism, not a fixed
  moral line. Default policy is EMPTY (no category enabled) → the guard is a
  no-op until the operator configures it. It never false-positives out of the box.
- Pluggable detection: a fast pattern baseline is built in; a Llama-Guard-class
  model backend can be attached (attach_backend) for semantic recall. The
  backend is advisory — a category hit from either source counts.
- Per-category action: "block" (fail-closed deny) or "flag" (allow + audit).
  When any matched category is a block-category the verdict blocks.

This module is model-free by default and fully testable offline; the optional
LLM backend is the live-stack piece.
"""
from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, Protocol

logger = logging.getLogger(__name__)

ACTION_BLOCK = "block"
ACTION_FLAG = "flag"
ACTION_ALLOW = "allow"


class ModerationBackend(Protocol):
    def categories_for(self, text: str) -> list[str]: ...


@dataclass
class CategoryRule:
    name: str
    action: str  # block | flag
    patterns: list[str] = field(default_factory=list)
    _compiled: list = field(default_factory=list, repr=False)

    def compile(self) -> "CategoryRule":
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]
        return self

    def matches(self, normalized_text: str) -> bool:
        return any(rx.search(normalized_text) for rx in self._compiled)


@dataclass
class ModerationResult:
    action: str  # block | flag | allow
    categories: list[str] = field(default_factory=list)
    content_hash: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == ACTION_BLOCK

    @property
    def flagged(self) -> bool:
        return self.action in (ACTION_BLOCK, ACTION_FLAG)


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class ContentModerationGuard:
    """Admin-tunable content-safety filter. Empty policy → no-op (allow-all)."""

    def __init__(self) -> None:
        self._rules: dict[str, CategoryRule] = {}
        self._backend: Optional[ModerationBackend] = None
        # category name → action, for categories the backend may report
        self._backend_actions: dict[str, str] = {}

    # ── configuration ───────────────────────────────────────────────────────
    def set_policy(self, rules: list[CategoryRule]) -> None:
        self._rules = {r.name: r.compile() for r in rules}
        logger.info("A12 content-moderation policy set: %d categor(y/ies)", len(self._rules))

    def attach_backend(self, backend: ModerationBackend,
                       category_actions: Optional[dict[str, str]] = None) -> None:
        """Attach a Llama-Guard-class backend. category_actions maps a
        backend-reported category to block/flag; unknown categories default to
        flag (surface, don't hard-block on an unmapped model label)."""
        self._backend = backend
        self._backend_actions = dict(category_actions or {})

    @property
    def active(self) -> bool:
        return bool(self._rules) or self._backend is not None

    # ── evaluation ──────────────────────────────────────────────────────────
    def moderate(self, text: str) -> ModerationResult:
        if not text or not self.active:
            return ModerationResult(action=ACTION_ALLOW)

        normalized = _normalize(text)
        matched: dict[str, str] = {}  # category → action

        for name, rule in self._rules.items():
            if rule.matches(normalized):
                matched[name] = rule.action

        if self._backend is not None:
            try:
                for cat in self._backend.categories_for(text):
                    if cat not in matched:
                        matched[cat] = self._backend_actions.get(cat, ACTION_FLAG)
            except Exception as exc:  # noqa: BLE001
                # A backend error must not silently pass content: surface it as a
                # flag on a synthetic category so the operator sees the gap.
                logger.warning("A12 moderation backend error: %s", exc)
                matched["moderation_backend_error"] = ACTION_FLAG

        if not matched:
            return ModerationResult(action=ACTION_ALLOW)

        action = ACTION_BLOCK if ACTION_BLOCK in matched.values() else ACTION_FLAG
        return ModerationResult(
            action=action,
            categories=sorted(matched.keys()),
            content_hash=_hash(text),
        )
