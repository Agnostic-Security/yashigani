"""
Yashigani Inspection — LLM→mechanical rule promotion (T1, 5.0).

The learning loop (Tiago): when the hardened LLM inspector catches a NOVEL
injection that the deterministic mechanical filter missed, distil it into a
candidate mechanical rule. After dual-control approval it joins the active
ruleset, so the NEXT instance of that pattern is blocked mechanically — cheaply,
deterministically, and WITHOUT touching the LLM. Over time the LLM's exposure
shrinks and the fast path covers more.

Safety by construction:
  - Candidate patterns are ESCAPED LITERALS of a distinctive, marker-anchored
    window of the (normalised) payload — never a model-authored free regex. This
    caps false-positive blast radius: a promoted rule matches that phrase, not a
    broad class.
  - A candidate is PENDING until a DIFFERENT admin approves it (re-supplying the
    confirming pattern, byte-compared) — the same corrected dual-control shape as
    the model-integrity / rug-pull gates. Nothing auto-activates.
  - Write-ahead durable audit on propose/approve/reject.
  - The active ruleset is a bounded, hot-reloadable set the mechanical layer
    consults in addition to its built-in patterns.

This module is deterministic + model-free; the LLM only PRODUCES the detection
that seeds a proposal — it never gets to author or activate a rule.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import unicodedata
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_PENDING_PREFIX = "yashigani:rulepromo:pending:"
_ACTIVE_KEY = "yashigani:rulepromo:active"
_PENDING_TTL_SECONDS = 7 * 24 * 3600
_MAX_ACTIVE_RULES = 2000
_MIN_MARKER_WINDOW_WORDS = 3
_MAX_MARKER_WINDOW_WORDS = 8

_WORD_RE = re.compile(r"\w+", re.UNICODE)

# Markers that make a window worth promoting (an anchor of injection intent).
_ANCHOR_MARKERS = (
    "ignore", "disregard", "forget", "override", "bypass", "system prompt",
    "your instructions", "you are now", "act as", "pretend", "reveal",
    "jailbreak", "developer mode", "dan mode", "exfiltrate", "no longer",
    "from now on", "new instructions",
)


class RulePromotionError(Exception):
    """Invalid propose/approve (self-approval, mismatch, no pending)."""


class RuleStoreUnavailableError(Exception):
    """Store unreachable — callers degrade gracefully (promotion is advisory)."""


def _normalize(text: str) -> str:
    """Match the built-in mechanical filter's obfuscation-defeating normalisation
    (NFKC + Cf-strip + homoglyph + leet), then casefold — so a promoted rule is
    no more evadable than a built-in one. Falls back to NFKC+casefold if the
    filter module is unavailable."""
    try:
        from yashigani.mcp._content_filter import normalize_for_detection
        return normalize_for_detection(text).casefold()
    except Exception:
        return unicodedata.normalize("NFKC", text).casefold()


def derive_candidate_patterns(content: str) -> list[str]:
    """Deterministically derive escaped-literal candidate patterns from a
    flagged payload: distinctive marker-anchored word windows. Returns [] when
    nothing distinctive is found (then no promotion is proposed)."""
    if not content:
        return []
    norm = _normalize(content)
    words = _WORD_RE.findall(norm)
    if not words:
        return []
    joined = " ".join(words)
    out: list[str] = []
    for marker in _ANCHOR_MARKERS:
        idx = joined.find(marker)
        if idx == -1:
            continue
        # Build a bounded window of words around the marker for specificity.
        m_words = marker.split()
        # locate marker start in the word list
        for i in range(len(words) - len(m_words) + 1):
            if words[i:i + len(m_words)] == m_words:
                # Anchor the window AT the marker (+ a few following words), not
                # before it — so the promoted rule matches the injection CORE
                # regardless of the benign lead-in the attacker varies.
                end = min(len(words), i + len(m_words) + 3)
                window = words[i:end]
                if len(window) < _MIN_MARKER_WINDOW_WORDS:
                    window = words[i:i + _MIN_MARKER_WINDOW_WORDS]
                window = window[:_MAX_MARKER_WINDOW_WORDS]
                phrase = " ".join(window)
                # Escaped literal, whitespace-flexible between tokens.
                pattern = r"\b" + r"\s+".join(re.escape(w) for w in phrase.split()) + r"\b"
                if pattern not in out:
                    out.append(pattern)
                break
    return out[:3]  # at most a few candidates per detection


@dataclass
class CandidateRule:
    candidate_id: str
    pattern: str
    source: str
    initiated_by: str


class RulePromotionStore:
    """Dual-control store for promoted mechanical rules (Redis-backed)."""

    def __init__(self, redis_client, audit_writer=None) -> None:
        self._r = redis_client
        self._audit = audit_writer

    # ── propose (seeded by an LLM novel detection) ──────────────────────────
    def propose_from_detection(
        self, content: str, initiated_by: str, source: str = "llm_novel_detection",
    ) -> list[str]:
        """Derive candidate patterns from a flagged payload and store each
        PENDING. Returns the candidate ids created. Idempotent on pattern:
        a pattern already pending or active is skipped."""
        patterns = derive_candidate_patterns(content)
        if not patterns:
            return []
        try:
            active = set(self.active_patterns())
        except RuleStoreUnavailableError:
            active = set()
        created: list[str] = []
        for pat in patterns:
            if pat in active or self._pattern_is_pending(pat):
                continue
            cid = uuid.uuid4().hex
            rec = {"candidate_id": cid, "pattern": pat, "source": source,
                   "initiated_by": initiated_by}
            self._audit_or_log("RULE_PROMOTION_PROPOSED", cid, pat, source,
                               initiated_by, "", "proposed")
            try:
                self._r.set(_PENDING_PREFIX + cid, json.dumps(rec),
                            ex=_PENDING_TTL_SECONDS)
            except Exception as exc:  # noqa: BLE001
                raise RuleStoreUnavailableError(str(exc)) from exc
            created.append(cid)
            logger.warning(
                "RULE_PROMOTION_PROPOSED candidate=%s pattern=%r source=%s by=%s",
                cid, pat, source, initiated_by)
        return created

    # ── dual-control approval ───────────────────────────────────────────────
    def approve(self, candidate_id: str, approver_id: str, confirming_pattern: str) -> str:
        raw = self._get(_PENDING_PREFIX + candidate_id)
        if not raw:
            raise RulePromotionError("No pending rule-promotion candidate with that id.")
        rec = json.loads(raw)
        if rec["initiated_by"] == approver_id:
            raise RulePromotionError("The approver must differ from the proposer.")
        if confirming_pattern != rec["pattern"]:
            self._audit_or_log("RULE_PROMOTION_REJECTED", candidate_id,
                               confirming_pattern, rec["source"], rec["initiated_by"],
                               approver_id, "rejected")
            raise RulePromotionError("Confirming pattern does not match the candidate.")
        # Write-ahead audit before activating.
        self._audit_or_log("RULE_PROMOTION_APPROVED", candidate_id, rec["pattern"],
                           rec["source"], rec["initiated_by"], approver_id, "approved")
        self._add_active(rec["pattern"])
        try:
            self._r.delete(_PENDING_PREFIX + candidate_id)
        except Exception:  # pragma: no cover
            pass
        logger.warning("RULE_PROMOTION_APPROVED candidate=%s pattern=%r by=%s",
                       candidate_id, rec["pattern"], approver_id)
        return rec["pattern"]

    def reject(self, candidate_id: str, approver_id: str) -> None:
        raw = self._get(_PENDING_PREFIX + candidate_id)
        if not raw:
            return
        rec = json.loads(raw)
        self._audit_or_log("RULE_PROMOTION_REJECTED", candidate_id, rec["pattern"],
                           rec["source"], rec["initiated_by"], approver_id, "rejected")
        try:
            self._r.delete(_PENDING_PREFIX + candidate_id)
        except Exception:  # pragma: no cover
            pass

    # ── active ruleset ──────────────────────────────────────────────────────
    def active_patterns(self) -> list[str]:
        try:
            raw = self._r.get(_ACTIVE_KEY)
        except Exception as exc:  # noqa: BLE001
            raise RuleStoreUnavailableError(str(exc)) from exc
        if not raw:
            return []
        return json.loads(raw if isinstance(raw, str) else raw.decode())

    def _add_active(self, pattern: str) -> None:
        try:
            current = self.active_patterns()
        except RuleStoreUnavailableError:
            current = []
        if pattern in current:
            return
        current.append(pattern)
        if len(current) > _MAX_ACTIVE_RULES:
            current = current[-_MAX_ACTIVE_RULES:]
        try:
            self._r.set(_ACTIVE_KEY, json.dumps(current))
        except Exception as exc:  # noqa: BLE001
            raise RuleStoreUnavailableError(str(exc)) from exc

    # ── internals ───────────────────────────────────────────────────────────
    def _get(self, key: str) -> Optional[str]:
        try:
            raw = self._r.get(key)
        except Exception as exc:  # noqa: BLE001
            raise RuleStoreUnavailableError(str(exc)) from exc
        if raw is None:
            return None
        return raw if isinstance(raw, str) else raw.decode()

    def _pattern_is_pending(self, pattern: str) -> bool:
        try:
            for key in self._r.scan_iter(_PENDING_PREFIX + "*"):
                raw = self._r.get(key)
                if not raw:
                    continue
                rec = json.loads(raw if isinstance(raw, str) else raw.decode())
                if rec.get("pattern") == pattern:
                    return True
        except Exception:  # noqa: BLE001 — pending-dedup is best-effort
            return False
        return False

    def _audit_or_log(self, event_type, cid, pattern, source, initiated_by,
                      approver, action) -> None:
        try:
            from yashigani.metrics.registry import rule_promotion_total
            rule_promotion_total.labels(event=action).inc()
        except Exception:  # pragma: no cover
            pass
        if self._audit is None:
            return
        from yashigani.audit.schema import RulePromotionEvent, EventType
        self._audit.write(RulePromotionEvent(
            event_type=getattr(EventType, event_type),
            candidate_id=cid, pattern=pattern, source=source,
            initiated_by=initiated_by, approver=approver, action_taken=action,
        ))


class PromotedRuleset:
    """Compiled view of the approved promoted patterns the mechanical layer
    consults alongside its built-ins. Self-refreshing: matches() reloads from
    the store when the cached view is older than refresh_interval, so an
    approved rule takes effect within that window without a gateway restart —
    no admin-side plumbing required for the loop to close."""

    def __init__(self, store: RulePromotionStore, refresh_interval_s: float = 30.0) -> None:
        self._store = store
        self._compiled: list[tuple[str, "re.Pattern[str]"]] = []
        self._interval = refresh_interval_s
        self._last_refresh: Optional[float] = None

    def refresh(self) -> int:
        try:
            patterns = self._store.active_patterns()
        except RuleStoreUnavailableError:
            return len(self._compiled)  # keep the last-known good set
        compiled = []
        for p in patterns:
            try:
                compiled.append((p, re.compile(p, re.IGNORECASE)))
            except re.error:
                logger.warning("promoted rule failed to compile, skipping: %r", p)
        self._compiled = compiled
        import time as _time
        self._last_refresh = _time.monotonic()
        return len(self._compiled)

    def _maybe_refresh(self) -> None:
        import time as _time
        now = _time.monotonic()
        if self._last_refresh is None or (now - self._last_refresh) >= self._interval:
            self.refresh()

    def matches(self, text: str) -> Optional[str]:
        if not text:
            return None
        self._maybe_refresh()
        norm = _normalize(text)
        for pattern, rx in self._compiled:
            if rx.search(norm):
                return pattern
        return None

    @property
    def size(self) -> int:
        return len(self._compiled)
