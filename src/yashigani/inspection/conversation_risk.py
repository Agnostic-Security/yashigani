"""
Yashigani Inspection — multi-turn / slow-burn conversational injection (5.0).

The problem (Tiago): modern prompt-injection is nuanced. The attack is not one
message a regex or a single-message classifier can catch — it unfolds over many
turns, goes on benign tangents to look innocent, primes context, gradually
shifts role, and only pivots to the payload late. Per-message detection is blind
to the TRAJECTORY.

Approach — a per-conversation risk ACCUMULATOR:
  - Each turn contributes a bounded risk score from cheap signals (mechanical
    near-misses, the hardened LLM's "is this building toward an attack" score,
    instruction-shaped language, role-shift markers, topic drift).
  - The accumulator DECAYS each turn but does not reset — so interleaved benign
    tangents lower it slowly without erasing a building attack, while sustained
    probing crosses a threshold.
  - Crossing thresholds escalates: flag → step_up → block. A single benign
    conversation never accumulates; a slow-burn attack does.

This is the sequence layer that sits ABOVE the per-message mechanical+LLM
checks. It is model-free itself (it consumes signals others produce), so it is
cheap and not itself an exploitable LLM surface. State is per-session and
short-lived (a conversation), pluggable behind a simple store interface.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

ACTION_ALLOW = "allow"
ACTION_FLAG = "flag"
ACTION_STEP_UP = "step_up"
ACTION_BLOCK = "block"

# Decay per turn: benign turns shrink the accumulator ~15%/turn, so an
# interleaved tangent does not reset a building attack but a genuinely benign
# conversation trends to zero.
_DEFAULT_DECAY = 0.85
_FLAG_THRESHOLD = 0.55
_STEP_UP_THRESHOLD = 0.75
_BLOCK_THRESHOLD = 1.0
# Per-turn contribution is clamped so one loud turn cannot alone cross BLOCK
# (that is the per-message layer's job); the sequence layer needs SUSTAINED signal.
_MAX_TURN_CONTRIBUTION = 0.6


@dataclass
class TurnSignals:
    """Signals extracted for a single turn by the cheaper per-message layers."""
    mechanical_soft: float = 0.0     # 0-1: near-miss / softer pattern density
    llm_suspicion: float = 0.0       # 0-1: hardened reviewer "building-toward-attack" score
    instruction_shaped: bool = False  # imperative/override-shaped language present
    role_shift: bool = False         # "you are now" / persona-pivot markers
    topic_drift: float = 0.0         # 0-1: drift from the established conversation topic

    def contribution(self) -> tuple[float, dict]:
        parts = {
            "mechanical_soft": 0.35 * _clamp(self.mechanical_soft),
            "llm_suspicion": 0.40 * _clamp(self.llm_suspicion),
            "instruction_shaped": 0.15 if self.instruction_shaped else 0.0,
            "role_shift": 0.20 if self.role_shift else 0.0,
            "topic_drift": 0.10 * _clamp(self.topic_drift),
        }
        raw = sum(parts.values())
        return min(_MAX_TURN_CONTRIBUTION, raw), parts


@dataclass
class ConversationVerdict:
    action: str
    accumulated_score: float
    turn_count: int
    signal_breakdown: dict = field(default_factory=dict)

    @property
    def escalated(self) -> bool:
        return self.action != ACTION_ALLOW


@dataclass
class _SessionState:
    score: float = 0.0
    turns: int = 0


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


class ConversationRiskTracker:
    """Per-session accumulate-decay-threshold tracker for slow-burn injection.

    Thread-safety: the default in-memory store is a plain dict guarded by the
    GIL for single-process use; pass a Redis-backed store for multi-instance.
    """

    def __init__(
        self,
        decay: float = _DEFAULT_DECAY,
        flag_threshold: float = _FLAG_THRESHOLD,
        step_up_threshold: float = _STEP_UP_THRESHOLD,
        block_threshold: float = _BLOCK_THRESHOLD,
        max_sessions: int = 10000,
    ) -> None:
        if not 0.0 < decay < 1.0:
            raise ValueError("decay must be in (0, 1)")
        self._decay = decay
        self._flag = flag_threshold
        self._step_up = step_up_threshold
        self._block = block_threshold
        self._sessions: dict[str, _SessionState] = {}
        self._max_sessions = max_sessions

    def observe(self, session_id: str, signals: TurnSignals) -> ConversationVerdict:
        key = session_id or "anonymous"
        st = self._sessions.get(key)
        if st is None:
            if len(self._sessions) >= self._max_sessions:
                # Simple bound: drop an arbitrary session. Conversation state is
                # short-lived; a dropped accumulator just restarts at 0 (safe —
                # the per-message layers still run every turn).
                self._sessions.pop(next(iter(self._sessions)), None)
            st = _SessionState()
            self._sessions[key] = st

        contribution, breakdown = signals.contribution()
        st.score = round(self._decay * st.score + contribution, 6)
        st.turns += 1

        if st.score >= self._block:
            action = ACTION_BLOCK
        elif st.score >= self._step_up:
            action = ACTION_STEP_UP
        elif st.score >= self._flag:
            action = ACTION_FLAG
        else:
            action = ACTION_ALLOW

        if action != ACTION_ALLOW:
            logger.warning(
                "CONVERSATION RISK %s session=%s score=%.3f turns=%d breakdown=%s",
                action.upper(), key, st.score, st.turns, breakdown,
            )
        return ConversationVerdict(
            action=action,
            accumulated_score=st.score,
            turn_count=st.turns,
            signal_breakdown=breakdown,
        )

    def reset(self, session_id: str) -> None:
        """Clear a session's accumulator (e.g. after a step-up is satisfied or
        the conversation ends)."""
        self._sessions.pop(session_id or "anonymous", None)

    def score_for(self, session_id: str) -> float:
        st = self._sessions.get(session_id or "anonymous")
        return st.score if st else 0.0


# ── cheap signal extraction (model-free) ────────────────────────────────────

_INSTRUCTION_MARKERS = (
    "ignore", "disregard", "forget", "override", "bypass", "instead of",
    "from now on", "no longer", "new instructions", "new rules",
)
_ROLE_SHIFT_MARKERS = (
    "you are now", "you are no longer", "act as", "pretend", "roleplay",
    "role-play", "you're now", "behave as", "imagine you are",
)


def extract_turn_signals(
    text: str,
    llm_suspicion: float = 0.0,
    mechanical_soft: float = 0.0,
) -> TurnSignals:
    """Derive per-turn signals from the message text + any scores the
    per-message layers already computed. Deliberately cheap + deterministic
    (lowercased substring markers) — the sequence layer must not add an
    exploitable LLM call of its own; llm_suspicion is passed IN from the
    already-hardened per-message reviewer when available."""
    low = (text or "").lower()
    instruction_shaped = any(m in low for m in _INSTRUCTION_MARKERS)
    role_shift = any(m in low for m in _ROLE_SHIFT_MARKERS)
    return TurnSignals(
        mechanical_soft=_clamp(mechanical_soft),
        llm_suspicion=_clamp(llm_suspicion),
        instruction_shaped=instruction_shaped,
        role_shift=role_shift,
    )
