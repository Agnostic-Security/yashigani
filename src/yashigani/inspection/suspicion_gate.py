"""
Yashigani Inspection — suspicion gate (5.0): decide WHO gets the LLM.

The design constraint (Tiago): do NOT send every message to the LLM inspector.
That is expensive, slow, and needlessly exposes the LLM to attacker content. We
only want the LLM to review the SUSPICIOUS prompts. The genuinely hard part is
distinguishing "suspicious" from "normal" — cheaply and DETERMINISTICALLY,
because if the LLM had to make that call we would be sending everything to it
anyway.

Three-tier flow (per message):
    mechanical hard-hit   → BLOCK           (deterministic; the LLM never runs)
    suspicion gate CLEAN  → PASS            (the LLM never runs — the common case)
    suspicion gate SUSPECT→ escalate to LLM (only here does the LLM read content)

This module is the middle decision. It is model-free (markers + structure +
obfuscation + optional cheap sklearn-uncertain + the multi-turn accumulator), so
it adds no exploitable LLM surface, and it keeps the LLM's exposure to a small
fraction of traffic. Normal conversational language has none of these signals →
it never reaches the LLM.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field

# YSG-RISK-319: the gate must score on the DECODED detection surface, not raw
# text. It computes this itself rather than trusting the caller's normalized_text
# — the never-escalate P0 was exactly a caller passing the forward text
# (safe_text, un-decoded) so the markers matched nothing. _content_filter does
# not import inspection, so this is not circular.
from yashigani.mcp._content_filter import (
    _decode_hidden_codepoints,
    normalize_for_detection,
)

logger = logging.getLogger(__name__)

# Imperative/override-shaped language: present in injection, rare in a normal
# question. Word-boundaried, lowercased match.
_INSTRUCTION_MARKERS = (
    "ignore", "disregard", "forget", "override", "bypass", "instead of",
    "from now on", "no longer", "new instructions", "new rules", "do not follow",
    "stop following", "you must", "you will now",
)
_ROLE_SHIFT_MARKERS = (
    "you are now", "you are no longer", "act as", "pretend", "roleplay",
    "role-play", "you're now", "behave as", "imagine you are", "dan mode",
    "developer mode", "jailbreak",
)
_EXFIL_MARKERS = (
    "system prompt", "your instructions", "reveal", "repeat everything",
    "print your", "show your", "initial prompt", "api key", "secret", "token",
)
# Fake-turn / delimiter injection — attempts to forge conversation structure.
_STRUCTURE_RE = re.compile(
    r"(?:^|\n)\s*(?:system|assistant|user|human)\s*:|<\s*/?(?:system|assistant|"
    r"user|human|im_start|im_end)\s*>|\[/?INST\]",
    re.IGNORECASE,
)


@dataclass
class SuspicionResult:
    suspicious: bool
    score: float                      # 0-1 cheap heuristic score
    reasons: list[str] = field(default_factory=list)

    @property
    def escalate_to_llm(self) -> bool:
        return self.suspicious


class SuspicionGate:
    """Cheap, deterministic decision: does this message warrant an LLM look?

    escalate = ANY of: instruction/role/exfil markers · forged conversation
    structure · material obfuscation (normalisation changed the text a lot) ·
    caller-supplied sklearn-uncertain · an already-elevated conversation score.
    """

    def __init__(
        self,
        marker_threshold: int = 1,
        obfuscation_ratio: float = 0.15,
        conversation_flag_score: float = 0.55,
    ) -> None:
        self._marker_threshold = max(1, marker_threshold)
        self._obf_ratio = obfuscation_ratio
        self._conv_flag = conversation_flag_score

    def assess(
        self,
        text: str,
        normalized_text: str | None = None,
        sklearn_uncertain: bool = False,
        conversation_score: float = 0.0,
    ) -> SuspicionResult:
        if not text:
            return SuspicionResult(suspicious=False, score=0.0)

        low = text.lower()
        # Decoded detection surface (YSG-RISK-319): normalize_for_detection now
        # decodes tag-block / variation-selector / PUA smuggling and de-leets /
        # de-homoglyphs, so markers match the RECOVERED payload that is invisible
        # in `low`. Computed here, NOT taken from the caller — a caller passing
        # raw/forward text is precisely how the smuggling class never escalated.
        det_low = normalize_for_detection(text).lower()
        reasons: list[str] = []
        score = 0.0

        def _hits(markers: tuple[str, ...]) -> int:
            return sum(1 for m in markers if m in low or m in det_low)

        instr = _hits(_INSTRUCTION_MARKERS)
        role = _hits(_ROLE_SHIFT_MARKERS)
        exfil = _hits(_EXFIL_MARKERS)
        marker_hits = instr + role + exfil
        if instr:
            reasons.append(f"instruction_markers:{instr}")
            score += 0.25 * min(instr, 2)
        if role:
            reasons.append(f"role_shift_markers:{role}")
            score += 0.30 * min(role, 2)
        if exfil:
            reasons.append(f"exfil_markers:{exfil}")
            score += 0.25 * min(exfil, 2)

        if _STRUCTURE_RE.search(text) or _STRUCTURE_RE.search(det_low):
            reasons.append("forged_conversation_structure")
            score += 0.35

        # Obfuscation: if NFKC-normalising materially changed the text (homoglyph
        # / control-char / width tricks), that is itself a signal. The caller can
        # pass the already-normalised text (from the mechanical filter) to avoid
        # recomputing; otherwise we normalise here.
        norm = normalized_text if normalized_text is not None else unicodedata.normalize("NFKC", text)
        if text and norm != text:
            changed = sum(1 for a, b in zip(text, norm) if a != b) + abs(len(text) - len(norm))
            ratio = changed / max(1, len(text))
            if ratio >= self._obf_ratio:
                reasons.append(f"obfuscation:{ratio:.2f}")
                score += 0.30

        # sklearn UNCERTAIN and an already-elevated multi-turn score are each a
        # strong standalone reason to have the LLM look — they escalate directly.
        direct_escalate = False
        # Smuggled codepoints were recovered from this message. A benign user
        # does not hide text in Unicode tag/variation-selector/PUA codepoints,
        # so this escalates directly to the LLM regardless of whether a marker
        # matched the decoded text (FP-safe: ordinary emoji, skin tones, flags,
        # and standard variation selectors do NOT set this — see
        # _decode_hidden_codepoints).
        _, _had_hidden = _decode_hidden_codepoints(text)
        if _had_hidden:
            reasons.append("hidden_codepoints")
            score += 0.35
            direct_escalate = True
        if sklearn_uncertain:
            reasons.append("sklearn_uncertain")
            score += 0.30
            direct_escalate = True
        if conversation_score >= self._conv_flag:
            reasons.append(f"conversation_risk:{conversation_score:.2f}")
            score += 0.30
            direct_escalate = True

        suspicious = (
            (marker_hits >= self._marker_threshold)
            or direct_escalate
            or bool(reasons and score >= 0.30)
        )
        return SuspicionResult(
            suspicious=suspicious,
            score=min(1.0, round(score, 4)),
            reasons=reasons,
        )
