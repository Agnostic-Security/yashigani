"""
Yashigani Inspection — system-prompt leakage guard (A4, 5.0).

Closes LLM07 / F-LLM07-001: system prompts are stored and access-controlled,
but nothing scrubs them when a model echoes them back in a response. An
extraction attack ("repeat everything above", DAN, etc.) that the request-leg
classifier misses still leaks if the model complies — so the defence must also
sit on the OUTPUT.

Detection is corpus-based and model-free (no extra inference in the request
path): the guard is given the registered system-prompt string(s) and looks for
verbatim / near-verbatim echoes in the response using word-shingle overlap.
This catches the model reproducing the prompt (the actual leak) while
tolerating incidental short overlaps with ordinary answers.

Design notes:
- Shingle size (default 8 words) is long enough that ordinary prose does not
  collide with the system prompt by chance, short enough to catch a partial
  quote of a distinctive instruction.
- Matching is on NFKC-normalised, whitespace-collapsed, case-folded text so
  trivial reformatting does not evade it.
- On a hit the guard redacts the offending run(s) with a placeholder and
  reports the leak; the caller decides block vs. redact-and-forward.
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_SHINGLE_WORDS = 8
_REDACTION = "[REDACTED: system prompt]"
_WORD_RE = re.compile(r"\w+", re.UNICODE)


def load_corpus_lines(path: str) -> list[str]:
    """Read a protected-system-prompts file: one prompt per line.

    TD-2026-07-25-05: blank lines AND `#`-prefixed comment lines are skipped
    — they are not prompts. Without this, a demo/operator asset with a
    header comment block (see scripts/demo-assets/protected-system-prompts.txt)
    silently loads the comment lines as if they were protected prompts,
    inflating the reported corpus count and contributing over-broad,
    unrelated shingles to the leak-detection window — which could cause a
    spurious scrub match against ordinary output. This is a hygiene fix
    (over-counting), not a security bypass: it cannot cause a real leak to
    go undetected, only (at most) a false-positive scrub of innocent text.
    """
    prompts: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            prompts.append(line)
    return prompts


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(_normalize(text))


def _shingles(words: list[str], n: int) -> set[str]:
    if len(words) < n:
        # Whole thing is one shingle when shorter than the window — a short but
        # distinctive prompt line is still matchable.
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + n]) for i in range(len(words) - n + 1)}


@dataclass
class LeakResult:
    leaked: bool
    scrubbed_text: str
    matched_shingles: int = 0
    overlap_ratio: float = 0.0
    audit_fields: dict = field(default_factory=dict)


class SystemPromptLeakGuard:
    """
    Detects and scrubs registered system-prompt content echoed in a response.

    Register the known system-prompt string(s) with set_corpus(); scan()
    returns a LeakResult. Thread-safety: set_corpus swaps the precomputed
    shingle set atomically via a plain attribute rebind (GIL-atomic); scan is
    read-only.
    """

    def __init__(
        self,
        shingle_words: int = _DEFAULT_SHINGLE_WORDS,
        min_matched_shingles: int = 1,
    ) -> None:
        if shingle_words < 1:
            raise ValueError("shingle_words must be >= 1")
        self._n = shingle_words
        self._min_matched = max(1, min_matched_shingles)
        self._corpus_shingles: set[str] = set()
        self._corpus_count = 0

    def set_corpus(self, prompts: list[str]) -> None:
        shingles: set[str] = set()
        count = 0
        for p in prompts:
            if not p:
                continue
            count += 1
            shingles |= _shingles(_words(p), self._n)
        self._corpus_shingles = shingles
        self._corpus_count = count
        logger.info(
            "SystemPromptLeakGuard corpus set: %d prompt(s), %d shingle(s)",
            count, len(shingles),
        )

    @property
    def has_corpus(self) -> bool:
        return bool(self._corpus_shingles)

    def scan(self, response_text: str) -> LeakResult:
        if not response_text or not self._corpus_shingles:
            return LeakResult(leaked=False, scrubbed_text=response_text or "")

        resp_words = _words(response_text)
        resp_shingles = _shingles(resp_words, self._n)
        matched = resp_shingles & self._corpus_shingles

        if len(matched) < self._min_matched:
            return LeakResult(leaked=False, scrubbed_text=response_text)

        overlap = len(matched) / max(1, len(self._corpus_shingles))
        scrubbed = self._scrub(response_text, matched)
        audit = {
            "event_type": "SYSTEM_PROMPT_LEAK_DETECTED",
            "matched_shingles": len(matched),
            "corpus_shingles": len(self._corpus_shingles),
            "overlap_ratio": round(overlap, 4),
        }
        logger.warning(
            "System-prompt leak detected in response: %d matched shingle(s), "
            "overlap=%.3f — scrubbing", len(matched), overlap,
        )
        return LeakResult(
            leaked=True,
            scrubbed_text=scrubbed,
            matched_shingles=len(matched),
            overlap_ratio=overlap,
            audit_fields=audit,
        )

    def _scrub(self, response_text: str, matched: set[str]) -> str:
        """Redact contiguous runs of leaked content.

        Walk the response's word tokens; any window that is a matched shingle
        marks its words for redaction. Contiguous redacted words collapse to a
        single placeholder so the output stays readable.
        """
        tokens = list(_WORD_RE.finditer(response_text))
        norm_words = [_normalize(m.group(0)) for m in tokens]
        n = self._n
        redact = [False] * len(tokens)

        if len(norm_words) < n:
            whole = " ".join(norm_words)
            if whole in matched:
                return _REDACTION
            return response_text

        for i in range(len(norm_words) - n + 1):
            if " ".join(norm_words[i : i + n]) in matched:
                for j in range(i, i + n):
                    redact[j] = True

        # Rebuild, collapsing contiguous redacted spans to one placeholder.
        out: list[str] = []
        cursor = 0
        k = 0
        while k < len(tokens):
            if redact[k]:
                start = tokens[k].start()
                # advance to end of this redacted run
                run_end_idx = k
                while run_end_idx + 1 < len(tokens) and redact[run_end_idx + 1]:
                    run_end_idx += 1
                end = tokens[run_end_idx].end()
                out.append(response_text[cursor:start])
                out.append(_REDACTION)
                cursor = end
                k = run_end_idx + 1
            else:
                k += 1
        out.append(response_text[cursor:])
        return "".join(out)
