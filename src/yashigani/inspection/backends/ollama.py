"""
Yashigani Inspection — Ollama classifier backend.

Implements ClassifierBackend using the local Ollama inference server.
Uses the shared classification prompt from classification_prompt.py.
No external network calls — Ollama is always local.

v4.1 Phase 1c (LAURA-I1-01 seam): transport moved to
yashigani.inspection._ollama_transport — on https URLs (the Caddy :11435
Ollama mesh front) it presents this service's mesh leaf; http URLs keep the
legacy plain path (dev/test).
"""
from __future__ import annotations

import json
import logging
import time

import httpx

from yashigani.inspection.backend_base import (
    ClassifierBackend,
    ClassifierResult,
    BackendUnavailableError,
)
from yashigani.inspection.classification_prompt import (
    SYSTEM_PROMPT,
    parse_classification_response,
)

logger = logging.getLogger(__name__)

# Classification labels (kept as module constants for import convenience)
LABEL_CLEAN = "CLEAN"
LABEL_CREDENTIAL_EXFIL = "CREDENTIAL_EXFIL"
LABEL_PROMPT_INJECTION_ONLY = "PROMPT_INJECTION_ONLY"


class OllamaBackend(ClassifierBackend):
    """
    Classifier backend backed by a local Ollama instance.
    Uses /api/chat with stream=False and JSON format enforced.
    """

    name = "ollama"

    def __init__(
        self,
        base_url: str = "http://ollama:11434",
        model: str = "qwen2.5:3b",
        timeout_seconds: int = 30,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout_seconds

    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content via Ollama.
        Raises BackendUnavailableError on connection error, timeout, or
        non-parseable response.
        """
        start_ms = int(time.monotonic() * 1000)
        try:
            raw = self._call_model(content)
        except httpx.TimeoutException as exc:
            raise BackendUnavailableError(
                f"Ollama timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise BackendUnavailableError(
                f"Ollama unreachable at {self._base_url}: {exc}"
            ) from exc
        except TimeoutError as exc:
            raise BackendUnavailableError(
                f"Ollama timed out after {self._timeout}s: {exc}"
            ) from exc
        except Exception as exc:
            raise BackendUnavailableError(
                f"Ollama request failed: {exc}"
            ) from exc

        latency_ms = int(time.monotonic() * 1000) - start_ms

        try:
            parsed = parse_classification_response(raw)
        except ValueError as exc:
            raise BackendUnavailableError(
                f"Ollama returned unparseable response: {exc}"
            ) from exc

        return ClassifierResult(
            label=parsed["label"],
            confidence=parsed["confidence"],
            backend=self.name,
            latency_ms=latency_ms,
            raw_response=raw,  # never logged, only held for debugging
        )

    def health_check(self) -> bool:
        """GET /api/tags — returns True if Ollama responds with HTTP 200."""
        from yashigani.inspection._ollama_transport import ollama_get_json
        return ollama_get_json(self._base_url, "/api/tags", timeout=5.0) is not None

    # ── Internal ─────────────────────────────────────────────────────────────

    def _call_model(self, content: str) -> str:
        """POST to /api/chat and return the model's message content string."""
        from yashigani.inspection._ollama_transport import ollama_post_json

        user_message = (
            "USER_CONTENT_START\n"
            + json.dumps(content)  # JSON-encode to escape special chars
            + "\nUSER_CONTENT_END"
        )
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0},
        }
        data = ollama_post_json(
            self._base_url, "/api/chat", payload, timeout=float(self._timeout),
        )
        return data.get("message", {}).get("content", "")
