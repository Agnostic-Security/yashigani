"""
Yashigani Inspection — LM Studio classifier backend.

LM Studio exposes an OpenAI-compatible API at a configurable base URL
(default http://localhost:1234). No auth by default for local installs.

Uses httpx (sync) — already a project dependency.
Not supported in production (YASHIGANI_ENV=production guard enforced
at the admin route layer, not here).
"""
from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

from yashigani.inspection.backend_base import (
    ClassifierBackend,
    ClassifierResult,
    BackendUnavailableError,
)
from yashigani.inspection.classification_prompt import (
    SYSTEM_PROMPT,
    build_user_message,
    parse_classification_response,
)

logger = logging.getLogger(__name__)


class LMStudioBackend(ClassifierBackend):
    """
    Classifier backend backed by a local LM Studio instance.
    Uses the OpenAI-compatible /v1/chat/completions endpoint.
    """

    name = "lmstudio"

    def __init__(
        self,
        base_url: str = "http://localhost:1234",
        model: str = "qwen2.5-3b-instruct",
        timeout_seconds: int = 30,
        api_key: Optional[str] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout_seconds
        # api_key is optional — LM Studio local has no auth by default
        self._api_key = api_key

    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content via LM Studio's OpenAI-compatible API.
        Raises BackendUnavailableError on connection error, timeout, or
        non-parseable response.
        """
        start_ms = int(time.monotonic() * 1000)

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_message(content)},
            ],
            "temperature": 0.0,
            "max_tokens": 256,
        }

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/v1/chat/completions",
                    json=payload,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as exc:
            raise BackendUnavailableError(
                f"LM Studio unreachable at {self._base_url}: {exc}"
            ) from exc
        except httpx.TimeoutException as exc:
            raise BackendUnavailableError(
                f"LM Studio timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise BackendUnavailableError(
                f"LM Studio returned HTTP {exc.response.status_code}: {exc}"
            ) from exc
        except Exception as exc:
            raise BackendUnavailableError(
                f"LM Studio request failed: {exc}"
            ) from exc

        latency_ms = int(time.monotonic() * 1000) - start_ms

        # Extract the model's reply
        try:
            raw = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendUnavailableError(
                f"LM Studio response missing expected fields: {exc}. Response: {str(data)[:200]}"
            ) from exc

        try:
            parsed = parse_classification_response(raw)
        except ValueError as exc:
            raise BackendUnavailableError(
                f"LM Studio returned unparseable classification: {exc}"
            ) from exc

        return ClassifierResult(
            label=parsed["label"],
            confidence=parsed["confidence"],
            backend=self.name,
            latency_ms=latency_ms,
            raw_response=raw,  # never logged, only held for debugging
        )

    def health_check(self) -> bool:
        """GET /v1/models — returns True if LM Studio responds with HTTP 200."""
        try:
            headers = {}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"
            with httpx.Client(timeout=5) as client:
                response = client.get(
                    f"{self._base_url}/v1/models",
                    headers=headers,
                )
                return response.status_code == 200
        except Exception:
            return False
