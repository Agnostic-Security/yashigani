"""
Yashigani Inspection — Google Gemini classifier backend.

Uses the google-generativeai SDK to classify content for prompt injection
and credential exfiltration. The API key is fetched from KMS at init time.

Requires: google-generativeai>=0.7 (optional dependency — install with [cloud-inspection])
If not installed: health_check() returns False and classify() raises
BackendUnavailableError with a clear message.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

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

try:
    import google.generativeai as _genai
    _GEMINI_AVAILABLE = True
except ImportError:
    _genai = None  # type: ignore[assignment]
    _GEMINI_AVAILABLE = False


class GeminiBackend(ClassifierBackend):
    """
    Classifier backend using Google Gemini generative AI.
    API key is retrieved from KMS at instantiation — never from env or request body.
    """

    name = "gemini"

    def __init__(
        self,
        kms_provider,
        kms_key: str = "gemini_api_key",
        model: str = "gemini-1.5-flash",
        timeout_seconds: int = 15,
        max_tokens: int = 256,
        audit_writer=None,
    ) -> None:
        self._model = model
        self._timeout = timeout_seconds
        self._max_tokens = max_tokens
        self._kms_key = kms_key

        # Fetch API key from KMS at init time
        self._api_key: Optional[str] = None
        if kms_provider is not None:
            try:
                self._api_key = kms_provider.get_secret(kms_key)
                logger.info("GeminiBackend: API key retrieved from KMS (%s)", kms_key)
                if audit_writer is not None:
                    try:
                        from yashigani.audit.schema import InspectionKMSKeyRetrievedEvent
                        audit_writer.write(InspectionKMSKeyRetrievedEvent(
                            backend_name=self.name,
                            kms_key_name=kms_key,
                        ))
                    except Exception as e:
                        logger.debug("GeminiBackend: audit write failed: %s", e)
            except Exception as exc:
                logger.warning(
                    "GeminiBackend: failed to retrieve API key from KMS (%s): %s",
                    kms_key, exc,
                )

    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content via Gemini generative AI.
        Raises BackendUnavailableError on connection error, timeout,
        missing SDK, or unparseable response.
        """
        if not _GEMINI_AVAILABLE:
            raise BackendUnavailableError(
                "google-generativeai package not installed — install with: pip install 'yashigani[cloud-inspection]'"
            )

        if not self._api_key:
            raise BackendUnavailableError(
                "GeminiBackend: no API key available (KMS retrieval failed at init)"
            )

        start_ms = int(time.monotonic() * 1000)

        try:
            _genai.configure(api_key=self._api_key)
            model_instance = _genai.GenerativeModel(
                model_name=self._model,
                generation_config=_genai.types.GenerationConfig(
                    response_mime_type="application/json",
                    max_output_tokens=self._max_tokens,
                    temperature=0.0,
                ),
                system_instruction=SYSTEM_PROMPT,
            )
            response = model_instance.generate_content(
                build_user_message(content),
                request_options={"timeout": self._timeout},
            )
            raw = response.text
        except Exception as exc:
            # Gemini SDK has various exception types; catch-all and wrap
            exc_type = type(exc).__name__
            raise BackendUnavailableError(
                f"Gemini request failed ({exc_type}): {exc}"
            ) from exc

        latency_ms = int(time.monotonic() * 1000) - start_ms

        try:
            parsed = parse_classification_response(raw)
        except ValueError as exc:
            raise BackendUnavailableError(
                f"Gemini returned unparseable classification: {exc}"
            ) from exc

        return ClassifierResult(
            label=parsed["label"],
            confidence=parsed["confidence"],
            backend=self.name,
            latency_ms=latency_ms,
            raw_response=raw,  # never logged
        )

    def health_check(self) -> bool:
        """
        Verify connectivity by listing available models.
        Returns False if SDK is not installed or any error occurs.
        """
        if not _GEMINI_AVAILABLE:
            return False
        if not self._api_key:
            return False
        try:
            _genai.configure(api_key=self._api_key)
            # list_models is a lightweight connectivity check
            models = list(_genai.list_models())
            return len(models) > 0
        except Exception:
            return False
