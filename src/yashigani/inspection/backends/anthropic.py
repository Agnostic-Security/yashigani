"""
Yashigani Inspection — Anthropic classifier backend.

Uses the Anthropic messages API to classify content for prompt injection
and credential exfiltration. The API key is fetched from KMS at init time
and never stored in plaintext beyond the instance lifetime.

Requires: anthropic>=0.25 (optional dependency — install with [cloud-inspection])
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
    import anthropic as _anthropic_sdk
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _anthropic_sdk = None  # type: ignore[assignment]
    _ANTHROPIC_AVAILABLE = False


class AnthropicBackend(ClassifierBackend):
    """
    Classifier backend using the Anthropic messages API.
    API key is retrieved from KMS at instantiation time — never from env or request body.
    """

    name = "anthropic"

    def __init__(
        self,
        kms_provider,
        kms_key: str = "anthropic_api_key",
        model: str = "claude-haiku-4-5",
        timeout_seconds: int = 15,
        max_tokens: int = 256,
        audit_writer=None,
    ) -> None:
        self._model = model
        self._timeout = timeout_seconds
        self._max_tokens = max_tokens
        self._kms_key = kms_key

        # Fetch API key from KMS at init time — cache in instance
        self._api_key: Optional[str] = None
        if kms_provider is not None:
            try:
                self._api_key = kms_provider.get_secret(kms_key)
                logger.info("AnthropicBackend: API key retrieved from KMS (%s)", kms_key)
                if audit_writer is not None:
                    try:
                        from yashigani.audit.schema import InspectionKMSKeyRetrievedEvent
                        audit_writer.write(InspectionKMSKeyRetrievedEvent(
                            backend_name=self.name,
                            kms_key_name=kms_key,
                        ))
                    except Exception as e:
                        logger.debug("AnthropicBackend: audit write failed: %s", e)
            except Exception as exc:
                logger.warning(
                    "AnthropicBackend: failed to retrieve API key from KMS (%s): %s",
                    kms_key, exc,
                )

    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content via Anthropic messages API.
        Raises BackendUnavailableError on connection error, timeout,
        missing SDK, or unparseable response.
        """
        if not _ANTHROPIC_AVAILABLE:
            raise BackendUnavailableError(
                "anthropic package not installed — install with: pip install 'yashigani[cloud-inspection]'"
            )

        if not self._api_key:
            raise BackendUnavailableError(
                "AnthropicBackend: no API key available (KMS retrieval failed at init)"
            )

        start_ms = int(time.monotonic() * 1000)

        try:
            client = _anthropic_sdk.Anthropic(
                api_key=self._api_key,
                timeout=float(self._timeout),
            )
            response = client.messages.create(
                model=self._model,
                max_tokens=self._max_tokens,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": build_user_message(content)},
                ],
            )
            raw = response.content[0].text  # type: ignore[union-attr]
        except _anthropic_sdk.APIConnectionError as exc:
            raise BackendUnavailableError(
                f"Anthropic API unreachable: {exc}"
            ) from exc
        except _anthropic_sdk.APITimeoutError as exc:
            raise BackendUnavailableError(
                f"Anthropic API timed out after {self._timeout}s: {exc}"
            ) from exc
        except _anthropic_sdk.AuthenticationError as exc:
            raise BackendUnavailableError(
                f"Anthropic authentication failed (check KMS key {self._kms_key!r}): {exc}"
            ) from exc
        except Exception as exc:
            raise BackendUnavailableError(
                f"Anthropic request failed: {exc}"
            ) from exc

        latency_ms = int(time.monotonic() * 1000) - start_ms

        try:
            parsed = parse_classification_response(raw)
        except ValueError as exc:
            raise BackendUnavailableError(
                f"Anthropic returned unparseable classification: {exc}"
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
        Verify connectivity by attempting a minimal token count operation.
        Returns False if the SDK is not installed or any error occurs.
        """
        if not _ANTHROPIC_AVAILABLE:
            return False
        if not self._api_key:
            return False
        try:
            client = _anthropic_sdk.Anthropic(
                api_key=self._api_key,
                timeout=5.0,
            )
            # Use count_tokens as a lightweight connectivity check
            client.messages.count_tokens(
                model=self._model,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception:
            return False
