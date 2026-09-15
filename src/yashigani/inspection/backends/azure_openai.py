"""
Yashigani Inspection — Azure OpenAI classifier backend.

Uses the Azure OpenAI chat completions API via the openai SDK.
The API key is fetched from KMS at init time — never from env or request body.
The azure_endpoint must use https:// (enforced at both construction and admin route).

Requires: openai>=1.30 (optional dependency — install with [cloud-inspection])
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
    from openai import AzureOpenAI as _AzureOpenAI
    import openai as _openai_sdk
    _OPENAI_AVAILABLE = True
except ImportError:
    _AzureOpenAI = None  # type: ignore[assignment,misc]
    _openai_sdk = None   # type: ignore[assignment]
    _OPENAI_AVAILABLE = False


class AzureOpenAIBackend(ClassifierBackend):
    """
    Classifier backend using Azure OpenAI chat completions.
    API key is retrieved from KMS at instantiation — never from env or body.
    azure_endpoint must use https:// (enforced at construction).
    """

    name = "azure_openai"

    def __init__(
        self,
        kms_provider,
        azure_endpoint: str,
        deployment_name: str = "gpt-4o-mini",
        api_version: str = "2024-02-01",
        kms_key: str = "azure_openai_key",
        timeout_seconds: int = 15,
        max_tokens: int = 256,
        audit_writer=None,
    ) -> None:
        # Validate endpoint uses TLS
        if not azure_endpoint.startswith("https://"):
            raise ValueError(
                f"AzureOpenAIBackend: azure_endpoint must start with https://, got {azure_endpoint!r}"
            )

        self._azure_endpoint = azure_endpoint
        self._deployment_name = deployment_name
        self._api_version = api_version
        self._kms_key = kms_key
        self._timeout = timeout_seconds
        self._max_tokens = max_tokens

        # Fetch API key from KMS at init time
        self._api_key: Optional[str] = None
        if kms_provider is not None:
            try:
                self._api_key = kms_provider.get_secret(kms_key)
                logger.info("AzureOpenAIBackend: API key retrieved from KMS (%s)", kms_key)
                if audit_writer is not None:
                    try:
                        from yashigani.audit.schema import InspectionKMSKeyRetrievedEvent
                        audit_writer.write(InspectionKMSKeyRetrievedEvent(
                            backend_name=self.name,
                            kms_key_name=kms_key,
                        ))
                    except Exception as e:
                        logger.debug("AzureOpenAIBackend: audit write failed: %s", e)
            except Exception as exc:
                logger.warning(
                    "AzureOpenAIBackend: failed to retrieve API key from KMS (%s): %s",
                    kms_key, exc,
                )

    def classify(self, content: str) -> ClassifierResult:
        """
        Classify content via Azure OpenAI chat completions.
        Raises BackendUnavailableError on connection error, timeout,
        missing SDK, or unparseable response.
        """
        if not _OPENAI_AVAILABLE:
            raise BackendUnavailableError(
                "openai package not installed — install with: pip install 'yashigani[cloud-inspection]'"
            )

        if not self._api_key:
            raise BackendUnavailableError(
                "AzureOpenAIBackend: no API key available (KMS retrieval failed at init)"
            )

        start_ms = int(time.monotonic() * 1000)

        try:
            client = _AzureOpenAI(
                azure_endpoint=self._azure_endpoint,
                api_key=self._api_key,
                api_version=self._api_version,
                timeout=float(self._timeout),
            )
            response = client.chat.completions.create(
                model=self._deployment_name,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_message(content)},
                ],
                max_tokens=self._max_tokens,
                temperature=0.0,
            )
            raw = response.choices[0].message.content or ""
        except _openai_sdk.APIConnectionError as exc:
            raise BackendUnavailableError(
                f"Azure OpenAI unreachable at {self._azure_endpoint}: {exc}"
            ) from exc
        except _openai_sdk.APITimeoutError as exc:
            raise BackendUnavailableError(
                f"Azure OpenAI timed out after {self._timeout}s: {exc}"
            ) from exc
        except _openai_sdk.AuthenticationError as exc:
            raise BackendUnavailableError(
                f"Azure OpenAI authentication failed (check KMS key {self._kms_key!r}): {exc}"
            ) from exc
        except Exception as exc:
            raise BackendUnavailableError(
                f"Azure OpenAI request failed: {exc}"
            ) from exc

        latency_ms = int(time.monotonic() * 1000) - start_ms

        try:
            parsed = parse_classification_response(raw)
        except ValueError as exc:
            raise BackendUnavailableError(
                f"Azure OpenAI returned unparseable classification: {exc}"
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
        Verify connectivity with a minimal models list call.
        Returns False if SDK is not installed or any error occurs.
        """
        if not _OPENAI_AVAILABLE:
            return False
        if not self._api_key:
            return False
        try:
            client = _AzureOpenAI(
                azure_endpoint=self._azure_endpoint,
                api_key=self._api_key,
                api_version=self._api_version,
                timeout=5.0,
            )
            client.models.list()
            return True
        except Exception:
            return False
