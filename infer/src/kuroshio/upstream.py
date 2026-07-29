# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Injectable HTTP client for talking to a loaded llama-server instance.

Same discipline as `ProcessRunner`/`Downloader`: the HTTP app never calls
`httpx` directly — every upstream call goes through this ABC, so route
handlers are unit-testable with a fake client that returns canned
responses/SSE lines, with no real `llama-server` process listening on any
port.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator


class UpstreamError(Exception):
    """Raised when a request to the upstream llama-server instance fails."""


class UpstreamClient(ABC):
    @abstractmethod
    async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        """POST `json_body` to `url`, return the decoded JSON response body."""
        raise NotImplementedError

    @abstractmethod
    def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
        """POST `json_body` to `url`, yield the response body as text lines
        (SSE framing: `data: {...}` lines, blank-line separators, terminal
        `data: [DONE]`)."""
        raise NotImplementedError


class HttpxUpstreamClient(UpstreamClient):
    """Real implementation — not exercised by the unit-test suite."""

    def __init__(self, *, timeout_seconds: float = 120.0) -> None:
        self._timeout_seconds = timeout_seconds

    async def request_json(self, url: str, json_body: dict[str, Any]) -> dict[str, Any]:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                resp = await client.post(url, json=json_body)
                resp.raise_for_status()
                result: dict[str, Any] = resp.json()
                return result
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream request to {url} failed: {exc}") from exc

    async def stream_lines(self, url: str, json_body: dict[str, Any]) -> AsyncIterator[str]:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                async with client.stream("POST", url, json=json_body) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        yield line
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream stream to {url} failed: {exc}") from exc


__all__ = ["UpstreamClient", "UpstreamError", "HttpxUpstreamClient"]
