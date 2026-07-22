# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Injectable network-download interface.

Every network-touching adapter (currently only Hugging Face) depends on
this ABC, never on `httpx`/`requests` directly. Unit tests inject a fake
implementation — this package's test suite makes NO live network calls
(hard constraint in the build brief). The real implementation
(`HttpxDownloader`) is exercised only by integration/manual testing, never
by `pytest`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class DownloadError(Exception):
    """Raised when a download fails (network error, non-2xx status, etc)."""


class Downloader(ABC):
    """Fetches a URL to a local destination path."""

    @abstractmethod
    def download(self, url: str, dest: Path, *, headers: dict[str, str] | None = None) -> None:
        """Stream `url` to `dest`. Implementations MUST write to a temp path
        and only make the final `dest` visible atomically on success —
        callers (e.g. the blob store) additionally verify content digest
        before trusting the download, but the downloader itself must never
        leave a partially-written file at `dest`."""
        raise NotImplementedError


class HttpxDownloader(Downloader):
    """Real network implementation, used only outside the unit-test suite."""

    def __init__(self, *, timeout_seconds: float = 300.0) -> None:
        self._timeout_seconds = timeout_seconds

    def download(self, url: str, dest: Path, *, headers: dict[str, str] | None = None) -> None:
        import os
        from uuid import uuid4

        import httpx

        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.parent / f".tmp-{uuid4().hex}"
        try:
            with httpx.stream(
                "GET", url, headers=headers, timeout=self._timeout_seconds, follow_redirects=True
            ) as resp:
                resp.raise_for_status()
                with open(tmp, "wb") as fh:
                    for chunk in resp.iter_bytes():
                        fh.write(chunk)
            os.replace(tmp, dest)
        except httpx.HTTPError as exc:
            raise DownloadError(f"download failed for {url}: {exc}") from exc
        finally:
            tmp.unlink(missing_ok=True)


__all__ = ["Downloader", "DownloadError", "HttpxDownloader"]
