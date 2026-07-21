"""
Yashigani Inspection — per-identity classifier concurrency guard (A10, 5.0).

Threat model (tier1 council 2026-07-14, Laura / compound Critical A1×A10):
the LLM-escalate classifier is a shared resource. Without per-identity
isolation, one identity can flood it with ordinary-looking load until every
request times out — and with a fail-open classifier that outage silently
approves the whole gateway's traffic. The guard caps concurrent
classifications PER IDENTITY, so an attacker can only shed their own
requests (fail-closed), never induce a gateway-wide bypass.

Scope note: this is the A10 minimum-viable half that the council required to
land WITH A1 (fail-closed disposition). The full denial-of-compute control
(GPU quota / loop-breaker across chained agents) is a separate 5.0 item.
"""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Iterator

logger = logging.getLogger(__name__)

_DEFAULT_MAX_PER_IDENTITY = 4


class IdentityConcurrencyGuard:
    """
    Bounded per-identity concurrency for classifier calls.

    slot(identity) yields True when a slot was acquired (caller runs the
    classification and the slot is released on exit) and False when the
    identity is already at its cap (caller must fail closed — shed the
    request, never skip inspection).

    Unknown/empty identities share the single "" bucket so an unauthenticated
    path cannot mint fresh buckets to dodge the cap.
    """

    def __init__(self, max_per_identity: int = _DEFAULT_MAX_PER_IDENTITY) -> None:
        if max_per_identity < 1:
            raise ValueError("max_per_identity must be >= 1")
        self._max = max_per_identity
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def max_per_identity(self) -> int:
        return self._max

    def try_acquire(self, identity: str) -> bool:
        key = identity or ""
        with self._lock:
            current = self._counts.get(key, 0)
            if current >= self._max:
                return False
            self._counts[key] = current + 1
            return True

    def release(self, identity: str) -> None:
        key = identity or ""
        with self._lock:
            current = self._counts.get(key, 0)
            if current <= 1:
                # Drop zeroed buckets so the dict stays bounded by concurrent
                # identities, not by every identity ever seen.
                self._counts.pop(key, None)
            else:
                self._counts[key] = current - 1

    @contextmanager
    def slot(self, identity: str) -> Iterator[bool]:
        acquired = self.try_acquire(identity)
        try:
            yield acquired
        finally:
            if acquired:
                self.release(identity)

    def in_flight(self, identity: str) -> int:
        with self._lock:
            return self._counts.get(identity or "", 0)
