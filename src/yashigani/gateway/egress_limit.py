# Last updated: 2026-07-09T00:00:00+00:00
"""
Yashigani Gateway — per-instance egress LLM rate/budget enforcer.

Enforces a fixed-window call-count cap on the /egress/eval path, keyed
on the per-instance SPIFFE URI (SHA-256 hash, same computation as OPA's
``_spiffe_hash`` in policy/mcp.rego:649).  Closes FLAG-3: the OPA
``rate_limit_key`` was emitted by mcp_decision but never read by
egress_proxy.py, leaving /egress/eval unbounded for langflow/letta/openclaw
LLM egress calls.

Applies to ALL agents that route LLM calls through /egress/eval — not
just langflow.  The enforcer is prefix-agnostic; the same bucket covers
every destination (slack, telegram, llm upstream) for a given instance.

Two modes (``YASHIGANI_EGRESS_LIMIT_MODE``):

  ``cap``     — Count + enforce: when the per-instance call count exceeds
                ``YASHIGANI_EGRESS_LIMIT_CALLS`` in the current window,
                the request is DENIED and egress_proxy returns HTTP 429.
                Fail-closed: Redis unavailability → deny (the cap cannot
                be verified, so the request is treated as over-limit).
                **Default mode.**

  ``monitor`` — Count + record: the call is metered and logged but never
                denied regardless of count.  Redis unavailability → allow
                (monitoring must not degrade availability; there is no cap
                to enforce).

Both modes increment the counter on every request (metering is shared).
The difference is solely in the deny decision when count > limit.

Redis key pattern::

    egress:rlk:{sha256hex(spiffe)}:{window_bucket}

where ``window_bucket = int(time.time() / window_seconds)``.
Key TTL is ``2 × window_seconds`` (set on first write, same pattern as
endpoint_ratelimit.py).

Configuration (env vars, read at ``__init__`` time)::

    YASHIGANI_EGRESS_LIMIT_MODE           "cap" | "monitor"   default: "cap"
    YASHIGANI_EGRESS_LIMIT_CALLS          int > 0             default: 200
    YASHIGANI_EGRESS_LIMIT_WINDOW_SECONDS int > 0             default: 60

All three are wired into Docker (docker-compose.yml gateway env) and Helm
(helm/yashigani/templates/gateway.yaml) for parity.

Design note — coordinator two-mode proposal (2026-07-09):
  A coordinator message suggested making monitor the default.  That
  message carries no user authority (per MEMORY.md rules).  Default is
  cap (fail-closed, per Tiago's original brief).  Operators who want
  visibility before blocking can set YASHIGANI_EGRESS_LIMIT_MODE=monitor,
  then flip back to cap once real usage is understood.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_VALID_MODES: frozenset[str] = frozenset({"cap", "monitor"})
_DEFAULT_MODE = "cap"
_DEFAULT_CALLS = 200
_DEFAULT_WINDOW = 60


def _resolve_mode(env: Optional[dict[str, str]] = None) -> str:
    raw = (env if env is not None else os.environ).get(
        "YASHIGANI_EGRESS_LIMIT_MODE", _DEFAULT_MODE
    ).strip().lower()
    if raw in _VALID_MODES:
        return raw
    logger.warning(
        "YASHIGANI_EGRESS_LIMIT_MODE=%r is not valid (expected 'cap' or 'monitor'); "
        "defaulting to 'cap'",
        raw,
    )
    return _DEFAULT_MODE


def _resolve_pos_int(
    key: str,
    default: int,
    env: Optional[dict[str, str]] = None,
) -> int:
    raw = (env if env is not None else os.environ).get(key, str(default)).strip()
    try:
        val = int(raw)
        if val > 0:
            return val
    except (ValueError, TypeError):
        pass
    logger.warning(
        "%s=%r is not a positive integer; using default %d", key, raw, default
    )
    return default


@dataclass(frozen=True)
class EgressLimitResult:
    """Result from :meth:`EgressLimitEnforcer.check_and_record`."""

    allowed: bool
    """
    False only when mode=cap AND count > limit (or Redis error in cap mode).
    Always True in monitor mode.
    """

    mode: str
    """Active mode: "cap" | "monitor"."""

    count: int
    """Current window call count.  0 when a Redis error occurred."""

    limit: int
    """Configured calls-per-window cap."""

    rate_limit_key: str
    """Redis key that was incremented: ``egress:rlk:{sha256}:{bucket}``."""

    retry_after_s: int
    """Seconds until the current window resets.  0 when allowed=True."""


class EgressLimitEnforcer:
    """
    Per-instance fixed-window call-count enforcer for ``/egress/eval``.

    Reuses the same Redis DB-2 instance (``egress:rlk:`` key prefix) as
    the endpoint rate limiter, with the same fixed-window INCR + TTL pattern.

    Usage::

        enforcer = EgressLimitEnforcer(redis_client)
        result = enforcer.check_and_record(caller_spiffe)
        if not result.allowed:
            return JSONResponse(status_code=429, ...)
    """

    def __init__(
        self,
        redis_client,
        *,
        mode: Optional[str] = None,
        calls_per_window: Optional[int] = None,
        window_seconds: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Args:
            redis_client:    Synchronous Redis client (DB-2 by convention).
            mode:            Override ``YASHIGANI_EGRESS_LIMIT_MODE``.
            calls_per_window: Override ``YASHIGANI_EGRESS_LIMIT_CALLS``.
            window_seconds:  Override ``YASHIGANI_EGRESS_LIMIT_WINDOW_SECONDS``.
            env:             Optional env mapping for testing (replaces os.environ).
        """
        self._r = redis_client

        self._mode: str = (
            mode
            if (isinstance(mode, str) and mode in _VALID_MODES)
            else _resolve_mode(env)
        )
        self._calls: int = (
            calls_per_window
            if (isinstance(calls_per_window, int) and calls_per_window > 0)
            else _resolve_pos_int("YASHIGANI_EGRESS_LIMIT_CALLS", _DEFAULT_CALLS, env)
        )
        self._window: int = (
            window_seconds
            if (isinstance(window_seconds, int) and window_seconds > 0)
            else _resolve_pos_int(
                "YASHIGANI_EGRESS_LIMIT_WINDOW_SECONDS", _DEFAULT_WINDOW, env
            )
        )
        logger.info(
            "EgressLimitEnforcer: mode=%s calls_per_window=%d window_seconds=%d",
            self._mode,
            self._calls,
            self._window,
        )

    # ------------------------------------------------------------------
    # Properties (for tests)
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def calls_per_window(self) -> int:
        return self._calls

    @property
    def window_seconds(self) -> int:
        return self._window

    # ------------------------------------------------------------------
    # Core enforcement
    # ------------------------------------------------------------------

    def check_and_record(self, caller_spiffe: str) -> EgressLimitResult:
        """
        Increment the per-instance counter for *caller_spiffe* and decide
        whether the egress call is allowed.

        Never raises.  Error behaviour by mode:

        - **cap**:     Redis error → fail-closed (``allowed=False``).
        - **monitor**: Redis error → allow (``allowed=True``, count=0).

        Returns:
            :class:`EgressLimitResult`
        """
        spiffe_hash = _spiffe_hash(caller_spiffe)
        bucket = int(time.time() / self._window)
        key = f"egress:rlk:{spiffe_hash}:{bucket}"
        retry_after = self._window - int(time.time() % self._window)

        try:
            count = int(self._r.incr(key))
            if count == 1:
                self._r.expire(key, self._window * 2)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "EgressLimitEnforcer: Redis error key=%s spiffe=%s: %s",
                key,
                caller_spiffe,
                exc,
            )
            if self._mode == "cap":
                logger.warning(
                    "EgressLimitEnforcer: Redis unavailable — fail-closed DENY "
                    "spiffe=%s mode=cap",
                    caller_spiffe,
                )
                return EgressLimitResult(
                    allowed=False,
                    mode=self._mode,
                    count=0,
                    limit=self._calls,
                    rate_limit_key=key,
                    retry_after_s=retry_after,
                )
            # monitor: Redis error → allow
            logger.warning(
                "EgressLimitEnforcer: Redis unavailable — allowing (monitor mode, "
                "no cap enforced) spiffe=%s",
                caller_spiffe,
            )
            return EgressLimitResult(
                allowed=True,
                mode=self._mode,
                count=0,
                limit=self._calls,
                rate_limit_key=key,
                retry_after_s=0,
            )

        over_limit = count > self._calls

        if over_limit:
            if self._mode == "cap":
                logger.warning(
                    "EgressLimitEnforcer: cap exceeded — DENY spiffe=%s "
                    "count=%d limit=%d key=%s retry_after_s=%d",
                    caller_spiffe,
                    count,
                    self._calls,
                    key,
                    retry_after,
                )
                return EgressLimitResult(
                    allowed=False,
                    mode=self._mode,
                    count=count,
                    limit=self._calls,
                    rate_limit_key=key,
                    retry_after_s=retry_after,
                )
            # monitor mode: log but allow
            logger.info(
                "EgressLimitEnforcer: cap exceeded (monitor — not enforced) "
                "spiffe=%s count=%d limit=%d key=%s",
                caller_spiffe,
                count,
                self._calls,
                key,
            )

        else:
            logger.debug(
                "EgressLimitEnforcer: under limit spiffe=%s count=%d/%d key=%s",
                caller_spiffe,
                count,
                self._calls,
                key,
            )

        return EgressLimitResult(
            allowed=True,
            mode=self._mode,
            count=count,
            limit=self._calls,
            rate_limit_key=key,
            retry_after_s=0,
        )


# ---------------------------------------------------------------------------
# Helper — mirrors OPA _spiffe_hash computation
# ---------------------------------------------------------------------------


def _spiffe_hash(spiffe: str) -> str:
    """
    SHA-256 hex digest of the SPIFFE URI.

    Mirrors OPA's ``_spiffe_hash := crypto.sha256(input.identity.spiffe)``
    (policy/mcp.rego:649) so the Redis bucket key aligns with the OPA
    ``rate_limit_key`` from ``mcp_decision``.  Falls back to the literal
    string ``"anonymous"`` on empty input.
    """
    if not spiffe:
        return "anonymous"
    return hashlib.sha256(spiffe.encode("utf-8")).hexdigest()
