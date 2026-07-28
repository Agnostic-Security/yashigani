"""
Yashigani — shared bounded lazy-reconnect primitive for Redis-backed
control-plane state (RBAC, agent registry, rate limiters, caches, ...).

YSG-RISK-131 (Iris systemic review, 2026-07-28, following the live-reproduced
gateway chat blocker): gateway and backoffice both build a large number of
Redis-dependent control-plane objects in one-shot try/except blocks at cold
boot. On k8s, Service DNS for Redis is not always resolvable at that instant
(the Redis Pod can be scheduled after the consumer Pod, and headless-Service
DNS only populates once the Pod IP registers with kube-dns) — a single failed
attempt then leaves the dependent field ``None`` for the ENTIRE pod lifetime,
because nothing at request time ever retries. docker/podman compose ordering
(``depends_on: condition: service_healthy``) hides this class completely,
which is why it shipped unnoticed until a live k8s deployment reproduced it
(backoffice: YSG-RISK-122; gateway: YSG-RISK-131, 13 additional Redis-backed
subsystems per Iris's remediation map).

This module factors out the *generic* shape first proven in
``backoffice/redis_selfheal.py`` (YSG-RISK-122) — cooldown-gated, at-most-one-
attempt-per-window, cheap non-Redis-round-trip healthy check — into a single
shared primitive, so ``backoffice/redis_selfheal.py`` and
``gateway/redis_selfheal.py`` become thin call-sites instead of two
copy-pasted implementations of the same bookkeeping (the exact "drift pair"
this integration review exists to prevent — see Iris's remediation map,
``testing_runs/yashigani/v412-e2e-latest-20260727/iris/remediation_map.md``).

Each call-site still owns its own ``ensure_*()`` function: a health check, a
builder (raises on failure — this module never invents fail-open behaviour),
and a success callback that writes the built object into whichever
live-read state container that subsystem's consumers actually check.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_last_attempt_monotonic: dict[str, float] = {}


def reset_cooldowns() -> None:
    """Test-only: clear every cooldown gate across every call-site.

    Never invoked from production code — tests use it to isolate timing
    assertions between cases that share this module's process-global gate.
    """
    with _lock:
        _last_attempt_monotonic.clear()


def _cooldown_elapsed(name: str, cooldown_s: float) -> bool:
    """Thread-safe "at most one attempt per cooldown_s window" gate, keyed by *name*."""
    now = time.monotonic()
    with _lock:
        last = _last_attempt_monotonic.get(name)
        if last is not None and (now - last) < cooldown_s:
            return False
        _last_attempt_monotonic[name] = now
        return True


def ensure(
    name: str,
    *,
    is_healthy: Callable[[], bool],
    build: Callable[[], Any],
    on_success: Callable[[Any], None],
    cooldown_s: float,
    unavailable_msg: str,
    recovered_msg: str,
) -> bool:
    """Bounded lazy reconnect for a single Redis-backed dependency.

    Returns True if *name* is healthy after this call (either it was already
    healthy — zero Redis round-trips in that case — or a reconnect attempt
    just succeeded); False if it remains unavailable.

    Never raises for a *build* failure: the exception is caught, logged, and
    turned into a ``False`` return so the caller's existing fail-closed
    503/disabled behaviour is completely unchanged — this primitive only
    changes WHO retries and WHEN, never whether a genuine outage is denied.
    A failure inside *on_success* (a bug in wiring code, not a Redis outage)
    is NOT swallowed — it propagates, since silently eating a real wiring bug
    the same way a Redis outage is handled would hide defects instead of
    fixing them.
    """
    if is_healthy():
        return True

    if not _cooldown_elapsed(name, cooldown_s):
        return False

    try:
        result = build()
    except Exception as exc:
        logger.warning(
            "%s (%s) — will retry after %.0fs", unavailable_msg, exc, cooldown_s
        )
        return False

    on_success(result)
    logger.info("%s (YSG-RISK-131 self-heal)", recovered_msg)
    return True
