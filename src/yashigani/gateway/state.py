"""
Yashigani Gateway — process-wide fallback state for components that
snapshot a Redis-backed dependency BY VALUE at construction time.

YSG-RISK-131: most gateway consumers of the RBAC/Agent-registry Redis stack
already read a live, mutable container at request time (``openai_router``'s
module-level ``_state``, and ``proxy.py``'s per-app ``_state`` dict exposed
via ``app.state.internal_state``) — self-heal just needs to write into those
containers and every subsequent request sees the update.

Two consumers do NOT read live state — they capture the constructor argument
into an instance attribute exactly once, at gateway-app build time:

  * ``AgentAuthMiddleware`` (``gateway/agent_auth.py``) — ``self._registry``,
    used to authenticate ``/agents/*`` inter-service calls.
  * ``MetricsCollector`` (``metrics/collectors.py``) — ``self._rbac_store`` /
    ``self._agent_registry``, used for the ``rbac_groups_total`` /
    ``agent_registry_size`` gauges.

If the cold-boot build failed, these objects are constructed with ``None``
and would stay ``None`` for the pod's entire lifetime even after a
self-healed reconnect populates every other consumer — unless something
central gets updated and BOTH of these fall back to reading it. This module
is that fallback: a tiny, purpose-built process singleton, NOT a general
"gateway state" god-object. Do not add fields here for anything that already
has a live-read home (``openai_router._state`` or ``proxy.py``'s
``app.state.internal_state``) — that would just create a second stale copy.

Last updated: 2026-07-28T00:00:00+00:00
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class GatewayFallbackState:
    rbac_store: Optional[Any] = None
    agent_registry: Optional[Any] = None


gateway_fallback_state = GatewayFallbackState()
