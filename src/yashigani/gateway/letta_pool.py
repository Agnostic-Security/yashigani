"""
Yashigani 4.0 — Letta Client Pool: per-user resolution seam.

PINNED SEAM: Captain is building the full implementation on
feat/4.0-agent-isolation.  This module defines the interface so that
user-plane routes can be written and tested NOW, while the concrete pool
wiring is in progress.

Until feat/4.0-agent-isolation merges, ``LettaClientPool.for_user()``
raises ``LettaPoolUnavailable``.  Route handlers MUST catch this and
return HTTP 503 with error code ``letta_pool_unavailable``.

Interface contract (Captain must honour this):
  ``await LettaClientPool.for_user(identity_id)``
  Returns ``(client, base_url, default_agent_id)`` where:
    client           — ``httpx.AsyncClient`` configured for the user's Letta
                       instance (correct base-URL, no auth — gateway-internal)
    base_url         — Letta REST root (e.g. ``http://letta:8283``)
    default_agent_id — The Letta agent_id to use when no specific agent is
                       requested (the user's "primary" Letta agent)

  For multi-agent users, callers obtain ``base_url`` and ``client`` from
  this call, then pass the specific ``letta_agent_id`` stored in their
  local metadata (ua:meta:{ua_agent_id}.letta_agent_id) to Letta API calls
  directly — they do NOT use the returned ``default_agent_id``.

Callers must close the returned client after use::
    client, base_url, _ = await LettaClientPool.for_user(identity_id)
    async with client:
        resp = await client.get(f"{base_url}/v1/agents/")

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import httpx


class LettaPoolUnavailable(RuntimeError):
    """Raised when the per-user Letta pool is not yet implemented.

    Route handlers catch this and return HTTP 503 (letta_pool_unavailable).
    """


class LettaClientPool:
    """Per-user Letta client resolver.

    Stub until feat/4.0-agent-isolation (Captain) merges.
    """

    @staticmethod
    async def for_user(identity_id: str) -> tuple[httpx.AsyncClient, str, str]:
        """Return (client, base_url, default_agent_id) for ``identity_id``.

        Raises:
            LettaPoolUnavailable: always, until Captain's implementation lands.
        """
        raise LettaPoolUnavailable(
            "LettaClientPool is not yet wired. "
            "Awaiting feat/4.0-agent-isolation (Captain). "
            f"Requested identity_id={identity_id!r}."
        )
