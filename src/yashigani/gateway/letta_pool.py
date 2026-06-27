"""
Yashigani 4.0 — Letta Client Pool: per-user resolution seam (adapter).

This module is the stable import path the user-plane routes use
(``from yashigani.gateway.letta_pool import LettaClientPool``). The concrete
per-user pool now lives in ``yashigani.gateway.letta_client.LettaClientPool``
(Captain, feat/4.0-agent-isolation). This adapter delegates to it and
translates any resolution/availability failure into ``LettaPoolUnavailable``
so route handlers keep their HTTP 503 (``letta_pool_unavailable``) contract.

Interface (unchanged):
  ``client, base_url, default_agent_id = await LettaClientPool.for_user(identity_id)``
  Close the returned client after use (``async with client:``).

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

import httpx

from yashigani.gateway.letta_client import LettaClientPool as _RealLettaClientPool


class LettaPoolUnavailable(RuntimeError):
    """Raised when the per-user Letta pool cannot resolve / is unreachable.

    Route handlers catch this and return HTTP 503 (letta_pool_unavailable).
    """


class LettaClientPool:
    """Adapter over the concrete per-user pool in ``letta_client``.

    Delegates to the real implementation and normalises failures to
    ``LettaPoolUnavailable`` so the user-plane 503 contract is preserved.
    """

    @staticmethod
    async def for_user(identity_id: str) -> tuple[httpx.AsyncClient, str, str]:
        """Return (client, base_url, default_agent_id) for ``identity_id``.

        Raises:
            LettaPoolUnavailable: if the pool cannot provision/resolve the
            user's Letta instance (container not ready, Letta unreachable, etc.).
        """
        try:
            return await _RealLettaClientPool.for_user(identity_id)
        except LettaPoolUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — normalise to the 503 contract
            raise LettaPoolUnavailable(
                f"Letta pool resolution failed for identity_id={identity_id!r}: {exc}"
            ) from exc
