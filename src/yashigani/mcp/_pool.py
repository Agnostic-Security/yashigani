"""
MCP Broker — per-tenant HTTP connection pool manager (P1-pool).

Phase-2 P1-pool finding:

  Per-tenant HTTP connection pools keyed (tenant_id, provider_host).
  Provider-key cache keyed (tenant_id, provider_id).
  Neither structure is ever shared across tenant_ids.

  Prevents cross-tenant connection/key bleed that arises from a single shared
  httpx.AsyncClient (where HTTP/2 multiplexing or connection keep-alive can
  allow tenant A's TCP connection to be reused for tenant B's request if the
  upstream host is the same).

Design:
  • One httpx.AsyncClient per (tenant_id, provider_host) pair.
  • Clients are created on first use and reused thereafter.
  • A threading.Lock guards the client registry dict.
  • Callers must close() all pools at shutdown.
  • Provider-key cache is a simple dict[tuple, str] guarded by the same lock.

Thread-safety note:
  The lock guards the registry dict itself (creation of new entries).
  httpx.AsyncClient is thread-safe for concurrent async calls once created.
  The lock is NOT held during actual HTTP I/O.

v2.25.0 / P1 Phase-2 / P1-pool / YSG-RISK-057 (cross-tenant isolation).
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_POOL_TIMEOUT = 30.0   # seconds


class TenantPoolManager:
    """
    Per-tenant HTTP connection pool manager.

    Each (tenant_id, provider_host) pair gets its own httpx.AsyncClient.
    Provider keys are cached per (tenant_id, provider_id).

    Usage::

        manager = TenantPoolManager()

        # Get (or lazily create) the client for this tenant + host
        client = manager.get_or_create_client("acme", "mcp.example.com")
        response = await client.post(...)

        # Store a provider API key for this tenant
        manager.set_provider_key("acme", "openai", "sk-...")

        # Retrieve it (returns None if not set)
        key = manager.get_provider_key("acme", "openai")

        # Shutdown: close all clients
        await manager.close_all()

    Security invariants:
    - ``get_or_create_client(tenant_id, host)`` NEVER returns a client
      created for a different tenant_id (even if the host is identical).
    - ``get_provider_key(tenant_id, provider_id)`` NEVER returns a value
      stored under a different tenant_id.
    """

    def __init__(
        self,
        timeout_seconds: float = _DEFAULT_POOL_TIMEOUT,
        limits: Optional[httpx.Limits] = None,
    ) -> None:
        self._timeout = timeout_seconds
        self._limits = limits or httpx.Limits(
            max_connections=10,
            max_keepalive_connections=5,
            keepalive_expiry=60.0,
        )
        # Registry: (tenant_id, provider_host) -> httpx.AsyncClient
        self._clients: dict[tuple[str, str], httpx.AsyncClient] = {}
        # Provider-key cache: (tenant_id, provider_id) -> api_key
        self._provider_keys: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()
        self._closed = False

    # ------------------------------------------------------------------
    # Connection pool
    # ------------------------------------------------------------------

    def get_or_create_client(
        self,
        tenant_id: str,
        provider_host: str,
    ) -> httpx.AsyncClient:
        """
        Return the httpx.AsyncClient for (tenant_id, provider_host).

        Creates a new client if one does not exist yet.  Raises RuntimeError
        if the manager has been closed.

        The tenant_id is part of the key: two tenants sharing the same upstream
        host get SEPARATE clients with no connection reuse between them.
        """
        if self._closed:
            raise RuntimeError(
                "TenantPoolManager.get_or_create_client: manager is closed"
            )
        key = (tenant_id, provider_host)
        with self._lock:
            if key not in self._clients:
                logger.debug(
                    "pool: creating httpx.AsyncClient tenant=%s host=%s",
                    tenant_id, provider_host,
                )
                self._clients[key] = httpx.AsyncClient(
                    timeout=self._timeout,
                    limits=self._limits,
                    base_url=f"https://{provider_host}",
                )
            return self._clients[key]

    def client_count(self) -> int:
        """Return the total number of active client pools."""
        with self._lock:
            return len(self._clients)

    def has_client(self, tenant_id: str, provider_host: str) -> bool:
        """Return True if a client exists for (tenant_id, provider_host)."""
        with self._lock:
            return (tenant_id, provider_host) in self._clients

    async def evict_client(self, tenant_id: str, provider_host: str) -> None:
        """Close and remove the client for (tenant_id, provider_host) if present."""
        key = (tenant_id, provider_host)
        with self._lock:
            client = self._clients.pop(key, None)
        if client is not None:
            await client.aclose()
            logger.debug(
                "pool: evicted client tenant=%s host=%s", tenant_id, provider_host
            )

    async def evict_tenant(self, tenant_id: str) -> int:
        """Close and remove all clients for a tenant; returns count removed."""
        with self._lock:
            keys = [k for k in self._clients if k[0] == tenant_id]
            to_close = {k: self._clients.pop(k) for k in keys}
        for client in to_close.values():
            await client.aclose()
        if to_close:
            logger.info("pool: evicted %d clients for tenant=%s", len(to_close), tenant_id)
        return len(to_close)

    # ------------------------------------------------------------------
    # Provider-key cache
    # ------------------------------------------------------------------

    def set_provider_key(
        self,
        tenant_id: str,
        provider_id: str,
        api_key: str,
    ) -> None:
        """
        Cache a provider API key for (tenant_id, provider_id).

        Replaces any existing entry.  Never accessible from a different
        tenant_id.
        """
        key = (tenant_id, provider_id)
        with self._lock:
            self._provider_keys[key] = api_key

    def get_provider_key(
        self,
        tenant_id: str,
        provider_id: str,
    ) -> Optional[str]:
        """
        Retrieve the provider API key for (tenant_id, provider_id).

        Returns None if not set.  NEVER returns a key for a different tenant.
        """
        key = (tenant_id, provider_id)
        with self._lock:
            return self._provider_keys.get(key)

    def evict_provider_key(self, tenant_id: str, provider_id: str) -> None:
        """Remove the cached key for (tenant_id, provider_id) if present."""
        key = (tenant_id, provider_id)
        with self._lock:
            self._provider_keys.pop(key, None)

    def evict_tenant_keys(self, tenant_id: str) -> int:
        """Remove all cached keys for a tenant; returns count removed."""
        with self._lock:
            keys = [k for k in self._provider_keys if k[0] == tenant_id]
            for k in keys:
                del self._provider_keys[k]
        return len(keys)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close_all(self) -> None:
        """
        Close all managed clients and mark the manager as closed.

        Must be called at shutdown.  After close_all(), get_or_create_client()
        raises RuntimeError.
        """
        with self._lock:
            to_close = dict(self._clients)
            self._clients.clear()
            self._provider_keys.clear()
            self._closed = True

        close_coros = [c.aclose() for c in to_close.values()]
        if close_coros:
            await asyncio.gather(*close_coros, return_exceptions=True)
        logger.info("pool: closed %d client pools", len(to_close))

    @property
    def is_closed(self) -> bool:
        return self._closed
