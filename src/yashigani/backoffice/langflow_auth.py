"""
Langflow API key manager for backoffice → langflow system calls (v4.1 F-G).

Implements the correct langflow app-layer auth for backoffice→langflow API calls.
The gateway's langflow_client.py already uses this pattern; this module mirrors
it for the backoffice process (a separate container).

On first use (lazy, thread-safe):
  1. GET  {url}/api/v1/auto_login     → session bearer (LANGFLOW_AUTO_LOGIN=true)
  2. GET  {url}/api/v1/api_key/       → list existing 'yashigani-service' keys
  3. DELETE {url}/api/v1/api_key/{id} → delete each (Laura constraint 2: one-key
                                         invariant — leaked SQLite snapshot → no
                                         valid old key)
  4. POST {url}/api/v1/api_key/       → create a fresh 'yashigani-service' key
  5. Cache the key at module level

Exposes:
    get_langflow_api_headers() -> {"x-api-key": <cached_key>}

All calls route through Caddy (YASHIGANI_LANGFLOW_INTERNAL_URL →
https://caddy:9705/agents/default/langflow). The Caddy mTLS + verify-mcp gate
is UNCHANGED — this module only fixes langflow application-layer auth.

Dependency: LANGFLOW_AUTO_LOGIN=true (required operational setting per design §5
FLAG-5). If not set, auto_login returns 401 and get_langflow_api_headers() raises
with a clear error log.

Last updated: 2026-07-09T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import threading

logger = logging.getLogger(__name__)

# Name used when creating the backoffice service API key in langflow's store.
_KEY_NAME = "yashigani-service"

# Module-level cache — one API key per backoffice process lifetime.
_api_key: str | None = None
_lock = threading.Lock()


def _langflow_url() -> str:
    """Langflow Caddy ingress URL (same env var as reconciler)."""
    return os.environ.get(
        "YASHIGANI_LANGFLOW_INTERNAL_URL", "http://langflow:7860"
    ).rstrip("/")


def _init_api_key() -> str:
    """Obtain a fresh langflow API key via list → delete → create.

    Laura constraint 2 (MANDATORY): enumerate ALL existing 'yashigani-service'
    keys and DELETE them before creating a new one.  This ensures exactly one
    live key at any time — a leaked snapshot of langflow's SQLite store cannot
    contain a valid stale 'yashigani-service' key.

    Raises RuntimeError on any failure (auto_login failure, network error,
    creation failure).  Caller logs and skips the reconciler tick.
    """
    from yashigani.pki.client import internal_httpx_sync_client  # noqa: PLC0415

    url = _langflow_url()
    with internal_httpx_sync_client(timeout=15.0) as client:
        # Step 1: auto_login → session bearer (requires LANGFLOW_AUTO_LOGIN=true)
        resp = client.get(f"{url}/api/v1/auto_login")
        if resp.status_code != 200:
            raise RuntimeError(
                f"langflow-auth: auto_login failed ({resp.status_code}) — "
                "LANGFLOW_AUTO_LOGIN=true is a required operational setting"
            )
        access_token = resp.json().get("access_token", "")
        if not access_token:
            raise RuntimeError("langflow-auth: auto_login returned no access_token")
        session_headers = {"Authorization": f"Bearer {access_token}"}

        # Step 2: list existing 'yashigani-service' keys (Laura constraint 2)
        list_resp = client.get(f"{url}/api/v1/api_key/", headers=session_headers)
        if list_resp.status_code == 200:
            existing = list_resp.json()
            if not isinstance(existing, list):
                existing = []
            for key_rec in existing:
                if not isinstance(key_rec, dict):
                    continue
                if key_rec.get("name") == _KEY_NAME:
                    key_id = str(key_rec.get("id", "")).strip()
                    if key_id:
                        del_resp = client.delete(
                            f"{url}/api/v1/api_key/{key_id}",
                            headers=session_headers,
                        )
                        logger.info(
                            "langflow-auth: deleted stale '%s' key id=%s "
                            "status=%d (Laura constraint 2 — one-key invariant)",
                            _KEY_NAME,
                            key_id,
                            del_resp.status_code,
                        )
        else:
            logger.warning(
                "langflow-auth: key list returned %d — "
                "proceeding without cleanup",
                list_resp.status_code,
            )

        # Step 3: create a fresh key
        create_resp = client.post(
            f"{url}/api/v1/api_key/",
            json={"name": _KEY_NAME},
            headers=session_headers,
        )
        if create_resp.status_code not in (200, 201):
            raise RuntimeError(
                f"langflow-auth: key creation failed ({create_resp.status_code})"
            )
        api_key = create_resp.json().get("api_key", "")
        if not api_key:
            raise RuntimeError(
                "langflow-auth: key creation response missing 'api_key' field"
            )

        logger.info(
            "langflow-auth: minted fresh '%s' API key "
            "(one-key invariant held, Laura constraint 2)",
            _KEY_NAME,
        )
        return api_key


def get_langflow_api_headers() -> dict:
    """Return {'x-api-key': <cached_key>} for langflow API calls.

    Thread-safe lazy initialisation.  On first call: auto_login → list stale
    keys → delete each → create fresh 'yashigani-service' key (Laura
    constraint 2).  Subsequent calls return the module-level cache.

    Raises RuntimeError on init failure — caller should log and skip the tick.
    """
    global _api_key
    if _api_key is not None:
        return {"x-api-key": _api_key}
    with _lock:
        if _api_key is None:
            _api_key = _init_api_key()
    return {"x-api-key": _api_key}


def _reset_cache_for_testing() -> None:
    """Reset module-level cache (test helper only — not for production use)."""
    global _api_key
    with _lock:
        _api_key = None


__all__ = ["get_langflow_api_headers"]
