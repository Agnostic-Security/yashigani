"""
MCP Broker — JWKS endpoint response builder.

Per Nico spec §5:
  - Endpoint: GET /.well-known/yashigani-mcp-jwks.json
  - Cache-Control: max-age=300, must-revalidate
  - No auth required (public endpoint).
  - Must be served over TLS.
  - During rotation overlap: both old and new keys included atomically.

Key rotation overlap:
  After a key rotation event, both old and new keys are in the JWKS response.
  The old key is retired after max_jwt_ttl + skew_tolerance = 65 seconds.
  Swap is atomic (read-copy-update via _active_jwks reference replacement).

v2.25.0 / P1 W3 Phase 2b-ii / Nico spec §5.
"""
from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

JWKS_CACHE_CONTROL = "max-age=300, must-revalidate"
JWKS_PATH = "/.well-known/yashigani-mcp-jwks.json"


class JwksStore:
    """
    Thread-safe JWKS response store with rotation overlap support.

    Usage:
        store = JwksStore(issuer)
        # On rotation:
        store.rotate(new_issuer)
        # In JWKS endpoint handler:
        return store.response()
    """

    def __init__(self, primary_issuer: object) -> None:
        """
        Parameters
        ----------
        primary_issuer:
            McpJwtIssuer instance. The public key JWK is read from it.
        """
        self._lock = threading.Lock()
        # List of JWK dicts — atomically replaced on rotation
        self._active_jwks: list[dict] = [primary_issuer.public_key_jwk()]  # type: ignore[attr-defined]

    def response(self) -> dict:
        """
        Return the current JWKS JSON dict.

        This is an atomic read — the caller always gets a consistent snapshot
        of either pre-rotation, overlap, or post-rotation keys.

        Thread-safe: uses a reference swap (read-copy-update pattern).
        """
        # Atomic reference read — no lock needed for reads (Python GIL)
        return {"keys": list(self._active_jwks)}

    def rotate(
        self,
        new_issuer: object,
        old_issuer: Optional[object] = None,
    ) -> None:
        """
        Initiate key rotation.

        Atomically replaces the JWKS with a set containing both old and new
        keys (rotation overlap window). Call retire_old() after
        max_jwt_ttl + skew_tolerance = 65 seconds to remove the old key.

        Parameters
        ----------
        new_issuer:
            New McpJwtIssuer instance with the new key.

        old_issuer:
            Old McpJwtIssuer instance. If provided, its JWK is included in
            the overlap set. If None, the current active JWKs are carried
            forward as the overlap set.
        """
        with self._lock:
            if old_issuer is not None:
                overlap_jwks = [
                    old_issuer.public_key_jwk(),  # type: ignore[attr-defined]
                    new_issuer.public_key_jwk(),  # type: ignore[attr-defined]
                ]
            else:
                # Include current active keys + new key
                overlap_jwks = list(self._active_jwks) + [new_issuer.public_key_jwk()]  # type: ignore[attr-defined]
            self._active_jwks = overlap_jwks
            logger.info(
                "mcp-broker: JWKS rotation overlap — %d keys active (old+new)",
                len(overlap_jwks),
            )

    def retire_old(self, new_issuer: object) -> None:
        """
        Remove old keys, leaving only the new issuer's key.

        Call after max_jwt_ttl + skew_tolerance (65s) from rotation start.
        """
        with self._lock:
            self._active_jwks = [new_issuer.public_key_jwk()]  # type: ignore[attr-defined]
            logger.info("mcp-broker: JWKS old key retired — 1 key active")

    @property
    def key_count(self) -> int:
        return len(self._active_jwks)
