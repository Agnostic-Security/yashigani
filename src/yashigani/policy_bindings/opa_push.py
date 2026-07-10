"""Yashigani policy-bindings — OPA data push (#16, OPA Phase 2).

Pushes the client-binding document to OPA under the SEPARATE
/v1/data/client_bindings namespace. This is deliberately disjoint from
/v1/data/yashigani (which push_rbac_data replaces atomically) so the two pushes
are independent and neither clobbers the other.

OPA holds data in memory only, so the backoffice re-pushes on startup (app.py
lifespan) after the RBAC re-sync, using the same retry pattern.
"""
from __future__ import annotations

import logging

from yashigani.pki.client import internal_httpx_sync_client
from yashigani.policy_bindings.store import BindingStore

logger = logging.getLogger(__name__)

_OPA_DATA_PATH = "/v1/data/client_bindings"


def push_bindings_data(store: BindingStore | None, opa_url: str) -> None:
    """PUT the client-binding document to OPA at /v1/data/client_bindings.

    Does NOT touch /v1/data/yashigani — this namespace is owned solely by the
    binding store, so push_rbac_data and this are independent.

    Raises:
        httpx.HTTPStatusError — OPA returned a non-2xx status.
        httpx.RequestError    — network/connection error.
    """
    assert store is not None, "push_bindings_data: store is required"
    # to_opa_document() returns {"client_bindings": {...}}; PUT the inner doc to
    # the /v1/data/client_bindings node so OPA sees data.client_bindings[...].
    opa_doc = store.to_opa_document()["client_bindings"]

    url = opa_url.rstrip("/") + _OPA_DATA_PATH
    with internal_httpx_sync_client(timeout=10.0) as client:
        response = client.put(
            url,
            json=opa_doc,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    logger.info("OPA client-bindings pushed: %d scope key(s)", len(opa_doc))
