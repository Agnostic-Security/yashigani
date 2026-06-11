"""
Yashigani Models — OPA allocation data push (Track B1).

Pushes the live model-allocation document to OPA at
``/v1/data/yashigani/allocations`` after every allocation mutation, and on
backoffice startup (reconcile from the durable Redis store). This mirrors the
RBAC ``push_rbac_data`` force-push so allocation changes take effect promptly
and survive an OPA restart (OPA holds data in memory only).

NOTE: actual model-RBAC ENFORCEMENT is performed in the gateway, which computes
the effective allowed-models set from the SAME durable allocation store on the
request path and feeds it into ``input.identity.allowed_models``. This pushed
document is the inspectable / reconciled mirror of the allocation set; pushing
it keeps OPA's view consistent and supports operator inspection + any future
in-rego use. The push targets a SEPARATE ``allocations`` namespace and never
touches the ``rbac`` document.
"""
from __future__ import annotations

import logging

from yashigani.pki.client import internal_httpx_sync_client

logger = logging.getLogger(__name__)

_OPA_DATA_PATH = "/v1/data/yashigani/allocations"


def push_allocations_data(store, opa_url: str) -> None:
    """Build the allocation document from *store* and PUT it to OPA.

    Raises httpx errors on non-2xx / network failure — the caller decides
    whether to swallow (store is authoritative) or surface.
    """
    if store is None or not opa_url:
        return
    doc = store.to_opa_document()
    url = opa_url.rstrip("/") + _OPA_DATA_PATH
    with internal_httpx_sync_client(timeout=10.0) as client:
        response = client.put(
            url,
            json=doc,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
    by_scope = doc.get("by_scope", {})
    logger.info(
        "OPA allocation data pushed: org=%d group=%d user=%d scope(s)",
        len(by_scope.get("org", {})),
        len(by_scope.get("group", {})),
        len(by_scope.get("user", {})),
    )
