"""
Yashigani Document Enforcement — OPA data push (2.26).

Pushes the document-enforcement policy matrix + config to OPA so the production
rego (policy/document.rego) evaluates the operator's live configuration.

This MIRRORS :mod:`yashigani.rbac.opa_push` exactly — same internal-mTLS client,
same PUT-the-whole-subtree-atomically idiom, same fail-loud-to-caller contract —
but targets the ``document`` sub-namespace so it never clobbers the RBAC/agents
sub-trees the RBAC push owns.

OPA Data API endpoint:
    PUT {opa_url}/v1/data/yashigani/document

This replaces the entire ``data.yashigani.document`` sub-document atomically
(policies + config).  The RBAC push targets ``/v1/data/yashigani`` (rbac +
agents); because OPA's PUT-by-path only replaces the addressed sub-tree, the two
pushes are independent and order-insensitive.
"""
from __future__ import annotations

import logging

from yashigani.pki.client import internal_httpx_sync_client

logger = logging.getLogger(__name__)

_OPA_DOCUMENT_PATH = "/v1/data/yashigani/document"


def push_document_data(store, opa_url: str) -> None:
    """Build the document data document from *store* and PUT it to OPA.

    Raises:
        httpx.HTTPStatusError  — OPA returned a non-2xx status.
        httpx.RequestError     — Network or connection error.

    The caller is responsible for logging/auditing; the store mutation itself
    has already succeeded by the time this is called.
    """
    assert store is not None, "push_document_data: store is required"
    opa_doc = store.to_opa_document()

    url = opa_url.rstrip("/") + _OPA_DOCUMENT_PATH
    # OPA serves mTLS; use internal_httpx_sync_client (EX-231-01), same as the
    # RBAC push.
    with internal_httpx_sync_client(timeout=10.0) as client:
        response = client.put(
            url,
            json=opa_doc,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()

    logger.info(
        "OPA document data pushed: %d document policy(ies)",
        len(opa_doc.get("policies", [])),
    )
