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
(policies + config).  The RBAC push targets ``/v1/data/yashigani/rbac`` +
``/v1/data/yashigani/agents`` (scoped as of V50-022); because OPA's
PUT-by-path only replaces the addressed sub-tree, all pushes under
data.yashigani.* are independent and order-insensitive PROVIDED every writer
stays scoped to its own sub-path.

V50-022 (Tom, 2026-07-29): until fixed, ``rbac/opa_push.py`` PUT the PARENT
path ``/v1/data/yashigani`` (not a scoped sub-path) — that is NOT "the two
pushes are independent"; a parent-path PUT replaces the WHOLE
``data.yashigani`` subtree, which silently wiped THIS module's ``document``
sub-document (along with ``mcp`` and ``allocations``) on every RBAC
mutation. The claim above is only true now that every writer under
data.yashigani.* is correctly scoped — see rbac/opa_push.py's module
docstring for the full incident writeup.
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
