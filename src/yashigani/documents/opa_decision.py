"""
Yashigani Document Enforcement — real-OPA decision client (2.26).

Queries the production document rego (policy/document.rego, package
``yashigani.document``) for the document disposition.  This is the path that
makes the document decision run through the ACTUAL OPA engine — the matrix-driven
``action`` (LOG / REDACT / PSEUDONYMIZE / ROUTE_LOCAL / BLOCK) is computed by OPA
from the operator's persisted policies, NOT by a Python branch.  ROUTE_LOCAL is the
PART 2 (Laura D1) field-role escalation: a cloud-bound (mode-B) PSEUDONYMIZE that
carries an OPERATE_ON sensitive field is routed to the LOCAL model by OPA rather
than blobbing a value the cloud would hallucinate over (policy/document.rego
``_route_local_escalation``).  The pipeline's field-role seam stays as the
fail-closed backstop when OPA is unreachable.

Query shape mirrors the gateway proxy's ``_opa_check`` (gateway/proxy.py):
    POST {opa_url}/v1/data/yashigani/document/decision
        body: {"input": {"document": {...}, "routing_decision": {...}, "request": {...}}}
    → {"result": { allow, deny, obligations, action, ... }}

Fail-closed (plan §6.1, NON-NEGOTIABLE): any OPA error, timeout, missing result,
or malformed decision → a synthetic BLOCK decision.  We NEVER fail open: an
unreachable policy engine must not let a document through.
"""
from __future__ import annotations

import logging

from yashigani.pki.client import internal_httpx_client

logger = logging.getLogger(__name__)

_OPA_DECISION_PATH = "/v1/data/yashigani/document/decision"

#: The fail-closed decision returned on ANY error.  Self-describing contract
#: preserved so the layman alert + audit event stay uniform.
_FAIL_CLOSED_DECISION = {
    "allow": False,
    "deny": ["opa_unavailable"],
    "obligations": [],
    "policy_id": "DOC-ENFORCE-001",
    "code": "DOCUMENT_BLOCKED",
    "user_message": (
        "This file was held because the policy engine could not clear it. "
        "It was blocked from leaving your environment."
    ),
    "action": "BLOCK",
    "pseudonymize_mode": "A",
    "per_match_actions": [],
    "matched_classes": [],
    "replacer_map_handle": "",
    "replacer_map_ttl": 300,
    "detokenize_rbac_role": "doc-pseudonymize-reverser",
}


def _coerce(result: object) -> dict:
    """Validate the OPA result is a usable decision; else fail-closed.

    A decision is usable only when it is a dict carrying an ``action`` in the
    known vocabulary.  Anything else (None, wrong type, unknown action) is
    treated as an engine failure and fails closed to BLOCK."""
    if not isinstance(result, dict):
        logger.error("document OPA: result is not an object (%r) — fail-closed", type(result))
        return dict(_FAIL_CLOSED_DECISION)
    action = result.get("action")
    if action not in ("LOG", "REDACT", "PSEUDONYMIZE", "ROUTE_LOCAL", "BLOCK"):
        logger.error("document OPA: unknown action %r — fail-closed", action)
        return dict(_FAIL_CLOSED_DECISION)
    return result


async def evaluate_document_decision(
    opa_url: str,
    document_input: dict,
    *,
    route: str = "any",
    pseudonymize_mode: str = "A",
    timeout_s: float = 5.0,
) -> dict:
    """Evaluate the document disposition through the REAL OPA engine.

    Parameters
    ----------
    opa_url:
        Base URL of the OPA server (e.g. ``https://policy:8181``).
    document_input:
        The ``input.document`` object, i.e. ``DocumentDecisionInput.to_opa_input()``.
    route:
        The routing decision (``ingress-upload`` | ``egress-mcp-result`` | ...);
        matched against each policy's ``route``.
    pseudonymize_mode:
        ``"A"`` (give-the-user-the-table, default) | ``"B"`` (internal round-trip).

    Returns
    -------
    dict
        The OPA ``decision`` document (allow/deny/obligations + action + the
        document-action outputs).  A synthetic fail-closed BLOCK decision on any
        OPA error — this function NEVER raises and NEVER fails open.
    """
    payload = {
        "input": {
            "document": document_input,
            "routing_decision": {"route": route},
            "request": {"pseudonymize_mode": pseudonymize_mode},
        }
    }
    url = opa_url.rstrip("/") + _OPA_DECISION_PATH
    try:
        async with internal_httpx_client(timeout=timeout_s) as client:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.error(
            "document OPA decision failed (%s) — denying (fail-closed BLOCK)", exc
        )
        return dict(_FAIL_CLOSED_DECISION)
    return _coerce(data.get("result"))
