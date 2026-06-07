"""Gateway client-policy enforcement (#16, OPA Phase 2).

Single OPA round-trip per direction to the client_enforce aggregator
(policy/clients_aggregate.rego, package client_enforce). Called STRICTLY AFTER
the existing core gates (_opa_v1_check / _opa_response_check) so it can only ADD
denials, never remove one. Fail-closed on every error/undefined.

Mirrors _opa_check's config access (cfg.opa_url) and the dev opt-in
(YASHIGANI_OPA_OPTIONAL + non-production) used by the response-leg check.
"""
from __future__ import annotations

import logging
import os

from yashigani.metrics.registry import client_enforce_failures_total
from yashigani.pki.client import internal_httpx_client

logger = logging.getLogger(__name__)

_AGGREGATE_PATH = "/v1/data/client_enforce/aggregate"

# IdentityKind / principal -> binding scope_kind. The gateway resolves the
# concrete scope_id (agent id, api-client id, user email) at the call site.
_SCOPE_KIND_BY_IDENTITY = {
    "human": "human",
    "service": "service",
    "api_client": "api_client",
    "agent": "agent",
    "mcp_server": "mcp_server",
}


def scope_kind_for(identity_kind: str | None) -> str:
    """Map an identity/principal kind to a binding scope_kind. Unknown -> 'human'
    (the most restrictive default scope; bindings are additive deny-only so an
    unbound 'human' scope is a no-op pass-through)."""
    return _SCOPE_KIND_BY_IDENTITY.get((identity_kind or "").lower(), "human")


def _dev_opt_in() -> bool:
    return (
        os.getenv("YASHIGANI_OPA_OPTIONAL", "false").strip().lower() == "true"
        and os.getenv("YASHIGANI_ENV", "production").strip().lower() != "production"
    )


def _fail(direction: str, outcome: str, code: str) -> dict:
    try:
        client_enforce_failures_total.labels(direction=direction, outcome=outcome).inc()
    except Exception:  # pragma: no cover — metrics must never break a request
        pass
    return {"allow": False, "deny": [code], "obligations": []}


async def evaluate_client_policies(
    cfg, scope_kind: str, scope_id: str, direction: str, base_input: dict
) -> dict:
    """Evaluate bound client policies for (scope_kind, scope_id, direction).

    Returns {"allow": bool, "deny": [codes], "obligations": [names]}. Fail-closed:
    missing OPA (prod), non-2xx, exception, or an undefined/ non-dict result all
    yield allow=False with a diagnostic deny code. Dev opt-in (OPA optional +
    non-prod) allows when OPA is not configured, mirroring _opa_check.
    """
    opa_url = getattr(cfg, "opa_url", "") or ""
    if not opa_url:
        if _dev_opt_in():
            return {"allow": True, "deny": [], "obligations": []}
        return _fail(direction, "not_configured", "client_enforce_not_configured")

    doc = dict(base_input)
    doc["_scope"] = {"kind": scope_kind, "id": scope_id or ""}
    doc["_direction"] = direction

    try:
        async with internal_httpx_client(timeout=5.0) as client:
            resp = await client.post(
                opa_url.rstrip("/") + _AGGREGATE_PATH,
                json={"input": doc},
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            res = resp.json().get("result")
            if not isinstance(res, dict):  # undefined -> fail-closed
                return _fail(direction, "undefined", "client_enforce_undefined")
            return {
                "allow": bool(res.get("allow", False)),
                "deny": list(res.get("deny", []) or []),
                "obligations": list(res.get("obligations", []) or []),
            }
    except Exception as exc:  # noqa: BLE001 — any failure denies fail-closed
        logger.error(
            "client-policy enforce FAILED (scope=%s:%s dir=%s): %s — denying fail-closed",
            scope_kind, scope_id, direction, exc,
        )
        return _fail(direction, "exception", "client_enforce_unavailable")
