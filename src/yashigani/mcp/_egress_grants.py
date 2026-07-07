# Last updated: 2026-07-06T00:00:00+00:00
"""
Yashigani MCP — (caller, prefix) egress grant document builder.

v4.1 unified-sidecar Phase 1 (Lu M1/M2, Laura L-US-1 — synthesis must-fix #1).

THE INPUT/DATA CONTRACT (what OPA enforces — policy/mcp.rego)
-------------------------------------------------------------
Input (built server-side by ``query_mcp_response_decision(egress_prefix=...)``;
the /egress/eval producer ALWAYS emits it)::

    input.egress = {"prefix": "<slug>"}     # first-class — never smuggled in
                                            # tool_name (that stays audit-only)
    input.caller.spiffe                     # EXACT presented SPIFFE URI
                                            # (Caddy-stamped from the verified
                                            # peer leaf — forge-proof)

Data (this module builds it; pushed to
``data.yashigani.mcp.egress_grants``)::

    {
      "<EXACT per-instance SPIFFE URI>": {
        "tenant":        "<tenant_id>",     # must equal the tenant embedded in
                                            # the /agents/<t>/<n>/<i> URI
        "prefixes":      ["slack", ...],    # POSITIVE set; [] = no egress
        "legacy_system": true,              # OPTIONAL — transitional only (see
                                            # below); never set for /agents/ URIs
      }
    }

Decision: ``allow`` requires ``input.egress.prefix in
egress_grants[input.caller.spiffe].prefixes`` with the tenant conjunct —
CLOSED world: absent data, absent caller key, empty prefixes, tenant
mismatch → DENY (``caller_not_granted_prefix``).  Grant-absence is the kill
switch (Nico Q3): revocation = re-pushing the document without the key.

Sources merged by :func:`build_egress_grants_doc` (store wins on collision):

1. **Transitional bundled-system seed** — pre-migration systems (openclaw)
   still hold a hand-minted SYSTEM-form identity
   (``spiffe://<td>/openclaw``, env ``YASHIGANI_OPENCLAW_SPIFFE_ID`` — the
   SAME env the live static Caddyfile pin keys on,
   docker/Caddyfile.openclaw-egress caller gate).  Without the seed, landing
   the closed-world grant model would hard-break openclaw's live Slack/
   Telegram egress (breaks-data-flow).  The seed grants exactly the prefixes
   the static Caddyfile handles expose (slack, slack-hooks, telegram) and is
   flagged ``legacy_system: true`` — the rego admits system-form URIs ONLY
   with that explicit flag.  This is the pin-AND-grants overlap the synthesis
   requires before any pin deletion.  RETIRES when openclaw migrates to a
   per-instance ``/agents/`` identity (design §3.1 step 1).

2. **Durable-registry grants** — written inside the step-up-gated approve
   transaction (backoffice/mcp_onboard.py step 4b-ii) from the manifest's
   declared ``spec.egress.needs[].prefix``, audited via
   ``MCP_EGRESS_GRANT_WRITTEN``.

Failure posture: building never raises (a broken Redis degrades to
seed-only → onboarded instances deny fail-closed); PUSHING is the caller's
concern (gateway startup push / backoffice approve push — both non-fatal,
deny-until-pushed is fail-closed).
"""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Egress prefixes exposed by the static egress Caddyfile per bundled system
# (docker/Caddyfile.openclaw-egress eval handles).  The transitional seed
# grants EXACTLY these sets — no more.  Mirrors each bundle descriptor's
# spec.egress.needs (bundles/<system>-egress.yaml) exactly.
#
# v4.1 three-agent wrap (2026-07-07): langflow + letta join openclaw on the
# unified egress-forwarder template.  Their ONLY governed outbound is the
# `llm` class (design §2.4 — /llm eval handle → /deliver/llm →
# gateway:8081); openclaw additionally keeps its Slack/Telegram prefixes.
_TRANSITIONAL_SYSTEM_PREFIXES: dict[str, tuple[str, ...]] = {
    "openclaw": ("llm", "slack", "slack-hooks", "telegram"),
    "langflow": ("llm",),
    "letta": ("llm",),
}

# Retained for backwards compatibility (tests/contract references).
_OPENCLAW_TRANSITIONAL_PREFIXES = _TRANSITIONAL_SYSTEM_PREFIXES["openclaw"]


def transitional_egress_seed() -> dict:
    """Return the transitional bundled-system egress grants.

    One entry per pre-migration bundled system (openclaw, langflow, letta).
    Keyed on the SAME env-configured SPIFFE the static Caddyfile gates use
    (``YASHIGANI_<SYSTEM>_SPIFFE_ID``, default
    ``spiffe://<trust_domain>/<system>``), granting exactly the prefixes the
    static egress Caddyfile exposes for that system.  ``legacy_system: true``
    is REQUIRED by the rego for system-form (non-/agents/) URIs.

    Harmless when a system is not installed: no leaf carries the seeded URI,
    so the grant is unreachable.  Each entry retires at that system's
    migration to a per-instance identity (design §3.1-§3.3).
    """
    from yashigani.identity.trust_domain import trust_domain  # noqa: PLC0415

    td = trust_domain()
    tenant = os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"
    seed: dict = {}
    for system, prefixes in _TRANSITIONAL_SYSTEM_PREFIXES.items():
        spiffe = (
            os.environ.get(
                "YASHIGANI_%s_SPIFFE_ID" % system.upper().replace("-", "_"), ""
            ).strip()
            or "spiffe://%s/%s" % (td, system)
        )
        seed[spiffe] = {
            "tenant": tenant,
            "prefixes": sorted(prefixes),
            "legacy_system": True,
        }
    return seed


def build_egress_grants_doc(registry_store: Optional[Any]) -> dict:
    """Build the full ``egress_grants`` OPA data sub-document.

    Merges the transitional seed with the durable-registry grants (registry
    wins on a key collision — a real per-instance grant supersedes any seed
    for the same URI).  ``registry_store=None`` (no Redis wired) degrades to
    seed-only: onboarded instances then deny fail-closed until the store is
    reachable and the document re-pushed.

    Never raises.
    """
    doc: dict = {}
    try:
        doc.update(transitional_egress_seed())
    except Exception as exc:  # noqa: BLE001 — seed failure must not kill the push
        logger.error(
            "egress-grants: transitional seed build failed (%s) — bundled "
            "pre-migration systems will DENY egress at OPA until fixed "
            "(fail-closed; static Caddy pins alone cannot allow)", exc,
        )
    if registry_store is not None:
        try:
            doc.update(registry_store.build_egress_grants_data())
        except Exception as exc:  # noqa: BLE001 — store failure degrades to seed-only
            logger.error(
                "egress-grants: durable-registry grant read failed (%s) — "
                "onboarded instances will DENY egress at OPA until the store "
                "is reachable and the document re-pushed (fail-closed)", exc,
            )
    return doc


__all__ = [
    "build_egress_grants_doc",
    "transitional_egress_seed",
]
