# Last updated: 2026-07-08T12:00:00+00:00
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
import threading
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level LKG cache (R2 — transient Redis failure fallback)
#
# Canonical home for the LKG claimed-SPIFFE snapshot.  Relocated here from
# agent_policies.py (R2 closure: the builder's elif self-read branch needs the
# same LKG; putting it at the source closes the fail-open for ALL callers,
# including mcp_onboard.py:854 which passes claimed_spiffes=None).
#
# agent_policies.py imports _lkg_claimed_lock and _get_claimed_spiffes_lkg from
# here — no duplicate, no circular import (this module only imports stdlib +
# yashigani.identity.trust_domain inside a function).
# ---------------------------------------------------------------------------
_lkg_claimed_lock = threading.Lock()
_lkg_claimed_spiffes: frozenset = frozenset()


def _get_claimed_spiffes_lkg(registry_store: Any) -> frozenset:
    """Return claimed SPIFFEs with LKG fallback on transient store failure (R2).

    On success, updates the module-level snapshot so future failures have a
    fresh baseline.  On failure, returns the last-good snapshot — suppression
    is never dropped to fail-open on a transient Redis blip.

    Used by:
    - agent_policies._run_apply / revoke_grant (explicit pre-resolved path)
    - build_egress_grants_doc's elif self-read branch (mcp_onboard path)
    """
    global _lkg_claimed_spiffes
    try:
        result = registry_store.get_claimed_egress_seed_spiffes()
        with _lkg_claimed_lock:
            _lkg_claimed_spiffes = result
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "egress-grants: get_claimed_egress_seed_spiffes failed (%s) — "
            "using LKG snapshot (%d entries, R2 fallback)",
            exc, len(_lkg_claimed_spiffes),
        )
        with _lkg_claimed_lock:
            return frozenset(_lkg_claimed_spiffes)


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


def bundled_system_spiffe_set() -> frozenset:
    """Return the set of bundled-system SPIFFE URIs (env-derived, runtime).

    Used by ``build_egress_grants_data`` to SERVER-DERIVE ``legacy_system``
    rather than reading it from the store (Lu MF-1, HIGH: a store-suppliable
    ``legacy_system`` is a tenant-conjunct bypass — any SPIFFE lacking an
    ``/agents/`` tenant segment could claim the ``legacy_system`` path in the
    OPA rule and bypass the per-tenant conjunct).

    Returns the same set of SPIFFEs that ``transitional_egress_seed`` keys on.
    ``frozenset()`` on any failure (fail-closed: no SPIFFE gets the flag).
    """
    try:
        return frozenset(transitional_egress_seed().keys())
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "egress-grants: bundled_system_spiffe_set failed (%s) — "
            "returning empty set (no SPIFFE gets legacy_system=true; "
            "bundled pre-migration systems deny egress until fixed)", exc,
        )
        return frozenset()


def build_egress_grants_doc(
    registry_store: Optional[Any],
    claimed_spiffes: Optional[frozenset] = None,
) -> dict:
    """Build the full ``egress_grants`` OPA data sub-document.

    Merges the transitional seed with the durable-registry grants (registry
    wins on a key collision — a real per-instance grant supersedes any seed
    for the same URI).  ``registry_store=None`` (no Redis wired) degrades to
    seed-only: onboarded instances then deny fail-closed until the store is
    reachable and the document re-pushed.

    Seed suppression (design §4.4 / Lu MF-2 fix-2a, R2): once the store has
    been asked to ``put_egress_grant`` for a bundled-system SPIFFE (admin
    applied or has ever been applied), that SPIFFE's seed entry is removed
    before the merge — grant-absence after a subsequent ``delete_egress_grant``
    IS the kill switch (the seed can never resurface it).

    ``claimed_spiffes`` (R2 LKG wiring): when provided, use this pre-resolved
    frozenset for suppression instead of calling
    ``registry_store.get_claimed_egress_seed_spiffes()``.  Callers in
    ``agent_policies.py`` resolve it through ``_get_claimed_spiffes_lkg``
    before calling this function — on a transient Redis failure the LKG
    snapshot is used, so suppression never drops to fail-open on a single
    blip.  When ``claimed_spiffes`` is None (e.g. mcp_onboard.py post-commit
    push or gateway startup push), the builder's elif branch calls
    ``_get_claimed_spiffes_lkg`` directly — same LKG fallback, no fail-open
    regardless of which path the caller takes (Lu R2 structural closure).

    Never raises.
    """
    # Build seed first so we can remove claimed entries before merging.
    seed: dict = {}
    try:
        seed = transitional_egress_seed()
    except Exception as exc:  # noqa: BLE001 — seed failure must not kill the push
        logger.error(
            "egress-grants: transitional seed build failed (%s) — bundled "
            "pre-migration systems will DENY egress at OPA until fixed "
            "(fail-closed; static Caddy pins alone cannot allow)", exc,
        )

    # Seed suppression: remove entries for SPIFFEs the store has ever claimed.
    # Once claimed, grant-absence = kill switch; seed must never resurface a
    # deliberate revocation (Lu MF-2a).
    if claimed_spiffes is not None:
        # R2 path: caller pre-resolved via LKG — use directly, no store call.
        for spiffe in claimed_spiffes:
            seed.pop(spiffe, None)
    elif registry_store is not None:
        # Self-read path (claimed_spiffes=None): caller did not pre-resolve.
        # mcp_onboard.py:854 (onboard-approve post-commit push) is the live
        # caller — it commits the envelope then re-pushes the full doc without
        # an explicit claimed set.
        #
        # Use _get_claimed_spiffes_lkg: on transient failure it returns the
        # last-good snapshot rather than dropping suppression to fail-open.
        # Every successful read updates the snapshot for future fallbacks.
        # Net: a single Redis blip can never resurface a previously-revoked
        # bundled seed grant (Lu R2 Medium×Bypass, structural closure).
        claimed = _get_claimed_spiffes_lkg(registry_store)
        for spiffe in claimed:
            seed.pop(spiffe, None)

    doc: dict = {}
    doc.update(seed)

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
    "bundled_system_spiffe_set",
    "transitional_egress_seed",
    "_get_claimed_spiffes_lkg",
    "_lkg_claimed_lock",
    "_lkg_claimed_spiffes",
]
