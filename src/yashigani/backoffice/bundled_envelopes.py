"""
Bundled-agent capability-envelope bootstrap (v4.1 unified-sidecar §2.5).

The §2.5 agent INGRESS fronts forward_auth every dispatch to
``/auth/verify-mcp``, whose step 3 requires an ACTIVE capability envelope
for the target ``(tenant, server)``.  BYO MCP servers get their envelope
from the import/approve ceremony (backoffice/routes/mcp_servers.py); the
BUNDLED agents (openclaw / langflow / letta) are enabled by the installing
operator via install.sh compose profiles and never pass through that
ceremony — so every dispatch through their fronts denied
``server_not_onboarded`` (fail-closed, no data path).

This module mints the missing envelopes at backoffice startup, reusing the
EXISTING envelope mechanism (CapabilityEnvelopeService, append-only,
single-active) — no parallel store, no verify-mcp weakening:

  * CLOSED allowlist: only the install-shipped bundled systems
    (_BUNDLED_INGRESS_AGENTS) are ever auto-minted.  A BYO agent registered
    with a caddy-front upstream NEVER gets an auto envelope — its approval
    remains the onboarding ceremony (auto-minting it would bypass the gate).
  * Registry-derived: a bundled system is bootstrapped only when the agent
    registry actually holds a registration whose upstream_url is its Caddy
    ingress front (``https://caddy:<port>/agents/<tenant>/<system>``) — i.e.
    only when the operator enabled the profile at install time.
  * Idempotent: an existing ACTIVE envelope for the provenance key
    (``<tenant>:<system>`` — the verify-mcp lookup key, iris §1) is never
    superseded or touched.
  * Honest record: tools={} (bundled agents expose an HTTP/OpenAI surface,
    not MCP tools — the envelope authorises ingress transport only);
    svid_spiffe_id records the TRANSITIONAL hand-minted service leaf
    (``spiffe://<td>/<system>``, bundles/<system>-egress.yaml overlap
    phase) with svid_issued=False — no per-instance /agents/ leaf was
    minted by an approve transaction (that lands with the §3.x identity
    migration).  Egress posture mirrors each bundle's §2.4 forwarder class.

Failure mode: any error here leaves verify-mcp denying the affected front
(fail-closed) until the next backoffice boot retries — availability-only
degradation, never an open path.

Last updated: 2026-07-07T00:00:00+00:00
"""
from __future__ import annotations

import logging
import re
from typing import Any

from yashigani.mcp._envelope import ServerEnvelope, surface_set_hash
from yashigani.mcp.envelope_service import (
    TOPOLOGY_RING_FENCED,
    CapabilityEnvelopeService,
)

_log = logging.getLogger("yashigani.backoffice.bundled_envelopes")

# CLOSED allowlist of install-shipped bundled agents → egress posture floor
# (D5, informational for a tool-less envelope).  Mirrors the §2.4 forwarder
# classes in bundles/<system>-egress.yaml: langflow/letta deliver internally
# (gateway-inference); openclaw has internet-facing egress needs.
# Any system NOT in this map is never auto-minted.
_BUNDLED_INGRESS_AGENTS: dict[str, str] = {
    "langflow": "INTERNAL",
    "letta": "INTERNAL",
    "openclaw": "OUTBOUND",
}

# The non-human operator identity recorded on auto-minted envelopes.  The
# underlying approval authority is the installing operator's explicit
# profile selection at install time (install.sh --profile / COMPOSE_PROFILES).
_BOOTSTRAP_OPERATOR = "system:bundled-agent-bootstrap"

# Caddy ingress-front upstream shape registered by install.sh
# (register_agents: https://caddy:<mesh_port>/agents/<tenant>/<system>).
# Slug charset mirrors auth.py _VERIFY_MCP_SLUG_RE.
_FRONT_UPSTREAM_RE = re.compile(
    r"^https://caddy:\d{4,5}"
    r"/agents/([a-zA-Z0-9][a-zA-Z0-9\-_]{0,62})/([a-zA-Z0-9][a-zA-Z0-9\-_]{0,62})/?$"
)


def _trust_domain() -> str:
    from yashigani.identity.trust_domain import trust_domain  # noqa: PLC0415
    return trust_domain()


def bundled_targets_from_registry(agent_registry: Any) -> list[tuple[str, str]]:
    """Return the ``(tenant, system)`` pairs needing a bundled envelope.

    Derived from live agent registrations: only upstreams matching the Caddy
    ingress-front shape AND whose system segment is in the closed bundled
    allowlist qualify.  Deterministic order, de-duplicated.
    """
    seen: set[tuple[str, str]] = set()
    targets: list[tuple[str, str]] = []
    for agent in agent_registry.list_all():
        upstream = str(agent.get("upstream_url") or "")
        m = _FRONT_UPSTREAM_RE.match(upstream)
        if m is None:
            continue
        tenant, system = m.group(1), m.group(2)
        if system not in _BUNDLED_INGRESS_AGENTS:
            # BYO / user-callee registrations never get auto envelopes —
            # their approval path is the onboarding ceremony.
            continue
        key = (tenant, system)
        if key not in seen:
            seen.add(key)
            targets.append(key)
    return targets


def _minimal_bundled_envelope(tenant: str, system: str) -> ServerEnvelope:
    """A tool-less envelope for a bundled agent's ingress front.

    provenance_id is the verify-mcp lookup key ``<tenant>:<system>``
    (consistent with mcp_servers.py import ceremony).  The byte-hash covers
    the (empty) tool surface — deterministic, so re-mints are stable.
    """
    return ServerEnvelope(
        provenance_id=f"{tenant}:{system}",
        tenant_id=tenant,
        tools={},
        egress_posture=_BUNDLED_INGRESS_AGENTS[system],
        surface_set_hash=surface_set_hash([]),
    )


async def bootstrap_bundled_agent_envelopes(
    envelope_service: CapabilityEnvelopeService,
    agent_registry: Any,
) -> list[str]:
    """Mint missing envelopes for registered bundled agents.  Idempotent.

    Returns the list of provenance ids minted this run (empty when all
    bundled fronts already hold an ACTIVE envelope).
    """
    if agent_registry is None:
        _log.info(
            "bundled-envelopes: agent registry unavailable — skipping "
            "bootstrap (bundled ingress fronts stay fail-closed until the "
            "next boot)"
        )
        return []

    td = _trust_domain()
    minted: list[str] = []
    for tenant, system in bundled_targets_from_registry(agent_registry):
        provenance_id = f"{tenant}:{system}"
        existing = await envelope_service.get_active_envelope(provenance_id)
        if existing is not None:
            _log.debug(
                "bundled-envelopes: %s already has ACTIVE envelope id=%d — skip",
                provenance_id, existing.id,
            )
            continue
        envelope_id = await envelope_service.mint_envelope(
            _minimal_bundled_envelope(tenant, system),
            server_id=system,
            operator_identity=_BOOTSTRAP_OPERATOR,
            topology=TOPOLOGY_RING_FENCED,
            # Transitional service-leaf identity (overlap phase) — recorded
            # honestly with svid_issued=False: no per-instance /agents/ leaf
            # was minted by an approve transaction (§3.x migration item).
            svid_instance_id=system,
            svid_spiffe_id=f"spiffe://{td}/{system}",
            svid_issued=False,
        )
        _log.info(
            "bundled-envelopes: minted envelope id=%d for bundled agent "
            "%s (transitional identity spiffe://%s/%s) — verify-mcp step 3 "
            "now passes for its ingress front",
            envelope_id, provenance_id, td, system,
        )
        minted.append(provenance_id)
    return minted
