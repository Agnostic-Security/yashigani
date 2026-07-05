"""
Per-instance SPIFFE trust-domain resolution (MI-6 / YSG-RISK-061).

Single source of truth for the instance's SPIFFE trust domain.  Every app-layer
SPIFFE validator/minter MUST route through these helpers rather than hardcoding
``yashigani.internal`` — otherwise a non-legacy (multi-instance) deployment fails
closed against its OWN workloads (the validators would reject the instance's own
``<project>.yashigani.internal`` agents/certs).

Provisioning (install side):
  Su's installer writes ``YASHIGANI_SPIFFE_TRUST_DOMAIN=<project>.yashigani.internal``
  into every container (compose ``x-common-env`` + helm gateway/backoffice) and
  rewrites the runtime service manifest's SPIFFE IDs to the same authority
  (``_apply_trust_domain_to_runtime_manifest`` / SAN-baking, Nico sign-off
  PASS-WITH-FIXES, 2026-06-10).

Backward-compat (legacy single-instance):
  ``PROJECT=docker`` / empty → the env var is either unset or the literal
  ``yashigani.internal``.  The default below preserves the legacy authority
  byte-for-byte, so existing single-instance installs are unchanged.

Isolation note:
  The hard cross-instance backstop is the per-instance CA root (X.509 chain
  validation at the TLS handshake) — independent of these helpers.  These
  helpers make the instance trust ITSELF; getting them wrong over-rejects own
  identity (instance won't run) or, if a validator's accept set widened, could
  accept a foreign label (still caught by the TLS anchor, but the label compare
  must stay exact).  Keep accept-own / reject-foreign exact per call site.
"""
from __future__ import annotations

import os

#: Legacy authority — preserved verbatim for single-instance installs.
_LEGACY_TRUST_DOMAIN = "yashigani.internal"

_ENV_VAR = "YASHIGANI_SPIFFE_TRUST_DOMAIN"


def trust_domain() -> str:
    """Return the instance's SPIFFE trust domain (the SPIFFE URI authority).

    Reads ``YASHIGANI_SPIFFE_TRUST_DOMAIN`` once; falls back to the legacy
    ``yashigani.internal`` when unset/blank so single-instance deployments are
    byte-for-byte unchanged.

    For a multi-instance deployment this is ``<project>.yashigani.internal``.
    """
    value = os.environ.get(_ENV_VAR, "").strip()
    return value or _LEGACY_TRUST_DOMAIN


def spiffe_agents_prefix() -> str:
    """``spiffe://<trust_domain>/agents`` — the agent-identity namespace root.

    No trailing slash (callers append ``/<tenant>/<name>`` or ``/`` as needed),
    mirroring the historical ``_SPIFFE_AGENTS_PREFIX`` shape.
    """
    return "spiffe://%s/agents" % trust_domain()


def agent_spiffe_uri(tenant_id: str, agent_name: str, instance_id: str = "") -> str:
    """Canonical agent SPIFFE URI for this instance's trust domain.

    Legacy (2-segment, no instance): ``spiffe://<td>/agents/{tenant_id}/{agent_name}``.

    Per-instance (v4.1 Phase 1a, GAP-1): when ``instance_id`` is supplied (the
    registry ``nhi_id``, shape ``nhi_<12 hex>``) a third path segment is added:

        spiffe://<td>/agents/{tenant_id}/{agent_name}/{instance_id}

    Two same-named instances therefore carry DISTINCT SPIFFE identities.  The
    instance segment always matches ``nhi_[0-9a-f]{12}`` so validators can
    distinguish instanced from legacy URIs (see ``parse_agent_spiffe_uri``).

    This is the single construction used by pool/manager, gateway/principal_token,
    mcp/broker and mcp/_jwt so the minted identity and every validator agree.
    """
    base = "spiffe://%s/agents/%s/%s" % (trust_domain(), tenant_id, agent_name)
    if instance_id:
        return "%s/%s" % (base, instance_id)
    return base


def parse_agent_spiffe_uri(uri: str) -> "tuple[str, str, str] | None":
    """Round-trip an agent SPIFFE URI → ``(tenant_id, agent_name, instance_id)``.

    ``instance_id`` is ``""`` for legacy 2-segment URIs.  Returns ``None`` when
    the URI is not under THIS instance's ``spiffe://<td>/agents/`` namespace
    (reject-foreign stays exact — see module docstring isolation note).
    """
    prefix = spiffe_agents_prefix() + "/"
    if not uri.startswith(prefix):
        return None
    rest = uri[len(prefix):]
    parts = rest.split("/")
    if len(parts) == 2 and all(parts):
        return parts[0], parts[1], ""
    if len(parts) == 3 and all(parts):
        return parts[0], parts[1], parts[2]
    return None


def gateway_issuer_prefix() -> str:
    """JWT issuer prefix for gateway-minted claims (tenant_id is appended).

    ``https://gateway.<trust_domain>/`` — used as the ``iss`` prefix for the
    orchestration-principal claim and the MCP relay JWT, and as the
    ``startswith`` accept check on the verify side (reject-foreign issuer).
    """
    return "https://gateway.%s/" % trust_domain()


def audit_signer_spiffe_id() -> str:
    """Default SPIFFE id for the audit-chain signer in this trust domain.

    ``spiffe://<trust_domain>/audit``.  ``audit/sinks.py`` prefers the explicit
    ``YASHIGANI_AUDIT_SIGNING_SPIFFE_ID`` env var (compose sets it per instance);
    this is the fallback when that var is unset.
    """
    return "spiffe://%s/audit" % trust_domain()
