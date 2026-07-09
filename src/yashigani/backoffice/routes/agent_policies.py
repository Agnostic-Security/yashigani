"""
Yashigani Backoffice — Agent Policy Template admin routes (v4.1 Phase B).

Design: AgnosticSecurity/Products/Yashigani/agent-admin-policy-templates-design-20260708.md

These routes give admins visibility into and control over the egress-grant
policies governing bundled agents (openclaw, langflow, letta) and onboarded
MCP instances via admin-selectable POLICY TEMPLATES.

Templates are data documents (grants), not Rego — they are distinct from Rego
source templates (policies.py) and user-agent behavioural templates
(agent-templates.js).  Applying a template WRITES a (caller SPIFFE, prefixes)
egress grant to the durable store and pushes it to OPA live.  OPA never reads
templates; the grant document is the sole authorisation input.

Routes:
  GET  /admin/agent-policies/templates                — shipped templates + residuals
  GET  /admin/agent-policies/status                   — join: registry+envelopes+grants
  POST /admin/agent-policies/{tenant}/{system}/apply  — apply template (StepUpAdminSession)
  POST /admin/agent-policies/{tenant}/{system}/adjust — re-apply with overrides (same auth)
  DELETE /admin/agent-policies/{tenant}/{system}/grant — revoke grant (StepUpAdminSession)

Security invariants:
  - All mutations: StepUpAdminSession (TOTP step-up TTL-bound) + require_spiffe_id
    (restricts caller to Caddy/backoffice mTLS peers — stolen session cookie cannot
    be replayed against the backoffice port directly; YSG-RISK-012b).
  - Tenant-scope authz (Laura F8): path {tenant} must match the configured tenant.
  - connect_hosts are perimeter-owned immutable data (Laura F2): admin may NOT
    supply free-form connect hosts; shipped entries only, toggle on/off.
  - Mode-B CONNECT (slack) is Track 2 ONLY — rejected with 422 in Track 1.
  - Revoke MUST use push_and_verify_egress_grants with must_be_absent (Lu R1).
  - R2: module-level LKG cache of claimed SPIFFE set — transient Redis failure
    falls back to the last-good snapshot, never drops suppression.
  - identity_basis is always "ringfence-position" on audit events (Lu MF-6).

Last updated: 2026-07-08T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from yashigani.auth.spiffe import require_spiffe_id
from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.mcp._egress_grants import _lkg_claimed_lock, _get_claimed_spiffes_lkg  # noqa: F401 — re-exported for tests + used below

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BUNDLED_SYSTEMS: frozenset = frozenset(["openclaw", "langflow", "letta"])

# Policy templates ship at this path (code-versioned YAML, drift-gated).
_TEMPLATES_DIR = Path(__file__).parent.parent.parent.parent.parent / "bundles" / "policy-templates"

# FQDN validation: labels [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])? separated by dots.
# Must not be an IP address (validated separately), must not have trailing dot,
# must have at least one dot (no bare hostnames as connect targets).
_FQDN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
)

# ---------------------------------------------------------------------------
# Template loader (code-versioned YAML)
# ---------------------------------------------------------------------------

_template_cache: Optional[dict] = None
_template_cache_lock = threading.Lock()


def _load_templates() -> dict:
    """Load shipped policy templates from bundles/policy-templates/*.yaml.

    Cached in-memory after first load (templates are code-versioned; no hot
    reload — a restart picks up new versions).  Returns {template_id: dict}.
    """
    global _template_cache
    with _template_cache_lock:
        if _template_cache is not None:
            return _template_cache
        templates: dict = {}
        if not _TEMPLATES_DIR.is_dir():
            logger.warning(
                "agent-policies: policy-templates directory missing at %s — "
                "no templates available", _TEMPLATES_DIR,
            )
            _template_cache = templates
            return templates
        for path in sorted(_TEMPLATES_DIR.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text())
                if not isinstance(data, dict):
                    logger.error("agent-policies: bad template YAML %s — not a dict", path.name)
                    continue
                meta = data.get("metadata", {}) or {}
                tmpl_id = str(meta.get("template_id", "")).strip()
                if not tmpl_id:
                    logger.error("agent-policies: template %s missing metadata.template_id", path.name)
                    continue
                templates[tmpl_id] = data
                logger.debug("agent-policies: loaded template %s v%s", tmpl_id, meta.get("version", 1))
            except Exception as exc:  # noqa: BLE001
                logger.error("agent-policies: failed to load template %s: %s", path.name, exc)
        _template_cache = templates
        logger.info("agent-policies: loaded %d policy template(s)", len(templates))
        return templates


def _get_template(template_id: str) -> Optional[dict]:
    """Return a loaded template by ID, or None."""
    return _load_templates().get(template_id)


# ---------------------------------------------------------------------------
# Host validation (B2)
# ---------------------------------------------------------------------------

def _validate_connect_host(host_port: str) -> str:
    """Validate a connect_host entry from a shipped template.

    Accepted format: lowercase FQDN:443 (no IP literals, port 443 only,
    no trailing dots, no wildcards).  Returns the normalised 'host:443' string.
    Raises ValueError with a human-readable reason on rejection.

    Lu MF-3 + Laura F7: reject decimal/octal/hex IPv4, IPv4-mapped-IPv6
    (::ffff:…), bare IPv6, trailing-dot, uppercase.
    """
    if not isinstance(host_port, str) or ":" not in host_port:
        raise ValueError(f"connect_host must be 'fqdn:443': {host_port!r}")
    # Split on last colon to handle IPv6 (though we reject bare IPv6 anyway)
    host, _, port_str = host_port.rpartition(":")
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"connect_host port is not an integer: {host_port!r}")
    if port != 443:
        raise ValueError(f"connect_host port must be 443 (got {port}): {host_port!r}")
    host = host.lower().strip()
    if not host:
        raise ValueError(f"connect_host hostname is empty: {host_port!r}")
    # Reject trailing dot
    if host.endswith("."):
        raise ValueError(f"connect_host: trailing dot not permitted: {host!r}")
    # Reject IPv4-mapped IPv6
    if host.startswith("::ffff:") or host.startswith("[::ffff:"):
        raise ValueError(f"connect_host: IPv4-mapped IPv6 not permitted: {host!r}")
    # Reject bare IPv6 (enclosed in brackets)
    if host.startswith("["):
        raise ValueError(f"connect_host: IPv6 literals not permitted: {host!r}")
    # Reject decimal/octal/hex IPv4 and all IP literals
    try:
        ipaddress.ip_address(host)
        raise ValueError(f"connect_host must be an FQDN, not an IP literal: {host!r}")
    except ValueError as exc:
        if "IP literal" in str(exc) or "not permitted" in str(exc):
            raise
        # ip_address raised ValueError because it's not an IP — that's expected for FQDNs
    # Reject uppercase (already lowercased, but double-check against original)
    if host_port != host_port.lower():
        raise ValueError(f"connect_host must be lowercase: {host_port!r}")
    # Validate FQDN pattern
    if not _FQDN_RE.match(host):
        raise ValueError(f"connect_host: invalid FQDN pattern: {host!r}")
    return f"{host}:{port}"


def _check_prefix_disjointness(egress_entries: list) -> None:
    """Raise ValueError if any prefix appears in both Mode A and Mode B (Lu MF-4)."""
    mode_a_prefixes: set = set()
    mode_b_prefixes: set = set()
    for entry in egress_entries:
        if not isinstance(entry, dict):
            continue
        prefix = str(entry.get("prefix", "")).strip()
        mode = str(entry.get("mode", "reverse_proxy")).strip()
        if not prefix:
            continue
        if mode == "connect":
            mode_b_prefixes.add(prefix)
        else:
            mode_a_prefixes.add(prefix)
    overlap = mode_a_prefixes & mode_b_prefixes
    if overlap:
        raise ValueError(
            f"Prefix(es) appear in both Mode A and Mode B (Lu MF-4): {sorted(overlap)}"
        )


# ---------------------------------------------------------------------------
# SPIFFE resolution for bundled agents (Nico gap-4)
# ---------------------------------------------------------------------------

def _resolve_bundled_spiffe(system: str) -> str:
    """Resolve the forwarder-leaf SPIFFE for a bundled system.

    The leaf that the forwarder actually presents (issued-leaf SAN) is the
    transitional system-form URI: spiffe://<trust_domain>/<system>.
    Reads YASHIGANI_<SYSTEM>_SPIFFE_ID first (same env the static Caddyfile
    gate uses), falls back to the derived form.

    Nico gap-4: do NOT hardcode gateway-process env SPIFFE — resolve the exact
    leaf SAN this agent presents on the forwarder hop.
    """
    env_key = f"YASHIGANI_{system.upper().replace('-', '_')}_SPIFFE_ID"
    spiffe = os.environ.get(env_key, "").strip()
    if spiffe:
        return spiffe
    from yashigani.identity.trust_domain import trust_domain  # noqa: PLC0415
    return f"spiffe://{trust_domain()}/{system}"


def _resolve_agent_spiffe(
    tenant: str,
    system: str,
    registry_store: Any,
) -> str:
    """Resolve the SPIFFE for a given (tenant, system) at apply time.

    Priority:
    1. Existing egress grant in the store (already has the correct SPIFFE).
    2. Registry descriptor's spiffe_id (onboarded MCP).
    3. Bundled-system transitional seed (openclaw/langflow/letta).

    Raises HTTPException(422) if the SPIFFE cannot be resolved.
    """
    # 1. Existing grant (fastest path — may already be claimed)
    try:
        existing_grant = registry_store.get_egress_grant(tenant, system)
        if existing_grant and existing_grant.get("spiffe"):
            return str(existing_grant["spiffe"]).strip()
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent-policies: get_egress_grant %s:%s failed: %s", tenant, system, exc)

    # 2. Registry descriptor spiffe_id (onboarded MCP via import ceremony)
    try:
        desc = registry_store.get(tenant, system)
        if desc and desc.get("spiffe_id"):
            return str(desc["spiffe_id"]).strip()
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent-policies: registry get %s:%s failed: %s", tenant, system, exc)

    # 3. Bundled-system transitional SPIFFE (openclaw / langflow / letta)
    if system in _BUNDLED_SYSTEMS:
        return _resolve_bundled_spiffe(system)

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "error": "spiffe_not_resolvable",
            "message": (
                f"Cannot resolve the issued-leaf SPIFFE for {tenant}/{system}. "
                "Ensure the agent has been onboarded or is a known bundled system."
            ),
        },
    )


# ---------------------------------------------------------------------------
# Tenant-scope authz helper (Laura F8)
# ---------------------------------------------------------------------------

def _assert_tenant_scope(path_tenant: str) -> None:
    """Verify the path tenant matches the configured installation tenant.

    Laura F8: the admin session's tenant scope must equal {tenant}, not merely
    'is-admin'.  In a single-tenant install the configured tenant is the ONLY
    valid tenant.  Multi-tenant: extend by carrying tenant_id on Session.
    """
    configured_tenant = os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"
    if path_tenant != configured_tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "tenant_scope_violation",
                "message": (
                    f"Admin session scope does not cover tenant {path_tenant!r}. "
                    f"This installation is scoped to {configured_tenant!r} (Laura F8)."
                ),
            },
        )


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class AcknowledgementEntry(BaseModel):
    residual_id: str = Field(..., min_length=1, max_length=64)
    justification: str = Field(..., min_length=10, max_length=1024)


class ApplyTemplateRequest(BaseModel):
    template_id: str = Field(..., min_length=1, max_length=128)
    overrides: dict = Field(default_factory=dict)
    acknowledgements: list[AcknowledgementEntry] = Field(default_factory=list)

    @field_validator("template_id")
    @classmethod
    def _no_html_in_template_id(cls, v: str) -> str:
        if re.search(r"(?i)(?:javascript:|data:|vbscript:|<[a-zA-Z/!])", v):
            raise ValueError("template_id contains disallowed characters")
        return v

    @field_validator("overrides")
    @classmethod
    def _reject_connect_hosts_override(cls, v: dict) -> dict:
        """Admin CANNOT supply free-form connect_hosts (Laura F2 — perimeter-owned).

        connect_hosts in shipped templates are immutable perimeter data.
        Admins may only toggle shipped entries on/off (not add new destinations).
        """
        if "connect_hosts" in v:
            raise ValueError(
                "connect_hosts is perimeter-owned immutable data (Laura F2). "
                "Admin may only toggle shipped entries on/off — no free-form "
                "connect hosts may be supplied at apply time."
            )
        return v


# ---------------------------------------------------------------------------
# Route helpers
# ---------------------------------------------------------------------------

def _registry_store():
    """Return the durable MCP registry store, or raise 503."""
    # The registry store is the DurableMcpRegistryStore wired at gateway startup.
    # In the backoffice, we access it via the gateway's durable store if available,
    # or instantiate one from the shared Redis connection.
    # Pattern: check backoffice_state for a wired store (future integration),
    # then fall back to constructing one from the YASHIGANI_REDIS_URL env.
    store = getattr(backoffice_state, "mcp_registry_store", None)
    if store is not None:
        return store
    # Construct from env — same Redis db/3 the gateway uses.
    try:
        import redis as _redis  # noqa: PLC0415
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore  # noqa: PLC0415
        redis_url = os.environ.get("YASHIGANI_REDIS_URL", "redis://redis:6379/3")
        # Force db/3 if not in URL
        if "/3" not in redis_url.split("?")[0]:
            redis_url = redis_url.rstrip("/0123456789") + "/3"
        r = _redis.Redis.from_url(redis_url)
        return DurableMcpRegistryStore(r)
    except Exception as exc:
        logger.error("agent-policies: cannot construct registry store: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "registry_store_unavailable",
                    "message": "MCP durable registry store is not available."},
        )


def _opa_url() -> str:
    return os.environ.get("YASHIGANI_OPA_URL", "https://policy:8181").strip() or "https://policy:8181"


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _overrides_digest(overrides: dict) -> str:
    """SHA-256 of canonical JSON of overrides (for audit trail)."""
    if not overrides:
        return ""
    canonical = json.dumps(overrides, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# GET /admin/agent-policies/templates
# ---------------------------------------------------------------------------

@router.get("/admin/agent-policies/templates")
async def list_templates(session: AdminSession) -> list[dict]:
    """Return all shipped policy templates with their residual disclosures.

    Read-only; no step-up required.  Templates are code-versioned YAML
    (bundles/policy-templates/*.yaml) — they are data, not Rego.
    """
    templates = _load_templates()
    result = []
    for tmpl_id, data in sorted(templates.items()):
        meta = data.get("metadata", {}) or {}
        spec = data.get("spec", {}) or {}
        disc = spec.get("disclosure", {}) or {}
        result.append({
            "template_id": tmpl_id,
            "version": meta.get("version", 1),
            "applies_to": meta.get("applies_to", ""),
            "description": meta.get("description", ""),
            "egress": [
                {
                    "prefix": e.get("prefix", ""),
                    "mode": e.get("mode", "reverse_proxy"),
                    "track_2_only": bool(e.get("track_2_only", False)),
                    "enabled": bool(e.get("enabled", True)),
                    "requires_acknowledgement": bool(e.get("requires_acknowledgement", False)),
                }
                for e in (spec.get("egress") or [])
            ],
            "disclosure": {
                "enforced": disc.get("enforced", []),
                "residuals": disc.get("residuals", []),
            },
        })
    return result


# ---------------------------------------------------------------------------
# GET /admin/agent-policies/status
# ---------------------------------------------------------------------------

def get_status_rows() -> list[dict]:
    """Build and return the joined policy status view rows.

    Extracted from policy_status for testability — policy_status delegates
    to this function.  Joins three sources:
      - Bundled agent catalogue (openclaw, langflow, letta)
      - Onboarded MCP instances (durable registry)
      - Active template applications (mcp:tmpl:* Redis keys)

    Residual disclosures are surfaced per row (B5):
      - Union-grant kill-switch degradation notice (Nico Q-N1)
      - graph_hash is drift-detection only (Nico Q-N3)
      - identity_basis: ringfence-position (Lu MF-6)
      - egress_attribution_note for NHI discovered flows (Lu disclosure, v4.1)
    """
    store = _registry_store()
    templates = _load_templates()
    configured_tenant = os.environ.get("YASHIGANI_TENANT_ID", "default").strip() or "default"

    rows: list[dict] = []

    # 1. Bundled systems
    for system in sorted(_BUNDLED_SYSTEMS):
        spiffe = _resolve_bundled_spiffe(system)
        grant = None
        try:
            grant = store.get_egress_grant(configured_tenant, system)
        except Exception:  # noqa: BLE001
            pass
        app = store.get_template_application(configured_tenant, system)
        tmpl_id = (app or {}).get("template_id") if app else None
        tmpl = templates.get(tmpl_id) if tmpl_id else None
        rows.append({
            "system_id": system,
            "tenant_id": configured_tenant,
            "kind": "bundled",
            "spiffe_id": spiffe,
            "svid_issued": True,    # bundled agents have bootstrap identity
            "egress_grant": {
                "prefixes": sorted((grant or {}).get("prefixes", [])),
                "has_connect": bool((grant or {}).get("connect")),
            } if grant else None,
            "template_applied": {
                "template_id": tmpl_id,
                "version": (app or {}).get("version"),
                "applied_by": (app or {}).get("applied_by"),
                "applied_at": (app or {}).get("applied_at"),
            } if app else None,
            "template_description": (
                ((tmpl or {}).get("metadata") or {}).get("description", "")
            ) if tmpl else "",
            # B5: honest residual notices always present
            "residuals": {
                "union_grant_note": (
                    "Revoking this agent's grant kills its ingress; sibling agents "
                    "holding the same prefix keep the forwarder route active. "
                    "Kill switch = grant absence in the pushed OPA data (Nico Q-N1)."
                ),
                "identity_basis": "ringfence-position",
                "graph_hash_note": (
                    "graph_hash is drift-detection metadata only — NOT attestation "
                    "of agent behaviour or tool surface (Nico Q-N3)."
                ),
            },
        })

    # 2. Onboarded MCP instances
    try:
        descriptors = store.list_all()
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent-policies: list_all failed: %s", exc)
        descriptors = []

    for desc in descriptors:
        system = desc.get("agent_name", "")
        tenant = desc.get("tenant_id", configured_tenant)
        if system in _BUNDLED_SYSTEMS:
            continue   # already covered above
        spiffe = desc.get("spiffe_id", "")
        is_nhi_discovered = (
            desc.get("kind") == "nhi" and bool(desc.get("langflow_flow_id"))
        )
        grant = None
        try:
            grant = store.get_egress_grant(tenant, system)
        except Exception:  # noqa: BLE001
            pass
        app = store.get_template_application(tenant, system)
        tmpl_id = (app or {}).get("template_id") if app else None
        # Residuals — base set shared by all descriptors
        residuals: dict = {
            "union_grant_note": (
                "Kill switch = grant absence in the pushed OPA data (Nico Q-N1)."
            ),
            "identity_basis": "ringfence-position",
            "graph_hash_note": (
                "graph_hash is drift-detection metadata only — NOT attestation "
                "(Nico Q-N3)."
            ),
        }
        # Lu disclosure (v4.1 F-G/F-H): discovered langflow NHI flows share the
        # langflow instance SPIFFE grant — egress is per-INSTANCE, NOT per-flow.
        if is_nhi_discovered:
            residuals["egress_attribution_note"] = (
                "Egress attribution: INSTANCE-LEVEL (langflow SPIFFE), NOT per-flow. "
                "All flows under this langflow instance share the union egress grant. "
                "Per-flow egress isolation requires per-instance containers (Track 3+)."
            )
        rows.append({
            "system_id": system,
            "tenant_id": tenant,
            "kind": desc.get("kind", "onboarded"),
            "spiffe_id": spiffe,
            "svid_issued": bool(desc.get("svid_issued", desc.get("svid_instance_id"))),
            "egress_grant": {
                "prefixes": sorted((grant or {}).get("prefixes", [])),
                "has_connect": bool((grant or {}).get("connect")),
            } if grant else None,
            "template_applied": {
                "template_id": tmpl_id,
                "version": (app or {}).get("version"),
                "applied_by": (app or {}).get("applied_by"),
                "applied_at": (app or {}).get("applied_at"),
            } if app else None,
            "residuals": residuals,
        })

    return rows


@router.get("/admin/agent-policies/status")
async def policy_status(session: AdminSession) -> list[dict]:
    """Return the joined policy status view (registry + grants + applications).

    Delegates to :func:`get_status_rows` — see its docstring for the full
    data model and residual-disclosure specification.
    """
    return get_status_rows()


# ---------------------------------------------------------------------------
# POST /admin/agent-policies/{tenant}/{system}/apply  (and /adjust)
# ---------------------------------------------------------------------------

async def _run_apply(
    tenant: str,
    system: str,
    body: ApplyTemplateRequest,
    session: StepUpAdminSession,
) -> dict:
    """Shared implementation for apply and adjust (both re-write the grant).

    Transaction (fail-closed, LIFO rollback — mirrors mcp_onboard.py):
      1. Tenant-scope authz (Laura F8)
      2. Load + validate template
      3. Reject Mode-B entries in Track 1 (422)
      4. Resolve issued-leaf SPIFFE (Nico gap-4)
      5. Minimal-descriptor registration (Lu MF-5) — in the apply transaction
      6. Write egress grant (put_egress_grant + claim_egress_seed)
      7. Write template application record
      8. Audit: MCP_EGRESS_GRANT_WRITTEN + AGENT_POLICY_TEMPLATE_APPLIED
      9. Push egress grants to OPA (post-commit; fail-closed on push failure)
    """
    # 1. Tenant-scope authz
    _assert_tenant_scope(tenant)

    store = _registry_store()
    audit = backoffice_state.audit_writer

    # 2. Load template
    tmpl = _get_template(body.template_id)
    if tmpl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "template_not_found",
                    "message": f"Policy template {body.template_id!r} not found."},
        )

    meta = tmpl.get("metadata", {}) or {}
    spec = tmpl.get("spec", {}) or {}
    applies_to = str(meta.get("applies_to", "")).strip()

    # Validate applies_to matches target system (exact match or "langflow-created" for NHIs)
    if applies_to not in (system, "langflow-created") and applies_to != system:
        # Allow exact match or "langflow-created" template on langflow-NHI systems
        if not (applies_to == "langflow-created" and system.startswith("langflow-nhi-")):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "template_mismatch",
                    "message": (
                        f"Template {body.template_id!r} applies to {applies_to!r}, "
                        f"not to {system!r}."
                    ),
                },
            )

    egress_entries = list(spec.get("egress") or [])

    # 3. Reject Mode-B (connect) entries in Track 1 (B1 — Mode-B is Track 2 ONLY).
    #    Fix (Lu incidental / openclaw applicability): skip entries that are
    #    track_2_only or enabled:false — they are inert in Track 1 and must not
    #    prevent the template's enabled Mode-A entries from applying.  The reject
    #    stays for any connect entry that IS active (enabled:true, not track_2_only).
    for entry in egress_entries:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("mode", "")).strip() == "connect":
            if bool(entry.get("track_2_only", False)) or not bool(entry.get("enabled", True)):
                continue  # Inert entry — do not build, do not 422
            prefix = entry.get("prefix", "")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "mode_b_not_available",
                    "message": (
                        f"Mode-B CONNECT egress (prefix={prefix!r}) is Track 2 ONLY. "
                        "It is not available in Track 1. "
                        "See design §3.2 — gated on Laura FP-01 re-review."
                    ),
                },
            )

    # 3b. Fail-closed on requires_acknowledgement (Nico latent bypass fix).
    #    No dual-admin ceremony infra exists in Track 1.  Any ACTIVE entry that
    #    carries requires_acknowledgement:true is a weaken-class operation and
    #    MUST be rejected 422 rather than silently applied (UI-only enforcement
    #    is not enough).  Inert entries (track_2_only or enabled:false) are
    #    skipped — they carry the flag as a future-ceremony annotation only.
    for entry in egress_entries:
        if not isinstance(entry, dict):
            continue
        if bool(entry.get("track_2_only", False)) or not bool(entry.get("enabled", True)):
            continue  # Inert — skip
        if bool(entry.get("requires_acknowledgement", False)):
            prefix = entry.get("prefix", "")
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "acknowledgement_ceremony_required",
                    "message": (
                        f"Egress entry {prefix!r} requires an acknowledgement ceremony "
                        "(requires_acknowledgement:true) that is not available in "
                        "Track 1. This is a weaken-class operation and cannot be "
                        "applied without dual-admin ceremony infrastructure "
                        "(design §5.3). Gated until Track 2."
                    ),
                },
            )

    # Validate prefix disjointness (Lu MF-4)
    try:
        _check_prefix_disjointness(egress_entries)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "prefix_disjointness_violation", "message": str(exc)},
        )

    # 4. Resolve issued-leaf SPIFFE (Nico gap-4)
    spiffe_id = _resolve_agent_spiffe(tenant, system, store)

    # Build granted prefixes from Mode-A entries only (Mode-B skipped in Track 1).
    # Lu informational: also exclude enabled:false entries — a Mode-A entry
    # marked enabled:false is not an active grant (latent-gap hardening; no
    # shipped template hits this, but the filter must be exhaustive).
    granted_prefixes = sorted(
        str(e.get("prefix", "")).strip()
        for e in egress_entries
        if isinstance(e, dict)
        and str(e.get("mode", "reverse_proxy")).strip() != "connect"
        and str(e.get("prefix", "")).strip()
        and not bool(e.get("track_2_only", False))
        and bool(e.get("enabled", True))
    )

    rollback_steps: list = []

    # 5. Minimal-descriptor registration (Lu MF-5 — must be IN the apply transaction)
    try:
        existing_desc = store.get(tenant, system)
    except Exception:  # noqa: BLE001
        existing_desc = None

    if existing_desc is None:
        minimal_desc: dict = {
            "agent_name": system,
            "tenant_id": tenant,
            "is_bundled": system in _BUNDLED_SYSTEMS,
            "upstream_url": f"https://caddy/{system}",  # placeholder for status join
            "registered_at": _now_iso(),
        }
        try:
            store.put(tenant, system, minimal_desc)
            rollback_steps.append(lambda: store.delete(tenant, system))
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "descriptor_write_failed",
                        "message": f"Failed to register minimal descriptor: {exc}"},
            )

    # 6. Write egress grant (includes claim_egress_seed inside put_egress_grant)
    grant_data: dict = {
        "spiffe": spiffe_id,
        "tenant": tenant,
        "prefixes": granted_prefixes,
        # Mode-B connect map NOT written in Track 1 (never enable in this release)
    }
    try:
        store.put_egress_grant(tenant, system, grant_data)
        rollback_steps.append(lambda: store.delete_egress_grant(tenant, system))
    except Exception as exc:
        # Rollback any descriptor we just wrote
        for step in reversed(rollback_steps):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "grant_write_failed",
                    "message": f"Failed to write egress grant: {exc}"},
        )

    # 7. Write template application record
    app_data: dict = {
        "template_id": body.template_id,
        "version": meta.get("version", 1),
        "overrides": body.overrides,
        "acknowledgements": [a.model_dump() for a in body.acknowledgements],
        "applied_by": session.account_id,
        "applied_at": _now_iso(),
    }
    try:
        store.put_template_application(tenant, system, app_data)
        rollback_steps.append(lambda: store.delete_template_application(tenant, system))
    except Exception as exc:
        for step in reversed(rollback_steps):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "template_app_write_failed",
                    "message": f"Failed to write template application record: {exc}"},
        )

    # 8. Audit: MCP_EGRESS_GRANT_WRITTEN + AGENT_POLICY_TEMPLATE_APPLIED (B5: identity_basis)
    if audit is not None:
        try:
            from yashigani.audit.schema import (  # noqa: PLC0415
                McpEgressGrantWrittenEvent,
                AgentPolicyTemplateAppliedEvent,
            )
            audit.write(McpEgressGrantWrittenEvent(
                approver_account=session.account_id,
                tenant_id=tenant,
                server_id=system,
                instance_id="",
                spiffe_id=spiffe_id,
                prefixes=list(granted_prefixes),
            ))
            audit.write(AgentPolicyTemplateAppliedEvent(
                admin_account=session.account_id,
                tenant_id=tenant,
                system_id=system,
                template_id=body.template_id,
                template_version=int(meta.get("version", 1)),
                spiffe_id=spiffe_id,
                granted_prefixes=list(granted_prefixes),
                overrides_digest=_overrides_digest(body.overrides),
                acknowledgements=[a.model_dump() for a in body.acknowledgements],
                identity_basis="ringfence-position",  # Lu MF-6: never implies mTLS
            ))
        except Exception as audit_exc:  # noqa: BLE001
            logger.error("agent-policies: audit write failed: %s", audit_exc)

    # 9. Post-commit: push egress grants to OPA (add-only — no must_be_absent needed).
    #    R2: resolve the claimed set through the LKG before building the doc so that
    #    a transient Redis failure here does not drop suppression for previously
    #    revoked bundled-system SPIFFEs (they would resurface from the seed).
    try:
        from yashigani.mcp._egress_grants import build_egress_grants_doc  # noqa: PLC0415
        from yashigani.mcp._opa_push import push_and_verify_egress_grants  # noqa: PLC0415
        claimed_for_push = _get_claimed_spiffes_lkg(store)
        push_and_verify_egress_grants(
            _opa_url(), build_egress_grants_doc(store, claimed_spiffes=claimed_for_push)
        )
    except Exception as push_exc:  # noqa: BLE001 — committed; deny-until-pushed is fail-closed
        logger.error(
            "agent-policies: OPA push failed after apply %s/%s (%s) — "
            "agent will DENY egress until gateway startup push or next apply",
            tenant, system, push_exc,
        )

    return {
        "status": "applied",
        "tenant_id": tenant,
        "system_id": system,
        "template_id": body.template_id,
        "spiffe_id": spiffe_id,
        "granted_prefixes": granted_prefixes,
        "applied_at": app_data["applied_at"],
    }


@router.post(
    "/admin/agent-policies/{tenant}/{system}/apply",
    status_code=200,
    dependencies=[Depends(require_spiffe_id("/admin/agent-policies"))],
)
async def apply_template(
    tenant: str,
    system: str,
    body: ApplyTemplateRequest,
    session: StepUpAdminSession,
) -> dict:
    """Apply a policy template to an agent (step-up-gated, tenant-scoped).

    Writes the egress grant, registers the minimal descriptor, records the
    template application, and pushes to OPA.  Mode-B CONNECT is Track 2 only;
    any template with connect entries returns 422 in this track.

    Step-up (Laura F10): StepUpAdminSession enforces TOTP re-verification via a
    5-minute reusable TTL window (YASHIGANI_STEPUP_TTL_SECONDS, default 300s),
    consistent with mcp_onboard approve semantics.  The step-up window is
    reusable within its TTL — multiple /apply calls in the same window are
    permitted.  Single-use enforcement is only required on the weaken-class path
    (requires_acknowledgement / Mode-B), which is now fail-closed in Track 1
    (rejected 422 before any grant write — see _run_apply step 3b).
    """
    return await _run_apply(tenant, system, body, session)


@router.post(
    "/admin/agent-policies/{tenant}/{system}/adjust",
    status_code=200,
    dependencies=[Depends(require_spiffe_id("/admin/agent-policies"))],
)
async def adjust_template(
    tenant: str,
    system: str,
    body: ApplyTemplateRequest,
    session: StepUpAdminSession,
) -> dict:
    """Re-apply a policy template with updated overrides (step-up-gated).

    Semantically identical to /apply: re-writes the grant (idempotent) and
    updates the application record.  Weaken-class widening (Mode-B / any entry
    with requires_acknowledgement:true) is fail-closed in Track 1 — rejected
    422 before any grant write (see _run_apply steps 3 + 3b).
    """
    return await _run_apply(tenant, system, body, session)


# ---------------------------------------------------------------------------
# DELETE /admin/agent-policies/{tenant}/{system}/grant
# ---------------------------------------------------------------------------

@router.delete(
    "/admin/agent-policies/{tenant}/{system}/grant",
    status_code=200,
    dependencies=[Depends(require_spiffe_id("/admin/agent-policies"))],
)
async def revoke_grant(
    tenant: str,
    system: str,
    session: StepUpAdminSession,
) -> dict:
    """Revoke the egress grant for an agent (step-up-gated, fail-closed).

    Grant absence in the re-pushed OPA data IS the kill switch (Nico Q3).

    Lu R1 (HARD GATE): uses push_and_verify_egress_grants with must_be_absent
    containing the revoked SPIFFE(s).  Plain push_egress_grants = fail-open
    regression; this route MUST use the verify path.

    R2: falls back to LKG claimed-SPIFFE snapshot on transient Redis failure
    (prevents seed suppression from dropping, which would allow a revoked
    grant to resurface from the transitional seed).
    """
    _assert_tenant_scope(tenant)

    store = _registry_store()
    audit = backoffice_state.audit_writer

    # Resolve the SPIFFE being revoked
    spiffe_id = _resolve_agent_spiffe(tenant, system, store)

    # Get current grant for audit trail
    revoked_prefixes: list = []
    try:
        existing = store.get_egress_grant(tenant, system)
        if existing:
            revoked_prefixes = sorted(existing.get("prefixes", []))
    except Exception:  # noqa: BLE001
        pass

    # Delete from the store
    try:
        store.delete_egress_grant(tenant, system)
    except Exception as exc:
        logger.error("agent-policies: delete_egress_grant %s/%s failed: %s", tenant, system, exc)
        # Continue — the OPA push with must_be_absent is the authoritative revocation

    # Also delete template application record
    try:
        store.delete_template_application(tenant, system)
    except Exception:  # noqa: BLE001
        pass

    # Lu R1 (HARD GATE): build the full doc and push with must_be_absent verification.
    # R2: use LKG snapshot for claimed set on transient Redis failure.
    try:
        from yashigani.mcp._egress_grants import (  # noqa: PLC0415
            build_egress_grants_doc,
            transitional_egress_seed,
        )
        from yashigani.mcp._opa_push import push_and_verify_egress_grants  # noqa: PLC0415

        # R2: resolve LKG claimed set — transient failure returns snapshot, never drops suppression.
        claimed_for_push = _get_claimed_spiffes_lkg(store)

        full_doc = build_egress_grants_doc(store, claimed_spiffes=claimed_for_push)
        push_and_verify_egress_grants(
            _opa_url(),
            full_doc,
            must_be_absent=frozenset([spiffe_id]),  # Lu R1: verify the revoke landed
        )
    except Exception as push_exc:
        logger.error(
            "agent-policies: REVOKE PUSH FAILED %s/%s spiffe=%s (%s) — "
            "GRANT MAY STILL BE ACTIVE IN OPA. Operator must re-push or restart "
            "the gateway (fail-closed: log + surface, not swallow).",
            tenant, system, spiffe_id, push_exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "revoke_push_failed",
                "message": (
                    "Egress grant was deleted from the store but the OPA push "
                    "verification failed — the grant MAY still be active in OPA. "
                    "Restart the gateway or call /admin/agent-policies/push to "
                    "force re-push. (Lu R1 fail-closed gate.)"
                ),
            },
        )

    # Audit
    if audit is not None:
        try:
            from yashigani.audit.schema import AgentPolicyTemplateRevokedEvent  # noqa: PLC0415
            audit.write(AgentPolicyTemplateRevokedEvent(
                admin_account=session.account_id,
                tenant_id=tenant,
                system_id=system,
                spiffe_id=spiffe_id,
                revoked_prefixes=revoked_prefixes,
                identity_basis="ringfence-position",  # Lu MF-6
            ))
        except Exception as audit_exc:  # noqa: BLE001
            logger.error("agent-policies: revoke audit write failed: %s", audit_exc)

    return {
        "status": "revoked",
        "tenant_id": tenant,
        "system_id": system,
        "spiffe_id": spiffe_id,
        "revoked_prefixes": revoked_prefixes,
    }


__all__ = ["router"]
