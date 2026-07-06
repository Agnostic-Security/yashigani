"""Unit tests — POST /admin/agents/{agent_id}/cert/rotate (v4.1 Phase 1, Nico Q1).

Unified-sidecar review must-fix #7: rotate.sh:180 POSTs this endpoint; it was
ACL'd + documented but unimplemented — continuously-running bundled agents
hard-failed when their leaf expired (≤90d).

Covered here (handler invoked directly; the SPIFFE ACL gate has its own suite
in test_spiffe_gate_agent_prefix.py):

  * happy path (registry NHI): re-mint keeps the SAME instance_id/SPIFFE and
    re-binds the registry-CURRENT scope_hash + image_digest (GAP-2 binding)
  * changed surface → 409 surface_changed_reapproval_required
  * wrong caller identity (registry SPIFFE mismatch) → 403
  * non-agent caller (backoffice exact-id) → 403
  * revoked runtime-manifest entry → 403
  * legacy 2-segment identity (install.sh CLI mint) rotates with no binding
  * MCP-onboarded instance: envelope-backed happy path + drift deny
  * response file contract: cert_pem = leaf+intermediate bundle; key matches

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fastapi import HTTPException

from yashigani.backoffice.routes import agents as agents_mod
from yashigani.backoffice.routes.agents import rotate_agent_cert
from yashigani.backoffice.state import backoffice_state
from yashigani.pki.binding import (
    binding_digest,
    parse_binding_extension,
    tool_surface_hash,
)
from yashigani.pki.issuer import IssuerPaths, bootstrap, mint_agent_leaf, revoke_agent_identity


_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
"""

_TENANT = "tenant1"
_NAME = "letta"
_NHI = "nhi_abcdefabcdef"
_TOOLS = ["fetch", "search"]
_SCOPE = tool_surface_hash(_TOOLS)
_IMAGE = "sha256:" + "ab" * 32
_SPIFFE = f"spiffe://yashigani.internal/agents/{_TENANT}/{_NAME}/{_NHI}"
_SPIFFE_LEGACY = f"spiffe://yashigani.internal/agents/{_TENANT}/{_NAME}"


class _FakeRegistry:
    def __init__(self, entries: Optional[dict] = None):
        self.entries = entries or {}

    def get(self, agent_id: str):
        return self.entries.get(agent_id)


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IssuerPaths:
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    secrets = tmp_path / "secrets"
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets))
    monkeypatch.setenv("YASHIGANI_SERVICE_MANIFEST_PATH", str(manifest))
    p = IssuerPaths(secrets_dir=secrets, manifest_path=manifest)
    bootstrap(p)
    return p


@pytest.fixture(autouse=True)
def _state():
    """Isolate backoffice_state across tests."""
    prev_reg = backoffice_state.agent_registry
    prev_audit = backoffice_state.audit_writer
    backoffice_state.agent_registry = None
    backoffice_state.audit_writer = None
    yield
    backoffice_state.agent_registry = prev_reg
    backoffice_state.audit_writer = prev_audit


def _nhi_entry(**overrides) -> dict:
    entry = {
        "agent_id": _NHI,
        "kind": "nhi",
        "status": "active",
        "svid_issued": True,
        "spiffe_id": _SPIFFE,
        "scope_hash": _SCOPE,
        "image_digest": _IMAGE,
        "allowed_tools": list(_TOOLS),
        "name": _NAME,
        "owner_identity_id": _TENANT,
    }
    entry.update(overrides)
    return entry


def _mint_initial(paths: IssuerPaths, instance: str = _NHI) -> str:
    return mint_agent_leaf(
        paths, _TENANT, _NAME,
        instance_id=instance,
        scope_hash=_SCOPE if instance else "",
        image_digest=_IMAGE if instance else "",
    )


def _leaf_of(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificates(pem.encode())[0]


# ---------------------------------------------------------------------------
# Registry-NHI path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_happy_path_registry_nhi(paths: IssuerPaths):
    assert _mint_initial(paths) == _SPIFFE
    old_serial = _leaf_of(
        paths.agent_cert(_TENANT, _NAME, _NHI).read_text()
    ).serial_number
    backoffice_state.agent_registry = _FakeRegistry({_NHI: _nhi_entry()})

    resp = await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)

    assert resp.spiffe_id == _SPIFFE                     # SAME instance identity
    certs = x509.load_pem_x509_certificates(resp.cert_pem.encode())
    assert len(certs) == 2, "cert_pem must be the leaf + intermediate bundle"
    leaf = certs[0]
    assert leaf.serial_number != old_serial              # actually re-minted
    # SPIFFE URI SAN preserved
    sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    uris = sans.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert _SPIFFE in uris
    # GAP-2 binding re-bound over the registry-CURRENT inputs
    assert parse_binding_extension(leaf) == binding_digest(_IMAGE, _SCOPE)
    # key_pem is the matching private key
    key = load_pem_private_key(resp.key_pem.encode(), password=None)
    assert key.public_key().public_numbers() == leaf.public_key().public_numbers()
    assert resp.cert_not_after  # informational, but populated
    # response is what rotate.sh writes back to disk — same file contract
    assert resp.cert_pem == paths.agent_cert(_TENANT, _NAME, _NHI).read_text()


@pytest.mark.asyncio
async def test_rotate_denied_when_surface_changed(paths: IssuerPaths):
    """A changed tool surface must go through re-approval, not rotation."""
    _mint_initial(paths)
    entry = _nhi_entry(allowed_tools=[*_TOOLS, "delete_everything"])
    backoffice_state.agent_registry = _FakeRegistry({_NHI: entry})

    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "surface_changed_reapproval_required"


@pytest.mark.asyncio
async def test_rotate_denied_on_registry_spiffe_mismatch(paths: IssuerPaths):
    _mint_initial(paths)
    entry = _nhi_entry(
        spiffe_id=f"spiffe://yashigani.internal/agents/{_TENANT}/{_NAME}/nhi_000000000000"
    )
    backoffice_state.agent_registry = _FakeRegistry({_NHI: entry})

    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "spiffe_identity_mismatch"


@pytest.mark.asyncio
async def test_rotate_denied_for_inactive_or_unapproved(paths: IssuerPaths):
    _mint_initial(paths)
    backoffice_state.agent_registry = _FakeRegistry(
        {_NHI: _nhi_entry(status="inactive")}
    )
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403

    backoffice_state.agent_registry = _FakeRegistry(
        {_NHI: _nhi_entry(svid_issued=False)}
    )
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# Identity-record guards
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_refuses_non_agent_identity(paths: IssuerPaths):
    """caddy/backoffice pass the ACL exact-id list but carry no agent identity."""
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(
            agent_id=_NAME,
            caller_spiffe="spiffe://yashigani.internal/backoffice",
        )
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "cert_rotate_requires_agent_identity"


@pytest.mark.asyncio
async def test_rotate_refuses_unprovisioned_identity(paths: IssuerPaths):
    """No runtime-manifest entry (never minted) → fail-closed."""
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "identity_not_provisioned"


@pytest.mark.asyncio
async def test_rotate_refuses_revoked_identity(paths: IssuerPaths):
    _mint_initial(paths)
    assert revoke_agent_identity(paths, _TENANT, _NAME, _NHI) is True
    backoffice_state.agent_registry = _FakeRegistry({_NHI: _nhi_entry()})

    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "identity_revoked"


# ---------------------------------------------------------------------------
# Legacy (install.sh CLI mint — bundled agents)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_legacy_two_segment_identity(paths: IssuerPaths):
    """Bundled agents have no registry/envelope row — the runtime manifest is
    the authorisation record; re-mint stays binding-free like the original."""
    assert _mint_initial(paths, instance="") == _SPIFFE_LEGACY

    resp = await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE_LEGACY)

    assert resp.spiffe_id == _SPIFFE_LEGACY
    leaf = _leaf_of(resp.cert_pem)
    assert parse_binding_extension(leaf) is None  # no GAP-2 ext, same as CLI mint


# ---------------------------------------------------------------------------
# MCP-onboarded instances (capability envelope is the approval record)
# ---------------------------------------------------------------------------

def _fake_envelope(monkeypatch, rec, image_digest=_IMAGE, baseline_hash=None):
    from yashigani.backoffice.routes import mcp_servers as mcp_mod

    class _Svc:
        async def get_active_envelope(self, provenance_id: str):
            assert provenance_id == f"{_TENANT}:{_NAME}"
            return rec

    class _Store:
        def get(self, tenant_id: str, server_id: str):
            return {"image_digest": image_digest, "svid_instance_id": _NHI}

        def get_baseline(self, tenant_id: str, server_id: str):
            return {"surface_hash": baseline_hash or _SCOPE, "tools": list(_TOOLS)}

    monkeypatch.setattr(mcp_mod, "_envelope_service", lambda: _Svc())
    monkeypatch.setattr(mcp_mod, "_durable_registry_store", lambda: _Store())


def _envelope_rec(**overrides) -> Any:
    rec = SimpleNamespace(
        svid_issued=True,
        svid_instance_id=_NHI,
        svid_spiffe_id=_SPIFFE,
        surface_set_hash="sha256:" + "11" * 32,
        current_surface_hash="sha256:" + "11" * 32,
        envelope=SimpleNamespace(tools={t: object() for t in _TOOLS}),
    )
    for k, v in overrides.items():
        setattr(rec, k, v)
    return rec


@pytest.mark.asyncio
async def test_rotate_mcp_instance_happy_path(paths, monkeypatch):
    _mint_initial(paths)
    backoffice_state.agent_registry = None  # MCP instances have no registry row
    _fake_envelope(monkeypatch, _envelope_rec())

    resp = await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)

    assert resp.spiffe_id == _SPIFFE
    leaf = _leaf_of(resp.cert_pem)
    # Re-bound over the envelope-current tool surface + descriptor image digest
    assert parse_binding_extension(leaf) == binding_digest(_IMAGE, _SCOPE)


@pytest.mark.asyncio
async def test_rotate_mcp_denied_on_surface_drift(paths, monkeypatch):
    """current_surface_hash advanced past the approved set ⇒ re-approve first."""
    _mint_initial(paths)
    _fake_envelope(
        monkeypatch,
        _envelope_rec(current_surface_hash="sha256:" + "22" * 32),
    )
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 409
    assert exc.value.detail["error"] == "surface_changed_reapproval_required"


@pytest.mark.asyncio
async def test_rotate_mcp_denied_on_superseded_identity(paths, monkeypatch):
    """Server re-onboarded (new nhi_id) — the OLD cert must not rotate."""
    _mint_initial(paths)
    _fake_envelope(
        monkeypatch,
        _envelope_rec(svid_instance_id="nhi_999999999999"),
    )
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "identity_superseded_reapproval_required"


@pytest.mark.asyncio
async def test_rotate_mcp_denied_when_no_envelope(paths, monkeypatch):
    _mint_initial(paths)
    _fake_envelope(monkeypatch, None)
    with pytest.raises(HTTPException) as exc:
        await rotate_agent_cert(agent_id=_NAME, caller_spiffe=_SPIFFE)
    assert exc.value.status_code == 403
    assert exc.value.detail["error"] == "identity_record_not_found"


# ---------------------------------------------------------------------------
# Route wiring — the ACL path constant matches the ACL'd endpoint
# ---------------------------------------------------------------------------

def test_route_registered_with_acl_gate():
    routes = {
        r.path: r for r in agents_mod.router.routes  # type: ignore[attr-defined]
    }
    assert "/admin/agents/{agent_id}/cert/rotate" in routes
    assert agents_mod._CERT_ROTATE_ACL_PATH == "/admin/agents/*/cert/rotate"
