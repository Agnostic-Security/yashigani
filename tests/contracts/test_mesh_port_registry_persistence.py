# Last updated: 2026-07-06T00:00:00+00:00 (v4.1 unified-sidecar must-fix #10 — Captain C1/C2)
"""
Mesh-port registry persistence (C1) + egress forwarder constant port (C2).

Design (unified-sidecar-design-review-synthesis-20260706.md must-fix #10):

C1 — ``_SEEN_MESH_PORTS`` is in-process only and cleared on restart; the
approve flow never reconciled against the durable broker registry, so a
backoffice restart forgot every claimed port and the next onboard could hash
(or be pinned) onto an occupied port — an opaque C10 failure mid-transaction.
Fix: ``seed_mesh_ports_from_descriptors()`` seeds the registry from persisted
``DurableMcpRegistryStore`` descriptors (their ``upstream_url`` carries the
port) at approve-transaction entry.

C2 — the forthcoming per-system egress FORWARDER listener uses ONE fixed
constant port (``MCP_EGRESS_FORWARDER_PORT`` == 9400), OUTSIDE the
ingress-only mesh-port range [9500, 9900), descriptor-overridable via
``spec.mcp.exposes.forwarder_port`` (override validated to stay outside the
ingress range and off reserved base listeners).

The restart-simulation test here is the load-bearing one: it proves the seed
turns the silent cross-restart port grant into the explicit fail-closed
``MCP_mesh_port_collision`` abort.
"""
from __future__ import annotations

from typing import Any

import pytest

from yashigani.manifest.codegen import (
    MCP_EGRESS_FORWARDER_PORT,
    CodegenError,
    _MCP_MESH_PORT_BASE,
    _MCP_MESH_PORT_RANGE,
    _MCP_RESERVED_PORTS,
    _mcp_mesh_port,
    _mesh_port_from_upstream_url,
    reset_codegen_registry,
    resolve_egress_forwarder_port,
    seed_mesh_ports_from_descriptors,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Every test starts and ends with an empty codegen registry."""
    reset_codegen_registry()
    yield
    reset_codegen_registry()


def _manifest(
    name: str = "filesystem",
    tenant_id: str = "acme-corp",
    mesh_port: int | None = None,
    forwarder_port: Any = None,
) -> dict[str, Any]:
    exposes: dict[str, Any] = {}
    if mesh_port is not None:
        exposes["mesh_port"] = mesh_port
    if forwarder_port is not None:
        exposes["forwarder_port"] = forwarder_port
    return {
        "metadata": {"name": name, "tenant_id": tenant_id},
        "spec": {"mcp": {"exposes": exposes}},
    }


def _descriptor(
    tenant_id: str, server_id: str, port: int, **overrides: Any
) -> dict[str, Any]:
    """Shape of a DurableMcpRegistryStore descriptor as written by the
    approve transaction (mcp_onboard.py step 4b)."""
    desc: dict[str, Any] = {
        "agent_name": server_id,
        "tenant_id": tenant_id,
        "upstream_url": f"https://caddy:{port}/mcp/{tenant_id}/{server_id}",
        "spiffe_id": f"spiffe://yashigani.internal/agents/{tenant_id}/{server_id}/nhi_x",
        "svid_instance_id": "nhi_x",
    }
    desc.update(overrides)
    return desc


# ---------------------------------------------------------------------------
# C1 — seeding
# ---------------------------------------------------------------------------


def test_upstream_url_port_extraction():
    assert _mesh_port_from_upstream_url("https://caddy:9614/mcp/t/s") == 9614
    assert _mesh_port_from_upstream_url("https://caddy/mcp/t/s") is None
    assert _mesh_port_from_upstream_url("") is None
    assert _mesh_port_from_upstream_url("not a url") is None
    assert _mesh_port_from_upstream_url("https://caddy:notaport/mcp") is None


def test_restart_simulation_seed_restores_collision_guard():
    """THE C1 scenario: onboard A → restart (registry cleared) → seed from
    persisted state → onboarding B pinned to A's port must abort with the
    explicit collision error instead of silently claiming the port."""
    # 1. First onboard: A resolves its deterministic port.
    port_a = _mcp_mesh_port(_manifest(name="filesystem", tenant_id="acme-corp"))
    persisted = [_descriptor("acme-corp", "filesystem", port_a)]

    # 2. Simulated backoffice restart: in-process registry is wiped.
    reset_codegen_registry()

    # 3. CONTROL — without the seed, the pre-fix behaviour silently grants
    #    A's port to B (this is the bug the fix closes).
    _mcp_mesh_port(_manifest(name="git", tenant_id="other-corp", mesh_port=port_a))
    reset_codegen_registry()

    # 4. FIX — engine init seeds from persisted descriptors...
    assert seed_mesh_ports_from_descriptors(persisted) == 1

    # ...and B pinning A's port now aborts fail-closed and names A.
    with pytest.raises(CodegenError, match="MCP_mesh_port_collision"):
        _mcp_mesh_port(_manifest(name="git", tenant_id="other-corp", mesh_port=port_a))


def test_seed_same_pair_reapprove_stays_safe():
    """Re-approving the instance that owns a seeded port must NOT collide
    (idempotent same-pair semantics — deterministic hash re-resolution)."""
    port_a = _mcp_mesh_port(_manifest(name="filesystem", tenant_id="acme-corp"))
    persisted = [_descriptor("acme-corp", "filesystem", port_a)]
    reset_codegen_registry()

    assert seed_mesh_ports_from_descriptors(persisted) == 1
    # Same (tenant, server) re-resolves the same port without error.
    assert _mcp_mesh_port(_manifest(name="filesystem", tenant_id="acme-corp")) == port_a


def test_seed_is_idempotent():
    persisted = [_descriptor("acme-corp", "filesystem", 9614)]
    assert seed_mesh_ports_from_descriptors(persisted) == 1
    assert seed_mesh_ports_from_descriptors(persisted) == 0  # no new claims


def test_seed_tolerates_malformed_descriptors(caplog):
    """Legacy/corrupt persisted entries must be skipped (warned), never brick
    onboarding.  Only the well-formed claim is registered."""
    entries: list[Any] = [
        _descriptor("acme-corp", "filesystem", 9614),          # good
        _descriptor("acme-corp", "no-port", 9615, upstream_url="https://caddy/mcp/t/s"),
        _descriptor("", "empty-tenant", 9616),                  # empty tenant
        _descriptor("acme-corp", "", 9617),                     # empty server
        {"agent_name": "no-url", "tenant_id": "t"},             # missing url
        "not-a-dict",                                           # wrong type
        _descriptor("acme-corp", "bad-url", 9618, upstream_url="::garbage::"),
        _descriptor("acme-corp", "low-port", 80, upstream_url="https://caddy:80/x"),
    ]
    assert seed_mesh_ports_from_descriptors(entries) == 1
    with pytest.raises(CodegenError, match="MCP_mesh_port_collision"):
        _mcp_mesh_port(_manifest(name="other", tenant_id="other", mesh_port=9614))


def test_seed_conflicting_persisted_claims_first_wins(caplog):
    """Two persisted descriptors claiming one port for different pairs is
    corrupt durable state (the approve tx would have aborted).  Seed keeps the
    first claim and logs an error; the loser's re-approve aborts fail-closed."""
    entries = [
        _descriptor("acme-corp", "filesystem", 9614),
        _descriptor("other-corp", "git", 9614),
    ]
    with caplog.at_level("ERROR"):
        assert seed_mesh_ports_from_descriptors(entries) == 1
    assert any("claimed by BOTH" in r.message for r in caplog.records)
    # The losing pair now collides explicitly on re-approve.
    with pytest.raises(CodegenError, match="MCP_mesh_port_collision"):
        _mcp_mesh_port(_manifest(name="git", tenant_id="other-corp", mesh_port=9614))


# ---------------------------------------------------------------------------
# C2 — forwarder constant port
# ---------------------------------------------------------------------------


def test_forwarder_port_is_fixed_and_outside_ingress_range():
    assert MCP_EGRESS_FORWARDER_PORT == 9400
    ingress_lo = _MCP_MESH_PORT_BASE
    ingress_hi = _MCP_MESH_PORT_BASE + _MCP_MESH_PORT_RANGE
    assert not (ingress_lo <= MCP_EGRESS_FORWARDER_PORT < ingress_hi), (
        "forwarder port leaked INTO the ingress-only mesh-port range"
    )
    assert MCP_EGRESS_FORWARDER_PORT in _MCP_RESERVED_PORTS, (
        "forwarder port must be reserved so an ingress pin can never claim it"
    )


def test_base_egress_listeners_are_reserved():
    """L4 same-class sweep: the static base listeners an ingress pin must
    never collide with (ollama front, openclaw app, openclaw egress gateway)."""
    for port in (11435, 18789, 18790):
        assert port in _MCP_RESERVED_PORTS, f"base listener {port} not reserved"


def test_ingress_pin_cannot_claim_forwarder_port():
    with pytest.raises(CodegenError, match="MCP_mesh_port_invalid"):
        _mcp_mesh_port(_manifest(mesh_port=MCP_EGRESS_FORWARDER_PORT))


def test_forwarder_port_default_and_override():
    assert resolve_egress_forwarder_port(None) == MCP_EGRESS_FORWARDER_PORT
    assert resolve_egress_forwarder_port(_manifest()) == MCP_EGRESS_FORWARDER_PORT
    # A valid override: outside ingress range, not reserved.
    assert resolve_egress_forwarder_port(_manifest(forwarder_port=9410)) == 9410
    # Overriding to the well-known constant itself is allowed (explicit default).
    assert resolve_egress_forwarder_port(
        _manifest(forwarder_port=MCP_EGRESS_FORWARDER_PORT)
    ) == MCP_EGRESS_FORWARDER_PORT


@pytest.mark.parametrize(
    "bad",
    [
        9500,          # ingress range floor
        9614,          # inside ingress range
        9899,          # ingress range ceiling
        8443,          # reserved base listener
        18790,         # reserved egress gateway
        80,            # < 1024
        70000,         # > 65535
        True,          # bool is not a port
        "9410",        # string is not a port
    ],
)
def test_forwarder_port_invalid_overrides_rejected(bad):
    with pytest.raises(CodegenError, match="MCP_forwarder_port_invalid"):
        resolve_egress_forwarder_port(_manifest(forwarder_port=bad))
