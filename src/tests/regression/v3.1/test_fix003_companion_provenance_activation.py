"""
FIX-003 companion — broker provenance_id activation for pinned imported servers.

Verifies that build_registry_from_env() wires P8 pin configs from
YASHIGANI_MCP_SERVERS JSON entries into each McpBroker, so:
  • broker._upstream_pin_map is populated for pinned servers
  • broker._provenance_id_for(server_id) returns a non-None value
  • broker._check_capability_envelope() is LIVE (not a no-op) for pinned servers

This closes the gap where _provenance_id_for always returned None because the
registry builder never passed upstream_pin_configs to McpBrokerConfig, making
capability-envelope enforcement inert for ALL servers regardless of whether an
envelope v1 had been minted (FIX-003).

Coverage:
  A. Registry wiring — pin config extracted from YASHIGANI_MCP_SERVERS entry
     A1. Entry with cert_fingerprint_sha256 → _upstream_pin_map populated
     A2. Entry with spiffe_id → _upstream_pin_map populated
     A3. Entry with no pin material → _upstream_pin_map empty (correct)
     A4. pin_mode defaults to cert_fingerprint when absent

  B. _provenance_id_for — pinned vs unpinned server
     B1. Pinned server (cert_fp) → provenance_id is non-None
     B2. Pinned server (spiffe) → provenance_id is non-None
     B3. Unpinned server (no pin material) → provenance_id is None
     B4. H(server_id ‖ pin_material) — consistent across calls

  C. _check_capability_envelope activation — pinned server with envelope service
     C1. Pinned server + envelope_service=None + prod → deny
         "capability_envelope_service_unavailable" (envelope gate LIVE)
     C2. Unpinned server + envelope_service=None + prod → no-op (None)
         (envelope gate correctly inert — not an imported MCP)

  D. Security — no server_id-only fallback in enforcing envs
     D1. Missing pin material in YASHIGANI_MCP_SERVERS → _provenance_id_for None
         (name-only fallback would be a cryptographic binding bypass)
"""
from __future__ import annotations

import json
import os
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_REAL_FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
_REAL_SPIFFE = "spiffe://cluster.local/ns/default/sa/github-mcp"


def _server_entry(
    agent_name: str = "github-mcp",
    upstream_url: str = "http://github-mcp:8000",
    tenant_id: str = "acme",
    cert_fingerprint_sha256: str = "",
    spiffe_id: str = "",
    pin_mode: str = "",
    pin_host: str = "",
    pin_port: Optional[int] = None,
):
    """Build a YASHIGANI_MCP_SERVERS-style entry dict."""
    entry: dict = {
        "agent_name": agent_name,
        "upstream_url": upstream_url,
        "tenant_id": tenant_id,
    }
    if cert_fingerprint_sha256:
        entry["cert_fingerprint_sha256"] = cert_fingerprint_sha256
    if spiffe_id:
        entry["spiffe_id"] = spiffe_id
    if pin_mode:
        entry["pin_mode"] = pin_mode
    if pin_host:
        entry["pin_host"] = pin_host
    if pin_port is not None:
        entry["pin_port"] = pin_port
    return entry


def _build_registry(entries: list, opa_url: str = "http://opa:8181"):
    """Call build_registry_from_env with a synthetic YASHIGANI_MCP_SERVERS."""
    from yashigani.mcp.registry import build_registry_from_env
    env = {
        "YASHIGANI_MCP_SERVERS": json.dumps(entries),
        "YASHIGANI_ENV": "development",  # avoid audit_writer prod check
    }
    # Patch McpBroker.__init__ audit_writer check so dev mode doesn't raise.
    with patch.dict(os.environ, env):
        registry, _ = build_registry_from_env(opa_url=opa_url)
    return registry


def _get_broker(registry, agent_name: str):
    """Extract broker from registry tuple."""
    entry = registry.get(agent_name)
    assert entry is not None, f"agent {agent_name!r} not in registry"
    broker, _ = entry
    return broker


# ─────────────────────────────────────────────────────────────────────────────
# A. Registry wiring — pin configs extracted from YASHIGANI_MCP_SERVERS entries
# ─────────────────────────────────────────────────────────────────────────────

class TestRegistryPinWiring:
    """build_registry_from_env wires P8 pin configs when present in entry."""

    def test_a1_cert_fingerprint_populates_pin_map(self):
        """A1: Entry with cert_fingerprint_sha256 → broker._upstream_pin_map non-empty."""
        entry = _server_entry(cert_fingerprint_sha256=_REAL_FP)
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")
        assert "github-mcp" in broker._upstream_pin_map, (
            "FIX-003-companion: entry with cert_fingerprint_sha256 must populate "
            "_upstream_pin_map so envelope enforcement activates. "
            f"Got map keys: {list(broker._upstream_pin_map.keys())!r}."
        )
        pin_cfg = broker._upstream_pin_map["github-mcp"]
        assert pin_cfg.cert_fingerprint_sha256 == _REAL_FP, (
            f"cert_fingerprint_sha256 must match. Got {pin_cfg.cert_fingerprint_sha256!r}."
        )

    def test_a2_spiffe_id_populates_pin_map(self):
        """A2: Entry with spiffe_id → broker._upstream_pin_map non-empty."""
        entry = _server_entry(spiffe_id=_REAL_SPIFFE, pin_mode="spiffe")
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")
        assert "github-mcp" in broker._upstream_pin_map, (
            "FIX-003-companion: entry with spiffe_id must populate _upstream_pin_map. "
            f"Got map keys: {list(broker._upstream_pin_map.keys())!r}."
        )
        pin_cfg = broker._upstream_pin_map["github-mcp"]
        assert pin_cfg.spiffe_id == _REAL_SPIFFE

    def test_a3_no_pin_material_leaves_pin_map_empty(self):
        """A3: Entry with no pin material → _upstream_pin_map empty (correct)."""
        entry = _server_entry()  # no cert_fingerprint_sha256, no spiffe_id
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")
        assert "github-mcp" not in broker._upstream_pin_map, (
            "FIX-003-companion: entry with no pin material must NOT populate "
            "_upstream_pin_map (correct — no cryptographic binding available). "
            f"Got map keys: {list(broker._upstream_pin_map.keys())!r}."
        )

    def test_a4_pin_mode_defaults_to_cert_fingerprint(self):
        """A4: Entry with cert_fp but no pin_mode → defaults to cert_fingerprint."""
        from yashigani.mcp._upstream_pin import PinMode
        entry = _server_entry(cert_fingerprint_sha256=_REAL_FP)
        # No pin_mode in entry — should default to cert_fingerprint
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")
        pin_cfg = broker._upstream_pin_map.get("github-mcp")
        assert pin_cfg is not None
        assert pin_cfg.pin_mode == PinMode.CERT_FINGERPRINT


# ─────────────────────────────────────────────────────────────────────────────
# B. _provenance_id_for — pinned vs unpinned server
# ─────────────────────────────────────────────────────────────────────────────

class TestProvenanceIdActivation:
    """broker._provenance_id_for returns non-None for pinned imported servers."""

    def test_b1_pinned_cert_fp_yields_provenance_id(self):
        """B1: Pinned server (cert_fp) → _provenance_id_for returns non-None hash."""
        entry = _server_entry(cert_fingerprint_sha256=_REAL_FP)
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")

        prov_id = broker._provenance_id_for("github-mcp")
        assert prov_id is not None, (
            "FIX-003-companion: pinned server (cert_fp) must yield a non-None "
            "provenance_id so capability-envelope gate activates. "
            "Got None — envelope enforcement is inert (the bug this fixes)."
        )
        assert len(prov_id) == 64, (
            f"provenance_id must be a 64-char hex SHA-256. Got len={len(prov_id)!r}."
        )

    def test_b2_pinned_spiffe_yields_provenance_id(self):
        """B2: Pinned server (spiffe) → _provenance_id_for returns non-None hash."""
        entry = _server_entry(spiffe_id=_REAL_SPIFFE, pin_mode="spiffe")
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")

        prov_id = broker._provenance_id_for("github-mcp")
        assert prov_id is not None, (
            "FIX-003-companion: pinned server (spiffe) must yield a non-None provenance_id."
        )

    def test_b3_unpinned_server_yields_none(self):
        """B3: Unpinned server (no pin material) → _provenance_id_for returns None."""
        entry = _server_entry()  # no cert_fingerprint_sha256, no spiffe_id
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")

        prov_id = broker._provenance_id_for("github-mcp")
        assert prov_id is None, (
            "FIX-003-companion: unpinned server must return None from _provenance_id_for. "
            "A name-only server is not an envelope-governed imported MCP. "
            f"Got {prov_id!r}."
        )

    def test_b4_provenance_id_consistent_across_calls(self):
        """B4: H(server_id ‖ pin_material) is deterministic — same value each call."""
        entry = _server_entry(cert_fingerprint_sha256=_REAL_FP)
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")

        prov_a = broker._provenance_id_for("github-mcp")
        prov_b = broker._provenance_id_for("github-mcp")
        assert prov_a == prov_b, (
            "provenance_id must be deterministic (same hash both calls). "
            f"Got {prov_a!r} vs {prov_b!r}."
        )


# ─────────────────────────────────────────────────────────────────────────────
# C. _check_capability_envelope — activated for pinned servers
# ─────────────────────────────────────────────────────────────────────────────

class TestCapabilityEnvelopeActivation:
    """
    _check_capability_envelope is LIVE for pinned servers.

    This is the core of the broker companion fix: before FIX-003-companion,
    _provenance_id_for always returned None → _check_capability_envelope
    short-circuited at "provenance_id is None → not an envelope-governed server"
    and returned None (allow) for every server, including pinned imported ones.

    Now that the registry wires pin configs, _check_capability_envelope
    reaches the envelope_service check for pinned servers, making the gate live.
    """

    @pytest.mark.asyncio
    async def test_c1_pinned_server_no_envelope_service_prod_denies(self):
        """
        C1: Pinned server + envelope_service=None + prod → DENY
        "capability_envelope_service_unavailable".

        This is the activation proof: _check_capability_envelope now reaches
        the prod-enforcing guard (provenance_id is not None, service is None,
        prod env → deny).  Before the fix: provenance_id=None → returns None
        without ever checking the service.
        """
        entry = _server_entry(cert_fingerprint_sha256=_REAL_FP)

        # Build registry without using build_registry_from_env helper because
        # we need envelope_service=None (the default) explicitly.
        from yashigani.mcp.registry import build_registry_from_env
        env = {
            "YASHIGANI_MCP_SERVERS": json.dumps([entry]),
            "YASHIGANI_ENV": "development",  # suppress audit_writer prod check at init
        }
        with patch.dict(os.environ, env):
            registry, _ = build_registry_from_env(opa_url="http://opa:8181")
        broker = _get_broker(registry, "github-mcp")

        # broker.envelope_service is None by default (not passed in registry builder)
        from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
        posture, binding = McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)
        ctx = McpCallContext(
            tenant_id="acme",
            agent_name="github-mcp",
            user_id="u1",
            posture=posture,
            posture_binding=binding,
            action="mcp.tools.call",
            tool_name="search_code",
            server_id="github-mcp",
        )

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            result = await broker._check_capability_envelope(ctx)

        assert result == "capability_envelope_service_unavailable", (
            "FIX-003-companion: pinned server + envelope_service=None + prod must "
            "return 'capability_envelope_service_unavailable'. "
            f"Got {result!r}. If None: envelope gate is still inert (fix didn't activate)."
        )

    @pytest.mark.asyncio
    async def test_c2_unpinned_server_no_service_is_noop(self):
        """
        C2: Unpinned server + envelope_service=None → None (no-op).

        Local stdio agents and first-party tools are not envelope-governed —
        they have no P8 pin → no provenance_id → gate correctly skips them.
        """
        entry = _server_entry()  # no pin material → unpinned
        env = {
            "YASHIGANI_MCP_SERVERS": json.dumps([entry]),
            "YASHIGANI_ENV": "development",
        }
        from yashigani.mcp.registry import build_registry_from_env
        with patch.dict(os.environ, env):
            registry, _ = build_registry_from_env(opa_url="http://opa:8181")
        broker = _get_broker(registry, "github-mcp")

        from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
        posture, binding = McpPosture.MCP_B, PostureBinding.for_posture(McpPosture.MCP_B)
        ctx = McpCallContext(
            tenant_id="acme",
            agent_name="github-mcp",
            user_id="u1",
            posture=posture,
            posture_binding=binding,
            action="mcp.tools.call",
            tool_name="some_tool",
            server_id="github-mcp",
        )

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            result = await broker._check_capability_envelope(ctx)

        assert result is None, (
            "FIX-003-companion: unpinned server must be a no-op for envelope gate "
            f"(not an imported MCP, no cryptographic binding). Got {result!r}."
        )


# ─────────────────────────────────────────────────────────────────────────────
# D. Security — no server_id-only name-fallback in enforcing envs
# ─────────────────────────────────────────────────────────────────────────────

class TestNoNameFallback:
    """
    Confirm no server_id-only name-fallback was introduced.

    A name-only fallback (provenance_id = H(server_id)) would be cryptographically
    weak — a spoofed server_id would pass envelope checks against any existing
    envelope.  The cryptographic binding REQUIRES pin material (cert fingerprint
    or SPIFFE ID) alongside the server_id.
    """

    def test_d1_no_pin_material_yields_none_not_name_based(self):
        """D1: Missing pin material → None, NOT H(server_id) name-only fallback."""
        entry = _server_entry()  # no cert_fp, no spiffe_id
        registry = _build_registry([entry])
        broker = _get_broker(registry, "github-mcp")

        prov_id = broker._provenance_id_for("github-mcp")
        assert prov_id is None, (
            "SECURITY: _provenance_id_for must return None when there is no pin "
            "material — a server_id name-only fallback would weaken cryptographic "
            "binding (names can be spoofed). "
            f"Got non-None {prov_id!r}."
        )
