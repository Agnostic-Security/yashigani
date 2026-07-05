# Last updated: 2026-07-05T00:00:00+00:00 (v4.1 Phase 1b-i — MCP Caddy-front wrap)
"""
v4.1 Phase 1b-i contract tests — the MCP Caddy-front ("the wrap").

Every onboarded Shape-C MCP server must be fronted by Caddy:
  docker/caddy/agents/<server_id>-mcp.caddy — dedicated mesh listener where
  Caddy PRESENTS the per-instance leaf (svid-sidecar tmpfs projection) and
  VERIFIES mesh clients (require_and_verify), forward_auths to backoffice,
  and reverse-proxies to the shim over the MCP's ringfence bridge.

SNIPPET CONTRACT pinned here (Su Phase 1b-ii + Tom build against this):
  route:          handle_path /mcp/<tenant_id>/<server_id>/*
  listener:       :<mesh_port> — deterministic 9500 + sha256(tenant/name)%400,
                  pinnable via spec.mcp.exposes.mesh_port
  leaf paths:     /run/secrets/svid/<tenant_id>/<server_id>/client.{crt,key}
                  (basenames = svid-sidecar rotate.sh contract; nhi_id lives
                  in the cert CONTENT, never the path)
  client trust:   /run/secrets/ca_intermediate.crt, mode require_and_verify
  forward_auth:   https://backoffice:8443 /auth/verify-mcp?tenant=&server=
  upstream:       http://<server_id>:<shim_port> (ringfence bridge, plain HTTP
                  by design — T2; identity = leaf + OPA input subject)
  bridge:         ringfence_<server_id> (internal:true); members: MCP + caddy
                  ONLY.  Gateway must NOT join (around-the-wrap bypass).
"""
from __future__ import annotations

import re
from typing import Any

import pytest

from yashigani.manifest.codegen import (
    CodegenEngineShapeC,
    CodegenError,
    _MCP_MESH_PORT_BASE,
    _MCP_MESH_PORT_RANGE,
    _mcp_mesh_port,
    reset_codegen_registry,
)

_FAKE_DIGEST = "sha256:" + "a" * 64


def _base_manifest(
    name: str = "filesystem",
    tenant_id: str = "acme-corp",
    mesh_port: int | None = None,
) -> dict[str, Any]:
    exposes: dict[str, Any] = {
        "listen_port": None,
        "shim_port": 8000,
        "tools": [
            {"name": "read_file", "allowed": True, "sensitivity_class": "INTERNAL"},
        ],
    }
    if mesh_port is not None:
        exposes["mesh_port"] = mesh_port
    return {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {
            "name": name,
            "tenant_id": tenant_id,
            "category": "mcp_server",
            "description": "MCP server for wrap contract testing",
            "vendor": "Anthropic",
            "licence": "MIT",
        },
        "spec": {
            "image": {
                "repository": "registry.yashigani.internal/bundles/mcp-filesystem",
                "tag": "latest",
                "digest": _FAKE_DIGEST,
            },
            "write_posture": "readonly",
            "subprocess": {"command": ["node", "index.js"], "args": ["/workspace"]},
            "network": {"egress_allow": []},
            "mcp": {
                "posture": "mcp-b",
                "transport": "stdio",
                "session_mode": "persistent",
                "identity_propagation": "gateway-enforced-only",
                "exposes": exposes,
            },
            "storage": {
                "mounts": [
                    {
                        "name": "ysg_fs_acme_corp_filesystem_workspace",
                        "type": "volume",
                        "container_path": "/workspace",
                        "read_only": False,
                        "create_if_missing": True,
                    }
                ],
                "tmpfs": [{"path": "/tmp", "size_limit": "64m"}],
            },
            "secrets": [],
            "lifecycle": {"mode": "persistent"},
        },
    }


@pytest.fixture(autouse=True)
def _reset_registry():
    reset_codegen_registry()
    yield
    reset_codegen_registry()


def _render(manifest: dict[str, Any] | None = None) -> dict[str, str]:
    engine = CodegenEngineShapeC(
        manifest or _base_manifest(),
        runtime="docker",
        caddy_validator=lambda _cfg: 0,
    )
    return engine.render(dry_run=True)


# ---------------------------------------------------------------------------
# 1. Artifact presence — wrap generated, egress route still absent
# ---------------------------------------------------------------------------


def test_wrap_snippet_present_and_egress_route_absent():
    artifacts = _render()
    assert "docker/caddy/agents/filesystem-mcp.caddy" in artifacts, (
        "Phase 1b-i wrap snippet missing — MCP would onboard UNWRAPPED"
    )
    # SC-EGRESS-NONE unchanged: no Shape-A LLM-egress route.
    assert "docker/caddy/agents/filesystem.caddy" not in artifacts


# ---------------------------------------------------------------------------
# 2. Snippet contract — every load-bearing element pinned
# ---------------------------------------------------------------------------


def test_wrap_snippet_contract():
    artifacts = _render()
    snip = artifacts["docker/caddy/agents/filesystem-mcp.caddy"]

    # Route namespace, prefix-stripping route.
    assert "handle_path /mcp/acme-corp/filesystem/*" in snip
    # Per-instance leaf presented by Caddy (svid-sidecar tmpfs projection).
    assert ("tls /run/secrets/svid/acme-corp/filesystem/client.crt "
            "/run/secrets/svid/acme-corp/filesystem/client.key") in snip
    # Mesh clients MUST present a cert chained to the internal intermediate.
    assert "mode require_and_verify" in snip
    assert "trust_pool file /run/secrets/ca_intermediate.crt" in snip
    assert "protocols tls1.3" in snip
    # Zero-trust header discipline: strip inbound, then set from VERIFIED cert.
    strip_idx = snip.index("request_header -X-SPIFFE-ID")
    set_idx = snip.index(
        "request_header X-SPIFFE-ID {http.request.tls.client.san.uris.0}")
    assert strip_idx < set_idx
    # App-layer ingress gate via backoffice.
    assert "forward_auth https://backoffice:8443" in snip
    assert "uri /auth/verify-mcp?tenant=acme-corp&server=filesystem" in snip
    # forward_auth itself is mTLS to backoffice.
    assert "tls_client_auth /run/secrets/caddy_client.crt /run/secrets/caddy_client.key" in snip
    # Upstream: shim over the ringfence bridge, plain HTTP (T2), C8 cap.
    assert "reverse_proxy http://filesystem:8000" in snip
    assert "max_conns_per_host 64" in snip
    # tls_insecure_skip_verify is NEVER emitted (C5 discipline).
    assert "tls_insecure_skip_verify" not in snip
    # Default-deny tail.
    assert 'respond "Not Found" 404' in snip


def test_wrap_listener_port_deterministic_and_in_range():
    artifacts = _render()
    snip = artifacts["docker/caddy/agents/filesystem-mcp.caddy"]
    m = re.search(r"^:(\d+) \{", snip, re.MULTILINE)
    assert m, "dedicated mesh listener block missing"
    port = int(m.group(1))
    assert _MCP_MESH_PORT_BASE <= port < _MCP_MESH_PORT_BASE + _MCP_MESH_PORT_RANGE

    # Deterministic across sessions.
    reset_codegen_registry()
    snip2 = _render()["docker/caddy/agents/filesystem-mcp.caddy"]
    assert snip == snip2


# ---------------------------------------------------------------------------
# 3. Mesh-port resolution — explicit pin, validation, collision
# ---------------------------------------------------------------------------


def test_mesh_port_explicit_pin_honoured():
    artifacts = _render(_base_manifest(mesh_port=9700))
    snip = artifacts["docker/caddy/agents/filesystem-mcp.caddy"]
    assert "\n:9700 {" in snip


@pytest.mark.parametrize("bad", [443, 8444, 80, 100, 70000, "9700", True])
def test_mesh_port_invalid_rejected(bad):
    manifest = _base_manifest()
    manifest["spec"]["mcp"]["exposes"]["mesh_port"] = bad
    with pytest.raises(CodegenError) as exc:
        _mcp_mesh_port(manifest)
    assert exc.value.code == "MCP_mesh_port_invalid"


def test_mesh_port_collision_aborts():
    _mcp_mesh_port(_base_manifest(name="filesystem", mesh_port=9600))
    with pytest.raises(CodegenError) as exc:
        _mcp_mesh_port(_base_manifest(name="git", mesh_port=9600))
    assert exc.value.code == "MCP_mesh_port_collision"


def test_mesh_port_same_instance_re_resolution_ok():
    a = _mcp_mesh_port(_base_manifest())
    b = _mcp_mesh_port(_base_manifest())  # same (tenant, name) — no collision
    assert a == b


# ---------------------------------------------------------------------------
# 4. Compose override — ringfence bridge shape (the containment half)
# ---------------------------------------------------------------------------


def test_compose_caddy_joins_ringfence_and_mcp_stays_isolated():
    artifacts = _render()
    compose = artifacts["docker/filesystem-compose.override.yml"]

    # Caddy joins the MCP's ringfence bridge (generated override — no monolith edit).
    caddy_stanza = compose.split("  caddy:", 1)[1]
    assert "- ringfence_filesystem" in caddy_stanza
    # The MCP itself joins ONLY the ringfence bridge — never caddy_internal.
    # (Line-based: comments legitimately mention caddy_internal.)
    assert not any(
        line.strip() in ("- caddy_internal", "caddy_internal:")
        for line in compose.splitlines()
    )
    # The old around-the-wrap guidance (gateway joins the bridge) is GONE.
    assert "gateway:" not in compose
    assert "docker compose up -d gateway" not in compose
    # Broker guidance points at the Caddy front, not the bare shim.
    assert re.search(r'"upstream_url": "https://caddy:\d+/mcp/acme-corp/filesystem"', compose)
    assert '"upstream_url": "http://filesystem:8000"' not in compose
    # Bridge remains internal:true.
    assert "internal: true" in compose


# ---------------------------------------------------------------------------
# 5. C10 — validator gate applies to the wrap snippet
# ---------------------------------------------------------------------------


def test_wrap_snippet_c10_validator_failure_aborts():
    engine = CodegenEngineShapeC(
        _base_manifest(), runtime="docker", caddy_validator=lambda _cfg: 1,
    )
    with pytest.raises(CodegenError) as exc:
        engine.render(dry_run=True)
    assert exc.value.code == "C10_caddy_validate_failed"


def test_wrap_snippet_passes_real_caddy_if_present():
    """Adapt + validate the generated snippet with the REAL caddy binary
    (ephemeral-cert substitution). Skipped when caddy is not on PATH."""
    import shutil as _shutil

    if _shutil.which("caddy") is None:
        pytest.skip("caddy binary not on PATH")
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)  # raises CodegenError on C10 failure
    assert "docker/caddy/agents/filesystem-mcp.caddy" in artifacts
