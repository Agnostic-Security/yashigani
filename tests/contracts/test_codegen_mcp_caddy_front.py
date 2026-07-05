# Last updated: 2026-07-06T00:00:00+00:00 (v4.1 Phase 1b-ii — SVID-GID model + demo-mcp + approve-hook)
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
    _MCP_SVID_GID,
    _mcp_mesh_port,
    _mcp_svid_volume_name,
    approve_mcp_onboard,
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


# ---------------------------------------------------------------------------
# 6. SVID volume + GID model (Phase 1b-ii seam)
# ---------------------------------------------------------------------------


def test_svid_volume_declared_in_compose_override():
    """Phase 1b-ii: compose override declares ysg_svid_<tenant>_<server> volume."""
    artifacts = _render()
    compose = artifacts["docker/filesystem-compose.override.yml"]
    vol_name = _mcp_svid_volume_name("acme-corp", "filesystem")
    # Named volume declared in the volumes: section.
    assert ("%s:" % vol_name) in compose
    assert "driver: local" in compose


def test_caddy_mounts_svid_volume_at_correct_path():
    """Phase 1b-ii: the Caddy stanza mounts the SVID volume at the expected path."""
    artifacts = _render()
    compose = artifacts["docker/filesystem-compose.override.yml"]
    vol_name = _mcp_svid_volume_name("acme-corp", "filesystem")
    expected_mount = "%s:/run/secrets/svid/acme-corp/filesystem" % vol_name
    # Mount is under the caddy: stanza (appears after the caddy: key).
    caddy_stanza = compose.split("  caddy:", 1)[1]
    assert expected_mount in caddy_stanza


def test_caddy_has_svid_gid_group_add():
    """Phase 1b-ii: Caddy gets group_add _MCP_SVID_GID so it can read 0440 keys."""
    artifacts = _render()
    compose = artifacts["docker/filesystem-compose.override.yml"]
    caddy_stanza = compose.split("  caddy:", 1)[1]
    # group_add must be present in the caddy stanza.
    assert "group_add:" in caddy_stanza
    assert ('"%d"' % _MCP_SVID_GID) in caddy_stanza


def test_svid_gid_is_distinct_from_kms_gid():
    """_MCP_SVID_GID must not equal 2002 (KMS GID S7) — the two access classes
    must never be conflated."""
    assert _MCP_SVID_GID != 2002, (
        "SVID GID must not be 2002 (KMS GID). Two distinct GIDs enforce"
        " least-privilege separation between SVID and KMS secret access."
    )


def test_perm_model_documented_in_compose():
    """Compose override comment must document the 0440 key-perm requirement so
    Su knows rotate.sh must be updated (chmod 0440, not 0400)."""
    artifacts = _render()
    compose = artifacts["docker/filesystem-compose.override.yml"]
    # The '0440' comment drives Su's rotate.sh perm-bump — MUST be present.
    assert "0440" in compose


# ---------------------------------------------------------------------------
# 7. demo-mcp via codegen onboarding flow (no hand-wired leaf source)
# ---------------------------------------------------------------------------

_DEMO_MCP_DIGEST = "sha256:" + "b" * 64


def _demo_mcp_manifest() -> dict[str, Any]:
    """Minimal Shape-C manifest for the demo-mcp server.

    demo-mcp is onboarded through the codegen approve flow just like any other
    Shape-C server.  It gets a proper per-instance leaf (minted by
    mint_agent_leaf) and a Caddy front — no second hand-wired leaf source.

    Tenant 'yashigani-demo' is the internal demo tenant; operators never
    interact with this tenant's servers directly.
    """
    return {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {
            "name": "demo-mcp",
            "tenant_id": "yashigani-demo",
            "category": "mcp_server",
            "description": "Purpose-built demo MCP server (cloud-9 rogue-tool demo)",
            "vendor": "Agnostic Security",
            "licence": "proprietary",
        },
        "spec": {
            "image": {
                "repository": "yashigani/demo-mcp",
                "tag": "3.0.0",
                "digest": _DEMO_MCP_DIGEST,
            },
            "write_posture": "readonly",
            "subprocess": {
                "command": ["python3", "server.py"],
                "args": [],
            },
            "network": {"egress_allow": []},
            "mcp": {
                "posture": "mcp-b",
                "transport": "stdio",
                "session_mode": "persistent",
                "identity_propagation": "gateway-enforced-only",
                "exposes": {
                    "listen_port": None,
                    "shim_port": 8000,
                    "tools": [
                        {"name": "echo", "allowed": True, "sensitivity_class": "PUBLIC"},
                        {"name": "add", "allowed": True, "sensitivity_class": "PUBLIC"},
                        {"name": "uppercase", "allowed": True, "sensitivity_class": "PUBLIC"},
                        {"name": "word_count", "allowed": True, "sensitivity_class": "PUBLIC"},
                        {"name": "current_time", "allowed": True, "sensitivity_class": "PUBLIC"},
                    ],
                },
            },
            "storage": {
                "mounts": [],
                "tmpfs": [{"path": "/tmp", "size_limit": "16m"}],
            },
            "secrets": [],
            "lifecycle": {"mode": "persistent"},
        },
    }


def test_demo_mcp_gets_caddy_front_via_codegen():
    """demo-mcp must receive a Caddy-front snippet through the codegen flow,
    not a hand-wired leaf.  Verifies the snippet is present, route-namespaced,
    and the SVID paths use the correct tenant."""
    reset_codegen_registry()
    artifacts = CodegenEngineShapeC(
        _demo_mcp_manifest(), runtime="docker", caddy_validator=lambda _: 0,
    ).render(dry_run=True)

    # Wrap snippet is present and correctly named.
    assert "docker/caddy/agents/demo-mcp-mcp.caddy" in artifacts
    # No egress route.
    assert "docker/caddy/agents/demo-mcp.caddy" not in artifacts

    snip = artifacts["docker/caddy/agents/demo-mcp-mcp.caddy"]
    # Route namespace uses the demo tenant.
    assert "handle_path /mcp/yashigani-demo/demo-mcp/*" in snip
    # SVID paths use the demo tenant — no cross-tenant path confusion.
    assert "tls /run/secrets/svid/yashigani-demo/demo-mcp/client.crt" in snip


def test_demo_mcp_compose_has_svid_volume_and_gid():
    """demo-mcp compose override must carry the SVID volume + Caddy group_add."""
    reset_codegen_registry()
    artifacts = CodegenEngineShapeC(
        _demo_mcp_manifest(), runtime="docker", caddy_validator=lambda _: 0,
    ).render(dry_run=True)

    compose = artifacts["docker/demo-mcp-compose.override.yml"]
    vol_name = _mcp_svid_volume_name("yashigani-demo", "demo-mcp")
    # SVID volume declared.
    assert ("%s:" % vol_name) in compose
    # Caddy mount.
    caddy_stanza = compose.split("  caddy:", 1)[1]
    assert "/run/secrets/svid/yashigani-demo/demo-mcp" in caddy_stanza
    assert ('"%d"' % _MCP_SVID_GID) in caddy_stanza


# ---------------------------------------------------------------------------
# 8. approve_mcp_onboard() — Phase 1c approve-hook interface
# ---------------------------------------------------------------------------


def test_approve_hook_returns_artifact_map():
    """approve_mcp_onboard() is the single entry point Tom calls from the
    approve transaction.  Smoke-test: it returns the same artifact map as
    CodegenEngineShapeC.render()."""
    reset_codegen_registry()
    artifacts = approve_mcp_onboard(
        _base_manifest(),
        runtime="docker",
        dry_run=True,
        caddy_validator=lambda _: 0,
    )
    # Load-bearing Phase 1c artifacts must be present.
    assert "docker/caddy/agents/filesystem-mcp.caddy" in artifacts
    assert "docker/filesystem-compose.override.yml" in artifacts
    assert "helm/yashigani/values-filesystem-networkpolicy.yaml" in artifacts


def test_approve_hook_error_propagates():
    """C10 failure inside approve_mcp_onboard propagates as CodegenError."""
    reset_codegen_registry()
    with pytest.raises(CodegenError) as exc:
        approve_mcp_onboard(
            _base_manifest(),
            runtime="docker",
            dry_run=True,
            caddy_validator=lambda _: 1,  # simulate caddy validate failure
        )
    assert exc.value.code == "C10_caddy_validate_failed"


def test_approve_hook_svid_volume_in_output():
    """approve_mcp_onboard() compose override carries SVID volume + GID — the
    approve transaction can rely on this without inspecting engine internals."""
    reset_codegen_registry()
    artifacts = approve_mcp_onboard(
        _base_manifest(),
        runtime="docker",
        dry_run=True,
        caddy_validator=lambda _: 0,
    )
    compose = artifacts["docker/filesystem-compose.override.yml"]
    vol_name = _mcp_svid_volume_name("acme-corp", "filesystem")
    assert ("%s:" % vol_name) in compose
    caddy_stanza = compose.split("  caddy:", 1)[1]
    assert ('"%d"' % _MCP_SVID_GID) in caddy_stanza
