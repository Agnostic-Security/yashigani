# Last updated: 2026-07-20T00:00:00+00:00
"""
Regression tests — RESTART-013 MCP leg, Gap B: the admin MCP-identity import
ceremony (POST /admin/mcp/servers/import, topology=ring_fenced) failing at
``artifact_write`` with 502 (McpOnboardError step="artifact_write").

ROOT CAUSE (confirmed live by Ava's 2026-07-20 byte-proof session, and
reproduced deterministically here without a live stack):
  CodegenEngine.render() / CodegenEngineShapeC.render() (manifest/codegen.py)
  wrote EVERY key in the rendered artifact map to ``output_root`` on
  dry_run=False, regardless of ``runtime``. The artifact map mirrors the FULL
  install-tree layout (docker/, helm/, opa/, tests/, plus loose top-level
  fragments), but a real compose install's output_root
  (YASHIGANI_MCP_ARTIFACT_ROOT=/mnt/install) is deliberately scoped to only
  the docker/ subtree — docker-compose.yml's backoffice volume is
  ``./:/mnt/install/docker:rw`` with the container's root filesystem
  otherwise read_only: true (blast-radius reasons, iris-phase1d-audit §5-B).
  Writing a "helm/..."-keyed artifact under that output_root asks
  Path.mkdir(parents=True) to create a directory under a read-only parent,
  which raises PermissionError (verified directly: mkdir under a chmod 0555
  parent raises errno 13) — NOT a CodegenError, so mcp_onboard.py's generic
  ``except Exception`` catches it and aborts the WHOLE transaction (502
  onboard_transaction_failed / artifact_write) even though the two artifacts
  a compose runtime actually needs (compose override + Caddy-front snippet,
  both "docker/"-prefixed) had already been written successfully moments
  earlier — exactly what Ava observed live for BOTH ``mirror-mcp`` and
  ``cloud9-demo`` (0 baselines pushed for either MCP server in that build).

FIX (manifest/codegen.py — is_artifact_relevant_for_runtime() +  both
render() write loops; backoffice/mcp_onboard.py — artifact_paths computed
from the same predicate): only PERSIST the subset of the artifact map the
target runtime's output_root is actually scoped to receive
("docker/"-prefixed for docker/podman-*, "helm/"-prefixed for k8s). The
full artifact map is still RETURNED (introspection/API-response contract
unchanged) — only the disk-write side effect is now runtime-scoped.

Tests here prove:
  1. The approve transaction (run_approve_transaction, the same code path
     POST /admin/mcp/servers/import hits) SUCCEEDS end-to-end when
     output_root is realistically scoped to a narrow, mostly-read-only
     directory tree — mirroring the actual compose bind-mount constraint,
     not the fully-writable tmp_path the pre-existing unit-test fixture used
     (which is why this bug shipped without a failing unit test).
  2. Runtime-scoped write filtering: docker/-prefixed artifacts persist,
     helm/-prefixed and other cross-runtime/advisory artifacts do not (and
     do NOT abort the transaction by their absence).
  3. The mTLS control this ceremony feeds is UNCHANGED and still holds: an
     MCP server that has NOT been through the import ceremony (or a caller
     that cannot present a Caddy-verified mTLS peer identity) is still
     denied on tools/call — proving the artifact_write fix does not touch,
     weaken, or bypass the identity_verified gate (LU-MCP-A1,
     gateway/mcp_router_runtime.py).
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from yashigani.backoffice.mcp_onboard import run_approve_transaction

_TENANT = "default"
_SERVER = "mirror-mcp"
_DIGEST = "sha256:" + "cd34" * 16


def _manifest_yaml(name: str = _SERVER, tenant: str = _TENANT) -> str:
    return textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {name}
          tenant_id: {tenant}
          category: mcp_server
          description: byte-proof probe MCP server (regression fixture)
          vendor: Agnostic Security (test artefact)
          licence: proprietary
        spec:
          image:
            repository: mirror-mcp
            tag: "test"
            digest: {_DIGEST}
          write_posture: readonly
          subprocess:
            command: ["python3", "server.py"]
            args: []
          network:
            egress_allow: []
          mcp:
            posture: mcp-b
            transport: stdio
            session_mode: persistent
            identity_propagation: gateway-enforced-only
            exposes:
              listen_port: null
              shim_port: 8000
              tools:
                - {{name: mirror, allowed: true, sensitivity_class: PUBLIC}}
          audit:
            sensitivity_ceiling: PUBLIC
          storage:
            mounts: []
            tmpfs:
              - {{path: /tmp, size_limit: 16m}}
          secrets: []
          lifecycle:
            mode: persistent
        """)


def _fake_env() -> MagicMock:
    env = MagicMock()
    env.tools = {f"{_SERVER}::mirror": MagicMock()}
    return env


class _FakeReloader:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1


def _svc() -> MagicMock:
    svc = MagicMock()
    svc.mint_envelope = AsyncMock(return_value=42)
    return svc


def _mint_side_effect(secrets_dir: Path):
    def _mint(paths, tenant_id, agent_name, *, instance_id="", scope_hash="",
              image_digest="", approved_by="", audit_writer=None, **kw):
        cert = paths.agent_cert(tenant_id, agent_name, instance_id)
        key = paths.agent_key(tenant_id, agent_name, instance_id)
        cert.write_text("CERT")
        key.write_text("KEY")
        return f"spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}/{instance_id}"
    return _mint


@pytest.fixture()
def narrow_compose_env(tmp_path, monkeypatch):
    """Reproduce the REAL compose bind-mount constraint: output_root has only
    a writable "docker/" child; everything else under it is read-only —
    mirroring docker-compose.yml's `./:/mnt/install/docker:rw` bind mount on
    an otherwise `read_only: true` backoffice container. The pre-existing
    txn_env fixture (test_v41_mcp_onboard_transaction.py) used a fully
    writable tmp_path everywhere, which is exactly why this bug shipped
    without a failing unit test — this fixture closes that gap.
    """
    from yashigani.manifest.codegen import reset_codegen_registry
    reset_codegen_registry()

    artifact_root = tmp_path / "mnt_install"
    docker_sub = artifact_root / "docker"
    docker_sub.mkdir(parents=True)
    docker_sub.chmod(0o755)
    # Only the docker/ child is writable; the parent (and any OTHER child,
    # e.g. helm/, opa/, tests/, or a loose top-level file) is not — matching
    # the container's read_only rootfs + narrow bind mount.
    artifact_root.chmod(0o555)

    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "ca_intermediate.crt").write_text("INTERMEDIATE-CA-PEM")

    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "docker")
    monkeypatch.delenv("YSG_REQUIRE_SIGNED_MANIFEST", raising=False)
    monkeypatch.delenv("YSG_REQUIRE_CADDY_VALIDATE", raising=False)
    monkeypatch.delenv("YASHIGANI_ENV", raising=False)

    yield artifact_root, secrets_dir

    # Restore write perms before pytest's tmp_path cleanup removes the tree.
    artifact_root.chmod(0o755)
    reset_codegen_registry()


class TestArtifactWriteSurvivesNarrowOutputRoot:
    """Gap B regression: the approve ceremony must not 502 when output_root
    is scoped to a docker/-only writable subtree (the real compose shape)."""

    @pytest.mark.asyncio
    async def test_ceremony_succeeds_under_narrow_output_root(self, narrow_compose_env):
        """This is the exact 502 Ava reproduced live: prior to the fix,
        run_approve_transaction raised McpOnboardError(step="artifact_write")
        the moment codegen tried to write the first non-"docker/"-prefixed
        key (e.g. helm/yashigani/values-mirror-mcp.yaml) under a read-only
        parent. Post-fix it must complete and commit."""
        artifact_root, secrets_dir = narrow_compose_env
        reloader = _FakeReloader()
        svc = _svc()

        with patch("yashigani.pki.issuer.mint_agent_leaf", side_effect=_mint_side_effect(secrets_dir)):
            result = await run_approve_transaction(
                manifest_yaml=_manifest_yaml(),
                server_id=_SERVER,
                tenant_id=_TENANT,
                env=_fake_env(),
                topology="ring_fenced",
                sidecar_scan_verdict={"classifier_status": "not_configured"},
                operator_identity="orchid",
                envelope_service=svc,
                audit_writer=None,
                caddy_reloader=reloader,
            )

        assert result.envelope_id == 42
        assert reloader.calls == 1
        svc.mint_envelope.assert_awaited_once()
        kwargs = svc.mint_envelope.call_args.kwargs
        assert kwargs["svid_issued"] is True

        # The two docker/-prefixed artifacts a compose runtime actually needs
        # ARE on disk (Ava's evidence: these two DID write successfully
        # before the 502 hit on the next, non-docker/ key).
        override = artifact_root / f"docker/{_SERVER}-compose.override.yml"
        snippet = artifact_root / f"docker/caddy/agents/{_SERVER}-mcp.caddy"
        assert override.is_file()
        assert snippet.is_file()
        assert f"docker/{_SERVER}-compose.override.yml" in result.artifact_paths
        assert f"docker/caddy/agents/{_SERVER}-mcp.caddy" in result.artifact_paths

        # The cross-runtime/advisory artifacts were correctly SKIPPED (never
        # attempted under the read-only parent) — not silently swallowed
        # errors, a deliberate no-op per is_artifact_relevant_for_runtime().
        assert not (artifact_root / "helm").exists()
        assert not (artifact_root / "opa").exists()
        assert not (artifact_root / "tests").exists()
        assert not (artifact_root / "service_identities.yaml.fragment").exists()
        # artifact_paths reports only what's actually on disk (evidentiary
        # principle — same discipline as svid_issued=True being cert-backed).
        assert all(p.startswith("docker/") for p in result.artifact_paths)

    @pytest.mark.asyncio
    async def test_k8s_runtime_persists_only_helm_prefixed(self, tmp_path, monkeypatch):
        """Sibling check: on runtime="k8s" only "helm/"-prefixed keys persist
        (docker/-prefixed artifacts are skipped — no docker-compose on K8s)."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()

        artifact_root = tmp_path / "artifacts"
        artifact_root.mkdir()
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        (secrets_dir / "ca_intermediate.crt").write_text("INTERMEDIATE-CA-PEM")

        monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
        monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
        monkeypatch.setenv(
            "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
        )
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "k8s")
        monkeypatch.delenv("YSG_REQUIRE_SIGNED_MANIFEST", raising=False)
        monkeypatch.delenv("YSG_REQUIRE_CADDY_VALIDATE", raising=False)
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)

        reloader = _FakeReloader()
        svc = _svc()
        with patch("yashigani.pki.issuer.mint_agent_leaf", side_effect=_mint_side_effect(secrets_dir)):
            result = await run_approve_transaction(
                manifest_yaml=_manifest_yaml(),
                server_id=_SERVER,
                tenant_id=_TENANT,
                env=_fake_env(),
                topology="ring_fenced",
                sidecar_scan_verdict={"classifier_status": "not_configured"},
                operator_identity="orchid",
                envelope_service=svc,
                audit_writer=None,
                caddy_reloader=reloader,
            )
        reset_codegen_registry()

        assert all(p.startswith("helm/") for p in result.artifact_paths)
        assert not (artifact_root / "docker").exists()
        assert (artifact_root / "helm").exists()


# ---------------------------------------------------------------------------
# The mTLS control this ceremony feeds — LU-MCP-A1 identity_verified — must
# hold unchanged. This exercises the REAL header-derivation code in
# _handle_mcp_call_inner (not a pre-computed ctx), matching Ava's live
# reproduction (POST /mcp/mirror-mcp via the public Caddy edge with bearer +
# identity headers but no verified peer cert -> 403 spiffe_not_verified).
# ---------------------------------------------------------------------------


def _make_jsonrpc_request(method: str, params=None, req_id="1") -> str:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _make_mock_broker_capturing_ctx():
    """A broker whose enforce() inspects the REAL ctx.identity_verified the
    router derived from request headers (not a canned always-allow/deny),
    mimicking what the real OPA mcp.rego `deny_reason := "spiffe_not_verified"`
    rule (policy/mcp.rego) actually keys on (`not _identity_verified`)."""
    from yashigani.mcp._types import BrokerDecision, EgressDecision, OpaDecision

    captured: dict = {}

    async def _enforce(ctx):
        captured["identity_verified"] = ctx.identity_verified
        allow = bool(ctx.identity_verified)
        opa_dec = OpaDecision(
            allow=allow,
            deny_reason="ok" if allow else "spiffe_not_verified",
            redact_args=set(),
            audit_capture=False,
            rate_limit_key=None,
        )
        return BrokerDecision(
            call_id="test-call-id",
            allow=allow,
            deny_reason="ok" if allow else "spiffe_not_verified",
            opa_decision=opa_dec,
            issued_jwt="test-jwt" if allow else None,
        )

    broker = MagicMock()
    broker.enforce = AsyncMock(side_effect=_enforce)
    broker.enforce_result = AsyncMock(return_value=EgressDecision(
        allow=True, deny_reason="ok", policy_id="mcp.response_decision",
        code="MCP_RESULT_OK", user_message="ok", elapsed_ms=1,
    ))
    broker._issuer = MagicMock()
    broker._issuer.issue = MagicMock(return_value="session-jwt-value")
    return broker, captured


def _build_app(registry):
    from yashigani.gateway.mcp_router_runtime import create_mcp_call_router
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(create_mcp_call_router(registry))
    return app


class TestMtlsControlHoldsAfterArtifactWriteFix:
    """LU-MCP-A1 identity_verified must be derived correctly and enforced
    regardless of the Gap-B codegen/mcp_onboard changes (which touch only
    the disk-write side effect of the approve ceremony, never this gate)."""

    def test_caller_without_caddy_verified_secret_denied_403(self):
        """No X-Caddy-Verified-Secret (and therefore no trusted x-spiffe-id)
        -> identity_verified must be False -> 403 MCP_TOOL_CALL_DENIED /
        spiffe_not_verified, EXACTLY Ava's live evidence
        (evidence/mcp_call_user_redact_response.json)."""
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

        broker, captured = _make_mock_broker_capturing_ctx()
        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://mirror-mcp:8000",
            is_filesystem_agent=False,
            tenant_id=_TENANT,
            agent_name=_SERVER,
        )
        reg.register(_SERVER, broker, cfg)
        app = _build_app(reg)
        client = TestClient(app)

        req = _make_jsonrpc_request(
            "tools/call", {"name": "mirror", "arguments": {"path": "/foo"}}, req_id="1",
        )
        # A bearer + identity header alone (no verified Caddy mTLS secret, no
        # x-spiffe-id) — the exact header shape Ava sent through the public
        # edge — must NOT satisfy identity_verified.
        resp = client.post(
            f"/mcp/{_SERVER}",
            content=req,
            headers={
                "Authorization": "Bearer fake-internal-bearer",
                "X-Yashigani-Identity-Id": "idnt_deadbeef0000",
            },
        )

        assert captured["identity_verified"] is False
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "MCP_TOOL_CALL_DENIED"
        assert data["deny_reason"] == "spiffe_not_verified"

    def test_forged_spiffe_header_without_caddy_secret_still_denied(self):
        """A caller cannot self-assert x-spiffe-id without the Caddy HMAC —
        identity_verified requires BOTH (Option C AND-coupling). Proves the
        gate is not a simple presence check on the spiffe header alone."""
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

        broker, captured = _make_mock_broker_capturing_ctx()
        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://mirror-mcp:8000",
            is_filesystem_agent=False,
            tenant_id=_TENANT,
            agent_name=_SERVER,
        )
        reg.register(_SERVER, broker, cfg)
        app = _build_app(reg)
        client = TestClient(app)

        req = _make_jsonrpc_request(
            "tools/call", {"name": "mirror", "arguments": {"path": "/foo"}}, req_id="2",
        )
        resp = client.post(
            f"/mcp/{_SERVER}",
            content=req,
            headers={"x-spiffe-id": "spiffe://yashigani.internal/agents/default/mirror-mcp/forged"},
        )

        assert captured["identity_verified"] is False
        assert resp.status_code == 403
        assert resp.json()["deny_reason"] == "spiffe_not_verified"

    def test_verified_caddy_peer_with_spiffe_header_allowed(self):
        """Positive control: when BOTH the Caddy HMAC secret AND x-spiffe-id
        are present (the shape a real Caddy require_and_verify front produces
        for a properly-imported, ring-fenced-onboarded MCP server —
        RESTART-013's fixed Gap B path), identity_verified is True and the
        call is allowed. Proves the fix didn't also break the legitimate
        path while locking the illegitimate one down."""
        from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig
        import yashigani.auth.caddy_verified as caddy_verified

        broker, captured = _make_mock_broker_capturing_ctx()
        reg = McpBrokerRegistry()
        cfg = McpBrokerServerConfig(
            upstream_url="http://mirror-mcp:8000",
            is_filesystem_agent=False,
            tenant_id=_TENANT,
            agent_name=_SERVER,
        )
        reg.register(_SERVER, broker, cfg)
        app = _build_app(reg)
        client = TestClient(app)

        fake_upstream_response = json.dumps({
            "jsonrpc": "2.0", "id": "3", "result": {"content": "mirrored"},
        })
        from yashigani.mcp._transport_http import McpHttpTransport as RealTransport

        async def fake_aenter(self):
            self.forward = AsyncMock(return_value=fake_upstream_response)
            return self

        with patch.object(caddy_verified, "_caddy_secret", "test-secret-value"), \
             patch.object(RealTransport, "__aenter__", fake_aenter):
            req = _make_jsonrpc_request(
                "tools/call", {"name": "mirror", "arguments": {"path": "/foo"}}, req_id="3",
            )
            resp = client.post(
                f"/mcp/{_SERVER}",
                content=req,
                headers={
                    "x-caddy-verified-secret": "test-secret-value",
                    "x-spiffe-id": "spiffe://yashigani.internal/agents/default/mirror-mcp/nhi_abc123",
                },
            )

        assert captured["identity_verified"] is True
        assert resp.status_code == 200
