# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — MCP approve transaction (v4.1 Phase 1c, Task B).

SYNTHESIS.md Issue-1 step 6: approve is an ATOMIC transaction —
mint per-instance leaf → codegen (approve_mcp_onboard) → artifact write →
caddy reload → durable envelope INSERT (commit point, svid_issued=True).

Contract under test:
  * success: leaf minted with Nico's contract kwargs; artifacts produced
    ({leaf}, wrap snippet, compose override); envelope minted LAST with
    svid_issued=True + instance/spiffe ids; result surfaces artifact map.
  * fail-CLOSED at every step: mint failure → no artifacts, no envelope;
    codegen CodegenError → leaf rolled back; reload failure → leaf +
    artifacts rolled back; envelope failure → leaf + artifacts rolled back +
    best-effort re-reload.  svid_issued is NEVER persisted on failure
    (BUG-A guard) — mint_envelope is not even called before the reload step.
  * config fail-closed: missing YASHIGANI_MCP_ARTIFACT_ROOT → 503, nothing
    executed.
  * mint_envelope guard: svid_issued=True without identity → ValueError.
"""
from __future__ import annotations

import os
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.backoffice.mcp_onboard import (
    McpOnboardError,
    run_approve_transaction,
)

_TENANT = "default"
_SERVER = "cloud9-demo"
_DIGEST = "sha256:" + "ab12" * 16


def _manifest_yaml(name: str = _SERVER, tenant: str = _TENANT) -> str:
    return textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {name}
          tenant_id: {tenant}
          category: mcp_server
          description: demo MCP for transaction tests
          vendor: Agnostic Security
          licence: proprietary
        spec:
          image:
            repository: yashigani/demo-mcp
            tag: "3.0.0"
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
                - {{name: echo, allowed: true, sensitivity_class: PUBLIC}}
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
    env.tools = {"cloud9-demo::echo": MagicMock()}
    return env


class _FakeReloader:
    def __init__(self, fail: bool = False):
        self.calls = 0
        self.fail = fail

    async def __call__(self) -> None:
        self.calls += 1
        if self.fail:
            raise McpOnboardError("caddy_reload", "socket unreachable")


@pytest.fixture()
def txn_env(tmp_path, monkeypatch):
    """Wire env + secrets dir; reset the codegen mesh-port session registry."""
    from yashigani.manifest.codegen import reset_codegen_registry
    reset_codegen_registry()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    # Step 2b (svid_init, f8dac097 / SEAM-1d-06) copies
    # IssuerPaths.intermediate_cert (= secrets_dir / "ca_intermediate.crt")
    # into secrets/svid-init/<tenant>/<server>/ca.crt. On a real install the
    # PKI bootstrap provisions it; the fixture must provide it or the
    # transaction fail-closes at svid_init before any step under test.
    (secrets_dir / "ca_intermediate.crt").write_text("INTERMEDIATE-CA-PEM")
    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    # FINDING-V412-SVID-WRITE-PATH (Captain, 2026-07-21): run_approve_transaction
    # now builds pki_paths with agents_dir=$YASHIGANI_AGENTS_DIR (default
    # /run/secrets-rw/agents — a real container path absent under pytest) and
    # reads $YASHIGANI_SVID_INIT_DIR for the step-2b staging dir (default
    # /run/secrets-rw/svid-init). Point both at tmp_path so the mint/svid-init
    # side effects land where this fixture (and the assertions below, which
    # still expect secrets_dir/"svid-init"/<tenant>/<server>) can see them.
    # Reuse secrets_dir (already created above) rather than a fresh subdir —
    # this suite tests transaction ORCHESTRATION, not agents_dir/secrets_dir
    # path separation (covered by pki/issuer.py unit tests); the mint mock
    # below (_mint_side_effect) writes via paths.agent_cert()/agent_key()
    # directly with no mkdir(parents=True), so the target must pre-exist.
    monkeypatch.setenv("YASHIGANI_AGENTS_DIR", str(secrets_dir))
    monkeypatch.setenv("YASHIGANI_SVID_INIT_DIR", str(secrets_dir / "svid-init"))
    # FINDING-V412-SVID-INIT-KEY-PERM: step 2b chgrps the staged key to
    # $YASHIGANI_SVID_GID (default 2003, the svid-sidecar/Caddy group) — the
    # test process isn't a member of that real GID. Point it at the test
    # process's OWN gid (any process may chgrp a file it owns to its own
    # current gid without needing supplementary group membership).
    monkeypatch.setenv("YASHIGANI_SVID_GID", str(os.getgid()))
    monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "docker")
    monkeypatch.delenv("YSG_REQUIRE_SIGNED_MANIFEST", raising=False)
    monkeypatch.delenv("YSG_REQUIRE_CADDY_VALIDATE", raising=False)
    monkeypatch.delenv("YASHIGANI_ENV", raising=False)
    yield artifact_root, secrets_dir
    reset_codegen_registry()


def _mint_side_effect(secrets_dir: Path):
    """Simulate mint_agent_leaf: write cert+key files, return the SPIFFE."""
    def _mint(paths, tenant_id, agent_name, *, instance_id="", scope_hash="",
              image_digest="", approved_by="", audit_writer=None, **kw):
        cert = paths.agent_cert(tenant_id, agent_name, instance_id)
        key = paths.agent_key(tenant_id, agent_name, instance_id)
        cert.write_text("CERT")
        key.write_text("KEY")
        return f"spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}/{instance_id}"
    return _mint


def _svc(fail: bool = False) -> MagicMock:
    svc = MagicMock()
    if fail:
        svc.mint_envelope = AsyncMock(side_effect=RuntimeError("db down"))
    else:
        svc.mint_envelope = AsyncMock(return_value=77)
    return svc


async def _run(secrets_dir, *, svc=None, reloader=None, manifest=None,
               mint=None, audit_writer=None):
    mint = mint or _mint_side_effect(secrets_dir)
    with patch("yashigani.pki.issuer.mint_agent_leaf", side_effect=mint):
        return await run_approve_transaction(
            manifest_yaml=manifest or _manifest_yaml(),
            server_id=_SERVER,
            tenant_id=_TENANT,
            env=_fake_env(),
            topology="ring_fenced",
            sidecar_scan_verdict={"classifier_status": "not_configured"},
            operator_identity="orchid",
            envelope_service=svc if svc is not None else _svc(),
            audit_writer=audit_writer,
            caddy_reloader=reloader or _FakeReloader(),
        )


def _leaf_files(secrets_dir: Path) -> list[Path]:
    return sorted(secrets_dir.glob("agent_*_client.*"))


class TestApproveTransactionCommit:
    @pytest.mark.asyncio
    async def test_success_produces_leaf_snippet_override_and_commits(self, txn_env):
        artifact_root, secrets_dir = txn_env
        svc = _svc()
        reloader = _FakeReloader()
        result = await _run(secrets_dir, svc=svc, reloader=reloader)

        # Leaf on disk (per-instance filenames).
        leaves = _leaf_files(secrets_dir)
        assert len(leaves) == 2, leaves
        assert result.instance_id in leaves[0].name

        # Step 2b (svid_init, f8dac097): svid-init dir populated with the
        # basenames Captain's sidecar projects (client.crt/client.key/ca.crt).
        svid_init = secrets_dir / "svid-init" / _TENANT / _SERVER
        assert (svid_init / "client.crt").is_file()
        assert (svid_init / "client.key").is_file()
        assert (svid_init / "ca.crt").read_text() == "INTERMEDIATE-CA-PEM"

        # Compose override written under the artifact root.
        # FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21): the wrap
        # snippet ("docker/caddy/agents/<server>-mcp.caddy") is DELIBERATELY
        # NOT written here anymore — codegen no longer authors Caddy
        # content at all; the approve transaction instead REGISTERS the
        # route with caddy-config-broker (the injected `reloader` stub
        # below stands in for that call — see
        # test_v412_caddy_config_broker.py for the broker's own render/
        # self-check coverage of the verify-mcp + X-Caddy-Verified-Secret
        # content this test used to assert directly from codegen's output).
        override = artifact_root / f"docker/{_SERVER}-compose.override.yml"
        assert override.is_file()
        snippet = artifact_root / f"docker/caddy/agents/{_SERVER}-mcp.caddy"
        assert not snippet.exists(), (
            "BUG: codegen wrote the Caddy-front wrap snippet directly — "
            "FINDING-V412-CADDYADMIN-002 requires this to go through "
            "caddy-config-broker's route-registration contract instead."
        )

        # Route registration happened exactly once, and the durable commit
        # carried the real identity with svid_issued=True.
        assert reloader.calls == 1
        kwargs = svc.mint_envelope.call_args.kwargs
        assert kwargs["svid_issued"] is True
        assert kwargs["svid_instance_id"] == result.instance_id
        assert kwargs["svid_spiffe_id"] == result.spiffe_id
        assert result.envelope_id == 77
        assert result.spiffe_id.endswith(f"/{_TENANT}/{_SERVER}/{result.instance_id}")
        assert f"docker/caddy/agents/{_SERVER}-mcp.caddy" not in result.artifact_paths

        # FINDING-V412-ONBOARDING-ROBUSTNESS #5 (Tom, 2026-07-21): the
        # ceremony registers the envelope + route but does NOT start the
        # container (backoffice has no docker socket, LAURA-30-001) — the
        # result must carry actionable, server_id-scoped deploy guidance
        # rather than leaving the operator to guess.
        assert _SERVER in result.deploy_hint["commands"][0]
        assert "compose.override.yml" in result.deploy_hint["commands"][0]

    @pytest.mark.asyncio
    async def test_nico_contract_kwargs_passed_to_mint(self, txn_env):
        _, secrets_dir = txn_env
        captured: dict = {}

        def _mint(paths, tenant_id, agent_name, **kw):
            captured.update(kw, tenant_id=tenant_id, agent_name=agent_name)
            return _mint_side_effect(secrets_dir)(paths, tenant_id, agent_name, **kw)

        await _run(secrets_dir, mint=_mint)
        assert captured["tenant_id"] == _TENANT
        assert captured["agent_name"] == _SERVER
        assert captured["instance_id"].startswith("nhi_")
        assert len(captured["instance_id"]) == 16  # nhi_ + 12 hex
        assert captured["scope_hash"].startswith("sha384:")
        assert captured["image_digest"] == _DIGEST
        assert captured["approved_by"] == "orchid"


class TestDeployHint:
    """FINDING-V412-ONBOARDING-ROBUSTNESS #5 — _agent_container_deploy_hint()
    in isolation (docker vs k8s; component isolation)."""

    def test_docker_hint_scoped_to_server_id(self):
        from yashigani.backoffice.mcp_onboard import _agent_container_deploy_hint
        hint = _agent_container_deploy_hint(
            tenant_id=_TENANT, server_id=_SERVER, runtime="docker",
        )
        assert hint["runtime"] == "docker"
        assert f"{_SERVER}-compose.override.yml" in hint["commands"][0]
        assert "install.sh --onboard" in hint["note"]  # explicitly disambiguated

    def test_k8s_hint_uses_helm(self):
        from yashigani.backoffice.mcp_onboard import _agent_container_deploy_hint
        hint = _agent_container_deploy_hint(
            tenant_id=_TENANT, server_id=_SERVER, runtime="k8s",
        )
        assert hint["runtime"] == "k8s"
        assert "helm" in hint["commands"][0]
        assert _SERVER in hint["commands"][0]


class TestApproveTransactionFailClosed:
    @pytest.mark.asyncio
    async def test_missing_artifact_root_fails_503_before_any_step(self, txn_env, monkeypatch):
        _, secrets_dir = txn_env
        monkeypatch.delenv("YASHIGANI_MCP_ARTIFACT_ROOT")
        svc = _svc()
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc)
        assert exc_info.value.step == "config"
        assert exc_info.value.http_status == 503
        assert not _leaf_files(secrets_dir)
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_manifest_name_mismatch_422(self, txn_env):
        _, secrets_dir = txn_env
        svc = _svc()
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, manifest=_manifest_yaml(name="other"))
        assert exc_info.value.step == "manifest"
        assert exc_info.value.http_status == 422
        assert not _leaf_files(secrets_dir)
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_manifest_tenant_mismatch_422(self, txn_env):
        _, secrets_dir = txn_env
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, manifest=_manifest_yaml(tenant="not-this-install"))
        assert exc_info.value.step == "manifest"

    @pytest.mark.asyncio
    async def test_mint_failure_aborts_with_no_svid_and_no_artifacts(self, txn_env):
        artifact_root, secrets_dir = txn_env
        svc = _svc()
        audit = MagicMock()

        def _boom(*a, **kw):
            raise RuntimeError("issuer down")

        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, mint=_boom, audit_writer=audit)
        assert exc_info.value.step == "mint_leaf"
        # No BUG-A shape: nothing persisted anywhere.
        svc.mint_envelope.assert_not_awaited()
        assert not list(artifact_root.rglob("*.caddy"))
        # Transaction-failure audit event emitted.
        events = [c.args[0] for c in audit.write.call_args_list]
        assert any(e.failed_step == "mint_leaf" for e in events)

    @pytest.mark.asyncio
    async def test_codegen_failure_rolls_back_minted_leaf(self, txn_env):
        artifact_root, secrets_dir = txn_env
        from yashigani.manifest.codegen import CodegenError
        svc = _svc()
        with patch(
            "yashigani.manifest.codegen.approve_mcp_onboard",
            side_effect=CodegenError("SC-NO-SECRETS", "violation"),
        ):
            with pytest.raises(McpOnboardError) as exc_info:
                await _run(secrets_dir, svc=svc)
        assert exc_info.value.step == "codegen"
        assert exc_info.value.http_status == 422
        # The minted leaf was rolled back — no cert/key remain on disk.
        assert not _leaf_files(secrets_dir)
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_reload_failure_rolls_back_leaf_and_artifacts(self, txn_env):
        artifact_root, secrets_dir = txn_env
        svc = _svc()
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, reloader=_FakeReloader(fail=True))
        assert exc_info.value.step == "caddy_reload"
        assert not _leaf_files(secrets_dir)
        assert not list(artifact_root.rglob("*.caddy"))
        assert not list(artifact_root.rglob("*compose.override.yml"))
        # svid-init population (step 2b) rolled back too.
        assert not list((secrets_dir / "svid-init").rglob("client.*"))
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_envelope_failure_rolls_back_everything_and_re_reloads(self, txn_env):
        artifact_root, secrets_dir = txn_env
        svc = _svc(fail=True)
        reloader = _FakeReloader()
        audit = MagicMock()
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, reloader=reloader, audit_writer=audit)
        assert exc_info.value.step == "envelope_mint"
        assert not _leaf_files(secrets_dir)
        assert not list(artifact_root.rglob("*.caddy"))
        # Applied config restored: reload ran twice (apply + rollback re-apply).
        assert reloader.calls == 2
        events = [c.args[0] for c in audit.write.call_args_list]
        assert any(e.failed_step == "envelope_mint" for e in events)


class TestMintEnvelopeSvidGuard:
    @pytest.mark.asyncio
    async def test_svid_issued_without_identity_refused(self):
        """mint_envelope must refuse svid_issued=True with no identity (BUG-A shape)."""
        from yashigani.mcp.envelope_service import CapabilityEnvelopeService
        svc = CapabilityEnvelopeService(pool=MagicMock())
        env = MagicMock()
        with pytest.raises(ValueError, match="svid_issued=True requires"):
            await svc.mint_envelope(
                env, server_id="s", operator_identity="op", svid_issued=True,
            )
