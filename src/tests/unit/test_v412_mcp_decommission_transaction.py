# Last updated: 2026-07-21T00:00:00+00:00
"""
Unit tests — MCP decommission transaction (FINDING-V412-ONBOARDING-
ROBUSTNESS #4, Tom, 2026-07-21).

No supported admin-API remove/decommission flow existed for a ring_fenced
MCP agent (Ava, testing_runs/yashigani/wt-fix-svid/evidence/
ava-onboarding-e2e-final.md §7 — hand cleanup required; envelope rows stayed
'active' permanently with no API to deactivate them).

Contract under test (mirrors test_v41_mcp_onboard_transaction.py's structure
for the FORWARD transaction):
  * success: envelope decommissioned FIRST (deny-first ordering); registry
    (Redis db/3) entries deleted + egress-grants re-pushed; broker route
    unregistered; per-instance SVID leaf + svid-init staging files removed;
    runtime-relevant codegen artifacts unlinked. Audit event emitted.
  * idempotent: a server_id with no active envelope (never onboarded, or
    already decommissioned) returns already_decommissioned=True and does NOT
    raise — every step is independently safe to repeat.
  * fail-closed ONLY at the security-critical step: envelope_decommission
    failure aborts the whole transaction (McpOnboardError) — because the
    caller cannot even confirm the deny-first step landed.
  * NOT roll-back on downstream (registry/route/svid/artifacts) failures —
    those steps only TIGHTEN the deny posture; a partial failure there is
    recorded in ``steps`` but does not raise, and does not undo the
    envelope decommission.
  * component isolation: every registry_store call and every artifact
    candidate path is keyed on server_id — no other agent is ever touched.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.backoffice.mcp_onboard import (
    McpOnboardError,
    run_decommission_transaction,
)

_TENANT = "default"
_SERVER = "cloud9-demo"
_OTHER_SERVER = "filesystem-mcp"
_INSTANCE = "nhi_deadbeef1234"
_SPIFFE = f"spiffe://yashigani.internal/agents/{_TENANT}/{_SERVER}/{_INSTANCE}"


def _active_record(instance_id=_INSTANCE, spiffe_id=_SPIFFE):
    rec = MagicMock()
    rec.svid_instance_id = instance_id
    rec.svid_spiffe_id = spiffe_id
    return rec


def _svc(record=None, decommission_result: bool = True, decommission_raises=None):
    svc = MagicMock()
    svc.get_active_envelope = AsyncMock(return_value=record)
    if decommission_raises is not None:
        svc.decommission_envelope = AsyncMock(side_effect=decommission_raises)
    else:
        svc.decommission_envelope = AsyncMock(return_value=decommission_result)
    return svc


def _registry_store():
    store = MagicMock()
    store.delete = MagicMock()
    store.delete_grant = MagicMock()
    store.delete_baseline = MagicMock()
    store.delete_egress_grant = MagicMock()
    store.list_all = MagicMock(return_value=[])
    return store


@pytest.fixture()
def dec_env(tmp_path, monkeypatch):
    """Wire env vars so the transaction's file-layer steps (svid leaf,
    svid-init staging, artifacts) land in tmp_path — same wiring pattern as
    test_v41_mcp_onboard_transaction.py's txn_env fixture."""
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    svid_init_root = tmp_path / "svid-init"

    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_AGENTS_DIR", str(agents_dir))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    monkeypatch.setenv("YASHIGANI_SVID_INIT_DIR", str(svid_init_root))
    monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "docker")
    return {
        "artifact_root": artifact_root,
        "agents_dir": agents_dir,
        "svid_init_root": svid_init_root,
    }


def _plant_svid_files(env: dict):
    """Simulate a real onboarded agent's on-disk footprint so the removal
    steps have something real to remove."""
    from yashigani.pki.issuer import IssuerPaths

    paths = IssuerPaths(
        secrets_dir=Path("/unused"),  # not read by agent_cert/agent_key
        manifest_path=Path("/unused"),
        agents_dir=env["agents_dir"],
    )
    cert = paths.agent_cert(_TENANT, _SERVER, _INSTANCE)
    key = paths.agent_key(_TENANT, _SERVER, _INSTANCE)
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text("CERT")
    key.write_text("KEY")

    svid_init_dir = env["svid_init_root"] / _TENANT / _SERVER
    svid_init_dir.mkdir(parents=True, exist_ok=True)
    (svid_init_dir / "client.crt").write_text("CERT")
    (svid_init_dir / "client.key").write_text("KEY")
    (svid_init_dir / "ca.crt").write_text("CA")

    override = env["artifact_root"] / "docker" / f"{_SERVER}-compose.override.yml"
    override.parent.mkdir(parents=True, exist_ok=True)
    override.write_text("services: {}\n")
    return cert, key, svid_init_dir, override


class TestDecommissionTransactionSuccess:
    @pytest.mark.asyncio
    async def test_success_reverses_every_step(self, dec_env):
        cert, key, svid_init_dir, override = _plant_svid_files(dec_env)
        svc = _svc(record=_active_record())
        registry_store = _registry_store()
        audit = MagicMock()

        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ) as unregister:
            with patch("yashigani.mcp._opa_push.push_egress_grants"):
                result = await run_decommission_transaction(
                    tenant_id=_TENANT,
                    server_id=_SERVER,
                    operator_identity="orchid",
                    envelope_service=svc,
                    audit_writer=audit,
                    registry_store=registry_store,
                    container_teardown_mode="keep",
                )

        # Step 1: envelope deactivated FIRST.
        svc.decommission_envelope.assert_awaited_once_with(f"{_TENANT}:{_SERVER}")
        assert result.steps["envelope"] == "decommissioned"
        assert result.already_decommissioned is False

        # Step 2: registry cleaned up, scoped to THIS server only.
        registry_store.delete.assert_called_once_with(_TENANT, _SERVER)
        registry_store.delete_grant.assert_called_once_with(_TENANT, _SERVER)
        registry_store.delete_baseline.assert_called_once_with(_TENANT, _SERVER)
        registry_store.delete_egress_grant.assert_called_once_with(_TENANT, _SERVER)
        assert result.steps["registry"] == "removed"

        # Step 3: broker route unregistered.
        unregister.assert_awaited_once_with(tenant_id=_TENANT, server_id=_SERVER)
        assert result.steps["route"] == "removed"

        # Step 4: SVID leaf + svid-init staging removed from disk.
        assert not cert.exists()
        assert not key.exists()
        assert not (svid_init_dir / "client.crt").exists()
        assert not (svid_init_dir / "client.key").exists()
        assert not (svid_init_dir / "ca.crt").exists()
        assert result.steps["svid"] == "removed"

        # Step 5: compose override artifact removed.
        assert not override.exists()
        assert f"docker/{_SERVER}-compose.override.yml" in result.artifact_paths_removed
        assert result.steps["artifacts"] == "removed_1"

        # Identity + audit surfaced.
        assert result.instance_id == _INSTANCE
        assert result.spiffe_id == _SPIFFE
        audit_events = [c.args[0] for c in audit.write.call_args_list]
        assert any(
            getattr(e, "event_type", "") == "MCP_DECOMMISSIONED" for e in audit_events
        )

        # Container-teardown guidance present but NOTHING executed — no
        # docker/podman socket access from backoffice (LAURA-30-001).
        assert result.container_teardown["mode"] == "keep"
        assert _SERVER in result.container_teardown["commands"][0]
        assert _OTHER_SERVER not in str(result.container_teardown)

    @pytest.mark.asyncio
    async def test_nuke_mode_includes_volume_removal_commands(self, dec_env):
        svc = _svc(record=None)  # no active row — envelope step is a no-op
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            result = await run_decommission_transaction(
                tenant_id=_TENANT,
                server_id=_SERVER,
                operator_identity="orchid",
                envelope_service=svc,
                registry_store=None,
                container_teardown_mode="nuke",
            )
        joined = " ".join(result.container_teardown["commands"])
        assert "--volumes" in joined or "network rm" in joined


class TestDecommissionTransactionIdempotent:
    @pytest.mark.asyncio
    async def test_never_onboarded_server_id_is_idempotent_not_an_error(self, dec_env):
        svc = _svc(record=None)  # no active envelope ever existed
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ) as unregister:
            result = await run_decommission_transaction(
                tenant_id=_TENANT,
                server_id="never-onboarded",
                operator_identity="orchid",
                envelope_service=svc,
                registry_store=None,
            )
        assert result.already_decommissioned is True
        assert result.steps["envelope"] == "already_inactive"
        assert result.steps["svid"] == "skipped_no_instance"
        assert result.instance_id == ""
        # Route unregister is still attempted (idempotent/harmless if the
        # broker never had this route) — no exception either way.
        unregister.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_repeat_call_after_success_is_also_idempotent(self, dec_env):
        """First call decommissions a real active row; a SECOND call against
        the same server_id (envelope now inactive) must not raise or
        re-remove anything that's already gone."""
        svc_first = _svc(record=_active_record())
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            first = await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc_first,
                registry_store=None,
            )
        assert first.already_decommissioned is False

        svc_second = _svc(record=None)  # now inactive
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            second = await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc_second,
                registry_store=None,
            )
        assert second.already_decommissioned is True


class TestDecommissionTransactionFailClosed:
    @pytest.mark.asyncio
    async def test_envelope_decommission_failure_aborts_transaction(self, dec_env):
        svc = _svc(record=_active_record(), decommission_raises=RuntimeError("db down"))
        audit = MagicMock()
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ) as unregister:
            with pytest.raises(McpOnboardError) as exc_info:
                await run_decommission_transaction(
                    tenant_id=_TENANT, server_id=_SERVER,
                    operator_identity="orchid", envelope_service=svc,
                    audit_writer=audit, registry_store=_registry_store(),
                )
        assert exc_info.value.step == "envelope_decommission"
        # Nothing downstream attempted — the one load-bearing step failed.
        unregister.assert_not_awaited()
        events = [c.args[0] for c in audit.write.call_args_list]
        assert any(
            getattr(e, "failed_step", "") == "envelope_decommission" for e in events
        )

    @pytest.mark.asyncio
    async def test_registry_failure_does_not_abort_remaining_steps(self, dec_env):
        """A downstream (non-security-critical) failure is recorded but does
        NOT prevent the route/svid/artifact steps from still running — every
        one of those steps only tightens the deny posture."""
        cert, key, svid_init_dir, override = _plant_svid_files(dec_env)
        svc = _svc(record=_active_record())
        registry_store = _registry_store()
        registry_store.delete.side_effect = RuntimeError("redis down")

        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ) as unregister:
            result = await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc,
                registry_store=registry_store,
            )

        assert result.steps["envelope"] == "decommissioned"
        assert result.steps["registry"].startswith("error:")
        # Downstream steps still ran despite the registry failure.
        unregister.assert_awaited_once()
        assert not cert.exists()
        assert result.steps["svid"] == "removed"
        assert not override.exists()


class TestDecommissionReleasesCodegenDedup:
    """FINDING N2 (v4.1.2 finalized onboarding e2e, Ava, 2026-07-21):
    decommission left the in-process codegen C3 duplicate-agent registry
    populated, so re-onboarding the SAME server_id failed C3_duplicate_agent
    until backoffice restarted. run_decommission_transaction must release the
    (tenant_id, server_id) entry symmetrically with where onboarding adds it
    (codegen._assert_unique_agent_pair)."""

    @pytest.fixture(autouse=True)
    def _clean_codegen_registry(self):
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        yield
        reset_codegen_registry()

    @pytest.mark.asyncio
    async def test_decommission_releases_registered_pair(self, dec_env):
        from yashigani.manifest.codegen import _SEEN_PAIRS, _assert_unique_agent_pair

        # Simulate onboarding having registered the pair (what
        # approve_mcp_onboard() -> CodegenEngineShapeC.render() does).
        _assert_unique_agent_pair(_TENANT, _SERVER)
        assert (_TENANT, _SERVER) in _SEEN_PAIRS

        svc = _svc(record=_active_record())
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            result = await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc,
                registry_store=None,
            )

        assert result.steps["codegen_dedup"] == "released"
        assert (_TENANT, _SERVER) not in _SEEN_PAIRS

    @pytest.mark.asyncio
    async def test_decommission_when_pair_never_registered_is_idempotent(self, dec_env):
        """Decommissioning a server_id whose codegen pair was never
        registered in THIS process (e.g. onboarded in a prior process
        lifetime) must not raise — the release is a no-op."""
        svc = _svc(record=None)
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            result = await run_decommission_transaction(
                tenant_id=_TENANT, server_id="never-registered-in-codegen",
                operator_identity="orchid", envelope_service=svc,
                registry_store=None,
            )
        assert result.steps["codegen_dedup"] == "not_registered"

    @pytest.mark.asyncio
    async def test_onboard_decommission_reonboard_same_server_id_succeeds(self, dec_env):
        """End-to-end contract: onboard -> decommission -> re-onboard the
        SAME server_id must succeed (no C3_duplicate_agent), all within one
        process (no restart) — this is the exact regression Ava hit live."""
        from yashigani.manifest.codegen import CodegenError, _assert_unique_agent_pair

        # 1) "Onboard" — codegen registers the pair (C3 guard engages).
        _assert_unique_agent_pair(_TENANT, _SERVER)

        # A duplicate onboard attempt (without decommission) is still
        # correctly rejected — the C3 guard itself is not weakened.
        with pytest.raises(CodegenError, match="C3_duplicate_agent"):
            _assert_unique_agent_pair(_TENANT, _SERVER)

        # 2) Decommission — must release the dedup entry as one of its steps.
        svc = _svc(record=_active_record())
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ):
            result = await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc,
                registry_store=None,
            )
        assert result.steps["codegen_dedup"] == "released"

        # 3) Re-onboard the SAME server_id — must succeed now (FINDING N2).
        _assert_unique_agent_pair(_TENANT, _SERVER)  # no raise


class TestDecommissionComponentIsolation:
    @pytest.mark.asyncio
    async def test_only_named_server_touched_never_another_agent(self, dec_env):
        svc = _svc(record=_active_record())
        registry_store = _registry_store()
        with patch(
            "yashigani.backoffice.mcp_onboard.unregister_mcp_route",
            new=AsyncMock(),
        ) as unregister:
            await run_decommission_transaction(
                tenant_id=_TENANT, server_id=_SERVER,
                operator_identity="orchid", envelope_service=svc,
                registry_store=registry_store,
            )
        for call in (
            registry_store.delete, registry_store.delete_grant,
            registry_store.delete_baseline, registry_store.delete_egress_grant,
        ):
            call.assert_called_once_with(_TENANT, _SERVER)
            assert _OTHER_SERVER not in call.call_args.args
        unregister.assert_awaited_once_with(tenant_id=_TENANT, server_id=_SERVER)
