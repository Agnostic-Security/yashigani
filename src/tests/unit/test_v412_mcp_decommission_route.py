# Last updated: 2026-07-21T00:00:00+00:00
"""
Route-level unit tests — DELETE /admin/mcp/servers/{server_id} (FINDING-
V412-ONBOARDING-ROBUSTNESS #4).

Mounts only mcp_servers.router with auth bypassed via dependency_overrides
(same pattern as test_v2255_admin_ui_crud.py's accounts-route tests) — no
running stack required. Exercises the HTTP contract (status codes, request/
response shape, step-up gating, mode validation) around the already-unit-
tested run_decommission_transaction (see
test_v412_mcp_decommission_transaction.py for the transaction-internals
coverage).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient


def _mcp_servers_app():
    from yashigani.backoffice.routes import mcp_servers as mcp_servers_routes
    from yashigani.backoffice.middleware import require_stepup_admin_session
    from yashigani.backoffice.state import backoffice_state

    backoffice_state.audit_writer = MagicMock()

    sess = SimpleNamespace(account_id="admin1", account_tier="admin")
    app = FastAPI()
    app.dependency_overrides[require_stepup_admin_session] = lambda: sess
    app.include_router(mcp_servers_routes.router, prefix="/admin/mcp/servers")
    return app


def _call(app, method: str, path: str, **kw):
    async def go():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            return await c.request(method, path, **kw)
    return asyncio.run(go())


class TestDecommissionRoute:
    def test_delete_success_returns_reversal_summary(self):
        app = _mcp_servers_app()

        fake_result = SimpleNamespace(
            server_id="cloud9-demo",
            tenant_id="default",
            already_decommissioned=False,
            instance_id="nhi_deadbeef1234",
            spiffe_id="spiffe://yashigani.internal/agents/default/cloud9-demo/nhi_deadbeef1234",
            artifact_paths_removed=["docker/cloud9-demo-compose.override.yml"],
            steps={"envelope": "decommissioned", "registry": "removed",
                   "route": "removed", "svid": "removed", "artifacts": "removed_1"},
            container_teardown={"runtime": "docker", "mode": "keep", "commands": []},
        )

        with patch(
            "yashigani.backoffice.mcp_onboard.run_decommission_transaction",
            new=AsyncMock(return_value=fake_result),
        ) as run_txn:
            with patch(
                "yashigani.backoffice.routes.mcp_servers._envelope_service",
                return_value=MagicMock(),
            ):
                with patch(
                    "yashigani.backoffice.routes.mcp_servers._durable_registry_store",
                    return_value=None,
                ):
                    r = _call(app, "DELETE", "/admin/mcp/servers/cloud9-demo")

        assert r.status_code == 200, r.text
        body = r.json()
        assert body["server_id"] == "cloud9-demo"
        assert body["already_decommissioned"] is False
        assert body["steps"]["envelope"] == "decommissioned"
        assert body["svid"]["instance_id"] == "nhi_deadbeef1234"
        assert "artifacts_removed" in body
        assert "container_teardown" in body

        # The route passed the caller's identity + step-up account through.
        kwargs = run_txn.call_args.kwargs
        assert kwargs["server_id"] == "cloud9-demo"
        assert kwargs["operator_identity"] == "admin1"
        assert kwargs["container_teardown_mode"] == "keep"  # default

    def test_delete_idempotent_never_onboarded_returns_200_not_404(self):
        app = _mcp_servers_app()
        fake_result = SimpleNamespace(
            server_id="ghost-mcp", tenant_id="default",
            already_decommissioned=True, instance_id="", spiffe_id="",
            artifact_paths_removed=[],
            steps={"envelope": "already_inactive", "registry": "skipped_no_store",
                   "route": "removed", "svid": "skipped_no_instance",
                   "artifacts": "removed_0"},
            container_teardown={"runtime": "docker", "mode": "keep", "commands": []},
        )
        with patch(
            "yashigani.backoffice.mcp_onboard.run_decommission_transaction",
            new=AsyncMock(return_value=fake_result),
        ):
            with patch(
                "yashigani.backoffice.routes.mcp_servers._envelope_service",
                return_value=MagicMock(),
            ):
                with patch(
                    "yashigani.backoffice.routes.mcp_servers._durable_registry_store",
                    return_value=None,
                ):
                    r = _call(app, "DELETE", "/admin/mcp/servers/ghost-mcp")
        assert r.status_code == 200, r.text
        assert r.json()["already_decommissioned"] is True

    def test_delete_invalid_mode_rejected_422(self):
        app = _mcp_servers_app()
        with patch(
            "yashigani.backoffice.routes.mcp_servers._envelope_service",
            return_value=MagicMock(),
        ):
            r = _call(
                app, "DELETE", "/admin/mcp/servers/cloud9-demo",
                params={"mode": "delete-everything-please"},
            )
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_mode"

    def test_delete_nuke_mode_passed_through(self):
        app = _mcp_servers_app()
        fake_result = SimpleNamespace(
            server_id="cloud9-demo", tenant_id="default",
            already_decommissioned=False, instance_id="i", spiffe_id="s",
            artifact_paths_removed=[],
            steps={}, container_teardown={"mode": "nuke", "commands": []},
        )
        with patch(
            "yashigani.backoffice.mcp_onboard.run_decommission_transaction",
            new=AsyncMock(return_value=fake_result),
        ) as run_txn:
            with patch(
                "yashigani.backoffice.routes.mcp_servers._envelope_service",
                return_value=MagicMock(),
            ):
                with patch(
                    "yashigani.backoffice.routes.mcp_servers._durable_registry_store",
                    return_value=None,
                ):
                    r = _call(
                        app, "DELETE", "/admin/mcp/servers/cloud9-demo",
                        params={"mode": "nuke"},
                    )
        assert r.status_code == 200, r.text
        assert run_txn.call_args.kwargs["container_teardown_mode"] == "nuke"

    def test_delete_transaction_failure_surfaces_step_and_status(self):
        from yashigani.backoffice.mcp_onboard import McpOnboardError

        app = _mcp_servers_app()
        with patch(
            "yashigani.backoffice.mcp_onboard.run_decommission_transaction",
            new=AsyncMock(
                side_effect=McpOnboardError(
                    "envelope_decommission", "db down", http_status=503,
                )
            ),
        ):
            with patch(
                "yashigani.backoffice.routes.mcp_servers._envelope_service",
                return_value=MagicMock(),
            ):
                with patch(
                    "yashigani.backoffice.routes.mcp_servers._durable_registry_store",
                    return_value=None,
                ):
                    r = _call(app, "DELETE", "/admin/mcp/servers/cloud9-demo")
        assert r.status_code == 503
        assert r.json()["detail"]["failed_step"] == "envelope_decommission"

    def test_delete_requires_step_up_session(self):
        """No dependency override for require_stepup_admin_session -> the
        real dependency runs against a request carrying no session cookie
        and rejects it before the route body runs (mirrors POST /import's
        own step-up gate)."""
        from yashigani.backoffice.routes import mcp_servers as mcp_servers_routes
        from yashigani.backoffice.state import backoffice_state

        backoffice_state.audit_writer = MagicMock()
        backoffice_state.session_store = MagicMock()
        app = FastAPI()
        app.include_router(mcp_servers_routes.router, prefix="/admin/mcp/servers")
        r = _call(app, "DELETE", "/admin/mcp/servers/cloud9-demo")
        assert r.status_code in (401, 403, 422)
