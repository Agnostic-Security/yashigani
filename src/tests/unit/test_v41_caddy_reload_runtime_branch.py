# Last updated: 2026-07-21T00:00:00+00:00 (FINDING-V412-CADDYADMIN-002 rework)
"""
Unit tests — MCP route-registration transport selection (v4.1 SU-SEAM-1d-04,
reworked FINDING-V412-CADDYADMIN-002).

Su flagged (ebe5f141): the approve transaction reloaded Caddy ONLY via the
unix admin socket shared caddy<->backoffice.  That works on single-host
compose (docker / podman-*) but NOT on K8s, where caddy and backoffice are
separate pods — a unix socket cannot span pods.  Fix: register_mcp_route()
branches on YASHIGANI_CONTAINER_RUNTIME:

  docker / podman-rootful / podman-rootless -> _register_route_via_broker_socket
      (dedicated unix socket, NEVER shared with caddy — see
       caddy_broker_route_sock, docker-compose.yml)
  k8s                                       -> _register_route_via_broker_relay
      (Caddy's mesh-mTLS admin relay :2019, now proxying to the
       caddy-config-broker sidecar's /route — mcp_onboard._DEFAULT_BROKER_RELAY_URL;
       client = yashigani.pki.client.internal_httpx_client — the backoffice
       ServiceIdentity leaf + internal-CA trust)

FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21) REWORK: the prior design
(Su 5443f11f) POSTed the ENTIRE monolith Caddyfile as a raw body to a
validating broker. Laura's final re-attack proved that broker FAILED live
under the real no-new-privileges security context (BLOCKER-A: the broker's
own `caddy adapt` EPERM'd — every legitimate reload 502'd) — see
laura-final-reattack.md + docker/caddy/config_broker.py module docstring.
The corrected contract sends narrow, typed DATA (tenant_id, server_id,
mesh_port, shim_port) to caddy-config-broker's POST/DELETE /route — never a
raw Caddyfile body — and the broker renders + writes + reloads itself.

Contract under test:
  * runtime dispatch — socket-on-compose / relay-on-k8s, invalid runtime
    fails CLOSED (503) before any transport work.
  * K8s path is mesh-gated fail-CLOSED:
      - default URL is the dedicated ClusterIP Service
        https://yashigani-caddy-admin:2019 (never the public LB Service);
      - plain-http YASHIGANI_CADDY_ADMIN_URL is REFUSED (mTLS only);
      - a missing mesh ServiceIdentity raises — there is NO identity-less
        fallback on an admin config-mutation surface;
      - non-2xx /route response raises (transaction rolls back).
  * both transports send the SAME four-field JSON DATA payload — never a
    Caddyfile body — and fail closed on transport errors.
  * unregister_mcp_route() (rollback path) mirrors the same dispatch but is
    best-effort (never raises — rollback must not itself abort a rollback).
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from yashigani.backoffice import mcp_onboard
from yashigani.backoffice.mcp_onboard import (
    McpOnboardError,
    _DEFAULT_BROKER_RELAY_URL,
    register_mcp_route,
    unregister_mcp_route,
)

pytestmark = pytest.mark.asyncio

_ROUTE_KWARGS = dict(tenant_id="acme-corp", server_id="filesystem", mesh_port=9611, shim_port=8000)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _Recorder:
    """Async callable recording invocations + kwargs (stand-in for a
    transport fn)."""

    def __init__(self) -> None:
        self.calls = 0
        self.kwargs_seen: list[dict] = []

    async def __call__(self, **kwargs) -> None:
        self.calls += 1
        self.kwargs_seen.append(kwargs)


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _FakeMeshClient:
    """Mimics the httpx.AsyncClient returned by internal_httpx_client()."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.post_calls: list[dict] = []
        self.request_calls: list[dict] = []

    async def __aenter__(self) -> "_FakeMeshClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def post(self, url: str, *, content: bytes, headers: dict) -> _FakeResponse:
        self.post_calls.append({"url": url, "content": content, "headers": headers})
        return self._response

    async def request(self, method: str, url: str, *, content: bytes, headers: dict) -> _FakeResponse:
        self.request_calls.append({
            "method": method, "url": url, "content": content, "headers": headers,
        })
        return self._response


# ---------------------------------------------------------------------------
# runtime dispatch — socket-on-compose / relay-on-k8s
# ---------------------------------------------------------------------------

class TestRuntimeDispatch:
    @pytest.mark.parametrize(
        "runtime", ["docker", "podman-rootful", "podman-rootless"]
    )
    async def test_compose_runtimes_select_broker_socket(self, runtime, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", runtime)
        socket_fn, relay_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_relay", relay_fn)

        await register_mcp_route(**_ROUTE_KWARGS)

        assert socket_fn.calls == 1
        assert relay_fn.calls == 0
        assert socket_fn.kwargs_seen[0] == _ROUTE_KWARGS

    async def test_k8s_runtime_selects_broker_relay(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "k8s")
        socket_fn, relay_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_relay", relay_fn)

        await register_mcp_route(**_ROUTE_KWARGS)

        assert relay_fn.calls == 1
        assert socket_fn.calls == 0
        assert relay_fn.kwargs_seen[0] == _ROUTE_KWARGS

    async def test_unset_runtime_defaults_to_docker_socket(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_CONTAINER_RUNTIME", raising=False)
        socket_fn, relay_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_relay", relay_fn)

        await register_mcp_route(**_ROUTE_KWARGS)

        assert socket_fn.calls == 1
        assert relay_fn.calls == 0

    async def test_invalid_runtime_fails_closed_before_any_transport(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "bare-metal")
        socket_fn, relay_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_register_route_via_broker_relay", relay_fn)

        with pytest.raises(McpOnboardError) as excinfo:
            await register_mcp_route(**_ROUTE_KWARGS)

        assert excinfo.value.step == "config"
        assert excinfo.value.http_status == 503
        assert socket_fn.calls == 0
        assert relay_fn.calls == 0

    async def test_unregister_dispatches_same_as_register(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "k8s")
        socket_fn, relay_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_unregister_route_via_broker_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_unregister_route_via_broker_relay", relay_fn)

        await unregister_mcp_route(tenant_id="acme-corp", server_id="filesystem")

        assert relay_fn.calls == 1
        assert socket_fn.calls == 0


# ---------------------------------------------------------------------------
# K8s route-registration transport — mesh-gated, fail-closed, DATA-only
# ---------------------------------------------------------------------------

class TestK8sBrokerRelayTransport:
    async def test_default_url_is_dedicated_admin_service_over_https(self, monkeypatch):
        """Default target = the ClusterIP-only yashigani-caddy-admin Service.

        NEVER the public yashigani-caddy LoadBalancer Service — the admin
        relay must not ride the external edge.
        """
        assert _DEFAULT_BROKER_RELAY_URL == "https://yashigani-caddy-admin:2019"

        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)
        fake = _FakeMeshClient(_FakeResponse(200))
        monkeypatch.setattr(
            "yashigani.pki.client.internal_httpx_client",
            lambda **kw: fake,
        )

        await mcp_onboard._register_route_via_broker_relay(**_ROUTE_KWARGS)

        assert len(fake.post_calls) == 1
        call = fake.post_calls[0]
        assert call["url"] == "https://yashigani-caddy-admin:2019/route"
        assert call["headers"]["Content-Type"] == "application/json"
        payload = json.loads(call["content"])
        assert payload == {
            "tenant_id": "acme-corp", "server_id": "filesystem",
            "mesh_port": 9611, "shim_port": 8000,
        }

    async def test_plain_http_admin_url_refused(self, monkeypatch):
        """The relay is mesh-mTLS only — an http:// override is a misconfig."""
        monkeypatch.setenv("YASHIGANI_CADDY_ADMIN_URL", "http://yashigani-caddy-admin:2019")
        sentinel = MagicMock(side_effect=AssertionError("must not build a client"))
        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", sentinel)

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._register_route_via_broker_relay(**_ROUTE_KWARGS)

        assert excinfo.value.step == "caddy_reload"
        assert "https" in str(excinfo.value)
        sentinel.assert_not_called()

    async def test_missing_service_identity_fails_closed_no_fallback(self, monkeypatch):
        """No identity-less fallback on a config-mutation surface."""
        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)

        def _boom(**kw):
            raise RuntimeError("no /run/secrets PKI in this environment")

        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", _boom)

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._register_route_via_broker_relay(**_ROUTE_KWARGS)

        assert excinfo.value.step == "caddy_reload"
        assert "ServiceIdentity" in str(excinfo.value)

    async def test_non_2xx_route_response_raises(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)
        fake = _FakeMeshClient(_FakeResponse(422, "rejected by broker"))
        monkeypatch.setattr(
            "yashigani.pki.client.internal_httpx_client",
            lambda **kw: fake,
        )

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._register_route_via_broker_relay(**_ROUTE_KWARGS)

        assert excinfo.value.step == "caddy_reload"
        assert "422" in str(excinfo.value)

    async def test_unregister_sends_delete_with_tenant_and_server_only(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)
        fake = _FakeMeshClient(_FakeResponse(200))
        monkeypatch.setattr(
            "yashigani.pki.client.internal_httpx_client",
            lambda **kw: fake,
        )

        await mcp_onboard._unregister_route_via_broker_relay(
            tenant_id="acme-corp", server_id="filesystem",
        )

        assert len(fake.request_calls) == 1
        call = fake.request_calls[0]
        assert call["method"] == "DELETE"
        assert call["url"] == "https://yashigani-caddy-admin:2019/route"
        assert json.loads(call["content"]) == {
            "tenant_id": "acme-corp", "server_id": "filesystem",
        }

    async def test_unregister_never_raises_on_failure(self, monkeypatch):
        """Rollback is best-effort — a broken mesh identity during rollback
        must be logged, never propagated (would mask the ORIGINAL failure)."""
        def _boom(**kw):
            raise RuntimeError("mesh identity unavailable")

        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", _boom)

        await mcp_onboard._unregister_route_via_broker_relay(
            tenant_id="acme-corp", server_id="filesystem",
        )  # must not raise


# ---------------------------------------------------------------------------
# compose socket transport — dedicated unix socket, DATA-only
# ---------------------------------------------------------------------------

class TestComposeBrokerSocketTransport:
    async def test_unreachable_socket_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_CADDY_BROKER_ROUTE_SOCKET", str(tmp_path / "no-such.sock"),
        )

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._register_route_via_broker_socket(**_ROUTE_KWARGS)

        assert excinfo.value.step == "caddy_reload"
        assert "unreachable" in str(excinfo.value)

    async def test_unregister_via_socket_never_raises_on_failure(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_CADDY_BROKER_ROUTE_SOCKET", str(tmp_path / "no-such.sock"),
        )
        await mcp_onboard._unregister_route_via_broker_socket(
            tenant_id="acme-corp", server_id="filesystem",
        )  # must not raise
