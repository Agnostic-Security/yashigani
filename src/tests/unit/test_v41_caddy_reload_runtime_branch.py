# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — caddy reload transport selection (v4.1 SU-SEAM-1d-04).

Su flagged (ebe5f141): the approve transaction reloaded Caddy ONLY via the
unix admin socket shared caddy↔backoffice.  That works on single-host compose
(docker / podman-*) but NOT on K8s, where caddy and backoffice are separate
pods — a unix socket cannot span pods.  Fix: default_caddy_reloader()
branches on YASHIGANI_CONTAINER_RUNTIME:

  docker / podman-rootful / podman-rootless → _reload_via_admin_socket
      (unchanged compose transport — shared /run/caddy/admin.sock)
  k8s                                       → _reload_via_admin_api
      (Caddy's mesh-mTLS admin relay :2019, mcp_onboard._DEFAULT_ADMIN_API_URL;
       client = yashigani.pki.client.internal_httpx_client — the backoffice
       ServiceIdentity leaf + internal-CA trust)

Contract under test:
  * runtime dispatch — socket-on-compose / admin-API-on-k8s, invalid runtime
    fails CLOSED (503) before any transport work.
  * K8s path is mesh-gated fail-CLOSED:
      - default URL is the dedicated ClusterIP Service
        https://yashigani-caddy-admin:2019 (never the public LB Service);
      - plain-http YASHIGANI_CADDY_ADMIN_URL is REFUSED (mTLS only);
      - a missing mesh ServiceIdentity raises — there is NO identity-less
        fallback on an admin config-mutation surface;
      - non-2xx /load response raises (transaction rolls back).
  * both transports read the same monolith Caddyfile
    (YASHIGANI_CADDY_CADDYFILE) and fail closed when it is unreadable.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from yashigani.backoffice import mcp_onboard
from yashigani.backoffice.mcp_onboard import (
    _DEFAULT_ADMIN_API_URL,
    McpOnboardError,
    default_caddy_reloader,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class _Recorder:
    """Async callable recording invocations (stand-in for a transport fn)."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _FakeMeshClient:
    """Mimics the httpx.AsyncClient returned by internal_httpx_client()."""

    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.post_calls: list[dict] = []

    async def __aenter__(self) -> "_FakeMeshClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def post(self, url: str, *, content: bytes, headers: dict) -> _FakeResponse:
        self.post_calls.append({"url": url, "content": content, "headers": headers})
        return self._response


@pytest.fixture()
def caddyfile(tmp_path, monkeypatch):
    """A readable monolith Caddyfile + env pointing at it."""
    path = tmp_path / "Caddyfile"
    path.write_text(":443 {\n}\nimport /etc/caddy/agents/*.caddy\n", encoding="utf-8")
    monkeypatch.setenv("YASHIGANI_CADDY_CADDYFILE", str(path))
    return path


# ---------------------------------------------------------------------------
# runtime dispatch — socket-on-compose / admin-API-on-k8s
# ---------------------------------------------------------------------------

class TestRuntimeDispatch:
    @pytest.mark.parametrize(
        "runtime", ["docker", "podman-rootful", "podman-rootless"]
    )
    async def test_compose_runtimes_select_admin_socket(self, runtime, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", runtime)
        socket_fn, api_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_api", api_fn)

        await default_caddy_reloader()

        assert socket_fn.calls == 1
        assert api_fn.calls == 0

    async def test_k8s_runtime_selects_admin_api(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "k8s")
        socket_fn, api_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_api", api_fn)

        await default_caddy_reloader()

        assert api_fn.calls == 1
        assert socket_fn.calls == 0

    async def test_unset_runtime_defaults_to_docker_socket(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_CONTAINER_RUNTIME", raising=False)
        socket_fn, api_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_api", api_fn)

        await default_caddy_reloader()

        assert socket_fn.calls == 1
        assert api_fn.calls == 0

    async def test_invalid_runtime_fails_closed_before_any_transport(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "bare-metal")
        socket_fn, api_fn = _Recorder(), _Recorder()
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_socket", socket_fn)
        monkeypatch.setattr(mcp_onboard, "_reload_via_admin_api", api_fn)

        with pytest.raises(McpOnboardError) as excinfo:
            await default_caddy_reloader()

        assert excinfo.value.step == "config"
        assert excinfo.value.http_status == 503
        assert socket_fn.calls == 0
        assert api_fn.calls == 0


# ---------------------------------------------------------------------------
# K8s admin-API transport — mesh-gated, fail-closed
# ---------------------------------------------------------------------------

class TestK8sAdminApiTransport:
    async def test_default_url_is_dedicated_admin_service_over_https(
        self, caddyfile, monkeypatch
    ):
        """Default target = the ClusterIP-only yashigani-caddy-admin Service.

        NEVER the public yashigani-caddy LoadBalancer Service — the admin
        relay must not ride the external edge.
        """
        assert _DEFAULT_ADMIN_API_URL == "https://yashigani-caddy-admin:2019"

        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)
        fake = _FakeMeshClient(_FakeResponse(200))
        monkeypatch.setattr(
            "yashigani.pki.client.internal_httpx_client",
            lambda **kw: fake,
        )

        await mcp_onboard._reload_via_admin_api()

        assert len(fake.post_calls) == 1
        call = fake.post_calls[0]
        assert call["url"] == "https://yashigani-caddy-admin:2019/load"
        assert call["headers"]["Content-Type"] == "text/caddyfile"
        assert b"import /etc/caddy/agents/*.caddy" in call["content"]

    async def test_plain_http_admin_url_refused(self, caddyfile, monkeypatch):
        """The relay is mesh-mTLS only — an http:// override is a misconfig."""
        monkeypatch.setenv("YASHIGANI_CADDY_ADMIN_URL", "http://yashigani-caddy-admin:2019")
        sentinel = MagicMock(side_effect=AssertionError("must not build a client"))
        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", sentinel)

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_api()

        assert excinfo.value.step == "caddy_reload"
        assert "https" in str(excinfo.value)
        sentinel.assert_not_called()

    async def test_missing_service_identity_fails_closed_no_fallback(
        self, caddyfile, monkeypatch
    ):
        """No identity-less fallback on an admin config-mutation surface."""
        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)

        def _boom(**kw):
            raise RuntimeError("no /run/secrets PKI in this environment")

        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", _boom)

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_api()

        assert excinfo.value.step == "caddy_reload"
        assert "ServiceIdentity" in str(excinfo.value)

    async def test_non_2xx_load_response_raises(self, caddyfile, monkeypatch):
        monkeypatch.delenv("YASHIGANI_CADDY_ADMIN_URL", raising=False)
        fake = _FakeMeshClient(_FakeResponse(400, "adapt error"))
        monkeypatch.setattr(
            "yashigani.pki.client.internal_httpx_client",
            lambda **kw: fake,
        )

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_api()

        assert excinfo.value.step == "caddy_reload"
        assert "400" in str(excinfo.value)

    async def test_unreadable_caddyfile_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_CADDY_CADDYFILE", str(tmp_path / "missing" / "Caddyfile")
        )
        sentinel = MagicMock(side_effect=AssertionError("must not build a client"))
        monkeypatch.setattr("yashigani.pki.client.internal_httpx_client", sentinel)

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_api()

        assert excinfo.value.step == "caddy_reload"
        sentinel.assert_not_called()


# ---------------------------------------------------------------------------
# compose socket transport — unchanged contract
# ---------------------------------------------------------------------------

class TestComposeSocketTransport:
    async def test_unreadable_caddyfile_fails_closed(self, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_CADDY_CADDYFILE", str(tmp_path / "missing" / "Caddyfile")
        )

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_socket()

        assert excinfo.value.step == "caddy_reload"

    async def test_unreachable_socket_fails_closed(self, caddyfile, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_CADDY_ADMIN_SOCKET", str(tmp_path / "no-such.sock")
        )

        with pytest.raises(McpOnboardError) as excinfo:
            await mcp_onboard._reload_via_admin_socket()

        assert excinfo.value.step == "caddy_reload"
        assert "unreachable" in str(excinfo.value)
