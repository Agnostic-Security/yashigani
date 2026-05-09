"""
Regression test — v2.23.3 micro-PR 4 + extend-pr-112-owui-wrap.

Gap: backoffice/routes/agents.py _push_openwebui_model() used a hand-rolled
_assert_safe_owui_url() with an inline SSRF allowlist (scheme check + host
allowlist from YASHIGANI_OWUI_HOSTNAMES) rather than the centralised HttpClient.
The OWUI_API_URL is admin-configured — an insider (TA-3) or a misconfigured
env var could point it at an SSRF-prone target.

Fix: remove _assert_safe_owui_url(); introduce _owui_http_client() — a lazy
singleton HttpClient with allow_http=True (OWUI runs on plain HTTP in the Docker
mesh) and an allowlist driven by YASHIGANI_OWUI_HOSTNAMES. _push_openwebui_model()
calls _owui_http_client()._check_policy(raw_owui_url) before any outbound request.
BlockedByPolicy is caught and re-raised as RuntimeError (non-fatal outer catch).

extend-pr-112-owui-wrap: _push_openwebui_model() is now async and routes all
outbound calls through pinned_resolver instead of urllib.request. The AST walker
for _push_openwebui_model now checks ast.AsyncFunctionDef (was ast.FunctionDef).
The urllib-call assertions are replaced with httpx-call assertions.

Closes: yashigani-retro#95 (partial — OWASP A10 / API7 SSRF)

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).parent.parent.parent / "yashigani"
_AGENTS_SRC = _SRC / "backoffice" / "routes" / "agents.py"


# ---------------------------------------------------------------------------
# AST structural tests
# ---------------------------------------------------------------------------


class TestAgentsOwuiSsrfAST:
    """Verify the hand-rolled _assert_safe_owui_url is removed and replaced."""

    def _src(self) -> str:
        return _AGENTS_SRC.read_text(encoding="utf-8")

    def test_assert_safe_owui_url_removed(self):
        """
        _assert_safe_owui_url() must no longer exist in agents.py.
        It has been replaced by the centralised HttpClient guard.
        """
        src = self._src()
        assert "def _assert_safe_owui_url" not in src, (
            "_assert_safe_owui_url() is still present — it must be removed and replaced by HttpClient._check_policy()"
        )

    def test_owui_http_client_singleton_exists(self):
        """_OWUI_HTTP_CLIENT module-level sentinel must be declared."""
        src = self._src()
        assert "_OWUI_HTTP_CLIENT" in src, "_OWUI_HTTP_CLIENT singleton variable not found in agents.py"

    def test_owui_http_client_factory_function_exists(self):
        """_owui_http_client() factory function must be defined."""
        tree = ast.parse(self._src())
        fn_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        assert "_owui_http_client" in fn_names, "_owui_http_client() factory function not found in agents.py"

    def _find_push_fn(self, tree):
        """Find _push_openwebui_model in AST — handles both sync and async def."""
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_push_openwebui_model":
                return node
        return None

    def test_push_openwebui_model_uses_check_policy(self):
        """_push_openwebui_model() must call _check_policy() before any network call."""
        tree = ast.parse(self._src())
        push_fn = self._find_push_fn(tree)
        assert push_fn is not None, "_push_openwebui_model() not found in agents.py"
        fn_src = ast.unparse(push_fn)
        assert "_check_policy" in fn_src, (
            "_push_openwebui_model() does not call _check_policy() — SSRF gate not applied to OWUI_API_URL"
        )

    def test_push_openwebui_model_no_longer_calls_assert_safe_owui_url(self):
        """_push_openwebui_model() must NOT reference the removed helper."""
        tree = ast.parse(self._src())
        push_fn = self._find_push_fn(tree)
        assert push_fn is not None
        fn_src = ast.unparse(push_fn)
        assert "_assert_safe_owui_url" not in fn_src, (
            "_push_openwebui_model() still calls _assert_safe_owui_url() — refactor not applied"
        )

    def test_push_openwebui_model_handles_blocked_by_policy(self):
        """_push_openwebui_model() must catch BlockedByPolicy."""
        tree = ast.parse(self._src())
        push_fn = self._find_push_fn(tree)
        assert push_fn is not None
        fn_src = ast.unparse(push_fn)
        assert "BlockedByPolicy" in fn_src, (
            "_push_openwebui_model() does not reference BlockedByPolicy — "
            "the policy exception must be caught and converted to RuntimeError"
        )

    def test_owui_http_client_uses_yashigani_owui_hostnames_env(self):
        """The factory must read YASHIGANI_OWUI_HOSTNAMES (same env as before)."""
        src = self._src()
        assert "YASHIGANI_OWUI_HOSTNAMES" in src, (
            "YASHIGANI_OWUI_HOSTNAMES env var not found in agents.py — allowlist not properly configured"
        )

    def test_allow_http_true_in_factory(self):
        """HttpClient must be created with allow_http=True for internal OWUI mesh."""
        src = self._src()
        assert "allow_http=True" in src, (
            "allow_http=True not set in _owui_http_client() — "
            "OWUI runs on plain HTTP inside Docker; this will block all requests"
        )


# ---------------------------------------------------------------------------
# Unit tests — policy enforcement
# ---------------------------------------------------------------------------


class TestOwuiHttpClientPolicyEnforcement:
    """Verify the centralised HttpClient correctly enforces SSRF policy."""

    def _reset_singleton(self):
        """Reset the module singleton for test isolation."""
        import yashigani.backoffice.routes.agents as _ag

        _ag._OWUI_HTTP_CLIENT = None

    def test_default_allowlist_accepts_open_webui(self, monkeypatch):
        """Default allowlist includes 'open-webui' hostname."""
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        client = _owui_http_client()
        # http://open-webui:8080 — open-webui is in the default allowlist
        # No exception should be raised
        client._check_policy("http://open-webui:8080/api/v1/models")

    def test_default_allowlist_accepts_localhost(self, monkeypatch):
        """Default allowlist includes 'localhost'."""
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        client = _owui_http_client()
        client._check_policy("http://localhost:8080/api/v1/models")

    def test_imds_rejected_regardless_of_allowlist(self, monkeypatch):
        """Cloud metadata endpoint must be hard-blocked even if env allows it."""
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "169.254.169.254,open-webui")
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client
        from yashigani.net import BlockedByPolicy

        client = _owui_http_client()
        with pytest.raises(BlockedByPolicy):
            client._check_policy("http://169.254.169.254/latest/meta-data")

    def test_non_allowlisted_host_rejected(self, monkeypatch):
        """A hostname not in YASHIGANI_OWUI_HOSTNAMES must be blocked."""
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui,localhost")
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client
        from yashigani.net import BlockedByPolicy

        client = _owui_http_client()
        with pytest.raises(BlockedByPolicy, match="not in YASHIGANI_OUTBOUND_ALLOWLIST"):
            client._check_policy("http://attacker.example.com/steal")

    def test_file_scheme_rejected(self, monkeypatch):
        """file:// scheme must be blocked outright."""
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client
        from yashigani.net import BlockedByPolicy

        client = _owui_http_client()
        with pytest.raises(BlockedByPolicy, match="Scheme"):
            client._check_policy("file:///etc/passwd")

    def test_gopher_scheme_rejected(self, monkeypatch):
        """gopher:// scheme must be blocked (classic SSRF pivot)."""
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client
        from yashigani.net import BlockedByPolicy

        client = _owui_http_client()
        with pytest.raises(BlockedByPolicy, match="Scheme"):
            client._check_policy("gopher://redis:6379/_FLUSHALL")

    def test_https_also_accepted_when_in_allowlist(self, monkeypatch):
        """HTTPS to an allowlisted host must pass (operators may use HTTPS for OWUI)."""
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui")
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        client = _owui_http_client()
        # Must not raise
        client._check_policy("https://open-webui:8443/api/v1/models")


# ---------------------------------------------------------------------------
# Behavioural tests — _push_openwebui_model blocks on policy violation
# ---------------------------------------------------------------------------


class TestPushOpenWebuiModelSsrfBlock:
    """_push_openwebui_model() must not issue any outbound request when policy blocks."""

    def _reset_singleton(self):
        import yashigani.backoffice.routes.agents as _ag

        _ag._OWUI_HTTP_CLIENT = None

    @pytest.mark.asyncio
    async def test_policy_violation_prevents_network_call(self, monkeypatch):
        """
        When the OWUI_API_URL violates policy, no outbound HTTP call must be made
        (neither urllib nor httpx) — the function must raise before reaching the
        network layer.

        Note: _push_openwebui_model is now async and uses httpx via pinned_resolver
        (extend-pr-112-owui-wrap). The assertion checks httpx calls, not urllib.
        """
        import httpx

        # Point OWUI_API_URL at a hard-blocked address (IMDS).
        monkeypatch.setenv("OWUI_API_URL", "http://169.254.169.254/steal")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "169.254.169.254")
        self._reset_singleton()

        httpx_calls: list[str] = []

        async def _mock_send(self, request, *args, **kwargs):
            httpx_calls.append(str(request.url))
            raise RuntimeError("httpx.send should not be called")

        monkeypatch.setattr(httpx.AsyncClient, "send", _mock_send)

        from yashigani.backoffice.routes.agents import _push_openwebui_model

        # Must not raise (outer try/except catches all failures as non-fatal)
        # and must not call httpx
        await _push_openwebui_model("test-agent", "http://open-webui:8080")

        assert httpx_calls == [], f"httpx made outbound calls despite policy block: {httpx_calls}"

    @pytest.mark.asyncio
    async def test_non_allowlisted_owui_url_is_non_fatal(self, monkeypatch):
        """
        A blocked OWUI_API_URL must not propagate as an exception —
        _push_openwebui_model is fire-and-forget.

        Note: _push_openwebui_model is now async (extend-pr-112-owui-wrap).
        """
        monkeypatch.setenv("OWUI_API_URL", "http://evil.attacker.com/steal")
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "open-webui,localhost")
        self._reset_singleton()

        from yashigani.backoffice.routes.agents import _push_openwebui_model

        # Must not raise
        try:
            await _push_openwebui_model("test-agent", "http://open-webui:8080")
        except Exception as exc:
            pytest.fail(f"_push_openwebui_model raised unexpectedly on blocked URL: {exc!r}")


# ---------------------------------------------------------------------------
# Singleton / factory tests
# ---------------------------------------------------------------------------


class TestOwuiHttpClientSingleton:
    """_owui_http_client() must return the same instance on repeated calls."""

    def _reset_singleton(self):
        import yashigani.backoffice.routes.agents as _ag

        _ag._OWUI_HTTP_CLIENT = None

    def test_singleton_returns_same_instance(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        c1 = _owui_http_client()
        c2 = _owui_http_client()
        assert c1 is c2, "Expected singleton — _owui_http_client() returned different instances"

    def test_singleton_is_httpclient_instance(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client
        from yashigani.net import HttpClient

        client = _owui_http_client()
        assert isinstance(client, HttpClient), f"Expected HttpClient, got {type(client).__name__}"

    def test_singleton_allows_http(self, monkeypatch):
        """allow_http must be True (OWUI uses plain HTTP on internal mesh)."""
        monkeypatch.delenv("YASHIGANI_OWUI_HOSTNAMES", raising=False)
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        client = _owui_http_client()
        assert client.allow_http is True, f"Expected allow_http=True, got {client.allow_http!r}"

    def test_env_driven_allowlist_applied(self, monkeypatch):
        """Custom YASHIGANI_OWUI_HOSTNAMES must be reflected in the allowlist."""
        monkeypatch.setenv("YASHIGANI_OWUI_HOSTNAMES", "custom-owui,my-owui")
        self._reset_singleton()
        from yashigani.backoffice.routes.agents import _owui_http_client

        client = _owui_http_client()
        assert "custom-owui" in client.allowlist, f"custom-owui not in allowlist: {client.allowlist!r}"
        assert "my-owui" in client.allowlist, f"my-owui not in allowlist: {client.allowlist!r}"
