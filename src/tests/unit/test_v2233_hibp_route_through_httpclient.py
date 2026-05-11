"""
Regression test — v2.23.3 micro-PR 3.

Gap: auth/password.py check_hibp() called httpx.get(_HIBP_API_URL + prefix)
directly, bypassing the centralised SSRF-guarded HttpClient. While the URL is
hardcoded (no immediate SSRF risk), defence-in-depth requires all outbound
HTTP to flow through the policy gate so future changes to _HIBP_API_URL are
automatically enforced.

Fix: route through HttpClient._check_policy() before issuing the request.
A singleton _HIBP_HTTP_CLIENT is initialised with allowlist=["api.pwnedpasswords.com"]
and allow_http=False (HTTPS-only). The policy check is applied once in
check_hibp() before the outbound call; _check_hibp_urllib() is the urllib
fallback and is only invoked after the policy gate passes.

Closes: yashigani-retro#95 (partial — OWASP A10 / API7 SSRF)

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_SRC = Path(__file__).parent.parent.parent / "yashigani"
_PASSWORD_SRC = _SRC / "auth" / "password.py"


# ---------------------------------------------------------------------------
# AST structural tests
# ---------------------------------------------------------------------------

class TestHibpHttpClientAST:
    """Verify the SSRF guard is present in the source."""

    def _src(self) -> str:
        return _PASSWORD_SRC.read_text(encoding="utf-8")

    def test_hibp_http_client_module_variable_exists(self):
        """_HIBP_HTTP_CLIENT module-level variable must be declared."""
        src = self._src()
        assert "_HIBP_HTTP_CLIENT" in src, (
            "_HIBP_HTTP_CLIENT sentinel variable not found in password.py"
        )

    def test_hibp_http_client_factory_function_exists(self):
        """_hibp_http_client() factory function must be defined."""
        tree = ast.parse(self._src())
        fn_names = {
            node.name for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert "_hibp_http_client" in fn_names, (
            "_hibp_http_client() factory not found in password.py"
        )

    def test_hibp_allowlist_set_to_pwnedpasswords(self):
        """HttpClient must be initialised with api.pwnedpasswords.com in the allowlist."""
        src = self._src()
        assert "api.pwnedpasswords.com" in src, (
            "api.pwnedpasswords.com not in password.py — allowlist not configured"
        )

    def test_check_hibp_calls_check_policy(self):
        """check_hibp() must call _check_policy() before the outbound request."""
        tree = ast.parse(self._src())
        check_hibp_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "check_hibp":
                check_hibp_fn = node
                break
        assert check_hibp_fn is not None, "check_hibp() not found"
        fn_src = ast.unparse(check_hibp_fn)
        assert "_check_policy" in fn_src, (
            "check_hibp() does not call _check_policy() — SSRF gate not applied"
        )

    def test_check_hibp_handles_blocked_by_policy(self):
        """check_hibp() must catch BlockedByPolicy and return None (fail-open)."""
        tree = ast.parse(self._src())
        check_hibp_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "check_hibp":
                check_hibp_fn = node
                break
        assert check_hibp_fn is not None
        fn_src = ast.unparse(check_hibp_fn)
        assert "BlockedByPolicy" in fn_src, (
            "check_hibp() does not catch BlockedByPolicy — "
            "policy block would propagate as unhandled exception"
        )

    def test_allow_http_is_false_in_factory(self):
        """HttpClient must be created with allow_http=False (HTTPS-only for HIBP)."""
        src = self._src()
        assert "allow_http=False" in src, (
            "allow_http=False not set in _hibp_http_client() — "
            "plain HTTP should be rejected for the HIBP endpoint"
        )


# ---------------------------------------------------------------------------
# Unit tests — policy enforcement
# ---------------------------------------------------------------------------

class TestHibpPolicyEnforcement:
    """Verify the SSRF guard rejects policy-violating URLs before any request."""

    def test_https_to_pwnedpasswords_passes_policy(self):
        """The default HIBP URL must pass the HttpClient policy check."""
        from yashigani.auth.password import _hibp_http_client, _HIBP_DEFAULT_API_URL
        client = _hibp_http_client()
        # Should not raise
        client._check_policy(f"{_HIBP_DEFAULT_API_URL}ABCDE")

    def test_http_scheme_rejected_by_policy(self):
        """Plain HTTP must be rejected — HIBP allowlist is HTTPS-only."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import BlockedByPolicy
        client = _hibp_http_client()
        with pytest.raises(BlockedByPolicy):
            client._check_policy("http://api.pwnedpasswords.com/range/ABCDE")

    def test_non_allowlisted_host_rejected(self):
        """A host not in the HIBP allowlist must be rejected."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import BlockedByPolicy
        client = _hibp_http_client()
        with pytest.raises(BlockedByPolicy, match="not in YASHIGANI_OUTBOUND_ALLOWLIST"):
            client._check_policy("https://evil.example.com/range/ABCDE")

    def test_imds_host_rejected(self):
        """Cloud metadata endpoint must be hard-blocked regardless of scheme."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import BlockedByPolicy
        client = _hibp_http_client()
        with pytest.raises(BlockedByPolicy):
            client._check_policy("https://169.254.169.254/latest/meta-data")

    def test_loopback_rejected(self):
        """Loopback address must be hard-blocked."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import BlockedByPolicy
        client = _hibp_http_client()
        with pytest.raises(BlockedByPolicy):
            client._check_policy("https://127.0.0.1/range/ABCDE")

    def test_file_scheme_rejected(self):
        """file:// scheme must be blocked — not in http/https set."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import BlockedByPolicy
        client = _hibp_http_client()
        with pytest.raises(BlockedByPolicy, match="Scheme"):
            client._check_policy("file:///etc/passwd")


# ---------------------------------------------------------------------------
# Behavioural tests — check_hibp return value when policy blocks
# ---------------------------------------------------------------------------

class TestCheckHibpPolicyBlock:
    """When the SSRF guard rejects the URL, check_hibp must return None (fail-open)."""

    def test_check_hibp_returns_none_when_policy_blocks(self, monkeypatch):
        """
        If the policy gate raises BlockedByPolicy, check_hibp must return None
        (not re-raise). Fail-open on policy block prevents HIBP from becoming
        a hard dependency that breaks password changes.
        """
        from yashigani.net import BlockedByPolicy

        # Patch _hibp_http_client() to return a client whose _check_policy raises
        mock_client = MagicMock()
        mock_client._check_policy.side_effect = BlockedByPolicy("blocked-test")

        import yashigani.auth.password as _pw_mod
        monkeypatch.setattr(_pw_mod, "_HIBP_HTTP_CLIENT", mock_client)

        from yashigani.auth.password import check_hibp
        result = check_hibp("A" * 36)
        assert result is None, (
            f"check_hibp must return None when policy blocks; got {result!r}"
        )

    def test_check_hibp_returns_none_when_api_unreachable(self, monkeypatch):
        """
        Existing fail-open: network error → return None. Must still work
        after the refactor (policy check passes, network call fails).
        """
        from yashigani.net import BlockedByPolicy

        # Policy passes (no BlockedByPolicy raised)
        mock_client = MagicMock()
        mock_client._check_policy.return_value = None

        import yashigani.auth.password as _pw_mod
        monkeypatch.setattr(_pw_mod, "_HIBP_HTTP_CLIENT", mock_client)

        # Patch httpx.get to raise a connection error
        with patch("httpx.get", side_effect=OSError("connection refused")):
            from yashigani.auth.password import check_hibp
            result = check_hibp("A" * 36)
        assert result is None

    def test_check_hibp_found_breach_returns_count(self, monkeypatch):
        """
        When the API responds with a matching suffix, check_hibp returns
        the breach count (positive int). Policy gate passes; mock httpx response.
        """
        import hashlib
        password = "A" * 36
        sha1 = hashlib.sha1(
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest().upper()
        suffix = sha1[5:]

        mock_client = MagicMock()
        mock_client._check_policy.return_value = None

        import yashigani.auth.password as _pw_mod
        monkeypatch.setattr(_pw_mod, "_HIBP_HTTP_CLIENT", mock_client)

        # Fake API response: suffix with count 42
        mock_response = MagicMock()
        mock_response.text = f"{suffix}:42\nOTHER0:1\n"
        mock_response.raise_for_status.return_value = None

        with patch("httpx.get", return_value=mock_response):
            from yashigani.auth.password import check_hibp
            result = check_hibp(password)

        assert result == 42, f"Expected breach count 42, got {result!r}"

    def test_check_hibp_no_match_returns_none(self, monkeypatch):
        """
        When the API responds but the suffix is not in the response body,
        check_hibp returns None (password is clean).
        """
        mock_client = MagicMock()
        mock_client._check_policy.return_value = None

        import yashigani.auth.password as _pw_mod
        monkeypatch.setattr(_pw_mod, "_HIBP_HTTP_CLIENT", mock_client)

        mock_response = MagicMock()
        mock_response.text = "00000:1\n11111:2\n"
        mock_response.raise_for_status.return_value = None

        with patch("httpx.get", return_value=mock_response):
            from yashigani.auth.password import check_hibp
            result = check_hibp("A" * 36)

        assert result is None


# ---------------------------------------------------------------------------
# Singleton / factory tests
# ---------------------------------------------------------------------------

class TestHibpHttpClientSingleton:
    """_hibp_http_client() must return the same instance on repeated calls."""

    def test_singleton_returns_same_instance(self):
        """Two calls to _hibp_http_client() must return the same object."""
        import yashigani.auth.password as _pw_mod
        # Reset singleton to ensure consistent state
        _pw_mod._HIBP_HTTP_CLIENT = None
        from yashigani.auth.password import _hibp_http_client
        c1 = _hibp_http_client()
        c2 = _hibp_http_client()
        assert c1 is c2, "Expected singleton — _hibp_http_client() returned two different instances"

    def test_singleton_is_httpclient_instance(self):
        """The returned object must be a yashigani.net.HttpClient instance."""
        from yashigani.auth.password import _hibp_http_client
        from yashigani.net import HttpClient
        client = _hibp_http_client()
        assert isinstance(client, HttpClient), (
            f"Expected HttpClient instance, got {type(client).__name__}"
        )

    def test_singleton_has_correct_allowlist(self):
        """The HttpClient allowlist must include api.pwnedpasswords.com."""
        from yashigani.auth.password import _hibp_http_client
        client = _hibp_http_client()
        assert "api.pwnedpasswords.com" in client.allowlist, (
            f"Expected api.pwnedpasswords.com in allowlist, got {client.allowlist!r}"
        )

    def test_singleton_disallows_plain_http(self):
        """The HttpClient must not allow plain HTTP."""
        from yashigani.auth.password import _hibp_http_client
        client = _hibp_http_client()
        assert client.allow_http is False, (
            f"Expected allow_http=False, got {client.allow_http!r}"
        )
