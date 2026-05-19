"""
Regression test — Option C: AND-couple x-spiffe-id with X-Caddy-Verified-Secret.

Covers Laura's ACCEPT-WITH-RESIDUAL condition (2026-05-19 verdict):
    "extend tests/laura/ with a direct-backoffice forge probe asserting that a
    request without a valid X-Caddy-Verified-Secret header AND a forged
    X-SPIFFE-ID is rejected at the middleware layer before reaching
    require_spiffe_id()."

Two forge failure modes tested:
  A. Missing HMAC header entirely → x-spiffe-id stripped in SpiffePeerCertMiddleware
     → require_spiffe_id() returns 401 no_spiffe_id.
  B. Present but INVALID HMAC → x-spiffe-id stripped in SpiffePeerCertMiddleware
     → require_spiffe_id() returns 401 no_spiffe_id.

Positive path also tested:
  C. Valid HMAC + valid x-spiffe-id → header preserved → require_spiffe_id()
     passes (simulates Caddy-proxied path).

All tests are pure unit tests (no live service required).  The ASGI call chain
is exercised directly by instantiating SpiffePeerCertMiddleware with a capture
app and running the middleware loop synchronously with asyncio.run().

Import note: SpiffePeerCertMiddleware lives in
``yashigani.gateway.spiffe_middleware`` but the package ``__init__.py`` imports
``proxy.py`` which raises ``RuntimeError`` if ``YASHIGANI_INTERNAL_BEARER`` is
not set (fail-closed by design).  We import the module directly via
``importlib.util.spec_from_file_location`` to bypass the package barrel export,
matching the approach used in test_v2231_postfix_bypass_regression.py — except
we fix the import cycle that file had by loading directly from the filesystem.

Last updated: 2026-05-19T00:00:00+01:00
"""
from __future__ import annotations

import asyncio
import importlib.util
import sys
import types
from pathlib import Path
import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Direct module loader — bypass gateway/__init__.py barrel
# ---------------------------------------------------------------------------

def _load_spiffe_middleware_module():
    """Load yashigani.gateway.spiffe_middleware without triggering gateway/__init__.py.

    gateway/__init__.py imports proxy.py which calls _load_internal_bearer() at
    module-load time and raises RuntimeError when YASHIGANI_INTERNAL_BEARER is
    absent.  We load the .py file directly to avoid that.
    """
    repo_root = Path(__file__).resolve().parents[4]
    module_path = repo_root / "src" / "yashigani" / "gateway" / "spiffe_middleware.py"
    module_name = "yashigani.gateway.spiffe_middleware"

    if module_name in sys.modules:
        return sys.modules[module_name]

    # Ensure parent package stubs exist so relative imports don't fail
    if "yashigani" not in sys.modules:
        sys.modules["yashigani"] = types.ModuleType("yashigani")
    if "yashigani.gateway" not in sys.modules:
        pkg = types.ModuleType("yashigani.gateway")
        pkg.__path__ = [str(module_path.parent)]
        pkg.__package__ = "yashigani.gateway"
        sys.modules["yashigani.gateway"] = pkg

    spec = importlib.util.spec_from_file_location(module_name, module_path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_SECRET = "a" * 64  # 64-char hex string, matches format from install.sh
_VALID_SPIFFE_ID = b"spiffe://yashigani.internal/caddy"


def _make_scope(headers: list[tuple[bytes, bytes]]) -> dict:
    """Build a minimal ASGI HTTP scope with the given headers."""
    return {
        "type": "http",
        "method": "POST",
        "path": "/admin/agents",
        "query_string": b"",
        "headers": list(headers),
    }


async def _run_middleware(scope: dict) -> dict:
    """Run SpiffePeerCertMiddleware on *scope* and return the modified scope.

    Uses a capture ASGI app that records the scope it receives.
    """
    mod = _load_spiffe_middleware_module()
    SpiffePeerCertMiddleware = mod.SpiffePeerCertMiddleware

    captured: dict = {}

    async def _capture_app(inner_scope, receive, send):
        captured.update(inner_scope)

    middleware = SpiffePeerCertMiddleware(_capture_app)
    await middleware(scope, None, None)
    return captured


def _headers_dict(scope: dict) -> dict[bytes, bytes]:
    """Flatten the scope headers list into a dict (last-wins for duplicates)."""
    return {k.lower(): v for k, v in scope.get("headers", [])}


# ---------------------------------------------------------------------------
# Option C: forge path A — missing HMAC header → x-spiffe-id stripped
# ---------------------------------------------------------------------------


class TestForgeMissingHmac:
    """Failure mode A: direct-backoffice request with forged X-SPIFFE-ID but
    NO X-Caddy-Verified-Secret header.  The middleware must strip x-spiffe-id.
    """

    def test_spiffe_id_stripped_when_hmac_absent(self):
        """
        Option C regression: SpiffePeerCertMiddleware must strip x-spiffe-id when
        X-Caddy-Verified-Secret header is absent.

        Forge shape: attacker on caddy_internal sends:
          X-SPIFFE-ID: spiffe://yashigani.internal/caddy
          (no X-Caddy-Verified-Secret)

        Expected: x-spiffe-id absent from the scope that reaches downstream.
        """
        # Patch _caddy_secret so validate_caddy_secret has a non-None secret.
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
                # No x-caddy-verified-secret header
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" not in headers, (
            "Option C failure: x-spiffe-id must be stripped when "
            "X-Caddy-Verified-Secret is absent — forge path A not blocked"
        )

    def test_peer_cert_header_set_to_empty_when_hmac_absent(self):
        """
        x-spiffe-id-peer-cert must still be injected (empty) even when HMAC absent.
        """
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id-peer-cert" in headers, (
            "x-spiffe-id-peer-cert must always be set by SpiffePeerCertMiddleware"
        )
        assert headers[b"x-spiffe-id-peer-cert"] == b"", (
            "x-spiffe-id-peer-cert must be empty when uvicorn TLS extension absent"
        )


# ---------------------------------------------------------------------------
# Option C: forge path B — invalid HMAC → x-spiffe-id stripped
# ---------------------------------------------------------------------------


class TestForgeInvalidHmac:
    """Failure mode B: direct-backoffice request with forged X-SPIFFE-ID and
    an INVALID X-Caddy-Verified-Secret header.  The middleware must strip x-spiffe-id.
    """

    def test_spiffe_id_stripped_when_hmac_invalid(self):
        """
        Option C regression: SpiffePeerCertMiddleware must strip x-spiffe-id when
        X-Caddy-Verified-Secret is present but does NOT match the installed secret.

        Forge shape: attacker on caddy_internal sends:
          X-SPIFFE-ID: spiffe://yashigani.internal/caddy
          X-Caddy-Verified-Secret: <wrong value>

        Expected: x-spiffe-id absent from the scope that reaches downstream.
        """
        wrong_secret = "b" * 64  # different from _VALID_SECRET
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
                (b"x-caddy-verified-secret", wrong_secret.encode("ascii")),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" not in headers, (
            "Option C failure: x-spiffe-id must be stripped when "
            "X-Caddy-Verified-Secret is invalid — forge path B not blocked"
        )

    def test_spiffe_id_stripped_when_hmac_empty_string(self):
        """
        Option C: empty string X-Caddy-Verified-Secret must NOT preserve x-spiffe-id.
        An attacker who knows the header name but not the value.
        """
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
                (b"x-caddy-verified-secret", b""),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" not in headers, (
            "Option C: empty X-Caddy-Verified-Secret must not preserve x-spiffe-id"
        )

    def test_spiffe_id_stripped_when_caddy_secret_not_loaded(self):
        """
        Option C: if _caddy_secret is None (lifespan not run yet) → fail-closed →
        x-spiffe-id is stripped even when a value is present in the forge header.
        """
        with patch("yashigani.auth.caddy_verified._caddy_secret", None):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
                (b"x-caddy-verified-secret", _VALID_SECRET.encode("ascii")),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" not in headers, (
            "Option C fail-closed: x-spiffe-id must be stripped when "
            "_caddy_secret is None (lifespan not yet run)"
        )


# ---------------------------------------------------------------------------
# Option C: positive path — valid HMAC + valid SPIFFE-ID → header preserved
# ---------------------------------------------------------------------------


class TestLegitCaddyPath:
    """Positive path: requests arriving via Caddy carry a valid HMAC.
    ``x-spiffe-id`` must survive to reach ``require_spiffe_id()``.
    """

    def test_spiffe_id_preserved_when_hmac_valid(self):
        """
        Option C: x-spiffe-id must NOT be stripped when X-Caddy-Verified-Secret
        matches the installed secret.  This is the Caddy-proxied happy path.
        """
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id", _VALID_SPIFFE_ID),
                (b"x-caddy-verified-secret", _VALID_SECRET.encode("ascii")),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" in headers, (
            "Option C: x-spiffe-id must be preserved when "
            "X-Caddy-Verified-Secret is valid (Caddy-proxied path broken)"
        )
        assert headers[b"x-spiffe-id"] == _VALID_SPIFFE_ID, (
            "Option C: x-spiffe-id value must be unchanged when HMAC valid"
        )

    def test_no_spiffe_id_header_present_and_valid_hmac_ok(self):
        """
        A request with valid HMAC but NO x-spiffe-id must not crash the middleware
        and must not inject a spurious x-spiffe-id.
        """
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-caddy-verified-secret", _VALID_SECRET.encode("ascii")),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert b"x-spiffe-id" not in headers, (
            "Middleware must not inject x-spiffe-id when it was not in the request"
        )
        assert b"x-spiffe-id-peer-cert" in headers


# ---------------------------------------------------------------------------
# Option C: client-supplied x-spiffe-id-peer-cert is always stripped
# ---------------------------------------------------------------------------


class TestPeerCertHeaderAlwaysStripped:
    """x-spiffe-id-peer-cert must ALWAYS be stripped and re-set from the TLS
    handshake regardless of HMAC state.  This is the pre-existing guarantee
    from SpiffePeerCertMiddleware; Option C must not regress it.
    """

    def test_client_peer_cert_header_stripped_no_hmac(self):
        """Client-supplied x-spiffe-id-peer-cert is stripped even without HMAC."""
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id-peer-cert", b"spiffe://yashigani.internal/attacker"),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        # Must be present (re-set to empty), not the forged value
        assert headers[b"x-spiffe-id-peer-cert"] == b"", (
            "x-spiffe-id-peer-cert must be overwritten with empty (from TLS handshake)"
        )

    def test_client_peer_cert_header_stripped_with_valid_hmac(self):
        """Client-supplied x-spiffe-id-peer-cert is stripped even with valid HMAC."""
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            scope = _make_scope([
                (b"x-spiffe-id-peer-cert", b"spiffe://yashigani.internal/attacker"),
                (b"x-caddy-verified-secret", _VALID_SECRET.encode("ascii")),
            ])
            result_scope = asyncio.run(_run_middleware(scope))

        headers = _headers_dict(result_scope)
        assert headers[b"x-spiffe-id-peer-cert"] == b"", (
            "x-spiffe-id-peer-cert must be overwritten even when HMAC valid"
        )


# ---------------------------------------------------------------------------
# validate_caddy_secret unit tests (new function in caddy_verified.py)
# ---------------------------------------------------------------------------


class TestValidateCaddySecret:
    """Unit tests for the new validate_caddy_secret() helper."""

    def test_returns_true_on_match(self):
        from yashigani.auth.caddy_verified import validate_caddy_secret
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            assert validate_caddy_secret(_VALID_SECRET) is True

    def test_returns_false_on_mismatch(self):
        from yashigani.auth.caddy_verified import validate_caddy_secret
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            assert validate_caddy_secret("wrong_value") is False

    def test_returns_false_when_secret_none(self):
        from yashigani.auth.caddy_verified import validate_caddy_secret
        with patch("yashigani.auth.caddy_verified._caddy_secret", None):
            assert validate_caddy_secret(_VALID_SECRET) is False

    def test_returns_false_on_empty_header_value(self):
        from yashigani.auth.caddy_verified import validate_caddy_secret
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            assert validate_caddy_secret("") is False

    def test_returns_false_on_non_ascii(self):
        from yashigani.auth.caddy_verified import validate_caddy_secret
        with patch("yashigani.auth.caddy_verified._caddy_secret", _VALID_SECRET):
            # Non-ASCII should be treated as mismatch, not exception
            assert validate_caddy_secret("\xff\xfe") is False

    def test_constant_time_compare(self):
        """validate_caddy_secret must use hmac.compare_digest (constant-time)."""
        import inspect
        from yashigani.auth import caddy_verified
        src = inspect.getsource(caddy_verified.validate_caddy_secret)
        assert "compare_digest" in src, (
            "validate_caddy_secret must use hmac.compare_digest for constant-time comparison"
        )
