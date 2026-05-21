"""
Regression tests for Compliance + Pentest post-fix bypass findings (2026-04-27).

LF-CSV-BYPASS     — V1.2.10 leading-whitespace bypass (added to test_v2231_asvs_fixes.py)
LF-SPIFFE-FORGE   — V10.3.5 peer-cert extraction middleware + openai_router fix
LF-STEPUP-AGENT-CREATE — V6.8.4 coverage gap: agent create/update + sensitivity/models endpoints
LF-SPIFFE-RETAIN  — V8.3.3 bounded retain-on-parse-failure (24h max-stale)
LF-DISABLE-PARTIAL — V8.3.2 identity-registry suspension on disable
LF-XSS-RES       — V1.2.1 residual innerHTML+err.detail sinks (static analysis)

Reference: /Users/max/Documents/Claude/Internal/ACS/v3/asvs-sanity-check-post-fix-2026-04-29.md
"""
# Last updated: 2026-04-27T00:00:00+01:00
from __future__ import annotations

import ast
import os
import re
import time
from pathlib import Path
from threading import Lock
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

SRC = Path(__file__).parent.parent.parent / "yashigani"
ROUTES_DIR = SRC / "backoffice" / "routes"
DASHBOARD_JS = SRC / "backoffice" / "static" / "js" / "dashboard.js"


# ---------------------------------------------------------------------------
# LF-SPIFFE-FORGE — SpiffePeerCertMiddleware + _resolve_identity peer-cert logic
# ---------------------------------------------------------------------------

class TestSpiffePeerCertMiddleware:
    """
    LF-SPIFFE-FORGE regression: the middleware must extract the SPIFFE URI from
    the ASGI TLS extension and inject it as X-SPIFFE-ID-Peer-Cert, overwriting
    any client-supplied value.
    """

    def _import_middleware(self):
        from yashigani.gateway.spiffe_middleware import (
            SpiffePeerCertMiddleware,
            _extract_spiffe_uri_from_cert,
        )
        return SpiffePeerCertMiddleware, _extract_spiffe_uri_from_cert

    def test_extract_spiffe_uri_from_cert_found(self):
        """URI SAN with spiffe:// prefix is returned."""
        _, extract = self._import_middleware()
        cert = {"subjectAltName": [
            ("DNS", "gateway.internal"),
            ("URI", "spiffe://yashigani.internal/agent-prod"),
        ]}
        assert extract(cert) == "spiffe://yashigani.internal/agent-prod"

    def test_extract_spiffe_uri_from_cert_none(self):
        """None cert returns empty string."""
        _, extract = self._import_middleware()
        assert extract(None) == ""

    def test_extract_spiffe_uri_from_cert_no_spiffe(self):
        """URI SAN without spiffe:// prefix is not returned."""
        _, extract = self._import_middleware()
        cert = {"subjectAltName": [("URI", "https://example.com")]}
        assert extract(cert) == ""

    def test_extract_spiffe_uri_from_cert_first_spiffe(self):
        """When multiple URI SANs exist, the first spiffe:// one is returned."""
        _, extract = self._import_middleware()
        cert = {"subjectAltName": [
            ("URI", "https://not-spiffe.com"),
            ("URI", "spiffe://yashigani.internal/svc-a"),
            ("URI", "spiffe://yashigani.internal/svc-b"),
        ]}
        assert extract(cert) == "spiffe://yashigani.internal/svc-a"

    def test_middleware_strips_client_supplied_peer_cert_header(self):
        """
        Client-supplied x-spiffe-id-peer-cert must be stripped and replaced
        with the server-extracted value (which may be empty if no TLS ext).
        """
        MW, _ = self._import_middleware()

        received_headers = {}

        async def fake_app(scope, receive, send):
            from starlette.datastructures import Headers
            hdrs = Headers(scope=scope)
            received_headers["peer_cert"] = hdrs.get("x-spiffe-id-peer-cert", "NOT_FOUND")

        middleware = MW(fake_app)

        # Simulate scope with a client-supplied forged header but no TLS extension
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/v1/chat/completions",
            "headers": [
                (b"authorization", b"Bearer stolen-key"),
                # Attacker tries to forge the server-controlled header
                (b"x-spiffe-id-peer-cert", b"spiffe://yashigani.internal/my-agent"),
            ],
            "extensions": {},  # No TLS extension — not a TLS connection
        }

        import asyncio
        asyncio.run(middleware(scope, None, None))

        # The forged header must be replaced with empty (no TLS ext = no cert)
        assert received_headers["peer_cert"] == "", (
            "LF-SPIFFE-FORGE: client-supplied x-spiffe-id-peer-cert must be stripped"
        )

    def test_middleware_injects_cert_uri_from_tls_extension(self):
        """
        When the ASGI scope has a TLS extension with a peer cert, the middleware
        extracts the SPIFFE URI and injects it as x-spiffe-id-peer-cert.
        """
        MW, _ = self._import_middleware()

        received_headers = {}

        async def fake_app(scope, receive, send):
            from starlette.datastructures import Headers
            hdrs = Headers(scope=scope)
            received_headers["peer_cert"] = hdrs.get("x-spiffe-id-peer-cert", "NOT_FOUND")

        middleware = MW(fake_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(b"authorization", b"Bearer valid-key")],
            "extensions": {
                "tls": {
                    "peer_cert": {
                        "subjectAltName": [
                            ("URI", "spiffe://yashigani.internal/agent-prod"),
                        ]
                    }
                }
            },
        }

        import asyncio
        asyncio.run(middleware(scope, None, None))

        assert received_headers["peer_cert"] == "spiffe://yashigani.internal/agent-prod", (
            "LF-SPIFFE-FORGE: middleware must inject SPIFFE URI from TLS peer cert"
        )

    def test_resolve_identity_uses_peer_cert_header_when_present(self):
        """
        When x-spiffe-id-peer-cert is present (injected by middleware from TLS),
        _resolve_identity uses it for the SPIFFE binding check — not X-SPIFFE-ID.

        Adversarial: bearer key bound to svc-A, X-SPIFFE-ID forged to svc-A,
        but x-spiffe-id-peer-cert reveals the actual peer cert is svc-B → reject.
        """
        from yashigani.gateway.openai_router import _resolve_identity, configure
        from starlette.requests import Request as StarletteRequest

        bound_uri = "spiffe://yashigani.internal/svc-a"
        identity = {
            "identity_id": "idnt_forge_test",
            "kind": "service",
            "name": "svc-a",
            "slug": "svc-a",
            "status": "active",
            "groups": [],
            "allowed_models": [],
            "sensitivity_ceiling": "PUBLIC",
            "bound_spiffe_uri": bound_uri,
        }
        registry = MagicMock()
        registry.get_by_api_key = MagicMock(return_value=identity)
        configure(identity_registry=registry)

        # Attacker forges X-SPIFFE-ID = svc-a (the bound URI),
        # but x-spiffe-id-peer-cert = svc-b (what their cert actually says)
        headers = {
            "authorization": "Bearer stolen-key",
            "x-spiffe-id": bound_uri,  # forged to match
            "x-spiffe-id-peer-cert": "spiffe://yashigani.internal/svc-b",  # real cert
        }
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
        req = StarletteRequest(scope)
        result = _resolve_identity(req)
        assert result is None, (
            "LF-SPIFFE-FORGE: when x-spiffe-id-peer-cert disagrees with bound_uri, "
            "must reject even if X-SPIFFE-ID was forged to match"
        )

    def test_resolve_identity_peer_cert_matches_accepts(self):
        """Valid bearer + peer cert SPIFFE URI matches bound_uri → accepted."""
        from yashigani.gateway.openai_router import _resolve_identity, configure
        from starlette.requests import Request as StarletteRequest

        bound_uri = "spiffe://yashigani.internal/agent-prod"
        identity = {
            "identity_id": "idnt_ok_test",
            "kind": "service",
            "name": "agent-prod",
            "slug": "agent-prod",
            "status": "active",
            "groups": [],
            "allowed_models": [],
            "sensitivity_ceiling": "PUBLIC",
            "bound_spiffe_uri": bound_uri,
        }
        registry = MagicMock()
        registry.get_by_api_key = MagicMock(return_value=identity)
        configure(identity_registry=registry)

        headers = {
            "authorization": "Bearer valid-key",
            "x-spiffe-id-peer-cert": bound_uri,  # server-extracted = correct
        }
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
        }
        req = StarletteRequest(scope)
        result = _resolve_identity(req)
        assert result is not None, "Valid peer cert URI match must be accepted"
        assert result["identity_id"] == "idnt_ok_test"


# ---------------------------------------------------------------------------
# LF-STEPUP-AGENT-CREATE — step-up gate coverage on agent + sensitivity + models
# ---------------------------------------------------------------------------

class TestStepUpCoverageExtended:
    """
    LF-STEPUP-AGENT-CREATE: verify that the newly gated endpoints use
    StepUpAdminSession in their function signatures.

    Uses AST-level source analysis (same approach as TestDisableUserSessionInvalidationLogic)
    so no asyncpg/multipart dependency needed.
    """

    def _fn_source(self, filename: str, fn_name: str) -> str:
        source = (ROUTES_DIR / filename).read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == fn_name:
                return ast.unparse(node)
        return ""

    # agents.py
    def test_register_agent_requires_stepup(self):
        fn = self._fn_source("agents.py", "register_agent")
        assert fn, "register_agent not found in agents.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: register_agent must use StepUpAdminSession"
        )

    def test_update_agent_requires_stepup(self):
        fn = self._fn_source("agents.py", "update_agent")
        assert fn, "update_agent not found in agents.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: update_agent must use StepUpAdminSession"
        )

    # sensitivity.py
    def test_create_pattern_requires_stepup(self):
        fn = self._fn_source("sensitivity.py", "create_pattern")
        assert fn, "create_pattern not found in sensitivity.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: create_pattern must use StepUpAdminSession"
        )

    def test_delete_pattern_requires_stepup(self):
        fn = self._fn_source("sensitivity.py", "delete_pattern")
        assert fn, "delete_pattern not found in sensitivity.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: delete_pattern must use StepUpAdminSession"
        )

    # models.py
    def test_create_alias_requires_stepup(self):
        fn = self._fn_source("models.py", "create_alias")
        assert fn, "create_alias not found in models.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: create_alias must use StepUpAdminSession"
        )

    def test_delete_alias_requires_stepup(self):
        fn = self._fn_source("models.py", "delete_alias")
        assert fn, "delete_alias not found in models.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: delete_alias must use StepUpAdminSession"
        )

    def test_create_allocation_requires_stepup(self):
        fn = self._fn_source("models.py", "create_allocation")
        assert fn, "create_allocation not found in models.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: create_allocation must use StepUpAdminSession"
        )

    def test_delete_allocation_requires_stepup(self):
        fn = self._fn_source("models.py", "delete_allocation")
        assert fn, "delete_allocation not found in models.py"
        assert "StepUpAdminSession" in fn or "require_stepup_admin_session" in fn, (
            "LF-STEPUP-AGENT-CREATE: delete_allocation must use StepUpAdminSession"
        )


# ---------------------------------------------------------------------------
# LF-SPIFFE-RETAIN — bounded retain-on-parse-failure (max-stale window)
# ---------------------------------------------------------------------------

class TestSpiffeRetainBounded:
    """
    LF-SPIFFE-RETAIN regression: retain-on-parse-failure must fail-closed-empty
    after YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS have elapsed without a
    successful manifest load.
    """

    def _reset(self):
        from yashigani.auth.spiffe import _reset_cache_for_tests
        _reset_cache_for_tests()

    def test_max_stale_env_readable(self):
        """_get_max_stale returns the env value when set."""
        from yashigani.auth import spiffe as _spiffe
        with patch.dict(os.environ, {"YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS": "120"}):
            assert _spiffe._get_max_stale() == 120.0

    def test_max_stale_default(self):
        """Default max stale is 86400 (24h)."""
        from yashigani.auth import spiffe as _spiffe
        env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS"}
        with patch.dict(os.environ, env, clear=True):
            assert _spiffe._get_max_stale() == 86400.0

    def test_max_stale_invalid_falls_back_to_default(self):
        """Invalid env value falls back to default."""
        from yashigani.auth import spiffe as _spiffe
        with patch.dict(os.environ, {"YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS": "not-a-number"}):
            assert _spiffe._get_max_stale() == 86400.0

    def test_retain_within_max_stale_window_returns_prev_acls(self):
        """Within the max-stale window, retain-on-failure returns previous ACL."""
        from yashigani.auth import spiffe as _spiffe
        self._reset()

        good_acl = {"/internal/metrics": frozenset(["spiffe://test/prom"])}

        call_count = [0]

        def first_good_then_bad():
            call_count[0] += 1
            if call_count[0] == 1:
                return good_acl
            raise IOError("manifest broken")

        with patch.object(_spiffe, "_read_manifest", side_effect=first_good_then_bad), \
             patch.dict(os.environ, {
                 "YASHIGANI_SPIFFE_ACL_TTL_SECONDS": "0",   # force every call to reload
                 "YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS": "3600",  # 1h window
             }):
            # First call loads good ACL
            result1 = _spiffe._load_acls()
            assert result1 == good_acl

            # Force TTL expiry by back-dating the cache timestamp
            # (keep _CACHE set so retry path is "TTL refresh failed", not "first load failed")
            _spiffe._CACHE = (time.monotonic() - 999, good_acl)
            result2 = _spiffe._load_acls()
            assert result2 == good_acl, (
                "LF-SPIFFE-RETAIN: within max-stale window, retain previous ACL"
            )

        self._reset()

    def test_retain_exceeds_max_stale_fails_closed(self):
        """After max-stale window expires, fail-closed-empty is returned."""
        from yashigani.auth import spiffe as _spiffe
        self._reset()

        good_acl = {"/internal/metrics": frozenset(["spiffe://test/prom"])}

        call_count = [0]

        def first_good_then_bad():
            call_count[0] += 1
            if call_count[0] == 1:
                return good_acl
            raise IOError("manifest permanently broken")

        with patch.object(_spiffe, "_read_manifest", side_effect=first_good_then_bad), \
             patch.dict(os.environ, {
                 "YASHIGANI_SPIFFE_ACL_TTL_SECONDS": "0",
                 "YASHIGANI_SPIFFE_ACL_MAX_STALE_SECONDS": "0",   # immediate expiry
             }):
            # First call loads good ACL; set _LAST_GOOD_LOAD_AT to now
            result1 = _spiffe._load_acls()
            assert result1 == good_acl

            # Expire the max-stale window (set last good load far in the past)
            _spiffe._LAST_GOOD_LOAD_AT = time.monotonic() - 1.0  # 1s ago, max_stale=0
            _spiffe._CACHE = None  # force reload

            result2 = _spiffe._load_acls()
            assert result2 == {}, (
                "LF-SPIFFE-RETAIN: after max-stale window, must fail-closed-empty"
            )

        self._reset()


# ---------------------------------------------------------------------------
# LF-DISABLE-PARTIAL — identity-registry suspension on disable
# ---------------------------------------------------------------------------

class TestDisableUserSuspendsIdentityRegistry:
    """
    LF-DISABLE-PARTIAL regression: disable_user must call
    _suspend_identity_registry_for_account so that API keys / agent tokens
    registered under the same account are also invalidated.
    """

    def test_disable_user_calls_suspend_registry(self):
        """AST: disable_user function body must call _suspend_identity_registry_for_account."""
        source = (ROUTES_DIR / "users.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        disable_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "disable_user":
                disable_fn = ast.unparse(node)
                break
        assert disable_fn is not None, "disable_user not found in users.py"
        assert "_suspend_identity_registry_for_account" in disable_fn, (
            "LF-DISABLE-PARTIAL: disable_user must call "
            "_suspend_identity_registry_for_account — API keys not suspended"
        )

    def test_disable_admin_calls_suspend_registry(self):
        """AST: disable_admin function body must call _suspend_identity_registry_for_account."""
        source = (ROUTES_DIR / "accounts.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        disable_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "disable_admin":
                disable_fn = ast.unparse(node)
                break
        assert disable_fn is not None, "disable_admin not found in accounts.py"
        assert "_suspend_identity_registry_for_account" in disable_fn, (
            "LF-DISABLE-PARTIAL: disable_admin must also call "
            "_suspend_identity_registry_for_account — parity with disable_user"
        )

    def test_suspend_helper_present_in_both_files(self):
        """Both users.py and accounts.py must define _suspend_identity_registry_for_account."""
        for filename in ["users.py", "accounts.py"]:
            source = (ROUTES_DIR / filename).read_text(encoding="utf-8")
            assert "_suspend_identity_registry_for_account" in source, (
                f"LF-DISABLE-PARTIAL: _suspend_identity_registry_for_account not found in {filename}"
            )

    def test_suspend_helper_uses_org_id_for_account_matching(self):
        """The suspend helper must check org_id == account_id for identity matching."""
        source = (ROUTES_DIR / "users.py").read_text(encoding="utf-8")
        # The helper iterates identities and checks org_id == account_id
        assert "org_id" in source, (
            "LF-DISABLE-PARTIAL: suspend helper must use org_id to match identities"
        )
        assert 'registry.suspend' in source, (
            "LF-DISABLE-PARTIAL: suspend helper must call registry.suspend()"
        )


# ---------------------------------------------------------------------------
# LF-XSS-RES — residual innerHTML+err.detail sinks static check
# ---------------------------------------------------------------------------

class TestXssResidualSinks:
    """
    LF-XSS-RES regression: all innerHTML + dynamic data sinks must use escapeHtml.

    Static analysis proxy: grep for innerHTML patterns that don't wrap dynamic
    content in escapeHtml().
    """

    def _js(self) -> str:
        return DASHBOARD_JS.read_text(encoding="utf-8")

    def _find_unescaped_innerhtml_sinks(self, js: str) -> list[tuple[int, str]]:
        """Return (lineno, line) for innerHTML assignments with unescaped dynamic content."""
        unescaped = []
        # Patterns that indicate user-controlled dynamic data
        dynamic_patterns = re.compile(
            r"err\.detail|err\.message|data\.detail|data\.message|data\.tier|data\.max_agents|data\.expires_at|sink\b|r\.status|resp\.status"
        )
        for i, line in enumerate(js.splitlines(), start=1):
            if "innerHTML" not in line:
                continue
            if not dynamic_patterns.search(line):
                continue
            # If every dynamic variable in the line is wrapped by escapeHtml, it's safe
            # Simple check: the line must contain escapeHtml( if it contains dynamic data
            if "escapeHtml(" not in line:
                unescaped.append((i, line.strip()))
        return unescaped

    def test_no_unescaped_dynamic_innerhtml_sinks(self):
        """All innerHTML sinks with dynamic data must use escapeHtml."""
        js = self._js()
        unescaped = self._find_unescaped_innerhtml_sinks(js)
        assert unescaped == [], (
            "LF-XSS-RES: unescaped innerHTML sinks found:\n"
            + "\n".join(f"  line {n}: {l}" for n, l in unescaped)
        )

    def test_escape_html_defined(self):
        """escapeHtml must be defined in dashboard.js."""
        js = self._js()
        assert "function escapeHtml" in js or "var escapeHtml" in js or "const escapeHtml" in js, (
            "escapeHtml not defined in dashboard.js"
        )

    def test_budget_endpoints_escaped(self):
        """Budget org/group/individual error paths must use escapeHtml."""
        js = self._js()
        # Find the three addOrgBudget/addGroupBudget/addIndBudget patterns
        budget_sections = re.findall(r"async function add\w+Budget.*?(?=async function|\Z)", js, re.DOTALL)
        for section in budget_sections:
            if "innerHTML" in section and "err.detail" in section:
                assert "escapeHtml(" in section, (
                    f"LF-XSS-RES: budget function has unescaped err.detail sink"
                )

    def test_sensitivity_pattern_error_escaped(self):
        """Sensitivity pattern error path must use escapeHtml."""
        js = self._js()
        # Find addPattern function area
        pat_start = js.find("async function addPattern")
        if pat_start == -1:
            pytest.skip("addPattern function not found — check function name")
        pat_section = js[pat_start:js.find("async function", pat_start + 1)]
        if "innerHTML" in pat_section and "err.detail" in pat_section:
            assert "escapeHtml(" in pat_section, (
                "LF-XSS-RES: addPattern has unescaped err.detail sink"
            )


# ---------------------------------------------------------------------------
# LAURA-V232-002 — SPIFFE identity forge via client-supplied X-SPIFFE-ID
# (updated for ISSUE-019 correction 2026-05-19)
# ---------------------------------------------------------------------------

class TestSpiffeForgeV232002:
    """
    LAURA-V232-002 / ISSUE-019 regression suite for SpiffePeerCertMiddleware.

    ISSUE-019 correction (2026-05-19): Su's LAURA-V232-002 fix stripped
    x-spiffe-id from all requests, which broke the Caddy→backoffice path:
    Caddy injects x-spiffe-id in the request it sends to backoffice, and
    that header IS present in the ASGI scope this middleware processes.
    Stripping it caused 401 no_spiffe_id for every SPIFFE-gated mutation
    route (POST /admin/agents, PUT /admin/agents/{id}, etc.).

    Corrected contract:
    - x-spiffe-id-peer-cert is ALWAYS overwritten (server-controlled).
    - x-spiffe-id is PRESERVED (Caddy-injected on Caddy→upstream path, or
      install.sh-injected on the direct-backoffice path).
    - Primary forge-prevention is CaddyVerifiedMiddleware Layer B (HMAC).
    - Residual risk: a direct-mesh attacker holding a CA cert + HMAC secret
      can forge x-spiffe-id.  Accepted for v2.23.4; tracked in YSG-RISK-012b.
      Long-term fix: Option A from LAURA-V232-002 (all access via Caddy only).
    """

    def _import_middleware(self):
        from yashigani.gateway.spiffe_middleware import SpiffePeerCertMiddleware
        return SpiffePeerCertMiddleware

    def test_x_spiffe_id_peer_cert_overwritten_by_middleware(self):
        """
        LAURA-V232-002 / ISSUE-019: x-spiffe-id-peer-cert supplied by the
        client must be overwritten (not passed through).  When the ASGI TLS
        extension is absent, it becomes "" (empty = no peer cert extracted).
        """
        MW = self._import_middleware()

        received_headers = {}

        async def fake_app(scope, receive, send):
            from starlette.datastructures import Headers
            hdrs = Headers(scope=scope)
            received_headers["x_spiffe_id"] = hdrs.get("x-spiffe-id")
            received_headers["peer_cert"] = hdrs.get("x-spiffe-id-peer-cert", "MISSING")

        middleware = MW(fake_app)

        # Simulate a request with a forged x-spiffe-id-peer-cert and a
        # legitimate x-spiffe-id (Caddy-injected or install.sh-injected).
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/admin/agents",
            "headers": [
                (b"x-spiffe-id", b"spiffe://yashigani.internal/backoffice"),
                (b"x-spiffe-id-peer-cert", b"spiffe://yashigani.internal/fake"),
                (b"authorization", b"Bearer whatever"),
            ],
            "extensions": {},  # No TLS extension — peer_cert absent
        }

        import asyncio
        asyncio.run(middleware(scope, None, None))

        # x-spiffe-id must be preserved (Caddy/install.sh injected).
        assert received_headers["x_spiffe_id"] == "spiffe://yashigani.internal/backoffice", (
            "ISSUE-019: x-spiffe-id must be preserved by middleware — "
            f"got x-spiffe-id={received_headers['x_spiffe_id']!r}"
        )
        # x-spiffe-id-peer-cert must be overwritten to "" (TLS ext absent).
        assert received_headers["peer_cert"] == "", (
            "LAURA-V232-002: x-spiffe-id-peer-cert must be empty when TLS ext absent, "
            f"got {received_headers['peer_cert']!r}"
        )

    def test_x_spiffe_id_preserved_caddy_path(self):
        """
        ISSUE-019: x-spiffe-id injected by Caddy on the Caddy→backoffice path
        must reach the downstream app unchanged.  This is the fix for the
        regression introduced by LAURA-V232-002 Su fix (commit 4a7a5a8).
        """
        MW = self._import_middleware()

        downstream_scope = {}

        async def capture_app(scope, receive, send):
            downstream_scope.update(scope)

        middleware = MW(capture_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/admin/agents",
            "headers": [
                (b"x-spiffe-id", b"spiffe://yashigani.internal/caddy"),
                (b"host", b"backoffice"),
            ],
            "extensions": {},
        }

        import asyncio
        asyncio.run(middleware(scope, None, None))

        header_names_and_values = {
            k.lower(): v for k, v in downstream_scope.get("headers", [])
        }
        assert b"x-spiffe-id" in header_names_and_values, (
            "ISSUE-019: x-spiffe-id must be preserved on Caddy→backoffice path"
        )
        assert header_names_and_values[b"x-spiffe-id"] == b"spiffe://yashigani.internal/caddy", (
            "ISSUE-019: x-spiffe-id value must be Caddy's SPIFFE identity"
        )

    def test_middleware_overwrites_peer_cert_header_preserves_spiffe_id(self):
        """
        ISSUE-019 / LAURA-V232-002: when ASGI TLS extension is absent,
        x-spiffe-id-peer-cert supplied by the client is overwritten to "".
        x-spiffe-id (Caddy/install.sh injected) is preserved.
        """
        MW = self._import_middleware()

        downstream_scope = {}

        async def capture_app(scope, receive, send):
            downstream_scope.update(scope)

        middleware = MW(capture_app)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/admin/agents",
            "headers": [
                (b"x-spiffe-id", b"spiffe://yashigani.internal/backoffice"),
                (b"x-spiffe-id-peer-cert", b"spiffe://yashigani.internal/fake"),
            ],
            "extensions": {},
        }

        import asyncio
        asyncio.run(middleware(scope, None, None))

        headers_dict = {k.lower(): v for k, v in downstream_scope.get("headers", [])}

        # x-spiffe-id-peer-cert must be empty (server-set from absent TLS ext;
        # client-supplied value overwritten).
        assert headers_dict.get(b"x-spiffe-id-peer-cert") == b"", (
            "LAURA-V232-002: x-spiffe-id-peer-cert must be empty when TLS ext absent"
        )
        # x-spiffe-id must be preserved (install.sh / Caddy injected).
        assert headers_dict.get(b"x-spiffe-id") == b"spiffe://yashigani.internal/backoffice", (
            "ISSUE-019: x-spiffe-id must be preserved — Caddy/install.sh injected value"
        )
