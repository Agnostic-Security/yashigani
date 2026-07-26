"""
Regression tests — LAURA-V50-008 (High): MCP tool-call path (POST /mcp/{agent})
was denied at the RBAC group-permission layer for every real end user, even
after an explicit admin grant. The injection/OPA-gating defence on the MCP
tools/call leg was structurally unreachable for any browser-cookie caller.

Root cause (confirmed live on yashigani-local, 2026-07-26): the Caddy
/v1/* and /mcp/* handle blocks (docker/Caddyfile.{selfsigned,acme,ca} +
helm/yashigani/templates/configmaps.yaml) reverse_proxy'd straight to gateway
with NO forward_auth step. strip-identity-headers (site-level) strips any
inbound X-Yashigani-Identity-Id and nothing ever re-populated it for these
two paths — unlike /admin/grafana etc, which forward_auth to backoffice's
/auth/verify-admin. backoffice's GET /auth/verify (the data-plane / user-tier
sibling — routes/auth.py verify_session) was fully implemented for exactly
this purpose but had ZERO callers anywhere in the Caddy config.

Every cookie-authenticated end-user request to /v1/* or /mcp/* resolved to
identity_id="unknown" at the gateway boundary resolver
(gateway/proxy.py::_extract_identity, reading request.state.ysg_principal set
by the "0b-pre" boundary block from X-Yashigani-Identity-Id), which is never a
member of any RBAC group, so policy/rbac.rego's allow_rbac denied
unconditionally — independent of any group grant, however correctly
configured and OPA-pushed.

SECOND bug found while proving the fix live: IdentityRegistry.get_by_
account_id() returns the FULL identity dict (identity/registry.py — it's
`self.get(identity_id)` under the hood), not the identity_id string. All
THREE /auth/verify* endpoints (verify_session, verify_admin_session,
verify_user_session in backoffice/routes/auth.py) assigned that dict DIRECTLY
to resp.headers["X-Yashigani-Identity-Id"]. Starlette's MutableHeaders.
__setitem__ calls value.encode("latin-1") — a dict has no .encode — raising
an exception silently swallowed by `except Exception: _log.debug(...)`.
X-Yashigani-Identity-Id was NEVER set on ANY /auth/verify* response, on every
deployment, since 4.1 SEC-GAP-1 shipped. See
tests/conformance/test_auth.py::TestAuthVerifyIdentityIdHeader for the
backoffice-side regression coverage of THAT bug; this file covers the
gateway-side identity->OPA-input resolution mechanism the Caddy fix restores.

This file tests the gateway-side mechanism directly:
  A. proxy.py::_extract_identity resolves user_id from request.state.
     ysg_principal.identity_id for a /mcp/{agent} path request (the exact
     leg LAURA-V50-008 exercised) — not just /v1/chat/completions (already
     covered by v4.1/test_secgap1_uid_unification.py).
  B. proxy.py::_extract_identity falls back to "unknown" when ysg_principal
     is absent (the boundary-resolver-never-ran state that Caddy's missing
     forward_auth produced for every real request pre-fix) — pinning the
     EXACT failure mode as a locked invariant, not a hypothetical.
  C. proxy.py::_opa_check posts the resolved identity_id (not "unknown")
     into input.session.identity_id / input.request.path for a /mcp/{agent}
     path — the OPA input rbac.rego's allow_rbac actually evaluates.

Fix: docker/Caddyfile.{selfsigned,acme,ca} + helm configmaps.yaml — forward_auth
to /auth/verify (scoped to session-cookie-bearing requests via
@has_user_session, so Bearer/API-key agent traffic is unaffected) before
reverse_proxy on /v1/* and /mcp/*. src/yashigani/backoffice/routes/auth.py —
extract identity_id from the dict get_by_account_id() actually returns.

Live proof (yashigani-local, 2026-07-26): a real onboarded scenario user
(ana@agnosticsec.com, data-team group, real identity_id=idnt_6e6c589d04d9)
granted POST /mcp/** via the real admin API:
  - Pre-fix: POST /mcp/cloud9-demo tools/call -> 403 opa_policy / "RBAC group
    permission" (reproduced live, matching Laura's finding exactly).
  - Post-fix: the SAME 403 opa_policy denial is GONE. The request now reaches
    the MCP broker's OWN later-stage gates (manifest re-approval, then the
    mcp.tools.call OPA policy's SPIFFE-identity requirement) — proving RBAC
    is no longer the blocker. With the RBAC grant removed and re-pushed, the
    403 opa_policy denial correctly returns (least-privilege intact).

Second finding (reported, NOT fixed here — see final report): the MCP
tools/call OPA policy (policy/mcp.rego) requires input.identity.verified==true,
which gateway/mcp_router_runtime.py derives ONLY from a caller-presented,
Caddy-verified X-SPIFFE-ID (mTLS peer leaf SAN) — structurally unsatisfiable
by ANY plain cookie-session browser caller, human or otherwise. This means
the injection classifier + broker.enforce() tool-gating on the MCP leg
remains unreachable for a human end user even after the RBAC fix — a
DIFFERENT, later-stage gate than the one this file/fix addresses. That is an
architecture decision (should end-user MCP tool-calls be mesh-identified via
an internal proxy hop, or should the SPIFFE requirement be relaxed for
verified-cookie callers?) outside this ticket's scope.

Last updated: 2026-07-26T00:00:00+00:00
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_request(path: str, identity_id: str | None, cookie: str = "") -> object:
    """Build a minimal Starlette Request for a POST to `path`, optionally with
    request.state.ysg_principal pre-populated (simulating the proxy.py "0b-pre"
    boundary resolver having already resolved X-Yashigani-Identity-Id — the
    exact state Caddy's forward_auth + copy_headers now produces post-fix)."""
    from starlette.requests import Request as StarletteRequest

    headers = []
    if cookie:
        headers.append((b"cookie", cookie.encode()))
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
    }
    req = StarletteRequest(scope)
    if identity_id is not None:
        from yashigani.gateway.types import ResolvedPrincipal

        req.state.ysg_principal = ResolvedPrincipal(
            identity_id=identity_id,
            principal_scope="user",
        )
    return req


class TestExtractIdentityOnMcpPath:
    """A. _extract_identity resolves the real identity_id for /mcp/{agent}."""

    def test_resolves_identity_id_from_ysg_principal_for_mcp_path(self):
        """Post-fix state: Caddy's forward_auth delivered X-Yashigani-Identity-Id,
        the proxy.py boundary resolver set request.state.ysg_principal from it —
        _extract_identity must surface that identity_id, not fall back."""
        from yashigani.gateway.proxy import _extract_identity

        req = _make_request(
            "/mcp/cloud9-demo",
            identity_id="idnt_6e6c589d04d9",
            cookie="__Host-yashigani_session=abc123",
        )
        session_id, agent_id, user_id = _extract_identity(req)
        assert user_id == "idnt_6e6c589d04d9", (
            "LAURA-V50-008: _extract_identity must resolve the real identity_id "
            "from request.state.ysg_principal for a /mcp/{agent} path request — "
            "the exact leg the finding was reproduced on."
        )

    def test_falls_back_to_unknown_when_ysg_principal_absent(self):
        """Pre-fix / no-forward_auth state: no ysg_principal was ever set
        (Caddy never delivered the header) — this is the EXACT mechanism that
        made every real cookie-authenticated /mcp/* caller resolve to
        identity_id="unknown", which is never a member of any RBAC group.
        This fallback itself is CORRECT (fail-closed) — the finding's fix is
        upstream in Caddy, not this fallback. Pinned here as a locked
        invariant of the mechanism, not a hypothetical."""
        from yashigani.gateway.proxy import _extract_identity

        req = _make_request(
            "/mcp/cloud9-demo",
            identity_id=None,
            cookie="__Host-yashigani_session=abc123",
        )
        session_id, agent_id, user_id = _extract_identity(req)
        assert user_id == "unknown", (
            "Without a boundary-resolved ysg_principal, _extract_identity must "
            "fail closed to 'unknown' (never a phantom/guessed identity) — this "
            "is the pre-fix failure mode LAURA-V50-008 traced live."
        )


class TestOpaCheckInputOnMcpPath:
    """C. _opa_check posts the resolved identity_id (not "unknown") for
    /mcp/{agent} — the OPA input policy/rbac.rego's allow_rbac evaluates."""

    @pytest.mark.asyncio
    async def test_opa_input_carries_real_identity_id_for_mcp_toolcall(self):
        """The OPA input.session.identity_id must be the REAL resolved
        identity_id for a /mcp/{agent} POST — this is exactly what
        policy/rbac.rego's allow_rbac keys data.yashigani.rbac.user_groups
        on. Mocks the OPA HTTP call and asserts the posted JSON body."""
        from yashigani.gateway.proxy import GatewayConfig, _opa_check

        req = _make_request(
            "/mcp/cloud9-demo",
            identity_id="idnt_6e6c589d04d9",
            cookie="__Host-yashigani_session=abc123",
        )
        cfg = GatewayConfig(upstream_base_url="https://upstream-test", opa_url="https://policy:8181")

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"result": True})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            return_value=mock_client,
        ):
            result = await _opa_check(
                cfg, req, "/mcp/cloud9-demo", "sess-001", "agent-x",
                "idnt_6e6c589d04d9",
            )

        assert result is True
        mock_client.post.assert_called_once()
        _, kwargs = mock_client.post.call_args
        posted = kwargs["json"]["input"]
        assert posted["session"]["identity_id"] == "idnt_6e6c589d04d9", (
            "LAURA-V50-008: OPA input.session.identity_id must be the real "
            "identity_id, not 'unknown' — this is the exact field policy/"
            "rbac.rego's allow_rbac keys data.yashigani.rbac.user_groups on."
        )
        assert posted["request"]["path"] == "/mcp/cloud9-demo"
        assert posted["request"]["method"] == "POST"

    @pytest.mark.asyncio
    async def test_opa_input_carries_unknown_when_identity_unresolved(self):
        """The pre-fix failure mode, at the OPA-input boundary: when
        _extract_identity falls back to "unknown" (no forward_auth ran),
        _opa_check faithfully posts "unknown" — which policy/rbac_test.rego's
        test_allow_rbac_false_for_mcp_toolcall_when_identity_unresolved
        proves is ALWAYS denied by allow_rbac, regardless of any real grant
        for the real identity. This test pins the gateway-side half of that
        chain; the rego test pins the OPA-side half."""
        from yashigani.gateway.proxy import GatewayConfig, _opa_check

        req = _make_request("/mcp/cloud9-demo", identity_id=None)
        cfg = GatewayConfig(upstream_base_url="https://upstream-test", opa_url="https://policy:8181")

        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"result": False})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            return_value=mock_client,
        ):
            result = await _opa_check(
                cfg, req, "/mcp/cloud9-demo", "sess-001", "agent-x", "unknown",
            )

        assert result is False
        _, kwargs = mock_client.post.call_args
        posted = kwargs["json"]["input"]
        assert posted["session"]["identity_id"] == "unknown"
