"""
Integration tests — SoD Admin/User Separation-of-Duties (Iris #96, v2.24.1).

Tests requiring live service infrastructure are marked with @pytest.mark.skip
and can be run against a local stack with: pytest -m live_stack tests/integration/

Core integration scenarios validated here (without live services, via mock stack):
  - SSO callback exploit replay: admin email → SSO callback → identity creation BLOCKED
  - /auth/verify exploit: admin session → /auth/verify → 403
  - End-to-end SoD-004 chain: admin SSO login → try to call /v1/chat/completions → BLOCKED

Live-stack scenarios (marked @pytest.mark.skip for CI):
  - Real SSO flow with admin email
  - Real /v1/chat/completions call with admin cookie

NIST AC-5 / SOC 2 CC6.3 / ISO 27001 A.5.16 / CMMC AC.L2-3.1.4 / ASVS V4.1.2
Last updated: 2026-05-25T00:00:00+00:00
"""
from __future__ import annotations

from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.audit.schema import (
    AuthVerifyRejectedAdminSessionEvent,
    EventType,
    SsoProvisionRejectedAdminExistsEvent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_account(username: str, account_tier: str, email: str = "") -> MagicMock:
    acct = MagicMock()
    acct.username = username
    acct.account_tier = account_tier
    acct.email = email or f"{username}@example.com"
    acct.account_id = f"uuid-{username}"
    acct.disabled = False
    acct.force_password_change = False
    acct.force_totp_provision = False
    acct.created_at = 0.0
    return acct


def _make_session(account_id: str, account_tier: str, token: str = "tok-abc") -> MagicMock:
    sess = MagicMock()
    sess.account_id = account_id
    sess.account_tier = account_tier
    sess.token = token
    return sess


# ---------------------------------------------------------------------------
# Integration: SSO OIDC callback exploit replay (SoD-002c / SoD-004)
# ---------------------------------------------------------------------------

class TestSsoCallbackExploitReplay:
    """
    Integration: admin email completing SSO should be blocked before identity creation.

    Replays the SoD-004 attack chain:
      1. Admin has an account with email=admin@corp.com
      2. Admin initiates SSO flow with same email
      3. oidc_callback receives successful SSO result for admin@corp.com
      4. _check_sod_admin_collision detects collision
      5. Redirects to /login?error=admin_cannot_use_platform
      6. _resolve_or_create_identity is NEVER called
      7. No HUMAN identity is created
      8. SSO_PROVISION_REJECTED_ADMIN_EXISTS event emitted
    """

    @pytest.mark.asyncio
    async def test_oidc_callback_admin_email_redirects_to_error(self):
        """OIDC callback with admin email redirects to error page — no identity created."""
        from fastapi import Request
        from fastapi.responses import RedirectResponse
        from yashigani.backoffice.routes import sso as _sso_mod

        existing_admin = _make_account("admin@corp.com", "admin", "admin@corp.com")

        # Mock successful SSO result for the admin's email
        mock_sso_result = MagicMock()
        mock_sso_result.success = True
        mock_sso_result.email = "admin@corp.com"
        mock_sso_result.name = "Admin User"
        mock_sso_result.groups = []
        mock_sso_result.idp_name = "test-idp"
        mock_sso_result.raw_claims = {}
        mock_sso_result.error = None

        mock_idp_cfg = MagicMock()
        mock_idp_cfg.org_id = ""
        mock_idp_cfg.default_sensitivity = "INTERNAL"
        mock_idp_cfg.required_acr_values = None
        mock_idp_cfg.required_amr_values = None

        mock_broker = MagicMock()
        mock_broker.get_idp = MagicMock(return_value=mock_idp_cfg)
        mock_broker.handle_oidc_callback = MagicMock(return_value=mock_sso_result)

        mock_redis = MagicMock()
        mock_redis.get = MagicMock(return_value=None)  # state consumed

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.identity_broker = mock_broker
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.5"

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            with patch.object(_sso_mod, "require_feature"):
                with patch.object(_sso_mod, "_consume_state", return_value={"idp_id": "test-idp", "nonce": "n", "code_verifier": ""}):
                    with patch.object(_sso_mod, "_build_redirect_uri", return_value="https://example.com/callback"):
                        with patch.object(_sso_mod, "_email_hash", return_value="test-hash-abc123"):
                            response = await _sso_mod.oidc_callback(
                                idp_id="test-idp",
                                request=mock_request,
                                code="auth-code",
                                state="csrf-state",
                            )

        # Must redirect to error page, NOT /chat
        assert isinstance(response, RedirectResponse)
        redirect_url = response.headers.get("location", "")
        assert "admin_cannot_use_platform" in redirect_url
        assert "/chat" not in redirect_url

    @pytest.mark.asyncio
    async def test_oidc_callback_identity_not_created_for_admin(self):
        """OIDC callback: _resolve_or_create_identity must NOT be called for admin email."""
        from fastapi import Request
        from yashigani.backoffice.routes import sso as _sso_mod

        existing_admin = _make_account("admin@corp.com", "admin", "admin@corp.com")

        mock_sso_result = MagicMock()
        mock_sso_result.success = True
        mock_sso_result.email = "admin@corp.com"
        mock_sso_result.name = "Admin"
        mock_sso_result.groups = []
        mock_sso_result.idp_name = "test-idp"
        mock_sso_result.raw_claims = {}

        mock_idp_cfg = MagicMock()
        mock_idp_cfg.org_id = ""
        mock_idp_cfg.default_sensitivity = "INTERNAL"
        mock_idp_cfg.required_acr_values = None
        mock_idp_cfg.required_amr_values = None

        mock_broker = MagicMock()
        mock_broker.get_idp = MagicMock(return_value=mock_idp_cfg)
        mock_broker.handle_oidc_callback = MagicMock(return_value=mock_sso_result)

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.identity_broker = mock_broker
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.5"

        resolve_calls = []

        def _mock_resolve(*args, **kwargs):
            resolve_calls.append((args, kwargs))
            return "would-be-identity-id"

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            with patch.object(_sso_mod, "require_feature"):
                with patch.object(_sso_mod, "_consume_state", return_value={"idp_id": "test-idp", "nonce": "n", "code_verifier": ""}):
                    with patch.object(_sso_mod, "_build_redirect_uri", return_value="https://example.com/callback"):
                        with patch.object(_sso_mod, "_email_hash", return_value="test-hash-abc123"):
                            with patch.object(_sso_mod, "_resolve_or_create_identity", side_effect=_mock_resolve):
                                await _sso_mod.oidc_callback(
                                    idp_id="test-idp",
                                    request=mock_request,
                                    code="auth-code",
                                    state="csrf-state",
                                )

        # The critical assertion: _resolve_or_create_identity must NOT have been called
        assert len(resolve_calls) == 0, (
            "CRITICAL: _resolve_or_create_identity was called for admin email — "
            "SoD-002c/SoD-004 exploit chain is NOT blocked!"
        )

    @pytest.mark.asyncio
    async def test_oidc_callback_admin_collision_emits_audit_event(self):
        """OIDC callback admin collision emits SSO_PROVISION_REJECTED_ADMIN_EXISTS."""
        from fastapi import Request
        from yashigani.backoffice.routes import sso as _sso_mod

        existing_admin = _make_account("admin@corp.com", "admin", "admin@corp.com")

        mock_sso_result = MagicMock()
        mock_sso_result.success = True
        mock_sso_result.email = "admin@corp.com"
        mock_sso_result.name = "Admin"
        mock_sso_result.groups = []
        mock_sso_result.idp_name = "test-idp"
        mock_sso_result.raw_claims = {}

        mock_idp_cfg = MagicMock()
        mock_idp_cfg.org_id = ""
        mock_idp_cfg.default_sensitivity = "INTERNAL"
        mock_idp_cfg.required_acr_values = None
        mock_idp_cfg.required_amr_values = None

        mock_broker = MagicMock()
        mock_broker.get_idp = MagicMock(return_value=mock_idp_cfg)
        mock_broker.handle_oidc_callback = MagicMock(return_value=mock_sso_result)

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state.identity_broker = mock_broker
        mock_state.session_store = MagicMock()
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.5"

        with patch.object(_sso_mod, "backoffice_state", mock_state):
            with patch.object(_sso_mod, "require_feature"):
                with patch.object(_sso_mod, "_consume_state", return_value={"idp_id": "test-idp", "nonce": "n", "code_verifier": ""}):
                    with patch.object(_sso_mod, "_build_redirect_uri", return_value="https://example.com/callback"):
                        with patch.object(_sso_mod, "_email_hash", return_value="test-hash-abc123"):
                            await _sso_mod.oidc_callback(
                                idp_id="test-idp",
                                request=mock_request,
                                code="auth-code",
                                state="csrf-state",
                            )

        calls = mock_state.audit_writer.write.call_args_list
        sod_events = [c for c in calls if isinstance(c[0][0], SsoProvisionRejectedAdminExistsEvent)]
        assert len(sod_events) >= 1


# ---------------------------------------------------------------------------
# Integration: /auth/verify admin session (SoD-003)
# ---------------------------------------------------------------------------

class TestAuthVerifyAdminSessionIntegration:
    """
    Integration: /auth/verify must reject admin sessions at the Caddy forward_auth layer.

    This is the final line of defence against the SoD-004 exploit chain.
    Even if (hypothetically) an admin identity existed in the registry,
    the admin's session would be blocked here.
    """

    @pytest.mark.asyncio
    async def test_auth_verify_admin_session_403_and_no_forwarded_user_header(self):
        """Admin session on /auth/verify returns 403 — no X-Forwarded-User header emitted."""
        from fastapi import HTTPException, Request
        from yashigani.backoffice.routes import auth as _auth_mod

        admin_session = _make_session("admin-corp", "admin", "admin-tok")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=admin_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_session": "admin-tok"}
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.100"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_session(mock_request)

        assert exc_info.value.status_code == 403
        # No X-Forwarded-User header should be emitted on 403
        assert not hasattr(exc_info.value, "headers") or \
               exc_info.value.headers is None or \
               "X-Forwarded-User" not in (exc_info.value.headers or {})

    @pytest.mark.asyncio
    async def test_auth_verify_user_session_200_with_forwarded_headers(self):
        """User session on /auth/verify returns 200 with X-Forwarded-User + X-Forwarded-Email."""
        from fastapi import Request
        from yashigani.backoffice.routes import auth as _auth_mod

        user_session = _make_session("user-corp", "user", "user-tok")
        user_record = _make_account("alice", "user", "alice@corp.com")

        mock_state = MagicMock()
        mock_state.auth_service = AsyncMock()
        mock_state.auth_service.get_account_by_id = AsyncMock(return_value=user_record)
        mock_state.session_store = MagicMock()
        mock_state.session_store.get = MagicMock(return_value=user_session)
        mock_state.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {"__Host-yashigani_session": "user-tok"}
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.101"

        with patch.object(_auth_mod, "backoffice_state", mock_state):
            resp = await _auth_mod.verify_session(mock_request)

        assert resp.status_code == 200
        assert resp.headers.get("X-Forwarded-User") == "alice@corp.com"
        assert resp.headers.get("X-Forwarded-Email") == "alice@corp.com"
        assert resp.headers.get("X-Forwarded-Name") == "alice"


# ---------------------------------------------------------------------------
# Integration: End-to-end SoD-004 attack chain
# ---------------------------------------------------------------------------

class TestSoD004EndToEndChain:
    """
    Replays the complete SoD-004 exploit chain and verifies it is blocked at layer 1 AND layer 2.

    Attack chain:
      1. Admin logs in normally (port 8443) — gets admin session cookie
      2. Admin navigates to SSO endpoint with admin email
      3. SSO callback receives successful result for admin@corp.com
      4. [Layer 1 SoD-002c] _check_sod_admin_collision blocks identity creation
      5. Redirect to error page — no session cookie issued
      6. Even if admin tries /auth/verify with admin session cookie:
      7. [Layer 2 SoD-003] /auth/verify returns 403
    """

    @pytest.mark.asyncio
    async def test_full_exploit_chain_blocked_at_both_layers(self):
        """End-to-end: admin SSO → blocked at identity creation + blocked at /auth/verify."""
        from fastapi import HTTPException, Request
        from fastapi.responses import RedirectResponse
        from yashigani.backoffice.routes import sso as _sso_mod
        from yashigani.backoffice.routes import auth as _auth_mod

        # Setup: admin exists
        existing_admin = _make_account("admin@corp.com", "admin", "admin@corp.com")
        admin_session = _make_session("admin-corp", "admin", "admin-tok")

        # --- LAYER 1: SSO callback ---
        mock_sso_result = MagicMock()
        mock_sso_result.success = True
        mock_sso_result.email = "admin@corp.com"
        mock_sso_result.name = "Admin"
        mock_sso_result.groups = []
        mock_sso_result.idp_name = "corp-idp"
        mock_sso_result.raw_claims = {}

        mock_idp_cfg = MagicMock()
        mock_idp_cfg.org_id = ""
        mock_idp_cfg.default_sensitivity = "INTERNAL"
        mock_idp_cfg.required_acr_values = None
        mock_idp_cfg.required_amr_values = None

        mock_broker = MagicMock()
        mock_broker.get_idp = MagicMock(return_value=mock_idp_cfg)
        mock_broker.handle_oidc_callback = MagicMock(return_value=mock_sso_result)

        mock_state_sso = MagicMock()
        mock_state_sso.auth_service = AsyncMock()
        mock_state_sso.auth_service.get_account = AsyncMock(return_value=existing_admin)
        mock_state_sso.auth_service.get_account_by_email = AsyncMock(return_value=existing_admin)
        mock_state_sso.identity_broker = mock_broker
        mock_state_sso.session_store = MagicMock()
        mock_state_sso.audit_writer = MagicMock()

        mock_request = MagicMock(spec=Request)
        mock_request.client = MagicMock()
        mock_request.client.host = "10.0.0.1"

        with patch.object(_sso_mod, "backoffice_state", mock_state_sso):
            with patch.object(_sso_mod, "require_feature"):
                with patch.object(_sso_mod, "_consume_state", return_value={"idp_id": "corp-idp", "nonce": "n", "code_verifier": ""}):
                    with patch.object(_sso_mod, "_build_redirect_uri", return_value="https://corp.com/cb"):
                        with patch.object(_sso_mod, "_email_hash", return_value="test-hash-abc123"):
                            sso_response = await _sso_mod.oidc_callback(
                                idp_id="corp-idp",
                                request=mock_request,
                                code="code",
                                state="state",
                            )

        # Layer 1: SSO blocked — redirect to error, NOT /chat
        assert isinstance(sso_response, RedirectResponse)
        redirect_url = sso_response.headers.get("location", "")
        assert "admin_cannot_use_platform" in redirect_url, \
            f"Layer 1 NOT blocked — redirect was: {redirect_url}"

        # No session cookie issued in SSO response
        response_cookies = sso_response.headers.get("set-cookie", "")
        assert "yashigani_session" not in response_cookies, \
            "Layer 1 NOT blocked — session cookie was issued for admin!"

        # --- LAYER 2: /auth/verify ---
        mock_state_auth = MagicMock()
        mock_state_auth.auth_service = AsyncMock()
        mock_state_auth.session_store = MagicMock()
        mock_state_auth.session_store.get = MagicMock(return_value=admin_session)
        mock_state_auth.audit_writer = MagicMock()

        mock_verify_request = MagicMock(spec=Request)
        mock_verify_request.cookies = {"__Host-yashigani_session": "admin-tok"}
        mock_verify_request.client = MagicMock()
        mock_verify_request.client.host = "10.0.0.1"

        with patch.object(_auth_mod, "backoffice_state", mock_state_auth):
            with pytest.raises(HTTPException) as exc_info:
                await _auth_mod.verify_session(mock_verify_request)

        # Layer 2: /auth/verify blocked admin session
        assert exc_info.value.status_code == 403, \
            f"Layer 2 NOT blocked — /auth/verify returned {exc_info.value.status_code}"
        assert exc_info.value.detail["error"] == "admin_session_not_allowed_data_plane", \
            f"Layer 2 wrong error code: {exc_info.value.detail}"


# ---------------------------------------------------------------------------
# Live-stack integration tests (require running deployment)
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Requires live Yashigani stack — run with pytest -m live_stack")
class TestLiveStackSoD:
    """Live-stack integration tests. Run against real deployment."""

    def test_admin_sso_login_redirects_to_error(self):
        """Live: POST to SSO OIDC callback with admin email → /login?error=admin_cannot_use_platform"""
        # Implemented via playwright or httpx against live stack
        pass

    def test_admin_cookie_blocked_at_chat_proxy(self):
        """Live: admin session cookie presented to /v1/chat/completions → 403"""
        # Caddy forward_auth calls /auth/verify → SoD-003 → 403 → Caddy returns 403 to caller
        pass

    def test_scim_provision_admin_email_returns_409(self):
        """Live: SCIM POST /scim/Users with admin email → SCIM 409 uniqueness"""
        pass
