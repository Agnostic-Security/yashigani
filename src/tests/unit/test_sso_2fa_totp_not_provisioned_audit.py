"""
NDC follow-up (2026-07-31, Tom) — sso.py::sso_2fa_verify()'s
totp_not_provisioned deny had NO audit trail (the sibling
totp_verification_failed deny already called _write_sso_failure_audit()).

Fix: totp_not_provisioned now reuses the same _write_sso_failure_audit()
helper/event shape (SSOLoginFailureEvent) that already covers every other
deny in this function.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_request(cookies=None, body=None):
    req = MagicMock()
    req.cookies = cookies or {}
    req.json = AsyncMock(return_value=body or {})
    return req


class TestSso2faTotpNotProvisionedAudited:
    @pytest.mark.asyncio
    async def test_totp_not_provisioned_writes_audit_event(self):
        from yashigani.backoffice.routes import sso as sso_routes

        pending = {
            "idp_id": "okta-1",
            "idp_name": "Okta",
            "identity_id": "idnt_abc123",
            "client_ip": "203.0.113.9",
        }
        fake_redis = MagicMock()
        fake_redis.get = MagicMock(return_value=json.dumps(pending).encode())
        fake_redis.delete = MagicMock()

        fake_registry = MagicMock()
        fake_registry.get = MagicMock(return_value={"totp_secret": ""})  # not provisioned

        aw = MagicMock()

        req = _make_request(
            cookies={sso_routes._PENDING_2FA_COOKIE: "tok-123"},
            body={"totp_code": "123456"},
        )

        with patch.object(sso_routes, "_redis", return_value=fake_redis), \
             patch.object(sso_routes.backoffice_state, "identity_registry", fake_registry), \
             patch.object(sso_routes.backoffice_state, "audit_writer", aw):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await sso_routes.sso_2fa_verify(req)
            assert exc.value.status_code == 403
            assert exc.value.detail["error"] == "totp_not_provisioned"

        aw.write.assert_called_once()
        event = aw.write.call_args[0][0]
        assert type(event).__name__ == "SSOLoginFailureEvent"
        assert event.failure_reason == "totp_not_provisioned"
        assert event.idp_id == "okta-1"
        assert event.idp_name == "Okta"

        # Pending token must still be consumed (fail-closed) regardless of audit.
        fake_redis.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_totp_not_provisioned_audit_failure_never_blocks_deny(self):
        """Audit is best-effort — a broken audit_writer must never prevent
        the 403 from being raised."""
        from yashigani.backoffice.routes import sso as sso_routes

        pending = {"idp_id": "okta-1", "idp_name": "Okta", "identity_id": "idnt_abc123"}
        fake_redis = MagicMock()
        fake_redis.get = MagicMock(return_value=json.dumps(pending).encode())

        fake_registry = MagicMock()
        fake_registry.get = MagicMock(return_value={"totp_secret": ""})

        broken_writer = MagicMock()
        broken_writer.write = MagicMock(side_effect=RuntimeError("audit sink down"))

        req = _make_request(
            cookies={sso_routes._PENDING_2FA_COOKIE: "tok-123"},
            body={"totp_code": "123456"},
        )

        with patch.object(sso_routes, "_redis", return_value=fake_redis), \
             patch.object(sso_routes.backoffice_state, "identity_registry", fake_registry), \
             patch.object(sso_routes.backoffice_state, "audit_writer", broken_writer):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await sso_routes.sso_2fa_verify(req)
            assert exc.value.status_code == 403
            assert exc.value.detail["error"] == "totp_not_provisioned"

    @pytest.mark.asyncio
    async def test_provisioned_identity_does_not_hit_this_branch(self):
        """Sanity: an identity WITH a totp_secret must proceed past this
        guard (reach TOTP verification) rather than being denied here."""
        from yashigani.backoffice.routes import sso as sso_routes

        pending = {"idp_id": "okta-1", "idp_name": "Okta", "identity_id": "idnt_abc123"}
        fake_redis = MagicMock()
        fake_redis.get = MagicMock(return_value=json.dumps(pending).encode())

        fake_registry = MagicMock()
        fake_registry.get = MagicMock(return_value={
            "totp_secret": "JBSWY3DPEHPK3PXP", "totp_algorithm": "SHA256",
        })

        aw = MagicMock()
        req = _make_request(
            cookies={sso_routes._PENDING_2FA_COOKIE: "tok-123"},
            body={"totp_code": "000000"},  # deliberately wrong — exercises the OTHER branch
        )

        with patch.object(sso_routes, "_redis", return_value=fake_redis), \
             patch.object(sso_routes.backoffice_state, "identity_registry", fake_registry), \
             patch.object(sso_routes.backoffice_state, "audit_writer", aw), \
             patch("yashigani.auth.totp.verify_totp", return_value=False):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc:
                await sso_routes.sso_2fa_verify(req)
            # Must reach the totp_verification_failed branch, NOT totp_not_provisioned.
            assert exc.value.detail["error"] == "invalid_totp_code"

        aw.write.assert_called_once()
        event = aw.write.call_args[0][0]
        assert event.failure_reason == "totp_verification_failed"
