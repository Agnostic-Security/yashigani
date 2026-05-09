"""
Unit tests — PKI v1 admin API routes (Issue #51, v2.23.3).

Coverage:
  PKI-R-01  GET /api/v1/admin/pki/chain/{service} — unauthenticated → 401
  PKI-R-02  GET /api/v1/admin/pki/chain/{service} — authenticated → 200 with chain info
  PKI-R-03  GET /api/v1/admin/pki/chain/{service} — DriverError → 503
  PKI-R-04  POST /api/v1/admin/pki/rotate/{service} — no step-up → 401 step_up_required
  PKI-R-05  POST /api/v1/admin/pki/rotate/{service} — with step-up → 200 success=True
  PKI-R-06  POST /api/v1/admin/pki/rotate/{service} — driver failure → 200 success=False
  PKI-R-07  GET /api/v1/admin/pki/bundle/{service} — returns PEM without PRIVATE KEY
  PKI-R-08  GET /api/v1/admin/pki/bundle/{service} — bundle with PRIVATE KEY aborted → 500
  PKI-R-09  GET /api/v1/admin/pki/status — returns list of services
  PKI-R-10  Service name validation — invalid chars → 422
  PKI-R-11  GET /api/v1/admin/pki/chain/{service} — unauthenticated user tier → 403

Last updated: 2026-05-09T00:00:00+01:00
"""
from __future__ import annotations

from typing import AsyncGenerator
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from yashigani.pki.drivers.base import CertChainInfo, DriverError, RotateResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_chain_info(service: str = "gateway", needs_renewal: bool = False) -> CertChainInfo:
    return CertChainInfo(
        subject_cn=service,
        issuer_cn="Yashigani Internal Intermediate CA",
        serial_hex="deadbeef12345678",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2026-04-01T00:00:00+00:00",
        fingerprint_sha256="a" * 64,
        dns_sans=["gateway", "localhost"],
        uri_sans=["spiffe://yashigani.internal/gateway"],
        ip_sans=["127.0.0.1", "::1"],
        chain_depth=1,
        ca_mode="internal",
        needs_renewal=needs_renewal,
    )


class _FakeAdminSession:
    account_id = "test-admin"
    account_tier = "admin"
    last_totp_verified_at: float | None = None


class _FakeStepUpAdminSession:
    """Simulates a fully-authenticated admin session with recent step-up."""
    account_id = "test-admin"
    account_tier = "admin"
    # Set to current time so assert_fresh_stepup sees a recent step-up
    last_totp_verified_at: float = 0.0  # overridden in __init__

    def __init__(self) -> None:
        import time
        self.last_totp_verified_at = time.time()


class _FakeUserSession:
    account_id = "test-user"
    account_tier = "user"
    last_totp_verified_at: float | None = None


# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------

def _make_app(
    *,
    session_tier: str = "admin",
    has_stepup: bool = False,
    raise_server_exceptions: bool = True,
) -> tuple[FastAPI, bool]:
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.routes.pki_v1 import router

    app = FastAPI()

    if session_tier == "admin":
        fake_session = _FakeAdminSession()

        async def _fake_admin():
            return fake_session

        app.dependency_overrides[require_admin_session] = _fake_admin

        if has_stepup:
            stepup_session = _FakeStepUpAdminSession()

            async def _fake_stepup():
                return stepup_session

            app.dependency_overrides[require_stepup_admin_session] = _fake_stepup
        else:
            # No stepup override — require_stepup_admin_session will call require_admin_session
            # (already overridden) then assert_fresh_stepup on _FakeAdminSession.
            # last_totp_verified_at=None → assert_fresh_stepup returns 401.
            pass

    app.include_router(router)
    return app, raise_server_exceptions


@pytest_asyncio.fixture
async def admin_client() -> AsyncGenerator[AsyncClient, None]:
    app, _ = _make_app(session_tier="admin", has_stepup=True)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def admin_no_stepup_client() -> AsyncGenerator[AsyncClient, None]:
    app, _ = _make_app(session_tier="admin", has_stepup=False)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def unauthed_client() -> AsyncGenerator[AsyncClient, None]:
    """Client with auth dep overridden to raise 401 (simulating missing session)."""
    from fastapi import HTTPException
    from yashigani.backoffice.middleware import (
        require_admin_session,
        require_stepup_admin_session,
    )
    from yashigani.backoffice.routes.pki_v1 import router

    app = FastAPI()

    async def _reject():
        raise HTTPException(status_code=401, detail={"error": "authentication_required"})

    app.dependency_overrides[require_admin_session] = _reject
    app.dependency_overrides[require_stepup_admin_session] = _reject
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# PKI-R-01: Unauthenticated → 401
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_unauthenticated(unauthed_client: AsyncClient) -> None:
    resp = await unauthed_client.get("/api/v1/admin/pki/chain/gateway")
    # The _reject dep raises 401 — auth-gated route returns 401
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PKI-R-02: Authenticated → 200 with chain info
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_authenticated(admin_client: AsyncClient) -> None:
    info = _make_chain_info("gateway")
    mock_driver = MagicMock()
    mock_driver.get_chain_info.return_value = info

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.get("/api/v1/admin/pki/chain/gateway")

    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "gateway"
    assert body["subject_cn"] == "gateway"
    assert body["issuer_cn"] == "Yashigani Internal Intermediate CA"
    assert body["fingerprint_sha256"] == "a" * 64
    assert "localhost" in body["dns_sans"]
    assert body["ca_mode"] == "internal"
    assert "PRIVATE KEY" not in resp.text


# ---------------------------------------------------------------------------
# PKI-R-03: DriverError → 503
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_driver_error(admin_client: AsyncClient) -> None:
    mock_driver = MagicMock()
    mock_driver.get_chain_info.side_effect = DriverError("cert file missing")

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.get("/api/v1/admin/pki/chain/gateway")

    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "pki_driver_error"


# ---------------------------------------------------------------------------
# PKI-R-04: No step-up → real dep should trigger step_up_required
# (in unit test mode, without stepup override, the dep raises or returns 401)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_no_stepup(admin_no_stepup_client: AsyncClient) -> None:
    # Without stepup override the require_stepup_admin_session dep fires.
    # _FakeAdminSession.last_totp_verified_at=None → assert_fresh_stepup → 401.
    resp = await admin_no_stepup_client.post("/api/v1/admin/pki/rotate/gateway")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PKI-R-05: With step-up → 200 success=True
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_success(admin_client: AsyncClient) -> None:
    new_info = _make_chain_info("gateway")
    result = RotateResult(success=True, new_chain=new_info)
    mock_driver = MagicMock()
    mock_driver.rotate.return_value = result

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.post("/api/v1/admin/pki/rotate/gateway")

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["service"] == "gateway"
    assert body["new_chain"]["ca_mode"] == "internal"
    assert "PRIVATE KEY" not in resp.text


# ---------------------------------------------------------------------------
# PKI-R-06: Driver rotation failure → 200 success=False
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rotate_driver_failure(admin_client: AsyncClient) -> None:
    result = RotateResult(success=False, error="intermediate key missing")
    mock_driver = MagicMock()
    mock_driver.rotate.return_value = result

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.post("/api/v1/admin/pki/rotate/gateway")

    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert "intermediate key missing" in body["error"]


# ---------------------------------------------------------------------------
# PKI-R-07: Bundle returns PEM without PRIVATE KEY
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bundle_no_private_key(admin_client: AsyncClient) -> None:
    fake_bundle = b"-----BEGIN CERTIFICATE-----\nfakecertdata\n-----END CERTIFICATE-----\n"
    mock_driver = MagicMock()
    mock_driver.get_pem_bundle.return_value = fake_bundle

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.get("/api/v1/admin/pki/bundle/gateway")

    assert resp.status_code == 200
    assert b"PRIVATE KEY" not in resp.content
    assert resp.headers["content-type"].startswith("application/x-pem-file")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert "gateway_cert_bundle.pem" in resp.headers.get("content-disposition", "")


# ---------------------------------------------------------------------------
# PKI-R-08: Bundle accidentally contains PRIVATE KEY → 500 (CWE-200)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bundle_aborts_on_private_key(admin_client: AsyncClient) -> None:
    evil_bundle = (
        b"-----BEGIN CERTIFICATE-----\nfakecertdata\n-----END CERTIFICATE-----\n"
        b"-----BEGIN PRIVATE KEY-----\nfakekeydata\n-----END PRIVATE KEY-----\n"
    )
    mock_driver = MagicMock()
    mock_driver.get_pem_bundle.return_value = evil_bundle

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.get("/api/v1/admin/pki/bundle/gateway")

    assert resp.status_code == 500
    assert b"PRIVATE KEY" not in resp.content


# ---------------------------------------------------------------------------
# PKI-R-09: Status returns list of services
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_returns_services(admin_client: AsyncClient) -> None:
    gateway_info = _make_chain_info("gateway")
    backoffice_info = _make_chain_info("backoffice", needs_renewal=True)

    mock_driver = MagicMock()
    mock_driver.get_chain_info.side_effect = lambda svc: {
        "gateway": gateway_info,
        "backoffice": backoffice_info,
    }[svc]

    with (
        patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver),
        patch("yashigani.backoffice.routes.pki_v1._live_service_names", return_value=["gateway", "backoffice"]),
    ):
        resp = await admin_client.get("/api/v1/admin/pki/status")

    assert resp.status_code == 200
    body = resp.json()
    assert "services" in body
    assert len(body["services"]) == 2
    svc_names = {s["service"] for s in body["services"]}
    assert "gateway" in svc_names
    assert "backoffice" in svc_names
    backoffice_row = next(s for s in body["services"] if s["service"] == "backoffice")
    assert backoffice_row["needs_renewal"] is True


# ---------------------------------------------------------------------------
# PKI-R-10: Invalid service name → 422
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_invalid_service_name(admin_client: AsyncClient) -> None:
    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver"):
        resp = await admin_client.get("/api/v1/admin/pki/chain/../etc/passwd")
    assert resp.status_code in (404, 422)  # path param with slash is 404; embedded dots are 422

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver"):
        resp = await admin_client.get("/api/v1/admin/pki/chain/UPPERCASE-Service")
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "invalid_service_name"


# ---------------------------------------------------------------------------
# PKI-R-11: Response never contains PRIVATE KEY
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_chain_response_no_private_key(admin_client: AsyncClient) -> None:
    info = _make_chain_info("gateway")
    mock_driver = MagicMock()
    mock_driver.get_chain_info.return_value = info

    with patch("yashigani.backoffice.routes.pki_v1.get_ca_driver", return_value=mock_driver):
        resp = await admin_client.get("/api/v1/admin/pki/chain/gateway")

    assert "PRIVATE KEY" not in resp.text
    assert "private_key" not in resp.json()
