# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — LAURA-V50-014 (Critical, fail-OPEN bypass): in a live-onboard-
only deploy (YASHIGANI_MCP_SERVERS empty at BOOT — the normal demo/
production topology), ``gateway/entrypoint.py`` built the McpBrokerRegistry
(with the SEAM-1d-07 durable-store lazy-load correctly attached) and then
DISCARDED it — ``_mcp_registry = None`` — because
``len(_mcp_registry) > 0`` was False (nothing had been onboarded/requested
YET this process lifetime). ``mcp_broker_registry=None`` on gateway state
meant ``gateway/proxy.py``'s catch-all NEVER intercepted ``/mcp/*``
(``if mcp_broker_registry is not None and norm_path.startswith("/mcp/")``)
— EVERY ``/mcp/*`` request (a real onboarded server AND a garbage name)
fell through to the generic upstream-forward and was blindly proxied to
``YASHIGANI_UPSTREAM_URL``. None of ``_identity_verified`` /
``_instance_identified`` / ``_grant_ok`` / ``_envelope_unchanged`` ever
evaluated. Live proof (Laura, 2026-07-28): ``tools/call`` to a never-
onboarded name returned 200; ``GET /mcp/health`` returned
``{"status":"error","detail":"mcp_not_configured"}``.

Fix under test (Tom, 2026-07-28):
  A. ``mcp/router.py`` — ``create_mcp_router(..., opa_url=...)`` /
     ``_opa_health_check()``: ``/mcp/health`` no longer REQUIRES a
     "representative" broker instance (McpBrokerRegistry.all_brokers()[0]
     — impossible to obtain before any server has been lazily built) —
     falls back to a direct OPA reachability check.
  B. ``gateway/entrypoint.py`` — the MCP wiring block is gated on
     ``_mcp_jwks_store is not None`` (== "is MCP genuinely configured",
     true whenever boot-list entries exist OR the durable registry/Redis
     is wired) INSTEAD OF ``len(_mcp_registry) > 0`` — the registry is
     NEVER discarded to None once configured.
  C. ``gateway/proxy.py``'s belt-and-suspenders ``_gateway_mcp_health_guard``
     — same "registry present, zero brokers built yet" fallback as (A).

This suite proves the Python-level FIX at both the wiring-decision level
(B is inherently untestable as a pure unit — entrypoint.py is a startup
monolith — so this suite instead proves the INVARIANT the fix restores:
once ``mcp_broker_registry`` is a real, non-None registry object — EXACTLY
what entrypoint.py now always passes when MCP is configured, per (B) —
the catch-all (gateway/proxy.py, full ``create_gateway_app`` +
``TestClient``) intercepts ``/mcp/*``, denies a fake name (never proxies
upstream), and reaches ``McpBroker.enforce()`` / ``query_mcp_decision()``
(the four-gate) for a real, live-imported server) AND the router-level
fix (A/C) directly.
"""
from __future__ import annotations

import json
import os
import textwrap
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from yashigani.mcp._durable_registry import DurableMcpRegistryStore
from yashigani.mcp._id_store import McpIdStore
from yashigani.mcp.registry import build_registry_from_env

_TENANT = "default"
_SERVER = "cloud9-demo"
_FAKE_SERVER = "totally-fake-nonexistent-server-xyz123"
_DIGEST = "sha256:" + "ab12" * 16


class _FakeRedis:
    """Minimal in-memory Redis stand-in — same shape used across the mcp/
    _id_store + _durable_registry unit/regression suites."""

    def __init__(self):
        self.kv: dict = {}
        self.sets: dict = {}

    def set(self, k, v):
        self.kv[k] = v.encode() if isinstance(v, str) else v

    def get(self, k):
        return self.kv.get(k)

    def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    def sadd(self, k, m):
        self.sets.setdefault(k, set()).add(m.encode() if isinstance(m, str) else m)

    def srem(self, k, m):
        self.sets.get(k, set()).discard(m.encode() if isinstance(m, str) else m)

    def smembers(self, k):
        return set(self.sets.get(k, set()))


def _live_imported_descriptor(mcp_id: str) -> dict:
    """Shape mcp_onboard.py step 4b writes for a live-imported server."""
    return {
        "agent_name": _SERVER,
        "upstream_url": "https://caddy:9443/mcp/%s/%s" % (_TENANT, _SERVER),
        "tenant_id": _TENANT,
        "is_filesystem_agent": False,
        "is_git_agent": False,
        "cert_fingerprint": "sha256:deadbeef",
        "spiffe_id": "spiffe://yashigani-local.yashigani.internal/agents/%s/%s/nhi_x"
        % (_TENANT, _SERVER),
        "svid_instance_id": "nhi_x",
        "image_digest": "",
        "mcp_id": mcp_id,
    }


def _build_registry_boot_empty(redis: _FakeRedis):
    """Reproduce EXACTLY what gateway/entrypoint.py does on a fresh boot
    with YASHIGANI_MCP_SERVERS="" (empty) AND a healthy Redis (durable
    store wired) — the scenario LAURA-V50-014 targets."""
    mcp_id_store = McpIdStore(redis)
    durable_store = DurableMcpRegistryStore(redis)
    preminted = mcp_id_store.get_or_mint(_SERVER)  # mirrors mcp_onboard.py's approve-time mint
    durable_store.put(_TENANT, _SERVER, _live_imported_descriptor(preminted))

    registry, jwks_store = build_registry_from_env(
        opa_url="https://policy:8181",
        mcp_id_store=mcp_id_store,
        durable_store=durable_store,
    )
    return registry, jwks_store, preminted


# ---------------------------------------------------------------------------
# A. mcp/router.py — /mcp/health without a representative broker instance
# ---------------------------------------------------------------------------


class TestHealthProbeWithoutBroker:
    @pytest.mark.asyncio
    async def test_health_ok_via_opa_url_fallback_when_broker_none(self):
        """Core LAURA-V50-014 router fix: broker=None (no server lazily
        built yet) + opa_url set -> /mcp/health reports CONFIGURED
        (queries OPA directly), never mcp_broker_not_configured."""
        from yashigani.mcp._jwks import JwksStore
        from yashigani.mcp._jwt import McpJwtIssuer
        from yashigani.mcp.router import create_mcp_router

        jwks_store = JwksStore(primary_issuer=McpJwtIssuer(tenant_id=_TENANT))
        mcp_router = create_mcp_router(jwks_store, broker=None, opa_url="https://policy:8181")

        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(mcp_router)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=cm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/mcp/health")

        assert resp.status_code == 200, resp.text
        assert resp.json() == {"status": "ok", "opa": "healthy"}

    def test_health_still_reports_unconfigured_when_neither_broker_nor_opa_url(self):
        """Backward compatible: broker=None AND opa_url=None (genuinely
        unconfigured) -> 503 mcp_broker_not_configured (unchanged)."""
        from yashigani.mcp._jwks import JwksStore
        from yashigani.mcp._jwt import McpJwtIssuer
        from yashigani.mcp.router import create_mcp_router

        jwks_store = JwksStore(primary_issuer=McpJwtIssuer(tenant_id=_TENANT))
        mcp_router = create_mcp_router(jwks_store, broker=None, opa_url=None)

        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(mcp_router)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/mcp/health")
        assert resp.status_code == 503
        assert resp.json()["detail"] == "mcp_broker_not_configured"


# ---------------------------------------------------------------------------
# B. Registry always attached — the wiring invariant entrypoint.py restores
# ---------------------------------------------------------------------------


class TestRegistryNeverDiscardedOnEmptyBootList:
    def test_is_mcp_configured_true_on_empty_boot_list_with_durable_store(self):
        """Reproduces the EXACT gateway startup condition that used to
        trigger `_mcp_registry = None`: YASHIGANI_MCP_SERVERS empty AND a
        durable-store descriptor exists (live-imported, not yet lazily
        loaded this process lifetime) -> len(registry) == 0 at this
        instant, but build_registry_from_env's jwks_store is non-None
        (MCP IS configured). entrypoint.py now gates registry attachment
        on is_mcp_configured(registry, jwks_store) instead of the old
        inline `len(registry) > 0 and jwks_store is not None`."""
        from yashigani.mcp.registry import is_mcp_configured

        redis = _FakeRedis()
        registry, jwks_store, _ = _build_registry_boot_empty(redis)

        assert len(registry) == 0, (
            "sanity: nothing has been lazily built yet — this is the exact "
            "instant the pre-fix code discarded the registry"
        )
        assert jwks_store is not None, "MCP is configured (durable store wired)"
        assert is_mcp_configured(registry, jwks_store) is True

    def test_old_inline_predicate_would_have_discarded_the_registry(self):
        """Side-by-side proof of the bug vs the fix, for the SAME inputs
        that a live-onboard-only deployment produces at boot: the OLD
        inline condition (`len(registry) > 0 and jwks_store is not None`,
        entrypoint.py pre-fix) evaluates False here -> `_mcp_registry =
        None` -> gateway/proxy.py's catch-all NEVER intercepts /mcp/*
        (LAURA-V50-014). The FIX's predicate (is_mcp_configured) evaluates
        True for the identical inputs -> the registry is never discarded."""
        from yashigani.mcp.registry import is_mcp_configured

        redis = _FakeRedis()
        registry, jwks_store, _ = _build_registry_boot_empty(redis)

        _old_buggy_condition = len(registry) > 0 and jwks_store is not None
        assert _old_buggy_condition is False, (
            "this IS the LAURA-V50-014 bug condition — the pre-fix code "
            "discarded a genuinely-configured registry right here"
        )
        assert is_mcp_configured(registry, jwks_store) is True, (
            "the fix must keep the registry attached for the EXACT same "
            "inputs the old condition wrongly discarded"
        )

    def test_is_mcp_configured_false_when_genuinely_unconfigured(self):
        """No boot-list entries AND no durable store (Redis unavailable)
        -> build_registry_from_env returns jwks_store=None -> the feature
        is genuinely off; is_mcp_configured must report False (unchanged
        pre-fix behaviour for this residual case)."""
        from yashigani.mcp.registry import build_registry_from_env, is_mcp_configured

        registry, jwks_store = build_registry_from_env(opa_url="https://policy:8181")
        assert jwks_store is None
        assert is_mcp_configured(registry, jwks_store) is False


# ---------------------------------------------------------------------------
# C. End-to-end (full create_gateway_app + TestClient): fake name denied,
#    real granted call reaches the four-gate — exactly as entrypoint.py now
#    wires it (mcp_broker_registry=<the registry from B>, never None).
# ---------------------------------------------------------------------------


def _minimal_gateway_app(mcp_broker_registry, mcp_jwks_store):
    """Build the gateway app EXACTLY as entrypoint.py now wires it for the
    empty-boot-list / live-onboard-only topology: mcp_broker_registry is
    the real (possibly len()==0) registry object, never None."""
    from yashigani.gateway.proxy import GatewayConfig, create_gateway_app
    from yashigani.mcp.router import create_mcp_router

    cfg = GatewayConfig(
        upstream_base_url="http://unreachable-demo-mcp-upstream-test:9999",
        opa_url="https://policy:8181",
    )
    representative_broker = (
        mcp_broker_registry.all_brokers()[0] if len(mcp_broker_registry) > 0 else None
    )
    info_router = create_mcp_router(
        mcp_jwks_store, representative_broker, opa_url=cfg.opa_url,
    )
    inspection_pipeline = MagicMock()
    inspection_pipeline.inspect.return_value = MagicMock(action="ALLOW", sanitized_content=None)

    app = create_gateway_app(
        config=cfg,
        inspection_pipeline=inspection_pipeline,
        chs=MagicMock(),
        audit_writer=MagicMock(),
        extra_routers=[info_router],
        mcp_broker_registry=mcp_broker_registry,
        mcp_jwks_store=mcp_jwks_store,
    )
    return app, cfg


class TestFakeNameDeniedRealCallReachesFourGate:
    def test_health_reports_configured_on_empty_boot_list(self):
        """The exact live proof point Laura's finding cites:
        GET /mcp/health must NOT report mcp_not_configured once the
        registry is (correctly) always attached, even with zero brokers
        built yet this process lifetime."""
        redis = _FakeRedis()
        registry, jwks_store, _ = _build_registry_boot_empty(redis)
        app, _ = _minimal_gateway_app(registry, jwks_store)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=mock_client)
        cm.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=cm):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get("/mcp/health")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body.get("status") == "ok", (
            "LAURA-V50-014: /mcp/health must report configured/healthy, "
            f"got: {body}"
        )

    def test_fake_agent_name_is_denied_not_proxied_upstream(self):
        """THE core LAURA-V50-014 proof: a tools/call to a never-onboarded
        garbage server name must be intercepted and DENIED (404, registry
        miss) — NEVER 200-proxied to YASHIGANI_UPSTREAM_URL. The upstream
        base_url in this fixture is deliberately unreachable
        (unreachable-demo-mcp-upstream-test:9999) — if the fix regressed
        and this fell through to the generic proxy, httpx would raise a
        connection error and the test would see a 502/500 from the
        FORWARDING attempt, NOT the clean 404 MCP_SERVER_NOT_FOUND the
        broker registry path returns. Either way it must NEVER be 200."""
        redis = _FakeRedis()
        registry, jwks_store, _ = _build_registry_boot_empty(redis)
        app, _ = _minimal_gateway_app(registry, jwks_store)

        with patch(
            "yashigani.gateway.proxy._opa_check",
            new=AsyncMock(return_value=True),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/mcp/%s" % _FAKE_SERVER,
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "probe"}},
                },
            )

        assert resp.status_code != 200, (
            "LAURA-V50-014 REGRESSION: a never-onboarded agent name was "
            f"NOT denied — got {resp.status_code}: {resp.text!r}. This is "
            "the exact fail-open the finding proved live (blind proxy to "
            "YASHIGANI_UPSTREAM_URL)."
        )
        assert resp.status_code == 404
        assert resp.json().get("error") == "MCP_SERVER_NOT_FOUND"

    def test_real_granted_call_reaches_the_four_gate(self):
        """A tools/call to the REAL live-imported server must reach
        McpBroker.enforce() -> query_mcp_decision() (the OPA four-gate:
        _instance_identified / _grant_ok / _envelope_unchanged /
        identity.verified) — proven by asserting the OPA query mock was
        actually invoked, with input.target.mcp_id == the server's minted
        id (not proxied around it, which is what LAURA-V50-014 found)."""
        from yashigani.mcp._opa import OpaDecisionResult

        redis = _FakeRedis()
        registry, jwks_store, minted_mcp_id = _build_registry_boot_empty(redis)
        app, _ = _minimal_gateway_app(registry, jwks_store)

        allow_result = OpaDecisionResult(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None, elapsed_ms=1,
        )
        query_mock = AsyncMock(return_value=allow_result)

        with (
            patch("yashigani.gateway.proxy._opa_check", new=AsyncMock(return_value=True)),
            patch("yashigani.mcp.broker.query_mcp_decision", new=query_mock),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            client.post(
                "/mcp/%s" % _SERVER,
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "probe"}},
                },
            )
            # Note: no status-code assertion here on purpose — after
            # broker.enforce() allows, dispatch_mcp_call() forwards to
            # upstream_url (deliberately unreachable in this fixture), so
            # the FINAL response is a transport-layer error (502/500), NOT
            # a clean 200. That is expected and irrelevant to what this
            # test proves: whether the four-gate was REACHED at all.

        assert query_mock.await_count >= 1, (
            "LAURA-V50-014: the real, live-imported server's tools/call "
            "never reached McpBroker.enforce() / query_mcp_decision() — "
            "the request was intercepted BEFORE the four-gate could "
            "evaluate it (the exact bug this fix closes)."
        )
        _, call_kwargs = query_mock.await_args
        assert call_kwargs.get("mcp_id") == minted_mcp_id, (
            "the OPA query must carry the SAME stable mcp_id the durable "
            "registry resolved — proves the four-gate saw the correctly-"
            "identified instance, not an empty/garbage target"
        )
