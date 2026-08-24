"""
Regression tests: P8 pin enforcement WIRED INTO enforce() + runtime forward paths.

Gap closed in v3.1:
  broker.verify_upstream() was fully implemented (FIX-P8-002) but NEVER CALLED
  in the live forward path.  This file proves the wiring is real:

  - enforce() (tools/call path) calls verify_upstream() BEFORE issuing a JWT
    → mismatch in prod env → BrokerDecision.allow=False, deny_reason=upstream_pin_mismatch
  - dispatch_mcp_call() (session/notification/passthrough) calls verify_upstream()
    BEFORE transport.forward()
    → mismatch in prod env → 403 UPSTREAM_PIN_DENIED

These tests are the regression guard: if verify_upstream() is removed from
enforce() or any runtime forward path, these fail.

YSG-RISK-056 / P8 / v3.1 wiring.
"""
from __future__ import annotations

import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REAL_FP = "a1b2c3d4" * 8    # 64-char SHA-256 hex — matching pin
MITM_FP = "deadbeef" * 8    # different — MITM / mismatch

SERVER_ID = "github-mcp"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def p384_key():
    return ec.generate_private_key(SECP384R1())


@pytest.fixture
def issuer(p384_key):
    from yashigani.mcp._jwt import McpJwtIssuer
    return McpJwtIssuer(tenant_id="tenant1", private_key=p384_key, chain_max_depth=3)


@pytest.fixture
def nonce_store():
    from yashigani.mcp._nonce import InMemoryNonceStore
    return InMemoryNonceStore()


@pytest.fixture
def mock_writer():
    writer = MagicMock()
    writer.write = MagicMock()
    return writer


def _make_broker_with_fp_pin(
    issuer: Any,
    nonce_store: Any,
    mock_writer: Any,
    fp: str = REAL_FP,
    server_id: str = SERVER_ID,
) -> Any:
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._upstream_pin import UpstreamPinConfig, PinMode

    pin = UpstreamPinConfig(
        server_id=server_id,
        host="mcp.github.example.com",
        port=443,
        pin_mode=PinMode.CERT_FINGERPRINT,
        cert_fingerprint_sha256=fp,
    )
    config = McpBrokerConfig(
        opa_url="http://localhost:8181",
        tenant_id="tenant1",
        issuer=issuer,
        nonce_store=nonce_store,
        audit_writer=mock_writer,
        upstream_pin_configs=[pin],
    )
    return McpBroker(config)


def _make_call_context(server_id: str = SERVER_ID) -> Any:
    """Build a minimal McpCallContext for a tools/call."""
    from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
    return McpCallContext(
        tenant_id="tenant1",
        agent_name=server_id,
        user_id="user1",
        posture=McpPosture.MCP_B,
        posture_binding=PostureBinding.for_posture(McpPosture.MCP_B),
        action="mcp.tools.call",
        tool_name="run_tests",
        call_id="test-call-1",
        request_id="test-req-1",
        server_id=server_id,
    )


# ---------------------------------------------------------------------------
# Module-level helper: patch the paths enforce() needs cleared to reach Step 2f.
#
# broker.enforce() steps before Step 2f (pin check):
#   2a: upstream JWT verify (MCP_C only — skipped for MCP_B)
#   2:  OPA query                 → patch query_mcp_decision
#   2b: filesystem gate           → is_filesystem_agent=False, skipped
#   2c: git gate                  → is_git_agent=False, skipped
#   2d: client-policy gate        → patch yashigani.gateway._client_enforce.evaluate_client_policies
#   2e: capability-envelope gate  → patch broker._check_capability_envelope
#   2f: [P8] pin check            → THIS IS WHAT WE WANT TO REACH
# ---------------------------------------------------------------------------


def _opa_allow_result() -> Any:
    """Return an OpaDecisionResult that allows the call."""
    from yashigani.mcp._opa import OpaDecisionResult
    return OpaDecisionResult(
        allow=True,
        deny_reason="ok",
        redact_args=set(),
        audit_capture=False,
        rate_limit_key=None,
        elapsed_ms=1,
        error=None,
    )


# ---------------------------------------------------------------------------
# Class 1: enforce() wiring
# ---------------------------------------------------------------------------

class TestP8WiredInEnforce:
    """
    Prove that broker.enforce() calls verify_upstream() before returning allow=True.

    The regression: previously enforce() completed ALL OPA+envelope gates and
    issued the JWT without ever touching verify_upstream() — so a pinned server
    with a mismatched cert would still get an allowed decision.  That's now fixed.
    """

    @pytest.mark.asyncio
    async def test_enforce_calls_verify_upstream_on_allow(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        On a call that OPA would allow, enforce() must call verify_upstream().

        We spy on verify_upstream to confirm it is invoked.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        ctx = _make_call_context()

        from yashigani.mcp._upstream_pin import PinVerificationResult

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_opa_allow_result()),
        ), patch(
            "yashigani.gateway._client_enforce.evaluate_client_policies",
            new=AsyncMock(return_value={"allow": True}),
        ), patch.object(
            broker, "_check_capability_envelope", new=AsyncMock(return_value=None)
        ), patch.object(
            broker, "_emit_audit", new=AsyncMock()
        ), patch.object(
            broker, "verify_upstream", wraps=broker.verify_upstream
        ) as spy_verify, patch(
            "yashigani.mcp._upstream_pin.verify_upstream_pin",
            return_value=PinVerificationResult(server_id=SERVER_ID, matched=True, reason="ok"),
        ), patch.dict(os.environ, {"YASHIGANI_ENV": "development"}):
            decision = await broker.enforce(ctx)

        # verify_upstream MUST have been called (this was the gap).
        spy_verify.assert_called_once_with(SERVER_ID)
        assert decision.allow is True, f"Expected allow, got deny: {decision.deny_reason}"

    @pytest.mark.asyncio
    async def test_enforce_denies_on_pin_mismatch_in_prod(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        REGRESSION: in prod env, pin mismatch inside enforce() must return
        BrokerDecision.allow=False with deny_reason='upstream_pin_mismatch'.

        Previously enforce() never called verify_upstream(), so a MITM cert
        would be undetected and the call would be allowed.

        Note: _check_connection_permit is patched to return None (allowed) so
        FIX-005 (permission_store_unavailable) does not fire before the P8 gate.
        This test's focus is pin verification; permission-store behaviour is
        tested in test_fix005_permission_store_failclosed.py.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        ctx = _make_call_context()

        from yashigani.mcp._upstream_pin import PinVerificationResult

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_opa_allow_result()),
        ), patch(
            "yashigani.gateway._client_enforce.evaluate_client_policies",
            new=AsyncMock(return_value={"allow": True}),
        ), patch.object(
            broker, "_check_capability_envelope", new=AsyncMock(return_value=None)
        ), patch.object(
            broker, "_emit_audit", new=AsyncMock()
        ), patch.object(
            broker, "_emit_upstream_pin_event"
        ), patch.object(
            # FIX-005: permission_store is None (no Redis in test env) → skip
            # the permission-store fail-closed gate so the test reaches P8.
            broker, "_check_connection_permit", return_value=None
        ), patch(
            # Simulate MITM: live cert returns MITM_FP instead of REAL_FP.
            "yashigani.mcp._upstream_pin.verify_upstream_pin",
            return_value=PinVerificationResult(
                server_id=SERVER_ID,
                matched=False,
                reason="MCP_UPSTREAM_CERT_PIN_MISMATCH",
            ),
        ), patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            decision = await broker.enforce(ctx)

        assert decision.allow is False, "Pin mismatch must deny the call"
        assert decision.deny_reason == "upstream_pin_mismatch", (
            f"Expected deny_reason='upstream_pin_mismatch', got {decision.deny_reason!r}"
        )

    @pytest.mark.asyncio
    async def test_enforce_denies_when_no_pin_config_in_prod(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        In prod, a server with NO pin config registered must be denied
        (pin_not_configured → ConnectionError → deny).

        Note: _check_connection_permit is patched to return None (allowed) so
        FIX-005 (permission_store_unavailable) does not fire before the P8 gate.
        """
        # Broker has "other-server" pinned; ctx targets "github-mcp" (no pin).
        broker = _make_broker_with_fp_pin(
            issuer, nonce_store, mock_writer, server_id="other-server"
        )
        ctx = _make_call_context(server_id="github-mcp")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_opa_allow_result()),
        ), patch(
            "yashigani.gateway._client_enforce.evaluate_client_policies",
            new=AsyncMock(return_value={"allow": True}),
        ), patch.object(
            broker, "_check_capability_envelope", new=AsyncMock(return_value=None)
        ), patch.object(
            broker, "_emit_audit", new=AsyncMock()
        ), patch.object(
            # FIX-005: permission_store is None (no Redis in test env) → skip
            # the permission-store fail-closed gate so the test reaches P8.
            broker, "_check_connection_permit", return_value=None
        ), patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            decision = await broker.enforce(ctx)

        assert decision.allow is False
        assert decision.deny_reason == "upstream_pin_mismatch"

    @pytest.mark.asyncio
    async def test_enforce_pin_ok_proceeds_to_jwt_issuance(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        When pin matches (prod), enforce() proceeds past Step 2f and issues JWT.
        The returned decision must carry an issued_jwt.

        Patch verify_upstream_pin at the broker module's local binding so the
        mock is seen by broker.verify_upstream() (which uses the local name).
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        ctx = _make_call_context()

        from yashigani.mcp._upstream_pin import PinVerificationResult

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=_opa_allow_result()),
        ), patch(
            "yashigani.gateway._client_enforce.evaluate_client_policies",
            new=AsyncMock(return_value={"allow": True}),
        ), patch.object(
            broker, "_check_capability_envelope", new=AsyncMock(return_value=None)
        ), patch.object(
            broker, "_emit_audit", new=AsyncMock()
        ), patch.object(
            # FIX-005: permission_store is None (no Redis in test env) → skip
            # the permission-store fail-closed gate so the test reaches P8.
            broker, "_check_connection_permit", return_value=None
        ), patch(
            # Must patch at the LOCAL binding in broker.py's namespace.
            # broker.py does 'from ._upstream_pin import verify_upstream_pin'
            # so patching the source module doesn't affect the local name.
            "yashigani.mcp.broker.verify_upstream_pin",
            return_value=PinVerificationResult(server_id=SERVER_ID, matched=True, reason="ok"),
        ), patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            decision = await broker.enforce(ctx)

        assert decision.allow is True, f"Expected allow; got {decision.deny_reason}"
        assert decision.issued_jwt is not None, "JWT must be issued on allow"

    @pytest.mark.asyncio
    async def test_enforce_skips_pin_when_no_server_id(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        If ctx.server_id is empty (''), Step 2f is skipped (no pin to check).
        The call goes through OPA gating; OPA deny is the result.
        """
        from yashigani.mcp._opa import OpaDecisionResult

        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer)
        ctx = _make_call_context(server_id="")

        opa_deny = OpaDecisionResult(
            allow=False,
            deny_reason="policy_deny",
            redact_args=set(),
            audit_capture=False,
            rate_limit_key=None,
            elapsed_ms=1,
            error=None,
        )

        verify_call_count = 0
        original_verify = broker.verify_upstream

        def spy_verify(sid: str, **kw: object) -> object:
            nonlocal verify_call_count
            verify_call_count += 1
            return original_verify(sid, **kw)

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=opa_deny),
        ), patch.object(
            broker, "_emit_audit", new=AsyncMock()
        ), patch.object(broker, "verify_upstream", side_effect=spy_verify):
            decision = await broker.enforce(ctx)

        # Pin check skipped (server_id=''), OPA deny is the decision.
        assert verify_call_count == 0, "verify_upstream must not be called when server_id=''"
        assert decision.allow is False
        assert decision.deny_reason == "policy_deny"


# ---------------------------------------------------------------------------
# Class 2: runtime router wiring (session / notification / passthrough)
# ---------------------------------------------------------------------------

class TestP8WiredInRuntime:
    """
    Prove that dispatch_mcp_call() calls broker.verify_upstream() before
    non-enforce() forward paths (session, notification, passthrough).

    These paths bypass broker.enforce() so the pin check must be explicit in
    the router.  Regression = pin not checked on these paths.
    """

    def _make_registry(self, broker: Any, upstream_url: str = "http://mcp-bridge:8080") -> Any:
        """Build a minimal mock registry that returns (broker, server_cfg)."""
        server_cfg = MagicMock()
        server_cfg.upstream_url = upstream_url
        server_cfg.tenant_id = "tenant1"

        registry = MagicMock()
        registry.get.return_value = (broker, server_cfg)
        return registry

    def _make_request(self, method: str, body: dict) -> Any:
        """Build a mock FastAPI Request for a given MCP method."""
        import json as _json

        body_bytes = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()

        request = MagicMock()
        request.headers = {"x-forwarded-user": "user1"}
        request.body = AsyncMock(return_value=body_bytes)
        return request

    @pytest.mark.asyncio
    async def test_session_method_denied_on_pin_mismatch_prod(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        tools/list (session method) in prod with pin mismatch → 403
        UPSTREAM_PIN_DENIED, NOT forwarded to upstream.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        registry = self._make_registry(broker)
        request = self._make_request("tools/list", {})

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}), \
             patch("yashigani.mcp._upstream_pin.verify_upstream_pin") as mock_pin_fn:
            from yashigani.mcp._upstream_pin import PinVerificationResult
            mock_pin_fn.return_value = PinVerificationResult(
                server_id=SERVER_ID, matched=False, reason="MCP_UPSTREAM_CERT_PIN_MISMATCH"
            )
            from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
            response = await dispatch_mcp_call(
                agent_name=SERVER_ID,
                request=request,
                registry=registry,
            )

        assert response.status_code == 403, (
            f"Expected 403 on pin mismatch for session method, got {response.status_code}"
        )
        import json as _json
        body = _json.loads(response.body)
        assert body.get("error") == "UPSTREAM_PIN_DENIED"
        assert body.get("deny_reason") == "upstream_pin_mismatch"

    @pytest.mark.asyncio
    async def test_notification_denied_on_pin_mismatch_prod(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        A notification (no id) in prod with pin mismatch → 403, not forwarded.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        registry = self._make_registry(broker)

        import json as _json
        notif_bytes = _json.dumps({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {},
        }).encode()  # No "id" field → is_notification=True
        request = MagicMock()
        request.headers = {"x-forwarded-user": "user1"}
        request.body = AsyncMock(return_value=notif_bytes)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}), \
             patch("yashigani.mcp._upstream_pin.verify_upstream_pin") as mock_pin_fn:
            from yashigani.mcp._upstream_pin import PinVerificationResult
            mock_pin_fn.return_value = PinVerificationResult(
                server_id=SERVER_ID, matched=False, reason="MCP_UPSTREAM_CERT_PIN_MISMATCH"
            )
            from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
            response = await dispatch_mcp_call(
                agent_name=SERVER_ID,
                request=request,
                registry=registry,
            )

        assert response.status_code == 403
        body = _json.loads(response.body)
        assert body.get("error") == "UPSTREAM_PIN_DENIED"

    @pytest.mark.asyncio
    async def test_passthrough_denied_on_pin_mismatch_prod(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        An unknown/passthrough method in prod with pin mismatch → 403.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        registry = self._make_registry(broker)
        request = self._make_request("custom/unknownMethod", {})

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}), \
             patch("yashigani.mcp._upstream_pin.verify_upstream_pin") as mock_pin_fn:
            from yashigani.mcp._upstream_pin import PinVerificationResult
            mock_pin_fn.return_value = PinVerificationResult(
                server_id=SERVER_ID, matched=False, reason="MCP_UPSTREAM_CERT_PIN_MISMATCH"
            )
            from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
            response = await dispatch_mcp_call(
                agent_name=SERVER_ID,
                request=request,
                registry=registry,
            )

        import json as _json
        assert response.status_code == 403
        body = _json.loads(response.body)
        assert body.get("error") == "UPSTREAM_PIN_DENIED"

    @pytest.mark.asyncio
    async def test_session_pin_ok_does_not_return_pin_denied(
        self, issuer, nonce_store, mock_writer
    ) -> None:
        """
        When pin matches (prod), session method must NOT return UPSTREAM_PIN_DENIED.
        The pin check passes → proceed to JWT issuance / forward (we mock
        the transport to avoid needing a live upstream).
        """
        from yashigani.mcp._types import McpPosture, PostureBinding
        from yashigani.mcp._upstream_pin import PinVerificationResult

        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)
        registry = self._make_registry(broker)
        request = self._make_request("tools/list", {})

        fake_upstream_response = '{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}'

        # Build a transport mock that handles BOTH the sync posture-derivation call
        # AND the async context manager forward call.
        mock_transport_instance = MagicMock()
        mock_transport_instance.derive_posture.return_value = (
            McpPosture.MCP_B,
            PostureBinding.for_posture(McpPosture.MCP_B),
        )
        mock_transport_instance.__aenter__ = AsyncMock(return_value=mock_transport_instance)
        mock_transport_instance.__aexit__ = AsyncMock(return_value=False)
        mock_transport_instance.forward = AsyncMock(return_value=fake_upstream_response)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}), \
             patch(
                 # Patch at broker.py's LOCAL binding — see test_enforce_pin_ok_proceeds_to_jwt_issuance
                 # for the rationale.  broker.verify_upstream() uses this local name.
                 "yashigani.mcp.broker.verify_upstream_pin",
                 return_value=PinVerificationResult(server_id=SERVER_ID, matched=True, reason="ok"),
             ), patch(
                 "yashigani.gateway.mcp_router_runtime.McpHttpTransport",
                 return_value=mock_transport_instance,
             ):
            from yashigani.gateway.mcp_router_runtime import dispatch_mcp_call
            response = await dispatch_mcp_call(
                agent_name=SERVER_ID,
                request=request,
                registry=registry,
            )

        # The pin was OK — must NOT return the pin-denied error shape.
        import json as _json
        if response.status_code == 403:
            body = _json.loads(response.body)
            assert body.get("error") != "UPSTREAM_PIN_DENIED", (
                "Pin-matched call must not return UPSTREAM_PIN_DENIED; "
                f"got status={response.status_code} body={body}"
            )
