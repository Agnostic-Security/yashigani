"""
Regression tests: LAURA-V250-P8 — upstream pin verification enforcement.

These tests are DERIVED DIRECTLY from Laura's PoC:
  - poc_p8_pin_verification.py (14 cases)

They validate the pin verification logic (verify_upstream_pin / broker.verify_upstream)
AND the new FIX-P8-002 inline enforcement (ConnectionError raised in prod/staging
on mismatch or missing pin config).

Fix references:
  FIX-P8-001 / LAURA-V250-P8 / YSG-RISK-056  (SPIFFE comment)
  FIX-P8-002 / LAURA-V250-P8 / YSG-RISK-056  (inline enforce in prod/staging)

v2.25.0 / P1 Phase-2 gate / Tom — 2026-05-29.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

REAL_FP = "a1b2c3d4" * 8         # 64-char SHA-256 hex
COLONED_FP = ":".join(REAL_FP[i:i+2] for i in range(0, 64, 2))
SPACED_FP = " ".join(REAL_FP[i:i+2] for i in range(0, 64, 2))
UPPER_PIN = REAL_FP.upper()
MITM_FP = "deadbeef" * 8         # different fingerprint
SHA1_FP = "aabbccdd" * 5         # 40-char — wrong length

SPIFFE_PIN = "spiffe://cluster.local/ns/mcp/sa/github-mcp"

CERT_PIN_MISMATCH_LABEL = "MCP_UPSTREAM_CERT_PIN_MISMATCH"


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
    from unittest.mock import MagicMock
    writer = MagicMock()
    writer.write = MagicMock()
    return writer


@pytest.fixture
def broker_no_pins(issuer, nonce_store, mock_writer):
    """Broker with no upstream pin configs registered."""
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    config = McpBrokerConfig(
        opa_url="http://localhost:8181",
        tenant_id="tenant1",
        issuer=issuer,
        nonce_store=nonce_store,
        audit_writer=mock_writer,
    )
    return McpBroker(config)


def _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp: str = REAL_FP, server_id: str = "github-mcp"):
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


def _make_broker_with_spiffe_pin(issuer, nonce_store, mock_writer, spiffe_id: str = SPIFFE_PIN):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp._upstream_pin import UpstreamPinConfig, PinMode
    pin = UpstreamPinConfig(
        server_id="github-mcp",
        host="mcp.github.example.com",
        port=443,
        pin_mode=PinMode.SPIFFE,
        spiffe_id=spiffe_id,
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


# ===========================================================================
# verify_upstream_pin unit cases (from poc_p8_pin_verification.py)
# ===========================================================================


class TestP8PinVerificationLogic:
    """
    Tests that mirror the 14 cases in Laura's poc_p8_pin_verification.py.
    Each case asserts (matched, reason_contains) from verify_upstream_pin().
    """

    def test_colon_format_pin_vs_raw_observed(self) -> None:
        """Colon-separated pin vs plain observed fingerprint normalises to match."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=COLONED_FP)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: REAL_FP)
        assert result.matched is True
        assert result.reason == "ok"

    def test_uppercase_pin_vs_lowercase_observed(self) -> None:
        """UPPERCASE pin matches lowercase observed (case-insensitive)."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=UPPER_PIN)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: REAL_FP.lower())
        assert result.matched is True
        assert result.reason == "ok"

    def test_space_separated_pin(self) -> None:
        """Space-separated pin normalises to match raw observed."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=SPACED_FP)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: REAL_FP)
        assert result.matched is True

    def test_mitm_different_fingerprint(self) -> None:
        """MITM attack: different fingerprint → matched=False + MISMATCH label."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=REAL_FP)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: MITM_FP)
        assert result.matched is False
        assert CERT_PIN_MISMATCH_LABEL in result.reason

    def test_empty_cert_fingerprint_sha256(self) -> None:
        """Empty cert_fingerprint_sha256 → matched=False, reason contains 'missing'."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256="")
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: REAL_FP)
        assert result.matched is False
        assert "missing" in result.reason

    def test_none_cert_fingerprint_sha256(self) -> None:
        """None cert_fingerprint_sha256 → matched=False, reason contains 'missing'."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=None)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: REAL_FP)
        assert result.matched is False
        assert "missing" in result.reason

    def test_sha1_length_observed_vs_sha256_pinned(self) -> None:
        """SHA-1 length (40 char) observed vs SHA-256 pinned (64 char) → mismatch."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256="a" * 64)
        result = verify_upstream_pin(cfg, _get_fp=lambda h, p, t: SHA1_FP)
        assert result.matched is False
        assert CERT_PIN_MISMATCH_LABEL in result.reason

    def test_network_error_fail_closed(self) -> None:
        """Network error during retrieval → matched=False (fail-closed), reason contains 'connection_error'."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode

        def _raise(h, p, t):
            raise OSError("timeout")

        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=REAL_FP)
        result = verify_upstream_pin(cfg, _get_fp=_raise)
        assert result.matched is False
        assert "connection_error" in result.reason

    def test_spiffe_exact_match(self) -> None:
        """SPIFFE ID exact match → matched=True."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.SPIFFE, spiffe_id=SPIFFE_PIN)
        result = verify_upstream_pin(cfg, _get_spiffe=lambda h, p, t: SPIFFE_PIN)
        assert result.matched is True
        assert result.reason == "ok"

    def test_spiffe_prefix_confusion_evil_suffix(self) -> None:
        """SPIFFE ID with evil suffix is rejected (exact match required)."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.SPIFFE, spiffe_id=SPIFFE_PIN)
        result = verify_upstream_pin(cfg, _get_spiffe=lambda h, p, t: SPIFFE_PIN + "-evil")
        assert result.matched is False
        assert CERT_PIN_MISMATCH_LABEL in result.reason

    def test_spiffe_none_observed(self) -> None:
        """SPIFFE ID None observed (no URI SAN) → mismatch."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.SPIFFE, spiffe_id=SPIFFE_PIN)
        result = verify_upstream_pin(cfg, _get_spiffe=lambda h, p, t: None)
        assert result.matched is False
        assert CERT_PIN_MISMATCH_LABEL in result.reason

    def test_empty_spiffe_id_pin_config(self) -> None:
        """Empty spiffe_id in pin config → matched=False, reason contains 'missing'."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig, PinMode
        cfg = UpstreamPinConfig("s1", "h", pin_mode=PinMode.SPIFFE, spiffe_id="")
        result = verify_upstream_pin(cfg, _get_spiffe=lambda h, p, t: SPIFFE_PIN)
        assert result.matched is False
        assert "missing" in result.reason

    def test_unknown_pin_mode(self) -> None:
        """Unknown pin_mode → matched=False, reason contains 'unknown_pin_mode'."""
        from yashigani.mcp._upstream_pin import verify_upstream_pin, UpstreamPinConfig
        # Force an unknown mode by bypassing the enum
        cfg = UpstreamPinConfig("s1", "h", pin_mode="token_binding")  # type: ignore[arg-type]
        result = verify_upstream_pin(cfg)
        assert result.matched is False
        assert "unknown_pin_mode" in result.reason

    def test_no_pin_config_in_broker(self, broker_no_pins) -> None:
        """No pin config in broker → matched=False, reason='pin_not_configured'."""
        result = broker_no_pins.verify_upstream("unknown-server")
        assert result.matched is False
        assert result.reason == "pin_not_configured"


# ===========================================================================
# FIX-P8-002: Inline enforcement in prod/staging
# ===========================================================================


class TestP8InlineEnforcementRegression:
    """
    FIX-P8-002: broker.verify_upstream() MUST raise ConnectionError in
    production/staging on mismatch or pin-not-configured.

    Previously, broker.verify_upstream() only returned matched=False and
    warned — the caller was relied upon to enforce.  FIX-P8-002 closes
    that gap.  Regression = ConnectionError NOT raised.
    """

    def test_prod_no_pin_config_raises_connection_error(self, issuer, nonce_store, mock_writer) -> None:
        """
        REGRESSION FIX-P8-002: prod env + no pin config → ConnectionError raised.

        Proves that 'warn-only' behaviour is gone in production.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            with pytest.raises(ConnectionError, match="no pin config"):
                broker.verify_upstream("server-not-in-pin-map")

    def test_staging_no_pin_config_raises_connection_error(self, issuer, nonce_store, mock_writer) -> None:
        """staging env + no pin config → ConnectionError raised."""
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "staging"}):
            with pytest.raises(ConnectionError):
                broker.verify_upstream("server-not-in-pin-map")

    def test_prod_pin_mismatch_raises_connection_error(self, issuer, nonce_store, mock_writer) -> None:
        """
        REGRESSION FIX-P8-002: prod env + cert fingerprint mismatch → ConnectionError.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            with pytest.raises(ConnectionError, match=CERT_PIN_MISMATCH_LABEL):
                broker.verify_upstream(
                    "github-mcp",
                    _get_fp=lambda host, port, timeout: MITM_FP,  # MITM
                )

    def test_prod_pin_match_does_not_raise(self, issuer, nonce_store, mock_writer) -> None:
        """prod env + cert fingerprint MATCHES → no exception, matched=True."""
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            result = broker.verify_upstream(
                "github-mcp",
                _get_fp=lambda host, port, timeout: REAL_FP,
            )
        assert result.matched is True
        assert result.reason == "ok"

    def test_dev_pin_mismatch_does_not_raise(self, issuer, nonce_store, mock_writer) -> None:
        """dev env + mismatch → matched=False but NO ConnectionError raised."""
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "development"}):
            result = broker.verify_upstream(
                "github-mcp",
                _get_fp=lambda host, port, timeout: MITM_FP,
            )
        assert result.matched is False  # still returns failure result
        # No exception: dev is non-enforcing

    def test_no_env_var_does_not_raise(self, issuer, nonce_store, mock_writer) -> None:
        """No YASHIGANI_ENV set → treated as non-enforcing, no ConnectionError."""
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)

        with patch.dict(os.environ, {}, clear=True):
            # Remove YASHIGANI_ENV if it exists
            env_clean = {k: v for k, v in os.environ.items() if k != "YASHIGANI_ENV"}
            with patch.dict(os.environ, env_clean, clear=True):
                result = broker.verify_upstream(
                    "github-mcp",
                    _get_fp=lambda host, port, timeout: MITM_FP,
                )
        assert result.matched is False

    def test_prod_pin_mismatch_emits_audit_event(self, issuer, nonce_store, mock_writer) -> None:
        """
        On prod mismatch, an audit event with the mismatch label MUST be emitted
        to the audit_writer BEFORE the ConnectionError is raised.

        Lu's requirement: structured witness trail for every pin failure.
        """
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer, fp=REAL_FP)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            with pytest.raises(ConnectionError):
                broker.verify_upstream(
                    "github-mcp",
                    _get_fp=lambda host, port, timeout: MITM_FP,
                )

        # Audit writer must have been called with an event whose event_type
        # carries the mismatch label.
        assert mock_writer.write.call_count >= 1, (
            "Audit event must be emitted on prod pin mismatch."
        )
        written_events = [call.args[0] for call in mock_writer.write.call_args_list]
        event_types = [getattr(ev, "event_type", None) for ev in written_events]
        assert any(CERT_PIN_MISMATCH_LABEL in (et or "") for et in event_types), (
            f"Expected at least one audit event with event_type containing "
            f"{CERT_PIN_MISMATCH_LABEL!r}. Got event_types: {event_types}"
        )

    def test_prod_no_pin_emits_audit_event(self, issuer, nonce_store, mock_writer) -> None:
        """On prod + pin-not-configured, audit event emitted before ConnectionError."""
        broker = _make_broker_with_fp_pin(issuer, nonce_store, mock_writer)

        with patch.dict(os.environ, {"YASHIGANI_ENV": "production"}):
            with pytest.raises(ConnectionError):
                broker.verify_upstream("no-such-server")

        assert mock_writer.write.call_count >= 1, (
            "Audit event must be emitted on prod pin-not-configured."
        )
        written_events = [call.args[0] for call in mock_writer.write.call_args_list]
        event_types = [getattr(ev, "event_type", None) for ev in written_events]
        assert any("pin_not_configured" in (et or "") for et in event_types), (
            f"Expected audit event with 'pin_not_configured'. Got: {event_types}"
        )
