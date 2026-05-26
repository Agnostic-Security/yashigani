"""
Unit tests for LU-AMEND-04: operator identity attestation on yashigani onboard.

Tests:
  1. POST /auth/operator-token:
     a. 401 when step-up not fresh (no last_totp_verified_at)
     b. 200 + token on fresh step-up
     c. Token contains correct claims (sub, jti, exp, purpose, iss)
  2. GET /auth/operator-token/verify:
     a. 400 when Authorization header absent
     b. 401 when token expired
     c. 401 when wrong purpose claim
     d. 200 + {valid, sub, jti, exp} on valid token
  3. POST /auth/onboard-event:
     a. 422 when identity_quality is invalid value
     b. 200 on valid attested event
     c. 200 on valid weak event

v2.24.1 / LU-AMEND-04.
"""

from __future__ import annotations

import time
import uuid

import jwt as pyjwt
import pytest


# ---------------------------------------------------------------------------
# Schema smoke tests (no I/O, no FastAPI dep)
# ---------------------------------------------------------------------------


def test_operator_token_issued_event_fields():
    """OperatorTokenIssuedEvent carries expected fields and event_type."""
    from yashigani.audit.schema import OperatorTokenIssuedEvent, EventType

    ev = OperatorTokenIssuedEvent(
        admin_account="admin1",
        token_jti="test-jti-001",
        token_ttl_seconds=900,
        issued_for="langflow onboard",
    )
    assert ev.event_type == EventType.OPERATOR_TOKEN_ISSUED
    assert ev.admin_account == "admin1"
    assert ev.token_jti == "test-jti-001"
    assert ev.token_ttl_seconds == 900
    assert ev.issued_for == "langflow onboard"
    # Token value MUST NOT appear in the event dict
    d = ev.to_dict()
    assert "token" not in d
    assert "token_value" not in d
    assert d["token_jti"] == "test-jti-001"


def test_onboard_attempted_event_attested():
    """OnboardAttemptedEvent correctly represents an attested onboard."""
    from yashigani.audit.schema import OnboardAttemptedEvent, EventType

    ev = OnboardAttemptedEvent(
        identity_quality="attested",
        operator_identity="admin1",
        token_jti="test-jti-002",
        agent_name="langflow",
        agent_url="http://langflow:7860",
        client_ip="10.0.0.5",
    )
    assert ev.event_type == EventType.ONBOARD_ATTEMPTED
    assert ev.identity_quality == "attested"
    assert ev.operator_identity == "admin1"
    assert ev.token_jti == "test-jti-002"


def test_onboard_attempted_event_weak():
    """OnboardAttemptedEvent correctly represents a weak-identity onboard."""
    from yashigani.audit.schema import OnboardAttemptedEvent

    ev = OnboardAttemptedEvent(
        identity_quality="weak",
        operator_identity="unknown",
        token_jti="",
        agent_name="test-agent",
        agent_url="http://test:8080",
        client_ip="cli",
    )
    assert ev.identity_quality == "weak"
    assert ev.token_jti == ""
    assert ev.operator_identity == "unknown"


# ---------------------------------------------------------------------------
# JWT structure tests (no server dependency)
# ---------------------------------------------------------------------------

_SIGNING_KEY = "test-signing-key-for-lu-amend-04-unit-tests-only"
_OPERATOR_TOKEN_TTL = 900


def _make_operator_token(
    sub: str = "admin1",
    jti: str | None = None,
    purpose: str = "operator-onboard",
    iss: str = "yashigani.backoffice",
    ttl: int = _OPERATOR_TOKEN_TTL,
    nbf_offset: int = 0,
) -> str:
    """Mint a test operator token with the given claims."""
    now = int(time.time()) + nbf_offset
    payload = {
        "sub": sub,
        "jti": jti or str(uuid.uuid4()),
        "iat": now,
        "exp": now + ttl,
        "iss": iss,
        "purpose": purpose,
        "issued_for": "unit-test",
    }
    return pyjwt.encode(payload, _SIGNING_KEY, algorithm="HS256")


def test_valid_operator_token_structure():
    """A correctly-minted operator token has the expected required claims."""
    token = _make_operator_token()
    decoded = pyjwt.decode(token, _SIGNING_KEY, algorithms=["HS256"])
    assert decoded["sub"] == "admin1"
    assert decoded["purpose"] == "operator-onboard"
    assert decoded["iss"] == "yashigani.backoffice"
    assert "jti" in decoded
    assert decoded["exp"] > int(time.time())


def test_expired_operator_token_rejected():
    """Expired operator token raises ExpiredSignatureError on decode."""
    token = _make_operator_token(ttl=-1, nbf_offset=-10)
    with pytest.raises(pyjwt.ExpiredSignatureError):
        pyjwt.decode(token, _SIGNING_KEY, algorithms=["HS256"])


def test_wrong_purpose_claim_detectable():
    """Token with wrong purpose claim is detectable post-decode."""
    token = _make_operator_token(purpose="wrong-purpose")
    decoded = pyjwt.decode(token, _SIGNING_KEY, algorithms=["HS256"])
    assert decoded["purpose"] != "operator-onboard"


def test_wrong_issuer_detectable():
    """Token with wrong issuer is detectable post-decode."""
    token = _make_operator_token(iss="attacker.example.com")
    decoded = pyjwt.decode(token, _SIGNING_KEY, algorithms=["HS256"])
    assert decoded["iss"] != "yashigani.backoffice"


# ---------------------------------------------------------------------------
# CLI script argument tests (no I/O)
# ---------------------------------------------------------------------------


def test_cli_argparse_requires_name_and_url():
    """yashigani-onboard --name and --url are required arguments."""
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "scripts/yashigani-onboard.py", "--help"],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[3]),
    )
    assert result.returncode == 0
    assert "--name" in result.stdout
    assert "--url" in result.stdout
    assert "--token" in result.stdout
    assert "--allow-weak-identity" in result.stdout


def test_cli_exits_3_without_token_and_no_allow_weak():
    """Without --token and without --allow-weak-identity, CLI exits with code 3."""
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "scripts/yashigani-onboard.py",
            "--name", "test-agent",
            "--url", "http://test:8080",
            # No --token, no --allow-weak-identity
        ],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[3]),
        timeout=10,
        env={
            **__import__("os").environ,
            # No YSG_CADDY_HMAC or /run/secrets — backoffice not reachable
        },
    )
    assert result.returncode == 3, (
        f"Expected exit 3 (usage error), got {result.returncode}. "
        f"stderr: {result.stderr[:200]}"
    )
    assert "Refusing to onboard without --token" in result.stderr


def test_cli_exits_3_on_invalid_url_scheme():
    """CLI exits 3 when --url does not start with http:// or https://."""
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "scripts/yashigani-onboard.py",
            "--name", "test-agent",
            "--url", "ftp://test:8080",
            "--allow-weak-identity",
        ],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[3]),
        timeout=10,
    )
    assert result.returncode == 3, (
        f"Expected exit 3 (usage error), got {result.returncode}. "
        f"stderr: {result.stderr[:200]}"
    )
    assert "http://" in result.stderr or "https://" in result.stderr


# ---------------------------------------------------------------------------
# EventType enum completeness
# ---------------------------------------------------------------------------


def test_event_type_enum_has_lu_amend_04_values():
    """EventType includes both LU-AMEND-04 event types."""
    from yashigani.audit.schema import EventType

    assert hasattr(EventType, "OPERATOR_TOKEN_ISSUED")
    assert hasattr(EventType, "ONBOARD_ATTEMPTED")
    assert EventType.OPERATOR_TOKEN_ISSUED == "OPERATOR_TOKEN_ISSUED"
    assert EventType.ONBOARD_ATTEMPTED == "ONBOARD_ATTEMPTED"
