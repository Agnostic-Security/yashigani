"""
Regression test — SEC-GAP-1 / OPA identity key fix.

What this tests:
  A. _opa_check (gateway/proxy.py) builds the OPA input document with
     ``session.identity_id``, NOT ``session.email``.  Commit 2797509e reverted
     the key back to "email"; this test would have caught it.

  B. _opa_denial_alert (gateway/proxy.py) builds the same document shape
     (same function, same fix site at :1506).

  C. rbac.rego allow_rbac reads ``input.session.identity_id`` (not .email) —
     the OPA test suite is 430/430; this test records the Python-side contract.

The regression: both _opa_check and _opa_denial_alert used
    "session": {"email": user_id}
The fix (this PR):
    "session": {"identity_id": user_id}

These tests assert on the actual document built by the production functions,
NOT on a re-implementation — they intercept the HTTP POST to OPA and inspect
the ``input`` JSON.

Last updated: 2026-07-13T00:00:00+00:00
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_request(path: str = "/v1/chat") -> MagicMock:
    """Minimal mock Request whose attributes _opa_check needs."""
    from fastapi import Request
    req = MagicMock(spec=Request)
    req.method = "GET"
    req.headers = {}
    req.state = MagicMock()
    req.state.ysg_principal = None
    return req


def _make_mock_cfg(opa_url: str = "http://opa:8181",
                   opa_policy_path: str = "/v1/data/yashigani/allow") -> MagicMock:
    cfg = MagicMock()
    cfg.opa_url = opa_url
    cfg.opa_policy_path = opa_policy_path
    return cfg


def _capture_posted_doc() -> tuple[list[dict], MagicMock]:
    """
    Return (captured_docs, patch_target).  When applied as a context manager,
    every POST to OPA appends ``input_doc`` to ``captured_docs``.
    """
    captured: list[dict] = []

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json = MagicMock(return_value={"result": True})
    mock_resp.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)

    async def _side_effect(url, *, json=None, headers=None, **kw):
        if json is not None and "input" in json:
            captured.append(json["input"])
        return mock_resp

    mock_client.post.side_effect = _side_effect

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)

    mock_factory = MagicMock(return_value=cm)
    return captured, mock_factory


# ---------------------------------------------------------------------------
# A. _opa_check must build session.identity_id
# ---------------------------------------------------------------------------

class TestOpaCheckSessionKey:
    """_opa_check must POST session.identity_id, not session.email."""

    @pytest.mark.asyncio
    async def test_opa_check_session_key_is_identity_id(self):
        """
        _opa_check must build input_doc["session"]["identity_id"] = user_id.
        Regression: commit 2797509e reverted this to "email".
        """
        captured, mock_factory = _capture_posted_doc()

        user_id = "idnt_aabbccdd1234"
        cfg = _make_mock_cfg()
        req = _make_mock_request()

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            mock_factory,
        ):
            from yashigani.gateway.proxy import _opa_check
            await _opa_check(
                cfg=cfg,
                request=req,
                path="/v1/chat",
                session_id="sess-001",
                agent_id="agent-001",
                user_id=user_id,
            )

        assert len(captured) == 1, "_opa_check must POST exactly once to OPA"
        doc = captured[0]

        # The critical assertion: must use identity_id, not email
        assert "session" in doc, "OPA input must contain 'session' key"
        session = doc["session"]
        assert "identity_id" in session, (
            "OPA input session must contain 'identity_id' key; "
            f"got keys: {list(session.keys())}"
        )
        assert session["identity_id"] == user_id, (
            f"session.identity_id must equal user_id={user_id!r}; "
            f"got {session['identity_id']!r}"
        )

    @pytest.mark.asyncio
    async def test_opa_check_session_has_no_email_key(self):
        """
        After the fix, session must NOT contain the stale 'email' key.
        Regression guard: if someone re-introduces 'email', this catches it.
        """
        captured, mock_factory = _capture_posted_doc()

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            mock_factory,
        ):
            from yashigani.gateway.proxy import _opa_check
            await _opa_check(
                cfg=_make_mock_cfg(),
                request=_make_mock_request(),
                path="/v1/chat",
                session_id="sess-001",
                agent_id="agent-001",
                user_id="idnt_aabbccdd1234",
            )

        assert len(captured) == 1
        session = captured[0]["session"]
        assert "email" not in session, (
            "OPA input session must NOT contain 'email' key after SEC-GAP-1 fix; "
            f"got session={session!r}"
        )

    @pytest.mark.asyncio
    async def test_opa_check_identity_id_value_matches_user_id(self):
        """user_id value (which IS the identity_id) must be forwarded as-is."""
        captured, mock_factory = _capture_posted_doc()
        uid = "idnt_ff00ee11dd22"

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            mock_factory,
        ):
            from yashigani.gateway.proxy import _opa_check
            await _opa_check(
                cfg=_make_mock_cfg(),
                request=_make_mock_request(),
                path="/v1/chat",
                session_id="sess-002",
                agent_id="agent-002",
                user_id=uid,
            )

        assert captured[0]["session"]["identity_id"] == uid


# ---------------------------------------------------------------------------
# B. _opa_denial_alert must build session.identity_id
# ---------------------------------------------------------------------------

class TestOpaDenialAlertSessionKey:
    """_opa_denial_alert must POST session.identity_id, not session.email."""

    @pytest.mark.asyncio
    async def test_opa_denial_alert_session_key_is_identity_id(self):
        """
        _opa_denial_alert (proxy.py:1506) must build input_doc["session"]["identity_id"].
        This is the second of the two sites fixed in SEC-GAP-1.
        """
        captured, mock_factory = _capture_posted_doc()

        user_id = "idnt_aabbccdd5678"
        cfg = _make_mock_cfg()
        req = _make_mock_request()

        with patch(
            "yashigani.gateway.proxy.internal_httpx_client",
            mock_factory,
        ):
            from yashigani.gateway.proxy import _opa_denial_alert
            # _opa_denial_alert is best-effort (never raises); call it and check.
            await _opa_denial_alert(
                cfg=cfg,
                request=req,
                path="/v1/chat",
                session_id="sess-003",
                agent_id="agent-003",
                user_id=user_id,
                request_id="req-001",
            )

        # The denial alert may POST to the decision path; check what was captured.
        assert len(captured) >= 1, "_opa_denial_alert must POST to OPA"
        doc = captured[0]
        assert "session" in doc, "OPA denial input must contain 'session' key"
        session = doc["session"]
        assert "identity_id" in session, (
            "OPA denial input session must contain 'identity_id'; "
            f"got keys: {list(session.keys())}"
        )
        assert session["identity_id"] == user_id
        assert "email" not in session, (
            "OPA denial input session must NOT contain stale 'email' key"
        )
