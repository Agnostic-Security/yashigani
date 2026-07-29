# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — LAURA-V50-COV-001 (generic deny reason on agent-to-agent calls).

gateway/agent_router.py::_opa_agent_check (~L679-707 pre-fix) queried ONLY the
boolean `agent_call_allowed` and hardcoded the deny reason to the generic
string "opa_denied" — it never queried agents.rego's `agent_call_deny_reason`,
which already computes the SPECIFIC reason:
  * caller_group_not_in_allowed_caller_groups
  * path_traversal_attempt
  * path_not_in_allowed_paths
  * target_agent_not_in_data
Both the AgentCallDeniedEvent audit event and the 403 JSON response
(`{"error": "AGENT_CALL_DENIED", "reason": opa_reason, ...}`) inherited the
useless generic label — an operator investigating a denied agent call, or an
audit reviewer, could not tell "wrong caller group" from "path traversal
attempt" from "target misconfigured" without re-deriving it by hand. Same
class as V50-011.

Fix: on deny, `_opa_agent_check` now makes a SECOND targeted OPA query to
`agent_call_deny_reason` and uses that as the reason, falling back to
"opa_denied" only if the reason query itself fails (best-effort — the
ALLOW/DENY decision is unaffected either way, already fail-closed via the
first query). This mirrors the (allowed, reason) tuple contract
`_opa_agent_response_check` already returns from `agent_response_decision`'s
compound decision object.

This suite exercises `_opa_agent_check` directly against a fake httpx
transport (no live OPA needed) and proves the SPECIFIC reason is surfaced for
a wrong-caller-group case and a wrong-path case — not the generic
"opa_denied". `route_agent_call`'s existing wiring (opa_reason -> audit event
+ HTTP response body, agent_router.py L296-321) is unchanged, so a correct
`_opa_agent_check` return value is sufficient to prove the reason reaches
both surfaces without re-testing that plumbing here.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from yashigani.gateway.agent_router import (
    _OPA_AGENT_ALLOWED_PATH,
    _OPA_AGENT_DENY_REASON_PATH,
    _opa_agent_check,
)


def _mock_client(allowed_response: MagicMock, reason_response: MagicMock | None = None) -> AsyncMock:
    """An httpx.AsyncClient-shaped async-context-manager mock whose .post()
    routes to a different canned response depending on the target path, so a
    single client double can answer BOTH OPA queries _opa_agent_check makes."""
    client = AsyncMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)

    async def _post(url, **kwargs):
        if url.endswith(_OPA_AGENT_DENY_REASON_PATH):
            assert reason_response is not None, (
                "agent_call_deny_reason was queried but the test didn't expect it "
                "(i.e. agent_call_allowed must have returned True)"
            )
            return reason_response
        assert url.endswith(_OPA_AGENT_ALLOWED_PATH)
        return allowed_response

    client.post = AsyncMock(side_effect=_post)
    return client


def _resp(status_code: int, result) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"result": result})
    return resp


OPA_URL = "https://policy:8181"
OPA_INPUT = {
    "principal": {"type": "agent", "agent_id": "caller-a", "groups": ["ops"]},
    "target_agent": {
        "agent_id": "target-b",
        "allowed_caller_groups": ["finance"],
        "allowed_paths": ["**"],
    },
    "request": {"remainder_path": "/v1/query"},
}


class TestSpecificDenyReasonSurfaced:
    @pytest.mark.asyncio
    async def test_wrong_caller_group_returns_specific_reason_not_generic(self, monkeypatch):
        """Caller not in target's allowed_caller_groups (the exact scenario
        in the ticket: wrong-group)."""
        allowed_resp = _resp(200, False)
        reason_resp = _resp(200, "caller_group_not_in_allowed_caller_groups")
        client = _mock_client(allowed_resp, reason_resp)

        monkeypatch.setattr(
            "yashigani.gateway.agent_router.internal_httpx_client",
            lambda timeout=5.0: client,
        )

        allowed, reason = await _opa_agent_check(OPA_URL, OPA_INPUT)

        assert allowed is False
        assert reason == "caller_group_not_in_allowed_caller_groups", (
            "LAURA-V50-COV-001 regression: deny reason must be the SPECIFIC "
            f"rego-computed reason, not generic — got {reason!r}"
        )
        assert reason != "opa_denied"
        # Confirm the SECOND, targeted query actually happened (not just a
        # lucky default).
        posted_urls = [c.args[0] if c.args else c.kwargs.get("url") for c in client.post.await_args_list]
        assert any(u.endswith(_OPA_AGENT_DENY_REASON_PATH) for u in posted_urls), (
            "agent_call_deny_reason was never queried"
        )

    @pytest.mark.asyncio
    async def test_wrong_path_returns_specific_reason_not_generic(self, monkeypatch):
        """Caller group matches but remainder_path is outside allowed_paths
        (the ticket's wrong-path scenario)."""
        allowed_resp = _resp(200, False)
        reason_resp = _resp(200, "path_not_in_allowed_paths")
        client = _mock_client(allowed_resp, reason_resp)

        monkeypatch.setattr(
            "yashigani.gateway.agent_router.internal_httpx_client",
            lambda timeout=5.0: client,
        )

        allowed, reason = await _opa_agent_check(OPA_URL, OPA_INPUT)

        assert allowed is False
        assert reason == "path_not_in_allowed_paths"
        assert reason != "opa_denied"

    @pytest.mark.asyncio
    async def test_allow_path_never_queries_deny_reason(self, monkeypatch):
        """When agent_call_allowed is True, the second query must NOT fire —
        it's deny-only, both for cost and because agent_call_deny_reason is
        undefined (not merely absent) when the call is allowed."""
        allowed_resp = _resp(200, True)
        client = _mock_client(allowed_resp, reason_response=None)

        monkeypatch.setattr(
            "yashigani.gateway.agent_router.internal_httpx_client",
            lambda timeout=5.0: client,
        )

        allowed, reason = await _opa_agent_check(OPA_URL, OPA_INPUT)

        assert allowed is True
        assert reason == ""
        client.post.assert_awaited_once()  # only the allowed query

    @pytest.mark.asyncio
    async def test_reason_query_failure_degrades_to_generic_but_stays_fail_closed(self, monkeypatch):
        """Best-effort contract: if the SECOND query itself blows up, the
        DECISION (deny) must be unaffected — only the label degrades to the
        old generic string. Never let a reason-lookup failure flip the
        decision to allow."""
        allowed_resp = _resp(200, False)
        client = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        async def _post(url, **kwargs):
            if url.endswith(_OPA_AGENT_DENY_REASON_PATH):
                raise ConnectionError("OPA reason query timed out")
            return allowed_resp

        client.post = AsyncMock(side_effect=_post)

        monkeypatch.setattr(
            "yashigani.gateway.agent_router.internal_httpx_client",
            lambda timeout=5.0: client,
        )

        allowed, reason = await _opa_agent_check(OPA_URL, OPA_INPUT)

        assert allowed is False, "a reason-query failure must never flip the decision to allow"
        assert reason == "opa_denied"

    @pytest.mark.asyncio
    async def test_opa_unreachable_on_primary_query_stays_fail_closed(self, monkeypatch):
        """Pre-existing fail-closed contract on the FIRST (allow) query must
        be unchanged by this fix."""
        client = AsyncMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        client.post = AsyncMock(side_effect=ConnectionError("OPA down"))

        monkeypatch.setattr(
            "yashigani.gateway.agent_router.internal_httpx_client",
            lambda timeout=5.0: client,
        )

        allowed, reason = await _opa_agent_check(OPA_URL, OPA_INPUT)

        assert allowed is False
        assert reason == "opa_unreachable"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
