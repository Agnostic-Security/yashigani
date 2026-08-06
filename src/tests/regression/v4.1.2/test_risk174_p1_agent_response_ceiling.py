"""
Regression tests — YSG-RISK-174 (chat-path repair, 2026-07-30).

Root cause: `_resolve_identity()`'s p1_agent branch hardcoded
``"sensitivity_ceiling": "INTERNAL"`` (rank 1 of 4) for EVERY per-agent P1
token identity, including the agent's own reasoning self-call to gateway's
``/v1/chat/completions`` -- the same "llm" egress class YSG-RISK-170 already
established deserves no artificial ceiling cap (that fix covered the
egress-eval gate; this is the SAME misapplied-ceiling class at the
response-delivery gate, ``_opa_response_check`` / ``policy/v1_routing.rego``
``response_decision``).

Live-confirmed while verifying the YSG-RISK-172 fix (langflow's per-agent
token now resolves correctly as p1_agent/agent__langflow instead of
anonymous): langflow's own self-call then started 403ing --

    OPA BLOCKED response delivery: identity=agent__langflow
    sensitivity=RESTRICTED reason=response_sensitivity_exceeds_ceiling

-- for the exact same trivial one-sentence-greeting response @letta and
@openclaw complete successfully. Root cause: letta/openclaw authenticate via
the SEPARATE ``_INTERNAL_BEARER`` fallback path, which already resolves to
``sensitivity_ceiling="RESTRICTED"`` (rank 3) -- only langflow's dedicated
per-agent P1 token (Phase 5 §C, the only agent using this branch as of
2026-07-30) took the INTERNAL-capped p1_agent branch, an inconsistency
between two equivalent internal-caller paths that both exist purely to let
an agent's own reasoning call complete.

Fix: raise p1_agent's `sensitivity_ceiling` to `RESTRICTED`, matching what
letta/openclaw already get via `_INTERNAL_BEARER`. This ONLY removes the
artificial rank-based cap on the ceiling comparison in
`policy/v1_routing.rego`'s `response_allowed` rule
(`_effective_sensitivity_rank <= _ceiling_rank(...)`). The SEPARATE,
unconditional `_response_blocked_by_inspection` hard gate
(`input.response_verdict == "blocked" AND identity.kind != "admin"`) is
UNTOUCHED and still denies a genuinely blocked/PII-flagged response
regardless of ceiling -- confirmed by inspecting `policy/v1_routing.rego`
lines ~232-247, where the two conditions are independent `if` clauses, not
folded into one comparison. This does NOT weaken real content inspection.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock


def _make_request(headers: dict):
    """Build a minimal FastAPI-style Request mock."""
    req = MagicMock()
    lower_headers = {k.lower(): v for k, v in headers.items()}
    req.headers.get = lambda key, default="": lower_headers.get(key.lower(), default)
    return req


class TestRisk174P1AgentResponseCeilingParity:
    """p1_agent identities must resolve with the SAME response-delivery
    ceiling as the equivalent _INTERNAL_BEARER-authenticated agents, not an
    artificially lower one that blocks their own trivial self-call."""

    def test_p1_agent_with_registry_entry_gets_restricted_ceiling(self, monkeypatch) -> None:
        import yashigani.gateway.openai_router as router_mod

        p1_token = "cafebabe" * 8
        monkeypatch.setattr(router_mod._state, "token_role_map", {
            p1_token: ("p1_agent", "agent__langflow"),
        })
        mock_registry = MagicMock()
        mock_registry.get.return_value = {
            "status": "active",
            "groups": [],
            "allowed_paths": [],
        }
        monkeypatch.setattr(router_mod._state, "agent_registry", mock_registry)
        monkeypatch.setattr(router_mod._state, "identity_registry", None)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({"Authorization": f"Bearer {p1_token}"})
        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "agent__langflow"
        assert result["sensitivity_ceiling"] == "RESTRICTED", (
            f"YSG-RISK-174 regression: p1_agent (registry-resolved) ceiling "
            f"reverted to an artificially low value; got "
            f"{result['sensitivity_ceiling']!r} -- this re-caps an agent's "
            f"own reasoning self-call below what an equivalent "
            f"_INTERNAL_BEARER caller already gets, false-denying trivial "
            f"responses (live-observed: langflow 403 "
            f"'response_sensitivity_exceeds_ceiling' on a one-sentence "
            f"greeting)."
        )

    def test_p1_agent_fallback_without_registry_gets_restricted_ceiling(self, monkeypatch) -> None:
        """No registry entry (fallback branch) must ALSO get the parity fix."""
        import yashigani.gateway.openai_router as router_mod

        p1_token = "deadc0de" * 8
        monkeypatch.setattr(router_mod._state, "token_role_map", {
            p1_token: ("p1_agent", "agent__letta"),
        })
        monkeypatch.setattr(router_mod._state, "agent_registry", None)
        monkeypatch.setattr(router_mod._state, "identity_registry", None)
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({"Authorization": f"Bearer {p1_token}"})
        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "agent__letta"
        assert result["sensitivity_ceiling"] == "RESTRICTED", (
            f"YSG-RISK-174 regression: p1_agent (no-registry fallback) "
            f"ceiling reverted; got {result['sensitivity_ceiling']!r}"
        )

    def test_internal_bearer_agent_ceiling_unchanged_for_parity_reference(self, monkeypatch) -> None:
        """Sanity-check the parity claim itself: the _INTERNAL_BEARER path
        (used by letta/openclaw) already resolves to RESTRICTED -- this is
        the reference value p1_agent must now match."""
        import yashigani.gateway.openai_router as router_mod

        monkeypatch.setattr(router_mod._state, "token_role_map", {})
        monkeypatch.setattr(router_mod._state, "audit_writer", None)

        req = _make_request({
            "Authorization": f"Bearer {router_mod._INTERNAL_BEARER}",
        })
        result = router_mod._resolve_identity(req)

        assert result is not None
        assert result["identity_id"] == "internal"
        assert result["sensitivity_ceiling"] == "RESTRICTED"


class TestRisk174HardInspectionGateUnaffected:
    """The fix must not touch the independent response-inspection hard gate
    -- confirm the source still carries the unconditional
    `_response_blocked_by_inspection` rule, decoupled from the ceiling
    comparison it now shares a RESTRICTED value with."""

    def test_response_blocked_by_inspection_is_independent_of_ceiling(self):
        repo_root = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
        )
        rego_path = os.path.join(repo_root, "policy", "v1_routing.rego")
        with open(rego_path, "r", encoding="utf-8") as fh:
            rego_src = fh.read()
        assert '_response_blocked_by_inspection if {' in rego_src, (
            "YSG-RISK-174 fix must not remove the independent "
            "_response_blocked_by_inspection hard gate"
        )
        assert 'input.response_verdict == "blocked"' in rego_src, (
            "The response_verdict==blocked hard gate must remain present "
            "and unconditional on ceiling"
        )
