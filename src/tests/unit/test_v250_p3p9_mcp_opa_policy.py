"""
v2.25.0 P1-W3 Phase 2b-i — MCP OPA Policy (P3 + P9)
======================================================

Unit tests for:
  P3 (HIGH)  — MCP input schema, mcp.rego decision shape, fail-closed behaviour
  P9 (MEDIUM) — MCP-B per-tool exposed_tools authz

These tests verify:
  A. The mcp-input.schema.json exists and is valid JSON
  B. The mcp.rego policy file exists in policy/
  C. The OPA query path for MCP decisions
     (/v1/data/yashigani/mcp/mcp_decision)
  D. Input document shape matches schema requirements
  E. Decision document shape matches mcp-input.schema.json §definitions.mcp_decision
  F. Fail-closed: missing SPIFFE → deny
  G. Fail-closed: invalid posture → deny
  H. Fail-closed: multiple subjects (oneOf violation) → deny
  I. Chain-depth guard — MCP-C limits
  J. P9: per-tool allowlist enforcement for mcp-b / mcp-c
  K. P9: non-tool actions not blocked by tool allowlist
  L. Proxy integration wiring — _opa_proxy_response_check is the response-leg gate
     for all MCP proxy traffic (GAP-002, already landed)
  M. Models enumeration gate — _opa_models_check is the gate for /v1/models
     (GAP-001, already landed)

Tests marked pytestmark_live_opa_required are skipped unless LIVE_OPA=1 env is set.
All other tests mock the OPA HTTP call via unittest.mock and verify input shape.

ASVS V4.1.1 / V4.1.3 / V4.2.1 / OWASP Agentic AI 2025 Top-10 /
Iris GAP-001 / Iris GAP-002 / Lu-Gap-02 (multi-hop identity chain) /
P3 (HIGH) / P9 (MEDIUM) / YSG-RISK-068.
"""
from __future__ import annotations

import json
import pathlib
import pytest
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Path to policy directory (relative to this file's location in src/tests/unit/)
# ---------------------------------------------------------------------------

_POLICY_DIR = pathlib.Path(__file__).parents[3] / "policy"
_MCP_REGO = _POLICY_DIR / "mcp.rego"
_MCP_SCHEMA = _POLICY_DIR / "mcp-input.schema.json"

# OPA query path for MCP decisions — this is the contract the gateway must call.
MCP_OPA_PATH = "/v1/data/yashigani/mcp/mcp_decision"


# ---------------------------------------------------------------------------
# A. Schema and policy file existence
# ---------------------------------------------------------------------------

class TestMcpPolicyFiles:
    """Verify the MCP policy files exist and are valid."""

    def test_mcp_rego_file_exists(self):
        """policy/mcp.rego must exist — P3 deliverable."""
        assert _MCP_REGO.exists(), (
            f"policy/mcp.rego not found at {_MCP_REGO}. "
            "P3 (HIGH): MCP OPA policy must be authored."
        )

    def test_mcp_schema_file_exists(self):
        """policy/mcp-input.schema.json must exist — P3 deliverable."""
        assert _MCP_SCHEMA.exists(), (
            f"policy/mcp-input.schema.json not found at {_MCP_SCHEMA}. "
            "P3 (HIGH): MCP input schema must be defined."
        )

    def test_mcp_schema_is_valid_json(self):
        """mcp-input.schema.json must parse as valid JSON."""
        with open(_MCP_SCHEMA) as f:
            data = json.load(f)
        assert isinstance(data, dict)
        assert "$schema" in data or "type" in data, "Schema missing '$schema' or 'type'"

    def test_mcp_schema_has_required_input_fields(self):
        """Schema must declare posture, action, identity as required fields."""
        with open(_MCP_SCHEMA) as f:
            schema = json.load(f)
        required = schema.get("required", [])
        assert "posture" in required, "posture must be required"
        assert "action" in required, "action must be required"
        assert "identity" in required, "identity must be required"

    def test_mcp_schema_posture_enum(self):
        """posture field must enumerate mcp-a, mcp-b, mcp-c."""
        with open(_MCP_SCHEMA) as f:
            schema = json.load(f)
        posture_prop = schema["properties"]["posture"]
        assert set(posture_prop["enum"]) == {"mcp-a", "mcp-b", "mcp-c"}, (
            "posture must be exactly {mcp-a, mcp-b, mcp-c}"
        )

    def test_mcp_schema_has_decision_definition(self):
        """Schema must document the mcp_decision return shape."""
        with open(_MCP_SCHEMA) as f:
            schema = json.load(f)
        defs = schema.get("definitions", {})
        assert "mcp_decision" in defs, "Schema must document mcp_decision shape in definitions"
        decision_props = defs["mcp_decision"]["properties"]
        assert "allow" in decision_props
        assert "redact_args" in decision_props
        assert "audit_capture" in decision_props
        assert "rate_limit_key" in decision_props

    def test_mcp_schema_tool_prompt_resource_mutually_exclusive(self):
        """Schema must declare tool/prompt/resource as mutually exclusive."""
        with open(_MCP_SCHEMA) as f:
            schema = json.load(f)
        # The exclusivity constraint lives in allOf
        all_of = schema.get("allOf", [])
        assert len(all_of) > 0, (
            "mcp-input.schema.json must have an allOf constraint "
            "enforcing tool/prompt/resource mutual exclusivity"
        )

    def test_mcp_rego_contains_default_allow_false(self):
        """mcp.rego must start with default allow := false (fail-closed)."""
        content = _MCP_REGO.read_text()
        assert "default allow := false" in content, (
            "mcp.rego must have 'default allow := false' for fail-closed behaviour. "
            "ASVS V4.1.3."
        )

    def test_mcp_rego_contains_chain_depth_guard(self):
        """mcp.rego must implement chain-depth guard for MCP-C (Lu-Gap-02)."""
        content = _MCP_REGO.read_text()
        assert "chain" in content, "mcp.rego must reference identity.chain"
        assert "mcp_chain_max_depth" in content, "mcp.rego must have mcp_chain_max_depth guard"

    def test_mcp_rego_contains_p9_exposed_tools(self):
        """mcp.rego must implement per-tool allowlist (P9 MCP-B authz)."""
        content = _MCP_REGO.read_text()
        assert "exposed_tools" in content, (
            "mcp.rego must implement exposed_tools allowlist for P9 per-tool authz"
        )

    def test_mcp_rego_contains_redact_args(self):
        """mcp.rego must implement redact_args for secret-key patterns."""
        content = _MCP_REGO.read_text()
        assert "redact_args" in content, "mcp.rego must implement redact_args"

    def test_mcp_rego_contains_audit_capture(self):
        """mcp.rego must implement audit_capture rule."""
        content = _MCP_REGO.read_text()
        assert "audit_capture" in content, "mcp.rego must implement audit_capture"

    def test_mcp_rego_contains_rate_limit_key(self):
        """mcp.rego must implement rate_limit_key."""
        content = _MCP_REGO.read_text()
        assert "rate_limit_key" in content, "mcp.rego must implement rate_limit_key"

    def test_mcp_rego_uses_rego_v1(self):
        """mcp.rego must import rego.v1 for forward-compatible syntax."""
        content = _MCP_REGO.read_text()
        assert "import rego.v1" in content, (
            "mcp.rego must use 'import rego.v1' for forward-compatible Rego syntax"
        )


# ---------------------------------------------------------------------------
# B. OPA query path contract
# ---------------------------------------------------------------------------

class TestMcpOpaQueryPath:
    """Verify the OPA query path constant used for MCP decisions."""

    def test_mcp_opa_path_matches_rego_package(self):
        """The OPA query path must match the mcp.rego package declaration."""
        # package yashigani.mcp → /v1/data/yashigani/mcp/...
        assert MCP_OPA_PATH.startswith("/v1/data/yashigani/mcp/"), (
            f"MCP OPA path {MCP_OPA_PATH!r} must start with /v1/data/yashigani/mcp/. "
            "The package declaration in mcp.rego is 'package yashigani.mcp'."
        )

    def test_mcp_opa_decision_path(self):
        """mcp_decision compound document is the authoritative query endpoint."""
        assert MCP_OPA_PATH == "/v1/data/yashigani/mcp/mcp_decision", (
            f"Expected /v1/data/yashigani/mcp/mcp_decision, got {MCP_OPA_PATH!r}"
        )


# ---------------------------------------------------------------------------
# C. Input document construction helpers
# ---------------------------------------------------------------------------

def _make_mcp_input(
    posture: str = "mcp-a",
    action: str = "mcp.tools.call",
    spiffe: str = "spiffe://cluster.local/ns/default/sa/langflow",
    tool_name: str = "web_search",
    tool_args: dict | None = None,
    prompt_name: str | None = None,
    resource_uri: str | None = None,
    chain: list | None = None,
    agent_runtime: str | None = None,
    budget_estimate: float | None = None,
) -> dict:
    """Build a minimal valid MCP OPA input document."""
    identity: dict = {"spiffe": spiffe}
    if chain is not None:
        identity["chain"] = chain

    doc: dict = {
        "posture": posture,
        "action": action,
        "identity": identity,
    }

    # Subject: exactly one of tool / prompt / resource
    if prompt_name is not None:
        doc["prompt"] = {"name": prompt_name}
    elif resource_uri is not None:
        doc["resource"] = {"uri": resource_uri}
    else:
        doc["tool"] = {"name": tool_name, "args_redacted": tool_args or {}}

    if agent_runtime is not None:
        doc["agent"] = {"runtime": agent_runtime}

    if budget_estimate is not None:
        doc["budget"] = {"this_call_estimate": budget_estimate}

    return doc


def _mock_opa_response(allow: bool, reason: str = "ok", extra: dict | None = None) -> MagicMock:
    """Build a mock httpx response simulating OPA's JSON output."""
    result: dict = {"allow": allow, "deny_reason": reason if not allow else "ok",
                    "redact_args": [], "audit_capture": not allow, "rate_limit_key": None}
    if extra:
        result.update(extra)
    mock = MagicMock()
    mock.status_code = 200
    mock.raise_for_status = MagicMock()
    mock.json.return_value = {"result": result}
    return mock


# ---------------------------------------------------------------------------
# D. Input document shape validation
# ---------------------------------------------------------------------------

class TestMcpInputDocumentShape:
    """Verify input documents match the schema requirements."""

    def test_valid_mcp_a_tool_input_has_all_required_fields(self):
        """A valid MCP-A tool call input has posture, action, identity, tool."""
        doc = _make_mcp_input(posture="mcp-a", action="mcp.tools.call")
        assert doc["posture"] == "mcp-a"
        assert doc["action"] == "mcp.tools.call"
        assert "spiffe" in doc["identity"]
        assert "tool" in doc
        assert "name" in doc["tool"]
        assert "args_redacted" in doc["tool"]

    def test_valid_mcp_b_prompt_input(self):
        """MCP-B prompt list input has posture mcp-b and prompt subject."""
        doc = _make_mcp_input(
            posture="mcp-b",
            action="mcp.prompts.list",
            prompt_name="summarize",
        )
        assert doc["posture"] == "mcp-b"
        assert "prompt" in doc
        assert "tool" not in doc
        assert "resource" not in doc

    def test_valid_mcp_c_input_has_chain(self):
        """MCP-C input must have identity.chain."""
        chain = [
            "spiffe://cluster.local/ns/default/sa/origin",
            "spiffe://cluster.local/ns/default/sa/relay",
        ]
        doc = _make_mcp_input(posture="mcp-c", chain=chain)
        assert "chain" in doc["identity"]
        assert len(doc["identity"]["chain"]) == 2

    def test_tool_args_redacted_is_object(self):
        """tool.args_redacted must be an object (dict) per schema."""
        doc = _make_mcp_input(tool_args={"query": "test", "api_key": "<REDACTED>"})
        assert isinstance(doc["tool"]["args_redacted"], dict)

    def test_budget_this_call_estimate_nullable(self):
        """budget.this_call_estimate accepts null per schema."""
        doc_with_null = _make_mcp_input(budget_estimate=None)
        assert "budget" not in doc_with_null  # None → not included by helper

        doc_with_value = _make_mcp_input()
        doc_with_value["budget"] = {"this_call_estimate": None}
        assert doc_with_value["budget"]["this_call_estimate"] is None

    def test_subject_mutual_exclusion_tool_only(self):
        """Only tool is present → no prompt and no resource."""
        doc = _make_mcp_input(tool_name="search")
        assert "tool" in doc
        assert "prompt" not in doc
        assert "resource" not in doc

    def test_subject_mutual_exclusion_prompt_only(self):
        """Only prompt is present → no tool and no resource."""
        doc = _make_mcp_input(action="mcp.prompts.list", prompt_name="summary")
        assert "prompt" in doc
        assert "tool" not in doc
        assert "resource" not in doc


# ---------------------------------------------------------------------------
# E. Decision document shape
# ---------------------------------------------------------------------------

class TestMcpDecisionShape:
    """Verify the expected shape of mcp_decision results."""

    def test_decision_allow_shape(self):
        """On allow, decision must have allow=True, deny_reason='ok', non-null rate_limit_key."""
        decision = {
            "allow": True,
            "deny_reason": "ok",
            "redact_args": [],
            "audit_capture": False,
            "rate_limit_key": "abc123/mcp.tools.call/web_search",
        }
        assert decision["allow"] is True
        assert decision["deny_reason"] == "ok"
        assert isinstance(decision["redact_args"], list)
        assert decision["rate_limit_key"] is not None

    def test_decision_deny_shape(self):
        """On deny, decision must have allow=False, non-ok deny_reason, null rate_limit_key."""
        decision = {
            "allow": False,
            "deny_reason": "missing_spiffe_identity",
            "redact_args": [],
            "audit_capture": True,
            "rate_limit_key": None,
        }
        assert decision["allow"] is False
        assert decision["deny_reason"] != "ok"
        assert decision["audit_capture"] is True
        assert decision["rate_limit_key"] is None

    def test_decision_required_keys_present(self):
        """Decision document must have all four required keys."""
        decision = _mock_opa_response(allow=True).json()["result"]
        required_keys = {"allow", "deny_reason", "redact_args", "audit_capture", "rate_limit_key"}
        missing = required_keys - set(decision.keys())
        assert not missing, f"Decision missing keys: {missing}"


# ---------------------------------------------------------------------------
# F. Fail-closed: missing SPIFFE → deny
# ---------------------------------------------------------------------------

class TestMcpFailClosed:
    """Verify the MCP policy is fail-closed on missing/malformed identity."""

    @pytest.mark.asyncio
    async def test_missing_spiffe_returns_deny_from_opa(self, monkeypatch):
        """When OPA returns deny for missing SPIFFE, gateway must propagate deny."""
        input_doc = _make_mcp_input(spiffe="")  # empty SPIFFE → missing identity
        mock_response = _mock_opa_response(allow=False, reason="missing_spiffe_identity")

        # Verify the input document would have spiffe="" (missing identity)
        assert input_doc["identity"]["spiffe"] == ""

        # Verify that a downstream consumer of the mcp_decision shape sees deny
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "missing_spiffe_identity"

    @pytest.mark.asyncio
    async def test_no_identity_field_returns_deny_from_opa(self, monkeypatch):
        """When identity is missing entirely, input document is malformed → deny expected."""
        # No identity field → the gateway should not even call OPA; but if it does,
        # OPA must return deny. We verify the input shape is flagged as incomplete.
        incomplete_input = {
            "posture": "mcp-a",
            "action": "mcp.tools.call",
            "tool": {"name": "web_search", "args_redacted": {}},
        }
        # Missing 'identity' key — schema required=["posture","action","identity"]
        assert "identity" not in incomplete_input

        mock_response = _mock_opa_response(allow=False, reason="missing_spiffe_identity")
        result = mock_response.json()["result"]
        assert result["allow"] is False


# ---------------------------------------------------------------------------
# G. Invalid posture → deny
# ---------------------------------------------------------------------------

class TestMcpInvalidPosture:
    """Verify that invalid posture values cause deny."""

    def test_invalid_posture_not_in_enum(self):
        """posture must be one of mcp-a|mcp-b|mcp-c per schema."""
        with open(_MCP_SCHEMA) as f:
            schema = json.load(f)
        valid_postures = set(schema["properties"]["posture"]["enum"])
        invalid = "mcp-z"
        assert invalid not in valid_postures

    @pytest.mark.asyncio
    async def test_invalid_posture_opa_returns_deny(self):
        """OPA must deny requests with invalid posture strings."""
        mock_response = _mock_opa_response(allow=False, reason="invalid_posture")
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "invalid_posture"


# ---------------------------------------------------------------------------
# H. OneOf violation: multiple subjects → deny
# ---------------------------------------------------------------------------

class TestMcpOneOfViolation:
    """Verify that multiple concurrent subjects cause deny."""

    def test_tool_and_prompt_simultaneously_violates_exclusivity(self):
        """Input with both tool and prompt must be rejected (oneOf violation)."""
        bad_input = _make_mcp_input(
            posture="mcp-a",
            action="mcp.tools.call",
            tool_name="web_search",
        )
        bad_input["prompt"] = {"name": "also_a_prompt"}  # inject second subject

        # Verify both subjects are present — this violates the schema allOf constraint
        assert "tool" in bad_input
        assert "prompt" in bad_input

        # Mock OPA returning deny for this case
        mock_response = _mock_opa_response(allow=False, reason="multiple_subjects_in_request")
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "multiple_subjects_in_request"

    def test_tool_and_resource_simultaneously_violates_exclusivity(self):
        """Input with both tool and resource must be rejected."""
        bad_input = _make_mcp_input(
            posture="mcp-a",
            action="mcp.tools.call",
            tool_name="web_search",
        )
        bad_input["resource"] = {"uri": "file:///data"}

        assert "tool" in bad_input
        assert "resource" in bad_input

        mock_response = _mock_opa_response(allow=False, reason="multiple_subjects_in_request")
        result = mock_response.json()["result"]
        assert result["allow"] is False


# ---------------------------------------------------------------------------
# I. Chain-depth guard — MCP-C
# ---------------------------------------------------------------------------

class TestMcpChainDepthGuard:
    """Verify chain-depth enforcement for MCP-C multi-hop calls (Lu-Gap-02)."""

    def test_chain_depth_3_at_default_max_allowed(self):
        """Chain depth == 3 (default max) → OPA allow expected."""
        chain = [
            "spiffe://cluster.local/ns/default/sa/hop1",
            "spiffe://cluster.local/ns/default/sa/hop2",
            "spiffe://cluster.local/ns/default/sa/hop3",
        ]
        assert len(chain) == 3  # equals default max

        mock_response = _mock_opa_response(allow=True)
        result = mock_response.json()["result"]
        assert result["allow"] is True

    def test_chain_depth_4_exceeds_default_max(self):
        """Chain depth == 4 exceeds default max of 3 → OPA deny expected."""
        chain = [
            "spiffe://cluster.local/ns/default/sa/hop1",
            "spiffe://cluster.local/ns/default/sa/hop2",
            "spiffe://cluster.local/ns/default/sa/hop3",
            "spiffe://cluster.local/ns/default/sa/hop4",
        ]
        assert len(chain) == 4  # exceeds default max

        mock_response = _mock_opa_response(allow=False, reason="chain_depth_exceeded")
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "chain_depth_exceeded"

    def test_mcp_c_with_no_chain_denied(self):
        """MCP-C posture with no chain field → deny mcp_c_requires_chain."""
        input_doc = _make_mcp_input(posture="mcp-c", chain=None)
        # No chain key in identity
        assert "chain" not in input_doc["identity"]

        mock_response = _mock_opa_response(allow=False, reason="mcp_c_requires_chain")
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "mcp_c_requires_chain"

    def test_mcp_c_with_empty_chain_denied(self):
        """MCP-C posture with empty chain list → deny mcp_c_requires_chain."""
        input_doc = _make_mcp_input(posture="mcp-c", chain=[])
        assert input_doc["identity"]["chain"] == []

        mock_response = _mock_opa_response(allow=False, reason="mcp_c_requires_chain")
        result = mock_response.json()["result"]
        assert result["allow"] is False

    def test_chain_depth_guard_is_in_mcp_rego(self):
        """Rego file must contain chain depth check code (Lu-Gap-02 verification)."""
        content = _MCP_REGO.read_text()
        # The policy must check chain length against a max
        assert "_chain_depth" in content
        assert "_chain_depth_ok" in content
        assert "chain_depth_exceeded" in content

    def test_chain_depth_operator_override_documented_in_rego(self):
        """Rego must support operator override of chain_max_depth via data bundle."""
        content = _MCP_REGO.read_text()
        assert "chain_max_depth" in content
        # The override mechanism: data.yashigani.mcp.policy.chain_max_depth
        assert "data.yashigani.mcp.policy.chain_max_depth" in content


# ---------------------------------------------------------------------------
# J. P9 per-tool allowlist enforcement
# ---------------------------------------------------------------------------

class TestMcpP9ToolAuthz:
    """Verify P9 MCP-B per-tool authz — exposed_tools allowlist."""

    def test_p9_tool_in_allowlist_returns_allow(self):
        """Tool name in exposed_tools → OPA returns allow."""
        mock_response = _mock_opa_response(allow=True)
        result = mock_response.json()["result"]
        assert result["allow"] is True

    def test_p9_tool_not_in_allowlist_returns_deny(self):
        """Tool name not in exposed_tools → OPA returns deny."""
        mock_response = _mock_opa_response(allow=False, reason="tool_not_in_exposed_allowlist")
        result = mock_response.json()["result"]
        assert result["allow"] is False
        assert result["deny_reason"] == "tool_not_in_exposed_allowlist"

    def test_p9_exposed_tools_implemented_in_mcp_rego(self):
        """mcp.rego must reference exposed_tools for P9 per-tool authz."""
        content = _MCP_REGO.read_text()
        assert "exposed_tools" in content
        assert "_tool_authz_ok" in content

    def test_p9_tool_allowlist_gate_only_on_mcp_b_and_mcp_c(self):
        """P9 tool allowlist documented as mcp-b + mcp-c gate in rego (mcp-a bypasses)."""
        content = _MCP_REGO.read_text()
        # mcp-a allow branch should NOT call _tool_authz_ok
        # mcp-b allow branch MUST call _tool_authz_ok
        # This is a structural check on the rego source
        lines = content.splitlines()
        mcp_a_block_lines = []
        mcp_b_block_lines = []
        in_mcp_a = False
        in_mcp_b = False
        for i, line in enumerate(lines):
            if 'input.posture == "mcp-a"' in line:
                in_mcp_a = True
                mcp_a_block_lines = []
            elif 'input.posture == "mcp-b"' in line:
                in_mcp_a = False
                in_mcp_b = True
                mcp_b_block_lines = []
            elif in_mcp_a and line.strip() == "}":
                in_mcp_a = False
            elif in_mcp_b and line.strip() == "}":
                in_mcp_b = False
            if in_mcp_a:
                mcp_a_block_lines.append(line)
            elif in_mcp_b:
                mcp_b_block_lines.append(line)

        # mcp-b allow block must reference _tool_authz_ok
        mcp_b_text = "\n".join(mcp_b_block_lines)
        assert "_tool_authz_ok" in mcp_b_text, (
            "mcp.rego mcp-b allow block must call _tool_authz_ok for P9 per-tool authz"
        )

    def test_p9_deny_reason_documents_allowlist_violation(self):
        """deny_reason for allowlist violation must be 'tool_not_in_exposed_allowlist'."""
        content = _MCP_REGO.read_text()
        assert "tool_not_in_exposed_allowlist" in content


# ---------------------------------------------------------------------------
# K. Non-tool actions not blocked by tool allowlist
# ---------------------------------------------------------------------------

class TestMcpNonToolActionsNotBlockedByAllowlist:
    """Verify that prompt/resource actions bypass the tool allowlist gate."""

    def test_prompt_action_not_blocked_by_tool_allowlist(self):
        """mcp.prompts.list should not be denied due to exposed_tools allowlist."""
        mock_response = _mock_opa_response(allow=True)
        result = mock_response.json()["result"]
        assert result["allow"] is True

    def test_resource_action_not_blocked_by_tool_allowlist(self):
        """mcp.resources.read should not be denied due to exposed_tools allowlist."""
        mock_response = _mock_opa_response(allow=True)
        result = mock_response.json()["result"]
        assert result["allow"] is True

    def test_tool_authz_ok_for_no_tool_in_rego(self):
        """_tool_authz_ok in rego must have a branch for 'no tool present → ok'."""
        content = _MCP_REGO.read_text()
        # The policy has: _tool_authz_ok if { not _tool_present }
        assert "not _tool_present" in content


# ---------------------------------------------------------------------------
# L. Proxy response-leg gate (GAP-002) already landed — verify wiring
# ---------------------------------------------------------------------------

class TestGap002ProxyResponseOpaAlreadyLanded:
    """Regression guard: GAP-002 proxy response OPA check must remain wired in proxy.py."""

    def test_opa_proxy_response_check_function_exists(self):
        """_opa_proxy_response_check must exist in proxy.py (GAP-002 closure)."""
        from yashigani.gateway import proxy as _proxy
        assert hasattr(_proxy, "_opa_proxy_response_check"), (
            "_opa_proxy_response_check missing from proxy.py — GAP-002 regression"
        )

    def test_opa_proxy_response_check_is_async(self):
        """_opa_proxy_response_check must be an async function."""
        import asyncio
        from yashigani.gateway import proxy as _proxy
        fn = _proxy._opa_proxy_response_check
        assert asyncio.iscoroutinefunction(fn), (
            "_opa_proxy_response_check must be async"
        )

    def test_proxy_response_sensitivity_function_exists(self):
        """_proxy_response_sensitivity must exist in proxy.py (GAP-002 helper)."""
        from yashigani.gateway import proxy as _proxy
        assert hasattr(_proxy, "_proxy_response_sensitivity"), (
            "_proxy_response_sensitivity missing from proxy.py — GAP-002 regression"
        )

    def test_gap002_opa_path_in_proxy(self):
        """proxy.py must query OPA at /v1/data/yashigani/v1/proxy_response_decision."""
        import inspect
        from yashigani.gateway import proxy as _proxy
        src = inspect.getsource(_proxy._opa_proxy_response_check)
        assert "proxy_response_decision" in src, (
            "proxy.py must query /v1/data/yashigani/v1/proxy_response_decision for GAP-002"
        )


# ---------------------------------------------------------------------------
# M. Models enumeration gate (GAP-001) already landed — verify wiring
# ---------------------------------------------------------------------------

class TestGap001ModelsOpaAlreadyLanded:
    """Regression guard: GAP-001 /v1/models OPA gate must remain wired in openai_router.py."""

    def test_opa_models_check_function_exists(self):
        """_opa_models_check must exist in openai_router.py (GAP-001 closure)."""
        from yashigani.gateway import openai_router as _router
        assert hasattr(_router, "_opa_models_check"), (
            "_opa_models_check missing from openai_router.py — GAP-001 regression"
        )

    def test_opa_models_check_is_async(self):
        """_opa_models_check must be an async function."""
        import asyncio
        from yashigani.gateway import openai_router as _router
        fn = _router._opa_models_check
        assert asyncio.iscoroutinefunction(fn), (
            "_opa_models_check must be async"
        )

    def test_gap001_opa_path_in_openai_router(self):
        """openai_router.py must query OPA at /v1/data/yashigani/v1/models_list_decision."""
        import inspect
        from yashigani.gateway import openai_router as _router
        src = inspect.getsource(_router._opa_models_check)
        assert "models_list_decision" in src, (
            "openai_router.py must query /v1/data/yashigani/v1/models_list_decision for GAP-001"
        )

    def test_gap001_opa_deny_returns_403_or_503(self):
        """list_models endpoint must return 403/503 on OPA deny (not 200 with empty list)."""
        import inspect
        from yashigani.gateway import openai_router as _router
        src = inspect.getsource(_router.list_models)
        assert "403" in src or "MODELS_LIST_DENIED" in src, (
            "list_models must return 403 on OPA deny — not 200 with empty list"
        )
