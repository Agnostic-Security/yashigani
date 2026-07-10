"""
Regression guard: YSG-RISK-056 — MCP-C chain_max_depth pinned as a policy constant.

The chain-depth limit must NOT be a runtime-overridable OPA data document (CWE-15:
the `data.yashigani.mcp.policy.chain_max_depth` path was writable via the OPA REST data
API, letting a policy-write cert holder raise the limit and defeat the chain-depth guard).
It is pinned in policy/mcp.rego and kept in sync with the broker + jwt defaults. Changing
it is a reviewed policy edit (a governed admin-UI setting is a tracked backlog item).

v2.25.2 — 2026-06-03.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[4]
PINNED = 9


def test_chain_max_depth_pinned_not_data_overridable() -> None:
    rego = (_ROOT / "policy" / "mcp.rego").read_text()
    assert re.search(rf"mcp_chain_max_depth\s*:=\s*{PINNED}\b", rego), \
        f"mcp_chain_max_depth not pinned to {PINNED}"
    # the runtime-writable data path must not appear in CODE (an explanatory comment may mention it)
    code = "\n".join(ln for ln in rego.splitlines() if not ln.lstrip().startswith("#"))
    assert "data.yashigani.mcp.policy.chain_max_depth" not in code, \
        "chain_max_depth still read from the operator-overridable OPA data path (CWE-15 regressed)"


def test_chain_max_depth_defaults_in_sync() -> None:
    broker = (_ROOT / "src" / "yashigani" / "mcp" / "broker.py").read_text()
    jwt = (_ROOT / "src" / "yashigani" / "mcp" / "_jwt.py").read_text()
    assert f"chain_max_depth: int = {PINNED}" in broker, "broker default out of sync with the pinned value"
    assert f"_DEFAULT_CHAIN_MAX_DEPTH = {PINNED}" in jwt, "jwt issuer default out of sync with the pinned value"
