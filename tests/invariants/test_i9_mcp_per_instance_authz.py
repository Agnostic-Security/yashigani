"""
I9 — MCP per-instance FOUR-GATE authz + change-prevention (v4.1 Phase 2b).

INVARIANT (must ALWAYS hold): no ``mcp.tools.call`` evaluates to allow=true in
``policy/mcp.rego`` on a remote posture (mcp-b / mcp-c) unless the input carried
ALL FOUR:

  1. ``identity.verified == true``  — gateway-attested SPIFFE↔leaf-SAN binding
     (LU-MCP-A1: a broker-asserted, name-derived SPIFFE alone never authorizes);
  2. a non-empty ``target.mcp_id`` — per-instance identification (LU-MCP-A2:
     two same-named MCPs share a name-SPIFFE, never an mcp_id);
  3. a per-instance / per-caller grant in
     ``data.yashigani.mcp.grants[mcp_id][spiffe]`` (closed world — LU-MCP-A2/A5);
  4. a ``target.surface_hash`` equal to the approved baseline in
     ``data.yashigani.mcp.baselines[mcp_id]`` with the tool inside the baseline
     tool set (change-prevention in POLICY, not only broker code — LU-MCP-A3).

Also pinned: the P9 ``exposed_tools`` gate is default-DENY (LU-MCP-A4) — the
pre-4.1 "allowlist absent/empty → gate open (backward-compat)" path is BANNED.

The approve-time deterministic structural diff (broker ``_envelope.py``) is the
only PRODUCER of grants + baselines — an LLM never grants. OPA is the ENFORCER
at invoke time. Absence of grant/baseline data is a closed world: everything
denies.

Two layers here:
  * text-level structural assertions on the rego source (always run);
  * LIVE adversarial probes through a real ``opa eval`` (run when the ``opa``
    binary is on PATH — CI release gate and dev machines have it; the rego unit
    suite ``policy/mcp_test.rego`` §11 duplicates these probes under ``opa test``
    so the contract is never gated on this optional path alone).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_REGO = REPO_ROOT / "policy" / "mcp.rego"
HELM_MCP_REGO = REPO_ROOT / "helm" / "yashigani" / "files" / "policy" / "mcp.rego"
SCHEMA = REPO_ROOT / "policy" / "mcp-input.schema.json"

FOUR_GATES = (
    "_identity_verified",
    "_instance_identified",
    "_grant_ok",
    "_envelope_unchanged",
)

DENY_REASONS = (
    "spiffe_not_verified",
    "instance_unidentified",
    "no_per_instance_grant",
    "capability_envelope_drift",
    "capability_envelope_not_active",
)


def _rego_text() -> str:
    return MCP_REGO.read_text(encoding="utf-8")


def _allow_blocks(text: str) -> list[str]:
    """Every top-level `allow if { ... }` body in mcp.rego."""
    return re.findall(r"^allow if \{\n(.*?)^\}", text, re.DOTALL | re.MULTILINE)


# --------------------------------------------------------------------------- #
# Text-level structural invariants (always run)
# --------------------------------------------------------------------------- #

def test_default_deny_present() -> None:
    assert "default allow := false" in _rego_text()


def test_four_gate_rules_exist() -> None:
    text = _rego_text()
    for gate in FOUR_GATES:
        assert f"{gate} if {{" in text, f"mcp.rego must define {gate}"


def test_every_remote_tools_call_allow_path_requires_all_four_gates() -> None:
    """Any allow body that can match mcp.tools.call on mcp-b/mcp-c must contain
    ALL FOUR gates. Bodies that exclude tools.call must say so explicitly."""
    blocks = _allow_blocks(_rego_text())
    assert blocks, "no allow blocks parsed from mcp.rego — parser drift, fix the test"
    checked = 0
    for body in blocks:
        if 'input.posture == "mcp-a"' in body:
            continue  # Shape A: transport-derived posture is the binding control
        if 'input.action != "mcp.tools.call"' in body:
            continue  # explicitly excludes invocation
        assert 'input.action == "mcp.tools.call"' in body, (
            "remote-posture allow block neither pins nor excludes mcp.tools.call — "
            "an invocation could slip through without the four-gate:\n" + body
        )
        for gate in FOUR_GATES:
            assert gate in body, f"tools.call allow path missing {gate}:\n" + body
        checked += 1
    assert checked >= 2, "expected four-gate tools.call allow paths for mcp-b AND mcp-c"


def test_exposed_tools_open_gate_is_banned() -> None:
    """The pre-4.1 default-OPEN behaviour must never return: no _tool_authz_ok
    body may pass on an EMPTY allowlist."""
    text = _rego_text()
    bodies = re.findall(r"^_tool_authz_ok if \{\n(.*?)^\}", text, re.DOTALL | re.MULTILINE)
    assert bodies, "_tool_authz_ok missing from mcp.rego"
    for body in bodies:
        assert "count(_exposed_tools) == 0" not in body, (
            "_tool_authz_ok re-grew the 'empty allowlist → open gate' path "
            "(LU-MCP-A4 regression):\n" + body
        )
        assert ("not _tool_present" in body) or ("input.tool.name in _exposed_tools" in body), (
            "_tool_authz_ok body is neither the no-tool-subject case nor an "
            "explicit allowlist membership check:\n" + body
        )


def test_per_instance_deny_reasons_exist() -> None:
    text = _rego_text()
    for reason in DENY_REASONS:
        assert f'"{reason}"' in text, f"deny_reason {reason} missing from mcp.rego"


def test_schema_carries_target_and_verified_contract() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert "verified" in schema["properties"]["identity"]["properties"]
    target = schema["properties"]["target"]["properties"]
    for key in ("mcp_id", "cert_fingerprint", "surface_hash"):
        assert key in target, f"target.{key} missing from mcp-input.schema.json"


def test_helm_bundle_mcp_rego_byte_identical() -> None:
    # I8 asserts the whole bundle; re-pinned here because THIS policy is the
    # authz perimeter — helm drift means K8s enforces different MCP authz.
    assert HELM_MCP_REGO.read_bytes() == MCP_REGO.read_bytes()


# --------------------------------------------------------------------------- #
# LIVE adversarial probes (real opa eval; skipped only when opa is absent)
# --------------------------------------------------------------------------- #

OPA = shutil.which("opa")

_SPIFFE = "spiffe://cluster.local/ns/default/sa/langflow"
_MCP_ID = "6a7b1c9e-0001-4000-8000-00000000i9"
_HASH = "sha256:" + "1" * 64

_AUTHZ_DATA = {
    "yashigani": {
        "mcp": {
            "grants": {_MCP_ID: {_SPIFFE: {"tools": ["web_search"], "actions": ["mcp.tools.call"]}}},
            "baselines": {_MCP_ID: {"surface_hash": _HASH, "tools": ["web_search"]}},
        }
    }
}

_GOOD_INPUT = {
    "posture": "mcp-b",
    "action": "mcp.tools.call",
    "identity": {"spiffe": _SPIFFE, "verified": True},
    "target": {"mcp_id": _MCP_ID, "cert_fingerprint": "sha256:leaf", "surface_hash": _HASH},
    "tool": {"name": "web_search", "args_redacted": {}},
}


def _eval(tmp_path: Path, input_doc: dict, data: dict | None) -> dict:
    cmd = [OPA, "eval", "--format", "json", "-d", str(MCP_REGO)]
    if data is not None:
        data_file = tmp_path / "authz_data.json"
        data_file.write_text(json.dumps(data), encoding="utf-8")
        cmd += ["-d", str(data_file)]
    cmd += ["--stdin-input", "data.yashigani.mcp.mcp_decision"]
    out = subprocess.run(
        cmd, input=json.dumps(input_doc), capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, f"opa eval failed: {out.stderr}"
    result = json.loads(out.stdout)["result"]
    assert result, "mcp_decision undefined — decision document must always be total"
    return result[0]["expressions"][0]["value"]


def _mutate(doc: dict, **top) -> dict:
    out = json.loads(json.dumps(doc))
    out.update(top)
    return out


pytestmark_live = pytest.mark.skipif(OPA is None, reason="opa binary not on PATH")


@pytestmark_live
def test_live_probe_the_probe_good_input_allows(tmp_path: Path) -> None:
    """The harness CAN produce allow=true — every deny below is a real deny,
    not a broken harness (SOP 4 probe-the-probe)."""
    d = _eval(tmp_path, _GOOD_INPUT, _AUTHZ_DATA)
    assert d["allow"] is True and d["deny_reason"] == "ok"


@pytestmark_live
def test_live_unverified_spiffe_denies(tmp_path: Path) -> None:
    doc = json.loads(json.dumps(_GOOD_INPUT))
    doc["identity"]["verified"] = False
    d = _eval(tmp_path, doc, _AUTHZ_DATA)
    assert d["allow"] is False and d["deny_reason"] == "spiffe_not_verified"


@pytestmark_live
def test_live_missing_target_denies(tmp_path: Path) -> None:
    doc = json.loads(json.dumps(_GOOD_INPUT))
    del doc["target"]
    d = _eval(tmp_path, doc, _AUTHZ_DATA)
    assert d["allow"] is False and d["deny_reason"] == "instance_unidentified"


@pytestmark_live
def test_live_drifted_surface_hash_denies(tmp_path: Path) -> None:
    doc = json.loads(json.dumps(_GOOD_INPUT))
    doc["target"]["surface_hash"] = "sha256:" + "2" * 64
    d = _eval(tmp_path, doc, _AUTHZ_DATA)
    assert d["allow"] is False and d["deny_reason"] == "capability_envelope_drift"


@pytestmark_live
def test_live_missing_grant_denies(tmp_path: Path) -> None:
    data = json.loads(json.dumps(_AUTHZ_DATA))
    data["yashigani"]["mcp"]["grants"] = {}
    d = _eval(tmp_path, _GOOD_INPUT, data)
    assert d["allow"] is False and d["deny_reason"] == "no_per_instance_grant"


@pytestmark_live
def test_live_no_data_at_all_denies_closed_world(tmp_path: Path) -> None:
    d = _eval(tmp_path, _GOOD_INPUT, None)
    assert d["allow"] is False and d["deny_reason"] == "capability_envelope_not_active"


@pytestmark_live
def test_live_legacy_open_gate_replay_still_denies(tmp_path: Path) -> None:
    """Regression pin: the exact input shape that was ALLOWED pre-4.1 (no
    verified flag, no target, no data loaded) must deny forever."""
    legacy = {
        "posture": "mcp-b",
        "action": "mcp.tools.call",
        "identity": {"spiffe": _SPIFFE},
        "tool": {"name": "dangerous_exec", "args_redacted": {}},
    }
    d = _eval(tmp_path, legacy, None)
    assert d["allow"] is False and d["deny_reason"] == "spiffe_not_verified"
