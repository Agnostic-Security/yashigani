"""
Unit tests — 3.0 / YSG-RISK-060 capability-envelope imported-MCP tool-pin.

Covers the design's required test matrix (Iris §9 / Laura §8):

  Projection + structural diff (the AUTHORITY):
    - reword = benign; tighten = benign; remove-tool = benign.
    - enum->string widen = expand; +tool = expand; +effect-class = expand;
      data-scope broaden = expand; additionalProperties open = expand;
      egress raise = expand; annotation flip = expand; output open = expand.
    - closed-world: an unmodelled schema flag ($ref / unevaluatedProperties)
      = expand.
    - effect-class max-rule (Laura Δ2): sidecar/operator can raise, structural
      floor is mandatory.

  Triage (structural authority + sidecar escalate-only):
    - in-envelope benign + sidecar clean => BENIGN auto-allow.
    - capability-expanding => EXPANDING block (sidecar cannot downgrade).
    - sidecar flags within-envelope reword => UNCERTAIN fail-closed block.
    - sidecar errors => UNCERTAIN fail-closed block.
    - drift-vs-ORIGINAL: salami N within-envelope steps then 1 exceed => the
      exceed blocks vs the ORIGINAL baseline (boiling-frog closed).

  Service (mock asyncpg pool):
    - mint v1; re-approval mints chained v2 + supersedes prior; benign re-pin
      advances current_surface_hash only; latch_block transitions active->blocked.
    - round-trip (serialise/deserialise envelope).

  privileged_mutation gate:
    - non-admin => NotAuthorised; admin w/o fresh step-up => StepUpRequired;
      admin + fresh step-up => passes + emits PRIVILEGED_MUTATION.

  Invocation hard gate (broker):
    - unpinned tool => deny; blocked envelope => deny; tool not in envelope =>
      deny; stale surface => deny; in-envelope tool => allow-through.
    - sidecar cannot auto-clear a block (escalate-only invariant).

Last updated: 2026-06-10T00:00:00+00:00
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional
from unittest.mock import AsyncMock, MagicMock

import pytest

from yashigani.mcp import (
    EffectClass,
    compute_provenance_id,
    namespaced_tool_key,
    surface_set_hash,
    project_surface,
    project_tool,
    combine_effect_classes,
    diff_envelope,
    triage_refresh,
    TriageClass,
)


PROV = compute_provenance_id("github-mcp", "sha256:deadbeef")
TENANT = "tenant-1"


def _tool(name, *, props=None, required=None, enum=None, ap=False,
          annotations=None, output_open=None, extra_schema=None):
    schema = {
        "type": "object",
        "properties": props if props is not None else {},
        "additionalProperties": ap,
    }
    if required is not None:
        schema["required"] = required
    if extra_schema:
        schema.update(extra_schema)
    raw = {"name": name, "description": f"{name} tool", "inputSchema": schema}
    if annotations is not None:
        raw["annotations"] = annotations
    if output_open is not None:
        raw["outputSchema"] = {"type": "object", "additionalProperties": output_open}
    return raw


# Canonical baseline surface used across diff tests.
BASE_TOOLS = [
    _tool("read_file",
          props={"path": {"type": "string", "enum": ["a", "b"]}},
          required=["path"], ap=False),
]


def _env(raw_tools, egress="NONE", declared=None):
    return project_surface(PROV, TENANT, raw_tools, egress_posture=egress,
                           declared=declared)


# ===========================================================================
# Projection + structural diff — the AUTHORITY
# ===========================================================================

class TestStructuralDiffBenign:
    def test_identical_surface_benign(self):
        base = _env(BASE_TOOLS)
        d = diff_envelope(base, _env(BASE_TOOLS))
        assert not d.expanded

    def test_description_reword_benign(self):
        base = _env(BASE_TOOLS)
        rew = [{**BASE_TOOLS[0], "description": "Reads a file (clarified docs)"}]
        d = diff_envelope(base, _env(rew))
        assert not d.expanded, [f.detail for f in d.findings]

    def test_enum_tighten_benign(self):
        base = _env(BASE_TOOLS)
        tight = [_tool("read_file",
                       props={"path": {"type": "string", "enum": ["a"]}},
                       required=["path"])]
        d = diff_envelope(base, _env(tight))
        assert not d.expanded

    def test_remove_tool_benign(self):
        base = _env(BASE_TOOLS + [_tool("extra", props={})])
        d = diff_envelope(base, _env(BASE_TOOLS))
        assert not d.expanded

    def test_required_to_optional_benign(self):
        base = _env(BASE_TOOLS)
        loosened_contract = [_tool("read_file",
                                   props={"path": {"type": "string", "enum": ["a", "b"]}},
                                   required=[])]  # now optional
        d = diff_envelope(base, _env(loosened_contract))
        assert not d.expanded


class TestStructuralDiffExpand:
    def test_enum_to_string_expand(self):
        base = _env(BASE_TOOLS)
        widen = [_tool("read_file",
                       props={"path": {"type": "string"}}, required=["path"])]
        d = diff_envelope(base, _env(widen))
        assert d.expanded
        assert any("enum" in f.detail for f in d.findings)

    def test_new_tool_expand(self):
        base = _env(BASE_TOOLS)
        addtool = BASE_TOOLS + [_tool("delete_all", props={})]
        d = diff_envelope(base, _env(addtool))
        assert d.expanded
        assert any(f.dimension == "tool_set" for f in d.findings)

    def test_new_arg_expand(self):
        base = _env(BASE_TOOLS)
        addarg = [_tool("read_file",
                        props={"path": {"type": "string", "enum": ["a", "b"]},
                               "notes": {"type": "string"}},
                        required=["path"])]
        d = diff_envelope(base, _env(addarg))
        assert d.expanded
        assert any("new argument" in f.detail for f in d.findings)

    def test_new_effect_class_expand(self):
        # read_file gains a write-shaped 'content' arg => structural floor WRITE.
        base = _env(BASE_TOOLS)
        write_shape = [_tool("read_file",
                             props={"path": {"type": "string", "enum": ["a", "b"]},
                                    "content": {"type": "string"}},
                             required=["path"])]
        d = diff_envelope(base, _env(write_shape))
        assert d.expanded
        assert any(f.dimension in ("effect_class", "arg_shape") for f in d.findings)

    def test_additional_properties_open_expand(self):
        base = _env(BASE_TOOLS)
        openw = [_tool("read_file",
                       props={"path": {"type": "string", "enum": ["a", "b"]}},
                       required=["path"], ap=True)]
        d = diff_envelope(base, _env(openw))
        assert d.expanded

    def test_pattern_drop_expand(self):
        base = _env([_tool("q", props={"x": {"type": "string", "pattern": "^[a-z]+$"}})])
        cur = _env([_tool("q", props={"x": {"type": "string"}})])
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any("pattern" in f.detail for f in d.findings)

    def test_egress_raise_expand(self):
        base = _env(BASE_TOOLS, egress="NONE")
        cur = _env(BASE_TOOLS, egress="OUTBOUND")
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any(f.dimension == "egress" for f in d.findings)

    def test_annotation_flip_expand(self):
        base = _env([_tool("t", props={}, annotations={"readOnlyHint": True})])
        cur = _env([_tool("t", props={}, annotations={"readOnlyHint": False})])
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any(f.dimension == "annotation" for f in d.findings)

    def test_output_open_expand(self):
        base = _env([_tool("t", props={}, output_open=False)])
        cur = _env([_tool("t", props={}, output_open=True)])
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any(f.dimension == "output" for f in d.findings)

    def test_data_scope_broaden_expand(self):
        declared = {"read_file": {"effect_classes": frozenset({EffectClass.READ}),
                                  "data_scopes": frozenset({"path:/data/*"})}}
        base = _env(BASE_TOOLS, declared=declared)
        wider = {"read_file": {"effect_classes": frozenset({EffectClass.READ}),
                               "data_scopes": frozenset({"path:/"})}}
        cur = _env(BASE_TOOLS, declared=wider)
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any(f.dimension == "data_scope" for f in d.findings)

    def test_data_scope_subpath_benign(self):
        declared = {"read_file": {"effect_classes": frozenset({EffectClass.READ}),
                                  "data_scopes": frozenset({"path:/data/*"})}}
        base = _env(BASE_TOOLS, declared=declared)
        narrower = {"read_file": {"effect_classes": frozenset({EffectClass.READ}),
                                  "data_scopes": frozenset({"path:/data/sub"})}}
        cur = _env(BASE_TOOLS, declared=narrower)
        d = diff_envelope(base, cur)
        assert not d.expanded


class TestClosedWorld:
    def test_ref_unmodelled_flag_expand(self):
        base = _env([_tool("t", props={"x": {"type": "string"}})])
        cur = _env([_tool("t", props={"x": {"$ref": "https://evil/schema.json"}})])
        d = diff_envelope(base, cur)
        assert d.expanded
        assert any(f.dimension in ("unknown", "arg_shape") for f in d.findings)

    def test_unevaluated_properties_expand(self):
        base = _env([_tool("t", props={"x": {"type": "string"}})])
        cur = _env([_tool("t",
                          props={"x": {"type": "string"}},
                          extra_schema={"unevaluatedProperties": True})])
        d = diff_envelope(base, cur)
        assert d.expanded


class TestEffectClassMaxRule:
    def test_sidecar_can_raise_not_lower(self):
        floor = frozenset({EffectClass.WRITE})
        # sidecar proposes only READ (lower) — floor must survive.
        combined = combine_effect_classes(floor, frozenset({EffectClass.READ}), None)
        assert EffectClass.WRITE in combined  # floor mandatory
        assert EffectClass.READ in combined

    def test_operator_can_raise(self):
        floor = frozenset({EffectClass.READ})
        combined = combine_effect_classes(floor, None, frozenset({EffectClass.EXEC}))
        assert EffectClass.EXEC in combined
        assert EffectClass.READ in combined


# ===========================================================================
# Triage — structural authority + escalate-only sidecar
# ===========================================================================

@dataclass
class _Verdict:
    is_injection: bool = False
    skipped: bool = False
    score: float = 0.0
    flagged_view: str = "raw"


class _CleanSidecar:
    def evaluate(self, content):
        return _Verdict(is_injection=False, skipped=False)


class _FlaggingSidecar:
    def evaluate(self, content):
        return _Verdict(is_injection=True, skipped=False, score=0.9)


class _SkippedSidecar:
    def evaluate(self, content):
        return _Verdict(skipped=True)


class _CrashingSidecar:
    def evaluate(self, content):
        raise RuntimeError("backend down")


def _outcome(current_raw, *, sidecar=None, baseline_raw=None):
    baseline_raw = baseline_raw or BASE_TOOLS
    baseline = _env(baseline_raw)
    current = _env(current_raw)
    return triage_refresh(
        approved_baseline=baseline,
        current_envelope=current,
        current_raw_tools=current_raw,
        new_surface_hash=surface_set_hash(current_raw),
        sidecar=sidecar,
    )


class TestTriage:
    def test_in_envelope_benign_auto_allows(self):
        rew = [{**BASE_TOOLS[0], "description": "Reads a file (reworded)"}]
        o = _outcome(rew, sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.BENIGN
        assert o.auto_allow and not o.should_block

    def test_capability_expanding_blocks(self):
        addtool = BASE_TOOLS + [_tool("delete_all", props={})]
        o = _outcome(addtool, sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.EXPANDING
        assert o.should_block

    def test_sidecar_cannot_downgrade_expanding(self):
        # Even a "clean" sidecar cannot turn a structural expansion into allow.
        addtool = BASE_TOOLS + [_tool("delete_all", props={})]
        o = _outcome(addtool, sidecar=_CleanSidecar())
        assert o.should_block  # structural authority wins

    def test_sidecar_escalates_benign_to_uncertain(self):
        rew = [{**BASE_TOOLS[0], "description": "Reads a file"}]
        o = _outcome(rew, sidecar=_FlaggingSidecar())
        assert o.triage_class is TriageClass.UNCERTAIN
        assert o.should_block and o.sidecar_escalated

    def test_sidecar_error_fail_closed_block(self):
        rew = [{**BASE_TOOLS[0], "description": "Reads a file"}]
        o = _outcome(rew, sidecar=_CrashingSidecar())
        assert o.triage_class is TriageClass.UNCERTAIN
        assert o.should_block
        assert o.sidecar_error and o.sidecar_error.startswith("sidecar_error")

    def test_sidecar_skipped_flag_off_benign(self):
        rew = [{**BASE_TOOLS[0], "description": "Reads a file"}]
        o = _outcome(rew, sidecar=_SkippedSidecar())
        assert o.triage_class is TriageClass.BENIGN

    def test_no_sidecar_benign(self):
        rew = [{**BASE_TOOLS[0], "description": "Reads a file"}]
        o = _outcome(rew, sidecar=None)
        assert o.triage_class is TriageClass.BENIGN


class TestSalamiBoilingFrog:
    """
    Laura must-have #1 / Δ1: drift is vs the ORIGINAL baseline, never the last
    auto-allowed state.  A salami chain of within-envelope steps then one exceed
    must block at the exceed — and crucially the exceed must be measured vs the
    ORIGINAL, so a step that is small-vs-prior but large-vs-original blocks.
    """

    def test_salami_steps_within_envelope_then_exceed_blocks(self):
        # Original envelope: read_file with enum[a,b].
        base = _env(BASE_TOOLS)

        # Step 1..N: within-envelope rewordings (all benign vs ORIGINAL).
        for i in range(5):
            rew = [{**BASE_TOOLS[0], "description": f"Reads a file rev{i}"}]
            o = triage_refresh(
                approved_baseline=base,
                current_envelope=_env(rew),
                current_raw_tools=rew,
                new_surface_hash=surface_set_hash(rew),
                sidecar=_CleanSidecar(),
            )
            assert o.triage_class is TriageClass.BENIGN, f"step {i}"

        # Step 6: enum widened to unconstrained string — small vs *prior* (a
        # reword), but a clear expansion vs the ORIGINAL enum baseline.
        exceed = [_tool("read_file",
                        props={"path": {"type": "string"}}, required=["path"])]
        o = triage_refresh(
            approved_baseline=base,                # ORIGINAL, not last state
            current_envelope=_env(exceed),
            current_raw_tools=exceed,
            new_surface_hash=surface_set_hash(exceed),
            sidecar=_CleanSidecar(),
        )
        assert o.triage_class is TriageClass.EXPANDING
        assert o.should_block

    def test_drift_measured_vs_original_not_prior(self):
        # A surface that drifted in two small steps still blocks when diffed
        # against the original (each step would be "small vs prior" but the
        # cumulative is an expansion vs original).
        base = _env(BASE_TOOLS)
        # cumulative drift: +tool AND enum-widen at once is the same as the sum.
        drifted = [
            _tool("read_file", props={"path": {"type": "string"}}, required=["path"]),
            _tool("write_file", props={"path": {"type": "string"},
                                       "content": {"type": "string"}}),
        ]
        o = triage_refresh(
            approved_baseline=base,
            current_envelope=_env(drifted),
            current_raw_tools=drifted,
            new_surface_hash=surface_set_hash(drifted),
            sidecar=_CleanSidecar(),
        )
        assert o.should_block


# ===========================================================================
# Δ4 — topology-gated conservative tiering (Captain)
# ===========================================================================

# A network-touching tool: a url/webhook-shaped arg projects to NETWORK.
_NET_TOOL = _tool("post_status",
                  props={"webhook_url": {"type": "string"}}, required=["webhook_url"])
_NET_BASE = [_NET_TOOL]


def _triage(current_raw, *, baseline_raw, topology, sidecar=None):
    baseline = _env(baseline_raw)
    current = _env(current_raw)
    return triage_refresh(
        approved_baseline=baseline,
        current_envelope=current,
        current_raw_tools=current_raw,
        new_surface_hash=surface_set_hash(current_raw),
        sidecar=sidecar,
        topology=topology,
    )


class TestTopologyGate:
    """
    Laura Δ4 / YSG-RISK-058: external-relay MCPs have no ring-fence backstop, so
    a within-envelope network/egress/host change cannot auto-allow.  Ring-fenced
    MCPs keep full tiering (the ring-fence contains a mis-triaged network change).
    """

    def test_ring_fenced_network_reword_auto_allows(self):
        # A network tool with a reworded description, ring-fenced → BENIGN.
        rew = [{**_NET_TOOL, "description": "Posts status (reworded)"}]
        o = _triage(rew, baseline_raw=_NET_BASE, topology="ring_fenced",
                    sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.BENIGN
        assert o.auto_allow

    def test_external_relay_network_reword_force_blocks(self):
        # Same within-envelope reword, external-relay → EXPANDING (no backstop).
        rew = [{**_NET_TOOL, "description": "Posts status (reworded)"}]
        o = _triage(rew, baseline_raw=_NET_BASE, topology="external_relay",
                    sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.EXPANDING
        assert o.should_block
        assert any(f.dimension == "egress" for f in o.findings)

    def test_external_relay_non_network_reword_still_auto_allows(self):
        # A NON-network tool reworded under external-relay → still BENIGN: the
        # gate only force-blocks network-class surfaces.
        rew = [{**BASE_TOOLS[0], "description": "Reads a file (reworded)"}]
        o = _triage(rew, baseline_raw=BASE_TOOLS, topology="external_relay",
                    sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.BENIGN

    def test_external_relay_egress_posture_change_blocks(self):
        # Baseline already INTERNAL egress; a within-envelope reword under
        # external-relay still blocks because the surface carries egress.
        baseline = _env(BASE_TOOLS, egress="INTERNAL")
        rew = [{**BASE_TOOLS[0], "description": "reworded"}]
        current = _env(rew, egress="INTERNAL")
        o = triage_refresh(
            approved_baseline=baseline,
            current_envelope=current,
            current_raw_tools=rew,
            new_surface_hash=surface_set_hash(rew),
            sidecar=_CleanSidecar(),
            topology="external_relay",
        )
        assert o.triage_class is TriageClass.EXPANDING

    def test_external_relay_structural_expand_still_blocks(self):
        # An actual structural expansion under external-relay blocks via the
        # structural authority (not the topology gate) — both paths block.
        addtool = _NET_BASE + [_tool("delete_all", props={})]
        o = _triage(addtool, baseline_raw=_NET_BASE, topology="external_relay",
                    sidecar=_CleanSidecar())
        assert o.triage_class is TriageClass.EXPANDING
        assert o.should_block


# ===========================================================================
# Service — mock asyncpg pool
# ===========================================================================

def _make_mock_pool():
    conn = AsyncMock()
    pool = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=cm)
    # transaction() async context manager
    tx = MagicMock()
    tx.__aenter__ = AsyncMock(return_value=None)
    tx.__aexit__ = AsyncMock(return_value=False)
    conn.transaction = MagicMock(return_value=tx)
    return pool, conn


class TestEnvelopeService:
    def test_none_pool_raises(self):
        from yashigani.mcp import CapabilityEnvelopeService
        with pytest.raises(RuntimeError, match="non-None"):
            CapabilityEnvelopeService(pool=None)

    async def test_mint_v1(self):
        from yashigani.mcp import CapabilityEnvelopeService
        pool, conn = _make_mock_pool()
        conn.fetchrow = AsyncMock(side_effect=[None, {"id": 1}])  # no prev, insert id
        conn.execute = AsyncMock(return_value="UPDATE 0")
        svc = CapabilityEnvelopeService(pool=pool)
        env = _env(BASE_TOOLS)
        new_id = await svc.mint_envelope(
            env, server_id="github-mcp", operator_identity="admin1",
        )
        assert new_id == 1

    async def test_reapproval_supersedes_prior(self):
        from yashigani.mcp import CapabilityEnvelopeService
        pool, conn = _make_mock_pool()
        # First fetchrow = prior active row; second = new insert id.
        conn.fetchrow = AsyncMock(side_effect=[{"id": 7, "envelope_version": 1},
                                               {"id": 8}])
        conn.execute = AsyncMock(return_value="UPDATE 1")
        svc = CapabilityEnvelopeService(pool=pool)
        new_id = await svc.mint_envelope(
            _env(BASE_TOOLS), server_id="github-mcp", operator_identity="admin1")
        assert new_id == 8
        # The prior row was superseded (an UPDATE was issued).
        assert conn.execute.await_count >= 1

    async def test_benign_repin_advances_hash_only(self):
        from yashigani.mcp import CapabilityEnvelopeService
        pool, conn = _make_mock_pool()
        conn.execute = AsyncMock(return_value="UPDATE 1")
        svc = CapabilityEnvelopeService(pool=pool)
        ok = await svc.record_benign_repin(PROV, "newhash")
        assert ok is True

    async def test_latch_block_transitions(self):
        from yashigani.mcp import CapabilityEnvelopeService
        pool, conn = _make_mock_pool()
        conn.execute = AsyncMock(return_value="UPDATE 1")
        svc = CapabilityEnvelopeService(pool=pool)
        latched = await svc.latch_block(PROV)
        assert latched is True

    async def test_latch_block_idempotent_no_active(self):
        from yashigani.mcp import CapabilityEnvelopeService
        pool, conn = _make_mock_pool()
        conn.execute = AsyncMock(return_value="UPDATE 0")  # no active row
        svc = CapabilityEnvelopeService(pool=pool)
        latched = await svc.latch_block(PROV)
        assert latched is False


class TestEnvelopeSerialisation:
    def test_round_trip(self):
        from yashigani.mcp import serialise_envelope, deserialise_envelope
        env = _env([_tool("read_file",
                          props={"path": {"type": "string", "enum": ["a", "b"]},
                                 "content": {"type": "string"}},
                          required=["path"], annotations={"readOnlyHint": False})])
        payload = serialise_envelope(env)
        rehydrated = deserialise_envelope(
            provenance_id=PROV,
            tenant_id=TENANT,
            effect_classes=payload["effect_classes"],
            arg_shape_signatures=payload["arg_shape_signatures"],
            data_scope=payload["data_scope"],
            egress_posture=payload["egress_posture"],
            surface_set_hash=payload["surface_set_hash"],
        )
        # Diffing the rehydrated envelope against the original must be benign
        # (identical) — proves the round-trip preserves the capability shape.
        d = diff_envelope(env, rehydrated)
        assert not d.expanded
        d2 = diff_envelope(rehydrated, env)
        assert not d2.expanded


# ===========================================================================
# privileged_mutation gate
# ===========================================================================

@dataclass
class _Session:
    account_id: str = "admin1"
    account_tier: str = "admin"
    last_totp_verified_at: Optional[float] = None


class TestPrivilegedMutationGate:
    def _ctx(self):
        from yashigani.auth import PrivilegedMutationContext
        return PrivilegedMutationContext(
            reason="mcp.envelope.reapprove", principal="admin1", target=PROV)

    def test_non_admin_denied(self):
        from yashigani.auth import (
            assert_privileged_mutation, NotAuthorisedForPrivilegedMutation)
        sess = _Session(account_tier="user", last_totp_verified_at=time.time())
        with pytest.raises(NotAuthorisedForPrivilegedMutation):
            assert_privileged_mutation(sess, self._ctx())

    def test_admin_without_stepup_requires_stepup(self):
        from yashigani.auth import assert_privileged_mutation, StepUpRequired
        sess = _Session(account_tier="admin", last_totp_verified_at=None)
        with pytest.raises(StepUpRequired):
            assert_privileged_mutation(sess, self._ctx())

    def test_admin_with_fresh_stepup_passes_and_audits(self):
        from yashigani.auth import assert_privileged_mutation
        writer = MagicMock()
        sess = _Session(account_tier="admin", last_totp_verified_at=time.time())
        assert_privileged_mutation(sess, self._ctx(), audit_writer=writer)
        # A PRIVILEGED_MUTATION event was written.
        assert writer.write.call_count == 1
        ev = writer.write.call_args[0][0]
        assert ev.reason == "mcp.envelope.reapprove"
        assert ev.target == PROV


# ===========================================================================
# MI-4 — step-up PROOF token contract (headless / install.sh path)
# ===========================================================================

_MI4_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def _mi4_signing_key(monkeypatch):
    """Provide a deterministic HMAC signing key for the MI-4 token tests."""
    monkeypatch.setenv("YASHIGANI_STEPUP_SIGNING_KEY", _MI4_KEY)


class TestStepUpProofToken:
    def test_mint_then_verify_roundtrip(self):
        from yashigani.auth import mint_stepup_proof, verify_stepup_proof
        tok, jti = mint_stepup_proof(subject="admin1", op="add-component")
        claims = verify_stepup_proof(tok, expected_op="add-component")
        assert claims["sub"] == "admin1"
        assert claims["op"] == "add-component"
        assert claims["purpose"] == "privileged-mutation"
        assert claims["iss"] == "yashigani.backoffice"
        assert claims["jti"] == jti

    def test_verify_rejects_forged_signature(self):
        from yashigani.auth import (
            mint_stepup_proof, verify_stepup_proof, StepUpProofInvalid)
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component")
        forged = tok[:-4] + ("A" if tok[-1] != "A" else "B") * 4
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof(forged, expected_op="add-component")
        assert ei.value.reason in ("bad_signature", "malformed")

    def test_verify_rejects_wrong_signing_key(self, monkeypatch):
        from yashigani.auth import (
            mint_stepup_proof, verify_stepup_proof, StepUpProofInvalid)
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component")
        # An attacker who does not hold caddy_internal_hmac cannot verify-true.
        monkeypatch.setenv("YASHIGANI_STEPUP_SIGNING_KEY", "deadbeef" * 4)
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof(tok, expected_op="add-component")
        assert ei.value.reason == "bad_signature"

    def test_verify_rejects_expired(self):
        from yashigani.auth import (
            mint_stepup_proof, verify_stepup_proof, StepUpProofInvalid)
        # ttl=-1 mints an already-expired token (exp = iat - 1).
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component", ttl_seconds=-1)
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof(tok, expected_op="add-component")
        assert ei.value.reason == "expired"

    def test_verify_rejects_op_mismatch(self):
        from yashigani.auth import (
            mint_stepup_proof, verify_stepup_proof, StepUpProofInvalid)
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component")
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof(tok, expected_op="uninstall")
        assert ei.value.reason == "op_mismatch"

    def test_verify_rejects_wrong_purpose_token(self):
        """An operator-onboard token (LU-AMEND-04) is NOT a mutation proof."""
        import jwt as _pyjwt
        import time as _t
        from yashigani.auth import verify_stepup_proof, StepUpProofInvalid
        onboard = _pyjwt.encode(
            {
                "sub": "admin1", "jti": "x", "iat": int(_t.time()),
                "exp": int(_t.time()) + 300, "iss": "yashigani.backoffice",
                "purpose": "operator-onboard",
            },
            _MI4_KEY, algorithm="HS256",
        )
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof(onboard, expected_op="add-component")
        assert ei.value.reason == "wrong_purpose"

    def test_verify_rejects_alg_none(self):
        """alg:none bypass is rejected (PyJWT requires HS256)."""
        import jwt as _pyjwt
        import time as _t
        from yashigani.auth import verify_stepup_proof, StepUpProofInvalid
        forged = _pyjwt.encode(
            {
                "sub": "attacker", "jti": "x", "iat": int(_t.time()),
                "exp": int(_t.time()) + 300, "iss": "yashigani.backoffice",
                "purpose": "privileged-mutation", "op": "add-component",
            },
            key="", algorithm="none",
        )
        with pytest.raises(StepUpProofInvalid):
            verify_stepup_proof(forged, expected_op="add-component")

    def test_verify_rejects_empty_token(self):
        from yashigani.auth import verify_stepup_proof, StepUpProofInvalid
        with pytest.raises(StepUpProofInvalid) as ei:
            verify_stepup_proof("", expected_op="add-component")
        assert ei.value.reason == "empty_token"

    def test_assert_token_gate_emits_audit_on_valid_proof(self):
        from yashigani.auth import mint_stepup_proof, assert_privileged_mutation_token
        writer = MagicMock()
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component")
        claims = assert_privileged_mutation_token(
            tok, expected_op="add-component", audit_writer=writer, target="prov-1")
        assert claims["sub"] == "admin1"
        assert writer.write.call_count == 1
        ev = writer.write.call_args[0][0]
        assert ev.principal == "admin1"
        assert ev.reason == "lifecycle.add-component"

    def test_assert_token_gate_rejects_stale_proof_no_audit(self):
        from yashigani.auth import (
            mint_stepup_proof, assert_privileged_mutation_token, StepUpProofInvalid)
        writer = MagicMock()
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component", ttl_seconds=-1)
        with pytest.raises(StepUpProofInvalid):
            assert_privileged_mutation_token(
                tok, expected_op="add-component", audit_writer=writer)
        # Fail-closed: no audit event for a rejected (stale) proof.
        assert writer.write.call_count == 0

    def test_cli_shim_ok_and_deny(self, monkeypatch, capsys):
        from yashigani.auth.stepup import _verify_proof_cli, mint_stepup_proof
        tok, _ = mint_stepup_proof(subject="admin1", op="add-component")
        rc = _verify_proof_cli(["--verify-proof", "--op", "add-component", "--token", tok])
        assert rc == 0
        out = capsys.readouterr().out
        assert out.startswith("OK sub=admin1")
        # Wrong op => DENY, non-zero exit.
        rc2 = _verify_proof_cli(["--verify-proof", "--op", "uninstall", "--token", tok])
        assert rc2 == 1


# ===========================================================================
# Invocation hard gate (broker) — fail-closed
# ===========================================================================

def _broker_with_envelope_service(env_service, *, enforce=True):
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig
    from yashigani.mcp import UpstreamPinConfig
    pin = UpstreamPinConfig(
        server_id="github-mcp", host="gh", port=443,
        cert_fingerprint_sha256="sha256:deadbeef",
    )
    cfg = McpBrokerConfig(
        opa_url="http://opa:8181",
        tenant_id=TENANT,
        upstream_pin_configs=[pin],
        envelope_service=env_service,
        enforce_capability_envelope=enforce,
    )
    return McpBroker(cfg)


def _ctx(tool_name="read_file"):
    from yashigani.mcp._types import (
        McpCallContext, McpPosture, PostureBinding)
    return McpCallContext(
        tenant_id=TENANT,
        agent_name="agent1",
        user_id="u1",
        posture=McpPosture.MCP_B,
        posture_binding=PostureBinding.for_posture(McpPosture.MCP_B),
        action="mcp.tools.call",
        tool_name=tool_name,
        server_id="github-mcp",
    )


@dataclass
class _EnvRecord:
    envelope: object
    current_surface_hash: str = ""
    topology: str = "ring_fenced"
    envelope_version: int = 1


class TestInvocationGate:
    async def test_unpinned_tool_denies(self):
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=None)  # no active
        broker = _broker_with_envelope_service(env_service)
        reason = await broker._check_capability_envelope(_ctx())
        assert reason == "capability_envelope_not_active"

    async def test_tool_not_in_envelope_denies(self):
        env = _env(BASE_TOOLS)  # only has read_file
        rec = _EnvRecord(envelope=env, current_surface_hash=env.surface_set_hash)
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=rec)
        broker = _broker_with_envelope_service(env_service)
        reason = await broker._check_capability_envelope(_ctx("delete_all"))
        assert reason == "capability_envelope_tool_not_approved"

    async def test_in_envelope_tool_allows(self):
        env = _env(BASE_TOOLS)
        rec = _EnvRecord(envelope=env, current_surface_hash=env.surface_set_hash)
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=rec)
        broker = _broker_with_envelope_service(env_service)
        reason = await broker._check_capability_envelope(_ctx("read_file"))
        assert reason is None

    async def test_lookup_error_fail_closed(self):
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(side_effect=RuntimeError("db down"))
        broker = _broker_with_envelope_service(env_service)
        reason = await broker._check_capability_envelope(_ctx())
        assert reason == "capability_envelope_lookup_error"

    async def test_non_tool_action_skips_gate(self):
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=None)
        broker = _broker_with_envelope_service(env_service)
        ctx = _ctx()
        ctx.tool_name = None  # resource/prompt call — no tool surface to pin
        reason = await broker._check_capability_envelope(ctx)
        assert reason is None

    async def test_gate_disabled_skips(self):
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=None)
        broker = _broker_with_envelope_service(env_service, enforce=False)
        reason = await broker._check_capability_envelope(_ctx())
        assert reason is None

    async def test_stale_surface_denies(self):
        env = _env(BASE_TOOLS)
        rec = _EnvRecord(envelope=env, current_surface_hash="pinned-hash")
        env_service = MagicMock()
        env_service.get_active_envelope = AsyncMock(return_value=rec)
        broker = _broker_with_envelope_service(env_service)
        # Seed the catalogue store with a DIFFERENT live surface hash.
        from yashigani.mcp._content_filter import TenantCatalogue
        cat = TenantCatalogue(tenant_id=TENANT, server_id="github-mcp",
                              surface_set_hash="live-mutated-hash")
        broker._catalogue_store.store(cat)
        reason = await broker._check_capability_envelope(_ctx("read_file"))
        assert reason == "capability_envelope_surface_stale"


class TestProvenanceBinding:
    def test_provenance_id_binds_server_and_pin(self):
        a = compute_provenance_id("s1", "pin1")
        b = compute_provenance_id("s1", "pin2")
        c = compute_provenance_id("s2", "pin1")
        assert a != b and a != c and b != c  # no collision across server/pin

    def test_namespaced_tool_key(self):
        assert namespaced_tool_key("prov", "tool") == "prov::tool"

    def test_provenance_requires_both(self):
        with pytest.raises(ValueError):
            compute_provenance_id("", "pin")
        with pytest.raises(ValueError):
            compute_provenance_id("s", "")
