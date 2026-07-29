# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — LAURA-V50-017 (High): live onboard+approve+grant left THREE
seeding gaps that made the RBAC/human-caller positive path unreachable for
a live-onboarded server even after LAURA-V50-010/014/016 were fixed. Laura
had to perform three UNDOCUMENTED manual interventions to reach a genuine
200 ALLOW:

  Gap A — the org-level ``mcp_server`` connection-permit grant
          (``McpBroker._check_connection_permit``, the FIRST gate, ahead of
          OPA entirely) was never auto-seeded by the approve transaction —
          first call denied ``403 mcp_server_not_permitted``. Worked around
          by a manual ``PUT /admin/api/permissions/grants/org/default/
          mcp_server/<mcp_id>`` (keyed by the mcp_id UUID — a resource_id=
          "cloud9-demo" grant silently had no effect).

  Gap B — the auto-written OPA grant was keyed ONLY by the gateway's own
          mesh SPIFFE (``spiffe://<td>/gateway``) — correct for the
          SPIFFE-verified agent-to-agent branch (mcp.rego MCP-A/MCP-C), but
          mcp.rego's RBAC/human-caller branch (MCP-B, non-SPIFFE) sets
          ``input.identity.spiffe`` to ``agent_spiffe_uri(tenant, agent)``
          (the target's own legacy 2-segment URI) — a key onboarding never
          wrote. Every RBAC/human-session tools/call was therefore
          structurally unsatisfiable at ``_grant_ok`` regardless of any
          admin action.

  Gap C — the automatic post-commit OPA push logged success ("1 instance
          grant(s) + 1 baseline(s)") but the data was verifiably absent
          from OPA minutes later. Root cause not conclusively isolated by
          Laura; this suite's companion coverage lives in
          ``test_v41_phase2b_integration_seams.py::TestPushMcpOpaData``
          (the readback-verification fix — see ``mcp/_opa_push.py``).

Fix under test (Tom, 2026-07-29):
  A. ``mcp_onboard.py::run_approve_transaction`` seeds the org-level
     mcp_server connection-permit grant (``permission_store``) atomically
     with the OPA grant/baseline write, keyed by the SAME mcp_id
     ``McpBroker._check_connection_permit`` resolves
     (``ctx.mcp_id or ctx.server_id or ctx.agent_name``).
  B. ``registry_store.put_grant()`` now writes BOTH the gateway-mesh SPIFFE
     AND ``agent_spiffe_uri(tenant, server)`` as grant keys (via the new
     ``caller_spiffes`` list field — ``mcp/_durable_registry.py``), so
     ``build_mcp_opa_data()`` produces a
     ``grants[mcp_id][spiffe]`` entry for EACH.

This suite drives the REAL ``run_approve_transaction()`` (only PKI/codegen/
Caddy/DB side effects are mocked — the grant-seeding logic under test runs
unmocked, against REAL ``DurableMcpRegistryStore`` / ``McpIdStore`` /
``PermissionStore`` instances backed by a fake in-memory Redis), then:

  1. Asserts the org-level connection-permit grant is present (Gap A).
  2. Asserts the durable-store grant record carries BOTH SPIFFE keys, and
     that ``build_mcp_opa_data()`` expands both into ``grants[mcp_id]``
     (Gap B, storage layer).
  3. Feeds the built OPA data document + a synthetic MCP-B (RBAC branch)
     ``tools/call`` input to the REAL ``policy/mcp.rego`` via the ``opa``
     CLI (``opa eval``) — proving the ACTUAL, UNMODIFIED gate logic now
     allows a benign call for a live-onboarded server with zero manual
     steps (never asserting against a Python re-implementation of the
     gate).
  4. Confirms the SAME data, evaluated against three adversarial inputs
     (over-scope tool, wrong SPIFFE, drifted baseline), still denies —
     proving Gap A/B's fix did not loosen enforcement.

No gate logic (mcp.rego, broker.py's four-gate) is touched anywhere in
this change — this suite proves the PROVISIONING side only, exactly as
scoped.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

_TENANT = "t1"
_SERVER = "cloud9-demo"
_TOOL = "echo"
# The real (unpatched) default trust domain — see identity/trust_domain.py
# _LEGACY_TRUST_DOMAIN. Deliberately not overridden (see comment at the
# trust_domain patch site below) so the value used inside
# run_approve_transaction and in this test's post-assertions is guaranteed
# identical.
_TRUST_DOMAIN = "yashigani.internal"
_REPO_ROOT = Path(__file__).resolve().parents[3].parent  # src/tests/regression/v5.0 -> repo root
_POLICY_DIR = _REPO_ROOT / "policy"

_OPA_BIN = shutil.which("opa")


def _fake_redis() -> MagicMock:
    """Minimal synchronous Redis stub backed by a plain dict (same shape
    used across mcp/_id_store + _durable_registry + permissions test
    suites)."""
    r = MagicMock()
    _store: dict = {}

    def _set(k, v, **_kw):
        _store[k] = v

    def _get(k):
        return _store.get(k)

    def _delete(*keys):
        n = 0
        for k in keys:
            if k in _store:
                _store.pop(k, None)
                n += 1
        return n

    def _sadd(k, *vals):
        _store.setdefault(k, set()).update(vals)

    def _srem(k, *vals):
        if isinstance(_store.get(k), set):
            for v in vals:
                _store[k].discard(v)

    def _smembers(k):
        v = _store.get(k, set())
        return {m.encode() if isinstance(m, str) else m for m in v}

    r.set.side_effect = _set
    r.get.side_effect = _get
    r.delete.side_effect = _delete
    r.sadd.side_effect = _sadd
    r.srem.side_effect = _srem
    r.smembers.side_effect = _smembers
    r._store = _store
    return r


def _opa_eval(query: str, data_doc: dict, input_doc: dict, tmp_path: Path) -> object:
    """Invoke the REAL opa CLI against the REAL, unmodified policy/ dir plus
    an overlay data document + input — returns the decoded result value."""
    assert _OPA_BIN, "opa binary not found on PATH — cannot run gate-side proof"
    data_file = tmp_path / f"opa_data_{uuid.uuid4().hex}.json"
    input_file = tmp_path / f"opa_input_{uuid.uuid4().hex}.json"
    data_file.write_text(json.dumps({"yashigani": {"mcp": data_doc}}))
    input_file.write_text(json.dumps(input_doc))

    proc = subprocess.run(
        [
            _OPA_BIN, "eval",
            "-d", str(_POLICY_DIR),
            "-d", str(data_file),
            "-i", str(input_file),
            "--format", "json",
            query,
        ],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, f"opa eval failed: {proc.stderr}\n{proc.stdout}"
    result = json.loads(proc.stdout)
    return result["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(_OPA_BIN is None, reason="opa CLI not found on PATH")
class TestLauraV50017OnboardGrantSeed:
    """Full onboard -> grant -> zero-manual-steps positive path, plus
    adversarial denials, proven against the REAL policy/mcp.rego."""

    @pytest.mark.asyncio
    async def test_onboard_seeds_all_grant_forms_and_gate_allows_benign_call(
        self, tmp_path: Path,
    ):
        from yashigani.backoffice.mcp_onboard import run_approve_transaction
        from yashigani.identity.trust_domain import agent_spiffe_uri
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore
        from yashigani.mcp._envelope import label_surface_hash
        from yashigani.mcp._id_store import McpIdStore
        from yashigani.permissions import PermissionStore, ResourceType

        # ── Real (fake-Redis-backed) stores — Gap A/B fix runs unmocked ────
        redis_client = _fake_redis()
        registry_store = DurableMcpRegistryStore(redis_client)
        mcp_id_store = McpIdStore(redis_client)
        permission_store = PermissionStore(redis_client, default_org_id="default")

        # ── PKI / codegen / Caddy mocking (same harness shape as
        #    TestApproveTransactionGrantBaseline::test_s3f_..., unrelated to
        #    the grant-seeding logic under test) ─────────────────────────
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2027, 1, 1, tzinfo=_dt.timezone.utc))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        cert_file = secrets_dir / "agent_client.crt"
        key_file = secrets_dir / "agent_client.key"
        ca_file = secrets_dir / "ca_intermediate.crt"
        for f in (cert_file, key_file, ca_file):
            f.write_bytes(cert_pem)

        fake_pki = MagicMock()
        fake_pki.agent_cert.return_value = cert_file
        fake_pki.agent_key.return_value = key_file
        fake_pki.intermediate_cert = ca_file

        _surface_hex = "aa" * 32
        env_mock = MagicMock()
        env_mock.provenance_id = f"{_TENANT}:{_SERVER}"
        env_mock.tools = {f"{_TENANT}:{_SERVER}::{_TOOL}": MagicMock()}
        env_mock.surface_set_hash = _surface_hex

        reloader = AsyncMock()
        envelope_svc = AsyncMock()
        envelope_svc.mint_envelope.return_value = 1

        with (
            patch("yashigani.backoffice.mcp_onboard._artifact_root", return_value=tmp_path),
            patch("yashigani.backoffice.mcp_onboard._runtime", return_value="docker"),
            patch("yashigani.pki.issuer.IssuerPaths", return_value=fake_pki),
            patch(
                "yashigani.pki.issuer.mint_agent_leaf",
                return_value=f"spiffe://{_TRUST_DOMAIN}/agents/{_TENANT}/{_SERVER}/nhi_deadbeef0001",
            ),
            patch(
                "yashigani.backoffice.mcp_onboard._validate_manifest_or_raise",
                return_value={
                    "metadata": {"name": _SERVER, "tenant_id": _TENANT},
                    "spec": {"image": {"digest": "sha256:" + "a" * 64}},
                },
            ),
            patch("yashigani.pki.binding.tool_surface_hash", return_value="sha384:" + "g" * 96),
            patch("yashigani.manifest.codegen.approve_mcp_onboard", return_value={}),
            patch("yashigani.manifest.codegen._mcp_mesh_port", return_value=8443),
            # Deliberately NOT patching trust_domain() — use the real
            # (default "yashigani.internal") value consistently both inside
            # run_approve_transaction AND in this test's post-assertions,
            # avoiding a patch-scope mismatch (agent_spiffe_uri computed
            # AFTER the `with` block exits must see the SAME value the
            # transaction saw).
            patch("os.environ.get", side_effect=lambda k, d="": {
                "YASHIGANI_ENV": "dev",
            }.get(k, d)),
            patch("os.getenv", side_effect=lambda k, d="": {
                "YASHIGANI_SECRETS_DIR": str(secrets_dir),
                "YASHIGANI_SERVICE_MANIFEST_PATH": str(tmp_path / "svc.yaml"),
                "YASHIGANI_SVID_INIT_DIR": str(secrets_dir / "svid-init"),
                "YASHIGANI_SVID_GID": str(os.getgid()),
            }.get(k, d)),
        ):
            await run_approve_transaction(
                manifest_yaml="---",
                server_id=_SERVER,
                tenant_id=_TENANT,
                env=env_mock,
                topology="standalone",
                sidecar_scan_verdict=None,
                operator_identity="admin",
                envelope_service=envelope_svc,
                caddy_reloader=reloader,
                registry_store=registry_store,
                mcp_id_store=mcp_id_store,
                permission_store=permission_store,
            )

        mcp_id = mcp_id_store.get_or_mint(_SERVER)  # idempotent — same id approve resolved

        # ── Gap A: org-level connection-permit grant present, keyed by
        #    mcp_id (NOT the server_id string) ─────────────────────────
        grant_value = permission_store.get_boolean_grant(
            ResourceType.MCP_SERVER, "org", "default", mcp_id,
        )
        assert grant_value is not None, (
            "LAURA-V50-017 Gap A REGRESSION: no org-level mcp_server "
            "connection-permit grant was seeded by the approve transaction "
            "— every call would deny mcp_server_not_permitted with zero "
            "manual admin steps possible to diagnose why."
        )
        assert grant_value.allow is True
        # Sanity: a grant keyed by the bare server_id string must NOT be
        # what satisfies this (the exact footgun Laura's manual workaround
        # hit) — confirm the mcp_id key is a REAL UUID, not the server_id.
        assert mcp_id != _SERVER

        # ── Gap B: BOTH SPIFFE forms present in the stored grant record ──
        stored_grant = registry_store.get_grant(_TENANT, _SERVER)
        assert stored_grant is not None
        _gateway_spiffe = f"spiffe://{_TRUST_DOMAIN}/gateway"
        _rbac_spiffe = agent_spiffe_uri(_TENANT, _SERVER)
        assert stored_grant["caller_spiffe"] == _gateway_spiffe  # back-compat primary key
        assert set(stored_grant["caller_spiffes"]) == {_gateway_spiffe, _rbac_spiffe}, (
            "LAURA-V50-017 Gap B REGRESSION: onboarding must write BOTH the "
            "gateway-mesh SPIFFE (agent-to-agent branch) AND "
            "agent_spiffe_uri(tenant,server) (the RBAC/human-caller branch "
            "mcp.rego's MCP-B rule actually looks up)."
        )

        # ── build_mcp_opa_data expands BOTH keys into grants[mcp_id] ──────
        opa_doc = registry_store.build_mcp_opa_data(mcp_id_store, "default")
        assert mcp_id in opa_doc["grants"]
        assert _gateway_spiffe in opa_doc["grants"][mcp_id]
        assert _rbac_spiffe in opa_doc["grants"][mcp_id], (
            "build_mcp_opa_data did not expand caller_spiffes into a "
            "per-spiffe grants[mcp_id] entry for the RBAC branch key."
        )
        assert opa_doc["grants"][mcp_id][_rbac_spiffe]["tools"] == [_TOOL]
        assert mcp_id in opa_doc["baselines"]
        expected_surface_hash = label_surface_hash(_surface_hex)
        assert opa_doc["baselines"][mcp_id]["surface_hash"] == expected_surface_hash

        # ── Gate-side proof: feed the built doc + a benign RBAC input into
        #    the REAL policy/mcp.rego (gate logic untouched) ──────────────
        benign_input = {
            "posture": "mcp-b",
            "action": "mcp.tools.call",
            "identity": {
                "spiffe": _rbac_spiffe,
                "verified": False,
                "chain": [],
                "rbac_verified": True,
            },
            "caller": {"agent_id": "", "user_id": "alice@example.com"},
            "tool": {"name": _TOOL, "args_redacted": {}},
            "target": {
                "mcp_id": mcp_id,
                "cert_fingerprint": "",
                "surface_hash": expected_surface_hash,
            },
        }
        allow = _opa_eval(
            "data.yashigani.mcp.allow", opa_doc, benign_input, tmp_path,
        )
        deny_reason = _opa_eval(
            "data.yashigani.mcp.deny_reason", opa_doc, benign_input, tmp_path,
        )
        assert allow is True, (
            f"LAURA-V50-017 REGRESSION: onboard->approve->grant with ZERO "
            f"manual steps must let a benign RBAC tools/call pass the REAL "
            f"policy/mcp.rego four-gate — got deny_reason={deny_reason!r}"
        )
        assert deny_reason == "ok"

        # ── Adversarial cases — Gap A/B's fix must NOT loosen enforcement ─

        # Over-scope tool: not in the granted tool set -> _grant_ok fails.
        overscope_input = dict(benign_input, tool={"name": "delete_everything", "args_redacted": {}})
        assert _opa_eval(
            "data.yashigani.mcp.allow", opa_doc, overscope_input, tmp_path,
        ) is False
        assert _opa_eval(
            "data.yashigani.mcp.deny_reason", opa_doc, overscope_input, tmp_path,
        ) == "rbac_no_per_instance_grant"

        # Wrong SPIFFE: caller asserts an identity with no grant entry.
        wrong_spiffe_input = dict(
            benign_input,
            identity=dict(benign_input["identity"], spiffe=agent_spiffe_uri(_TENANT, "some-other-server")),
        )
        assert _opa_eval(
            "data.yashigani.mcp.allow", opa_doc, wrong_spiffe_input, tmp_path,
        ) is False
        assert _opa_eval(
            "data.yashigani.mcp.deny_reason", opa_doc, wrong_spiffe_input, tmp_path,
        ) == "rbac_no_per_instance_grant"

        # Drift: surface_hash no longer matches the approved baseline.
        drift_input = dict(
            benign_input,
            target=dict(benign_input["target"], surface_hash="sha256:" + "ff" * 32),
        )
        assert _opa_eval(
            "data.yashigani.mcp.allow", opa_doc, drift_input, tmp_path,
        ) is False
        assert _opa_eval(
            "data.yashigani.mcp.deny_reason", opa_doc, drift_input, tmp_path,
        ) == "rbac_capability_envelope_drift"

    @pytest.mark.asyncio
    async def test_production_env_fails_closed_without_permission_store(
        self, tmp_path: Path,
    ):
        """LAURA-V50-017 Gap A: production/staging with permission_store=None
        must fail closed BEFORE minting anything (same posture as
        registry_store=None), not silently onboard an unusable server."""
        from yashigani.backoffice.mcp_onboard import (
            McpOnboardError,
            run_approve_transaction,
        )
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore

        registry_store = DurableMcpRegistryStore(_fake_redis())

        with patch("os.environ.get", side_effect=lambda k, d="": {
            "YASHIGANI_ENV": "production",
        }.get(k, d)):
            with pytest.raises(McpOnboardError) as exc_info:
                await run_approve_transaction(
                    manifest_yaml="---",
                    server_id=_SERVER,
                    tenant_id=_TENANT,
                    env=MagicMock(),
                    topology="standalone",
                    sidecar_scan_verdict=None,
                    operator_identity="admin",
                    envelope_service=AsyncMock(),
                    registry_store=registry_store,
                    permission_store=None,
                )
        assert exc_info.value.step == "config"
        assert exc_info.value.http_status == 503
