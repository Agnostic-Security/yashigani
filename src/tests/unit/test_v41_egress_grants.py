# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — v4.1 unified-sidecar Phase 1: (caller, prefix) egress GRANT model
(Lu M1/M2, Laura L-US-1 — synthesis must-fix #1).

Python-side plumbing under test (the rego closed-world semantics are covered
in policy/mcp_test.rego section 18):

  * query_mcp_response_decision(egress_prefix=...) emits FIRST-CLASS
    ``input.egress = {"prefix": ...}``; None omits the key entirely (the
    broker tool-result path MUST NOT carry it).
  * /egress/eval passes ``egress_prefix=prefix`` (not smuggled in tool_name)
    and the deny audit event carries the FULL caller SPIFFE.
  * DurableMcpRegistryStore egress-grant CRUD + build_egress_grants_data.
  * transitional_egress_seed / build_egress_grants_doc (merge semantics,
    store-wins, never-raises degradation).
  * Approve transaction step 4b-iii: grant written from the manifest's
    spec.egress.needs[].prefix, keyed on the minted per-instance SPIFFE,
    MCP_EGRESS_GRANT_WRITTEN audited, rollback deletes the record.

The OPA data contract these tests pin::

    data.yashigani.mcp.egress_grants = {
      "<EXACT per-instance SPIFFE URI>": {
        "tenant":   "<tenant_id>",
        "prefixes": ["slack", ...],
        # "legacy_system": true — transitional seed entries only
      }
    }
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yashigani.mcp._durable_registry import DurableMcpRegistryStore
from yashigani.mcp._egress_grants import (
    build_egress_grants_doc,
    transitional_egress_seed,
)

_TENANT = "default"
_SERVER = "cloud9-demo"
_DIGEST = "sha256:" + "ab" * 32
_MOD = "yashigani.gateway.egress_proxy"

_AGENT_SPIFFE = "spiffe://yashigani.internal/agents/default/notifier/nhi_aaa111"


class _FakeRedis:
    """Minimal in-memory Redis stand-in (bytes-returning, like db/3 client)."""

    def __init__(self):
        self.kv: dict = {}
        self.sets: dict = {}

    def set(self, k, v):
        self.kv[k] = v.encode() if isinstance(v, str) else v

    def get(self, k):
        return self.kv.get(k)

    def delete(self, k):
        self.kv.pop(k, None)

    def sadd(self, k, m):
        self.sets.setdefault(k, set()).add(m.encode() if isinstance(m, str) else m)

    def srem(self, k, m):
        self.sets.get(k, set()).discard(m.encode() if isinstance(m, str) else m)

    def smembers(self, k):
        return set(self.sets.get(k, set()))


# ---------------------------------------------------------------------------
# A. query_mcp_response_decision — first-class input.egress plumbing
# ---------------------------------------------------------------------------


class TestQueryInputEgressPlumbing:
    @staticmethod
    def _client_capturing(posted: list) -> AsyncMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"result": {
            "allow": True, "deny_reason": "ok",
            "policy_id": "mcp.response_decision",
            "code": "MCP_RESULT_OK", "user_message": "ok",
        }}
        client = AsyncMock()

        async def _post(url, json=None):
            posted.append((url, json))
            return resp

        client.post = AsyncMock(side_effect=_post)
        return client

    @pytest.mark.asyncio
    async def test_egress_prefix_becomes_first_class_input_field(self):
        from yashigani.mcp._opa import query_mcp_response_decision
        posted: list = []
        await query_mcp_response_decision(
            opa_url="https://policy:8181",
            caller_spiffe=_AGENT_SPIFFE,
            caller_sensitivity_ceiling="PUBLIC",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            tool_name="egress:slack",
            egress_prefix="slack",
            http_client=self._client_capturing(posted),
        )
        assert len(posted) == 1
        _, body = posted[0]
        assert body["input"]["egress"] == {"prefix": "slack"}
        # tool_name remains audit context — present but NOT the grant carrier.
        assert body["input"]["tool"] == {"name": "egress:slack"}
        assert body["input"]["caller"]["spiffe"] == _AGENT_SPIFFE

    @pytest.mark.asyncio
    async def test_none_prefix_omits_egress_key_broker_path(self):
        from yashigani.mcp._opa import query_mcp_response_decision
        posted: list = []
        await query_mcp_response_decision(
            opa_url="https://policy:8181",
            caller_spiffe=_AGENT_SPIFFE,
            caller_sensitivity_ceiling="RESTRICTED",
            caller_groups=[],
            result_sensitivity="PUBLIC",
            pii_detected=False,
            tool_name="web_search",
            http_client=self._client_capturing(posted),
        )
        _, body = posted[0]
        # The broker tool-result path must NOT carry the egress key — its
        # PRESENCE is what selects the grant model in rego (fail-closed).
        assert "egress" not in body["input"]


# ---------------------------------------------------------------------------
# B. /egress/eval — prefix passed first-class + deny audit caller SPIFFE
# ---------------------------------------------------------------------------


def _make_app(audit_writer=None):
    from yashigani.gateway import egress_proxy as _mod

    _mod._state.opa_url = "https://policy:8181"
    _mod._state.audit_writer = audit_writer if audit_writer is not None else MagicMock()
    _mod._state.caddy_egress_base = "https://caddy:18790"
    app = FastAPI()
    app.include_router(_mod.router)
    return app


def _clean_scan() -> MagicMock:
    v = MagicMock()
    v.is_secret = False
    return v


def _clean_filter() -> MagicMock:
    r = MagicMock()
    r.rejected = False
    r.reject_reason = ""
    return r


def _opa_deny_not_granted() -> MagicMock:
    r = MagicMock()
    r.allow = False
    r.deny_reason = "caller_not_granted_prefix"
    r.user_message = "No grant for this destination."
    r.policy_id = "mcp.response_decision"
    r.code = "MCP_EGRESS_PREFIX_NOT_GRANTED"
    r.error = ""
    return r


class TestEgressProxyGrantPlumbing:
    def test_prefix_passed_first_class_to_opa_query(self):
        audit = MagicMock()
        app = _make_app(audit_writer=audit)
        opa_mock = AsyncMock(return_value=_opa_deny_not_granted())
        with patch(f"{_MOD}.scan_secrets", return_value=_clean_scan()), \
             patch(f"{_MOD}.filter_description", return_value=_clean_filter()), \
             patch(f"{_MOD}.query_mcp_response_decision", opa_mock):
            client = TestClient(app)
            resp = client.post(
                "/egress/eval/slack/api/chat.postMessage",
                content=b'{"text": "hi"}',
                headers={"X-SPIFFE-ID": _AGENT_SPIFFE},
            )
        assert resp.status_code == 403
        assert resp.json()["error"] == "caller_not_granted_prefix"
        kwargs = opa_mock.call_args.kwargs
        # FIRST-CLASS prefix — the grant carrier.
        assert kwargs["egress_prefix"] == "slack"
        # tool_name stays audit-context-only (unchanged shape).
        assert kwargs["tool_name"] == "egress:slack"
        assert kwargs["caller_spiffe"] == _AGENT_SPIFFE

    def test_deny_audit_carries_full_caller_spiffe(self):
        audit = MagicMock()
        app = _make_app(audit_writer=audit)
        with patch(f"{_MOD}.scan_secrets", return_value=_clean_scan()), \
             patch(f"{_MOD}.filter_description", return_value=_clean_filter()), \
             patch(f"{_MOD}.query_mcp_response_decision",
                   AsyncMock(return_value=_opa_deny_not_granted())):
            client = TestClient(app)
            resp = client.post(
                "/egress/eval/webhook-exfil/x",
                content=b"data",
                headers={"X-SPIFFE-ID": _AGENT_SPIFFE},
            )
        assert resp.status_code == 403
        audit.write.assert_called_once()
        event = audit.write.call_args.args[0]
        # Full per-instance SPIFFE — agent_name alone is name-collapsed and
        # cannot attribute a grant denial to an instance (Lu M1).
        assert event.caller_spiffe == _AGENT_SPIFFE
        assert event.agent_name == "notifier"
        assert event.deny_reason == "egress:caller_not_granted_prefix"
        assert event.tool_name == "egress:webhook-exfil"


# ---------------------------------------------------------------------------
# C. DurableMcpRegistryStore — egress grant CRUD + data doc
# ---------------------------------------------------------------------------


def _descriptor(server=_SERVER, tenant=_TENANT, spiffe=_AGENT_SPIFFE) -> dict:
    return {
        "agent_name": server,
        "upstream_url": f"https://caddy:9573/mcp/{tenant}/{server}",
        "tenant_id": tenant,
        "spiffe_id": spiffe,
        "svid_instance_id": "nhi_aaa111",
    }


class TestDurableStoreEgressGrants:
    def test_put_get_delete_roundtrip(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put_egress_grant(_TENANT, _SERVER, {
            "spiffe": _AGENT_SPIFFE, "tenant": _TENANT,
            "prefixes": ["slack", "telegram"],
        })
        grant = store.get_egress_grant(_TENANT, _SERVER)
        assert grant == {
            "spiffe": _AGENT_SPIFFE, "tenant": _TENANT,
            "prefixes": ["slack", "telegram"],
        }
        store.delete_egress_grant(_TENANT, _SERVER)
        assert store.get_egress_grant(_TENANT, _SERVER) is None

    def test_put_without_spiffe_raises(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        with pytest.raises(ValueError):
            store.put_egress_grant(_TENANT, _SERVER, {
                "tenant": _TENANT, "prefixes": ["slack"],
            })

    def test_build_egress_grants_data_keys_on_exact_spiffe(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        store.put_egress_grant(_TENANT, _SERVER, {
            "spiffe": _AGENT_SPIFFE, "tenant": _TENANT,
            "prefixes": ["telegram", "slack"],
        })
        doc = store.build_egress_grants_data()
        assert doc == {
            _AGENT_SPIFFE: {"tenant": _TENANT, "prefixes": ["slack", "telegram"]},
        }

    def test_descriptor_without_grant_absent_from_doc_closed_world(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        assert store.build_egress_grants_data() == {}


# ---------------------------------------------------------------------------
# D. transitional seed + doc builder
# ---------------------------------------------------------------------------


class TestTransitionalSeedAndDocBuilder:
    def test_seed_defaults_match_static_caddyfile_pin(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OPENCLAW_SPIFFE_ID", raising=False)
        monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
        monkeypatch.setenv("YASHIGANI_TENANT_ID", "default")
        seed = transitional_egress_seed()
        # Same default SPIFFE the Caddyfile caller gate pins; same prefixes
        # the static /slack /slack-hooks /telegram eval handles expose.
        assert seed == {
            "spiffe://yashigani.internal/openclaw": {
                "tenant": "default",
                "prefixes": ["slack", "slack-hooks", "telegram"],
                "legacy_system": True,
            }
        }

    def test_seed_env_override(self, monkeypatch):
        monkeypatch.setenv(
            "YASHIGANI_OPENCLAW_SPIFFE_ID", "spiffe://acme.yashigani.internal/openclaw",
        )
        seed = transitional_egress_seed()
        assert list(seed) == ["spiffe://acme.yashigani.internal/openclaw"]
        assert seed["spiffe://acme.yashigani.internal/openclaw"]["legacy_system"] is True

    def test_doc_builder_merges_store_over_seed(self, monkeypatch):
        monkeypatch.delenv("YASHIGANI_OPENCLAW_SPIFFE_ID", raising=False)
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        store.put_egress_grant(_TENANT, _SERVER, {
            "spiffe": _AGENT_SPIFFE, "tenant": _TENANT, "prefixes": ["slack"],
        })
        doc = build_egress_grants_doc(store)
        assert _AGENT_SPIFFE in doc
        assert "spiffe://yashigani.internal/openclaw" in doc

    def test_doc_builder_none_store_degrades_to_seed_only(self):
        doc = build_egress_grants_doc(None)
        assert len(doc) == 1  # seed only

    def test_doc_builder_never_raises_on_store_failure(self):
        broken = MagicMock()
        broken.build_egress_grants_data.side_effect = RuntimeError("redis down")
        doc = build_egress_grants_doc(broken)  # must not raise
        assert isinstance(doc, dict)


# ---------------------------------------------------------------------------
# E. Approve transaction — grant write + audit + rollback (step 4b-iii)
# ---------------------------------------------------------------------------


def _manifest_yaml(egress_block: str = "") -> str:
    doc = textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {_SERVER}
          tenant_id: {_TENANT}
          category: mcp_server
          description: demo MCP for egress-grant tests
          vendor: Agnostic Security
          licence: proprietary
        spec:
          image:
            repository: yashigani/demo-mcp
            tag: "3.0.0"
            digest: {_DIGEST}
          write_posture: readonly
          subprocess:
            command: ["python3", "server.py"]
            args: []
          network:
            egress_allow: []
        @EGRESS@
          mcp:
            posture: mcp-b
            transport: stdio
            session_mode: persistent
            identity_propagation: gateway-enforced-only
            exposes:
              listen_port: null
              shim_port: 8000
              tools:
                - {{name: echo, allowed: true, sensitivity_class: PUBLIC}}
          audit:
            sensitivity_ceiling: PUBLIC
          storage:
            mounts: []
            tmpfs:
              - {{path: /tmp, size_limit: 16m}}
          secrets: []
          lifecycle:
            mode: persistent
        """)
    if egress_block:
        return doc.replace("@EGRESS@\n", egress_block)
    return doc.replace("@EGRESS@\n", "")


# Phase 2a: internet-facing needs MUST declare account pins — the
# egress-forwarder template FAILS render without them (Laura L-US-3,
# codegen._assert_egress_pins). The grant write itself consumes only prefix.
_EGRESS_BLOCK = """\
  egress:
    needs:
      - {prefix: slack, deliver_to: "slack.com:443", pins: {bot_token_env: TEST_SLACK_BOT_TOKEN}}
      - {prefix: telegram, deliver_to: "api.telegram.org:443", pins: {bot_id_env: TEST_TG_BOT_ID}}
"""


def _self_signed_pem() -> bytes:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unit-leaf")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def _mint_side_effect(secrets_dir: Path):
    pem = _self_signed_pem()

    def _mint(paths, tenant_id, agent_name, *, instance_id="", scope_hash="",
              image_digest="", approved_by="", audit_writer=None, **kw):
        cert = paths.agent_cert(tenant_id, agent_name, instance_id)
        key = paths.agent_key(tenant_id, agent_name, instance_id)
        cert.write_bytes(pem)
        key.write_text("KEY")
        return (
            f"spiffe://yashigani.internal/agents/{tenant_id}/"
            f"{agent_name}/{instance_id}"
        )
    return _mint


class _FakeReloader:
    def __init__(self):
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1


@pytest.fixture()
def txn_env(tmp_path, monkeypatch):
    from yashigani.manifest.codegen import reset_codegen_registry
    reset_codegen_registry()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    # Step 2b (svid-init, SEAM-1d-06) copies the intermediate CA into the
    # per-instance init dir — provide one so the tx can pass that step.
    (secrets_dir / "ca_intermediate.crt").write_bytes(_self_signed_pem())
    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "docker")
    monkeypatch.delenv("YSG_REQUIRE_SIGNED_MANIFEST", raising=False)
    monkeypatch.delenv("YSG_REQUIRE_CADDY_VALIDATE", raising=False)
    monkeypatch.delenv("YASHIGANI_ENV", raising=False)
    yield artifact_root, secrets_dir
    reset_codegen_registry()


def _svc(fail: bool = False) -> MagicMock:
    svc = MagicMock()
    if fail:
        svc.mint_envelope = AsyncMock(side_effect=RuntimeError("db down"))
    else:
        svc.mint_envelope = AsyncMock(return_value=77)
    return svc


async def _run(secrets_dir, *, manifest=None, svc=None, registry_store=None,
               audit_writer=None):
    from yashigani.backoffice.mcp_onboard import run_approve_transaction
    with patch(
        "yashigani.pki.issuer.mint_agent_leaf",
        side_effect=_mint_side_effect(secrets_dir),
    ):
        return await run_approve_transaction(
            manifest_yaml=manifest if manifest is not None else _manifest_yaml(),
            server_id=_SERVER,
            tenant_id=_TENANT,
            env=MagicMock(tools={f"{_SERVER}::echo": MagicMock()}),
            topology="ring_fenced",
            sidecar_scan_verdict={"classifier_status": "not_configured"},
            operator_identity="orchid",
            envelope_service=svc if svc is not None else _svc(),
            audit_writer=audit_writer,
            caddy_reloader=_FakeReloader(),
            registry_store=registry_store,
        )


class TestApproveWritesEgressGrant:
    @pytest.mark.asyncio
    async def test_grant_written_from_manifest_egress_needs(self, txn_env):
        _, secrets_dir = txn_env
        store = DurableMcpRegistryStore(_FakeRedis())
        result = await _run(
            secrets_dir, manifest=_manifest_yaml(_EGRESS_BLOCK),
            registry_store=store,
        )
        grant = store.get_egress_grant(_TENANT, _SERVER)
        assert grant is not None
        # Keyed on the EXACT minted per-instance SPIFFE — byte-match contract.
        assert grant["spiffe"] == result.spiffe_id
        assert grant["tenant"] == _TENANT
        assert grant["prefixes"] == ["slack", "telegram"]

    @pytest.mark.asyncio
    async def test_no_egress_block_writes_explicit_empty_grant(self, txn_env):
        _, secrets_dir = txn_env
        store = DurableMcpRegistryStore(_FakeRedis())
        await _run(secrets_dir, registry_store=store)
        grant = store.get_egress_grant(_TENANT, _SERVER)
        # Closed world: no declaration = explicitly granted NO egress.
        assert grant is not None
        assert grant["prefixes"] == []

    @pytest.mark.asyncio
    async def test_grant_write_audited(self, txn_env):
        _, secrets_dir = txn_env
        from yashigani.audit.schema import McpEgressGrantWrittenEvent
        store = DurableMcpRegistryStore(_FakeRedis())
        audit = MagicMock()
        result = await _run(
            secrets_dir, manifest=_manifest_yaml(_EGRESS_BLOCK),
            registry_store=store, audit_writer=audit,
        )
        grant_events = [
            c.args[0] for c in audit.write.call_args_list
            if isinstance(c.args[0], McpEgressGrantWrittenEvent)
        ]
        assert len(grant_events) == 1
        ev = grant_events[0]
        assert ev.event_type == "MCP_EGRESS_GRANT_WRITTEN"
        assert ev.approver_account == "orchid"
        assert ev.spiffe_id == result.spiffe_id
        assert ev.prefixes == ["slack", "telegram"]
        assert ev.tenant_id == _TENANT
        assert ev.server_id == _SERVER

    @pytest.mark.asyncio
    async def test_rollback_deletes_egress_grant(self, txn_env):
        _, secrets_dir = txn_env
        from yashigani.backoffice.mcp_onboard import McpOnboardError
        store = DurableMcpRegistryStore(_FakeRedis())
        with pytest.raises(McpOnboardError):
            await _run(
                secrets_dir, manifest=_manifest_yaml(_EGRESS_BLOCK),
                svc=_svc(fail=True), registry_store=store,
            )
        # Grant-absence is the kill switch: a rolled-back onboarding leaves
        # NO egress grant behind.
        assert store.get_egress_grant(_TENANT, _SERVER) is None
