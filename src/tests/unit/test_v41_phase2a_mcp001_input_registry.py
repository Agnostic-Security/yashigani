# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — v4.1 Phase 2a (Issue 2): broker→OPA transport + OPA input
PRODUCER + durable broker registry.

  Task A (MCP-001): _make_opa_http_client uses the gateway mesh identity
    (internal_httpx_client) as the PRIMARY transport; falls back to the
    identity-less CA-only client only when the ServiceIdentity is
    unavailable (dev/test) — a mesh-mTLS OPA refuses that client at the
    handshake, so the fallback stays fail-closed (C9).

  Task B (lu.md §3a — PRODUCER): _build_opa_input carries
    identity.verified (bool, always present, default False) and
    target{mcp_id, cert_fingerprint, surface_hash} (emitted when mcp_id is
    known), WITHOUT breaking any existing input field, and the produced
    document validates against policy/mcp-input.schema.json.
    broker.enforce() threads ctx.identity_verified / ctx.mcp_id /
    ctx.target_cert_fingerprint / the live catalogue surface hash into
    query_mcp_decision.

  Task C (Iris SEAM-1d-07): the approve transaction durably registers the
    onboarded MCP (canonical <tenant>:<server> key) into the
    DurableMcpRegistryStore, with fail-closed rollback; the gateway
    McpBrokerRegistry lazily loads it on a lookup miss — /mcp/<server>
    routes WITHOUT a gateway reboot.
"""
from __future__ import annotations

import datetime
import json
import os
import textwrap
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jsonschema
import pytest

from yashigani.mcp._opa import _build_opa_input, _make_opa_http_client
from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
from yashigani.mcp.broker import McpBroker, McpBrokerConfig, _sha256_label
from yashigani.mcp._durable_registry import (
    DurableMcpRegistryStore,
    canonical_server_key,
)
from yashigani.mcp.registry import McpBrokerRegistry, McpBrokerServerConfig

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCHEMA_PATH = _REPO_ROOT / "policy" / "mcp-input.schema.json"

_TENANT = "default"
_SERVER = "cloud9-demo"
_HEX64 = "ab12" * 16


# ---------------------------------------------------------------------------
# Task A — MCP-001 transport
# ---------------------------------------------------------------------------

class TestMcp001Transport:
    def test_primary_path_uses_mesh_identity_client(self, monkeypatch):
        """_make_opa_http_client MUST use internal_httpx_client (mesh mTLS)."""
        sentinel = httpx.AsyncClient()
        captured: dict = {}

        def _fake_internal(*, timeout, **kw):
            captured["timeout"] = timeout
            return sentinel

        import yashigani.pki.client as pki_client
        monkeypatch.setattr(pki_client, "internal_httpx_client", _fake_internal)

        client = _make_opa_http_client()
        assert client is sentinel
        # C9: the 500ms broker budget is preserved on the mesh client.
        assert captured["timeout"] == pytest.approx(0.5)

    def test_fallback_when_service_identity_unavailable(self, monkeypatch):
        """No ServiceIdentity (dev/test) → identity-less fallback client.

        Fail-closed note: against a mesh-mTLS OPA this client is refused at
        the TLS handshake → opa_unreachable → deny (proven in
        mcp001_ab_proof.txt).  The fallback only serves plain-HTTP/dev OPA.
        """
        import yashigani.pki.client as pki_client

        def _boom(**kw):
            raise RuntimeError("no /run/secrets in unit tests")

        monkeypatch.setattr(pki_client, "internal_httpx_client", _boom)
        monkeypatch.delenv("YASHIGANI_CA_CERT", raising=False)
        client = _make_opa_http_client()
        assert isinstance(client, httpx.AsyncClient)
        assert client is not None

    def test_fallback_honours_yashigani_ca_cert(self, monkeypatch, tmp_path):
        import yashigani.pki.client as pki_client

        def _boom(**kw):
            raise RuntimeError("no identity")

        monkeypatch.setattr(pki_client, "internal_httpx_client", _boom)
        ca = tmp_path / "ca_root.crt"
        ca.write_bytes(_self_signed_pem())  # real PEM — httpx loads it eagerly
        monkeypatch.setenv("YASHIGANI_CA_CERT", str(ca))
        client = _make_opa_http_client()
        assert isinstance(client, httpx.AsyncClient)


# ---------------------------------------------------------------------------
# Task B — OPA input contract (PRODUCER)
# ---------------------------------------------------------------------------

def _schema() -> dict:
    with open(_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


class TestOpaInputProducer:
    def test_identity_verified_default_false_and_no_target(self):
        doc = _build_opa_input(
            posture="mcp-b", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a", chain=[],
            tool_name="echo",
        )
        inner = doc["input"]
        assert inner["identity"]["verified"] is False   # fail-closed default
        assert "target" not in inner                     # no mcp_id → no target

    def test_identity_verified_true_is_strict_bool(self):
        doc = _build_opa_input(
            posture="mcp-b", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a", chain=[],
            tool_name="echo", identity_verified=True,
        )
        assert doc["input"]["identity"]["verified"] is True

    def test_target_emitted_with_all_fields(self):
        doc = _build_opa_input(
            posture="mcp-b", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a", chain=[],
            tool_name="echo",
            identity_verified=True,
            mcp_id="11111111-2222-3333-4444-555555555555",
            cert_fingerprint=f"sha256:{_HEX64}",
            surface_hash=f"sha256:{_HEX64}",
        )
        target = doc["input"]["target"]
        assert target["mcp_id"] == "11111111-2222-3333-4444-555555555555"
        assert target["cert_fingerprint"] == f"sha256:{_HEX64}"
        assert target["surface_hash"] == f"sha256:{_HEX64}"

    def test_target_omits_empty_optional_fields(self):
        doc = _build_opa_input(
            posture="mcp-b", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a", chain=[],
            tool_name="echo", mcp_id="abc",
            cert_fingerprint=None, surface_hash="",
        )
        target = doc["input"]["target"]
        assert target == {"mcp_id": "abc"}

    def test_existing_fields_unbroken(self):
        """Do NOT break the existing input fields (brief requirement)."""
        doc = _build_opa_input(
            posture="mcp-c", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a",
            chain=["spiffe://td/agents/t/origin"],
            tool_name="read_file",
            tool_args={"path": "notes%2Ftodo.txt"},
            tool_args_redacted={"path": "notes/todo.txt"},
            agent_name="filesystem",
            caller={"agent_id": "agent-1", "user_id": "u-1"},
            identity_verified=True,
            mcp_id="i-1",
        )
        inner = doc["input"]
        assert inner["posture"] == "mcp-c"
        assert inner["action"] == "mcp.tools.call"
        assert inner["identity"]["spiffe"] == "spiffe://td/agents/t/a"
        assert inner["identity"]["chain"] == ["spiffe://td/agents/t/origin"]
        assert inner["tool"]["name"] == "read_file"
        assert inner["tool"]["args"] == {"path": "notes/todo.txt"}  # FIX-P3-001 decode
        assert inner["tool"]["args_redacted"] == {"path": "notes/todo.txt"}
        assert inner["agent"] == {"name": "filesystem"}
        assert inner["caller"] == {"agent_id": "agent-1", "user_id": "u-1"}

    def test_document_validates_against_schema(self):
        """The PRODUCED document must satisfy policy/mcp-input.schema.json."""
        schema = _schema()
        doc = _build_opa_input(
            posture="mcp-b", action="mcp.tools.call",
            spiffe_uri="spiffe://td/agents/t/a", chain=[],
            tool_name="echo",
            tool_args={"path": "x"},
            tool_args_redacted={"path": "x"},
            agent_name="cloud9-demo",
            caller={"agent_id": "", "user_id": "u"},
            identity_verified=True,
            mcp_id="11111111-2222-3333-4444-555555555555",
            cert_fingerprint=f"sha256:{_HEX64}",
            surface_hash=f"sha256:{_HEX64}",
        )
        jsonschema.validate(instance=doc["input"], schema=schema)

    def test_legacy_document_without_new_fields_still_validates(self):
        """Backwards compatibility: pre-Phase-2a documents remain schema-valid."""
        schema = _schema()
        doc = _build_opa_input(
            posture="mcp-a", action="mcp.prompts.list",
            spiffe_uri="", chain=[], prompt_name="greeting",
        )
        jsonschema.validate(instance=doc["input"], schema=schema)

    def test_schema_has_no_duplicate_keys(self):
        """Guard against concurrent-edit duplicate JSON keys in the schema."""
        import collections

        def _dup_check(pairs):
            dups = [k for k, c in collections.Counter(
                k for k, _ in pairs).items() if c > 1]
            assert not dups, f"duplicate keys in mcp-input.schema.json: {dups}"
            return dict(pairs)

        with open(_SCHEMA_PATH, encoding="utf-8") as f:
            json.load(f, object_pairs_hook=_dup_check)

    def test_sha256_label_normalisation(self):
        assert _sha256_label("") is None
        assert _sha256_label("AB:CD") == "sha256:abcd"
        assert _sha256_label("deadBEEF") == "sha256:deadbeef"
        assert _sha256_label("sha256:deadbeef") == "sha256:deadbeef"
        assert _sha256_label("SHA256:AB CD") == "sha256:abcd"


class TestBrokerThreadsTargetIntoOpa:
    @pytest.mark.asyncio
    async def test_enforce_passes_verified_and_target(self, monkeypatch):
        """broker.enforce() (broker.py step 2) MUST pass ctx.identity_verified,
        ctx.mcp_id, the leaf fingerprint and the live surface hash into
        query_mcp_decision."""
        captured: dict = {}

        async def _fake_query(**kwargs):
            captured.update(kwargs)
            from yashigani.mcp._opa import OpaDecisionResult
            return OpaDecisionResult(
                allow=False, deny_reason="unit_deny", redact_args=set(),
                audit_capture=False, rate_limit_key=None, elapsed_ms=1,
            )

        import yashigani.mcp.broker as broker_mod
        monkeypatch.setattr(broker_mod, "query_mcp_decision", _fake_query)

        broker = McpBroker(McpBrokerConfig(opa_url="http://opa", tenant_id=_TENANT))
        # Live catalogue stub — same source _check_capability_envelope reads.
        cat = MagicMock()
        cat.surface_set_hash = _HEX64
        store = MagicMock()
        store.get.return_value = cat
        broker._catalogue_store = store

        ctx = McpCallContext(
            tenant_id=_TENANT,
            agent_name=_SERVER,
            user_id="u-1",
            posture=McpPosture.MCP_B,
            posture_binding=PostureBinding.for_posture(McpPosture.MCP_B),
            action="mcp.tools.call",
            tool_name="echo",
            server_id=_SERVER,
            mcp_id="mcp-uuid-1",
            identity_verified=True,
            target_cert_fingerprint="AB:CD" + ":EF" * 0 + _HEX64[4:],  # messy input
        )
        decision = await broker.enforce(ctx)
        assert decision.allow is False  # our stub denies; the wiring is the test

        assert captured["identity_verified"] is True
        assert captured["mcp_id"] == "mcp-uuid-1"
        # Broker normalises to sha256:<lowercase hex, no separators>.
        assert captured["cert_fingerprint"].startswith("sha256:")
        assert ":" not in captured["cert_fingerprint"][len("sha256:"):]
        assert captured["surface_hash"] == f"sha256:{_HEX64}"

    @pytest.mark.asyncio
    async def test_enforce_defaults_fail_closed(self, monkeypatch):
        """Unverified ctx (defaults) → verified=False, no target material."""
        captured: dict = {}

        async def _fake_query(**kwargs):
            captured.update(kwargs)
            from yashigani.mcp._opa import OpaDecisionResult
            return OpaDecisionResult(
                allow=False, deny_reason="unit_deny", redact_args=set(),
                audit_capture=False, rate_limit_key=None, elapsed_ms=1,
            )

        import yashigani.mcp.broker as broker_mod
        monkeypatch.setattr(broker_mod, "query_mcp_decision", _fake_query)

        broker = McpBroker(McpBrokerConfig(opa_url="http://opa", tenant_id=_TENANT))
        store = MagicMock()
        store.get.return_value = None   # no catalogue fetched yet
        broker._catalogue_store = store

        ctx = McpCallContext(
            tenant_id=_TENANT, agent_name=_SERVER, user_id="u",
            posture=McpPosture.MCP_B,
            posture_binding=PostureBinding.for_posture(McpPosture.MCP_B),
            action="mcp.tools.call", tool_name="echo", server_id=_SERVER,
        )
        await broker.enforce(ctx)
        assert captured["identity_verified"] is False
        assert captured["mcp_id"] is None
        assert captured["cert_fingerprint"] is None
        assert captured["surface_hash"] is None


# ---------------------------------------------------------------------------
# Task C — durable broker registry (SEAM-1d-07)
# ---------------------------------------------------------------------------

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


def _descriptor(server=_SERVER, tenant=_TENANT) -> dict:
    return {
        "agent_name": server,
        "upstream_url": f"https://caddy:9573/mcp/{tenant}/{server}",
        "tenant_id": tenant,
        "is_filesystem_agent": False,
        "is_git_agent": False,
        "cert_fingerprint": f"sha256:{_HEX64}",
        "spiffe_id": f"spiffe://td/agents/{tenant}/{server}/nhi_0011",
        "svid_instance_id": "nhi_0011",
    }


class TestDurableMcpRegistryStore:
    def test_put_get_roundtrip_on_canonical_key(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        got = store.get(_TENANT, _SERVER)
        assert got is not None
        assert got["upstream_url"].endswith(f"/mcp/{_TENANT}/{_SERVER}")
        assert got["registered_at"]  # stamped
        assert canonical_server_key(_TENANT, _SERVER) == f"{_TENANT}:{_SERVER}"

    def test_get_by_agent_name(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        got = store.get_by_agent_name(_SERVER)
        assert got is not None and got["agent_name"] == _SERVER
        assert store.get_by_agent_name("unknown") is None

    def test_ambiguous_agent_name_across_tenants_refuses(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put("t1", _SERVER, _descriptor(tenant="t1"))
        store.put("t2", _SERVER, _descriptor(tenant="t2"))
        assert store.get_by_agent_name(_SERVER) is None  # never guess a tenant

    def test_delete_removes_key_and_index(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        store.delete(_TENANT, _SERVER)
        assert store.get(_TENANT, _SERVER) is None
        assert store.get_by_agent_name(_SERVER) is None
        assert store.list_all() == []

    def test_read_paths_degrade_to_miss_on_redis_error(self):
        broken = MagicMock()
        broken.get.side_effect = RuntimeError("redis down")
        broken.smembers.side_effect = RuntimeError("redis down")
        store = DurableMcpRegistryStore(broken)
        assert store.get(_TENANT, _SERVER) is None
        assert store.get_by_agent_name(_SERVER) is None
        assert store.list_all() == []

    def test_write_path_raises_on_redis_error(self):
        broken = MagicMock()
        broken.set.side_effect = RuntimeError("redis down")
        store = DurableMcpRegistryStore(broken)
        with pytest.raises(RuntimeError):
            store.put(_TENANT, _SERVER, _descriptor())


class TestRegistryLazyLoad:
    def _factory_calls(self):
        calls: list = []

        def _factory(desc: dict):
            calls.append(desc)
            cfg = McpBrokerServerConfig(
                upstream_url=desc["upstream_url"],
                is_filesystem_agent=bool(desc.get("is_filesystem_agent")),
                is_git_agent=bool(desc.get("is_git_agent")),
                tenant_id=desc["tenant_id"],
                agent_name=desc["agent_name"],
                cert_fingerprint=desc.get("cert_fingerprint", ""),
            )
            return object(), cfg

        return calls, _factory

    def test_miss_lazily_builds_registers_and_caches(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())
        calls, factory = self._factory_calls()

        registry = McpBrokerRegistry()
        registry.attach_durable_source(store, factory)

        assert len(registry) == 0
        entry = registry.get(_SERVER)          # miss → lazy load
        assert entry is not None
        _broker, cfg = entry
        assert cfg.agent_name == _SERVER
        assert cfg.cert_fingerprint == f"sha256:{_HEX64}"
        assert len(registry) == 1

        registry.get(_SERVER)                  # second hit → cached
        assert len(calls) == 1                 # factory ran exactly once

    def test_miss_without_durable_source_stays_404(self):
        registry = McpBrokerRegistry()
        assert registry.get(_SERVER) is None

    def test_factory_failure_degrades_to_miss(self):
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())

        def _bad_factory(desc):
            raise RuntimeError("bad descriptor")

        registry = McpBrokerRegistry()
        registry.attach_durable_source(store, _bad_factory)
        assert registry.get(_SERVER) is None
        assert len(registry) == 0

    def test_build_registry_from_env_empty_env_with_durable_store(self, monkeypatch):
        """Empty boot env + durable store → shared machinery built, lazy load
        works end-to-end (the no-reboot path for a first-ever onboard)."""
        from yashigani.mcp.registry import build_registry_from_env

        monkeypatch.delenv("YASHIGANI_MCP_SERVERS", raising=False)
        monkeypatch.delenv("REDIS_URL", raising=False)
        store = DurableMcpRegistryStore(_FakeRedis())
        store.put(_TENANT, _SERVER, _descriptor())

        registry, jwks_store = build_registry_from_env(
            opa_url="http://opa:8181", durable_store=store,
        )
        assert jwks_store is not None       # lazily-built brokers can sign
        assert len(registry) == 0
        entry = registry.get(_SERVER)
        assert entry is not None
        broker, cfg = entry
        assert cfg.upstream_url.endswith(f"/mcp/{_TENANT}/{_SERVER}")
        assert len(registry) == 1

    def test_build_registry_from_env_empty_env_no_store_unchanged(self, monkeypatch):
        """Backward compatibility: unset env + no store → (empty, None)."""
        from yashigani.mcp.registry import build_registry_from_env

        monkeypatch.delenv("YASHIGANI_MCP_SERVERS", raising=False)
        registry, jwks_store = build_registry_from_env(opa_url="http://opa:8181")
        assert len(registry) == 0
        assert jwks_store is None


# ---------------------------------------------------------------------------
# Task C — approve transaction registers the broker descriptor
# ---------------------------------------------------------------------------

from yashigani.backoffice.mcp_onboard import (  # noqa: E402
    McpOnboardError,
    run_approve_transaction,
)

_DIGEST = "sha256:" + "ab12" * 16


def _manifest_yaml(name: str = _SERVER, tenant: str = _TENANT) -> str:
    return textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {name}
          tenant_id: {tenant}
          category: mcp_server
          description: demo MCP for phase-2a registry tests
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


def _self_signed_pem() -> bytes:
    """A real (throwaway) self-signed cert so _leaf_cert_fingerprint parses."""
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
        return f"spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}/{instance_id}"
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
    # Step 2b (svid_init, f8dac097 / SEAM-1d-06) copies
    # IssuerPaths.intermediate_cert (= secrets_dir / "ca_intermediate.crt")
    # into secrets/svid-init/<tenant>/<server>/ca.crt. The fixture must
    # provide it or the transaction fail-closes at svid_init.
    (secrets_dir / "ca_intermediate.crt").write_text("INTERMEDIATE-CA-PEM")
    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    # FINDING-V412-SVID-WRITE-PATH (Captain, 2026-07-21) — see
    # test_v41_mcp_onboard_transaction.py txn_env for full rationale.
    monkeypatch.setenv("YASHIGANI_AGENTS_DIR", str(secrets_dir))
    monkeypatch.setenv("YASHIGANI_SVID_INIT_DIR", str(secrets_dir / "svid-init"))
    monkeypatch.setenv("YASHIGANI_SVID_GID", str(os.getgid()))
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


async def _run(secrets_dir, *, svc=None, reloader=None, registry_store=None):
    with patch(
        "yashigani.pki.issuer.mint_agent_leaf",
        side_effect=_mint_side_effect(secrets_dir),
    ):
        return await run_approve_transaction(
            manifest_yaml=_manifest_yaml(),
            server_id=_SERVER,
            tenant_id=_TENANT,
            env=MagicMock(tools={"cloud9-demo::echo": MagicMock()}),
            topology="ring_fenced",
            sidecar_scan_verdict={"classifier_status": "not_configured"},
            operator_identity="orchid",
            envelope_service=svc if svc is not None else _svc(),
            audit_writer=None,
            caddy_reloader=reloader or _FakeReloader(),
            registry_store=registry_store,
        )


class TestApproveRegistersDurableDescriptor:
    @pytest.mark.asyncio
    async def test_success_registers_canonical_descriptor(self, txn_env):
        _, secrets_dir = txn_env
        store = DurableMcpRegistryStore(_FakeRedis())
        result = await _run(secrets_dir, registry_store=store)

        desc = store.get(_TENANT, _SERVER)
        assert desc is not None, "descriptor must be registered at approve/commit"
        # Canonical key + wrap upstream (base URL — transport appends /mcp).
        assert desc["agent_name"] == _SERVER
        assert desc["tenant_id"] == _TENANT
        assert desc["upstream_url"].startswith("https://caddy:")
        assert desc["upstream_url"].endswith(f"/mcp/{_TENANT}/{_SERVER}")
        # Per-instance identity binding for the OPA target.
        assert desc["cert_fingerprint"].startswith("sha256:")
        assert len(desc["cert_fingerprint"]) == len("sha256:") + 64
        assert desc["spiffe_id"] == result.spiffe_id
        assert desc["svid_instance_id"] == result.instance_id
        # And the gateway lazy path resolves it by agent_name.
        assert store.get_by_agent_name(_SERVER) is not None

    @pytest.mark.asyncio
    async def test_registry_put_failure_rolls_back_fail_closed(self, txn_env):
        artifact_root, secrets_dir = txn_env
        svc = _svc()
        store = MagicMock()
        store.put.side_effect = RuntimeError("redis down")
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, registry_store=store)
        assert exc_info.value.step == "broker_registry"
        # Full rollback: no leaf, no artifacts, envelope never minted.
        assert not sorted(secrets_dir.glob("agent_*_client.*"))
        assert not list(artifact_root.rglob("*.caddy"))
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_envelope_failure_deletes_registration(self, txn_env):
        _, secrets_dir = txn_env
        store = DurableMcpRegistryStore(_FakeRedis())
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=_svc(fail=True), registry_store=store)
        assert exc_info.value.step == "envelope_mint"
        # The step-4b registration was rolled back with everything else.
        assert store.get(_TENANT, _SERVER) is None

    @pytest.mark.asyncio
    async def test_prod_without_registry_store_fails_closed_503(
        self, txn_env, monkeypatch,
    ):
        _, secrets_dir = txn_env
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        svc = _svc()
        with pytest.raises(McpOnboardError) as exc_info:
            await _run(secrets_dir, svc=svc, registry_store=None)
        assert exc_info.value.step == "config"
        assert exc_info.value.http_status == 503
        # Fails BEFORE minting anything.
        assert not sorted(secrets_dir.glob("agent_*_client.*"))
        svc.mint_envelope.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_dev_without_registry_store_warn_skips(self, txn_env):
        """Dev/test path: no store → transaction still commits (pre-Phase-3)."""
        _, secrets_dir = txn_env
        result = await _run(secrets_dir, registry_store=None)
        assert result.envelope_id == 77
