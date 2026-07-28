# Last updated: 2026-07-28T00:00:00+00:00
"""
Regression — LAURA-V50-010: a live-imported MCP server never got an mcp_id
minted; ``policy/mcp.rego``'s ``_instance_identified`` gate then denied
EVERY ``tools/call`` (benign and malicious) before the broker's M4 /
capability-envelope / YSG-RISK-144 gates were reached.

Traced root cause (Tom, 2026-07-28 — code + live simulation, not inferred):

  1. ``registry.py:_build_broker_and_config`` (shared by BOTH the
     YASHIGANI_MCP_SERVERS boot loop AND the durable-registry lazy-load
     path, SEAM-1d-07) already calls ``McpIdStore.get_or_mint()`` — so a
     server's mcp_id DOES eventually get minted, but only LAZILY, on the
     FIRST ``McpBrokerRegistry.get()`` hit (i.e. the server's first live
     request). Until that first hit, a server registered only via the live
     import/approve ceremony (durable registry, no YASHIGANI_MCP_SERVERS
     boot entry) has ``server_cfg.mcp_id == ""`` — exactly what
     ``_instance_identified`` denies on.
  2. ``backoffice/mcp_onboard.py``'s step 4b broker descriptor NEVER wrote
     an "mcp_id" field, so the operator-pin fast path
     (``override_mcp_id``) was never used either — the descriptor was
     ALWAYS relying on the lazy mint above.
  3. ``push_mcp_opa_data`` (grants/baselines -> OPA) was ONLY called from
     the gateway's startup path (entrypoint.py) — a server onboarded via
     the live import ceremony after boot had no live OPA push at all until
     the next gateway restart, so even a correctly-minted mcp_id could not
     satisfy ``_grant_ok`` / ``_envelope_unchanged`` either.

Fix under test (Tom, 2026-07-28):
  A. ``McpIdStore.mint_all()`` — eager, best-effort mint for a batch of
     agent_names (used by the new gateway startup pass AND directly
     testable here).
  B. ``gateway/entrypoint.py`` — eager mint for every durable-registry
     descriptor at startup (not only boot-list entries), BEFORE the
     gateway finishes MCP wiring — closes the "unminted until first live
     call" window for durably-registered servers.
  C. ``backoffice/mcp_onboard.py`` — ``run_approve_transaction(...,
     mcp_id_store=...)`` resolves + writes a non-empty ``mcp_id`` into the
     broker descriptor AT APPROVE TIME, and (companion fix) pushes the
     FULL grants/baselines/egress_grants document live via
     ``push_mcp_opa_data`` instead of only ``egress_grants``.

Live proof that a real ``tools/call`` now reaches the broker's four-gate
(M4 / capability-envelope / YSG-RISK-144) is DEFERRED to the rebuild +
Laura re-attack (per the LAURA-V50-010 fix brief) — this suite proves the
Python-level wiring: every registered MCP server resolves a stable,
non-empty mcp_id that reaches ``input.target.mcp_id`` deterministically,
with no dependency on lazy on-demand minting.
"""
from __future__ import annotations

import json
import os
import textwrap
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from yashigani.mcp._durable_registry import DurableMcpRegistryStore
from yashigani.mcp._id_store import McpIdStore
from yashigani.mcp.registry import build_registry_from_env

_TENANT = "default"
_SERVER = "cloud9-demo"
_DIGEST = "sha256:" + "ab12" * 16


class _FakeRedis:
    """Minimal in-memory Redis stand-in (bytes-returning, like db/3 client) —
    same shape as test_v41_egress_grants.py's fixture, reused here so
    McpIdStore + DurableMcpRegistryStore share ONE backing store, exactly
    as they share Redis db/3 in the real gateway/backoffice."""

    def __init__(self):
        self.kv: dict = {}
        self.sets: dict = {}

    def set(self, k, v):
        self.kv[k] = v.encode() if isinstance(v, str) else v

    def get(self, k):
        return self.kv.get(k)

    def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    def sadd(self, k, m):
        self.sets.setdefault(k, set()).add(m.encode() if isinstance(m, str) else m)

    def srem(self, k, m):
        self.sets.get(k, set()).discard(m.encode() if isinstance(m, str) else m)

    def smembers(self, k):
        return set(self.sets.get(k, set()))


# ---------------------------------------------------------------------------
# A. McpIdStore.mint_all — eager batch mint (Fix A)
# ---------------------------------------------------------------------------


class TestMintAll:
    def test_mints_every_name_non_empty(self):
        store = McpIdStore(_FakeRedis())
        resolved = store.mint_all(["cloud9-demo", "filesystem-mcp", "git"])
        assert set(resolved) == {"cloud9-demo", "filesystem-mcp", "git"}
        for mcp_id in resolved.values():
            assert mcp_id
            uuid.UUID(mcp_id)  # must be a real UUID

    def test_idempotent_across_two_passes(self):
        """Two eager-mint passes (e.g. two gateway restarts) must resolve
        the SAME id — this is the rename-survivability / grant-stability
        invariant the whole McpIdStore design depends on."""
        store = McpIdStore(_FakeRedis())
        first = store.mint_all(["cloud9-demo"])
        second = store.mint_all(["cloud9-demo"])
        assert first["cloud9-demo"] == second["cloud9-demo"]

    def test_skips_blank_names(self):
        store = McpIdStore(_FakeRedis())
        resolved = store.mint_all(["", "  ", "real-server"])
        assert set(resolved) == {"real-server"}

    def test_single_name_failure_does_not_abort_the_batch(self):
        """LAURA-V50-010's own recommendation: a per-name mint failure must
        be logged and skipped, never silently abort the whole startup pass
        (that would regress EVERY other server to unminted, not just the
        one with the transient Redis blip)."""
        store = McpIdStore(_FakeRedis())
        real_get_or_mint = store.get_or_mint

        def _flaky(name, **kw):
            if name == "flaky-server":
                raise ConnectionError("simulated Redis blip")
            return real_get_or_mint(name, **kw)

        with patch.object(store, "get_or_mint", side_effect=_flaky):
            resolved = store.mint_all(["cloud9-demo", "flaky-server", "letta"])
        assert set(resolved) == {"cloud9-demo", "letta"}
        assert "flaky-server" not in resolved


# ---------------------------------------------------------------------------
# B. build_registry_from_env — durable-registry (live-import) lazy path
#    still mints correctly, INCLUDING when the descriptor has no "mcp_id"
#    field yet (the pre-fix mcp_onboard.py shape) — proves Fix A/B's eager
#    startup pass is a genuine hardening, not compensating for broken lazy
#    logic.
# ---------------------------------------------------------------------------


class TestDurableLazyLoadMintsMcpId:
    def _durable_descriptor(self, mcp_id: str = "") -> dict:
        """Exact shape mcp_onboard.py step 4b writes (agent_name/upstream_
        url/tenant_id/is_filesystem_agent/is_git_agent/cert_fingerprint/
        spiffe_id + optionally mcp_id after Fix C)."""
        desc = {
            "agent_name": _SERVER,
            "upstream_url": "https://caddy:9443/mcp/%s/%s" % (_TENANT, _SERVER),
            "tenant_id": _TENANT,
            "is_filesystem_agent": False,
            "is_git_agent": False,
            "cert_fingerprint": "sha256:deadbeef",
            "spiffe_id": "spiffe://yashigani-local.yashigani.internal/agents/%s/%s/nhi_x"
            % (_TENANT, _SERVER),
            "svid_instance_id": "nhi_x",
            "image_digest": "",
        }
        if mcp_id:
            desc["mcp_id"] = mcp_id
        return desc

    def test_lazy_get_mints_when_descriptor_has_no_mcp_id(self, monkeypatch):
        """Pre-Fix-C descriptor shape (no 'mcp_id' key at all): the FIRST
        McpBrokerRegistry.get() call must still resolve a non-empty
        server_cfg.mcp_id via the durable lazy-load path. This is the
        EXISTING (already-correct) mechanism Fix A/B eagerly front-loads —
        this test pins it so a future refactor cannot silently break it."""
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "")
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        durable_store = DurableMcpRegistryStore(redis)
        durable_store.put(_TENANT, _SERVER, self._durable_descriptor())

        registry, _ = build_registry_from_env(
            opa_url="https://policy:8181",
            mcp_id_store=mcp_id_store,
            durable_store=durable_store,
        )
        assert len(registry) == 0, "server is durable-only — not in the boot list"

        entry = registry.get(_SERVER)
        assert entry is not None, "lazy durable-store load must not 404"
        _, server_cfg = entry
        assert server_cfg.mcp_id, "LAURA-V50-010: mcp_id must be non-empty"
        uuid.UUID(server_cfg.mcp_id)

    def test_lazy_get_honours_preminted_mcp_id_from_approve_time(self, monkeypatch):
        """Post-Fix-C descriptor shape (mcp_onboard.py now writes 'mcp_id'
        at approve time): the lazy build must use that EXACT id (operator-
        pin fast path), not mint a fresh/different one."""
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "")
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        # Simulate approve-time minting (Fix C) — the id is already in
        # Redis under mcp:name_to_id:cloud9-demo BEFORE the descriptor is
        # ever read by the lazy path.
        preminted = mcp_id_store.get_or_mint(_SERVER)
        durable_store = DurableMcpRegistryStore(redis)
        durable_store.put(_TENANT, _SERVER, self._durable_descriptor(mcp_id=preminted))

        registry, _ = build_registry_from_env(
            opa_url="https://policy:8181",
            mcp_id_store=mcp_id_store,
            durable_store=durable_store,
        )
        _, server_cfg = registry.get(_SERVER)
        assert server_cfg.mcp_id == preminted


# ---------------------------------------------------------------------------
# C. run_approve_transaction — mcp_id minted + written into the descriptor
#    at approve time (Fix C)
# ---------------------------------------------------------------------------


def _manifest_yaml() -> str:
    return textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {_SERVER}
          tenant_id: {_TENANT}
          category: mcp_server
          description: LAURA-V50-010 regression fixture
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
    """Real (self-signed, throwaway) leaf PEM — step 4b's
    ``_leaf_cert_fingerprint()`` parses the minted cert with
    ``x509.load_pem_x509_certificate``, so a placeholder string ("CERT")
    is not enough once ``registry_store`` is wired (mirrors
    test_v41_egress_grants.py's fixture of the same name)."""
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
        return f"spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}/{instance_id}"
    return _mint


class _FakeReloader:
    def __init__(self):
        self.calls = 0

    async def __call__(self) -> None:
        self.calls += 1


def _svc() -> MagicMock:
    svc = MagicMock()
    svc.mint_envelope = AsyncMock(return_value=99)
    return svc


@pytest.fixture()
def txn_env(tmp_path, monkeypatch):
    from yashigani.manifest.codegen import reset_codegen_registry
    reset_codegen_registry()
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "ca_intermediate.crt").write_text("INTERMEDIATE-CA-PEM")
    monkeypatch.setenv("YASHIGANI_MCP_ARTIFACT_ROOT", str(artifact_root))
    monkeypatch.setenv("YASHIGANI_SECRETS_DIR", str(secrets_dir))
    monkeypatch.setenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH", str(tmp_path / "service_identities.yaml"),
    )
    monkeypatch.setenv("YASHIGANI_AGENTS_DIR", str(secrets_dir))
    monkeypatch.setenv("YASHIGANI_SVID_INIT_DIR", str(secrets_dir / "svid-init"))
    monkeypatch.setenv("YASHIGANI_SVID_GID", str(os.getgid()))
    monkeypatch.setenv("YASHIGANI_CONTAINER_RUNTIME", "docker")
    monkeypatch.delenv("YSG_REQUIRE_SIGNED_MANIFEST", raising=False)
    monkeypatch.delenv("YSG_REQUIRE_CADDY_VALIDATE", raising=False)
    monkeypatch.delenv("YASHIGANI_ENV", raising=False)
    monkeypatch.delenv("YASHIGANI_OPA_URL", raising=False)
    yield artifact_root, secrets_dir
    reset_codegen_registry()


async def _run(secrets_dir, *, registry_store=None, mcp_id_store=None):
    from yashigani.backoffice.mcp_onboard import run_approve_transaction
    with patch("yashigani.pki.issuer.mint_agent_leaf", side_effect=_mint_side_effect(secrets_dir)):
        return await run_approve_transaction(
            manifest_yaml=_manifest_yaml(),
            server_id=_SERVER,
            tenant_id=_TENANT,
            env=MagicMock(tools={f"{_SERVER}::echo": MagicMock()}),
            topology="ring_fenced",
            sidecar_scan_verdict={"classifier_status": "not_configured"},
            operator_identity="orchid",
            envelope_service=_svc(),
            caddy_reloader=_FakeReloader(),
            registry_store=registry_store,
            mcp_id_store=mcp_id_store,
        )


class TestApproveTransactionMintsMcpId:
    @pytest.mark.asyncio
    async def test_descriptor_carries_non_empty_mcp_id(self, txn_env):
        """Core LAURA-V50-010 fix: the durable-registry descriptor written
        by the approve transaction now has a real, non-empty mcp_id — the
        gap the finding traced (mcp_onboard.py never wrote this field)."""
        _, secrets_dir = txn_env
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        registry_store = DurableMcpRegistryStore(redis)

        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=mcp_id_store)

        descriptor = registry_store.get(_TENANT, _SERVER)
        assert descriptor is not None
        assert descriptor.get("mcp_id"), "descriptor must carry a non-empty mcp_id"
        uuid.UUID(descriptor["mcp_id"])

    @pytest.mark.asyncio
    async def test_mcp_id_matches_the_id_store_mapping(self, txn_env):
        """The id written into the descriptor must be the SAME id
        McpIdStore.get_or_mint(server_id) resolves — i.e. the descriptor's
        pin and the store's canonical name->id mapping never drift."""
        _, secrets_dir = txn_env
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        registry_store = DurableMcpRegistryStore(redis)

        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=mcp_id_store)

        descriptor = registry_store.get(_TENANT, _SERVER)
        assert descriptor["mcp_id"] == mcp_id_store.get_mcp_id_for_name(_SERVER)

    @pytest.mark.asyncio
    async def test_without_mcp_id_store_descriptor_degrades_to_empty(self, txn_env):
        """Backward compatible: mcp_id_store=None (dev/test, or an install
        that has not wired McpIdStore into backoffice) must NOT fail the
        transaction — the descriptor's mcp_id is simply "" and the
        gateway's existing lazy-mint fallback still covers the server
        (proven by TestDurableLazyLoadMintsMcpId above)."""
        _, secrets_dir = txn_env
        registry_store = DurableMcpRegistryStore(_FakeRedis())

        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=None)

        descriptor = registry_store.get(_TENANT, _SERVER)
        assert descriptor is not None
        assert descriptor.get("mcp_id", "") == ""

    @pytest.mark.asyncio
    async def test_reapprove_is_idempotent_same_mcp_id(self, txn_env):
        """A re-approve (same server_id) must resolve the SAME mcp_id —
        the grant/baseline keying must never drift across re-onboards."""
        _, secrets_dir = txn_env
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        registry_store = DurableMcpRegistryStore(redis)

        from yashigani.manifest.codegen import reset_codegen_registry

        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=mcp_id_store)
        first_id = registry_store.get(_TENANT, _SERVER)["mcp_id"]

        reset_codegen_registry()
        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=mcp_id_store)
        second_id = registry_store.get(_TENANT, _SERVER)["mcp_id"]

        assert first_id == second_id


# ---------------------------------------------------------------------------
# D. End-to-end: approve -> durable descriptor -> lazy registry load ->
#    McpCallContext.mcp_id -> OPA input.target.mcp_id (_instance_identified)
# ---------------------------------------------------------------------------


class TestEndToEndFourGateReachability:
    @pytest.mark.asyncio
    async def test_approved_server_reaches_instance_identified_shape(self, txn_env, monkeypatch):
        """The exact causal chain LAURA-V50-010 traced, reproduced without a
        live stack: approve (mints mcp_id) -> gateway builds its registry
        against the SAME durable store/id store (mirrors a gateway restart
        OR the eager startup pass, Fix B) -> registry.get() resolves a
        non-empty mcp_id -> _build_opa_input emits a non-empty
        input.target.mcp_id (the exact field policy/mcp.rego's
        _instance_identified requires)."""
        _, secrets_dir = txn_env
        monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "")
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        registry_store = DurableMcpRegistryStore(redis)

        await _run(secrets_dir, registry_store=registry_store, mcp_id_store=mcp_id_store)

        # Mirrors gateway/entrypoint.py's registry construction (build_registry_
        # from_env with the SAME mcp_id_store + durable_store the approve
        # transaction wrote into).
        registry, _ = build_registry_from_env(
            opa_url="https://policy:8181",
            mcp_id_store=mcp_id_store,
            durable_store=registry_store,
        )
        _, server_cfg = registry.get(_SERVER)
        assert server_cfg.mcp_id, "LAURA-V50-010: broker-visible mcp_id must be non-empty"

        from yashigani.mcp._opa import _build_opa_input

        opa_input = _build_opa_input(
            posture="mcp-b",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/%s/%s/nhi_x" % (_TENANT, _SERVER),
            chain=[],
            tool_name="echo",
            mcp_id=server_cfg.mcp_id,
        )
        # This is EXACTLY policy/mcp.rego's _instance_identified predicate,
        # evaluated in Python against the real produced input document.
        # _build_opa_input wraps the document under {"input": {...}} per
        # OPA's REST API contract (POST /v1/data/... body shape).
        doc = opa_input["input"]
        assert "target" in doc, "target must be emitted (mcp_id is non-empty)"
        assert isinstance(doc["target"]["mcp_id"], str)
        assert doc["target"]["mcp_id"] != ""
