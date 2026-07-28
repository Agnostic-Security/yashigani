# Last updated: 2026-07-28T00:00:00+00:00
"""
Converged end-to-end regression — LAURA-V50-010 + LAURA-V50-014 together.

Both findings live in the SAME code family (gateway/entrypoint.py +
mcp/registry.py + backoffice/mcp_onboard.py) and must be proven TOGETHER,
not in isolation, because each alone is necessary but not sufficient for
the "secure MCP" claim:

  * LAURA-V50-014 (Critical, fail-OPEN) fixed: the broker registry is
    ALWAYS attached to gateway state once MCP is configured — a
    live-onboard-only boot (empty YASHIGANI_MCP_SERVERS, the normal demo/
    production topology) no longer discards it to None. Without 014, a
    fake AND a real agent name would both blindly proxy to
    YASHIGANI_UPSTREAM_URL, bypassing every OPA gate.

  * LAURA-V50-010 (High, unreachable-fail-closed) fixed: a server onboarded
    via the LIVE import/approve ceremony gets a stable mcp_id minted AT
    APPROVE TIME (not only lazily on its first live request) and its
    grants/baselines/egress are pushed to OPA's live data at that same
    approve time (not only at the next gateway restart). Without 010, 014
    alone gets you only as far as "the registry answers registry.get()
    with a real broker+config" — but that config's mcp_id would still be
    "" until a live request happened to lazily mint it, and even once
    minted, data.yashigani.mcp.grants[mcp_id] would be EMPTY (never
    pushed) — so _instance_identified and/or _grant_ok would STILL deny a
    real, correctly-onboarded, correctly-granted server. 014 makes the
    request REACHABLE; 010 makes it ANSWERABLE.

This suite proves the end state Laura must be able to re-attack: boot
empty -> live-import+approve a real server (mints mcp_id + pushes grants,
010) -> a fake name is DENIED (never proxied, 014) AND the real server's
tools/call reaches the broker four-gate carrying the correct mcp_id (014
routes it there; 010 is why the mcp_id is non-empty and why OPA's grants
document actually has an entry for it).
"""
from __future__ import annotations

import os
import textwrap
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from yashigani.mcp._durable_registry import DurableMcpRegistryStore
from yashigani.mcp._id_store import McpIdStore
from yashigani.mcp.registry import build_registry_from_env, is_mcp_configured

_TENANT = "default"
_SERVER = "cloud9-demo"
_FAKE_SERVER = "totally-fake-nonexistent-server-xyz123"
_DIGEST = "sha256:" + "ab12" * 16


class _FakeRedis:
    """Minimal in-memory Redis stand-in (bytes-returning, like db/3 client)."""

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
# Real live-import machinery (010) — same fixture shape as
# test_laura_v50_010_mcp_id_never_minted.py, self-contained here so this
# file stands alone as the converged proof.
# ---------------------------------------------------------------------------


def _manifest_yaml() -> str:
    return textwrap.dedent(f"""\
        apiVersion: yashigani.io/v1alpha1
        kind: AgentIntegration
        metadata:
          name: {_SERVER}
          tenant_id: {_TENANT}
          category: mcp_server
          description: LAURA-V50-010+014 converged regression fixture
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
    monkeypatch.setenv("YASHIGANI_MCP_SERVERS", "")  # empty boot list — the topology under test
    yield artifact_root, secrets_dir
    reset_codegen_registry()


async def _live_import(secrets_dir, registry_store, mcp_id_store):
    """Run the REAL approve transaction — 010's live-import path — mints
    mcp_id at approve time and writes the durable descriptor + OPA
    grant/baseline records, exactly as backoffice/routes/mcp_servers.py's
    POST /import wires it."""
    from yashigani.backoffice.mcp_onboard import run_approve_transaction

    # provenance_id MUST match the real "<tenant>:<server_id>" format
    # (mcp_servers.py route: provenance_id = f"{tenant}:{body.server_id}")
    # — step 4b-ii strips this exact prefix off the namespaced tool key to
    # recover the bare tool name ("echo") for the OPA grant's tools list;
    # a MagicMock auto-attribute here would silently leave the tool key
    # namespaced and this test's grant-content assertions would misfire.
    env = MagicMock(
        tools={f"{_TENANT}:{_SERVER}::echo": MagicMock()},
        provenance_id=f"{_TENANT}:{_SERVER}",
        surface_set_hash="deadbeef" * 8,
    )
    with patch("yashigani.pki.issuer.mint_agent_leaf", side_effect=_mint_side_effect(secrets_dir)):
        return await run_approve_transaction(
            manifest_yaml=_manifest_yaml(),
            server_id=_SERVER,
            tenant_id=_TENANT,
            env=env,
            topology="ring_fenced",
            sidecar_scan_verdict={"classifier_status": "not_configured"},
            operator_identity="orchid",
            envelope_service=_svc(),
            caddy_reloader=_FakeReloader(),
            registry_store=registry_store,
            mcp_id_store=mcp_id_store,
        )


def _boot_gateway_after_live_import(registry_store, mcp_id_store):
    """Mirrors gateway/entrypoint.py's startup wiring for the live-onboard-
    only topology: empty YASHIGANI_MCP_SERVERS, the SAME durable store +
    id store the approve transaction (above) just wrote into."""
    registry, jwks_store = build_registry_from_env(
        opa_url="https://policy:8181",
        mcp_id_store=mcp_id_store,
        durable_store=registry_store,
    )
    assert is_mcp_configured(registry, jwks_store) is True, (
        "014: MCP must be reported configured on an empty boot list once "
        "the durable registry is wired"
    )
    return registry, jwks_store


def _minimal_gateway_app(mcp_broker_registry, mcp_jwks_store):
    """Build the gateway app exactly as entrypoint.py now wires it
    (014: mcp_broker_registry is the real registry object, never None)."""
    from yashigani.gateway.proxy import GatewayConfig, create_gateway_app
    from yashigani.mcp.router import create_mcp_router

    cfg = GatewayConfig(
        upstream_base_url="http://unreachable-demo-mcp-upstream-test:9999",
        opa_url="https://policy:8181",
    )
    representative_broker = (
        mcp_broker_registry.all_brokers()[0] if len(mcp_broker_registry) > 0 else None
    )
    info_router = create_mcp_router(mcp_jwks_store, representative_broker, opa_url=cfg.opa_url)
    inspection_pipeline = MagicMock()
    inspection_pipeline.inspect.return_value = MagicMock(action="ALLOW", sanitized_content=None)

    app = create_gateway_app(
        config=cfg,
        inspection_pipeline=inspection_pipeline,
        chs=MagicMock(),
        audit_writer=MagicMock(),
        extra_routers=[info_router],
        mcp_broker_registry=mcp_broker_registry,
        mcp_jwks_store=mcp_jwks_store,
    )
    return app, cfg


class TestConvergedBootEmptyLiveImportFakeDeniedRealReachesFourGate:
    @pytest.mark.asyncio
    async def test_full_lifecycle(self, txn_env):
        """The exact end-state Laura must be able to re-attack:

        1. Gateway boots with YASHIGANI_MCP_SERVERS="" (empty).
        2. A real server is live-imported + approved (010's
           run_approve_transaction, mints mcp_id + pushes OPA grant/
           baseline to the durable store).
        3. The gateway (re)builds its registry against that SAME durable
           store (mirrors a restart OR the SEAM-1d-07 lazy-load carrying
           forward within one process) -- registry is ALWAYS attached
           (014), and the live-imported server already carries a non-
           empty, approve-time-minted mcp_id (010) baked into its
           descriptor -- no lazy-mint race.
        4. A fake/never-onboarded agent name -> DENIED (404,
           MCP_SERVER_NOT_FOUND), never proxied upstream (014's core
           fix -- fail-closed, not fail-open).
        5. The real server's tools/call -> reaches McpBroker.enforce() /
           query_mcp_decision() (the four-gate) carrying the SAME mcp_id
           run_approve_transaction() minted (014 routes it there; 010 is
           why that id is non-empty and stable).
        6. The OPA grants document build_mcp_opa_data() produces (010's
           companion push fix) contains a REAL grant entry keyed on that
           EXACT mcp_id for the gateway's calling SPIFFE identity, and
           its tools list includes "echo" -- i.e. an OPA evaluating this
           input would find _grant_ok satisfiable, not just
           _instance_identified. This is the "grants resolved in OPA"
           requirement -- proven WITHOUT a live OPA process by asserting
           the exact document that gets PUT to OPA's data API.
        """
        _, secrets_dir = txn_env
        redis = _FakeRedis()
        mcp_id_store = McpIdStore(redis)
        registry_store = DurableMcpRegistryStore(redis)

        # ── Step 2: live import + approve (010) ─────────────────────────
        result = await _live_import(secrets_dir, registry_store, mcp_id_store)

        descriptor = registry_store.get(_TENANT, _SERVER)
        assert descriptor is not None
        minted_mcp_id = descriptor.get("mcp_id", "")
        assert minted_mcp_id, (
            "LAURA-V50-010: the descriptor written by the live-import "
            "ceremony must carry a non-empty mcp_id at APPROVE time"
        )
        uuid.UUID(minted_mcp_id)
        assert minted_mcp_id == mcp_id_store.get_mcp_id_for_name(_SERVER)

        # ── Step 6 (checked early, independent of the live HTTP flow) ───
        # The OPA data document 010's companion fix pushes at approve time
        # (and at every gateway startup) actually resolves a grant for
        # this exact mcp_id + the gateway's calling SPIFFE + the "echo"
        # tool -- this is what makes _grant_ok satisfiable once the call
        # reaches OPA, not just _instance_identified.
        opa_doc = registry_store.build_mcp_opa_data(mcp_id_store, "default")
        assert minted_mcp_id in opa_doc["grants"], (
            "LAURA-V50-010: the live-imported server's mcp_id must have a "
            "grant entry in the OPA data document — without this, even a "
            "correctly-identified call (014 routes it there) would still "
            "deny at _grant_ok"
        )
        from yashigani.identity.trust_domain import trust_domain
        gateway_spiffe = "spiffe://%s/gateway" % trust_domain()
        assert gateway_spiffe in opa_doc["grants"][minted_mcp_id]
        assert "echo" in opa_doc["grants"][minted_mcp_id][gateway_spiffe]["tools"]
        assert minted_mcp_id in opa_doc["baselines"], (
            "LAURA-V50-010: the live-imported server's mcp_id must also "
            "have a baseline entry — without this _envelope_unchanged "
            "would deny"
        )

        # ── Step 3: gateway boots (or re-registers) against the SAME
        #    durable store the import just wrote into ──────────────────
        registry, jwks_store = _boot_gateway_after_live_import(registry_store, mcp_id_store)
        app, _ = _minimal_gateway_app(registry, jwks_store)

        # ── Step 4: fake name -> denied, never proxied upstream ─────────
        with patch("yashigani.gateway.proxy._opa_check", new=AsyncMock(return_value=True)):
            client = TestClient(app, raise_server_exceptions=False)
            fake_resp = client.post(
                "/mcp/%s" % _FAKE_SERVER,
                json={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "probe"}},
                },
            )
        assert fake_resp.status_code == 404, (
            "LAURA-V50-014 REGRESSION: a never-onboarded agent name was "
            f"not denied — got {fake_resp.status_code}: {fake_resp.text!r}"
        )
        assert fake_resp.json().get("error") == "MCP_SERVER_NOT_FOUND"

        # ── Step 5: the REAL server's tools/call reaches the four-gate ───
        from yashigani.mcp._opa import OpaDecisionResult

        allow_result = OpaDecisionResult(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None, elapsed_ms=1,
        )
        query_mock = AsyncMock(return_value=allow_result)
        with (
            patch("yashigani.gateway.proxy._opa_check", new=AsyncMock(return_value=True)),
            patch("yashigani.mcp.broker.query_mcp_decision", new=query_mock),
        ):
            client = TestClient(app, raise_server_exceptions=False)
            client.post(
                "/mcp/%s" % _SERVER,
                json={
                    "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "probe"}},
                },
            )
            # No status-code assertion: after enforce() allows, the call
            # forwards to upstream_url (deliberately unreachable in this
            # fixture) -> a transport-layer error, not a clean 200. That is
            # expected and irrelevant to what this test proves.

        assert query_mock.await_count >= 1, (
            "LAURA-V50-014 REGRESSION: the real, live-imported, granted "
            "server's tools/call never reached McpBroker.enforce() / "
            "query_mcp_decision() — intercepted before the four-gate."
        )
        _, call_kwargs = query_mock.await_args
        assert call_kwargs.get("mcp_id") == minted_mcp_id, (
            "LAURA-V50-010 REGRESSION: the four-gate query must carry the "
            "SAME approve-time-minted mcp_id, not an empty/lazily-"
            "generated/mismatched one"
        )
