"""
Regression tests — BUG-A (v4.1 Phase 0): agent leaf minting dead on arrival.

Two-part bug:

  Part 1 — pki/issuer.mint_agent_leaf() called build_leaf() with scrambled
  positional args AND a non-existent kwarg (``leaf_lifetime_days=`` instead of
  ``lifetime_days=``).  Every mint raised TypeError; no agent leaf could ever
  be issued.  Correct call per the build_leaf signature (issuer.py):
      build_leaf(service, intermediate_cert, intermediate_key, policy,
                 lifetime_days=None, *, extra_dns_sans=None, extra_ip_sans=None)

  Part 2 — backoffice approve route set svid_issued=1 via registry.approve_svid()
  BEFORE the mint, and swallowed mint failures ("best-effort").  A registry that
  claims an issued SVID with no cert on disk is fail-open.  Fixed: mint FIRST,
  approve only on mint success; mint failure → NhiSvidIssuanceFailedEvent audit
  + HTTP 502, svid_issued stays 0.

The mint tests below re-fail on the original Part-1 bug (TypeError from the
bad kwarg).  The route tests re-fail on the original Part-2 bug (svid_issued
flipped despite mint failure).
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Set

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.pki.issuer import IssuerPaths, bootstrap, mint_agent_leaf


_MANIFEST = """\
schema_version: 1
services:
  - name: gateway
    dns_sans: [gateway, gateway.internal]
    purpose: "data plane"
    mtls_capable: true
    bootstrap_token_sha256: ""
    revoked: false
cert_policy:
  root_lifetime_years_min: 5
  root_lifetime_years_max: 20
  root_lifetime_years_default: 10
  root_rotation_requires_manual_confirmation: true
  intermediate_lifetime_days_min: 90
  intermediate_lifetime_days_max: 365
  intermediate_lifetime_days_default: 180
  leaf_lifetime_days_min: 30
  leaf_lifetime_days_max: 90
  leaf_lifetime_days_default: 90
  renewal_threshold: 0.33
ca_source:
  mode: yashigani_generated
  byo: {}
  remote_acme: {}
  min_license_tier:
    yashigani_generated: community
"""


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IssuerPaths:
    # Legacy trust domain for deterministic SPIFFE URIs.
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    p = IssuerPaths(secrets_dir=tmp_path / "secrets", manifest_path=manifest)
    bootstrap(p)
    return p


# ---------------------------------------------------------------------------
# Part 1 — mint_agent_leaf produces a REAL leaf (would TypeError pre-fix)
# ---------------------------------------------------------------------------


def test_mint_agent_leaf_yields_real_ec_p256_leaf(paths: IssuerPaths) -> None:
    """mint_agent_leaf() must produce a physical EC P-256 leaf on disk,
    SPIFFE URI SAN set, signed by the internal intermediate CA."""
    spiffe_id = mint_agent_leaf(paths, "tenant1", "letta")
    assert spiffe_id == "spiffe://yashigani.internal/agents/tenant1/letta"

    cert_path = paths.agent_cert("tenant1", "letta")
    key_path = paths.agent_key("tenant1", "letta")
    assert cert_path.exists(), "agent leaf cert file must exist on disk"
    assert key_path.exists(), "agent leaf key file must exist on disk"

    # Bundle = leaf || intermediate.
    certs = x509.load_pem_x509_certificates(cert_path.read_bytes())
    assert len(certs) == 2, "cert file must bundle leaf + intermediate"
    leaf, bundled_intermediate = certs

    # EC P-256 key pair.
    pub = leaf.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert isinstance(pub.curve, ec.SECP256R1)
    priv = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    assert isinstance(priv, ec.EllipticCurvePrivateKey)
    assert priv.public_key().public_numbers() == pub.public_numbers(), (
        "on-disk private key must match the leaf cert public key"
    )

    # SPIFFE URI SAN present in the single SAN extension.
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [spiffe_id], f"leaf must carry the SPIFFE URI SAN, got {uris!r}"

    # Signed by the internal intermediate CA (issuer name + signature check).
    standalone_intermediate = x509.load_pem_x509_certificate(
        paths.intermediate_cert.read_bytes()
    )
    assert leaf.issuer == standalone_intermediate.subject
    assert (
        bundled_intermediate.serial_number == standalone_intermediate.serial_number
    )
    # Cryptographic proof: leaf signature verifies against intermediate key.
    leaf.verify_directly_issued_by(standalone_intermediate)

    # Not a CA cert.
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False

    # Runtime manifest gained the identity entry.
    runtime_text = paths.runtime_manifest.read_text()
    assert "name: agent_tenant1_letta" in runtime_text
    assert spiffe_id in runtime_text


def test_mint_agent_leaf_respects_lifetime_override(paths: IssuerPaths) -> None:
    """lifetime_days must be forwarded (the pre-fix kwarg was silently wrong);
    policy clamps to leaf_lifetime_days_min=30."""
    mint_agent_leaf(paths, "tenant1", "shortlived", leaf_lifetime_days=45)
    leaf = x509.load_pem_x509_certificates(
        paths.agent_cert("tenant1", "shortlived").read_bytes()
    )[0]
    days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days
    assert 44 <= days <= 45, f"expected ~45d lifetime, got {days}d"


# ---------------------------------------------------------------------------
# Part 2 — approve route is fail-closed on mint failure
# ---------------------------------------------------------------------------
# Minimal Redis stub (mirrors regression/v4.0/test_nhi_approve_gate.py — kept
# local: 'v4.0' is not an importable module name).


class _FakeRedis:
    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}
        self._sets: dict[str, set[bytes]] = {}

    def hset(self, key, field_or_mapping=None, value=None, mapping=None, **kwargs) -> None:
        items = {}
        if mapping is not None:
            items = mapping
        elif isinstance(field_or_mapping, dict):
            items = field_or_mapping
        elif field_or_mapping is not None and value is not None:
            items = {field_or_mapping: value}
        for k, v in items.items():
            raw_k = k if isinstance(k, bytes) else str(k).encode()
            raw_v = v if isinstance(v, bytes) else str(v).encode()
            self._store[f"{key}:{raw_k.decode()}"] = raw_v

    def hgetall(self, key: str) -> dict:
        prefix = f"{key}:"
        return {
            k[len(prefix):].encode(): v
            for k, v in self._store.items()
            if k.startswith(prefix)
        }

    def get(self, key: str):
        return self._store.get(key)

    def set(self, key: str, value) -> None:
        self._store[key] = value if isinstance(value, bytes) else str(value).encode()

    def sadd(self, key: str, *values) -> None:
        self._sets.setdefault(key, set())
        for v in values:
            self._sets[key].add(v if isinstance(v, bytes) else str(v).encode())

    def scard(self, key: str) -> int:
        return len(self._sets.get(key, set()))

    def smembers(self, key: str) -> Set[bytes]:
        return self._sets.get(key, set())

    def pipeline(self) -> "_FakePipeline":
        return _FakePipeline(self)


class _FakePipeline:
    def __init__(self, redis: _FakeRedis):
        self._r = redis
        self._cmds: list = []

    def hset(self, key, field_or_mapping=None, value=None, mapping=None, **kwargs):
        self._cmds.append(("hset", key, field_or_mapping, value, mapping))
        return self

    def set(self, key, value):
        self._cmds.append(("set", key, value))
        return self

    def sadd(self, key, *values):
        self._cmds.append(("sadd", key, values))
        return self

    def srem(self, key, *values):
        return self

    def delete(self, key):
        return self

    def execute(self):
        for cmd, *args in self._cmds:
            if cmd == "hset":
                key, field_or_mapping, value, mapping = args
                self._r.hset(key, field_or_mapping, value, mapping)
            elif cmd == "sadd":
                key, values = args
                self._r.sadd(key, *values)
            elif cmd == "set":
                key, value = args
                self._r.set(key, value)
        self._cmds.clear()
        return []


class _FakeAuditWriter:
    def __init__(self) -> None:
        self.events: list = []

    def write(self, event) -> None:
        self.events.append(event)


class _FakeStepUpSession:
    account_id = "admin__test"


def _make_registry():
    from yashigani.agents.registry import AgentRegistry
    return AgentRegistry(redis_client=_FakeRedis(), durable_store=None)


def _register_nhi(reg) -> tuple[str, str]:
    return reg.register_nhi(
        name="bug-a-agent",
        owner_identity_id="user__alice",
        template_id="tmpl_base",
        allowed_tools=["search"],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 1000, "max_tool_calls_per_run": 5},
    )


def test_approve_fail_closed_on_mint_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mint failure → 502, svid_issued stays False, NhiSvidIssuanceFailedEvent
    on the audit chain.  Pre-fix behaviour: svid_issued flipped to 1 and the
    route returned approved=True with no cert on disk (fail-open)."""
    from fastapi import HTTPException

    import yashigani.pki.issuer as issuer_mod
    from yashigani.backoffice.routes.agents import approve_nhi_svid
    from yashigani.backoffice.state import backoffice_state

    reg = _make_registry()
    nhi_id, token = _register_nhi(reg)
    aw = _FakeAuditWriter()

    monkeypatch.setattr(backoffice_state, "agent_registry", reg)
    monkeypatch.setattr(backoffice_state, "audit_writer", aw)

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated PKI issuer failure")

    monkeypatch.setattr(issuer_mod, "mint_agent_leaf", _boom)

    session: Any = _FakeStepUpSession()
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(approve_nhi_svid(nhi_id, session))

    assert excinfo.value.status_code == 502
    detail = excinfo.value.detail
    assert isinstance(detail, dict)
    assert detail["error"] == "svid_issuance_failed"

    # Fail-closed: svid_issued must remain False; NHI stays pending.
    entry = reg.get(nhi_id)
    assert entry.get("svid_issued") is False, (
        "svid_issued must NOT be set when the PKI mint fails (fail-open regression)"
    )
    assert token not in reg.get_nhi_token_map(), (
        "un-issued NHI token must not enter the gateway token-role-map"
    )

    # Audit: exactly one issuance-failed event, no approved event.
    types = [e.event_type for e in aw.events]
    assert "NHI_SVID_ISSUANCE_FAILED" in types
    assert "NHI_SVID_APPROVED" not in types
    failed = next(e for e in aw.events if e.event_type == "NHI_SVID_ISSUANCE_FAILED")
    assert failed.nhi_id == nhi_id
    assert failed.approver_account == "admin__test"
    assert failed.error_type == "RuntimeError"


def test_approve_mints_before_setting_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Success path: mint runs BEFORE approve_svid; svid_issued=True only after
    a successful mint; NhiSvidApprovedEvent emitted."""
    import yashigani.pki.issuer as issuer_mod
    from yashigani.backoffice.routes.agents import approve_nhi_svid
    from yashigani.backoffice.state import backoffice_state

    reg = _make_registry()
    nhi_id, token = _register_nhi(reg)
    aw = _FakeAuditWriter()

    monkeypatch.setattr(backoffice_state, "agent_registry", reg)
    monkeypatch.setattr(backoffice_state, "audit_writer", aw)

    call_order: list[str] = []

    def _fake_mint(*args, **kwargs):
        # Ordering proof: at mint time the flag must still be unset.
        assert reg.get(nhi_id).get("svid_issued") is False, (
            "svid_issued was set BEFORE the mint — approve-before-mint regression"
        )
        call_order.append("mint")
        return "spiffe://yashigani.internal/agents/user__alice/bug-a-agent"

    monkeypatch.setattr(issuer_mod, "mint_agent_leaf", _fake_mint)

    session: Any = _FakeStepUpSession()
    result = asyncio.run(approve_nhi_svid(nhi_id, session))

    assert call_order == ["mint"]
    assert result["approved"] is True
    assert result["spiffe_id"].endswith("/agents/user__alice/bug-a-agent")
    assert reg.get(nhi_id).get("svid_issued") is True
    assert token in reg.get_nhi_token_map()
    assert "NHI_SVID_APPROVED" in [e.event_type for e in aw.events]
