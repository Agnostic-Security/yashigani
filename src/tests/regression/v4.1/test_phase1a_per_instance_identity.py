"""
Regression tests — v4.1 Phase 1a: per-instance agent/MCP leaf identity +
change-prevention binding (Nico GAP-1 / GAP-2 / GAP-4 + DNS-SAN hygiene).

GAP-1  Two same-named instances previously COLLIDED: identical SPIFFE URI
       (trust_domain.agent_spiffe_uri keyed on tenant+name) and identical
       cert/key file paths (IssuerPaths.agent_cert/agent_key) — the second
       mint silently overwrote the first instance's identity.  Fixed: the
       registry ``nhi_id`` becomes an instance segment in BOTH.

GAP-2  The leaf carried no cryptographic binding to WHAT was approved.  Fixed:
       a NON-critical custom extension (pki/binding.BINDING_EXTENSION_OID)
       carries sha384(image_digest ‖ 0x00 ‖ scope_hash).

       Phase 1b-i amendment (Captain, 2026-07-05): the extension was flipped
       CRITICAL → NON-critical.  Go crypto/x509 (Caddy ``require_and_verify``)
       rejects any leaf carrying an unrecognised CRITICAL extension (RFC 5280
       §4.2), which would make every Go-based mesh verifier refuse the
       per-instance leaf.  Change-prevention is enforced at the OPA input
       layer, not TLS path validation — Nico's Phase 1a handoff note called
       out exactly this consumer constraint.  The criticality assertion below
       is updated accordingly and is load-bearing in the OPPOSITE direction:
       a regression back to critical=True bricks the Caddy front.

GAP-4  Deactivate left the runtime-manifest entry ``revoked: false`` and the
       NHI in ``nhi:index:active`` (token stayed in the gateway token map).

DNS-SAN hygiene: agent leaves are SPIFFE-URI-identified — the synthetic
``DNSName(service.name)`` fallback is dropped; localhost + loopback retained
for the Phase 2 Caddy-front loopback bind / in-container healthchecks.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any, Set

import pytest

from cryptography import x509

from yashigani.pki.binding import (
    BINDING_EXTENSION_OID,
    binding_digest,
    encode_binding_extension_value,
    parse_binding_extension,
    tool_surface_hash,
)
from yashigani.pki.issuer import (
    IssuerPaths,
    bootstrap,
    mint_agent_leaf,
    revoke_agent_identity,
)


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

_SCOPE = tool_surface_hash(["search", "fetch"])
_IMAGE = "sha256:" + "ab" * 32


@pytest.fixture
def paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> IssuerPaths:
    monkeypatch.delenv("YASHIGANI_SPIFFE_TRUST_DOMAIN", raising=False)
    manifest = tmp_path / "service_identities.yaml"
    manifest.write_text(_MANIFEST)
    p = IssuerPaths(secrets_dir=tmp_path / "secrets", manifest_path=manifest)
    bootstrap(p)
    return p


def _leaf(paths: IssuerPaths, tenant: str, name: str, instance: str) -> x509.Certificate:
    return x509.load_pem_x509_certificates(
        paths.agent_cert(tenant, name, instance).read_bytes()
    )[0]


# ---------------------------------------------------------------------------
# GAP-1 — per-instance identity: no collide/overwrite
# ---------------------------------------------------------------------------


def test_two_same_named_instances_distinct_identities(paths: IssuerPaths) -> None:
    """Verify criterion (a): two same-named instances → distinct SPIFFE URIs
    AND distinct cert/key files; neither mint overwrites the other."""
    id_a, id_b = "nhi_aaaaaaaaaaaa", "nhi_bbbbbbbbbbbb"
    spiffe_a = mint_agent_leaf(
        paths, "tenant1", "cloud9", instance_id=id_a, scope_hash=_SCOPE
    )
    spiffe_b = mint_agent_leaf(
        paths, "tenant1", "cloud9", instance_id=id_b, scope_hash=_SCOPE
    )

    assert spiffe_a != spiffe_b
    assert spiffe_a == f"spiffe://yashigani.internal/agents/tenant1/cloud9/{id_a}"
    assert spiffe_b == f"spiffe://yashigani.internal/agents/tenant1/cloud9/{id_b}"

    cert_a = paths.agent_cert("tenant1", "cloud9", id_a)
    cert_b = paths.agent_cert("tenant1", "cloud9", id_b)
    key_a = paths.agent_key("tenant1", "cloud9", id_a)
    key_b = paths.agent_key("tenant1", "cloud9", id_b)
    assert cert_a != cert_b and key_a != key_b
    for f in (cert_a, cert_b, key_a, key_b):
        assert f.exists(), f"{f} must exist — instances must not overwrite"

    leaf_a, leaf_b = _leaf(paths, "tenant1", "cloud9", id_a), _leaf(paths, "tenant1", "cloud9", id_b)
    assert leaf_a.serial_number != leaf_b.serial_number
    san_a = leaf_a.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    san_b = leaf_b.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san_a.get_values_for_type(x509.UniformResourceIdentifier) == [spiffe_a]
    assert san_b.get_values_for_type(x509.UniformResourceIdentifier) == [spiffe_b]

    # Both instance identities land in the runtime manifest, distinctly named.
    runtime = paths.runtime_manifest.read_text()
    assert f"name: agent_tenant1_cloud9_{id_a}" in runtime
    assert f"name: agent_tenant1_cloud9_{id_b}" in runtime


def test_uri_shape_is_round_trippable() -> None:
    from yashigani.identity.trust_domain import agent_spiffe_uri, parse_agent_spiffe_uri

    uri = agent_spiffe_uri("t1", "goose", "nhi_0123456789ab")
    assert parse_agent_spiffe_uri(uri) == ("t1", "goose", "nhi_0123456789ab")
    # Legacy 2-segment URIs stay byte-for-byte stable and parse with "".
    legacy = agent_spiffe_uri("t1", "goose")
    assert legacy == "spiffe://yashigani.internal/agents/t1/goose"
    assert parse_agent_spiffe_uri(legacy) == ("t1", "goose", "")
    # Foreign namespace → None (reject-foreign stays exact).
    assert parse_agent_spiffe_uri("spiffe://evil.example/agents/t1/goose") is None


def test_legacy_mint_without_instance_unchanged(paths: IssuerPaths) -> None:
    """No instance_id / no scope_hash (CLI path) — legacy URI, legacy file
    names, and NO binding extension (a binding over empty inputs would be a
    false 'nothing approved' attestation)."""
    spiffe = mint_agent_leaf(paths, "tenant1", "letta")
    assert spiffe == "spiffe://yashigani.internal/agents/tenant1/letta"
    assert paths.agent_cert("tenant1", "letta").name == "agent_tenant1_letta_client.crt"
    leaf = _leaf(paths, "tenant1", "letta", "")
    assert parse_binding_extension(leaf) is None


# ---------------------------------------------------------------------------
# GAP-2 — change-prevention binding extension
# ---------------------------------------------------------------------------


def test_binding_extension_present_noncritical_and_correct(paths: IssuerPaths) -> None:
    """Verify criterion (b): extension present, NON-critical, value equal to
    sha384(image_digest ‖ 0x00 ‖ scope_hash) in the documented encoding.

    Phase 1b-i: non-criticality is LOAD-BEARING — Go crypto/x509 (Caddy
    require_and_verify) rejects leaves with unrecognised CRITICAL extensions;
    a critical binding extension bricks the entire Caddy-front architecture.
    """
    mint_agent_leaf(
        paths, "tenant1", "cloud9",
        instance_id="nhi_cccccccccccc", scope_hash=_SCOPE, image_digest=_IMAGE,
    )
    leaf = _leaf(paths, "tenant1", "cloud9", "nhi_cccccccccccc")

    ext = leaf.extensions.get_extension_for_oid(BINDING_EXTENSION_OID)
    assert ext.critical is False, (
        "change-prevention extension MUST be NON-critical — Go crypto/x509 "
        "(Caddy require_and_verify) rejects unrecognised critical extensions "
        "(RFC 5280 §4.2); enforcement is at the OPA input layer"
    )

    # Independent recomputation — do not trust binding.py's own digest helper.
    expected = "sha384:" + hashlib.sha384(
        _IMAGE.encode() + b"\x00" + _SCOPE.encode()
    ).hexdigest()
    assert isinstance(ext.value, x509.UnrecognizedExtension)
    assert ext.value.value == expected.encode("ascii")
    assert binding_digest(_IMAGE, _SCOPE) == expected
    assert parse_binding_extension(leaf) == expected

    # A modified tool surface or swapped image breaks the binding.
    assert binding_digest(_IMAGE, tool_surface_hash(["search", "fetch", "exec"])) != expected
    assert binding_digest("sha256:" + "cd" * 32, _SCOPE) != expected


def test_binding_unpinned_image_recorded_honestly(paths: IssuerPaths) -> None:
    """image_digest="" (not yet pinned) still binds the tool surface; the
    digest is over ("" ‖ 0x00 ‖ scope_hash), never skipped or faked."""
    mint_agent_leaf(
        paths, "tenant1", "cloud9", instance_id="nhi_dddddddddddd", scope_hash=_SCOPE,
    )
    leaf = _leaf(paths, "tenant1", "cloud9", "nhi_dddddddddddd")
    expected = "sha384:" + hashlib.sha384(b"\x00" + _SCOPE.encode()).hexdigest()
    assert parse_binding_extension(leaf) == expected


def test_oid_arcs_go_parseable_and_uuid_derived() -> None:
    """Phase 1b-i: every arc of the binding-extension OID MUST fit in an
    int32.  Go crypto/x509 (Caddy require_and_verify, gateway mesh listeners)
    rejects the ENTIRE certificate when any extension OID arc exceeds 2^31-1
    — empirically proven (arc 2^31-1 accepted, 2^32-1 → decode_error abort;
    the original X.667 single-UUID arc ~2^127 → same abort).  Also pins the
    derivation: eight 16-bit chunks of the provenance UUID."""
    import uuid as _uuid

    from yashigani.pki.binding import (
        YASHIGANI_ARC_PROVENANCE_UUID,
        YASHIGANI_PRIVATE_ARC,
        BINDING_EXTENSION_OID_DOTTED,
    )

    arcs = [int(a) for a in BINDING_EXTENSION_OID_DOTTED.split(".")]
    assert all(a <= 2**31 - 1 for a in arcs), (
        "binding-extension OID arc exceeds int32 — Go crypto/x509 will "
        "reject every per-instance leaf at TLS handshake (Phase 1b-i proof)"
    )
    # Derivation pin: last eight arcs of the private arc are the provenance
    # UUID split into big-endian 16-bit chunks.
    u = _uuid.UUID(YASHIGANI_ARC_PROVENANCE_UUID).bytes
    expected_chunks = [
        int.from_bytes(u[i:i + 2], "big") for i in range(0, 16, 2)
    ]
    assert YASHIGANI_PRIVATE_ARC.split(".")[-8:] == [str(c) for c in expected_chunks]
    assert BINDING_EXTENSION_OID_DOTTED == YASHIGANI_PRIVATE_ARC + ".1"


def test_tool_surface_hash_matches_r3_inline_encoding() -> None:
    """binding.tool_surface_hash must stay byte-identical to the original R3
    inline computation in user_agents.py (audit-chain continuity)."""
    tools = ["zeta", "alpha", "alpha"]  # unsorted, dup — canonicalisation check
    inline = "sha384:" + hashlib.sha384(
        json.dumps({"allowed_tools": sorted(tools)}, sort_keys=True).encode("utf-8")
    ).hexdigest()
    assert tool_surface_hash(tools) == inline


def test_encode_parse_rejects_garbage() -> None:
    assert encode_binding_extension_value("", _SCOPE).startswith(b"sha384:")
    # parse_binding_extension fail-closes on malformed values (tampering evidence).
    from cryptography.hazmat.primitives import hashes as _h
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    import datetime as _dt
    k = _ec.generate_private_key(_ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "t")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(k.public_key()).serial_number(1)
        .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=1))
        .add_extension(
            x509.UnrecognizedExtension(BINDING_EXTENSION_OID, b"sha384:nothex"),
            critical=False,  # matches the shipping contract (non-critical)
        )
        .sign(k, _h.SHA256())
    )
    with pytest.raises(ValueError):
        parse_binding_extension(cert)


# ---------------------------------------------------------------------------
# DNS-SAN hygiene — agent leaves are SPIFFE-URI-identified
# ---------------------------------------------------------------------------


def test_agent_leaf_dns_san_surface_minimal(paths: IssuerPaths) -> None:
    """Agent leaves: NO synthetic service-name DNS SAN; keep exactly
    localhost + 127.0.0.1 + ::1 (Caddy-front loopback bind / healthchecks)."""
    mint_agent_leaf(
        paths, "tenant1", "cloud9", instance_id="nhi_eeeeeeeeeeee", scope_hash=_SCOPE,
    )
    leaf = _leaf(paths, "tenant1", "cloud9", "nhi_eeeeeeeeeeee")
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    assert dns == ["localhost"], f"agent leaf DNS SANs must be exactly ['localhost'], got {dns}"
    assert set(ips) == {"127.0.0.1", "::1"}
    assert not any(d.startswith("agent_") for d in dns)


def test_service_leaves_keep_dns_sans(paths: IssuerPaths) -> None:
    """Regular mesh service leaves (gateway etc.) are hostname-verified —
    their DNS SANs are unchanged by the hygiene fix."""
    gw = x509.load_pem_x509_certificates(paths.leaf_cert("gateway").read_bytes())[0]
    san = gw.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    assert "gateway" in dns and "gateway.internal" in dns and "localhost" in dns


# ---------------------------------------------------------------------------
# GAP-4 — revocation wired to deactivate
# ---------------------------------------------------------------------------


def test_revoke_flips_only_target_instance(paths: IssuerPaths) -> None:
    id_a, id_b = "nhi_aaaaaaaaaaaa", "nhi_bbbbbbbbbbbb"
    mint_agent_leaf(paths, "t1", "dup", instance_id=id_a, scope_hash=_SCOPE)
    mint_agent_leaf(paths, "t1", "dup", instance_id=id_b, scope_hash=_SCOPE)

    assert revoke_agent_identity(paths, "t1", "dup", instance_id=id_a) is True
    text = paths.runtime_manifest.read_text()

    def _entry_block(nid: str) -> str:
        start = text.index(f"- name: agent_t1_dup_{nid}")
        nxt = text.find("- name:", start + 1)
        return text[start: nxt if nxt != -1 else len(text)]

    assert "revoked: true" in _entry_block(id_a)
    assert "revoked: false" in _entry_block(id_b), "sibling instance must stay valid"

    # Idempotent-ish: already-revoked → False, unknown entry → False, no crash.
    assert revoke_agent_identity(paths, "t1", "dup", instance_id=id_a) is False
    assert revoke_agent_identity(paths, "t1", "ghost", instance_id="nhi_000000000000") is False


def test_revoke_missing_manifest_never_raises(tmp_path: Path) -> None:
    p = IssuerPaths(secrets_dir=tmp_path / "nowhere", manifest_path=tmp_path / "m.yaml")
    assert revoke_agent_identity(p, "t", "n", instance_id="nhi_000000000000") is False


# ---------------------------------------------------------------------------
# Registry + route threading (fake-redis, mirrors BUG-A harness)
# ---------------------------------------------------------------------------


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

    def srem(self, key: str, *values) -> None:
        for v in values:
            self._sets.get(key, set()).discard(
                v if isinstance(v, bytes) else str(v).encode()
            )

    def delete(self, *keys) -> int:
        """FIND-0813-013: AgentRegistry.deactivate() now calls self._r.delete()
        directly (not only via a pipeline) to revoke agent:token:{id} /
        agent:token:grace:{id}. Mirrors real redis-py's DEL semantics closely
        enough for these tests: removes each key from the flat string store,
        returns the count actually removed."""
        removed = 0
        for k in keys:
            if k in self._store:
                del self._store[k]
                removed += 1
        return removed

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
        self._cmds.append(("srem", key, values))
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
            elif cmd == "srem":
                key, values = args
                self._r.srem(key, *values)
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


def _register_nhi(reg, scope_hash: str = ""):
    return reg.register_nhi(
        name="dup-agent",
        owner_identity_id="user__alice",
        template_id="tmpl_base",
        allowed_tools=["search", "fetch"],
        allowed_paths=["/v1/chat/completions"],
        allowed_models=["gpt-4o-mini"],
        sensitivity_ceiling="INTERNAL",
        budget_cap={"max_tokens_per_run": 1000, "max_tool_calls_per_run": 5},
        scope_hash=scope_hash,
    )


def test_registry_stores_scope_hash() -> None:
    reg = _make_registry()
    nhi_id, _ = _register_nhi(reg, scope_hash=_SCOPE)
    assert reg.get(nhi_id)["scope_hash"] == _SCOPE


def test_deactivate_clears_nhi_active_index_and_token_map() -> None:
    """GAP-4 adjacency: a deactivated NHI must drop out of nhi:index:active —
    otherwise its token stays live in the gateway token-role-map."""
    reg = _make_registry()
    nhi_id, token = _register_nhi(reg, scope_hash=_SCOPE)
    reg.approve_svid(nhi_id)
    assert token in reg.get_nhi_token_map()
    reg.deactivate(nhi_id)
    assert token not in reg.get_nhi_token_map(), (
        "deactivated NHI token must leave the gateway token map immediately"
    )
    # FIND-0813-013 (Nico, 2026-08-13): deactivate() must also revoke the
    # agent:token:{id} bcrypt-hash key it now deletes (the fix that closed
    # "deactivate() doesn't actually revoke" for the PSK-authenticated
    # /agents/* path). NHIs mint under nhi_id, not agnt_id, so no such key
    # was ever written here -- this asserts the delete is a correct
    # (harmless) no-op for NHIs, not that it silently swallowed an error.
    assert reg._r.get(f"agent:token:{nhi_id}") is None


def test_approve_threads_instance_id_and_binding_into_mint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The approve route must pass nhi_id as instance_id and the stored
    scope_hash (+ image_digest) into mint_agent_leaf (GAP-1 + GAP-2)."""
    import yashigani.pki.issuer as issuer_mod
    from yashigani.backoffice.routes.agents import approve_nhi_svid
    from yashigani.backoffice.state import backoffice_state

    reg = _make_registry()
    nhi_id, _tok = _register_nhi(reg, scope_hash=_SCOPE)
    monkeypatch.setattr(backoffice_state, "agent_registry", reg)
    monkeypatch.setattr(backoffice_state, "audit_writer", _FakeAuditWriter())

    captured: dict[str, Any] = {}

    def _fake_mint(paths, tenant_id, agent_name, **kwargs):
        captured.update(kwargs, tenant_id=tenant_id, agent_name=agent_name)
        from yashigani.identity.trust_domain import agent_spiffe_uri
        return agent_spiffe_uri(tenant_id, agent_name, kwargs.get("instance_id", ""))

    monkeypatch.setattr(issuer_mod, "mint_agent_leaf", _fake_mint)

    session: Any = _FakeStepUpSession()
    result = asyncio.run(approve_nhi_svid(nhi_id, session))

    assert captured["instance_id"] == nhi_id, "nhi_id must become the instance segment"
    assert captured["scope_hash"] == _SCOPE, "stored scope_hash must reach the mint"
    assert captured["image_digest"] == ""  # unpinned at approve — recorded honestly
    assert result["spiffe_id"].endswith(f"/agents/user__alice/dup-agent/{nhi_id}")
    # Persisted back: the registry entry carries the per-instance SPIFFE ID.
    assert reg.get(nhi_id)["spiffe_id"] == result["spiffe_id"]


def test_approve_recomputes_scope_hash_for_legacy_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Entries registered before the scope_hash field existed: approve must
    recompute the SAME canonical hash from the registry's allowed_tools."""
    import yashigani.pki.issuer as issuer_mod
    from yashigani.backoffice.routes.agents import approve_nhi_svid
    from yashigani.backoffice.state import backoffice_state

    reg = _make_registry()
    nhi_id, _tok = _register_nhi(reg, scope_hash="")  # pre-field entry
    monkeypatch.setattr(backoffice_state, "agent_registry", reg)
    monkeypatch.setattr(backoffice_state, "audit_writer", _FakeAuditWriter())

    captured: dict[str, Any] = {}

    def _fake_mint(paths, tenant_id, agent_name, **kwargs):
        captured.update(kwargs)
        return "spiffe://yashigani.internal/agents/user__alice/dup-agent/" + nhi_id

    monkeypatch.setattr(issuer_mod, "mint_agent_leaf", _fake_mint)
    asyncio.run(approve_nhi_svid(nhi_id, _FakeStepUpSession()))
    assert captured["scope_hash"] == tool_surface_hash(["search", "fetch"])


def test_deactivate_route_revokes_nhi_manifest_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GAP-4: DELETE /admin/agents/{nhi_id} on an NHI calls
    revoke_agent_identity with the per-instance coordinates."""
    import yashigani.backoffice.routes.agents as agents_mod
    from yashigani.backoffice.state import backoffice_state

    reg = _make_registry()
    nhi_id, _tok = _register_nhi(reg, scope_hash=_SCOPE)
    reg.approve_svid(nhi_id)
    monkeypatch.setattr(backoffice_state, "agent_registry", reg)
    monkeypatch.setattr(backoffice_state, "audit_writer", _FakeAuditWriter())
    monkeypatch.setattr(agents_mod, "_push_opa", lambda: None)

    captured: dict[str, Any] = {}

    def _fake_revoke(paths, tenant_id, agent_name, instance_id=""):
        captured.update(tenant_id=tenant_id, agent_name=agent_name, instance_id=instance_id)
        return True

    import yashigani.pki.issuer as issuer_mod
    monkeypatch.setattr(issuer_mod, "revoke_agent_identity", _fake_revoke)

    asyncio.run(agents_mod.deactivate_agent(nhi_id, _FakeStepUpSession(), None))

    assert captured == {
        "tenant_id": "user__alice",
        "agent_name": "dup-agent",
        "instance_id": nhi_id,
    }
    assert reg.get(nhi_id)["status"] == "inactive"
    # FIND-0813-013: the admin deactivate ROUTE must reach AgentRegistry
    # .deactivate()'s token-revocation path too, not just the PKI revoke call
    # this test primarily targets -- prove the full call chain, not a mock.
    assert reg._r.get(f"agent:token:{nhi_id}") is None
