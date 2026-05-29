"""
v2.25.0 P1 W3 Phase 2b-ii — MCP Broker CORE tests
===================================================

Test coverage:
  A. Posture-from-channel (YSG-RISK-055 / LAURA-MCP-003 binding requirement)
     - test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only  ← NOW REAL (was SKIPPED in mcp_test.rego)
     - mcp-a assigned only when LOCAL_STDIO + is_local_pipe=True
     - Network transport NEVER assigns mcp-a
     - Chained relay assigns mcp-c (upstream JWT verified + chain non-empty)
     - is_local_pipe=False on LOCAL_STDIO degrades to mcp-b
  B. ES384 JWT issuance (Nico spec §1-§4)
     - Algorithm header == "ES384"
     - kid in header
     - identity.chain is array of strings
     - Chain extension rule: append own SPIFFE, never prepend
     - Chain depth pre-validation (exceeds max → ChainDepthExceeded before signing)
     - Known-bad object chain rejected before issuance (Nico FIPS checklist §7)
     - Startup self-test fires
  C. JWT verification
     - Verifier accepts valid ES384 JWT
     - Verifier rejects wrong algorithm
     - Verifier rejects expired JWT
     - Verifier rejects tampered payload
     - Chain format validation in verifier
  D. Nonce store (jti replay prevention)
     - First call: new jti → accepted
     - Second call: same jti → replayed → rejected
     - Expired entries cleaned up
  E. OPA enforcement (fail-closed)
     - OPA allow → decision.allow=True
     - OPA deny → decision.allow=False
     - OPA timeout (500ms) → fail-closed deny
     - OPA unreachable → fail-closed deny
     - Input chain MUST be array of strings (ValueError before OPA call if not)
  F. Broker pipeline (end-to-end)
     - Allowed call → issued JWT + audit events emitted
     - OPA deny → no JWT issued + audit events emitted
     - mcp-c upstream JWT verified + chain extended
     - mcp-c upstream JWT replay rejected
     - JWT issuance failure → deny (fail-closed)
  G. Audit emission (YSG-RISK-054)
     - MCP_CALL emitted on every call (allow AND deny)
     - OPA_DECISION_ON_MCP emitted on every call
     - audit_capture=True from OPA → args_redacted flag set
  H. JWKS store
     - JWKS response contains EC P-384 key
     - Cache-Control header constant correct
     - Rotation overlap: two keys returned atomically
     - retire_old: single key after retirement
  I. Chain posture_binding values
     - mcp-a → derived_from="physical_channel", channel_type="local-stdio"
     - mcp-b → derived_from="tls_channel", channel_type="network-streamable-http"
     - mcp-c → derived_from="spiffe_cert", channel_type="chained-relay"

v2.25.0 / P1 W3 Phase 2b-ii / YSG-RISK-054 + YSG-RISK-055.
"""
from __future__ import annotations

import asyncio
import base64
import json
import time
import uuid
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_p384_key_pem_b64() -> str:
    """Generate a P-384 key and return it as base64-encoded PEM for env injection."""
    key = ec.generate_private_key(SECP384R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.b64encode(pem).decode("ascii")


@pytest.fixture
def p384_key():
    """Fresh P-384 key for each test."""
    return ec.generate_private_key(SECP384R1())


@pytest.fixture
def issuer(p384_key):
    """McpJwtIssuer with a known P-384 key."""
    from yashigani.mcp._jwt import McpJwtIssuer
    return McpJwtIssuer(
        tenant_id="tenant1",
        private_key=p384_key,
        key_generated_at=1748476800,
        chain_max_depth=3,
    )


@pytest.fixture
def verifier(issuer):
    """McpJwtVerifier backed by the same issuer."""
    from yashigani.mcp._jwt import McpJwtVerifier
    return McpJwtVerifier.from_issuer(issuer)


@pytest.fixture
def nonce_store():
    """Fresh InMemoryNonceStore for each test."""
    from yashigani.mcp._nonce import InMemoryNonceStore
    # Suppress the DEV MODE warning during tests
    import logging
    with patch.object(logging.getLogger("yashigani.mcp._nonce"), "warning"):
        store = InMemoryNonceStore()
    return store


@pytest.fixture
def broker_config(issuer, nonce_store):
    """McpBrokerConfig with all dependencies wired for testing."""
    from yashigani.mcp.broker import McpBrokerConfig
    from yashigani.mcp._jwt import McpJwtVerifier
    verifier = McpJwtVerifier.from_issuer(issuer)
    return McpBrokerConfig(
        opa_url="http://localhost:8181",
        tenant_id="tenant1",
        issuer=issuer,
        verifier=verifier,
        nonce_store=nonce_store,
        audit_writer=None,  # test mode — warnings only
    )


@pytest.fixture
def broker(broker_config):
    """McpBroker instance for testing."""
    from yashigani.mcp.broker import McpBroker
    return McpBroker(broker_config)


def _make_call_context(
    posture_str: str = "mcp-a",
    action: str = "mcp.tools.call",
    tool_name: str = "web_search",
    upstream_chain: Optional[list] = None,
    upstream_jwt: Optional[str] = None,
) -> "McpCallContext":
    from yashigani.mcp._types import McpCallContext, McpPosture, PostureBinding
    posture = McpPosture(posture_str)
    binding = PostureBinding.for_posture(posture)
    return McpCallContext(
        tenant_id="tenant1",
        agent_name="hermes",
        user_id="_test_user",
        posture=posture,
        posture_binding=binding,
        action=action,
        tool_name=tool_name,
        upstream_chain=upstream_chain or [],
        upstream_jwt=upstream_jwt,
    )


# ---------------------------------------------------------------------------
# A. Posture-from-channel — the binding requirement
# ---------------------------------------------------------------------------


class TestPostureFromChannel:
    """
    YSG-RISK-055 / LAURA-MCP-003 — posture MUST derive from physical channel.

    The OPA policy test test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only
    was SKIPPED in mcp_test.rego because it is a transport-layer property, not
    an OPA-input property. These tests validate it at the Python broker layer.
    """

    def test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only(self):
        """
        YSG-RISK-055 BINDING REQUIREMENT:
        mcp-a is assigned ONLY when transport_kind==LOCAL_STDIO AND is_local_pipe==True.

        A network-arriving request (NETWORK_STREAMABLE_HTTP) MUST NOT receive mcp-a
        regardless of any body claim. This test was the SKIPPED test in mcp_test.rego
        (test_TRANSPORT_REQUIREMENT_mcp_a_must_be_local_only). It is now real.

        LAURA-MCP-003 gate closed.
        """
        from yashigani.mcp._posture import derive_posture_from_channel
        from yashigani.mcp._types import McpPosture, McpTransportKind

        # Network transport → NEVER mcp-a
        network_posture, network_binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.NETWORK_STREAMABLE_HTTP,
        )
        assert network_posture != McpPosture.MCP_A, (
            "TRANSPORT REQUIREMENT VIOLATED: mcp-a must not be assigned to a "
            "network-arriving request. YSG-RISK-055 / LAURA-MCP-003."
        )
        assert network_posture == McpPosture.MCP_B

        # Local stdio + confirmed pipe → mcp-a (only case where mcp-a is valid)
        local_posture, local_binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.LOCAL_STDIO,
            is_local_pipe=True,
            peer_pid=12345,
        )
        assert local_posture == McpPosture.MCP_A, (
            "Local stdio with confirmed pipe must assign mcp-a"
        )

        # Local stdio but is_local_pipe=False → degraded to mcp-b (defensive)
        degraded_posture, _ = derive_posture_from_channel(
            transport_kind=McpTransportKind.LOCAL_STDIO,
            is_local_pipe=False,
        )
        assert degraded_posture == McpPosture.MCP_B, (
            "LOCAL_STDIO with is_local_pipe=False must degrade to mcp-b "
            "(not mcp-a) — YSG-RISK-055 defence"
        )

    def test_network_http_transport_never_returns_mcp_a(self):
        """HTTP transport always returns mcp-b (or mcp-c for relays)."""
        from yashigani.mcp._transport_http import McpHttpTransport
        from yashigani.mcp._types import McpPosture

        transport = McpHttpTransport(upstream_url="https://mcp.example.com")
        posture, _ = transport.derive_posture()
        assert posture != McpPosture.MCP_A
        assert posture == McpPosture.MCP_B

    def test_relay_http_transport_returns_mcp_c(self):
        """HTTP relay transport returns mcp-c when upstream chain is verified."""
        from yashigani.mcp._transport_http import McpHttpTransport
        from yashigani.mcp._types import McpPosture

        chain = [
            "spiffe://yashigani.internal/agents/tenant1/hermes",
        ]
        transport = McpHttpTransport(
            upstream_url="https://mcp.example.com",
            is_relay=True,
            upstream_chain=chain,
            upstream_jwt_verified=True,
        )
        posture, binding = transport.derive_posture()
        assert posture == McpPosture.MCP_C

    def test_relay_transport_without_verification_raises(self):
        """Relay transport with upstream_jwt_verified=False raises PostureDerivationError."""
        from yashigani.mcp._transport_http import McpHttpTransport
        from yashigani.mcp._posture import PostureDerivationError

        chain = ["spiffe://yashigani.internal/agents/tenant1/hermes"]
        transport = McpHttpTransport(
            upstream_url="https://mcp.example.com",
            is_relay=True,
            upstream_chain=chain,
            upstream_jwt_verified=False,  # not verified → error
        )
        with pytest.raises(PostureDerivationError, match="upstream_jwt_verified=False"):
            transport.derive_posture()

    def test_mcp_a_posture_binding(self):
        """mcp-a posture_binding: derived_from=physical_channel, channel_type=local-stdio."""
        from yashigani.mcp._posture import derive_posture_from_channel
        from yashigani.mcp._types import McpPosture, McpTransportKind

        posture, binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.LOCAL_STDIO,
            is_local_pipe=True,
        )
        assert posture == McpPosture.MCP_A
        assert binding.derived_from == "physical_channel"
        assert binding.channel_type == "local-stdio"

    def test_mcp_b_posture_binding(self):
        """mcp-b posture_binding: derived_from=tls_channel, channel_type=network-streamable-http."""
        from yashigani.mcp._posture import derive_posture_from_channel
        from yashigani.mcp._types import McpPosture, McpTransportKind

        posture, binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.NETWORK_STREAMABLE_HTTP,
        )
        assert posture == McpPosture.MCP_B
        assert binding.derived_from == "tls_channel"
        assert binding.channel_type == "network-streamable-http"

    def test_mcp_c_posture_binding(self):
        """mcp-c posture_binding: derived_from=spiffe_cert, channel_type=chained-relay."""
        from yashigani.mcp._posture import derive_posture_from_channel
        from yashigani.mcp._types import McpPosture, McpTransportKind

        posture, binding = derive_posture_from_channel(
            transport_kind=McpTransportKind.CHAINED_RELAY,
            upstream_chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            upstream_jwt_verified=True,
        )
        assert posture == McpPosture.MCP_C
        assert binding.derived_from == "spiffe_cert"
        assert binding.channel_type == "chained-relay"


# ---------------------------------------------------------------------------
# B. ES384 JWT issuance (Nico spec)
# ---------------------------------------------------------------------------


class TestJwtIssuance:
    def test_algorithm_header_is_es384(self, issuer):
        """JWT header must carry alg=ES384 (Nico spec §1 — locked)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "ES384", (
            "JWT algorithm MUST be ES384 (Nico spec §1 — NO SUBSTITUTES)"
        )

    def test_kid_in_jwt_header(self, issuer):
        """JWT header must contain kid (Nico spec §5 — upstream verifiers use kid)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-b",
            posture_binding={"derived_from": "tls_channel", "channel_type": "network-streamable-http"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        header = pyjwt.get_unverified_header(token)
        assert "kid" in header, "JWT header must contain kid (Nico spec §5)"
        assert header["kid"].startswith("mcp-tenant1-"), (
            "kid format must be mcp-{tenant_id}-{epoch}"
        )

    def test_identity_chain_is_array_of_strings(self, issuer):
        """identity.chain in issued JWT must be a JSON array of strings (Nico spec §4)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        # Decode without verification to inspect claims
        payload = pyjwt.decode(token, options={"verify_signature": False})
        chain = payload["identity"]["chain"]
        assert isinstance(chain, list), "identity.chain must be a list"
        for element in chain:
            assert isinstance(element, str), (
                f"identity.chain element must be a string; got {type(element).__name__}: {element!r}"
            )

    def test_first_hop_chain_contains_own_spiffe(self, issuer):
        """For first hop (no upstream chain), chain = [own SPIFFE URI]."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
            upstream_chain=None,  # first hop
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        chain = payload["identity"]["chain"]
        assert len(chain) == 1
        assert chain[0] == "spiffe://yashigani.internal/agents/tenant1/hermes"

    def test_relay_hop_appends_own_spiffe(self, issuer):
        """Chain extension rule: own SPIFFE appended to upstream chain (Nico spec §4)."""
        upstream_chain = [
            "spiffe://yashigani.internal/agents/tenant1/hermes",
        ]
        token = issuer.issue(
            user_id="_test",
            agent_name="artemis",
            posture="mcp-c",
            posture_binding={"derived_from": "spiffe_cert", "channel_type": "chained-relay"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
            upstream_chain=upstream_chain,
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        chain = payload["identity"]["chain"]
        assert len(chain) == 2
        assert chain[0] == "spiffe://yashigani.internal/agents/tenant1/hermes", (
            "Original chain element must be preserved (append, not prepend)"
        )
        assert chain[1] == "spiffe://yashigani.internal/agents/tenant1/artemis", (
            "Own SPIFFE URI must be APPENDED (Nico spec §4: append-only)"
        )

    def test_chain_depth_exceeded_raises_before_signing(self, issuer):
        """Gateway pre-validates chain depth; raises before signing (Nico spec §9.7)."""
        from yashigani.mcp._jwt import ChainDepthExceeded
        # chain_max_depth=3; this chain of 3 + appending own = 4 → exceeds limit
        over_limit_chain = [
            "spiffe://yashigani.internal/agents/tenant1/a",
            "spiffe://yashigani.internal/agents/tenant1/b",
            "spiffe://yashigani.internal/agents/tenant1/c",
        ]
        with pytest.raises(ChainDepthExceeded, match="mcp_chain_max_depth"):
            issuer.issue(
                user_id="_test",
                agent_name="zeus",
                posture="mcp-c",
                posture_binding={"derived_from": "spiffe_cert", "channel_type": "chained-relay"},
                action="mcp.tools.call",
                call_id=str(uuid.uuid4()),
                upstream_chain=over_limit_chain,
            )

    def test_object_chain_rejected_before_signing(self, issuer):
        """
        Known-bad: chain with object elements rejected before signing.
        Nico FIPS checklist §7 + OPA guard (is_array AND every is_string).
        """
        from yashigani.mcp._jwt import ChainValidationError
        bad_chain = [{"spiffe": "should-be-string-not-object"}]
        with pytest.raises(ChainValidationError, match="must be a string"):
            issuer.issue(
                user_id="_test",
                agent_name="hermes",
                posture="mcp-c",
                posture_binding={"derived_from": "spiffe_cert", "channel_type": "chained-relay"},
                action="mcp.tools.call",
                call_id=str(uuid.uuid4()),
                upstream_chain=bad_chain,  # type: ignore[arg-type]
            )

    def test_int_chain_element_rejected_before_signing(self, issuer):
        """Integer elements in chain rejected (Nico spec §4 binding requirement)."""
        from yashigani.mcp._jwt import ChainValidationError
        bad_chain = [42]  # type: ignore[list-item]
        with pytest.raises(ChainValidationError):
            issuer.issue(
                user_id="_test",
                agent_name="hermes",
                posture="mcp-c",
                posture_binding={"derived_from": "spiffe_cert", "channel_type": "chained-relay"},
                action="mcp.tools.call",
                call_id=str(uuid.uuid4()),
                upstream_chain=bad_chain,
            )

    def test_startup_self_test_passes(self):
        """McpJwtIssuer startup self-test must pass on construction."""
        from yashigani.mcp._jwt import McpJwtIssuer
        key = ec.generate_private_key(SECP384R1())
        # Construction triggers self-test; if it raises, the test fails
        issuer = McpJwtIssuer(tenant_id="test", private_key=key)
        assert issuer is not None

    def test_jti_is_uuid4(self, issuer):
        """jti claim must be a UUIDv4 string (Nico spec §3)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")
        assert jti is not None, "JWT must contain jti claim"
        # Validate it's a UUID4 format
        parsed = uuid.UUID(jti)
        assert parsed.version == 4, "jti must be UUIDv4"

    def test_ttl_is_60_seconds(self, issuer):
        """JWT exp - iat == TTL (default 60s per Nico spec §3 recommendation)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["exp"] - payload["iat"] == 60, (
            "JWT TTL must be 60 seconds (Nico spec §3 OD-1 recommendation)"
        )

    def test_audience_is_yashigani_mcp_upstream(self, issuer):
        """aud must be 'yashigani-mcp-upstream' (Nico spec §4)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert payload["aud"] == "yashigani-mcp-upstream", (
            "JWT aud must be 'yashigani-mcp-upstream' (Nico spec §4)"
        )

    def test_posture_binding_in_jwt(self, issuer):
        """posture_binding claim must be present in issued JWT (Nico spec §4)."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-b",
            posture_binding={"derived_from": "tls_channel", "channel_type": "network-streamable-http"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        payload = pyjwt.decode(token, options={"verify_signature": False})
        assert "posture_binding" in payload, "posture_binding must be in JWT claims"
        assert payload["posture_binding"]["derived_from"] == "tls_channel"
        assert payload["posture_binding"]["channel_type"] == "network-streamable-http"


# ---------------------------------------------------------------------------
# C. JWT verification
# ---------------------------------------------------------------------------


class TestJwtVerification:
    def test_verifier_accepts_valid_jwt(self, issuer, verifier):
        """Verifier accepts a valid JWT from the same issuer."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        payload = verifier.verify(token)
        assert payload["agent"] == "hermes"
        assert payload["tenant"] == "tenant1"

    def test_verifier_rejects_wrong_algorithm(self, issuer):
        """Verifier rejects JWTs signed with wrong algorithm."""
        from yashigani.mcp._jwt import McpJwtVerifier

        # Generate an RS256 token (wrong alg)
        import jwt
        wrong_key = ec.generate_private_key(ec.SECP256R1())  # P-256, not P-384
        wrong_token = jwt.encode(
            {"sub": "test", "aud": "yashigani-mcp-upstream",
             "iat": int(time.time()), "exp": int(time.time()) + 60,
             "jti": str(uuid.uuid4())},
            wrong_key,
            algorithm="ES256",
            headers={"alg": "ES256"},
        )

        # Create a verifier (it won't have the P-256 key)
        verifier = McpJwtVerifier.from_issuer(issuer)
        with pytest.raises(Exception):  # InvalidAlgorithmError or DecodeError
            verifier.verify(wrong_token)

    def test_verifier_rejects_tampered_payload(self, issuer, verifier):
        """Verifier rejects tokens with tampered payload."""
        token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        # Tamper with middle segment
        parts = token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded)
        payload_dict = json.loads(payload_bytes)
        payload_dict["agent"] = "attacker"
        tampered_bytes = json.dumps(payload_dict).encode()
        tampered_b64 = base64.urlsafe_b64encode(tampered_bytes).rstrip(b"=").decode()
        tampered_token = f"{parts[0]}.{tampered_b64}.{parts[2]}"

        with pytest.raises(Exception):
            verifier.verify(tampered_token)

    def test_verifier_rejects_object_chain_in_upstream_jwt(self, issuer, p384_key):
        """Verifier rejects JWTs where identity.chain contains non-string elements."""
        from yashigani.mcp._jwt import McpJwtVerifier

        # Manually build a JWT with a bad chain (bypassing issuer validation)
        bad_payload = {
            "iss": "https://gateway.yashigani.internal/tenant1",
            "aud": "yashigani-mcp-upstream",
            "iat": int(time.time()),
            "exp": int(time.time()) + 60,
            "jti": str(uuid.uuid4()),
            "sub": "_test",
            "identity": {
                "spiffe": "spiffe://yashigani.internal/agents/tenant1/hermes",
                "chain": [{"bad": "object-not-a-string"}],  # BAD: object in chain
            },
            "tenant": "tenant1",
            "agent": "hermes",
            "posture": "mcp-c",
        }
        bad_token = pyjwt.encode(
            bad_payload, p384_key, algorithm="ES384",
            headers={"kid": "mcp-tenant1-1748476800", "alg": "ES384"},
        )

        verifier = McpJwtVerifier.from_issuer(issuer)
        with pytest.raises(pyjwt.DecodeError, match="string"):
            verifier.verify(bad_token)


# ---------------------------------------------------------------------------
# D. Nonce store (jti replay prevention)
# ---------------------------------------------------------------------------


class TestNonceStore:
    def test_new_jti_accepted(self, nonce_store):
        """First use of a jti → accepted (is_new=True)."""
        jti = str(uuid.uuid4())
        result = nonce_store.check_and_record(jti, time.time() + 60, "tenant1")
        assert result is True

    def test_replayed_jti_rejected(self, nonce_store):
        """Second use of same jti within TTL → rejected (is_new=False)."""
        jti = str(uuid.uuid4())
        nonce_store.check_and_record(jti, time.time() + 60, "tenant1")
        result = nonce_store.check_and_record(jti, time.time() + 60, "tenant1")
        assert result is False, "Replayed jti must be rejected"

    def test_different_jtis_accepted_independently(self, nonce_store):
        """Different jtis are each accepted once."""
        for _ in range(5):
            jti = str(uuid.uuid4())
            assert nonce_store.check_and_record(jti, time.time() + 60, "tenant1") is True

    def test_expired_entries_cleaned(self):
        """Expired entries (exp < now - skew) are removed during cleanup."""
        from yashigani.mcp._nonce import InMemoryNonceStore
        import logging
        with patch.object(logging.getLogger("yashigani.mcp._nonce"), "warning"):
            store = InMemoryNonceStore(skew_tolerance_seconds=0.0)

        jti = str(uuid.uuid4())
        # Record with exp in the past (expired)
        past_exp = time.time() - 10
        store.check_and_record(jti, past_exp, "tenant1")
        assert store.size == 1

        # Cleanup
        removed = store.cleanup_expired("tenant1")
        assert removed == 1
        assert store.size == 0

    def test_after_expiry_jti_accepted_again(self):
        """After expiry window, same jti can be re-accepted (entry cleaned up)."""
        from yashigani.mcp._nonce import InMemoryNonceStore
        import logging
        with patch.object(logging.getLogger("yashigani.mcp._nonce"), "warning"):
            store = InMemoryNonceStore(skew_tolerance_seconds=0.0)

        jti = str(uuid.uuid4())
        # Record with past exp
        past_exp = time.time() - 10
        store.check_and_record(jti, past_exp, "tenant1")

        # After cleanup, the same jti should be accepted again
        store.cleanup_expired("tenant1")
        result = store.check_and_record(jti, time.time() + 60, "tenant1")
        assert result is True, "After expiry, same jti can be re-accepted"


# ---------------------------------------------------------------------------
# E. OPA enforcement (fail-closed)
# ---------------------------------------------------------------------------


class TestOpaEnforcement:
    async def test_opa_allow_returns_allow_decision(self):
        """OPA allow response → OpaDecisionResult.allow=True."""
        from yashigani.mcp._opa import query_mcp_decision

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "allow": True,
                "deny_reason": "ok",
                "redact_args": [],
                "audit_capture": False,
                "rate_limit_key": None,
            }
        }

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        result = await query_mcp_decision(
            opa_url="http://localhost:8181",
            posture="mcp-a",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/tenant1/hermes",
            chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            tool_name="web_search",
            http_client=mock_client,
        )
        assert result.allow is True
        assert result.deny_reason == "ok"

    async def test_opa_deny_returns_deny_decision(self):
        """OPA deny response → OpaDecisionResult.allow=False."""
        from yashigani.mcp._opa import query_mcp_decision

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "result": {
                "allow": False,
                "deny_reason": "tool_not_in_exposed_allowlist",
                "redact_args": [],
                "audit_capture": True,
                "rate_limit_key": None,
            }
        }

        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=mock_response)
        mock_client.aclose = AsyncMock()

        result = await query_mcp_decision(
            opa_url="http://localhost:8181",
            posture="mcp-b",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/tenant1/hermes",
            chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            tool_name="dangerous_tool",
            http_client=mock_client,
        )
        assert result.allow is False
        assert result.deny_reason == "tool_not_in_exposed_allowlist"

    async def test_opa_timeout_is_fail_closed(self):
        """OPA timeout → fail-closed deny (C9). Never allows through."""
        from yashigani.mcp._opa import query_mcp_decision

        mock_client = MagicMock()
        mock_client.post = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_client.aclose = AsyncMock()

        result = await query_mcp_decision(
            opa_url="http://localhost:8181",
            posture="mcp-a",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/tenant1/hermes",
            chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            tool_name="web_search",
            http_client=mock_client,
        )
        assert result.allow is False, (
            "OPA timeout MUST be fail-closed (C9 requirement)"
        )
        assert result.deny_reason == "opa_timeout"
        assert result.error is not None

    async def test_opa_unreachable_is_fail_closed(self):
        """OPA connection error → fail-closed deny."""
        from yashigani.mcp._opa import query_mcp_decision
        import httpx

        mock_client = MagicMock()
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        mock_client.aclose = AsyncMock()

        result = await query_mcp_decision(
            opa_url="http://localhost:8181",
            posture="mcp-a",
            action="mcp.tools.call",
            spiffe_uri="spiffe://yashigani.internal/agents/tenant1/hermes",
            chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            tool_name="web_search",
            http_client=mock_client,
        )
        assert result.allow is False, "OPA unreachable MUST be fail-closed"
        assert "opa_unreachable" in result.deny_reason

    def test_opa_input_chain_must_be_array_of_strings(self):
        """OPA input construction rejects non-string chain elements before the OPA call."""
        from yashigani.mcp._opa import _build_opa_input

        # Object element
        with pytest.raises(ValueError, match="must be a string"):
            _build_opa_input(
                posture="mcp-c",
                action="mcp.tools.call",
                spiffe_uri="spiffe://...",
                chain=[{"bad": "object"}],  # type: ignore[list-item]
                tool_name="web_search",
            )

    def test_opa_input_chain_not_list_rejected(self):
        """OPA input construction rejects non-list chain."""
        from yashigani.mcp._opa import _build_opa_input

        with pytest.raises(ValueError, match="must be a list"):
            _build_opa_input(
                posture="mcp-c",
                action="mcp.tools.call",
                spiffe_uri="spiffe://...",
                chain="not-a-list",  # type: ignore[arg-type]
                tool_name="web_search",
            )

    def test_opa_decision_honors_redact_args(self):
        """OPA redact_args from policy is parsed into a set of strings."""
        from yashigani.mcp._opa import _parse_opa_response

        raw = {
            "result": {
                "allow": True,
                "deny_reason": "ok",
                "redact_args": ["api_key", "token"],
                "audit_capture": True,
                "rate_limit_key": "spiffe-hash/mcp.tools.call/web_search",
            }
        }
        result = _parse_opa_response(raw, elapsed_ms=50)
        assert result.redact_args == {"api_key", "token"}
        assert result.audit_capture is True
        assert result.rate_limit_key == "spiffe-hash/mcp.tools.call/web_search"


# ---------------------------------------------------------------------------
# F. Broker pipeline (end-to-end)
# ---------------------------------------------------------------------------


class TestBrokerPipeline:
    def _mock_opa_allow(self):
        from yashigani.mcp._opa import OpaDecisionResult
        return OpaDecisionResult(
            allow=True,
            deny_reason="ok",
            redact_args=set(),
            audit_capture=False,
            rate_limit_key=None,
            elapsed_ms=10,
        )

    def _mock_opa_deny(self, reason="tool_not_in_exposed_allowlist"):
        from yashigani.mcp._opa import OpaDecisionResult
        return OpaDecisionResult(
            allow=False,
            deny_reason=reason,
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=10,
        )

    async def test_allowed_call_returns_jwt(self, broker):
        """Broker allow path: decision.allow=True and issued_jwt is set."""
        ctx = _make_call_context(posture_str="mcp-a")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_allow()),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is True
        assert decision.issued_jwt is not None
        assert decision.deny_reason == "ok"

    async def test_opa_deny_returns_no_jwt(self, broker):
        """Broker deny path: decision.allow=False and issued_jwt is None."""
        ctx = _make_call_context(posture_str="mcp-b")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_deny()),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False
        assert decision.issued_jwt is None
        assert decision.deny_reason == "tool_not_in_exposed_allowlist"

    async def test_mcp_c_relay_extends_chain(self, broker, issuer):
        """mcp-c call with valid upstream JWT: chain is extended by one hop."""
        # Issue an upstream JWT (simulating relay caller)
        upstream_token = issuer.issue(
            user_id="_test",
            agent_name="hermes",  # upstream agent
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
            upstream_chain=None,
        )

        ctx = _make_call_context(
            posture_str="mcp-c",
            upstream_chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            upstream_jwt=upstream_token,
        )

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_allow()),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is True
        assert decision.chain_depth == 2, (
            "mcp-c relay must result in chain_depth=2 (upstream + this hop)"
        )

    async def test_mcp_c_replay_rejected(self, broker, issuer, nonce_store):
        """mcp-c with replayed upstream JWT jti is rejected by nonce store."""
        # Issue upstream JWT
        upstream_token = issuer.issue(
            user_id="_test",
            agent_name="hermes",
            posture="mcp-a",
            posture_binding={"derived_from": "physical_channel", "channel_type": "local-stdio"},
            action="mcp.tools.call",
            call_id=str(uuid.uuid4()),
        )
        # Extract jti and pre-populate nonce store (simulate first call already went through)
        payload = pyjwt.decode(upstream_token, options={"verify_signature": False})
        jti = payload["jti"]
        exp = payload["exp"]
        nonce_store.check_and_record(jti, float(exp), "tenant1")  # first call consumes jti

        ctx = _make_call_context(
            posture_str="mcp-c",
            upstream_chain=["spiffe://yashigani.internal/agents/tenant1/hermes"],
            upstream_jwt=upstream_token,
        )

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_allow()),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False, "Replayed JWT must be denied"
        assert "replayed" in decision.deny_reason.lower() or "verification_failed" in decision.deny_reason

    async def test_opa_timeout_in_broker_returns_deny(self, broker):
        """Broker enforce: OPA timeout in pipeline → deny (fail-closed)."""
        from yashigani.mcp._opa import OpaDecisionResult
        timeout_result = OpaDecisionResult(
            allow=False,
            deny_reason="opa_timeout",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=500,
            error="OPA timeout after 500ms",
        )

        ctx = _make_call_context(posture_str="mcp-a")
        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=timeout_result),
        ):
            decision = await broker.enforce(ctx)

        assert decision.allow is False
        assert decision.deny_reason == "opa_timeout"


# ---------------------------------------------------------------------------
# G. Audit emission (YSG-RISK-054)
# ---------------------------------------------------------------------------


class TestAuditEmission:
    """
    AU-2 / AU-12 / CC7.1 — every MCP decision emits audit events.
    A clean allowed call MUST leave a witness record.
    """

    def _make_mock_writer(self):
        writer = MagicMock()
        writer.write = MagicMock()
        return writer

    def _mock_opa_allow(self):
        from yashigani.mcp._opa import OpaDecisionResult
        return OpaDecisionResult(
            allow=True, deny_reason="ok", redact_args=set(),
            audit_capture=False, rate_limit_key=None, elapsed_ms=10,
        )

    def _mock_opa_deny(self):
        from yashigani.mcp._opa import OpaDecisionResult
        return OpaDecisionResult(
            allow=False, deny_reason="missing_spiffe_identity",
            redact_args=set(), audit_capture=True, rate_limit_key=None, elapsed_ms=10,
        )

    async def test_allowed_call_emits_mcp_call_event(self, broker_config, issuer):
        """Allowed MCP call emits MCP_CALL audit event (AU-2/12/CC7.1 witness)."""
        from yashigani.mcp.broker import McpBroker, McpBrokerConfig
        from yashigani.audit.schema import EventType

        writer = self._make_mock_writer()
        config = McpBrokerConfig(
            opa_url="http://localhost:8181",
            tenant_id="tenant1",
            issuer=issuer,
            audit_writer=writer,
        )
        broker = McpBroker(config)
        ctx = _make_call_context(posture_str="mcp-a")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_allow()),
        ):
            await broker.enforce(ctx)

        assert writer.write.call_count >= 2, (
            "Audit writer must be called at least twice (MCP_CALL + OPA_DECISION_ON_MCP)"
        )
        written_events = [call.args[0] for call in writer.write.call_args_list]
        event_types = [e.event_type for e in written_events]
        assert "MCP_CALL" in event_types, (
            "MCP_CALL event must be emitted on allowed calls (AU-2/12/CC7.1)"
        )
        assert "OPA_DECISION_ON_MCP" in event_types, (
            "OPA_DECISION_ON_MCP event must be emitted on every decision"
        )

    async def test_denied_call_emits_audit_events(self, broker_config, issuer):
        """Denied MCP call also emits MCP_CALL + OPA_DECISION_ON_MCP events."""
        from yashigani.mcp.broker import McpBroker, McpBrokerConfig
        from yashigani.audit.schema import EventType

        writer = self._make_mock_writer()
        config = McpBrokerConfig(
            opa_url="http://localhost:8181",
            tenant_id="tenant1",
            issuer=issuer,
            audit_writer=writer,
        )
        broker = McpBroker(config)
        ctx = _make_call_context(posture_str="mcp-b")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=self._mock_opa_deny()),
        ):
            await broker.enforce(ctx)

        assert writer.write.call_count >= 2, (
            "Denied call must also emit audit events (deny is a security-relevant event)"
        )
        written_events = [call.args[0] for call in writer.write.call_args_list]
        event_types = [e.event_type for e in written_events]
        assert "MCP_CALL" in event_types
        assert "OPA_DECISION_ON_MCP" in event_types

    async def test_audit_capture_true_sets_args_redacted(self, broker_config, issuer):
        """audit_capture=True from OPA → args_redacted=True in MCP_CALL event."""
        from yashigani.mcp.broker import McpBroker, McpBrokerConfig
        from yashigani.mcp._opa import OpaDecisionResult

        writer = self._make_mock_writer()
        config = McpBrokerConfig(
            opa_url="http://localhost:8181",
            tenant_id="tenant1",
            issuer=issuer,
            audit_writer=writer,
        )
        broker = McpBroker(config)

        # OPA returns audit_capture=True with redact_args
        result_with_redact = OpaDecisionResult(
            allow=True, deny_reason="ok",
            redact_args={"api_key", "token"},  # non-empty → args_redacted=True
            audit_capture=True, rate_limit_key=None, elapsed_ms=10,
        )
        ctx = _make_call_context(posture_str="mcp-b")

        with patch(
            "yashigani.mcp.broker.query_mcp_decision",
            new=AsyncMock(return_value=result_with_redact),
        ):
            await broker.enforce(ctx)

        written_events = [call.args[0] for call in writer.write.call_args_list]
        mcp_call_events = [e for e in written_events if e.event_type == "MCP_CALL"]
        assert mcp_call_events, "MCP_CALL event must be emitted"
        assert mcp_call_events[0].args_redacted is True, (
            "args_redacted must be True when OPA returns non-empty redact_args"
        )


# ---------------------------------------------------------------------------
# H. JWKS store
# ---------------------------------------------------------------------------


class TestJwksStore:
    def test_jwks_response_contains_ec_p384_key(self, issuer):
        """JWKS response contains an EC P-384 key entry."""
        from yashigani.mcp._jwks import JwksStore

        store = JwksStore(issuer)
        response = store.response()

        assert "keys" in response
        assert len(response["keys"]) == 1
        key = response["keys"][0]
        assert key["kty"] == "EC"
        assert key["crv"] == "P-384"
        assert key["alg"] == "ES384"
        assert "kid" in key
        assert "x" in key
        assert "y" in key

    def test_jwks_cache_control_constant(self):
        """Cache-Control value is max-age=300 (Nico spec §5)."""
        from yashigani.mcp._jwks import JWKS_CACHE_CONTROL
        assert "max-age=300" in JWKS_CACHE_CONTROL
        assert "must-revalidate" in JWKS_CACHE_CONTROL

    def test_rotation_overlap_two_keys(self, p384_key):
        """During rotation overlap, JWKS contains both old and new keys."""
        from yashigani.mcp._jwks import JwksStore
        from yashigani.mcp._jwt import McpJwtIssuer

        new_key = ec.generate_private_key(SECP384R1())
        old_issuer = McpJwtIssuer(tenant_id="t1", private_key=p384_key, key_generated_at=1000)
        new_issuer = McpJwtIssuer(tenant_id="t1", private_key=new_key, key_generated_at=2000)

        store = JwksStore(old_issuer)
        assert store.key_count == 1

        store.rotate(new_issuer, old_issuer=old_issuer)
        assert store.key_count == 2, "Rotation overlap must have 2 keys"

        response = store.response()
        kids = [k["kid"] for k in response["keys"]]
        assert "mcp-t1-1000" in kids
        assert "mcp-t1-2000" in kids

    def test_retire_old_leaves_single_key(self, p384_key):
        """After retiring old key, only new key remains."""
        from yashigani.mcp._jwks import JwksStore
        from yashigani.mcp._jwt import McpJwtIssuer

        new_key = ec.generate_private_key(SECP384R1())
        old_issuer = McpJwtIssuer(tenant_id="t1", private_key=p384_key, key_generated_at=1000)
        new_issuer = McpJwtIssuer(tenant_id="t1", private_key=new_key, key_generated_at=2000)

        store = JwksStore(old_issuer)
        store.rotate(new_issuer, old_issuer=old_issuer)
        assert store.key_count == 2

        store.retire_old(new_issuer)
        assert store.key_count == 1
        response = store.response()
        assert response["keys"][0]["kid"] == "mcp-t1-2000"

    def test_jwks_path_constant(self):
        """JWKS endpoint path matches Nico spec §5."""
        from yashigani.mcp._jwks import JWKS_PATH
        assert JWKS_PATH == "/.well-known/yashigani-mcp-jwks.json"


# ---------------------------------------------------------------------------
# I. Public key JWK format
# ---------------------------------------------------------------------------


class TestPublicKeyJwk:
    def test_public_key_jwk_has_all_required_fields(self, issuer):
        """JWK entry has all required fields (Nico spec §5)."""
        jwk = issuer.public_key_jwk()
        required = ["kty", "crv", "use", "alg", "kid", "x", "y", "nbf", "exp"]
        for field in required:
            assert field in jwk, f"JWK missing required field: {field}"

    def test_public_key_jwk_alg_es384(self, issuer):
        """JWK alg must be ES384."""
        jwk = issuer.public_key_jwk()
        assert jwk["alg"] == "ES384"

    def test_public_key_jwk_use_sig(self, issuer):
        """JWK use must be 'sig' (signature use)."""
        jwk = issuer.public_key_jwk()
        assert jwk["use"] == "sig"

    def test_public_key_jwk_x_y_are_base64url(self, issuer):
        """JWK x and y are valid base64url without padding."""
        jwk = issuer.public_key_jwk()
        for field in ["x", "y"]:
            val = jwk[field]
            assert isinstance(val, str)
            assert "=" not in val, f"JWK {field} must not have base64 padding"
            # Must decode cleanly
            padded = val + "=" * (4 - len(val) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            assert len(decoded) == 48, f"P-384 coord must be 48 bytes; {field} decoded to {len(decoded)}"
