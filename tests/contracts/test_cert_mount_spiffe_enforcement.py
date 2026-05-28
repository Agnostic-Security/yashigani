"""
FIX-3 (Nico gate) — CertMount SPIFFE identity prefix enforcement.

Contract: CertMount.__post_init__ raises ValueError if spiffe_identity is
non-empty and does NOT match ``spiffe://yashigani.internal/agents/``.
Empty string is allowed (non-agent pool containers).

Three cases:
  1. Valid prefix  → CertMount constructed without error.
  2. Arbitrary URI → ValueError raised at construction.
  3. Empty string  → CertMount constructed without error (non-agent container).

Reference: src/yashigani/pool/POOL_MANAGER_CONTRACT.md §2
"""
import pytest

from yashigani.pool.manager import CertMount


# ---------------------------------------------------------------------------
# Minimal required positional args for CertMount
# ---------------------------------------------------------------------------

_CERT = "/opt/yashigani/docker/secrets/agent_client.crt"
_KEY = "/opt/yashigani/docker/secrets/agent_client.key"
_CA = "/opt/yashigani/docker/secrets/ca_root.crt"


# ---------------------------------------------------------------------------
# Case 1 — valid prefix passes
# ---------------------------------------------------------------------------

class TestValidSpiffePrefix:
    def test_canonical_uri_passes(self):
        """spiffe://yashigani.internal/agents/tenant-a/goose is accepted."""
        cm = CertMount(
            host_cert_path=_CERT,
            host_key_path=_KEY,
            host_ca_path=_CA,
            spiffe_identity="spiffe://yashigani.internal/agents/tenant-a/goose",
        )
        assert cm.spiffe_identity == "spiffe://yashigani.internal/agents/tenant-a/goose"

    def test_override_id_subpath_passes(self):
        """A subpath beyond the standard name segment is accepted."""
        cm = CertMount(
            host_cert_path=_CERT,
            host_key_path=_KEY,
            host_ca_path=_CA,
            spiffe_identity="spiffe://yashigani.internal/agents/tenant-b/letta/v2",
        )
        assert cm.spiffe_identity == "spiffe://yashigani.internal/agents/tenant-b/letta/v2"

    def test_minimal_prefix_plus_tenant_passes(self):
        """Bare tenant-level URI (no agent name component) is accepted
        because the prefix mandate ends at /agents/."""
        cm = CertMount(
            host_cert_path=_CERT,
            host_key_path=_KEY,
            host_ca_path=_CA,
            spiffe_identity="spiffe://yashigani.internal/agents/my-tenant/my-agent",
        )
        assert cm.spiffe_identity == "spiffe://yashigani.internal/agents/my-tenant/my-agent"


# ---------------------------------------------------------------------------
# Case 2 — arbitrary identity raises ValueError
# ---------------------------------------------------------------------------

class TestArbitrarySpiffeRaises:
    def test_wrong_trust_domain_raises(self):
        """spiffe://attacker.example/ must not flow into ContainerInfo."""
        with pytest.raises(ValueError, match="spiffe://yashigani\\.internal/agents/"):
            CertMount(
                host_cert_path=_CERT,
                host_key_path=_KEY,
                host_ca_path=_CA,
                spiffe_identity="spiffe://attacker.example/agents/tenant/agent",
            )

    def test_core_service_uri_raises(self):
        """spiffe://yashigani.internal/services/ collides with core services (Nico NICO-002)."""
        with pytest.raises(ValueError):
            CertMount(
                host_cert_path=_CERT,
                host_key_path=_KEY,
                host_ca_path=_CA,
                spiffe_identity="spiffe://yashigani.internal/services/gateway",
            )

    def test_plain_string_raises(self):
        """A non-URI string must not be accepted."""
        with pytest.raises(ValueError):
            CertMount(
                host_cert_path=_CERT,
                host_key_path=_KEY,
                host_ca_path=_CA,
                spiffe_identity="not-a-spiffe-uri",
            )

    def test_empty_trust_domain_raises(self):
        """spiffe:// with no trust domain must be rejected."""
        with pytest.raises(ValueError):
            CertMount(
                host_cert_path=_CERT,
                host_key_path=_KEY,
                host_ca_path=_CA,
                spiffe_identity="spiffe:///agents/tenant/agent",
            )

    def test_wrong_path_prefix_raises(self):
        """Correct trust domain but wrong path segment (/agent/ vs /agents/)."""
        with pytest.raises(ValueError):
            CertMount(
                host_cert_path=_CERT,
                host_key_path=_KEY,
                host_ca_path=_CA,
                spiffe_identity="spiffe://yashigani.internal/agent/tenant/goose",
            )


# ---------------------------------------------------------------------------
# Case 3 — empty string allowed (non-agent pool container)
# ---------------------------------------------------------------------------

class TestEmptySpiffeAllowed:
    def test_empty_string_default_passes(self):
        """Default spiffe_identity='' is allowed (non-agent pool container)."""
        cm = CertMount(
            host_cert_path=_CERT,
            host_key_path=_KEY,
            host_ca_path=_CA,
        )
        assert cm.spiffe_identity == ""

    def test_explicit_empty_string_passes(self):
        """Explicitly passing spiffe_identity='' is allowed."""
        cm = CertMount(
            host_cert_path=_CERT,
            host_key_path=_KEY,
            host_ca_path=_CA,
            spiffe_identity="",
        )
        assert cm.spiffe_identity == ""
