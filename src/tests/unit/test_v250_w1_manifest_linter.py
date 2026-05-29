"""
W1 — manifest linter tests (M5, M6, M7, N1, C1, C3, M8) — v2.25.0 P1.

Tests:
  - M5: inbound_ports allowlist 1024-49151, non-MCP forbidden
  - M6: image digest required, sidecar digest required, format validation
  - M7: signature structural gate (crypto tested separately in signatures tests)
  - N1: SPIFFE /agents/{tenant_id}/{name} prefix mandate
  - C1: egress_allow RFC1918/loopback/link-local blocked
  - C3: metadata.name and tenant_id presence
  - M8: JSON-Schema structural errors surface cleanly
  - LintResult.format_report() human-quality output (K3)
"""
from __future__ import annotations

import os
import pytest

_VALID_DIGEST = "a" * 64

_BASE_PARSED = {
    "apiVersion": "yashigani.io/v1alpha1",
    "kind": "AgentIntegration",
    "metadata": {
        "name": "goose",
        "tenant_id": "acme-corp",
    },
    "spec": {
        "image": {
            "repository": "ghcr.io/acme/goose",
            "tag": "1.0.0",
            "digest": "sha256:" + _VALID_DIGEST,
        },
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Simple deep merge helper."""
    import copy
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


class TestBarrelImport:
    def test_validate_manifest_importable(self) -> None:
        from yashigani.manifest import validate_manifest
        assert callable(validate_manifest)

    def test_lint_result_importable(self) -> None:
        from yashigani.manifest import LintResult
        assert LintResult is not None

    def test_lint_error_importable(self) -> None:
        from yashigani.manifest import LintError
        assert LintError is not None


class TestHappyPath:
    def test_valid_manifest_passes(self) -> None:
        from yashigani.manifest import validate_manifest
        import os
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(_BASE_PARSED)
            assert result.passed, result.format_report()
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_format_report_ok(self) -> None:
        from yashigani.manifest import validate_manifest
        import os
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(_BASE_PARSED)
            report = result.format_report()
            assert "OK" in report or "PASSED" in report
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# M5 — inbound_ports
# ---------------------------------------------------------------------------

class TestM5InboundPorts:
    def test_valid_mcp_port(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "mcp": {
                        "exposes": {"listen_port": 8080}
                    },
                    "network": {"inbound_ports": [8080]},
                }
            })
            result = validate_manifest(parsed)
            # Should pass — port is MCP listen port and in range
            m5_errors = [e for e in result.errors if e.rule.startswith("M5")]
            assert not m5_errors, [e.human_message() for e in m5_errors]
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_port_below_1024_rejected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "mcp": {"exposes": {"listen_port": 80}},
                    "network": {"inbound_ports": [80]},
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M5" in r for r in rules)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_port_above_49151_rejected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "mcp": {"exposes": {"listen_port": 60000}},
                    "network": {"inbound_ports": [60000]},
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M5" in r for r in rules)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_non_mcp_inbound_rejected(self) -> None:
        """An inbound port that is not the MCP listen port is rejected (v1)."""
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "mcp": {"exposes": {"listen_port": 8080}},
                    "network": {"inbound_ports": [9090]},  # different port
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M5_non_mcp_inbound" in r for r in rules)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# M6 — image digest
# ---------------------------------------------------------------------------

class TestM6ImageDigest:
    def test_missing_digest_detected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            import copy
            parsed = copy.deepcopy(_BASE_PARSED)
            del parsed["spec"]["image"]["digest"]
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M6" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_invalid_digest_format_detected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {"image": {"digest": "sha256:notvalidhex"}}
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            # Either schema (M8) or M6 format rule fires
            assert any("M6" in r or "M8" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_sidecar_digest_required(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "sidecars": [
                        {
                            "name": "pgbouncer",
                            "image": {
                                "repository": "bitnami/pgbouncer",
                                "tag": "1.22.0",
                                # no digest
                            }
                        }
                    ]
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M6_sidecar_digest" in r or "M8" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_sidecar_with_digest_passes(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "sidecars": [
                        {
                            "name": "pgbouncer",
                            "image": {
                                "repository": "bitnami/pgbouncer",
                                "tag": "1.22.0",
                                "digest": "sha256:" + "b" * 64,
                            }
                        }
                    ]
                }
            })
            result = validate_manifest(parsed)
            m6_errors = [e for e in result.errors if "M6_sidecar" in e.rule]
            assert not m6_errors, [e.human_message() for e in m6_errors]
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_verify_digests_live_mock(self) -> None:
        """M6 live digest path: mock inspector confirming digest match passes."""
        from yashigani.manifest import validate_manifest

        class _MockInspector:
            def inspect(self, repo: str, tag: str) -> str:
                return "sha256:" + _VALID_DIGEST  # matches declared

        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(
                _BASE_PARSED,
                verify_digests=True,
                digest_inspector=_MockInspector(),
            )
            m6_live_errors = [e for e in result.errors if "M6_digest_mismatch" in e.rule]
            assert not m6_live_errors
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_verify_digests_live_mismatch_detected(self) -> None:
        """M6 live digest path: mock inspector returning different digest raises error."""
        from yashigani.manifest import validate_manifest

        class _MockInspector:
            def inspect(self, repo: str, tag: str) -> str:
                return "sha256:" + "z" * 64  # different from declared

        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            result = validate_manifest(
                _BASE_PARSED,
                verify_digests=True,
                digest_inspector=_MockInspector(),
            )
            rules = [e.rule for e in result.errors]
            assert "M6_digest_mismatch" in rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# M7 — signature gate (structural)
# ---------------------------------------------------------------------------

class TestM7SignatureGate:
    def test_missing_signature_fails_when_required(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            result = validate_manifest(_BASE_PARSED)
            rules = [e.rule for e in result.errors]
            assert any("M7" in r for r in rules), rules
            assert not result.passed
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_missing_signature_warn_mode_passes(self) -> None:
        """In warn mode, missing signature does not block (no structural error)."""
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "warn"
        try:
            result = validate_manifest(_BASE_PARSED)
            m7_errors = [e for e in result.errors if "M7" in e.rule]
            # warn mode: structural check returns no errors (only a log warning)
            assert not m7_errors, [e.human_message() for e in m7_errors]
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_unknown_signature_algorithm_rejected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "signature": {
                        "algorithm": "pgp",
                        "signature_hex": "deadbeef",
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("M7_unknown_algorithm" in r or "M8" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# N1 — SPIFFE prefix
# ---------------------------------------------------------------------------

class TestN1SpiffePrefix:
    def test_valid_spiffe_override_passes(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/agents/acme-corp/goose"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            n1_errors = [e for e in result.errors if "N1" in e.rule]
            assert not n1_errors
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_wrong_spiffe_prefix_rejected(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/gateway/goose"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_core_service_collision_prevented(self) -> None:
        """A SPIFFE ID impersonating a core service (no /agents/ prefix) is rejected."""
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/yashigani-gateway"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# C1 — egress_allow private IPs
# ---------------------------------------------------------------------------

class TestC1EgressAllow:
    @pytest.mark.parametrize("host,desc", [
        ("10.0.0.1", "RFC1918 class A"),
        ("172.16.0.1", "RFC1918 class B"),
        ("192.168.1.1", "RFC1918 class C"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("::1", "IPv6 loopback"),
        ("fe80::1", "IPv6 link-local"),
    ])
    def test_private_host_rejected(self, host: str, desc: str) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "network": {
                        "egress_allow": [{"host": host}]
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "C1_private_egress_host" in rules, "%s not rejected for %s" % (host, desc)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_public_host_accepted(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "network": {
                        "egress_allow": [{"host": "api.openai.com"}]
                    }
                }
            })
            result = validate_manifest(parsed)
            c1_errors = [e for e in result.errors if "C1" in e.rule]
            assert not c1_errors
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_public_ip_accepted(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "network": {
                        "egress_allow": [{"host": "8.8.8.8"}]
                    }
                }
            })
            result = validate_manifest(parsed)
            c1_errors = [e for e in result.errors if "C1" in e.rule]
            assert not c1_errors
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# C3 — name/tenant_id presence
# ---------------------------------------------------------------------------

class TestC3NamePresence:
    def test_missing_name_flagged(self) -> None:
        from yashigani.manifest import validate_manifest
        import copy
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = copy.deepcopy(_BASE_PARSED)
            del parsed["metadata"]["name"]
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("C3_name_empty" in r or "M8" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_missing_tenant_id_flagged(self) -> None:
        from yashigani.manifest import validate_manifest
        import copy
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            parsed = copy.deepcopy(_BASE_PARSED)
            del parsed["metadata"]["tenant_id"]
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert any("C3_tenant_id_empty" in r or "M8" in r for r in rules), rules
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


# ---------------------------------------------------------------------------
# Human-quality error messages (K3)
# ---------------------------------------------------------------------------

class TestK3HumanErrors:
    def test_error_message_has_fix(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            result = validate_manifest(_BASE_PARSED)
            for err in result.errors:
                # Every error must have a non-empty fix hint
                assert err.fix, "Error %s has no fix hint" % err.rule
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_format_report_contains_error_count(self) -> None:
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            result = validate_manifest(_BASE_PARSED)
            report = result.format_report()
            assert "ERRORS" in report or "FAILED" in report
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]
