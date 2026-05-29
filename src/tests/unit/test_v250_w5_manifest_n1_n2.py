"""
W5 — manifest linter tests for N1 (SPIFFE namespace mandate) and
N2 (onboard-time cert issuance constraint) — v2.25.0 P1.

N1 proving tests (plan §2.F):
  - override_id that collides with a core-service identity → rejected
  - override_id in another tenant's namespace → rejected
  - valid in-namespace override → accepted
  - no override (default) → accepted

N2 proving tests (plan §2.F):
  - on-demand + container_per:identity → rejected with N2_ondemand_identity_v1_blocked
  - persistent (any container_per) → accepted
  - on-demand without container_per:identity (container_per:agent) → rejected by schema
    (M8 enum) but NOT by N2 linter rule
  - on-demand without container_per set → rejected by schema but NOT by N2 linter rule

Additional cross-cutting tests:
  - N1 error message is human-quality: mentions the required prefix + fix hint
  - N2 error message is human-quality: mentions v2.24.0 constraint + fix hint
  - N2 rule fires independently (even if M8 schema also fires for on-demand)

References: plan §2.F, Nico NICO-002 (N1), Nico NICO-003 (N2).
"""
from __future__ import annotations

import copy
import os

_VALID_DIGEST = "a" * 64

_BASE_PARSED: dict = {
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
    """Simple deep merge helper (matches W1 test helper pattern)."""
    result = copy.deepcopy(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def _env_skip() -> None:
    """Set YSG_REQUIRE_SIGNED_MANIFEST=skip for tests that don't exercise M7."""
    os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"


def _env_cleanup() -> None:
    os.environ.pop("YSG_REQUIRE_SIGNED_MANIFEST", None)


# ============================================================================
# N1 — SPIFFE /agents/{tenant_id}/{name} namespace mandate
# ============================================================================

class TestN1SpiffeNamespaceMandate:
    """
    N1: spec.identity.spiffe.override_id MUST start with
    spiffe://yashigani.internal/agents/<tenant_id>/

    Nico NICO-002 — prevents core-service collision and cross-tenant impersonation.
    """

    def test_no_override_accepted(self) -> None:
        """No override_id set: default URI construction path — always accepted by N1."""
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            result = validate_manifest(_BASE_PARSED)
            n1_errors = [e for e in result.errors if e.rule.startswith("N1")]
            assert not n1_errors, [e.human_message() for e in n1_errors]
        finally:
            _env_cleanup()

    def test_valid_in_namespace_override_accepted(self) -> None:
        """override_id correctly scoped under /agents/acme-corp/ — accepted."""
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
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
            n1_errors = [e for e in result.errors if e.rule.startswith("N1")]
            assert not n1_errors, [e.human_message() for e in n1_errors]
        finally:
            _env_cleanup()

    def test_valid_in_namespace_subpath_override_accepted(self) -> None:
        """override_id with a subpath under the tenant namespace — accepted."""
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/agents/acme-corp/goose/sidecar"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            n1_errors = [e for e in result.errors if e.rule.startswith("N1")]
            assert not n1_errors, [e.human_message() for e in n1_errors]
        finally:
            _env_cleanup()

    def test_core_service_collision_gateway_rejected(self) -> None:
        """
        override_id = spiffe://yashigani.internal/gateway impersonates the
        ring-fence gateway core service — must be rejected with N1 error.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/gateway"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "Core-service collision (gateway) not rejected. Errors: %s" % rules
            )
        finally:
            _env_cleanup()

    def test_core_service_collision_with_name_suffix_rejected(self) -> None:
        """
        override_id = spiffe://yashigani.internal/gateway/<name> — still under
        /gateway/, not /agents/ — must be rejected.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
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
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "Core-service namespace escape not rejected. Errors: %s" % rules
            )
        finally:
            _env_cleanup()

    def test_another_tenant_namespace_rejected(self) -> None:
        """
        override_id in another tenant's namespace
        (spiffe://yashigani.internal/agents/evil-corp/...) — must be rejected.
        Manifest tenant_id is acme-corp; override references evil-corp.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/agents/evil-corp/goose"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "Cross-tenant namespace override not rejected. Errors: %s" % rules
            )
        finally:
            _env_cleanup()

    def test_another_tenant_with_correct_name_rejected(self) -> None:
        """
        override_id uses our agent name but wrong tenant — still rejected.
        spiffe://yashigani.internal/agents/other-corp/goose is outside acme-corp.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/agents/other-corp/goose"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "Other-tenant-same-agent-name override not rejected. Errors: %s" % rules
            )
        finally:
            _env_cleanup()

    def test_agents_prefix_but_wrong_trust_domain_rejected(self) -> None:
        """
        override_id with correct path structure but wrong trust domain — rejected.
        spiffe://attacker.example.com/agents/acme-corp/goose escapes the trust domain.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://attacker.example.com/agents/acme-corp/goose"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "Wrong trust-domain override not rejected. Errors: %s" % rules
            )
        finally:
            _env_cleanup()

    def test_n1_error_message_is_human_quality(self) -> None:
        """N1 error: human_message() must include the required prefix and a Fix hint."""
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/gateway"
                        }
                    }
                }
            })
            result = validate_manifest(parsed)
            n1_errs = [e for e in result.errors if e.rule == "N1_spiffe_override_out_of_namespace"]
            assert n1_errs, "Expected N1 error"
            err = n1_errs[0]
            # human_message() must contain the required prefix
            msg = err.human_message()
            assert "spiffe://yashigani.internal/agents/acme-corp/" in msg, (
                "N1 message does not reference required prefix: %r" % msg
            )
            # Fix hint must be non-empty
            assert err.fix, "N1 error has no fix hint"
            assert "override_id" in err.fix.lower() or "persistent" in err.fix.lower() or "agents" in err.fix, (
                "N1 fix hint does not mention override_id or path: %r" % err.fix
            )
        finally:
            _env_cleanup()


# ============================================================================
# N2 — onboard-time cert issuance constraint
# ============================================================================

class TestN2OndemandIdentityBlocked:
    """
    N2: lifecycle.mode:on-demand + pool.container_per:identity is BLOCKED in v1.
    PKI Issuer API required for on-demand per-identity cert issuance (v2.24.0).

    Nico NICO-003.
    """

    def test_persistent_mode_accepted(self) -> None:
        """lifecycle.mode:persistent — always accepted by N2."""
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "persistent"},
                "pool": {"container_per": "identity"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        assert not errors, [e.human_message() for e in errors]

    def test_persistent_mode_with_agent_container_per_accepted(self) -> None:
        """lifecycle.mode:persistent + container_per:agent — accepted."""
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "persistent"},
                "pool": {"container_per": "agent"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        assert not errors, [e.human_message() for e in errors]

    def test_no_lifecycle_no_pool_accepted(self) -> None:
        """Neither lifecycle nor pool set — default path, N2 does not fire."""
        from yashigani.manifest.linter import _lint_lifecycle_n2
        errors = _lint_lifecycle_n2(_BASE_PARSED)
        assert not errors, [e.human_message() for e in errors]

    def test_ondemand_identity_combination_rejected_by_n2(self) -> None:
        """
        lifecycle.mode:on-demand + pool.container_per:identity — rejected with
        N2_ondemand_identity_v1_blocked.

        This is the proving test for the N2 rule itself (direct call).
        """
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "on-demand"},
                "pool": {"container_per": "identity"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        rules = [e.rule for e in errors]
        assert "N2_ondemand_identity_v1_blocked" in rules, (
            "N2 did not fire for on-demand+identity combination. Errors: %s" % rules
        )

    def test_ondemand_identity_combination_rejected_via_validate_manifest(self) -> None:
        """
        End-to-end: on-demand + identity via full validate_manifest() — N2 error present.
        M8 schema error (on-demand not in enum) will also fire; N2 must fire independently.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "lifecycle": {"mode": "on-demand"},
                    "pool": {"container_per": "identity"},
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N2_ondemand_identity_v1_blocked" in rules, (
                "N2 not in validate_manifest errors: %s" % rules
            )
            assert not result.passed
        finally:
            _env_cleanup()

    def test_ondemand_without_identity_does_not_trigger_n2(self) -> None:
        """
        lifecycle.mode:on-demand + pool.container_per:agent — N2 does NOT fire.
        (M8 schema may still fire because on-demand is not in the enum; N2 is silent.)
        """
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "on-demand"},
                "pool": {"container_per": "agent"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        n2_errors = [e for e in errors if e.rule == "N2_ondemand_identity_v1_blocked"]
        assert not n2_errors, (
            "N2 fired for on-demand+agent (should only fire for on-demand+identity): %s" % (
                [e.human_message() for e in n2_errors]
            )
        )

    def test_ondemand_without_pool_does_not_trigger_n2(self) -> None:
        """
        lifecycle.mode:on-demand, no pool set — N2 does NOT fire.
        Only the schema (M8) rejects on-demand.
        """
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "on-demand"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        n2_errors = [e for e in errors if e.rule == "N2_ondemand_identity_v1_blocked"]
        assert not n2_errors, (
            "N2 fired for on-demand without pool (should only fire for on-demand+identity): %s" % (
                [e.human_message() for e in n2_errors]
            )
        )

    def test_n2_error_message_is_human_quality(self) -> None:
        """N2 error: human_message() must mention v2.24.0 / PKI Issuer API + fix hint."""
        from yashigani.manifest.linter import _lint_lifecycle_n2
        parsed = _deep_merge(_BASE_PARSED, {
            "spec": {
                "lifecycle": {"mode": "on-demand"},
                "pool": {"container_per": "identity"},
            }
        })
        errors = _lint_lifecycle_n2(parsed)
        n2_errs = [e for e in errors if e.rule == "N2_ondemand_identity_v1_blocked"]
        assert n2_errs, "Expected N2 error"
        err = n2_errs[0]
        msg = err.human_message()
        # Must reference the v2 / PKI constraint
        assert "v2.24.0" in msg or "PKI Issuer" in msg or "NICO-003" in msg, (
            "N2 message does not reference v2.24.0 or PKI Issuer API: %r" % msg
        )
        # Fix hint must point to persistent mode
        assert err.fix, "N2 error has no fix hint"
        assert "persistent" in err.fix, (
            "N2 fix hint does not mention persistent mode: %r" % err.fix
        )

    def test_n2_schema_also_rejects_ondemand_directly(self) -> None:
        """
        Belt-and-suspenders: the JSON-Schema enum must also reject on-demand
        (independent of N2 linter rule).  Tests that M8 fires for on-demand.
        """
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_BASE_PARSED)
        m["spec"]["lifecycle"] = {"mode": "on-demand"}
        errors = validate_schema(m)
        assert errors, "Schema should reject lifecycle.mode: on-demand (not in enum)"


# ============================================================================
# N1 + N2 interaction: both can fire on the same manifest
# ============================================================================

class TestN1N2BothFire:
    def test_n1_and_n2_both_fire_on_bad_manifest(self) -> None:
        """
        A manifest with a cross-tenant override_id AND on-demand+identity gets
        both N1 and N2 errors.  The linter accumulates all errors.
        """
        from yashigani.manifest.linter import validate_manifest
        _env_skip()
        try:
            parsed = _deep_merge(_BASE_PARSED, {
                "spec": {
                    "identity": {
                        "spiffe": {
                            "override_id": "spiffe://yashigani.internal/gateway"
                        }
                    },
                    "lifecycle": {"mode": "on-demand"},
                    "pool": {"container_per": "identity"},
                }
            })
            result = validate_manifest(parsed)
            rules = [e.rule for e in result.errors]
            assert "N1_spiffe_override_out_of_namespace" in rules, (
                "N1 not fired: %s" % rules
            )
            assert "N2_ondemand_identity_v1_blocked" in rules, (
                "N2 not fired: %s" % rules
            )
            assert not result.passed
        finally:
            _env_cleanup()
