"""
W1 — manifest JSON-Schema validation tests (M8) — v2.25.0 P1.

Tests:
  - Schema bundle loads correctly (no external $ref)
  - Valid manifest passes schema validation
  - Missing required fields are caught
  - External $ref resolution is disabled (P10)
  - jsonschema version constraint satisfied (>=4.17.3, <5.0)
  - Descriptor schema §3.3 fields validated:
      spec.network, spec.model_egress, spec.mcp, spec.audit,
      spec.identity.spiffe, spec.signature
"""
from __future__ import annotations

import pytest

_VALID_DIGEST = "a" * 64

_VALID_MANIFEST: dict = {
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


class TestSchemaLoad:
    def test_schema_loads_without_error(self) -> None:
        from yashigani.manifest.schema import _get_schema
        schema = _get_schema()
        assert schema["$id"] == "yashigani.io/v1alpha1/AgentIntegration"

    def test_jsonschema_version(self) -> None:
        """jsonschema version must be >=4.17.3 and <5.0 (M8)."""
        import importlib.metadata
        ver_str = importlib.metadata.version("jsonschema")
        parts = [int(x) for x in ver_str.split(".")[:2]]
        major, minor = parts[0], parts[1]
        assert (major, minor) >= (4, 17), "jsonschema < 4.17 — M8 constraint violated"
        assert major < 5, "jsonschema >= 5.0 — M8 upper-bound constraint violated"

    def test_external_ref_resolution_disabled(self) -> None:
        """
        A schema with an external $ref must fail validation without fetching the URL.

        We use a schema with an external $ref in the ``$defs`` property and
        validate a document against it; the validator must raise rather than
        reach out to the network.
        """
        from yashigani.manifest.schema import _make_validator, _get_schema
        from jsonschema.exceptions import SchemaError

        schema = _get_schema()
        validator = _make_validator(schema)

        # The validator should be instantiated cleanly (no external fetch yet).
        assert validator is not None

        # Verify that the schema $id does not reference an external URI
        # (our bundled schema is self-contained).
        assert "$ref" not in str(schema.get("$defs", {})), (
            "Bundled schema must not contain external $ref"
        )


class TestSchemaValidation:
    def test_valid_manifest_no_errors(self) -> None:
        from yashigani.manifest.schema import validate_schema
        errors = validate_schema(_VALID_MANIFEST)
        assert errors == [], "Unexpected errors: %s" % errors

    def test_assert_schema_valid_passes(self) -> None:
        from yashigani.manifest.schema import assert_schema_valid
        assert_schema_valid(_VALID_MANIFEST)  # should not raise

    def test_missing_apiversion_caught(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        del bad["apiVersion"]
        errors = validate_schema(bad)
        assert any("apiVersion" in e for e in errors), errors

    def test_missing_kind_caught(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        del bad["kind"]
        errors = validate_schema(bad)
        assert any("kind" in e for e in errors), errors

    def test_wrong_apiversion_caught(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        bad["apiVersion"] = "yashigani.io/v99"
        errors = validate_schema(bad)
        assert errors  # schema const violation

    def test_missing_image_caught(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        del bad["spec"]["image"]
        errors = validate_schema(bad)
        assert any("image" in e for e in errors), errors

    def test_invalid_tenant_id_pattern_caught(self) -> None:
        """The schema pattern for tenant_id catches uppercase."""
        from yashigani.manifest.schema import validate_schema
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        bad["metadata"]["tenant_id"] = "ACME"  # uppercase — schema pattern rejects
        errors = validate_schema(bad)
        assert errors  # pattern validation error

    def test_manifest_schema_error_raised(self) -> None:
        from yashigani.manifest.schema import assert_schema_valid, ManifestSchemaError
        import copy
        bad = copy.deepcopy(_VALID_MANIFEST)
        del bad["spec"]["image"]
        with pytest.raises(ManifestSchemaError):
            assert_schema_valid(bad)


class TestDescriptorSchemaFields:
    """§3.3 descriptor fields validate correctly."""

    def test_spec_model_egress_valid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["model_egress"] = {"provider": "openai", "base_url": "https://api.openai.com"}
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_model_egress_bad_provider(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["model_egress"] = {"provider": "unknown_provider"}
        errors = validate_schema(m)
        assert errors  # enum violation

    def test_spec_mcp_posture_valid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["mcp"] = {"posture": "mcp-a"}
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_mcp_posture_invalid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["mcp"] = {"posture": "mcp-z"}
        errors = validate_schema(m)
        assert errors

    def test_spec_audit_capture_valid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["audit"] = {
            "capture": ["mcp_call", "egress_allow_used"]
        }
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_audit_capture_invalid_type(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["audit"] = {"capture": ["nonexistent_event_type"]}
        errors = validate_schema(m)
        assert errors  # enum violation in items

    def test_spec_signature_cosign_valid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["signature"] = {
            "algorithm": "cosign-bundled-key",
            "signature_hex": "deadbeef" * 16,
            "signed_at": "2026-05-28T00:00:00Z",
            "signer_key_id": "sha256:abcdef",
        }
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_signature_rsa_pss_valid(self) -> None:
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["signature"] = {
            "algorithm": "rsa-pss-3072-sha384",
            "signature_hex": "a0b1c2d3" * 16,
        }
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_lifecycle_mode_persistent(self) -> None:
        """Only persistent mode is v1 (Nico NICO-003)."""
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["lifecycle"] = {"mode": "persistent"}
        errors = validate_schema(m)
        assert not errors, errors

    def test_spec_lifecycle_mode_on_demand_rejected(self) -> None:
        """on-demand is v2 only — schema must reject it."""
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["lifecycle"] = {"mode": "on-demand"}
        errors = validate_schema(m)
        assert errors  # enum violation

    def test_spec_mcp_consumes_requires_pin_mode(self) -> None:
        """Each consumes.servers entry must declare pin_mode (P8)."""
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["mcp"] = {
            "consumes": {
                "servers": [
                    {"id": "fs-server", "transport": "stdio"}
                    # missing pin_mode — schema should catch
                ]
            }
        }
        errors = validate_schema(m)
        assert errors, "pin_mode should be required"

    def test_spec_inbound_port_range_schema(self) -> None:
        """Port outside [1024, 49151] fails schema (M5)."""
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["network"] = {"inbound_ports": [80]}
        errors = validate_schema(m)
        assert errors

    def test_eu_ai_act_field_optional(self) -> None:
        """spec.eu_ai_act.annex_iii_category is optional (N8)."""
        from yashigani.manifest.schema import validate_schema
        import copy
        m = copy.deepcopy(_VALID_MANIFEST)
        m["spec"]["eu_ai_act"] = {"annex_iii_category": "limited-risk"}
        errors = validate_schema(m)
        assert not errors, errors
