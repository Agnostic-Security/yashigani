# Last updated: 2026-05-29T00:00:00+00:00 (P3 filesystem-mcp bundle — Shape-C codegen)
"""
Shape-C codegen contract tests.

Covers the CodegenEngineShapeC artifact set for the filesystem MCP server bundle.
Tests are organised by constraint from Laura's threat model §4.

Constraints verified:
  SC-EGRESS-NONE  — no Caddy snippet generated; no caddy_internal in compose
  SC-NO-SECRETS   — group_add 2002 NOT in compose; no secrets gate fires
  SC-VOLUME       — named tenant-namespaced volume present
  SC-TMPFS        — /tmp tmpfs present
  SC-L9-RUNUSER   — runAsUser 10001 in compose
  L9              — read_only: true, cap_drop ALL, no-new-privileges
  SPIFFE          — shape: "c" in service_identities fragment
  FS1             — linter rejects hostPath / dangerous container_path / wrong volume name
  LAURA-FS-TM-008 — two distinct tenant_ids produce distinct volume names
  OPA content     — opa/<agent>.rego contains readonly/readwrite rules and path-arg checks

Laura threat model refs: §2, §4.1–4.8, §5, LAURA-FS-TM-001/002/008
"""
from __future__ import annotations

from typing import Any

import pytest

from yashigani.manifest.codegen import (
    CodegenEngineShapeC,
    CodegenError,
    _is_shape_c,
    _sc_volume_name,
    reset_codegen_registry,
)
from yashigani.manifest.linter import validate_manifest, LintResult

# ---------------------------------------------------------------------------
# Fixtures — minimal valid manifests
# ---------------------------------------------------------------------------

_FAKE_DIGEST = "sha256:" + "a" * 64


def _base_manifest(
    name: str = "filesystem",
    tenant_id: str = "acme-corp",
    write_posture: str = "readonly",
) -> dict[str, Any]:
    """Return a minimal valid Shape-C manifest dict."""
    return {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {
            "name": name,
            "tenant_id": tenant_id,
            "category": "mcp_server",
            "description": "Filesystem MCP server for testing",
            "vendor": "Anthropic",
            "licence": "MIT",
        },
        "spec": {
            "image": {
                "repository": "registry.yashigani.internal/bundles/mcp-filesystem",
                "tag": "latest",
                "digest": _FAKE_DIGEST,
            },
            "write_posture": write_posture,
            "subprocess": {
                "command": ["node", "index.js"],
                "args": ["/workspace"],
            },
            "network": {
                "egress_allow": [],
            },
            "mcp": {
                "posture": "mcp-b",
                "transport": "stdio",
                "session_mode": "persistent",
                "identity_propagation": "gateway-enforced-only",
                "exposes": {
                    "listen_port": None,
                    "tools": [
                        {"name": "read_file", "allowed": True, "sensitivity_class": "INTERNAL"},
                        {"name": "write_file", "allowed": False, "reason": "denied by default"},
                    ],
                },
            },
            "secrets": [],
            "storage": {
                "mounts": [
                    {
                        "name": "ysg_fs_acme_corp_filesystem_workspace",
                        "type": "volume",
                        "container_path": "/workspace",
                        "read_only": False,
                        "create_if_missing": True,
                    }
                ],
                "tmpfs": [
                    {"path": "/tmp", "size_limit": "64m"},
                ],
            },
            "lifecycle": {"mode": "persistent"},
            "audit": {
                "capture": ["mcp_call", "mcp_tool_description_fetched", "opa_decision_on_mcp"],
                "sensitivity_ceiling": "INTERNAL",
            },
        },
    }


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset codegen C3 pair registry before each test."""
    reset_codegen_registry()
    yield
    reset_codegen_registry()


# ---------------------------------------------------------------------------
# 1. _is_shape_c detection
# ---------------------------------------------------------------------------

def test_is_shape_c_by_category():
    parsed = _base_manifest()
    assert _is_shape_c(parsed) is True


def test_is_shape_c_by_transport_and_posture():
    parsed = _base_manifest()
    # Remove category but keep transport+posture
    del parsed["metadata"]["category"]
    assert _is_shape_c(parsed) is True


def test_is_shape_c_false_for_shape_a():
    """Standard Shape-A LLM agent should not be detected as Shape-C."""
    parsed = {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {"name": "my-agent", "tenant_id": "acme-corp", "category": "llm_agent"},
        "spec": {
            "image": {"repository": "repo", "tag": "v1", "digest": _FAKE_DIGEST},
            "mcp": {"posture": "mcp-a", "transport": "streamable_http"},
        },
    }
    assert _is_shape_c(parsed) is False


# ---------------------------------------------------------------------------
# 2. _sc_volume_name — tenant-namespace isolation (LAURA-FS-TM-008)
# ---------------------------------------------------------------------------

def test_sc_volume_name_format():
    vol = _sc_volume_name("acme-corp", "filesystem")
    assert vol == "ysg_fs_acme_corp_filesystem_workspace"


def test_sc_volume_name_distinct_for_different_tenants():
    """Two distinct tenant_ids must produce distinct volume names (LAURA-FS-TM-008)."""
    v1 = _sc_volume_name("tenant-a", "filesystem")
    v2 = _sc_volume_name("tenant-b", "filesystem")
    assert v1 != v2, "Different tenants must produce different volume names"


def test_sc_volume_name_has_ysg_fs_prefix():
    vol = _sc_volume_name("acme-corp", "filesystem")
    assert vol.startswith("ysg_fs_")


def test_sc_volume_name_contains_tenant_id():
    vol = _sc_volume_name("acme-corp", "filesystem")
    assert "acme_corp" in vol


# ---------------------------------------------------------------------------
# 3. SC-EGRESS-NONE — no Caddy snippet generated
# ---------------------------------------------------------------------------

def test_sc_no_caddy_snippet_in_artifacts():
    """SC-EGRESS-NONE: no caddy agent file in artifact map."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    caddy_key = "docker/caddy/agents/filesystem.caddy"
    assert caddy_key not in artifacts, (
        "Caddy snippet must NOT be generated for Shape-C agents (SC-EGRESS-NONE)"
    )


def test_sc_no_caddy_internal_in_compose():
    """SC-EGRESS-NONE: compose override must not list caddy_internal as a network entry."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    # Check that caddy_internal does not appear as a YAML network entry
    # (lines starting with optional spaces + "- caddy_internal")
    assert not any(
        line.strip() in ("- caddy_internal", "caddy_internal:") or
        (line.strip().startswith("- ") and "caddy_internal" in line and not line.strip().startswith("# "))
        for line in compose.splitlines()
    ), "caddy_internal must not be a network entry in Shape-C compose (SC-EGRESS-NONE)"


def test_sc_egress_not_empty_raises():
    """SC-EGRESS-NONE: codegen aborts if egress_allow is non-empty."""
    parsed = _base_manifest()
    parsed["spec"]["network"]["egress_allow"] = [{"host": "api.openai.com", "ports": [443]}]
    with pytest.raises(CodegenError) as exc_info:
        CodegenEngineShapeC(parsed, runtime="docker").render(dry_run=True)
    assert exc_info.value.code == "SC_egress_not_empty"


# ---------------------------------------------------------------------------
# 4. SC-NO-SECRETS — no group_add 2002, no secrets
# ---------------------------------------------------------------------------

def test_sc_no_group_add_2002_in_compose():
    """SC-NO-SECRETS: group_add 2002 must NOT appear as a YAML directive in compose output."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    # group_add must not appear as a YAML key (not in a comment)
    non_comment_lines = [
        line for line in compose.splitlines()
        if not line.strip().startswith("#")
    ]
    non_comment_text = "\n".join(non_comment_lines)
    assert "group_add" not in non_comment_text, (
        "group_add directive must not appear in Shape-C compose (SC-NO-SECRETS)"
    )
    assert "  - \"2002\"" not in non_comment_text, (
        "GID 2002 must not appear as YAML list entry in Shape-C compose (SC-NO-SECRETS)"
    )


def test_sc_secrets_with_gid2002_raises():
    """SC-NO-SECRETS: codegen aborts if spec.secrets is non-empty."""
    parsed = _base_manifest()
    parsed["spec"]["secrets"] = [{"name": "API_KEY", "source": "kms", "kms_path": "/tenant/acme-corp/key"}]
    with pytest.raises(CodegenError) as exc_info:
        CodegenEngineShapeC(parsed, runtime="docker").render(dry_run=True)
    assert exc_info.value.code == "SC_secrets_with_gid2002"


# ---------------------------------------------------------------------------
# 5. L9 hardened security context
# ---------------------------------------------------------------------------

def test_sc_read_only_true_in_compose():
    """L9: read_only: true must be present in compose."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "read_only: true" in compose


def test_sc_cap_drop_all_in_compose():
    """L9: cap_drop ALL must be present."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "cap_drop:" in compose
    assert "- ALL" in compose


def test_sc_no_new_privileges_in_compose():
    """L9: no-new-privileges:true must be present."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "no-new-privileges:true" in compose


def test_sc_run_as_user_10001_in_compose():
    """Laura §4.6: user must be 10001:10001 (dedicated non-root UID)."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "10001:10001" in compose


def test_sc_resource_limits_in_compose():
    """Laura §4.6: CPU and memory limits must be present."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "cpus:" in compose
    assert "memory:" in compose


# ---------------------------------------------------------------------------
# 6. Named-volume workspace mount (LAURA-FS-TM-008)
# ---------------------------------------------------------------------------

def test_sc_named_volume_in_compose():
    """Shape-C: tenant-namespaced volume name must appear in compose."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    expected_vol = _sc_volume_name("acme-corp", "filesystem")
    assert expected_vol in compose, (
        "Volume name %r must appear in compose (LAURA-FS-TM-008)" % expected_vol
    )


def test_sc_volume_definition_in_compose():
    """Shape-C: Docker volume definition must be declared in compose."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    # Must have a top-level 'volumes:' section with the volume definition
    assert "volumes:" in compose
    vol = _sc_volume_name("acme-corp", "filesystem")
    # Volume definition format: "  vol_name:\n    driver: local"
    assert ("%s:" % vol) in compose


# ---------------------------------------------------------------------------
# 7. tmpfs /tmp overlay (Laura §2.6.1 / §4.3)
# ---------------------------------------------------------------------------

def test_sc_tmpfs_tmp_in_compose():
    """Shape-C: /tmp tmpfs must appear in compose."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    compose = artifacts["docker/filesystem-compose.override.yml"]
    assert "tmpfs:" in compose
    assert "/tmp" in compose


# ---------------------------------------------------------------------------
# 8. SPIFFE shape marker in service_identities
# ---------------------------------------------------------------------------

def test_sc_spiffe_shape_c_in_service_identities():
    """Shape-C: service_identities fragment must carry shape: "c"."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    svcid = artifacts["service_identities.yaml.fragment"]
    assert 'shape: "c"' in svcid


def test_sc_spiffe_id_in_service_identities():
    """SPIFFE URI must be present in service_identities fragment."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    svcid = artifacts["service_identities.yaml.fragment"]
    assert "spiffe://yashigani.internal/agents/acme-corp/filesystem" in svcid


# ---------------------------------------------------------------------------
# 9. OPA policy content — per-tool authz (P9 / Laura §5)
# ---------------------------------------------------------------------------

def test_sc_opa_contains_readonly_tool_rules():
    """OPA policy must contain readonly tool set definition."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    assert "_fs_readonly_tools" in opa
    assert "read_file" in opa
    assert "list_directory" in opa


def test_sc_opa_contains_write_tool_rules():
    """OPA policy must contain write tool set definition."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    assert "_fs_write_tools" in opa
    assert "write_file" in opa


def test_sc_opa_readonly_posture_denies_writes():
    """OPA policy with readonly write_posture must have the deny comment, not an allow rule."""
    engine = CodegenEngineShapeC(_base_manifest(write_posture="readonly"), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    # readonly posture: the _gen_opa_write_rules produces a comment, not an allow rule
    assert "DENIED in readonly posture" in opa
    # Must NOT contain the readwrite allow block
    assert 'write_posture == "readwrite"' not in opa


def test_sc_opa_readwrite_posture_permits_writes():
    """OPA policy with readwrite write_posture must have write-tool allow rule."""
    parsed = _base_manifest(write_posture="readwrite")
    engine = CodegenEngineShapeC(parsed, runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    # readwrite posture: _gen_opa_write_rules emits an allow rule that references _fs_write_tools
    assert 'input.tool.name in _fs_write_tools' in opa
    # Must contain an actual allow if block (not just the deny_reason reference)
    assert "Write tools: PERMIT when write_posture=readwrite" in opa


def test_sc_opa_path_validation_rules_present():
    """OPA policy must contain path-arg validation (LAURA-FS-TM-001 / §5.1)."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    assert "_path_arg_safe" in opa
    assert '"../"' in opa or "\"../\"" in opa


def test_sc_opa_directory_tree_depth_cap_present():
    """OPA policy must contain directory_tree depth cap (§5.2)."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    assert "_directory_tree_safe" in opa
    assert "<= 5" in opa


def test_sc_opa_search_files_pattern_cap_present():
    """OPA policy must contain search_files pattern length cap (§5.3)."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    assert "_search_files_safe" in opa
    assert "<= 256" in opa


def test_sc_opa_list_allowed_directories_has_no_allow_rule():
    """list_allowed_directories must NOT have an allow rule (always denied)."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    opa = artifacts["opa/filesystem.rego"]
    # The deny reason must exist
    assert "fs_list_allowed_directories_denied" in opa


# ---------------------------------------------------------------------------
# 10. CodegenEngineShapeC rejects non-Shape-C manifests
# ---------------------------------------------------------------------------

def test_sc_engine_rejects_shape_a_manifest():
    """CodegenEngineShapeC must raise NOT_SHAPE_C for a Shape-A manifest."""
    parsed = {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {"name": "my-agent", "tenant_id": "acme-corp"},
        "spec": {
            "image": {"repository": "r", "tag": "v1", "digest": _FAKE_DIGEST},
            "mcp": {"posture": "mcp-a"},
        },
    }
    with pytest.raises(CodegenError) as exc_info:
        CodegenEngineShapeC(parsed, runtime="docker")
    assert exc_info.value.code == "NOT_SHAPE_C"


def test_sc_engine_rejects_invalid_runtime():
    """CodegenEngineShapeC must raise INVALID_RUNTIME for unknown runtimes."""
    with pytest.raises(CodegenError) as exc_info:
        CodegenEngineShapeC(_base_manifest(), runtime="invalid-runtime")
    assert exc_info.value.code == "INVALID_RUNTIME"


def test_sc_listen_port_raises():
    """SC: listen_port must be null for stdio shape."""
    parsed = _base_manifest()
    parsed["spec"]["mcp"]["exposes"]["listen_port"] = 8080
    with pytest.raises(CodegenError) as exc_info:
        CodegenEngineShapeC(parsed, runtime="docker").render(dry_run=True)
    assert exc_info.value.code == "SC_listen_port_on_stdio"


# ---------------------------------------------------------------------------
# 11. Artifact key inventory — Shape-C must not include caddy, Shape-A keys
# ---------------------------------------------------------------------------

def test_sc_artifact_keys_inventory():
    """Verify the expected artifact key set for Shape-C."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)

    expected_keys = {
        "docker/filesystem-compose.override.yml",
        "helm/yashigani/values-filesystem.yaml",
        "helm/yashigani/values-filesystem-networkpolicy.yaml",
        "helm/yashigani/templates/agents/filesystem-policy-exception.yaml",
        "service_identities.yaml.fragment",
        "pki_ownership-filesystem.sh",
        "opa/filesystem.rego",
        "tests/contracts/test_filesystem_shape_c_compose.py",
    }

    # Caddy snippet must NOT be present (SC-EGRESS-NONE)
    assert "docker/caddy/agents/filesystem.caddy" not in artifacts

    for key in expected_keys:
        assert key in artifacts, "Expected artifact key missing: %r" % key


# ---------------------------------------------------------------------------
# 12. Helm NetworkPolicy — SC-EGRESS-NONE has no Caddy allow
# ---------------------------------------------------------------------------

def test_sc_helm_networkpolicy_no_caddy_egress():
    """SC-EGRESS-NONE: Helm NetworkPolicy must not allow egress to Caddy."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    netpol = artifacts["helm/yashigani/values-filesystem-networkpolicy.yaml"]
    # No Caddy pod selector rule
    assert "app.kubernetes.io/name: caddy" not in netpol
    # The SC-EGRESS-NONE comment must be present
    assert "SC-EGRESS-NONE" in netpol


# ---------------------------------------------------------------------------
# 13. FS1 linter rules — storage.mounts validation
# ---------------------------------------------------------------------------

def test_fs1_hostpath_rejected_by_linter():
    """FS1: linter must reject hostPath mount type."""
    parsed = _base_manifest()
    parsed["spec"]["storage"]["mounts"][0]["type"] = "hostPath"
    result: LintResult = validate_manifest(parsed)
    codes = {e.rule for e in result.errors}
    assert "FS1_hostpath_blocked" in codes, (
        "Linter must reject hostPath mounts (FS1 / LAURA-FS-TM-002)"
    )


def test_fs1_dangerous_container_path_rejected():
    """FS1: linter must reject /etc as container_path."""
    parsed = _base_manifest()
    parsed["spec"]["storage"]["mounts"][0]["container_path"] = "/etc"
    result: LintResult = validate_manifest(parsed)
    codes = {e.rule for e in result.errors}
    assert "FS1_dangerous_container_path" in codes


def test_fs1_slash_container_path_rejected():
    """FS1: linter must reject / as container_path."""
    parsed = _base_manifest()
    parsed["spec"]["storage"]["mounts"][0]["container_path"] = "/"
    result: LintResult = validate_manifest(parsed)
    codes = {e.rule for e in result.errors}
    assert "FS1_dangerous_container_path" in codes


def test_fs1_volume_name_wrong_tenant_rejected():
    """FS1: linter must reject volume name with wrong tenant prefix."""
    parsed = _base_manifest()
    parsed["spec"]["storage"]["mounts"][0]["name"] = "ysg_fs_evil_corp_filesystem_workspace"
    result: LintResult = validate_manifest(parsed)
    codes = {e.rule for e in result.errors}
    assert "FS1_volume_name_wrong_tenant" in codes or "FS1_volume_name_not_tenant_namespaced" in codes


def test_fs1_valid_mount_passes_linter():
    """FS1: valid Shape-C storage.mounts must pass the linter."""
    parsed = _base_manifest()
    result: LintResult = validate_manifest(parsed)
    fs1_errors = [e for e in result.errors if e.rule.startswith("FS1")]
    assert fs1_errors == [], "Valid Shape-C manifest should pass FS1 linter rules"


def test_fs1_no_mounts_passes_linter():
    """FS1 is silent when spec.storage.mounts is absent (Shape-A manifests)."""
    parsed = {
        "apiVersion": "yashigani.io/v1alpha1",
        "kind": "AgentIntegration",
        "metadata": {"name": "my-agent", "tenant_id": "acme-corp"},
        "spec": {
            "image": {"repository": "r", "tag": "v1", "digest": _FAKE_DIGEST},
        },
    }
    result: LintResult = validate_manifest(parsed)
    fs1_errors = [e for e in result.errors if e.rule.startswith("FS1")]
    assert fs1_errors == [], "FS1 must be silent when storage.mounts is absent"


# ---------------------------------------------------------------------------
# 14. Helm values Shape-C specific content
# ---------------------------------------------------------------------------

def test_sc_helm_values_run_as_user_10001():
    """Laura §4.6: Helm values must specify runAsUser: 10001."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    values = artifacts["helm/yashigani/values-filesystem.yaml"]
    assert "runAsUser: 10001" in values


def test_sc_helm_values_no_supplemental_groups_2002():
    """SC-NO-SECRETS: Helm values must NOT include supplementalGroups: [2002]."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    values = artifacts["helm/yashigani/values-filesystem.yaml"]
    assert "supplementalGroups: [2002]" not in values


def test_sc_helm_values_tmpfs_emptydir():
    """Shape-C: Helm values must specify /tmp tmpfs emptyDir."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    values = artifacts["helm/yashigani/values-filesystem.yaml"]
    assert "tmpfs:" in values
    assert "/tmp" in values


def test_sc_helm_values_resource_limits():
    """Laura §4.6: Helm values must include resource limits."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    values = artifacts["helm/yashigani/values-filesystem.yaml"]
    assert "limits:" in values
    assert "cpu:" in values
    assert "memory:" in values


# ---------------------------------------------------------------------------
# 15. M9 manifest hash present in all artifacts
# ---------------------------------------------------------------------------

def test_sc_manifest_hash_in_all_artifacts():
    """M9 drift detection: .yashigani-manifest-hash must appear in all generated artifacts."""
    engine = CodegenEngineShapeC(_base_manifest(), runtime="docker")
    artifacts = engine.render(dry_run=True)
    for key, content in artifacts.items():
        assert ".yashigani-manifest-hash" in content, (
            "M9 drift-detection hash missing from artifact %r" % key
        )
