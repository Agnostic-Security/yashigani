"""
W3 — codegen engine tests (Shape A, v2.25.0 P1).

Security control proving tests (each MUST pass to gate shipping):
  C1  (SHIP-BLOCKER) Private-IP upstream aborts codegen.
  C3  (HIGH)         Duplicate (tenant_id, agent_id) aborts codegen.
  C10 (HIGH)         Injected caddy validator: pass + fail paths both work.
  M9  (MEDIUM)       Symlinked output path is refused.
  S6  (SHIP-BLOCKER) Shell fragment passes bash -n; shellcheck mock path.
  L9               Compose + Helm artifacts carry hardened security defaults.
  L3  (compose)    IPv6 disable sysctls present.
  L7  (compose)    depends_on with service_completed_successfully present.
  S7              group_add 2002 for kms-secret agents.
  P2               gateway-enforced-only forbidden for CONFIDENTIAL/RESTRICTED.

Additional tests:
  - Dry-run returns artifact dict without writing files.
  - Schema: per-user-credential is now a valid identity_propagation value.
  - Barrel imports: CodegenEngine, CodegenError, reset_codegen_registry.
  - Rootless Podman L1 gap annotation present.
  - OPA stub is fail-closed (deny-all default).
  - Caddy snippet: route namespaced /agents/{tenant}/{agent}, strip_prefix present.
  - pki_ownership fragment is bash-3.2-safe (no declare -A, no ${var,,}, no mapfile).
  - Kyverno PolicyException scoped to ringfence-init label.
  - service_identities entry includes SPIFFE URI.
  - M9: writes outside allowed root are refused.
  - Runtime validation: unknown runtime aborts.
  - reset_codegen_registry clears C3 state between sessions.
"""
from __future__ import annotations

import copy
import os
import pytest

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_VALID_DIGEST = "a" * 64
_VALID_DIGEST_SHA256 = "sha256:" + _VALID_DIGEST

_BASE_PARSED: dict = {
    "apiVersion": "yashigani.io/v1alpha1",
    "kind": "AgentIntegration",
    "metadata": {
        "name": "hermes-agent",
        "tenant_id": "acme-corp",
    },
    "spec": {
        "image": {
            "repository": "ghcr.io/acme/hermes",
            "tag": "2.0.0",
            "digest": _VALID_DIGEST_SHA256,
        },
        "model_egress": {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
        },
        "network": {
            "egress_allow": [
                {"host": "api.openai.com", "ports": [443]},
            ],
        },
    },
}


def _parsed_with(**overrides) -> dict:
    """Return a deep copy of _BASE_PARSED with spec overrides applied."""
    p = copy.deepcopy(_BASE_PARSED)
    spec = p.setdefault("spec", {})
    spec.update(overrides)
    return p


def _fresh_engine(parsed=None, runtime="docker", caddy_validator=None):
    """Return a CodegenEngine with a clean C3 registry."""
    from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
    reset_codegen_registry()
    p = parsed if parsed is not None else copy.deepcopy(_BASE_PARSED)
    return CodegenEngine(p, runtime, caddy_validator=caddy_validator)


# ---------------------------------------------------------------------------
# Barrel import tests
# ---------------------------------------------------------------------------

class TestBarrelImports:
    def test_codegen_engine_importable(self) -> None:
        from yashigani.manifest import CodegenEngine
        assert callable(CodegenEngine)

    def test_codegen_error_importable(self) -> None:
        from yashigani.manifest import CodegenError
        assert issubclass(CodegenError, ValueError)

    def test_reset_codegen_registry_importable(self) -> None:
        from yashigani.manifest import reset_codegen_registry
        assert callable(reset_codegen_registry)

    def test_codegen_engine_in_all(self) -> None:
        import yashigani.manifest as m
        assert "CodegenEngine" in m.__all__

    def test_codegen_error_in_all(self) -> None:
        import yashigani.manifest as m
        assert "CodegenError" in m.__all__

    def test_reset_in_all(self) -> None:
        import yashigani.manifest as m
        assert "reset_codegen_registry" in m.__all__


# ---------------------------------------------------------------------------
# C1 — private-IP upstream aborts codegen (SHIP-BLOCKER)
# ---------------------------------------------------------------------------

class TestC1PrivateUpstreamAborts:
    """C1 (SHIP-BLOCKER): any RFC1918/loopback/link-local upstream aborts codegen."""

    @pytest.mark.parametrize("host,desc", [
        ("10.0.0.1", "RFC1918 class A"),
        ("172.16.50.1", "RFC1918 class B"),
        ("192.168.1.100", "RFC1918 class C"),
        ("127.0.0.1", "loopback"),
        ("169.254.169.254", "AWS IMDS link-local"),
        ("::1", "IPv6 loopback"),
    ])
    def test_private_ip_in_egress_allow_aborts(self, host: str, desc: str) -> None:
        """Private IP in egress_allow must abort codegen with C1_private_upstream."""
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [{"host": host, "ports": [443]}]
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "%s (%s) was not rejected; got code=%s" % (host, desc, exc_info.value.code)
        )

    @pytest.mark.parametrize("base_url,desc", [
        ("http://10.0.0.1/v1", "RFC1918 model base_url"),
        ("http://127.0.0.1:11434/api", "loopback ollama"),
        ("http://169.254.169.254/latest", "IMDS metadata endpoint"),
    ])
    def test_private_ip_in_model_egress_base_url_aborts(self, base_url: str, desc: str) -> None:
        """Private IP in model_egress.base_url must abort codegen with C1_private_upstream."""
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = base_url
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "%s (%s) was not rejected; got code=%s" % (base_url, desc, exc_info.value.code)
        )

    def test_public_ip_upstream_passes(self) -> None:
        """Public upstream passes C1 check."""
        from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [{"host": "8.8.8.8", "ports": [443]}]
        engine = CodegenEngine(parsed, "docker")
        artifacts = engine.render(dry_run=True)
        assert artifacts  # no exception

    def test_hostname_upstream_passes(self) -> None:
        """Hostname (non-IP) upstream passes C1 check (DNS not resolved at codegen)."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        artifacts = _fresh_engine().render(dry_run=True)
        assert "docker/hermes-agent-compose.override.yml" in artifacts


# ---------------------------------------------------------------------------
# C3 — duplicate (tenant_id, agent_id) aborts codegen (HIGH)
# ---------------------------------------------------------------------------

class TestC3DuplicateAgentAborts:
    """C3 (HIGH): duplicate (tenant_id, agent_id) in the same session aborts codegen."""

    def test_duplicate_pair_aborts_second_call(self) -> None:
        """Second render with the same (tenant_id, agent_id) must abort."""
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        p = copy.deepcopy(_BASE_PARSED)
        # First call: succeeds
        e1 = CodegenEngine(p, "docker")
        e1.render(dry_run=True)
        # Second call: same pair, must abort
        e2 = CodegenEngine(copy.deepcopy(p), "docker")
        with pytest.raises(CodegenError) as exc_info:
            e2.render(dry_run=True)
        assert exc_info.value.code == "C3_duplicate_agent"

    def test_different_tenant_passes(self) -> None:
        """Different tenant_id with the same agent name passes C3."""
        from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
        reset_codegen_registry()
        p1 = copy.deepcopy(_BASE_PARSED)
        p1["metadata"]["tenant_id"] = "tenant-a"
        p2 = copy.deepcopy(_BASE_PARSED)
        p2["metadata"]["tenant_id"] = "tenant-b"
        CodegenEngine(p1, "docker").render(dry_run=True)
        CodegenEngine(p2, "docker").render(dry_run=True)  # should not raise

    def test_reset_registry_clears_c3_state(self) -> None:
        """reset_codegen_registry() clears C3 state so the same pair can be re-onboarded."""
        from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
        reset_codegen_registry()
        p = copy.deepcopy(_BASE_PARSED)
        CodegenEngine(p, "docker").render(dry_run=True)
        # After reset, same pair should succeed again
        reset_codegen_registry()
        CodegenEngine(copy.deepcopy(p), "docker").render(dry_run=True)  # no exception


# ---------------------------------------------------------------------------
# C10 — Caddy validator injectable (HIGH ship-gate)
# ---------------------------------------------------------------------------

class TestC10CaddyValidator:
    """C10: injected caddy validator — both pass and fail paths tested."""

    def test_injected_validator_pass_path(self) -> None:
        """C10: injected validator returning 0 allows codegen to complete."""
        def _pass_validator(caddyfile: str) -> int:
            assert "admin off" in caddyfile  # basic sanity
            return 0

        artifacts = _fresh_engine(caddy_validator=_pass_validator).render(dry_run=True)
        assert "docker/caddy/agents/hermes-agent.caddy" in artifacts

    def test_injected_validator_fail_path_aborts_codegen(self) -> None:
        """C10: injected validator returning non-zero aborts codegen."""
        from yashigani.manifest.codegen import CodegenError

        def _fail_validator(caddyfile: str) -> int:
            return 1

        with pytest.raises(CodegenError) as exc_info:
            _fresh_engine(caddy_validator=_fail_validator).render(dry_run=True)
        assert exc_info.value.code == "C10_caddy_validate_failed"

    def test_injected_validator_receives_snippet(self) -> None:
        """C10: validator callable receives the generated Caddy snippet."""
        received: list[str] = []

        def _capture_validator(caddyfile: str) -> int:
            received.append(caddyfile)
            return 0

        _fresh_engine(caddy_validator=_capture_validator).render(dry_run=True)
        assert len(received) == 1
        assert "hermes-agent" in received[0]

    def test_no_validator_absent_caddy_emits_warning(self, caplog) -> None:
        """
        C10: when no validator is injected and caddy binary is absent,
        the codegen SKIPS with a WARNING (not an error) and returns artifacts.
        """
        import shutil
        import unittest.mock as mock
        # Patch shutil.which to report caddy absent
        with mock.patch.object(shutil, "which", return_value=None):
            with caplog.at_level("WARNING", logger="yashigani.manifest.codegen"):
                artifacts = _fresh_engine(caddy_validator=None).render(dry_run=True)
        assert artifacts  # artifacts generated despite missing caddy
        assert any("caddy binary not found" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# M9 — symlinked output path refused (MEDIUM)
# ---------------------------------------------------------------------------

class TestM9SymlinkWriteRefused:
    """M9: writing through a symlinked path is refused."""

    def test_symlinked_output_path_refused(self, tmp_path) -> None:
        """
        M9: if the output destination is (or is under) a symlink, codegen refuses.

        Create a symlink in the output tree and attempt to write through it.
        """
        from yashigani.manifest.codegen import _safe_write, CodegenError

        # Create a real dir and a symlink target
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        sym_dir = tmp_path / "link_to_real"
        sym_dir.symlink_to(real_dir)

        dest = sym_dir / "output.txt"
        with pytest.raises(CodegenError) as exc_info:
            _safe_write(dest, "test content", tmp_path)
        assert exc_info.value.code == "M9_symlink_write"

    def test_write_outside_allowed_root_refused(self, tmp_path) -> None:
        """M9: writing outside the allowed root is refused."""
        from yashigani.manifest.codegen import _safe_write, CodegenError

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        # Path outside allowed root
        outside = tmp_path / "outside" / "file.txt"

        with pytest.raises(CodegenError) as exc_info:
            _safe_write(outside, "test", allowed)
        assert exc_info.value.code == "M9_path_traversal"

    def test_write_inside_allowed_root_succeeds(self, tmp_path) -> None:
        """M9: writing inside the allowed root with no symlinks succeeds."""
        from yashigani.manifest.codegen import _safe_write

        allowed = tmp_path / "allowed"
        allowed.mkdir()
        dest = allowed / "subdir" / "output.txt"
        _safe_write(dest, "hello codegen", allowed)
        assert dest.read_text() == "hello codegen"

    def test_dry_run_does_not_write_files(self, tmp_path) -> None:
        """Dry-run must not write any files to disk."""
        artifacts = _fresh_engine().render(output_root=tmp_path, dry_run=True)
        # No files should have been written
        written = list(tmp_path.rglob("*"))
        assert written == [], "dry_run wrote files: %s" % written
        assert len(artifacts) > 0

    def test_real_run_writes_files(self, tmp_path) -> None:
        """Real run writes files under output_root."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        engine = _fresh_engine()
        artifacts = engine.render(output_root=tmp_path, dry_run=False)
        for rel_path in artifacts:
            dest = tmp_path / rel_path
            assert dest.is_file(), "Expected file not found: %s" % dest
            assert dest.read_text() == artifacts[rel_path]


# ---------------------------------------------------------------------------
# S6 — shell fragment bash-3.2 safety (SHIP-BLOCKER)
# ---------------------------------------------------------------------------

class TestS6ShellFragmentSafety:
    """S6 (SHIP-BLOCKER): pki_ownership shell fragment is bash-3.2 safe."""

    def test_pki_fragment_no_declare_a(self) -> None:
        """S6: pki_ownership fragment must not use declare -A (bash 3.2 incompatible)."""
        artifacts = _fresh_engine().render(dry_run=True)
        key = [k for k in artifacts if k.startswith("pki_ownership")][0]
        # Check only non-comment lines
        lines = [
            line for line in artifacts[key].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        executable_content = "\n".join(lines)
        assert "declare -A" not in executable_content, (
            "declare -A found in executable pki_ownership fragment lines (S6): %s" % executable_content
        )

    def test_pki_fragment_no_bash4_lowercase(self) -> None:
        """S6: pki_ownership fragment must not use ${var,,} (bash 4+ only)."""
        artifacts = _fresh_engine().render(dry_run=True)
        key = [k for k in artifacts if k.startswith("pki_ownership")][0]
        # Only check executable lines (not comments)
        lines = [
            line for line in artifacts[key].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        executable_content = "\n".join(lines)
        import re
        assert not re.search(r"\$\{[a-zA-Z_][a-zA-Z0-9_]*,,\}", executable_content), (
            "bash 4+ ${var,,} found in pki_ownership executable fragment (S6)"
        )

    def test_pki_fragment_no_mapfile(self) -> None:
        """S6: pki_ownership fragment must not use mapfile (bash 4+ only)."""
        artifacts = _fresh_engine().render(dry_run=True)
        key = [k for k in artifacts if k.startswith("pki_ownership")][0]
        # Only check executable lines (not comments)
        lines = [
            line for line in artifacts[key].splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        executable_content = "\n".join(lines)
        assert "mapfile" not in executable_content, (
            "mapfile found in executable pki_ownership fragment lines (S6): %s" % executable_content
        )

    def test_pki_fragment_passes_bash_n(self) -> None:
        """S6: pki_ownership fragment must pass bash -n syntax check."""
        import shutil
        import subprocess
        artifacts = _fresh_engine().render(dry_run=True)
        key = [k for k in artifacts if k.startswith("pki_ownership")][0]
        content = artifacts[key]

        bash_bin = shutil.which("bash")
        if bash_bin is None:
            pytest.skip("bash not available")

        import tempfile
        fd, tmp = tempfile.mkstemp(suffix=".sh")
        try:
            os.write(fd, content.encode("utf-8"))
            os.close(fd)
            result = subprocess.run(
                [bash_bin, "-n", tmp],
                capture_output=True,
                timeout=10,
            )
            assert result.returncode == 0, (
                "bash -n failed on pki_ownership fragment (S6): %s" % result.stderr.decode()
            )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def test_s6_validation_runs_without_error(self) -> None:
        """S6: _validate_shell_fragment must not raise for a valid fragment."""
        from yashigani.manifest.codegen import _validate_shell_fragment
        valid_fragment = (
            "#!/bin/sh\n"
            "PKI_OWNER_ACME_HERMES=\"acme-corp:hermes-agent:agents/acme-corp/hermes-agent\"\n"
            "export PKI_OWNER_ACME_HERMES\n"
        )
        # Should not raise
        _validate_shell_fragment(valid_fragment, "test-fragment")


# ---------------------------------------------------------------------------
# L9 — hardened security defaults in generated artifacts
# ---------------------------------------------------------------------------

class TestL9HardenedDefaults:
    """L9: generated artifacts carry hardened K8s/Compose security defaults."""

    def test_compose_no_new_privileges(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "no-new-privileges:true" in compose

    def test_compose_cap_drop_all(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "cap_drop:" in compose
        assert "- ALL" in compose

    def test_compose_read_only(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "read_only: true" in compose

    def test_helm_run_as_non_root(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "runAsNonRoot: true" in values

    def test_helm_no_privilege_escalation(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "allowPrivilegeEscalation: false" in values

    def test_helm_read_only_root_filesystem(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "readOnlyRootFilesystem: true" in values

    def test_helm_drop_all_caps(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "drop:" in values
        assert "- ALL" in values

    def test_helm_seccomp_runtime_default(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "RuntimeDefault" in values


# ---------------------------------------------------------------------------
# L3 — IPv6 default-deny sysctls
# ---------------------------------------------------------------------------

class TestL3IPv6DefaultDeny:
    """L3 (compose): IPv6 disable sysctls must be present."""

    def test_compose_ipv6_disable_all(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "net.ipv6.conf.all.disable_ipv6: 1" in compose

    def test_compose_ipv6_disable_default(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "net.ipv6.conf.default.disable_ipv6: 1" in compose


# ---------------------------------------------------------------------------
# L7 — depends_on with service_completed_successfully
# ---------------------------------------------------------------------------

class TestL7DependsOn:
    """L7 (compose): depends_on ringfence-init with service_completed_successfully."""

    def test_compose_depends_on_ringfence_init(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "depends_on:" in compose
        assert "ringfence-init-hermes-agent:" in compose
        assert "condition: service_completed_successfully" in compose


# ---------------------------------------------------------------------------
# S7 — group_add 2002 for kms-secret agents
# ---------------------------------------------------------------------------

class TestS7GroupAdd:
    """S7: group_add 2002 (supplementalGroups in K8s) for agents with kms secrets."""

    def test_compose_group_add_for_kms_agent(self) -> None:
        """Compose override gets group_add 2002 when agent has kms secrets."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["secrets"] = [
            {"name": "api-key", "source": "kms", "kms_path": "/tenant/acme-corp/api-key"}
        ]
        engine = _fresh_engine(parsed=parsed)
        artifacts = engine.render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "group_add:" in compose
        assert '"2002"' in compose

    def test_helm_supplemental_groups_for_kms_agent(self) -> None:
        """Helm values get supplementalGroups: [2002] when agent has kms secrets."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["secrets"] = [
            {"name": "api-key", "source": "kms", "kms_path": "/tenant/acme-corp/api-key"}
        ]
        engine = _fresh_engine(parsed=parsed)
        artifacts = engine.render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "supplementalGroups: [2002]" in values

    def test_compose_no_group_add_for_non_kms_agent(self) -> None:
        """No group_add when agent has no kms secrets."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "group_add:" not in compose


# ---------------------------------------------------------------------------
# Caddy snippet: C1 path structure + C3 namespace
# ---------------------------------------------------------------------------

class TestCaddySnippetShape:
    """Caddy snippet structure: C1 uri strip_prefix, C3 namespaced route."""

    def test_caddy_route_namespaced(self) -> None:
        """C3: Caddy route must be namespaced /agents/{tenant_id}/{agent_id}/."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "/agents/acme-corp/hermes-agent" in caddy

    def test_caddy_strip_prefix(self) -> None:
        """C1: Caddy snippet must use uri strip_prefix for path canonicalisation."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "uri strip_prefix" in caddy

    def test_caddy_no_header_upstream(self) -> None:
        """C1: Caddy snippet must not source upstreams from request headers."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "{header." not in caddy
        assert "{query." not in caddy

    def test_caddy_upstream_is_hardcoded(self) -> None:
        """C1: upstream is hardcoded from manifest base_url, not dynamic."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "api.openai.com" in caddy

    def test_caddy_carries_manifest_hash(self) -> None:
        """M9: Caddy snippet carries .yashigani-manifest-hash comment."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert ".yashigani-manifest-hash:" in caddy

    def test_caddy_carries_ysg_runtime(self) -> None:
        """L10: Caddy snippet carries YSG_RUNTIME comment."""
        artifacts = _fresh_engine().render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "YSG_RUNTIME: docker" in caddy


# ---------------------------------------------------------------------------
# Rootless Podman L1 gap annotation
# ---------------------------------------------------------------------------

class TestRootlessPodmanAnnotation:
    """L10/HIGH-01: rootless Podman triggers L1-gap annotation in all artifacts."""

    def test_compose_carries_rootless_gap_note(self) -> None:
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        engine = _fresh_engine(runtime="podman-rootless")
        artifacts = engine.render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "ROOTLESS-PODMAN-L1-GAP" in compose

    def test_values_carries_rootless_gap_note(self) -> None:
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        engine = _fresh_engine(runtime="podman-rootless")
        artifacts = engine.render(dry_run=True)
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "ROOTLESS-PODMAN-L1-GAP" in values

    def test_k8s_runtime_no_rootless_note(self) -> None:
        """k8s runtime must NOT carry the rootless L1 gap note."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        engine = _fresh_engine(runtime="k8s")
        artifacts = engine.render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "ROOTLESS-PODMAN-L1-GAP" not in compose


# ---------------------------------------------------------------------------
# OPA stub: fail-closed
# ---------------------------------------------------------------------------

class TestOpaSub:
    """OPA stub is fail-closed (deny-all default)."""

    def test_opa_stub_deny_all_default(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        opa = artifacts["opa/hermes-agent.rego"]
        assert "default allow := false" in opa

    def test_opa_stub_stub_comment(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        opa = artifacts["opa/hermes-agent.rego"]
        assert "STUB" in opa

    def test_opa_stub_package_name(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        opa = artifacts["opa/hermes-agent.rego"]
        assert "package yashigani.agents.hermes_agent" in opa


# ---------------------------------------------------------------------------
# Kyverno PolicyException
# ---------------------------------------------------------------------------

class TestKyvernoPolicyException:
    """Kyverno PolicyException scoped to ringfence-init label (L1)."""

    def test_kyverno_exception_scoped_to_ringfence_init(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        kyverno = artifacts["helm/yashigani/templates/agents/hermes-agent-policy-exception.yaml"]
        assert "yashigani.io/ringfence-init" in kyverno
        assert '"true"' in kyverno

    def test_kyverno_exception_kind_correct(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        kyverno = artifacts["helm/yashigani/templates/agents/hermes-agent-policy-exception.yaml"]
        assert "kind: PolicyException" in kyverno

    def test_kyverno_exception_agent_label(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        kyverno = artifacts["helm/yashigani/templates/agents/hermes-agent-policy-exception.yaml"]
        assert "hermes-agent" in kyverno
        assert "acme-corp" in kyverno


# ---------------------------------------------------------------------------
# service_identities SPIFFE URI
# ---------------------------------------------------------------------------

class TestServiceIdentities:
    """service_identities entry includes SPIFFE URI."""

    def test_spiffe_uri_in_service_identity(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        svcid = artifacts["service_identities.yaml.fragment"]
        assert "spiffe://yashigani.internal/agents/acme-corp/hermes-agent" in svcid

    def test_manifest_hash_in_service_identity(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        svcid = artifacts["service_identities.yaml.fragment"]
        assert "manifest_hash:" in svcid

    def test_shape_a_tag(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        svcid = artifacts["service_identities.yaml.fragment"]
        assert 'shape: "a"' in svcid


# ---------------------------------------------------------------------------
# Runtime validation
# ---------------------------------------------------------------------------

class TestRuntimeValidation:
    """Invalid runtime aborts CodegenEngine construction."""

    def test_invalid_runtime_raises(self) -> None:
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        with pytest.raises(CodegenError) as exc_info:
            CodegenEngine(copy.deepcopy(_BASE_PARSED), "unknown-runtime")
        assert exc_info.value.code == "INVALID_RUNTIME"

    def test_valid_runtimes_accepted(self) -> None:
        from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry, VALID_RUNTIMES
        for rt in sorted(VALID_RUNTIMES):
            reset_codegen_registry()
            engine = CodegenEngine(copy.deepcopy(_BASE_PARSED), rt)
            artifacts = engine.render(dry_run=True)
            assert artifacts, "runtime %s produced no artifacts" % rt


# ---------------------------------------------------------------------------
# Dry-run: no file writes
# ---------------------------------------------------------------------------

class TestDryRun:
    """Dry-run returns artifact dict without writing files."""

    def test_dry_run_returns_artifact_dict(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        assert isinstance(artifacts, dict)
        assert len(artifacts) > 0

    def test_dry_run_artifact_keys(self) -> None:
        """All expected artifact keys are present in dry-run output."""
        artifacts = _fresh_engine().render(dry_run=True)
        expected_keys = [
            "docker/hermes-agent-compose.override.yml",
            "helm/yashigani/values-hermes-agent.yaml",
            "helm/yashigani/values-hermes-agent-networkpolicy.yaml",
            "helm/yashigani/templates/agents/hermes-agent-policy-exception.yaml",
            "docker/caddy/agents/hermes-agent.caddy",
            "service_identities.yaml.fragment",
            "pki_ownership-hermes-agent.sh",
            "opa/hermes-agent.rego",
            "tests/contracts/test_hermes-agent_compose.py",
            "tests/contracts/test_hermes-agent_helm.py",
        ]
        for key in expected_keys:
            assert key in artifacts, "missing artifact key: %s" % key

    def test_dry_run_missing_output_root_ok(self) -> None:
        """Dry-run succeeds without an output_root."""
        artifacts = _fresh_engine().render(dry_run=True)
        assert artifacts

    def test_real_run_without_output_root_raises(self) -> None:
        """Real run without output_root raises CodegenError."""
        from yashigani.manifest.codegen import CodegenError, reset_codegen_registry
        reset_codegen_registry()
        engine = _fresh_engine()
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=False)
        assert exc_info.value.code == "MISSING_OUTPUT_ROOT"


# ---------------------------------------------------------------------------
# M9 — manifest hash and runtime comment in ALL artifacts
# ---------------------------------------------------------------------------

class TestM9DriftDetection:
    """M9: all artifacts carry .yashigani-manifest-hash and YSG_RUNTIME comments."""

    def test_all_artifacts_carry_manifest_hash(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        for path, content in artifacts.items():
            assert ".yashigani-manifest-hash:" in content, (
                "artifact %s is missing .yashigani-manifest-hash (M9)" % path
            )

    def test_all_artifacts_carry_runtime_tag(self) -> None:
        artifacts = _fresh_engine().render(dry_run=True)
        for path, content in artifacts.items():
            assert "YSG_RUNTIME:" in content, (
                "artifact %s is missing YSG_RUNTIME (L10)" % path
            )


# ---------------------------------------------------------------------------
# P2 — gateway-enforced-only forbidden for CONFIDENTIAL/RESTRICTED
# ---------------------------------------------------------------------------

class TestP2GatewayEnforcedOnly:
    """P2: gateway-enforced-only is forbidden for CONFIDENTIAL/RESTRICTED sensitivity."""

    def _validate(self, parsed: dict):
        from yashigani.manifest import validate_manifest
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            return validate_manifest(parsed)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_gateway_enforced_only_confidential_rejected(self) -> None:
        """gateway-enforced-only + CONFIDENTIAL ceiling must fail with P2 error."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-enforced-only",
        }
        parsed["spec"]["audit"] = {"sensitivity_ceiling": "CONFIDENTIAL"}
        result = self._validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "P2_gateway_enforced_only_forbidden" in rules

    def test_gateway_enforced_only_restricted_rejected(self) -> None:
        """gateway-enforced-only + RESTRICTED ceiling must fail with P2 error."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-enforced-only",
        }
        parsed["spec"]["audit"] = {"sensitivity_ceiling": "RESTRICTED"}
        result = self._validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "P2_gateway_enforced_only_forbidden" in rules

    def test_gateway_enforced_only_absent_ceiling_defaults_confidential(self) -> None:
        """gateway-enforced-only + absent ceiling defaults to CONFIDENTIAL — P2 fires."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-enforced-only",
        }
        # No spec.audit.sensitivity_ceiling — defaults to CONFIDENTIAL per L-01
        result = self._validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "P2_gateway_enforced_only_forbidden" in rules

    def test_gateway_enforced_only_public_passes(self) -> None:
        """gateway-enforced-only + PUBLIC ceiling is allowed (P2 only blocks high sensitivity)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-enforced-only",
        }
        parsed["spec"]["audit"] = {"sensitivity_ceiling": "PUBLIC"}
        result = self._validate(parsed)
        p2_errors = [e for e in result.errors if e.rule == "P2_gateway_enforced_only_forbidden"]
        assert not p2_errors, "P2 fired for PUBLIC ceiling: %s" % p2_errors

    def test_gateway_enforced_only_internal_passes(self) -> None:
        """gateway-enforced-only + INTERNAL ceiling is allowed."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-enforced-only",
        }
        parsed["spec"]["audit"] = {"sensitivity_ceiling": "INTERNAL"}
        result = self._validate(parsed)
        p2_errors = [e for e in result.errors if e.rule == "P2_gateway_enforced_only_forbidden"]
        assert not p2_errors

    def test_gateway_signed_jwt_confidential_passes(self) -> None:
        """gateway-signed-jwt + CONFIDENTIAL is the expected v1 pattern — no P2."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {
            "identity_propagation": "gateway-signed-jwt",
        }
        parsed["spec"]["audit"] = {"sensitivity_ceiling": "CONFIDENTIAL"}
        result = self._validate(parsed)
        p2_errors = [e for e in result.errors if e.rule == "P2_gateway_enforced_only_forbidden"]
        assert not p2_errors


# ---------------------------------------------------------------------------
# Schema: per-user-credential enum value
# ---------------------------------------------------------------------------

class TestSchemaIdentityPropagation:
    """Schema: per-user-credential is now a valid identity_propagation value."""

    def test_per_user_credential_passes_schema(self) -> None:
        """per-user-credential must be a valid enum value in the schema."""
        from yashigani.manifest.schema import validate_schema
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {"identity_propagation": "per-user-credential"}
        errors = validate_schema(parsed)
        schema_mcp_errors = [e for e in errors if "identity_propagation" in e]
        assert not schema_mcp_errors, (
            "per-user-credential rejected by schema: %s" % schema_mcp_errors
        )

    def test_gateway_signed_jwt_passes_schema(self) -> None:
        """gateway-signed-jwt must still pass schema (regression)."""
        from yashigani.manifest.schema import validate_schema
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {"identity_propagation": "gateway-signed-jwt"}
        errors = validate_schema(parsed)
        schema_mcp_errors = [e for e in errors if "identity_propagation" in e]
        assert not schema_mcp_errors

    def test_gateway_enforced_only_passes_schema(self) -> None:
        """gateway-enforced-only passes schema (linter rejects, not schema)."""
        from yashigani.manifest.schema import validate_schema
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {"identity_propagation": "gateway-enforced-only"}
        errors = validate_schema(parsed)
        schema_mcp_errors = [e for e in errors if "identity_propagation" in e]
        assert not schema_mcp_errors

    def test_invalid_propagation_fails_schema(self) -> None:
        """An unknown identity_propagation value fails schema validation."""
        from yashigani.manifest.schema import validate_schema
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["mcp"] = {"identity_propagation": "bogus-mode"}
        errors = validate_schema(parsed)
        assert any("identity_propagation" in e for e in errors), (
            "bogus-mode was not rejected by schema: %s" % errors
        )


# ---------------------------------------------------------------------------
# Compose + Helm parity (§3.5)
# ---------------------------------------------------------------------------

class TestComposeHelmParity:
    """§3.5: compose and helm artifacts must have parity on key fields."""

    def test_compose_and_helm_same_image_repo(self) -> None:
        """Same image repository in compose and helm values."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert "ghcr.io/acme/hermes" in compose
        assert "ghcr.io/acme/hermes" in values

    def test_compose_and_helm_same_image_digest(self) -> None:
        """Same image digest in compose and helm values."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        values = artifacts["helm/yashigani/values-hermes-agent.yaml"]
        assert _VALID_DIGEST_SHA256 in compose
        assert _VALID_DIGEST_SHA256 in values
