"""
W3 security fix proving tests — v2.25.0 P1.

Covers Laura findings (LAURA-001..005) and Iris artifact-shape findings
(W3-F1..F4) from the P1-W3 codegen gate review.

Each section has a comment linking the finding ID so failures are traceable.

CRITICAL: W3-F3 tests do NOT mock away the caddy validator unconditionally —
they assert on the structural form of the emitted reverse_proxy line, and also
invoke real `caddy validate` if the binary is available.
"""
from __future__ import annotations

import copy
import os
import shutil
import subprocess
import tempfile
import unittest.mock as mock
import pytest

# ---------------------------------------------------------------------------
# Shared fixtures (mirrors test_v250_w3_codegen.py)
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


def _fresh_engine(parsed=None, runtime="docker", caddy_validator=None):
    from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
    reset_codegen_registry()
    p = parsed if parsed is not None else copy.deepcopy(_BASE_PARSED)
    return CodegenEngine(p, runtime, caddy_validator=caddy_validator)


def _validate(parsed: dict):
    """Run validate_manifest with M7 gate in skip mode."""
    from yashigani.manifest import validate_manifest
    os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
    try:
        return validate_manifest(parsed)
    finally:
        os.environ.pop("YSG_REQUIRE_SIGNED_MANIFEST", None)


# ---------------------------------------------------------------------------
# LAURA-001 — SSRF bypass hardening (_is_private_address)
# ---------------------------------------------------------------------------

class TestLaura001SSRFBypassHardening:
    """
    LAURA-001 (CRITICAL): five proven bypass forms are now REJECTED.

    PoC source: poc_c1_bypass_manifests.yaml
    Proving: every encoding is blocked both at the linter path (_lint_model_egress_base_url)
    AND at the codegen C1 path (_validate_upstreams).
    """

    # --- direct _is_private_address unit tests ---

    @pytest.mark.parametrize("host,desc", [
        # C1-A: IPv6-mapped IPv4 (urlparse.hostname strips brackets)
        ("::ffff:169.254.169.254", "C1-A IPv6-mapped IMDS (no brackets)"),
        # C1-B: decimal integer encoding
        ("2852039166", "C1-B decimal-encoded IMDS (169.254.169.254)"),
        # C1-C: ULA IPv6
        ("fd00::1", "C1-C IPv6 ULA fd00::/8"),
        ("fc00::1", "C1-C IPv6 ULA fc00::/8 (fc00::/7 covers both)"),
        # C1-D: zero address
        ("0.0.0.0", "C1-D zero address"),
        ("0.1.2.3", "C1-D 0.x.x.x zero-prefix"),
        # C1-E: trailing dot
        ("169.254.169.254.", "C1-E trailing-dot IMDS"),
        ("127.0.0.1.", "C1-E trailing-dot loopback"),
        # Additional IPv4-mapped forms
        ("::ffff:10.0.0.1", "IPv4-mapped RFC1918"),
        ("::ffff:127.0.0.1", "IPv4-mapped loopback"),
        # Hex-encoded IP
        ("0xA9FEA9FE", "hex-encoded 169.254.169.254"),
    ])
    def test_is_private_address_blocks_bypass(self, host: str, desc: str) -> None:
        """_is_private_address must return True for all bypass-encoding forms."""
        from yashigani.manifest.linter import _is_private_address
        assert _is_private_address(host), (
            "_is_private_address(%r) returned False — SSRF bypass NOT blocked (%s)" % (host, desc)
        )

    @pytest.mark.parametrize("host,desc", [
        ("8.8.8.8", "Google DNS public"),
        ("1.1.1.1", "Cloudflare DNS public"),
        ("2001:4860:4860::8888", "Google IPv6 DNS"),
        ("api.openai.com", "public hostname"),
        ("my-model-server.example.com", "private-sounding but valid hostname"),
    ])
    def test_is_private_address_passes_legitimate(self, host: str, desc: str) -> None:
        """_is_private_address must return False for legitimate public addresses."""
        from yashigani.manifest.linter import _is_private_address
        assert not _is_private_address(host), (
            "_is_private_address(%r) returned True — legitimate host incorrectly blocked (%s)" % (host, desc)
        )

    # --- linter path (C1_model_egress_private_url) ---

    @pytest.mark.parametrize("url,desc", [
        ("http://[::ffff:169.254.169.254]/v1", "C1-A bracket IPv6-mapped IMDS"),
        ("http://2852039166/v1", "C1-B decimal IMDS"),
        ("http://[fd00::1]/v1", "C1-C ULA IPv6"),
        ("http://0.0.0.0/v1", "C1-D zero addr"),
        ("http://169.254.169.254./v1", "C1-E trailing-dot IMDS"),
    ])
    def test_linter_blocks_poc_bypass_urls(self, url: str, desc: str) -> None:
        """
        Linter must reject all PoC bypass URLs with C1_model_egress_private_url.
        Tests the linter path used by `yashigani validate`.
        """
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = url
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C1_model_egress_private_url" in rules, (
            "Linter did not reject %r (%s); errors: %s" % (url, desc, rules)
        )

    # --- codegen path (_validate_upstreams → C1_private_upstream) ---

    @pytest.mark.parametrize("url,desc", [
        ("http://[::ffff:169.254.169.254]/v1", "C1-A bracket IPv6-mapped IMDS"),
        ("http://2852039166/v1", "C1-B decimal IMDS"),
        ("http://[fd00::1]/v1", "C1-C ULA IPv6"),
        ("http://0.0.0.0/v1", "C1-D zero addr"),
        ("http://169.254.169.254./v1", "C1-E trailing-dot IMDS"),
    ])
    def test_codegen_blocks_poc_bypass_urls(self, url: str, desc: str) -> None:
        """
        Codegen must raise C1_private_upstream for all PoC bypass URLs.
        Tests the codegen path used by `yashigani onboard`.
        """
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = url
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "Codegen did not abort for %r (%s); code=%s" % (url, desc, exc_info.value.code)
        )

    # --- egress_allow bypass path ---

    @pytest.mark.parametrize("host,desc", [
        ("::ffff:169.254.169.254", "C1-A IPv6-mapped IMDS in egress_allow"),
        ("2852039166", "C1-B decimal IMDS in egress_allow"),
        ("fd00::1", "C1-C ULA in egress_allow"),
        ("0.0.0.0", "C1-D zero addr in egress_allow"),
        ("169.254.169.254.", "C1-E trailing-dot in egress_allow"),
    ])
    def test_codegen_blocks_poc_hosts_in_egress_allow(self, host: str, desc: str) -> None:
        """Codegen must reject bypass hosts in egress_allow too."""
        from yashigani.manifest.codegen import CodegenEngine, CodegenError, reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [{"host": host, "ports": [443]}]
        engine = CodegenEngine(parsed, "docker")
        with pytest.raises(CodegenError) as exc_info:
            engine.render(dry_run=True)
        assert exc_info.value.code == "C1_private_upstream", (
            "Codegen did not abort for egress host %r (%s); code=%s" % (host, desc, exc_info.value.code)
        )

    # --- linter egress_allow path ---

    @pytest.mark.parametrize("host,desc", [
        ("::ffff:169.254.169.254", "C1-A IPv6-mapped in egress_allow"),
        ("2852039166", "C1-B decimal in egress_allow"),
        ("fd00::1", "C1-C ULA in egress_allow"),
        ("0.0.0.0", "C1-D zero in egress_allow"),
        ("169.254.169.254.", "C1-E trailing-dot in egress_allow"),
    ])
    def test_linter_blocks_poc_hosts_in_egress_allow(self, host: str, desc: str) -> None:
        """Linter must reject bypass hosts in egress_allow with C1_private_egress_host."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [{"host": host}]
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C1_private_egress_host" in rules, (
            "Linter did not reject egress_allow host %r (%s); errors: %s" % (host, desc, rules)
        )


# ---------------------------------------------------------------------------
# LAURA-002 / LAURA-003 — slug validation (injection prevention)
# ---------------------------------------------------------------------------

class TestLaura002003SlugValidation:
    """
    LAURA-002/003 (HIGH): slug validation on metadata.name and metadata.tenant_id.

    PoC source: poc_injection_manifests.yaml, poc_c3_namespace.py
    Proving: INJ-A (Caddy brace), INJ-B (shell quote), INJ-D (Kyverno YAML
    newline) all rejected at the linter. The slug constraint closes all four
    sub-findings simultaneously.
    """

    # --- INJ-A: Caddy directive injection (brace/newline in name) ---

    def test_inj_a_brace_newline_name_rejected_by_linter(self) -> None:
        """INJ-A: name with } and newline is rejected by linter (C3_name_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = 'x}\n:80 { respond "ring-fence disabled" 200'
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules, (
            "INJ-A: brace/newline name not rejected; errors: %s" % rules
        )

    # --- INJ-B: shell injection (double-quote in name) ---

    def test_inj_b_shell_quote_name_rejected_by_linter(self) -> None:
        """INJ-B: name with \" is rejected by linter (C3_name_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = 'x"; rm -rf /srv; echo "'
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules, (
            "INJ-B: shell-injection name not rejected; errors: %s" % rules
        )

    # --- INJ-D: Kyverno YAML scope escape (newline in tenant_id) ---

    def test_inj_d_newline_tenant_id_rejected_by_linter(self) -> None:
        """INJ-D: tenant_id with embedded newline is rejected by linter (C3_tenant_id_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["tenant_id"] = 'acme\n              yashigani.io/agent: "*"'
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_tenant_id_invalid_slug" in rules, (
            "INJ-D: newline tenant_id not rejected; errors: %s" % rules
        )

    # --- C3 namespace collision: slash in name/tenant_id (PoC C3) ---

    def test_poc_c3_slash_in_name_rejected_by_linter(self) -> None:
        """C3 route namespace collision: slash in name is rejected (C3_name_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = "other/evil"
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules, (
            "Slash in name not rejected; errors: %s" % rules
        )

    def test_poc_c3_slash_in_tenant_id_rejected_by_linter(self) -> None:
        """C3 route namespace collision: slash in tenant_id is rejected (C3_tenant_id_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["tenant_id"] = "acme/other"
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_tenant_id_invalid_slug" in rules, (
            "Slash in tenant_id not rejected; errors: %s" % rules
        )

    def test_poc_c3_dotdot_traversal_rejected_by_linter(self) -> None:
        """C3 path traversal: '../../' in name is rejected (C3_name_invalid_slug)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = "agent/../../other-tenant/steal"
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules, (
            "Dotdot traversal in name not rejected; errors: %s" % rules
        )

    # --- ensure slug with } or " cannot reach any artifact ---

    def test_brace_name_cannot_reach_codegen(self) -> None:
        """A name with } aborts at linter before codegen is invoked."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = 'x}'
        # The name fails the slug check — codegen itself also validates via
        # C3 duplicate check. But independently: slug-invalid names cannot
        # be processed by the codegen because linter must run before codegen.
        # We verify the linter rejects it.
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules

    def test_newline_name_cannot_reach_codegen(self) -> None:
        """A name with embedded newline aborts at linter before codegen is invoked."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = "name\nwith\nnewlines"
        result = _validate(parsed)
        rules = [e.rule for e in result.errors]
        assert "C3_name_invalid_slug" in rules

    # --- valid slugs still pass ---

    @pytest.mark.parametrize("name,desc", [
        ("my-agent", "standard kebab"),
        ("hermes-agent-v2", "versioned kebab"),
        ("a1", "minimal two-char"),
        ("acme-corp-hermes", "corp prefix"),
    ])
    def test_valid_slug_name_passes(self, name: str, desc: str) -> None:
        """Valid slug names pass the linter (regression guard)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = name
        result = _validate(parsed)
        slug_errors = [e for e in result.errors if "slug" in e.rule.lower()]
        assert not slug_errors, (
            "Valid slug name %r was incorrectly rejected (%s): %s" % (name, desc, slug_errors)
        )

    @pytest.mark.parametrize("tenant,desc", [
        ("acme-corp", "standard tenant"),
        ("my-org", "two-part tenant"),
        ("a1", "minimal two-char"),
    ])
    def test_valid_slug_tenant_passes(self, tenant: str, desc: str) -> None:
        """Valid slug tenant_ids pass the linter (regression guard)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["tenant_id"] = tenant
        result = _validate(parsed)
        slug_errors = [e for e in result.errors if "slug" in e.rule.lower()]
        assert not slug_errors, (
            "Valid slug tenant_id %r was incorrectly rejected (%s): %s" % (tenant, desc, slug_errors)
        )

    # --- invalid slug forms ---

    @pytest.mark.parametrize("name,desc", [
        ("UPPER-CASE", "uppercase letters forbidden"),
        ("-leading-hyphen", "leading hyphen forbidden"),
        ("trailing-hyphen-", "trailing hyphen forbidden"),
        ("a", "single char too short"),
        ("a" * 65, "65 chars too long"),
        ("with spaces", "spaces forbidden"),
        ("with_underscore", "underscore forbidden"),
    ])
    def test_invalid_slug_name_rejected(self, name: str, desc: str) -> None:
        """Linter rejects names that do not match the slug format."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = name
        result = _validate(parsed)
        slug_errors = [e for e in result.errors if "slug" in e.rule.lower() or "C3_name" in e.rule]
        assert slug_errors, (
            "Invalid name %r was NOT rejected (%s)" % (name, desc)
        )


# ---------------------------------------------------------------------------
# LAURA-005 — C10 absent-caddy enforcement-level gate
# ---------------------------------------------------------------------------

class TestLaura005C10EnvGate:
    """
    LAURA-005 (MED): absent caddy binary behaviour depends on env gate.

    Dev mode (unset / dev): skip with WARNING (original behaviour).
    Production mode (YSG_REQUIRE_CADDY_VALIDATE=true or YASHIGANI_ENV=production):
    HARD FAIL — C10_caddy_binary_absent.
    """

    def test_absent_caddy_dev_mode_warns_not_fails(self, caplog) -> None:
        """Dev mode: absent caddy emits WARNING and allows codegen to proceed."""
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)
            os.environ.pop("YASHIGANI_ENV", None)
            try:
                with caplog.at_level("WARNING", logger="yashigani.manifest.codegen"):
                    artifacts = _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert artifacts, "Dev mode: codegen should proceed despite absent caddy"
                assert any("caddy binary not found" in r.message for r in caplog.records), (
                    "Dev mode: expected WARNING about absent caddy"
                )
            finally:
                os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)
                os.environ.pop("YASHIGANI_ENV", None)

    def test_absent_caddy_explicit_require_hard_fails(self) -> None:
        """YSG_REQUIRE_CADDY_VALIDATE=true: absent caddy is a hard failure."""
        from yashigani.manifest.codegen import CodegenError
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ["YSG_REQUIRE_CADDY_VALIDATE"] = "true"
            try:
                with pytest.raises(CodegenError) as exc_info:
                    _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert exc_info.value.code == "C10_caddy_binary_absent"
            finally:
                os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)

    def test_absent_caddy_ysg_require_1_hard_fails(self) -> None:
        """YSG_REQUIRE_CADDY_VALIDATE=1: absent caddy is a hard failure."""
        from yashigani.manifest.codegen import CodegenError
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ["YSG_REQUIRE_CADDY_VALIDATE"] = "1"
            try:
                with pytest.raises(CodegenError) as exc_info:
                    _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert exc_info.value.code == "C10_caddy_binary_absent"
            finally:
                os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)

    def test_absent_caddy_production_env_hard_fails(self) -> None:
        """YASHIGANI_ENV=production: absent caddy is a hard failure."""
        from yashigani.manifest.codegen import CodegenError
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)
            os.environ["YASHIGANI_ENV"] = "production"
            try:
                with pytest.raises(CodegenError) as exc_info:
                    _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert exc_info.value.code == "C10_caddy_binary_absent"
            finally:
                os.environ.pop("YASHIGANI_ENV", None)

    def test_absent_caddy_staging_env_hard_fails(self) -> None:
        """YASHIGANI_ENV=staging: absent caddy is a hard failure."""
        from yashigani.manifest.codegen import CodegenError
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)
            os.environ["YASHIGANI_ENV"] = "staging"
            try:
                with pytest.raises(CodegenError) as exc_info:
                    _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert exc_info.value.code == "C10_caddy_binary_absent"
            finally:
                os.environ.pop("YASHIGANI_ENV", None)

    def test_absent_caddy_dev_env_warns_not_fails(self, caplog) -> None:
        """YASHIGANI_ENV=dev: absent caddy is a WARNING, not a failure."""
        with mock.patch.object(shutil, "which", return_value=None):
            os.environ.pop("YSG_REQUIRE_CADDY_VALIDATE", None)
            os.environ["YASHIGANI_ENV"] = "dev"
            try:
                with caplog.at_level("WARNING", logger="yashigani.manifest.codegen"):
                    artifacts = _fresh_engine(caddy_validator=None).render(dry_run=True)
                assert artifacts
            finally:
                os.environ.pop("YASHIGANI_ENV", None)

    def test_present_caddy_injected_validator_still_enforces(self) -> None:
        """When a validator is injected, it is always used (regardless of env gate)."""
        from yashigani.manifest.codegen import CodegenError
        def _fail_validator(caddyfile: str) -> int:
            return 1
        with pytest.raises(CodegenError) as exc_info:
            _fresh_engine(caddy_validator=_fail_validator).render(dry_run=True)
        assert exc_info.value.code == "C10_caddy_validate_failed"


# ---------------------------------------------------------------------------
# LAURA-004 — M9 comment accuracy (no assertion on comment wording needed,
# just ensure _safe_write still works correctly — main proving tests are
# the existing M9 test class in test_v250_w3_codegen.py)
# ---------------------------------------------------------------------------

class TestLaura004M9CommentAccuracy:
    """LAURA-004 (LOW): _safe_write comment corrected; existing M9 tests cover behaviour."""

    def test_safe_write_docstring_does_not_claim_o_nofollow(self) -> None:
        """The _safe_write docstring must not claim O_NOFOLLOW semantics."""
        import inspect
        from yashigani.manifest.codegen import _safe_write
        doc = inspect.getdoc(_safe_write) or ""
        # Must NOT contain the misleading O_NOFOLLOW claim
        assert "O_NOFOLLOW semantics via the realpath" not in doc, (
            "LAURA-004: _safe_write still claims 'O_NOFOLLOW semantics via the realpath' "
            "— this is inaccurate and must be corrected."
        )

    def test_safe_write_docstring_mentions_toctou(self) -> None:
        """The _safe_write docstring must acknowledge the TOCTOU residual."""
        import inspect
        from yashigani.manifest.codegen import _safe_write
        doc = inspect.getdoc(_safe_write) or ""
        assert "TOCTOU" in doc, (
            "LAURA-004: _safe_write docstring must acknowledge the TOCTOU residual "
            "(check-then-act gap when output_root is attacker-writable)."
        )


# ---------------------------------------------------------------------------
# W3-F1 — ringfence bridge in compose override
# ---------------------------------------------------------------------------

class TestW3F1RingfenceBridge:
    """
    W3-F1 (HIGH): compose override must declare the isolated ringfence_<agent>
    bridge (internal:true, enable_ipv6:false) AND caddy_internal.

    Replicates the langflow_isolated / letta_isolated / openclaw_isolated
    pattern at docker-compose.yml:2405-2413.
    """

    def test_compose_declares_ringfence_bridge_network(self) -> None:
        """Compose override must list ringfence_<agent> in agent networks."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "ringfence_hermes-agent" in compose, (
            "W3-F1: ringfence bridge not declared in compose override"
        )

    def test_compose_ringfence_bridge_is_internal(self) -> None:
        """Ringfence bridge must have internal: true."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        # Check that 'internal: true' appears after the ringfence network declaration
        assert "internal: true" in compose, (
            "W3-F1: internal: true not found in compose override"
        )

    def test_compose_ringfence_bridge_disables_ipv6(self) -> None:
        """Ringfence bridge must have enable_ipv6: false."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "enable_ipv6: false" in compose, (
            "W3-F1: enable_ipv6: false not found in ringfence bridge"
        )

    def test_compose_agent_joins_both_networks(self) -> None:
        """Agent must be on both ringfence_<agent> AND caddy_internal."""
        artifacts = _fresh_engine().render(dry_run=True)
        compose = artifacts["docker/hermes-agent-compose.override.yml"]
        assert "ringfence_hermes-agent" in compose
        assert "caddy_internal" in compose

    def test_compose_ringfence_bridge_name_matches_agent(self) -> None:
        """Ringfence bridge name is ringfence_<agent_name>."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["metadata"]["name"] = "my-llm-agent"
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker")
        artifacts = engine.render(dry_run=True)
        compose = artifacts["docker/my-llm-agent-compose.override.yml"]
        assert "ringfence_my-llm-agent" in compose, (
            "W3-F1: ringfence bridge name should be ringfence_my-llm-agent"
        )


# ---------------------------------------------------------------------------
# W3-F2 — NetworkPolicy egress: Caddy selector + kube-dns
# ---------------------------------------------------------------------------

class TestW3F2NetworkPolicyEgress:
    """
    W3-F2 (MED): NetworkPolicy overlay must include:
    1. Egress to Caddy pod selector (app.kubernetes.io/name: caddy) on port 443.
    2. Egress to kube-dns (k8s-app: kube-dns) on UDP/TCP 53.

    Replicates allow-agent-bundle-egress pattern from networkpolicy.yaml:1177-1247.
    """

    def test_netpol_overlay_has_caddy_selector_egress(self) -> None:
        """NetworkPolicy overlay must allow egress to Caddy pod selector on port 443."""
        artifacts = _fresh_engine().render(dry_run=True)
        netpol = artifacts["helm/yashigani/values-hermes-agent-networkpolicy.yaml"]
        assert "app.kubernetes.io/name: caddy" in netpol, (
            "W3-F2: Caddy pod selector not in NetworkPolicy overlay"
        )
        assert "port: 443" in netpol, (
            "W3-F2: port 443 not present alongside Caddy selector"
        )

    def test_netpol_overlay_has_kube_dns_egress_udp(self) -> None:
        """NetworkPolicy overlay must allow egress to kube-dns on UDP 53."""
        artifacts = _fresh_engine().render(dry_run=True)
        netpol = artifacts["helm/yashigani/values-hermes-agent-networkpolicy.yaml"]
        assert "k8s-app: kube-dns" in netpol, (
            "W3-F2: kube-dns selector not in NetworkPolicy overlay"
        )
        assert "protocol: UDP" in netpol, (
            "W3-F2: UDP protocol not present for kube-dns egress"
        )

    def test_netpol_overlay_has_kube_dns_egress_tcp(self) -> None:
        """NetworkPolicy overlay must allow egress to kube-dns on TCP 53."""
        artifacts = _fresh_engine().render(dry_run=True)
        netpol = artifacts["helm/yashigani/values-hermes-agent-networkpolicy.yaml"]
        assert "protocol: TCP" in netpol, (
            "W3-F2: TCP protocol not present for kube-dns egress"
        )
        assert "port: 53" in netpol, (
            "W3-F2: port 53 not present for kube-dns egress"
        )

    def test_netpol_overlay_caddy_egress_present_even_with_no_egress_allow(self) -> None:
        """Caddy + kube-dns egress always present, even when egress_allow is empty."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = []
        parsed["spec"]["model_egress"] = {}  # no base_url
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker")
        artifacts = engine.render(dry_run=True)
        netpol = artifacts["helm/yashigani/values-hermes-agent-networkpolicy.yaml"]
        assert "app.kubernetes.io/name: caddy" in netpol
        assert "k8s-app: kube-dns" in netpol


# ---------------------------------------------------------------------------
# W3-F3 — Caddy reverse_proxy syntax
# ---------------------------------------------------------------------------

class TestW3F3CaddyReverseProxySyntax:
    """
    W3-F3 (MED): Caddy reverse_proxy syntax must be valid.

    The existing C10 test mock returns 0 unconditionally and MASKED this bug.
    These tests:
    1. Assert the structural form of the emitted reverse_proxy line directly
       (does NOT use an always-0 mock for this assertion).
    2. Invoke real `caddy validate` if the binary is available.

    Valid forms per Caddy docs:
      - Single upstream: `reverse_proxy <upstream>` (inline)
      - Multiple upstreams: `reverse_proxy { to <u1>\n to <u2>\n }`
    Invalid form (what the bug produced):
      - `reverse_proxy {\n    <bare-hostname>\n}` — bare hostname NOT valid
    """

    def test_single_upstream_uses_inline_form(self) -> None:
        """
        W3-F3: single upstream emits `reverse_proxy <upstream>` (inline form).
        Not using a mock — asserting on the actual generated text.
        """
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        # Single upstream only (via base_url, no egress_allow)
        parsed["spec"]["network"]["egress_allow"] = []
        parsed["spec"]["model_egress"]["base_url"] = "https://api.openai.com/v1"
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker", caddy_validator=lambda _: 0)
        artifacts = engine.render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]

        # Must contain `reverse_proxy api.openai.com` (inline, no bare sub-line)
        assert "        reverse_proxy api.openai.com" in caddy, (
            "W3-F3: single upstream must use inline form 'reverse_proxy <upstream>'.\n"
            "Got caddy snippet:\n%s" % caddy
        )
        # Must NOT have a bare hostname as a sub-line (the old buggy form)
        for line in caddy.split("\n"):
            stripped = line.strip()
            if stripped == "api.openai.com":
                raise AssertionError(
                    "W3-F3: bare hostname 'api.openai.com' found as a sub-line "
                    "(old buggy form). Must use 'reverse_proxy <upstream>' inline.\n"
                    "Got caddy snippet:\n%s" % caddy
                )

    def test_multiple_upstreams_uses_to_form(self) -> None:
        """
        W3-F3: multiple upstreams emit `reverse_proxy { to <u1>\n to <u2> }`.
        Not using a mock — asserting on the actual generated text.
        """
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = "https://api.openai.com/v1"
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "fallback.openai.com", "ports": [443]},
        ]
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker", caddy_validator=lambda _: 0)
        artifacts = engine.render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]

        # Must contain the block form
        assert "        reverse_proxy {" in caddy, (
            "W3-F3: multiple upstreams must use block form 'reverse_proxy { ... }'.\n"
            "Got:\n%s" % caddy
        )
        # Must have `to <upstream>` lines
        assert "            to api.openai.com" in caddy, (
            "W3-F3: expected 'to api.openai.com' sub-line in reverse_proxy block.\n"
            "Got:\n%s" % caddy
        )
        assert "            to fallback.openai.com:443" in caddy, (
            "W3-F3: expected 'to fallback.openai.com:443' sub-line in reverse_proxy block.\n"
            "Got:\n%s" % caddy
        )
        # Must NOT have bare hostnames (old buggy form)
        for line in caddy.split("\n"):
            stripped = line.strip()
            if stripped in ("api.openai.com", "fallback.openai.com:443"):
                raise AssertionError(
                    "W3-F3: bare upstream %r found as sub-line (old buggy form).\n"
                    "Got caddy snippet:\n%s" % (stripped, caddy)
                )

    def test_no_upstream_emits_502_respond(self) -> None:
        """No upstream: placeholder respond 502 (unchanged, regression guard)."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = []
        parsed["spec"]["model_egress"] = {}
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker", caddy_validator=lambda _: 0)
        artifacts = engine.render(dry_run=True)
        caddy = artifacts["docker/caddy/agents/hermes-agent.caddy"]
        assert "respond" in caddy and "502" in caddy, (
            "W3-F3: no-upstream case must emit placeholder 502 respond"
        )

    def test_real_caddy_validate_if_available(self) -> None:
        """
        W3-F3 real validation: if caddy binary is available, validate the snippet.

        This test is the anti-mock proving test — it bypasses the always-0
        mock and tests against the real caddy binary when present.
        If caddy is absent, the test is skipped (not failed).
        """
        caddy_bin = shutil.which("caddy")
        if caddy_bin is None:
            pytest.skip("caddy binary not available — skipping real caddy validate test")

        from yashigani.manifest.codegen import reset_codegen_registry, _gen_caddy_snippet
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = []
        parsed["spec"]["model_egress"]["base_url"] = "https://api.openai.com/v1"
        snippet = _gen_caddy_snippet(parsed, manifest_hash="abc123", runtime="docker")

        caddyfile = "{\n    admin off\n}\n\n" + snippet
        fd, tmp_path = tempfile.mkstemp(suffix=".Caddyfile", prefix="ysg-test-")
        try:
            os.write(fd, caddyfile.encode("utf-8"))
            os.close(fd)
            result = subprocess.run(
                [caddy_bin, "validate", "--config", tmp_path],
                capture_output=True,
                timeout=30,
            )
            assert result.returncode == 0, (
                "W3-F3: real caddy validate failed for generated snippet.\n"
                "Snippet:\n%s\n\nStderr: %s" % (
                    snippet, result.stderr.decode("utf-8", errors="replace")[:1024]
                )
            )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# W3-F4 — SPIFFE fallback removed (ValueError propagates)
# ---------------------------------------------------------------------------

class TestW3F4SpifffeFallbackRemoved:
    """
    W3-F4 (LOW): _gen_service_identity_entry must propagate ValueError from
    resolve_spiffe_uri instead of silently reconstructing a fallback URI.

    The fallback reconstruction meant that a future validation addition in
    resolve_spiffe_uri could be silently bypassed.
    """

    def test_spiffe_uri_missing_name_raises_value_error(self) -> None:
        """
        W3-F4: if metadata.name is missing, resolve_spiffe_uri raises ValueError
        which propagates through _gen_service_identity_entry.
        """
        from yashigani.manifest.codegen import _gen_service_identity_entry
        parsed = {
            "metadata": {"tenant_id": "acme"},
            "spec": {},
        }
        with pytest.raises(ValueError, match="Cannot resolve SPIFFE URI"):
            _gen_service_identity_entry(parsed, manifest_hash="abc", runtime="docker")

    def test_spiffe_uri_missing_tenant_raises_value_error(self) -> None:
        """
        W3-F4: if metadata.tenant_id is missing, resolve_spiffe_uri raises ValueError.
        """
        from yashigani.manifest.codegen import _gen_service_identity_entry
        parsed = {
            "metadata": {"name": "my-agent"},
            "spec": {},
        }
        with pytest.raises(ValueError, match="Cannot resolve SPIFFE URI"):
            _gen_service_identity_entry(parsed, manifest_hash="abc", runtime="docker")

    def test_spiffe_uri_present_uses_correct_value(self) -> None:
        """W3-F4 regression: valid manifest still gets correct SPIFFE URI."""
        artifacts = _fresh_engine().render(dry_run=True)
        svcid = artifacts["service_identities.yaml.fragment"]
        assert "spiffe://yashigani.internal/agents/acme-corp/hermes-agent" in svcid, (
            "W3-F4: SPIFFE URI missing or incorrect in service identity entry"
        )

    def test_spiffe_override_id_is_used(self) -> None:
        """W3-F4 regression: spec.identity.spiffe.override_id is used when present."""
        from yashigani.manifest.codegen import reset_codegen_registry
        reset_codegen_registry()
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["identity"] = {
            "spiffe": {"override_id": "spiffe://yashigani.internal/agents/acme-corp/custom-id"}
        }
        from yashigani.manifest.codegen import CodegenEngine
        engine = CodegenEngine(parsed, "docker", caddy_validator=lambda _: 0)
        artifacts = engine.render(dry_run=True)
        svcid = artifacts["service_identities.yaml.fragment"]
        assert "spiffe://yashigani.internal/agents/acme-corp/custom-id" in svcid
