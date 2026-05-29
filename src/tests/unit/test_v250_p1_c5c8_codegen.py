"""
P1 C5 + C8 — Caddy egress codegen proving tests (v2.25.0 P1 W3).

C5 (MED): Per-upstream TLS verification.
  - Generated reverse_proxy transport block has explicit `tls` directive.
  - tls_server_name is set to the provider hostname from model_egress.base_url
    (hardcoded from manifest config — NEVER from request headers).
  - tls_insecure_skip_verify MUST NOT appear anywhere in the snippet.
  - Caddy never proxies a client-supplied Host to the upstream TLS handshake.
  - tls_server_name correctly extracted for multiple provider URL patterns.
  - No-base_url edge case: transport block still has tls + max_conns_per_host.

C8 (MED): Connection-pool exhaustion cap.
  - max_conns_per_host present in transport block.
  - Value equals _C8_MAX_CONNS_PER_HOST_DEFAULT (64).
  - Constant is queryable and sensible (>0, <=1024).
  - OPA budget-gate deferred: YSG-C8-OPA-BUDGET TODO present in generated snippet.

Structural shape assertions (for Captain/Iris review):
  - transport http block is a subdirective of reverse_proxy (correct placement).
  - Block form always used when upstreams present (C5+C8 require block form).
  - Single-upstream now uses block form (regression: prior inline form drops transport).

All tests use dry_run=True (no file writes).
"""
from __future__ import annotations

import copy
import re

# ---------------------------------------------------------------------------
# Shared fixtures — extend base manifest from W3 test suite
# ---------------------------------------------------------------------------

_VALID_DIGEST_SHA256 = "sha256:" + "a" * 64

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
    """Return a CodegenEngine with a clean C3 registry."""
    from yashigani.manifest.codegen import CodegenEngine, reset_codegen_registry
    reset_codegen_registry()
    p = parsed if parsed is not None else copy.deepcopy(_BASE_PARSED)
    return CodegenEngine(p, runtime, caddy_validator=caddy_validator)


def _caddy_snippet(parsed=None, runtime="docker") -> str:
    """Render and return the Caddy snippet string."""
    artifacts = _fresh_engine(parsed=parsed, runtime=runtime).render(dry_run=True)
    return artifacts["docker/caddy/agents/hermes-agent.caddy"]


# ---------------------------------------------------------------------------
# C5 — per-upstream TLS verification
# ---------------------------------------------------------------------------

class TestC5TlsVerification:
    """C5 (MED): explicit TLS transport block with hardcoded tls_server_name."""

    def test_transport_http_block_present(self) -> None:
        """C5: generated Caddy snippet must contain a transport http { ... } block."""
        caddy = _caddy_snippet()
        assert "transport http {" in caddy, (
            "C5: transport http block missing from generated Caddy snippet"
        )

    def test_tls_directive_present(self) -> None:
        """C5: transport block must enable TLS (`tls` directive on its own line)."""
        caddy = _caddy_snippet()
        # Match bare `tls` on a line (not tls_server_name or other tls_* variants)
        assert re.search(r"^\s+tls\s*$", caddy, re.MULTILINE), (
            "C5: bare `tls` directive missing from transport http block. "
            "This enables TLS to the upstream — required for cert verification."
        )

    def test_tls_server_name_set_from_base_url(self) -> None:
        """C5: tls_server_name must be set to the provider hostname from model_egress.base_url."""
        caddy = _caddy_snippet()
        assert "tls_server_name api.openai.com" in caddy, (
            "C5: tls_server_name not set to provider host api.openai.com from model_egress.base_url"
        )

    def test_no_tls_insecure_skip_verify(self) -> None:
        """C5: tls_insecure_skip_verify MUST NOT appear in the generated snippet."""
        caddy = _caddy_snippet()
        assert "tls_insecure_skip_verify" not in caddy, (
            "C5 CRITICAL: tls_insecure_skip_verify found in generated Caddy snippet. "
            "This disables TLS verification and must NEVER be emitted."
        )

    def test_no_skip_verify_variants(self) -> None:
        """C5: no variant of skip-verify language anywhere in the snippet."""
        caddy = _caddy_snippet()
        banned_patterns = [
            "skip_verify",
            "InsecureSkipVerify",
            "insecure_skip",
            "verify=false",
            "noverify",
        ]
        for pattern in banned_patterns:
            assert pattern not in caddy, (
                "C5: found banned TLS bypass token %r in generated Caddy snippet" % pattern
            )

    def test_tls_server_name_hardcoded_not_from_headers(self) -> None:
        """C5: tls_server_name must be a literal hostname, not a Caddy placeholder."""
        caddy = _caddy_snippet()
        # Caddy placeholders are {header.Host}, {http.request.host}, etc.
        # If tls_server_name contains any { ... } placeholder, the SNI is
        # derived from runtime input — a critical SSRF vector.
        tls_sni_lines = [
            line for line in caddy.splitlines()
            if "tls_server_name" in line
        ]
        assert tls_sni_lines, "C5: no tls_server_name line found"
        for line in tls_sni_lines:
            assert "{" not in line, (
                "C5 CRITICAL: tls_server_name contains a Caddy placeholder {}: %r. "
                "SNI must be a literal hostname from manifest config — "
                "NEVER derived from request headers." % line
            )

    def test_tls_server_name_anthropic(self) -> None:
        """C5: tls_server_name correctly set for Anthropic provider."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = "https://api.anthropic.com/v1"
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.anthropic.com", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "tls_server_name api.anthropic.com" in caddy, (
            "C5: tls_server_name not set to api.anthropic.com for Anthropic provider"
        )
        assert "tls_server_name api.openai.com" not in caddy, (
            "C5: openai tls_server_name leaked into Anthropic provider snippet"
        )

    def test_tls_server_name_mistral(self) -> None:
        """C5: tls_server_name correctly set for Mistral provider."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = "https://api.mistral.ai/v1"
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.mistral.ai", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "tls_server_name api.mistral.ai" in caddy, (
            "C5: tls_server_name not set for Mistral provider"
        )

    def test_tls_server_name_no_port_included(self) -> None:
        """C5: tls_server_name must be bare hostname, not host:port."""
        # base_url with explicit port should still yield bare hostname for SNI
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"]["base_url"] = "https://api.openai.com:443/v1"
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        # tls_server_name api.openai.com (no :443)
        assert "tls_server_name api.openai.com" in caddy, (
            "C5: tls_server_name must be bare hostname without port"
        )
        # Negative: must not be api.openai.com:443
        assert "tls_server_name api.openai.com:443" not in caddy, (
            "C5: tls_server_name must not include port number"
        )

    def test_transport_block_inside_reverse_proxy(self) -> None:
        """C5: transport http block must be a subdirective of reverse_proxy."""
        caddy = _caddy_snippet()
        # The transport block must appear AFTER reverse_proxy { and BEFORE its closing }
        # We verify the structural ordering: 'reverse_proxy {' appears before 'transport http {'
        rp_pos = caddy.find("reverse_proxy {")
        transport_pos = caddy.find("transport http {")
        assert rp_pos != -1, "reverse_proxy block not found"
        assert transport_pos != -1, "transport http block not found"
        assert rp_pos < transport_pos, (
            "C5: transport http block must appear INSIDE reverse_proxy block. "
            "Found transport http before reverse_proxy {"
        )

    def test_c5_no_base_url_still_has_tls(self) -> None:
        """C5 edge case: no model_egress.base_url — transport block still has tls directive."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"] = {}  # no base_url
        # Only egress_allow upstreams
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "transport http {" in caddy, (
            "C5: transport block missing when no model_egress.base_url"
        )
        assert re.search(r"^\s+tls\s*$", caddy, re.MULTILINE), (
            "C5: bare tls directive missing when no model_egress.base_url"
        )

    def test_c5_no_base_url_no_tls_server_name_directive(self) -> None:
        """C5 edge case: no model_egress.base_url — no tls_server_name directive (nothing to pin)."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"] = {}
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        # tls_server_name may appear in header comments but must not be a directive line
        # (i.e. `tls_server_name <hostname>` as an indented directive in the transport block)
        tls_sni_directive_lines = [
            line for line in caddy.splitlines()
            if re.match(r"^\s+tls_server_name\s+\S", line)
        ]
        assert not tls_sni_directive_lines, (
            "C5 edge: tls_server_name directive should be absent when no model_egress.base_url. "
            "Found: %s" % tls_sni_directive_lines
        )

    def test_c5_snippet_comments_reference_finding(self) -> None:
        """C5: generated snippet comments must reference C5 for audit traceability."""
        caddy = _caddy_snippet()
        assert "C5" in caddy, (
            "C5: generated Caddy snippet must reference C5 in a comment for audit traceability"
        )

    def test_c5_comment_mentions_no_request_source(self) -> None:
        """C5: transport block comment must say SNI is NEVER from request."""
        caddy = _caddy_snippet()
        # The codegen emits: '# C5: TLS to upstream — SNI hardcoded from manifest (NEVER from request)'
        assert "NEVER from request" in caddy, (
            "C5: transport block comment must state SNI is NEVER from request — "
            "required for security audit readability"
        )


# ---------------------------------------------------------------------------
# C8 — connection-pool exhaustion cap
# ---------------------------------------------------------------------------

class TestC8ConnectionPoolCap:
    """C8 (MED): max_conns_per_host in transport block caps upstream connection pool."""

    def test_max_conns_per_host_present(self) -> None:
        """C8: max_conns_per_host directive must be present in the Caddy snippet."""
        caddy = _caddy_snippet()
        assert "max_conns_per_host" in caddy, (
            "C8: max_conns_per_host missing from generated Caddy snippet"
        )

    def test_max_conns_per_host_value_matches_constant(self) -> None:
        """C8: max_conns_per_host value must equal _C8_MAX_CONNS_PER_HOST_DEFAULT."""
        from yashigani.manifest.codegen import _C8_MAX_CONNS_PER_HOST_DEFAULT
        caddy = _caddy_snippet()
        expected = "max_conns_per_host %d" % _C8_MAX_CONNS_PER_HOST_DEFAULT
        assert expected in caddy, (
            "C8: max_conns_per_host value mismatch. "
            "Expected %r, not found in snippet." % expected
        )

    def test_c8_default_constant_is_sane(self) -> None:
        """C8: _C8_MAX_CONNS_PER_HOST_DEFAULT must be a positive int <= 1024."""
        from yashigani.manifest.codegen import _C8_MAX_CONNS_PER_HOST_DEFAULT
        assert isinstance(_C8_MAX_CONNS_PER_HOST_DEFAULT, int), (
            "C8: _C8_MAX_CONNS_PER_HOST_DEFAULT must be an int"
        )
        assert 1 <= _C8_MAX_CONNS_PER_HOST_DEFAULT <= 1024, (
            "C8: _C8_MAX_CONNS_PER_HOST_DEFAULT=%d is outside sane bounds [1, 1024]"
            % _C8_MAX_CONNS_PER_HOST_DEFAULT
        )

    def test_c8_default_is_64(self) -> None:
        """C8: default is 64 — document if changed."""
        from yashigani.manifest.codegen import _C8_MAX_CONNS_PER_HOST_DEFAULT
        assert _C8_MAX_CONNS_PER_HOST_DEFAULT == 64, (
            "C8: default changed from 64. If intentional, update this test "
            "AND document the rationale in codegen.py."
        )

    def test_max_conns_inside_transport_block(self) -> None:
        """C8: max_conns_per_host must be inside the transport http { } block."""
        caddy = _caddy_snippet()
        transport_start = caddy.find("transport http {")
        transport_end = caddy.find("}", transport_start)
        assert transport_start != -1, "transport http block not found"
        assert transport_end != -1, "closing } for transport block not found"
        transport_body = caddy[transport_start:transport_end]
        assert "max_conns_per_host" in transport_body, (
            "C8: max_conns_per_host is not inside the transport http block"
        )

    def test_c8_snippet_comments_reference_finding(self) -> None:
        """C8: generated snippet must reference C8 for audit traceability."""
        caddy = _caddy_snippet()
        assert "C8" in caddy, (
            "C8: generated snippet must reference C8 in a comment for audit traceability"
        )

    def test_c8_opa_budget_gate_todo_present(self) -> None:
        """C8: OPA budget-gate TODO comment must be present (deferred half of C8)."""
        caddy = _caddy_snippet()
        assert "YSG-C8-OPA-BUDGET" in caddy, (
            "C8: YSG-C8-OPA-BUDGET TODO reference missing from generated snippet. "
            "The OPA budget-gate half of C8 (per-token/per-minute spend cap) is "
            "deferred to the policy layer. Its absence must be flagged in the "
            "generated artifact for operability / future-sprint reference."
        )

    def test_c8_max_conns_in_no_base_url_snippet(self) -> None:
        """C8: max_conns_per_host present even when no model_egress.base_url."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"] = {}
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]}
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "max_conns_per_host" in caddy, (
            "C8: max_conns_per_host missing when no model_egress.base_url"
        )


# ---------------------------------------------------------------------------
# Structural shape: block form always used when upstreams present
# ---------------------------------------------------------------------------

class TestReverseProxyBlockForm:
    """
    Structural: block form (reverse_proxy { ... }) is always used when upstreams
    are configured. This is required for C5+C8 transport subdirective placement.

    Prior to C5/C8: single-upstream used inline form `reverse_proxy <upstream>`
    which cannot carry a transport subdirective. Now always block form.
    """

    def test_single_upstream_uses_block_form(self) -> None:
        """Single upstream now uses block form to carry transport subdirective."""
        parsed = copy.deepcopy(_BASE_PARSED)
        # Only one upstream: just the base_url, no egress_allow
        parsed["spec"]["network"]["egress_allow"] = []
        caddy = _caddy_snippet(parsed=parsed)
        # Block form has: reverse_proxy {
        assert "reverse_proxy {" in caddy, (
            "Single upstream must use block form for transport subdirective placement"
        )

    def test_multi_upstream_uses_block_form(self) -> None:
        """Multiple upstreams use block form (pre-existing + preserved)."""
        caddy = _caddy_snippet()
        assert "reverse_proxy {" in caddy

    def test_no_inline_reverse_proxy_form(self) -> None:
        """Inline form `reverse_proxy <upstream>` (no block) must not appear."""
        caddy = _caddy_snippet()
        # Inline form: `reverse_proxy api.openai.com` (no opening brace on same line)
        # Block form:  `reverse_proxy {` (with brace)
        # We assert there is no bare `reverse_proxy <hostname>` without opening brace.
        non_block_rp = re.search(
            r"^\s+reverse_proxy\s+[^{{\n]+$",
            caddy,
            re.MULTILINE,
        )
        assert non_block_rp is None, (
            "C5/C8 regression: inline reverse_proxy form found. "
            "Transport subdirective requires block form. Matched: %r" % (
                non_block_rp.group(0) if non_block_rp else None
            )
        )

    def test_no_upstream_emits_502_not_reverse_proxy(self) -> None:
        """No-upstream case emits respond 502, not a reverse_proxy block."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["model_egress"] = {}
        parsed["spec"]["network"]["egress_allow"] = []
        caddy = _caddy_snippet(parsed=parsed)
        assert "respond" in caddy
        assert "502" in caddy
        assert "reverse_proxy" not in caddy, (
            "No-upstream case must not emit reverse_proxy block"
        )


# ---------------------------------------------------------------------------
# C5 + C8 combined: multi-provider variant
# ---------------------------------------------------------------------------

class TestC5C8MultiProvider:
    """
    Multi-egress_allow: transport block with single tls_server_name from primary
    model_egress.base_url, all upstreams in the same reverse_proxy block.
    """

    def test_multi_provider_has_single_transport_block(self) -> None:
        """One reverse_proxy block with one transport http block for multi-provider."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]},
            {"host": "oai-fallback.example.com", "ports": [443]},
        ]
        caddy = _caddy_snippet(parsed=parsed)
        # Exactly one transport http block
        transport_count = caddy.count("transport http {")
        assert transport_count == 1, (
            "Expected exactly 1 transport http block, got %d" % transport_count
        )

    def test_multi_provider_tls_server_name_from_base_url(self) -> None:
        """tls_server_name is always from model_egress.base_url for multi-egress."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]},
            {"host": "oai-fallback.example.com", "ports": [443]},
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "tls_server_name api.openai.com" in caddy, (
            "tls_server_name must be from model_egress.base_url for multi-egress"
        )

    def test_multi_provider_all_upstreams_present(self) -> None:
        """All configured upstreams appear in the reverse_proxy block."""
        parsed = copy.deepcopy(_BASE_PARSED)
        parsed["spec"]["network"]["egress_allow"] = [
            {"host": "api.openai.com", "ports": [443]},
            {"host": "oai-fallback.example.com", "ports": [443]},
        ]
        caddy = _caddy_snippet(parsed=parsed)
        assert "api.openai.com" in caddy
        assert "oai-fallback.example.com" in caddy


# ---------------------------------------------------------------------------
# Regression: existing W3 controls still pass through C5/C8 changes
# ---------------------------------------------------------------------------

class TestC5C8Regressions:
    """Regression tests: existing controls unaffected by C5/C8 implementation."""

    def test_c1_strip_prefix_still_present(self) -> None:
        """C1: uri strip_prefix still present after C5/C8 changes."""
        caddy = _caddy_snippet()
        assert "uri strip_prefix" in caddy

    def test_c3_namespaced_route_still_present(self) -> None:
        """C3: route namespaced /agents/{tenant}/{agent} still present."""
        caddy = _caddy_snippet()
        assert "/agents/acme-corp/hermes-agent" in caddy

    def test_c1_no_header_placeholders_still_clean(self) -> None:
        """C1: no {header.X} placeholders in snippet (SSRF guard)."""
        caddy = _caddy_snippet()
        assert "{header." not in caddy
        assert "{query." not in caddy

    def test_manifest_hash_still_present(self) -> None:
        """M9: .yashigani-manifest-hash still present after refactor."""
        caddy = _caddy_snippet()
        assert ".yashigani-manifest-hash:" in caddy

    def test_ysg_runtime_still_present(self) -> None:
        """L10: YSG_RUNTIME comment still present after refactor."""
        caddy = _caddy_snippet()
        assert "YSG_RUNTIME: docker" in caddy

    def test_forward_auth_still_present(self) -> None:
        """Auth gate: forward_auth block still present."""
        caddy = _caddy_snippet()
        assert "forward_auth" in caddy
        assert "copy_headers X-Agent-Identity X-Tenant-Id" in caddy

    def test_rootless_podman_annotation_still_present(self) -> None:
        """L10/HIGH-01: rootless Podman annotation still present after C5/C8 changes."""
        caddy = _caddy_snippet(runtime="podman-rootless")
        assert "ROOTLESS-PODMAN-L1-GAP" in caddy

    def test_c10_injected_validator_receives_transport_block(self) -> None:
        """C10: injected caddy validator receives snippet with transport block."""
        received: list[str] = []

        def _capture(caddyfile: str) -> int:
            received.append(caddyfile)
            return 0

        _fresh_engine(caddy_validator=_capture).render(dry_run=True)
        assert len(received) == 1
        assert "transport http {" in received[0], (
            "C10: validator received snippet without transport http block"
        )
        assert "tls_server_name" in received[0], (
            "C10: validator received snippet without tls_server_name"
        )
        assert "max_conns_per_host" in received[0], (
            "C10: validator received snippet without max_conns_per_host"
        )


# ---------------------------------------------------------------------------
# _extract_tls_server_name unit tests
# ---------------------------------------------------------------------------

class TestExtractTlsServerName:
    """Unit tests for the _extract_tls_server_name helper."""

    def _extract(self, url: str) -> str:
        from yashigani.manifest.codegen import _extract_tls_server_name
        return _extract_tls_server_name(url)

    def test_openai_base_url(self) -> None:
        assert self._extract("https://api.openai.com/v1") == "api.openai.com"

    def test_anthropic_base_url(self) -> None:
        assert self._extract("https://api.anthropic.com/v1") == "api.anthropic.com"

    def test_url_with_explicit_port(self) -> None:
        """Port must be stripped — tls_server_name is bare hostname."""
        assert self._extract("https://api.openai.com:443/v1") == "api.openai.com"

    def test_url_with_path_only(self) -> None:
        """Non-http(s) scheme or bare path — return empty string."""
        result = self._extract("api.openai.com/v1")
        # urlparse of a bare path yields empty hostname
        assert result == ""

    def test_empty_string(self) -> None:
        assert self._extract("") == ""

    def test_hostname_is_lowercased(self) -> None:
        """urlparse.hostname lowercases the host."""
        assert self._extract("https://API.OpenAI.COM/v1") == "api.openai.com"

    def test_returns_string_not_none(self) -> None:
        """Return type is always str, never None."""
        result = self._extract("")
        assert isinstance(result, str)

    def test_subdomain_url(self) -> None:
        assert self._extract("https://my.custom.llm.example.com/api") == "my.custom.llm.example.com"
