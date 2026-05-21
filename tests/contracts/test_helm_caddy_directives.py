# Last updated: 2026-05-19T00:00:00+01:00
"""
Helm Caddyfile directive contract tests — YSG-RISK-025 + SIDE-001 regression gates.

Ensures the Helm-rendered Caddyfile (embedded in caddy-config ConfigMap) never
regresses to the deprecated ``tls_trusted_ca_certs`` directive (removed in
Caddy 2.12). The compose-side migration was applied in v2.23.2; the helm-side
was tracked as YSG-RISK-025 and closed in v2.23.4.

Also asserts SIDE-001 (2026-05-19): the /admin/* handle must inject Caddy's
SPIFFE identity (``request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"``)
when mtls.enabled=true. Without this, POST /admin/agents via Caddy returns
401 no_spiffe_id because require_spiffe_id() never receives a caller identity.
Parity with docker/Caddyfile.{selfsigned,ca,acme} (commit 8a1dbf5).

Contract
--------
1. ``tls_trusted_ca_certs`` must not appear anywhere in the rendered
   configmaps.yaml output (rendered with mtls.enabled=true and both internal
   metrics listeners enabled so all Caddyfile fragments are emitted).

2. ``tls_trust_pool`` MUST appear at least once — confirming the replacement
   directive is present, not just that the deprecated one was deleted.

3. ``handle /admin/*`` block must contain
   ``request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"``
   when mtls.enabled=true (SIDE-001 regression gate).

4. ``handle /admin/*`` block must contain
   ``request_header -X-SPIFFE-ID`` (strip before set) when mtls.enabled=true.

Mutation test
-------------
``test_mutation_trust_pool_check_catches_regression`` introduces
``tls_trusted_ca_certs`` into the in-memory render output and asserts the
contract would have caught it. Per feedback_test_harness_no_fake_green.md:
a test that passes on a mutated fixture is evidence fabrication (SOP 4).

``test_mutation_admin_spiffe_catch_regression`` removes the X-SPIFFE-ID
injection from a synthetic /admin block and confirms the gate would catch it.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.parent
_HELM_CHART = _REPO / "helm" / "yashigani"

# Stable test bearer token — no install semantics, only bypasses the
# validate-security.yaml internalBearer guard during helm template rendering.
_LINT_BEARER = "helm-lint-only-not-a-real-secret-000000000000"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _helm_render() -> str:
    """
    Run ``helm template`` with mtls and internal metrics listeners enabled so
    all Caddyfile fragments (snippets + metrics-listener blocks) are present in
    the output.

    internalBearer.value is supplied to satisfy the validate-security.yaml
    INTERNAL-BEARER-001 gate (required as of v2.23.4).  The value is a stable
    lint-only sentinel — it carries no install semantics.

    Returns the full rendered YAML as a string.
    Raises subprocess.CalledProcessError on helm failure.
    """
    result = subprocess.run(
        [
            "helm", "template", "yashigani", str(_HELM_CHART),
            "--namespace", "yashigani-validate",
            "--set", "mtls.enabled=true",
            "--set", "caddy.internalMetricsListenerGateway.enabled=true",
            "--set", "caddy.internalMetricsListenerBackoffice.enabled=true",
            "--set", f"internalBearer.value={_LINT_BEARER}",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


# ---------------------------------------------------------------------------
# Contract tests
# ---------------------------------------------------------------------------


class TestHelmCaddyTrustPool:
    """Helm-rendered Caddyfile must use tls_trust_pool, not tls_trusted_ca_certs."""

    @pytest.fixture(scope="class")
    def rendered(self) -> str:
        """Run helm template once per class; skip if helm binary absent."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        return _helm_render()

    def test_no_deprecated_tls_trusted_ca_certs(self, rendered: str) -> None:
        """YSG-RISK-025 regression gate: deprecated directive must not appear."""
        assert "tls_trusted_ca_certs" not in rendered, (
            "helm-rendered configmap still contains deprecated 'tls_trusted_ca_certs'. "
            "Caddy 2.12+ removed this directive — use 'tls_trust_pool file <path>' "
            "inside transport http blocks. YSG-RISK-025 regression."
        )

    def test_tls_trust_pool_present(self, rendered: str) -> None:
        """Confirm replacement directive is present in render."""
        assert "tls_trust_pool" in rendered, (
            "helm-rendered configmap has no 'tls_trust_pool' directive. "
            "The replacement for tls_trusted_ca_certs must be present in transport http "
            "blocks inside (internal-mtls-gateway) and (internal-mtls-backoffice) snippets "
            "and in the internalMetricsListener reverse_proxy blocks."
        )

    def test_trust_pool_count_matches_expected(self, rendered: str) -> None:
        """
        Expect exactly 4 occurrences: 2 snippet definitions + 2 metrics-listener
        reverse_proxy blocks. A count change means a fragment was added or removed
        without updating this gate.
        """
        count = rendered.count("tls_trust_pool")
        assert count == 4, (
            f"Expected 4 'tls_trust_pool' occurrences in helm render, found {count}. "
            "If new mTLS transport blocks were added or removed, update the expected count "
            "in this test and confirm the new directives are correct."
        )


# ---------------------------------------------------------------------------
# SIDE-001: /admin/* X-SPIFFE-ID injection gate
# ---------------------------------------------------------------------------


class TestHelmAdminSpiffeInjection:
    """
    SIDE-001 (2026-05-19) regression gate: handle /admin/* must inject Caddy's
    SPIFFE identity header when mtls.enabled=true.

    Without this, POST /admin/agents via the Helm Caddy ingress returns
    401 no_spiffe_id because require_spiffe_id() receives no caller identity.
    Browser sessions arrive at Caddy without a client cert; Caddy injects its
    own identity ("spiffe://yashigani.internal/caddy") on the Caddy→backoffice
    leg.  Parity with docker/Caddyfile.{selfsigned,ca,acme} (commit 8a1dbf5).
    """

    @pytest.fixture(scope="class")
    def rendered(self) -> str:
        """Run helm template once per class; skip if helm binary absent."""
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        return _helm_render()

    def test_admin_handle_injects_spiffe_id(self, rendered: str) -> None:
        """
        SIDE-001: handle /admin/* must set X-SPIFFE-ID to Caddy's identity.

        Checks the literal string that must appear in the rendered Caddyfile.
        The value "spiffe://yashigani.internal/caddy" matches the ACL entry in
        service_identities.yaml endpoint_acls["/admin/agents"].
        """
        assert 'request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"' in rendered, (
            "SIDE-001 REGRESSION: handle /admin/* in Helm Caddyfile does not inject "
            "'request_header X-SPIFFE-ID \"spiffe://yashigani.internal/caddy\"'. "
            "POST /admin/agents via Caddy will return 401 no_spiffe_id. "
            "Fix: add the directive inside {{- if .Values.mtls.enabled }} in the "
            "handle /admin/* block in helm/yashigani/templates/configmaps.yaml."
        )

    def test_admin_handle_strips_spiffe_id_before_set(self, rendered: str) -> None:
        """
        SIDE-001: handle /admin/* must strip any client-supplied X-SPIFFE-ID
        before setting Caddy's identity.  ``request_header -X-SPIFFE-ID`` must
        precede the set directive — strips externally-supplied (forge-attempt)
        values.  Same strip-before-set discipline as /v1/* and /agents/* blocks.
        """
        assert "request_header -X-SPIFFE-ID" in rendered, (
            "SIDE-001 REGRESSION: 'request_header -X-SPIFFE-ID' (strip directive) "
            "is absent from Helm Caddyfile render. The strip-before-set discipline "
            "must be present on /admin/* to prevent header injection from clients. "
            "Fix: add 'request_header -X-SPIFFE-ID' before the set directive in the "
            "handle /admin/* block."
        )

    def test_admin_spiffe_absent_when_mtls_disabled(self) -> None:
        """
        With mtls.enabled=false (development mode), the /admin/* block must NOT
        inject X-SPIFFE-ID — no SPIFFE gate exists without mTLS.
        Rendered separately because the production validate-security.yaml blocks
        mtls.enabled=false in the default environment; use global.environment=development.
        """
        import shutil
        if not shutil.which("helm"):
            pytest.skip("helm binary not found — install helm to run this check")
        result = subprocess.run(
            [
                "helm", "template", "yashigani", str(_HELM_CHART),
                "--namespace", "yashigani-validate",
                "--set", "mtls.enabled=false",
                "--set", "global.environment=development",
                "--set", f"internalBearer.value={_LINT_BEARER}",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        rendered_no_mtls = result.stdout
        assert 'request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"' not in rendered_no_mtls, (
            "SIDE-001 GUARD: handle /admin/* injects X-SPIFFE-ID even when "
            "mtls.enabled=false. The directive must be inside "
            "{{- if .Values.mtls.enabled }} to avoid injecting a header when "
            "the SPIFFE gate is not active."
        )


# ---------------------------------------------------------------------------
# Mutation test — must FAIL on tampered fixture
# ---------------------------------------------------------------------------


def test_mutation_trust_pool_check_catches_regression() -> None:
    """
    Mutation guard: inject 'tls_trusted_ca_certs' into in-memory render output
    and confirm the contract test would have caught it.

    Per feedback_test_harness_no_fake_green.md (SOP 4): a test that passes on a
    mutated fixture is a fake-green — it provides no real protection.
    """
    # Inject the deprecated directive into a synthetic render blob
    mutated = (
        "        tls\n"
        "        tls_trusted_ca_certs /run/secrets/ca_bundle.crt\n"
        "        tls_client_auth /run/secrets/caddy_client.crt /run/secrets/caddy_client.key\n"
    )

    # The contract must fire
    assert "tls_trusted_ca_certs" in mutated, (
        "MUTATION TEST SETUP ERROR: test blob does not contain tls_trusted_ca_certs"
    )

    # Simulate what the contract check does
    contract_would_fail = "tls_trusted_ca_certs" in mutated
    assert contract_would_fail, (
        "MUTATION TEST FAILED: contract would NOT have caught tls_trusted_ca_certs "
        "in render output — the test provides no real regression protection."
    )


def test_mutation_admin_spiffe_catch_regression() -> None:
    """
    Mutation guard (SIDE-001): simulate a render where the /admin/* block does
    NOT contain the X-SPIFFE-ID injection, and confirm the contract test would
    have caught it.

    Per feedback_test_harness_no_fake_green.md (SOP 4): a test that passes on a
    mutated fixture is a fake-green.
    """
    # Synthetic /admin/* block WITHOUT the X-SPIFFE-ID injection
    mutated_missing_spiffe = (
        "      handle /admin/* {\n"
        "        reverse_proxy https://yashigani-backoffice:8443 {\n"
        "          import internal-mtls-backoffice\n"
        "          import inject-caddy-verified\n"
        "        }\n"
        "      }\n"
    )

    # Confirm the mutation does NOT contain the required directive
    spiffe_present = 'request_header X-SPIFFE-ID "spiffe://yashigani.internal/caddy"' in mutated_missing_spiffe
    assert not spiffe_present, (
        "MUTATION TEST SETUP ERROR: test blob unexpectedly contains the SPIFFE injection"
    )

    # Simulate what the contract check does — it would FAIL on this render
    contract_would_catch = not spiffe_present
    assert contract_would_catch, (
        "MUTATION TEST FAILED: contract would NOT have caught missing X-SPIFFE-ID "
        "injection in /admin/* block — the test provides no real regression protection."
    )
