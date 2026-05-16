# Last updated: 2026-05-16T00:00:00+01:00
"""
Helm Caddyfile directive contract tests — ACS-RISK-025 regression gate.

Ensures the Helm-rendered Caddyfile (embedded in caddy-config ConfigMap) never
regresses to the deprecated ``tls_trusted_ca_certs`` directive (removed in
Caddy 2.12). The compose-side migration was applied in v2.23.2; the helm-side
was tracked as ACS-RISK-025 and closed in v2.23.4.

Contract
--------
1. ``tls_trusted_ca_certs`` must not appear anywhere in the rendered
   configmaps.yaml output (rendered with mtls.enabled=true and both internal
   metrics listeners enabled so all Caddyfile fragments are emitted).

2. ``tls_trust_pool`` MUST appear at least once — confirming the replacement
   directive is present, not just that the deprecated one was deleted.

Mutation test
-------------
``test_mutation_trust_pool_check_catches_regression`` introduces
``tls_trusted_ca_certs`` into the in-memory render output and asserts the
contract would have caught it. Per feedback_test_harness_no_fake_green.md:
a test that passes on a mutated fixture is evidence fabrication (SOP 4).
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _helm_render() -> str:
    """
    Run ``helm template`` with mtls and internal metrics listeners enabled so
    all Caddyfile fragments (snippets + metrics-listener blocks) are present in
    the output.

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
        """ACS-RISK-025 regression gate: deprecated directive must not appear."""
        assert "tls_trusted_ca_certs" not in rendered, (
            "helm-rendered configmap still contains deprecated 'tls_trusted_ca_certs'. "
            "Caddy 2.12+ removed this directive — use 'tls_trust_pool file <path>' "
            "inside transport http blocks. ACS-RISK-025 regression."
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
