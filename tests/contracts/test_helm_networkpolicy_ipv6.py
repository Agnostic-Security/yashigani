# Last updated: 2026-05-26T00:00:00+01:00
"""
Helm NetworkPolicy IPv6 alignment contract tests — LAURA-V243-003 + FIND-C9-001/002.

Tiago directive 2026-05-26:
  "allow ipv6 in the front to connect to the internet if the client wants to"
  "anything else internally is ipv4"
  "block it" (referring to IPv6 internal egress)

Asserts:
  1. allow-caddy-ingress has BOTH 0.0.0.0/0 AND ::/0 ipBlock entries (Gap 1 /
     FIND-C9-001 MEDIUM). IPv6 internet clients must reach the Caddy
     LoadBalancer on ports 443 and 80 in dual-stack clusters.
  2. allow-ollama-egress has an explicit ipBlock (not port-only). The ipBlock
     MUST be IPv4-only (0.0.0.0/0 with RFC1918 except entries), implicitly
     blocking IPv6 egress (Gap 2 / LAURA-V243-003 HIGH).
  3. allow-openclaw-external-egress has an explicit ipBlock with the same
     IPv4-public-internet constraint (Gap 3 / LAURA-V243-003 HIGH).

Test approach: subprocess helm template render — no cluster required.
YAML parsed with PyYAML to avoid brittle string matching on rendered comments.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"

# RFC1918 ranges that MUST appear as except entries for external egress rules
RFC1918_RANGES = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run `helm template` and return stdout; raise via pytest.fail on error."""
    cmd = [
        "helm",
        "template",
        "yashigani",
        str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "admissionPolicies.enabled=false",
        "--set", "agentBundles.openclaw.enabled=true",
        "--set", "ollama.enabled=true",
        "--set", "openWebui.enabled=true",
    ]
    if extra_set:
        for s in extra_set:
            cmd += ["--set", s]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:2000]}\n"
            f"STDERR: {result.stderr[:2000]}"
        )
    return result.stdout


def _parse_network_policies(rendered: str) -> dict[str, Any]:
    """
    Parse all NetworkPolicy documents from a helm template render.
    Returns a dict keyed by metadata.name.
    """
    policies: dict[str, Any] = {}
    for doc in yaml.safe_load_all(rendered):
        if doc is None:
            continue
        if doc.get("kind") == "NetworkPolicy":
            name = doc["metadata"]["name"]
            policies[name] = doc
    return policies


def _ingress_cidrs(policy: dict[str, Any]) -> set[str]:
    """
    Return the set of all ipBlock CIDRs appearing in any ingress rule of
    the given NetworkPolicy document.
    """
    cidrs: set[str] = set()
    for rule in policy.get("spec", {}).get("ingress", []):
        for source in rule.get("from", []):
            block = source.get("ipBlock", {})
            if "cidr" in block:
                cidrs.add(block["cidr"])
    return cidrs


def _egress_ip_blocks(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return all ipBlock dicts appearing in any egress `to:` block of the
    given NetworkPolicy document.
    """
    blocks: list[dict[str, Any]] = []
    for rule in policy.get("spec", {}).get("egress", []):
        for dest in rule.get("to", []):
            if "ipBlock" in dest:
                blocks.append(dest["ipBlock"])
    return blocks


def _egress_has_port_only_rule(policy: dict[str, Any]) -> bool:
    """
    Returns True if any egress rule has `ports` but no `to:` block
    (the vulnerable pattern that permits egress to any destination including IPv6).
    """
    for rule in policy.get("spec", {}).get("egress", []):
        if rule.get("ports") and not rule.get("to"):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def rendered_policies() -> dict[str, Any]:
    """Module-scoped: render once, parse all NetworkPolicy docs."""
    rendered = _helm_template()
    return _parse_network_policies(rendered)


class TestCaddyIngressIPv6:
    """Gap 1 / FIND-C9-001 MEDIUM — allow-caddy-ingress must accept IPv6 clients."""

    def test_policy_exists(self, rendered_policies: dict[str, Any]) -> None:
        assert "allow-caddy-ingress" in rendered_policies, (
            "allow-caddy-ingress NetworkPolicy not found in helm render"
        )

    def test_ipv4_cidr_present(self, rendered_policies: dict[str, Any]) -> None:
        """0.0.0.0/0 must be present for IPv4 internet clients."""
        cidrs = _ingress_cidrs(rendered_policies["allow-caddy-ingress"])
        assert "0.0.0.0/0" in cidrs, (
            f"allow-caddy-ingress: missing 0.0.0.0/0 ipBlock ingress. "
            f"Found: {cidrs}"
        )

    def test_ipv6_cidr_present(self, rendered_policies: dict[str, Any]) -> None:
        """
        ::/0 must be present for IPv6 internet clients on dual-stack clusters.
        Tiago directive 2026-05-26: 'allow ipv6 in the front to connect to
        the internet if the client wants to'.
        FIND-C9-001 MEDIUM: without ::/0, IPv6 LoadBalancer traffic is
        dropped on dual-stack K8s clusters.
        """
        cidrs = _ingress_cidrs(rendered_policies["allow-caddy-ingress"])
        assert "::/0" in cidrs, (
            f"allow-caddy-ingress: missing ::/0 ipBlock ingress (FIND-C9-001). "
            f"IPv6 internet clients will be dropped on dual-stack clusters. "
            f"Found CIDRs: {cidrs}"
        )

    def test_both_cidrs_cover_ports_443_and_80(
        self, rendered_policies: dict[str, Any]
    ) -> None:
        """Both 0.0.0.0/0 and ::/0 rules must cover ports 443 and 80."""
        policy = rendered_policies["allow-caddy-ingress"]
        cidr_to_ports: dict[str, set[int]] = {}
        for rule in policy.get("spec", {}).get("ingress", []):
            ports = {p["port"] for p in rule.get("ports", [])}
            for source in rule.get("from", []):
                cidr = source.get("ipBlock", {}).get("cidr")
                if cidr in ("0.0.0.0/0", "::/0"):
                    cidr_to_ports.setdefault(cidr, set()).update(ports)

        for cidr in ("0.0.0.0/0", "::/0"):
            covered = cidr_to_ports.get(cidr, set())
            assert 443 in covered and 80 in covered, (
                f"allow-caddy-ingress: ipBlock {cidr!r} does not cover "
                f"both port 443 and 80. Covered ports: {covered}"
            )


class TestOllamaEgressIPv4Only:
    """Gap 2 / LAURA-V243-003 HIGH — allow-ollama-egress must be IPv4-only."""

    def test_policy_exists(self, rendered_policies: dict[str, Any]) -> None:
        assert "allow-ollama-egress" in rendered_policies, (
            "allow-ollama-egress NetworkPolicy not found in helm render"
        )

    def test_no_port_only_egress_rule(self, rendered_policies: dict[str, Any]) -> None:
        """
        No egress rule should have `ports` without a `to:` block.
        Port-only egress without ipBlock permits egress to any destination,
        including IPv6, on dual-stack clusters (LAURA-V243-003 HIGH).
        """
        has_port_only = _egress_has_port_only_rule(
            rendered_policies["allow-ollama-egress"]
        )
        assert not has_port_only, (
            "allow-ollama-egress: found port-only egress rule (no 'to:' block). "
            "This implicitly permits IPv6 egress on dual-stack clusters. "
            "Add an explicit ipBlock with cidr: 0.0.0.0/0 and RFC1918 except entries."
        )

    def test_has_explicit_ipv4_ipblock(self, rendered_policies: dict[str, Any]) -> None:
        """Egress must have an explicit 0.0.0.0/0 ipBlock."""
        blocks = _egress_ip_blocks(rendered_policies["allow-ollama-egress"])
        cidrs = {b["cidr"] for b in blocks}
        assert "0.0.0.0/0" in cidrs, (
            f"allow-ollama-egress: no 0.0.0.0/0 ipBlock in egress. "
            f"Found: {cidrs}"
        )

    def test_rfc1918_ranges_excluded(self, rendered_policies: dict[str, Any]) -> None:
        """RFC1918 private ranges must appear in except: to prevent targeting internal services."""
        blocks = _egress_ip_blocks(rendered_policies["allow-ollama-egress"])
        ipv4_block = next(
            (b for b in blocks if b.get("cidr") == "0.0.0.0/0"), None
        )
        assert ipv4_block is not None, (
            "allow-ollama-egress: 0.0.0.0/0 ipBlock not found"
        )
        except_ranges = set(ipv4_block.get("except", []))
        missing = RFC1918_RANGES - except_ranges
        assert not missing, (
            f"allow-ollama-egress: RFC1918 ranges missing from ipBlock except: {missing}. "
            f"Found: {except_ranges}"
        )

    def test_no_ipv6_cidr_in_egress(self, rendered_policies: dict[str, Any]) -> None:
        """
        ::/0 must NOT appear in egress. Tiago directive 2026-05-26:
        'anything else internally is ipv4 ... block it'.
        """
        blocks = _egress_ip_blocks(rendered_policies["allow-ollama-egress"])
        cidrs = {b["cidr"] for b in blocks}
        assert "::/0" not in cidrs, (
            f"allow-ollama-egress: ::/0 found in egress ipBlocks — violates "
            f"IPv4-internal-only directive. Found: {cidrs}"
        )


class TestOpenclawExternalEgressIPv4Only:
    """Gap 3 / LAURA-V243-003 HIGH — allow-openclaw-external-egress must be IPv4-only."""

    def test_policy_exists(self, rendered_policies: dict[str, Any]) -> None:
        assert "allow-openclaw-external-egress" in rendered_policies, (
            "allow-openclaw-external-egress NetworkPolicy not found in helm render. "
            "Ensure agentBundles.openclaw.enabled=true is set."
        )

    def test_no_port_only_egress_rule(self, rendered_policies: dict[str, Any]) -> None:
        """
        No egress rule should have `ports` without a `to:` block.
        Port-only egress without ipBlock permits egress to any destination,
        including IPv6, on dual-stack clusters (LAURA-V243-003 HIGH).
        """
        has_port_only = _egress_has_port_only_rule(
            rendered_policies["allow-openclaw-external-egress"]
        )
        assert not has_port_only, (
            "allow-openclaw-external-egress: found port-only egress rule "
            "(no 'to:' block). This implicitly permits IPv6 egress on "
            "dual-stack clusters. Add an explicit ipBlock."
        )

    def test_has_explicit_ipv4_ipblock(self, rendered_policies: dict[str, Any]) -> None:
        """Egress must have an explicit 0.0.0.0/0 ipBlock."""
        blocks = _egress_ip_blocks(rendered_policies["allow-openclaw-external-egress"])
        cidrs = {b["cidr"] for b in blocks}
        assert "0.0.0.0/0" in cidrs, (
            f"allow-openclaw-external-egress: no 0.0.0.0/0 ipBlock in egress. "
            f"Found: {cidrs}"
        )

    def test_rfc1918_ranges_excluded(self, rendered_policies: dict[str, Any]) -> None:
        """RFC1918 private ranges must appear in except: to prevent targeting internal services."""
        blocks = _egress_ip_blocks(
            rendered_policies["allow-openclaw-external-egress"]
        )
        ipv4_block = next(
            (b for b in blocks if b.get("cidr") == "0.0.0.0/0"), None
        )
        assert ipv4_block is not None, (
            "allow-openclaw-external-egress: 0.0.0.0/0 ipBlock not found"
        )
        except_ranges = set(ipv4_block.get("except", []))
        missing = RFC1918_RANGES - except_ranges
        assert not missing, (
            f"allow-openclaw-external-egress: RFC1918 ranges missing from "
            f"ipBlock except: {missing}. Found: {except_ranges}"
        )

    def test_no_ipv6_cidr_in_egress(self, rendered_policies: dict[str, Any]) -> None:
        """
        ::/0 must NOT appear in egress. Tiago directive 2026-05-26:
        'anything else internally is ipv4 ... block it'.
        """
        blocks = _egress_ip_blocks(
            rendered_policies["allow-openclaw-external-egress"]
        )
        cidrs = {b["cidr"] for b in blocks}
        assert "::/0" not in cidrs, (
            f"allow-openclaw-external-egress: ::/0 found in egress ipBlocks — "
            f"violates IPv4-internal-only directive. Found: {cidrs}"
        )


class TestOpenclawWebhookEgressIPv4Only:
    """
    A3 HIGH / LAURA-V243-003 residual — allow-openclaw-egress webhook rule
    must be IPv4-only (not port-only).

    allow-openclaw-external-egress (PR #155 v2.24.3) closed the broad external
    HTTPS egress gap. But allow-openclaw-egress (the webhook section of the
    per-agent policy) still carried a port-only rule with no `to:` ipBlock —
    on dual-stack K8s that implicitly permits egress to ANY destination
    including IPv6, regenerating the LAURA-V243-003 gap.

    Fix: the webhook egress rule now uses the same explicit IPv4-public-internet
    ipBlock pattern as allow-ollama-egress and allow-openclaw-external-egress.
    """

    def test_policy_exists(self, rendered_policies: dict[str, Any]) -> None:
        assert "allow-openclaw-egress" in rendered_policies, (
            "allow-openclaw-egress NetworkPolicy not found in helm render. "
            "Ensure agentBundles.openclaw.enabled=true is set."
        )

    def test_no_port_only_egress_rule(self, rendered_policies: dict[str, Any]) -> None:
        """
        No egress rule in allow-openclaw-egress should have `ports` without
        a `to:` block. Port-only egress permits egress to any IPv6 destination
        on dual-stack clusters (LAURA-V243-003 residual A3 HIGH).
        """
        has_port_only = _egress_has_port_only_rule(
            rendered_policies["allow-openclaw-egress"]
        )
        assert not has_port_only, (
            "allow-openclaw-egress: found port-only egress rule (no 'to:' block). "
            "This implicitly permits IPv6 egress on dual-stack clusters "
            "(LAURA-V243-003 residual). Add an explicit ipBlock with cidr: "
            "0.0.0.0/0 and RFC1918 except entries."
        )

    def test_webhook_rule_has_explicit_ipv4_ipblock(
        self, rendered_policies: dict[str, Any]
    ) -> None:
        """Webhook egress must carry an explicit 0.0.0.0/0 ipBlock."""
        blocks = _egress_ip_blocks(rendered_policies["allow-openclaw-egress"])
        cidrs = {b["cidr"] for b in blocks}
        assert "0.0.0.0/0" in cidrs, (
            f"allow-openclaw-egress: no 0.0.0.0/0 ipBlock in egress. "
            f"Found: {cidrs}"
        )

    def test_webhook_rule_rfc1918_excluded(
        self, rendered_policies: dict[str, Any]
    ) -> None:
        """RFC1918 private ranges must appear in except: on the webhook ipBlock."""
        blocks = _egress_ip_blocks(rendered_policies["allow-openclaw-egress"])
        ipv4_block = next(
            (b for b in blocks if b.get("cidr") == "0.0.0.0/0"), None
        )
        assert ipv4_block is not None, (
            "allow-openclaw-egress: 0.0.0.0/0 ipBlock not found"
        )
        except_ranges = set(ipv4_block.get("except", []))
        missing = RFC1918_RANGES - except_ranges
        assert not missing, (
            f"allow-openclaw-egress: RFC1918 ranges missing from ipBlock "
            f"except: {missing}. Found: {except_ranges}"
        )

    def test_no_ipv6_cidr_in_egress(self, rendered_policies: dict[str, Any]) -> None:
        """::/0 must NOT appear in allow-openclaw-egress egress blocks."""
        blocks = _egress_ip_blocks(rendered_policies["allow-openclaw-egress"])
        cidrs = {b["cidr"] for b in blocks}
        assert "::/0" not in cidrs, (
            f"allow-openclaw-egress: ::/0 found in egress ipBlocks — violates "
            f"IPv4-internal-only directive. Found: {cidrs}"
        )
