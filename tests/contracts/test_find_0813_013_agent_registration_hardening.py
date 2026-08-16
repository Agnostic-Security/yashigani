# Last updated: 2026-08-16T00:00:00+00:00
"""
Contract/regression tests for FIND-0813-013 (SEC-001 no-admin-API durable
agent-registration path) -- six-reviewer red panel (Laura/Iris/Tom/Captain/
Nico), findings in
testing_runs/yashigani/ytf-412-20260813/red-sec001-{tom,captain,nico,iris,
laura}.md (2026-08-16). Scope of THIS fix pass: install.sh only, plus a
comment in docker/docker-compose.yml (Captain item 4).

Static/string-level tests only -- no live stack (rig wiped). Each test in
this module is written to FAIL against the pre-fix install.sh content
(preserved for reference reasoning at ``git show HEAD~N:install.sh`` at the
commit that introduces it) and PASS against the fixed content, proving the
check has teeth.

Item map:
  1. Tom  -- register_agent_bundles() (compose) must call
             AgentRegistry(_rc, durable_store=durable).register(...) instead
             of hand-rolled durable.upsert()+restore_from_durable() (closes
             the max_agents licence-limit bypass + the Postgres-before-Redis
             write-order inversion).
  2. Laura/Iris -- both the compose and k8s durable-write payloads must emit
             an AgentRegisteredEvent (mirrors routes/agents.py:533-549) and
             an envelope-mint audit record; zero audit refs pre-fix.
  3. Iris -- k8s_register_agent_bundles() must gain the SAME belt-and-braces
             durable-Postgres pre-check register_agent_bundles() (compose)
             already has, closing the cross-runtime FIND-IRIS-DUP-AGENT
             exposure asymmetry.
  4. Captain -- the payload's "mesh-isolated (data-network only)" comment is
             factually false (backoffice is on 7 networks, including
             caddy_internal, the bridge shared with the internet-facing
             Caddy edge proxy) and must be replaced with the real trust
             basis (host/cluster exec authorization, which differs between
             rootful Docker and rootless Podman).
  5. Nico -- the ``.dup-<ts>`` re-registration backup must not leave a live,
             un-TTL'd, unencrypted PSK sitting in the live secrets dir
             forever; the stale plaintext token must be securely removed,
             not preserved.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
COMPOSE_YML = REPO_ROOT / "docker" / "docker-compose.yml"


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────

def _read_install() -> str:
    return INSTALL_SH.read_text(encoding="utf-8")


def _extract_function(script: str, signature: str) -> str:
    """Extract a top-level bash function body by its `name() {` signature line."""
    lines = script.splitlines()
    start = None
    depth = 0
    for i, line in enumerate(lines):
        if start is None:
            if line.strip() == signature:
                start = i
                # Count the signature line's own opening brace -- it is NOT
                # revisited below (the loop `continue`s past it), so depth
                # must be seeded here or the very first inner "}" line (e.g.
                # a dict literal close inside the embedded python payload)
                # is mistaken for the function's closing brace.
                depth = line.count("{") - line.count("}")
                continue
        else:
            depth += line.count("{") - line.count("}")
            if depth <= 0 and line.strip() == "}":
                return "\n".join(lines[start:i + 1])
    raise AssertionError(f"{signature!r} not found in install.sh")


def _compose_register_body() -> str:
    return _extract_function(_read_install(), "register_agent_bundles() {")


def _k8s_register_body() -> str:
    return _extract_function(_read_install(), "k8s_register_agent_bundles() {")


def _compose_python_payload(body: str) -> str:
    m = re.search(r"python3 -c '\n(.*?)\n'\s*2>&1\)\"", body, re.S)
    assert m, "compose python3 -c payload not found inside register_agent_bundles()"
    return m.group(1)


def _k8s_python_payload(body: str) -> str:
    m = re.search(r"python3 -c '\n(.*?)\n'\s*<<<", body, re.S)
    assert m, "k8s python3 -c payload not found inside k8s_register_agent_bundles()"
    return m.group(1)


# ──────────────────────────────────────────────────────────────────────────
# bash -n baseline -- must always pass (T2/basic sanity for every fix below)
# ──────────────────────────────────────────────────────────────────────────

def test_install_sh_bash_syntax_ok():
    import subprocess
    result = subprocess.run(["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True)
    assert result.returncode == 0, f"install.sh bash -n failed: {result.stderr}"


def test_compose_python_payload_is_valid_python():
    import ast
    payload = _compose_python_payload(_compose_register_body())
    ast.parse(payload)  # raises SyntaxError on failure


def test_k8s_python_payload_is_valid_python():
    import ast
    payload = _k8s_python_payload(_k8s_register_body())
    ast.parse(payload)  # raises SyntaxError on failure


# ──────────────────────────────────────────────────────────────────────────
# Item 1 (Tom) -- compose path uses registry.register(), not the hand-rolled
# durable.upsert()+restore_from_durable() pair.
# ──────────────────────────────────────────────────────────────────────────

class TestItem1ComposeUsesRegisterAPI:
    @pytest.fixture(scope="class")
    def payload(self) -> str:
        return _compose_python_payload(_compose_register_body())

    def test_calls_registry_register(self, payload: str) -> None:
        """FIND-0813-013 item 1: the payload must call registry.register(...)
        -- the same atomic, licence-enforced primitive
        routes/agents.py::register_agent uses. Pre-fix: this call did not
        exist at all (only durable.upsert() + registry.restore_from_durable())."""
        assert re.search(r"\bregistry\.register\(\s*$", payload, re.M) or \
               re.search(r"registry\.register\(\s*\n\s*name=", payload), (
            "FIND-0813-013 item 1 REGRESSION: register_agent_bundles() (compose) "
            "does not call registry.register(...). It must use the same atomic, "
            "licence-limit-enforced primitive routes/agents.py::register_agent "
            "uses, not a hand-rolled durable.upsert()+restore_from_durable() pair."
        )

    def test_does_not_call_restore_from_durable_for_new_registration(self, payload: str) -> None:
        """restore_from_durable()'s own docstring says it does not enforce the
        licence limit and is designed for the startup reconciler restoring
        ALREADY-licensed rows -- not for originating brand-new agents. It must
        no longer be CALLED from the registration try block (mentions inside
        explanatory comments about the removed old behaviour are fine)."""
        assert "registry.restore_from_durable(" not in payload, (
            "FIND-0813-013 item 1 REGRESSION: registry.restore_from_durable() is "
            "still called from the NEW-registration path. Its own docstring says "
            "\"Does not enforce the licence limit\" -- using it to originate new "
            "rows bypasses max_agents entirely. Use registry.register() instead."
        )

    def test_durable_store_wired_into_constructor(self, payload: str) -> None:
        """register() only dual-writes to Postgres when constructed with
        durable_store= (registry.py:244-265). Without it, register() is
        Redis-only and durability regresses relative to the pre-fix behaviour."""
        assert re.search(r"AgentRegistry\(\s*_rc\s*,\s*durable_store\s*=\s*durable\s*\)", payload), (
            "FIND-0813-013 item 1 REGRESSION: AgentRegistry(...) must be "
            "constructed with durable_store=durable so register() performs its "
            "own Postgres dual-write (registry.py ISSUE-AGENT-REG-DURABILITY)."
        )

    def test_license_limit_exceeded_is_handled(self, payload: str) -> None:
        """register() raises LicenseLimitExceeded on breach (registry.py:219-232).
        The payload must import and handle it explicitly (even if the outer
        bare except would also catch it) so a licence-limit FAIL is
        identifiable, matching routes/agents.py:519-523's HTTP 402 handling
        in spirit."""
        assert "LicenseLimitExceeded" in payload, (
            "FIND-0813-013 item 1: LicenseLimitExceeded is never imported/handled "
            "-- register_agent_bundles() (compose) should surface a licence-limit "
            "breach distinctly, the same failure mode routes/agents.py handles."
        )

    def test_manual_bcrypt_token_minting_removed(self, payload: str) -> None:
        """The old code hand-rolled bcrypt.hashpw()+secrets.token_hex() to mint
        the PSK itself; register() does this internally (registry.py:176-180)
        with the exact same primitives at the exact same bcrypt cost. The
        hand-rolled duplicate must be gone (single source of truth for token
        minting)."""
        assert "_bcrypt.hashpw" not in payload, (
            "FIND-0813-013 item 1 REGRESSION: manual bcrypt.hashpw() token "
            "minting still present in the compose payload -- register() already "
            "does this identically; hand-rolling it again reintroduces a second, "
            "divergence-prone implementation of the same primitive."
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
