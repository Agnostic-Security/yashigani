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


# ──────────────────────────────────────────────────────────────────────────
# Item 2 (Laura/Iris) -- audit events on BOTH compose and k8s payloads.
# k8s-side assertions in this class are expected to FAIL until the item-3
# commit lands the k8s twin of this fix (item 3 requires items 1+2 to apply
# to both paths; this commit lands item 2 on the compose path first).
# ──────────────────────────────────────────────────────────────────────────

class TestItem2AuditEventsBothPaths:
    @pytest.fixture(scope="class")
    def compose_payload(self) -> str:
        return _compose_python_payload(_compose_register_body())

    @pytest.fixture(scope="class")
    def k8s_payload(self) -> str:
        return _k8s_python_payload(_k8s_register_body())

    def test_compose_payload_references_audit_writer(self, compose_payload: str) -> None:
        """Laura CONFIRMED (2026-08-16): 'grep -c ... for "audit" -> 0' across
        the whole compose payload span. Must now construct an AuditLogWriter
        and write AgentRegisteredEvent."""
        assert "AuditLogWriter" in compose_payload, (
            "FIND-0813-013 item 2 REGRESSION: compose payload does not construct "
            "an AuditLogWriter -- install-time agent registration still has zero "
            "audit references (Laura's CONFIRMED finding)."
        )
        assert "AgentRegisteredEvent" in compose_payload, (
            "FIND-0813-013 item 2 REGRESSION: compose payload does not write an "
            "AgentRegisteredEvent -- must mirror routes/agents.py:533-549."
        )

    def test_compose_payload_audits_envelope_mint(self, compose_payload: str) -> None:
        """Laura: bundled_envelopes.py/envelope_service.py mint zero audit
        references on ANY call site -- the envelope-mint step must also land
        a record in the tamper-evident chain."""
        assert "MCP_ENVELOPE_MINTED" in compose_payload, (
            "FIND-0813-013 item 2 REGRESSION: the capability-envelope mint step "
            "(SEC-ENVELOPE-001) writes no audit event -- Laura's finding names "
            "this as equally unaudited to the agent-registration gap itself."
        )

    def test_k8s_payload_references_audit_writer(self, k8s_payload: str) -> None:
        """Same gap, same fix, k8s twin. Landed in the item-3 commit."""
        assert "AuditLogWriter" in k8s_payload and "AgentRegisteredEvent" in k8s_payload, (
            "FIND-0813-013 item 2/3 REGRESSION: k8s_register_agent_bundles() "
            "payload does not audit agent registration -- item 3 requires items "
            "1+2 to apply to BOTH the compose and k8s paths."
        )

    def test_k8s_payload_audits_envelope_mint(self, k8s_payload: str) -> None:
        assert "MCP_ENVELOPE_MINTED" in k8s_payload, (
            "FIND-0813-013 item 2/3 REGRESSION: k8s envelope-mint step is "
            "unaudited -- must match the compose fix."
        )

    def test_audit_write_failure_is_non_fatal(self, compose_payload: str) -> None:
        """Audit is defence-in-depth here (matches routes/agents.py:533-549's
        own try/except-log pattern) -- an audit-writer failure must never
        cause a real, successful registration to be reported as FAIL."""
        # The AgentRegisteredEvent write must be inside its own try/except,
        # separate from the registration try/except that produces OK:/FAIL:.
        assert re.search(r"except Exception as _ae:\s*\n\s*results\.append\(\"AUDIT_WARN:", compose_payload), (
            "FIND-0813-013 item 2: AgentRegisteredEvent write is not wrapped in "
            "its own non-fatal except clause -- an audit-sink failure must not "
            "cause a successful registration to be reported as FAIL:."
        )

    def test_bash_parser_recognises_audit_warn_lines(self) -> None:
        """AUDIT_WARN: lines must be a recognised case in the bash result
        parser, or the FIND-IRIS-DUP-AGENT-REGRESSION loud-failure guard
        would (harmlessly but confusingly) treat a run that ONLY produced
        AUDIT_WARN: lines as an unrecognised infra failure."""
        body = _compose_register_body()
        assert "AUDIT_WARN:*" in body, (
            "FIND-0813-013 item 2 REGRESSION: bash result parser in "
            "register_agent_bundles() has no AUDIT_WARN:* case -- an audit-only "
            "warning line would fall through unrecognised."
        )


# ──────────────────────────────────────────────────────────────────────────
# Item 3 (Iris) -- k8s parity: belt-and-braces durable-Postgres pre-check +
# the closest achievable equivalent of item 1 for the token-preservation-
# constrained k8s payload (licence-limit check + Redis-first/Postgres-second
# write order).
#
# NOTE on scope-honesty: register_agent_bundles() (compose) can switch
# wholesale to registry.register() because it always mints a brand-new
# token. k8s_register_agent_bundles() cannot -- its raw PSK is READ from a
# pre-provisioned Helm Secret and must be preserved bit-for-bit (the agent
# workload is already deployed presenting that exact token). register()
# always mints its own token internally with no way to inject a
# caller-supplied one, so calling it here would desync the registered
# bcrypt hash from what the running agent pod actually presents, breaking
# k8s agent auth outright. This class tests the CLOSEST correct equivalent,
# not a literal register() call.
# ──────────────────────────────────────────────────────────────────────────

class TestItem3K8sParity:
    @pytest.fixture(scope="class")
    def k8s_body(self) -> str:
        return _k8s_register_body()

    @pytest.fixture(scope="class")
    def k8s_payload(self, k8s_body: str) -> str:
        return _k8s_python_payload(k8s_body)

    def test_belt_and_braces_postgres_precheck_present(self, k8s_body: str) -> None:
        """Iris CONFIRMED: k8s_register_agent_bundles() lacked the
        durable-Postgres pre-check register_agent_bundles() (compose) has,
        leaving k8s MORE exposed to the FIND-IRIS-DUP-AGENT race than
        compose. Must gain an equivalent pre-check querying agent_registry
        directly via the postgres pod, with the SAME fail-open invariant
        (a query failure must exclude nobody)."""
        assert "_ysg_agent_pre_existing" in k8s_body, (
            "FIND-0813-013 item 3 REGRESSION: k8s_register_agent_bundles() has "
            "no durable-Postgres pre-check (_ysg_agent_pre_existing) -- the "
            "cross-runtime asymmetry Iris found is unresolved."
        )
        assert "agent_registry" in k8s_body and "psql" in k8s_body, (
            "FIND-0813-013 item 3 REGRESSION: k8s pre-check does not query the "
            "durable agent_registry table via psql."
        )

    def test_precheck_gates_before_token_fetch(self, k8s_body: str) -> None:
        """The pre-check skip must happen BEFORE the (network-costly, and in
        the token-not-found case log-noisy) kubectl get secret call, not
        after -- mirroring the compose ordering where the pre-check gates
        entry into the per-profile body before any further work."""
        precheck_pos = k8s_body.find("FIND-IRIS-DUP-AGENT guard, k8s")
        token_fetch_pos = k8s_body.find("kubectl get secret")
        assert precheck_pos != -1, "pre-check skip branch not found"
        assert token_fetch_pos != -1, "kubectl get secret token fetch not found"
        assert precheck_pos < token_fetch_pos, (
            "FIND-0813-013 item 3: the pre-check skip must gate BEFORE the "
            "kubectl get secret token fetch, not after."
        )

    def test_fail_open_invariant_preserved(self, k8s_body: str) -> None:
        """FIND-IRIS-DUP-AGENT-REGRESSION invariant (compose comment, must
        hold for k8s too): on a pre-check query failure, the pre-existing
        set must stay empty (fail-open, excludes nobody) -- never populated
        with a poisoned value that would cause every profile to be
        (wrongly) treated as pre-existing."""
        assert 'local _ysg_agent_pre_existing=","' in k8s_body, (
            "FIND-0813-013 item 3 REGRESSION: _ysg_agent_pre_existing must be "
            "seeded to the empty-membership sentinel \",\" -- any other seed "
            "value risks the fail-open invariant."
        )

    def test_license_limit_check_present(self, k8s_payload: str) -> None:
        """Item 1 (k8s twin): register() cannot be used here (token must be
        preserved), so the SAME licence-limit enforcement register() performs
        atomically must be replicated as an explicit defence-in-depth check
        against the same get_license() source of truth."""
        assert "get_license" in k8s_payload and "LicenseLimitExceeded" in k8s_payload, (
            "FIND-0813-013 item 1/3 REGRESSION: k8s payload has no licence-limit "
            "check -- restore_from_durable() does not enforce max_agents "
            "(registry.py docstring), and this path cannot call register() "
            "(token-preservation constraint), so it must replicate the check "
            "explicitly."
        )

    def test_redis_before_postgres_write_order(self, k8s_payload: str) -> None:
        """Item 1 (k8s twin): restore_from_durable() (Redis) must run BEFORE
        durable.upsert() (Postgres) -- the old order (Postgres first, Redis
        second, both inside one try/except) could leave a permanently-stuck
        active Postgres row with no Redis entry if the Redis write then
        failed. This matches register()s Redis-first/Postgres-second
        semantics and every other AgentRegistry mutator."""
        redis_pos = k8s_payload.find("registry.restore_from_durable(")
        postgres_pos = k8s_payload.find("durable.upsert(")
        assert redis_pos != -1 and postgres_pos != -1, "both calls must be present"
        assert redis_pos < postgres_pos, (
            "FIND-0813-013 item 1/3 REGRESSION: k8s payload still writes "
            "Postgres (durable.upsert) BEFORE Redis (restore_from_durable) -- "
            "must be reordered Redis-first to match register()s semantics and "
            "avoid a permanently-stuck active-Postgres/absent-Redis split."
        )

    def test_postgres_mirror_failure_is_non_fatal(self, k8s_payload: str) -> None:
        """The Postgres mirror write (durable.upsert, now SECOND) must be
        wrapped in its own try/except -- a Postgres failure must not cause a
        successful Redis registration to be reported as FAIL:."""
        assert re.search(
            r"try:\s*\n\s*durable\.upsert\(agent_data, token_hash=token_hash\)\s*\n\s*except Exception as _de:\s*\n\s*results\.append\(\"DURABLE_WARN:",
            k8s_payload,
        ), (
            "FIND-0813-013 item 1/3 REGRESSION: durable.upsert() in the k8s "
            "payload is not wrapped in its own non-fatal except clause -- a "
            "Postgres mirror failure must not roll back a successful Redis "
            "registration into a reported FAIL:."
        )


# ──────────────────────────────────────────────────────────────────────────
# Item 4 (Captain) -- the "mesh-isolated (data-network only)" security
# comment was factually false (backoffice is on 7 networks, including
# caddy_internal, shared with the internet-facing Caddy edge proxy) and
# must be replaced with the real trust basis (host/cluster exec
# authorization, which differs between rootful Docker and rootless Podman).
# ──────────────────────────────────────────────────────────────────────────

class TestItem4CommentAccuracy:
    def test_false_mesh_isolated_claim_removed_from_install_sh(self) -> None:
        payload = _compose_python_payload(_compose_register_body())
        assert "mesh-isolated (data-network only)" not in payload, (
            "FIND-0813-013 item 4 REGRESSION: the false 'mesh-isolated "
            "(data-network only)' security justification is still present in "
            "register_agent_bundles(). Captain REFUTED this claim (backoffice "
            "is on 7 networks including caddy_internal, shared with the "
            "internet-facing Caddy edge proxy) -- it must be replaced, not "
            "merely reworded around."
        )

    def test_real_trust_basis_documented_in_install_sh(self) -> None:
        payload = _compose_python_payload(_compose_register_body())
        assert "exec authorization" in payload or "EXEC AUTHORIZATION" in payload, (
            "FIND-0813-013 item 4 REGRESSION: the corrected comment must name "
            "the ACTUAL control (host/cluster exec authorization), not just "
            "delete the false claim and say nothing."
        )
        assert "rootless" in payload.lower() and "rootful" in payload.lower(), (
            "FIND-0813-013 item 4 REGRESSION: the corrected comment must "
            "distinguish rootful Docker (exec access already root-equivalent) "
            "from rootless Podman (exec access is NOT root-equivalent -- a "
            "real, not merely latent, capability gap per Captain's review) -- "
            "a single blanket justification across both runtimes is exactly "
            "the defect Captain found in the original comment."
        )

    def test_docker_compose_caddy_internal_comment_corrected(self) -> None:
        text = COMPOSE_YML.read_text(encoding="utf-8")
        # Extract the caddy_internal: network definition block.
        idx = text.find("caddy_internal:")
        assert idx != -1, "caddy_internal: network definition not found in docker-compose.yml"
        block = text[idx:idx + 2000]
        assert "FIND-0813-013" in block, (
            "FIND-0813-013 item 4 REGRESSION: docker-compose.yml's "
            "caddy_internal network definition does not reference the "
            "corrected trust-basis writeup -- a future reader could still "
            "independently re-derive the false 'internal: true == isolated "
            "from the internet' claim from this file alone."
        )
        assert "internet" in block.lower(), (
            "FIND-0813-013 item 4 REGRESSION: the caddy_internal comment must "
            "explicitly clarify that Caddy (internet-facing) is a member of "
            "this bridge -- internal: true does not mean internet-isolated."
        )

    def test_yaml_still_parses(self) -> None:
        import yaml
        with open(COMPOSE_YML) as f:
            doc = yaml.safe_load(f)
        assert "caddy_internal" in doc["networks"], (
            "docker-compose.yml no longer parses correctly after the item-4 "
            "comment edit, or the caddy_internal network definition was lost."
        )


# ──────────────────────────────────────────────────────────────────────────
# Item 5 (Nico) -- the ".dup-<ts>" re-registration backup must not leave a
# live, un-TTL'd, unencrypted PSK sitting in the live secrets dir forever.
# ──────────────────────────────────────────────────────────────────────────

class TestItem5DupTokenDisposition:
    @pytest.fixture(scope="class")
    def register_body(self) -> str:
        return _compose_register_body()

    def test_plaintext_cp_backup_removed(self, register_body: str) -> None:
        """Nico CONFIRMED (sharpest finding): `cp -p ... .dup-<ts>` left a
        permanent, unencrypted, un-TTL'd copy of a still-valid raw PSK in the
        live secrets dir with no code path that ever deleted it. The
        plaintext-preserving cp -p must be gone."""
        assert 'cp -p "${secrets_dir}' not in register_body, (
            "FIND-0813-013 item 5 REGRESSION: register_agent_bundles() still "
            "invokes `cp -p` to preserve the stale raw token in plaintext at "
            "${secrets_dir}/${_profile}_token.dup-<ts> -- Nico's CONFIRMED "
            "finding (a permanent, unencrypted, un-TTL'd live credential on "
            "disk) is unresolved."
        )
        assert '_dup_backup=' not in register_body, (
            "FIND-0813-013 item 5 REGRESSION: the .dup-<ts> backup filename "
            "variable (_dup_backup) is still assigned -- the stale plaintext "
            "token must not be written to a new file at all, not just "
            "renamed (mentioning the old pattern in an explanatory comment "
            "about what was removed is fine; actually constructing the "
            "filename is not)."
        )

    def test_stale_token_securely_removed(self, register_body: str) -> None:
        """The old plaintext token file must actually be deleted (shred
        preferred, rm -f fallback), not left on disk under any name."""
        assert re.search(r"shred\s+-u.*token", register_body) or \
               re.search(r'rm\s+-f\s+--\s+"\$\{secrets_dir\}/\$\{_profile\}_token"', register_body), (
            "FIND-0813-013 item 5 REGRESSION: no secure-delete (shred -u, or "
            "rm -f fallback) of the stale token file found -- the old "
            "plaintext PSK must be actively removed, not merely left in "
            "place under its original name either."
        )

    def test_fingerprint_logged_not_raw_token(self, register_body: str) -> None:
        """A SHA-256 fingerprint (irreversible, cannot authenticate) may be
        logged for operator correlation -- the raw token value itself must
        never appear in a log line."""
        assert "sha256sum" in register_body, (
            "FIND-0813-013 item 5: no SHA-256 fingerprint computed for "
            "operator log-correlation before the stale token is destroyed -- "
            "an operator has zero way to correlate the log entry to the "
            "credential that was removed."
        )
        # The fingerprint variable, not the raw $_token, must be what is logged.
        assert "_dup_fp" in register_body, (
            "FIND-0813-013 item 5 REGRESSION: fingerprint variable not found "
            "in the FIND-IRIS-DUP-AGENT log_error message."
        )

    def test_operator_guidance_still_present(self, register_body: str) -> None:
        """The existing /admin/agents remediation guidance must be preserved
        (not just the plaintext removed) -- an operator still needs to know
        HOW to resolve the duplicate registration."""
        assert "/admin/agents" in register_body, (
            "FIND-0813-013 item 5 REGRESSION: /admin/agents remediation "
            "guidance was lost when the plaintext-preservation branch was "
            "rewritten."
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
