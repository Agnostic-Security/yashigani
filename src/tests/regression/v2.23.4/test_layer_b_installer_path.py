"""
Regression tests for BUG-INSTALLER-AUTO-AGENT-REG-401 (backlog #9, v2.23.4).

Root cause: register_agent_bundles() Python heredoc in install.sh was missing:
  1. X-Caddy-Verified-Secret header on all direct-backoffice HTTP requests
     (CaddyVerifiedMiddleware returns 401 without it on every non-healthz route).
  2. /auth/stepup call before POST /admin/agents
     (StepUpAdminSession middleware returns 401/step_up_required without it).

This file tests that both fixes are present in install.sh:
  - The heredoc reads caddy_internal_hmac from /run/secrets/.
  - X-Caddy-Verified-Secret header appears on the login request.
  - X-Caddy-Verified-Secret header appears on the stepup request.
  - X-Caddy-Verified-Secret header appears on each agent POST.
  - The /auth/stepup call sits between the login block and the agent registration loop.

Test strategy: static-string grep on the extracted register_agent_bundles()
function body — no live service required (same pattern as test_install_totp_uri.py).

Last updated: 2026-05-13T00:00:00+01:00
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[4]  # regression/v2.23.4 → repo root
INSTALL_SH = REPO_ROOT / "install.sh"


def _extract_function(func_name: str) -> str:
    """
    Extract a bash function body from install.sh by name.
    Returns the full text between the opening '{' and the matching closing '}'.
    Raises pytest.fail() if the function is not found.
    """
    if not INSTALL_SH.exists():
        pytest.skip(f"install.sh not found at {INSTALL_SH}")

    lines = INSTALL_SH.read_text(encoding="utf-8").splitlines()
    in_func = False
    depth = 0
    collected: list[str] = []

    for line in lines:
        if not in_func:
            if re.match(rf"^{re.escape(func_name)}\s*\(\)", line):
                in_func = True
                depth = 0
                collected.append(line)
                depth += line.count("{") - line.count("}")
                continue
        else:
            collected.append(line)
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                break

    if not collected:
        pytest.fail(f"Could not extract function {func_name!r} from {INSTALL_SH}")
    return "\n".join(collected)


def _get_register_body() -> str:
    return _extract_function("register_agent_bundles")


# ---------------------------------------------------------------------------
# Layer B header: caddy_internal_hmac read
# ---------------------------------------------------------------------------

class TestCaddyHmacRead:
    """
    The installer must read caddy_internal_hmac from /run/secrets/ before making
    any HTTP request to the backoffice. Without this value the header cannot be set.
    """

    def test_caddy_internal_hmac_read(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: register_agent_bundles() must call
        read_secret("caddy_internal_hmac") to load the Layer B HMAC secret.
        """
        body = _get_register_body()
        assert 'read_secret("caddy_internal_hmac")' in body, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: register_agent_bundles() must read "
            "caddy_internal_hmac from /run/secrets/ — CaddyVerifiedMiddleware returns "
            "HTTP 401 on every request that lacks the X-Caddy-Verified-Secret header."
        )

    def test_caddy_hmac_checked_in_missing_secrets_guard(self):
        """
        caddy_hmac must be included in the missing-secrets guard so the script
        exits cleanly when the secret is absent rather than sending empty headers.
        """
        body = _get_register_body()
        # The guard must include caddy_hmac alongside the other secrets
        assert "caddy_hmac" in body, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: caddy_hmac variable must be present "
            "in register_agent_bundles() Python block"
        )
        # The all([...]) guard must reference caddy_hmac
        guard_match = re.search(r"if not all\(\[([^\]]+)\]\)", body)
        assert guard_match is not None, (
            "register_agent_bundles(): missing-secrets guard 'if not all([...])' not found"
        )
        assert "caddy_hmac" in guard_match.group(1), (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: caddy_hmac must be included in the "
            "missing-secrets guard — an empty HMAC would silently produce a broken header"
        )


# ---------------------------------------------------------------------------
# Layer B header: X-Caddy-Verified-Secret on all three endpoints
# ---------------------------------------------------------------------------

class TestXCaddyVerifiedSecretHeader:
    """
    X-Caddy-Verified-Secret must appear on every direct-backoffice HTTP request:
    login, stepup, and each agent POST.

    CaddyVerifiedMiddleware (caddy_verified.py:172-184) returns HTTP 401 with
    CADDY_VERIFIED_REQUIRED on any request that lacks this header.
    """

    def test_header_present_on_login_request(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: login request must include
        X-Caddy-Verified-Secret header.
        """
        body = _get_register_body()
        # The login Request block must set the header
        login_block_match = re.search(
            r'Request\("https://localhost:8443/auth/login".*?\)',
            body,
            re.DOTALL,
        )
        assert login_block_match is not None, (
            "register_agent_bundles(): login Request() call not found"
        )
        login_block = login_block_match.group(0)
        assert "X-Caddy-Verified-Secret" in login_block, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/login Request must include "
            "X-Caddy-Verified-Secret header — missing header causes HTTP 401 from "
            "CaddyVerifiedMiddleware before authentication can proceed"
        )

    def test_header_present_on_stepup_request(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: stepup request must include
        X-Caddy-Verified-Secret header.
        """
        body = _get_register_body()
        stepup_block_match = re.search(
            r'Request\("https://localhost:8443/auth/stepup".*?\)',
            body,
            re.DOTALL,
        )
        assert stepup_block_match is not None, (
            "register_agent_bundles(): stepup Request() call not found — "
            "/auth/stepup must be called between login and agent registration"
        )
        stepup_block = stepup_block_match.group(0)
        assert "X-Caddy-Verified-Secret" in stepup_block, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup Request must include "
            "X-Caddy-Verified-Secret header"
        )

    def test_header_present_on_agent_post_request(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: agent registration POST must include
        X-Caddy-Verified-Secret header.
        """
        body = _get_register_body()
        agents_block_match = re.search(
            r'Request\("https://localhost:8443/admin/agents".*?\)',
            body,
            re.DOTALL,
        )
        assert agents_block_match is not None, (
            "register_agent_bundles(): /admin/agents Request() call not found"
        )
        agents_block = agents_block_match.group(0)
        assert "X-Caddy-Verified-Secret" in agents_block, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /admin/agents Request must include "
            "X-Caddy-Verified-Secret header"
        )

    def test_header_value_is_caddy_hmac_variable(self):
        """
        The X-Caddy-Verified-Secret header value must reference the caddy_hmac
        variable (not a hardcoded string or empty).
        """
        body = _get_register_body()
        # Every occurrence of X-Caddy-Verified-Secret should reference caddy_hmac
        header_assignments = re.findall(
            r'"X-Caddy-Verified-Secret"\s*:\s*([^\n,}]+)',
            body,
        )
        assert len(header_assignments) >= 3, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: expected X-Caddy-Verified-Secret header "
            f"on at least 3 requests (login, stepup, agent POST), found {len(header_assignments)}"
        )
        for assignment in header_assignments:
            assert "caddy_hmac" in assignment, (
                f"BUG-INSTALLER-AUTO-AGENT-REG-401: X-Caddy-Verified-Secret value must "
                f"reference caddy_hmac variable, got: {assignment!r}"
            )


# ---------------------------------------------------------------------------
# Ordering: stepup must sit between login and agent registration
# ---------------------------------------------------------------------------

class TestStepupOrdering:
    """
    /auth/stepup must be called AFTER login (session cookie needed) and BEFORE
    POST /admin/agents (StepUpAdminSession is required for that route).

    Without stepup: POST /admin/agents returns HTTP 401 step_up_required.
    """

    def test_stepup_endpoint_is_present(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup must be called in
        register_agent_bundles().
        """
        body = _get_register_body()
        assert "/auth/stepup" in body, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup call missing from "
            "register_agent_bundles() — POST /admin/agents requires StepUpAdminSession "
            "(assert_fresh_stepup), which returns HTTP 401 step_up_required when "
            "last_totp_verified_at is None"
        )

    def test_stepup_call_before_agent_registration_loop(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup call must appear BEFORE
        the /admin/agents registration loop.

        Search for the Request() URL strings (not comments) to avoid a false
        ordering result from the step-up comment that mentions /admin/agents.
        """
        body = _get_register_body()
        # Use the full quoted URL as it appears in Request() calls
        stepup_url = '"https://localhost:8443/auth/stepup"'
        agents_url = '"https://localhost:8443/admin/agents"'

        stepup_idx = body.find(stepup_url)
        agents_idx = body.find(agents_url)

        assert stepup_idx != -1, (
            "register_agent_bundles(): Request URL 'https://localhost:8443/auth/stepup' "
            "not found — /auth/stepup call must be present"
        )
        assert agents_idx != -1, (
            "register_agent_bundles(): Request URL 'https://localhost:8443/admin/agents' "
            "not found"
        )
        assert stepup_idx < agents_idx, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup Request must appear BEFORE "
            "/admin/agents Request in register_agent_bundles() — stepup must complete "
            "before any agent POST to satisfy StepUpAdminSession"
        )

    def test_stepup_call_after_login_session_extraction(self):
        """
        /auth/stepup must appear AFTER the session cookie is extracted from the
        login response (stepup requires an active admin session).
        """
        body = _get_register_body()
        # Session extraction: 'if not session:' guard
        session_guard_idx = body.find("if not session:")
        stepup_idx = body.find("/auth/stepup")

        assert session_guard_idx != -1, (
            "register_agent_bundles(): 'if not session:' guard not found — "
            "session extraction block must be present before stepup"
        )
        assert stepup_idx > session_guard_idx, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: /auth/stepup must appear AFTER "
            "the session cookie is extracted from the login response"
        )

    def test_stepup_failure_is_warn_and_continue(self):
        """
        BUG-INSTALLER-AUTO-AGENT-REG-401: stepup failure must produce a WARNING
        log, not a hard sys.exit(). The installer pattern is warn-and-continue
        so a TOTP replay or timing edge case does not abort the entire install.
        """
        body = _get_register_body()

        # Find the stepup try/except block
        stepup_pos = body.find("/auth/stepup")
        assert stepup_pos != -1, "register_agent_bundles(): /auth/stepup not found"

        # After the stepup request, there must be a WARNING print, not sys.exit
        after_stepup = body[stepup_pos:]
        # Must contain WARNING
        assert "WARNING:stepup_failed" in after_stepup, (
            "BUG-INSTALLER-AUTO-AGENT-REG-401: stepup failure must print "
            "WARNING:stepup_failed (warn-and-continue pattern)"
        )
        # Must NOT call sys.exit in the stepup except block (before # Register agents)
        register_agents_pos = after_stepup.find("# Register agents")
        if register_agents_pos != -1:
            stepup_except_region = after_stepup[:register_agents_pos]
            assert "sys.exit" not in stepup_except_region, (
                "BUG-INSTALLER-AUTO-AGENT-REG-401: stepup failure must NOT call "
                "sys.exit() — installer must warn-and-continue to match existing pattern"
            )
