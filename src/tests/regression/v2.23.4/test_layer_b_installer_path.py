"""
Regression tests for the installer's agent-registration path.

ORIGINAL SCOPE (v2.23.4, BUG-INSTALLER-AUTO-AGENT-REG-401): register_agent_bundles()
drove the ADMIN HTTP API and was missing the X-Caddy-Verified-Secret header and the
/auth/stepup call, so every registration 401'd. These tests asserted that HMAC header,
the admin login, and the step-up were present in the heredoc.

SUPERSEDED 2026-06-14 by SEC-001. The registration flow was deliberately REPLACED with a
"NO-ADMIN-API durable path" that writes straight to Postgres (AgentDurableStore) + Redis
db/3 (AgentRegistry) from inside the mesh-isolated backoffice container. install.sh says
so in the payload itself:

    "No admin login, no TOTP, no step-up, no install_svc service account.
     Eliminates LAURA-2255-001 (human admin bootstrap regression) and the
     install_svc standing-admin backdoor."
    "The HTTP stack is not touched — no admin session, no TOTP, no HMAC secret."

So the 10 assertions below were not merely stale: they demanded the presence of exactly
what a SECURITY fix removed. Left unchanged they exert pressure to re-introduce a
standing-admin backdoor — the precise thing SEC-001 eliminated (cf. the standing rule
against standing backdoor service accounts).

REWRITTEN 2026-08-16 to guard the CURRENT property instead: registration MUST use the
durable no-admin-API path, and MUST NOT reacquire an admin session, TOTP, step-up or an
install_svc account. The bug the old tests guarded (401 on a missing header) cannot recur,
because the HTTP admin path is no longer used at all.

Test strategy unchanged: static-string analysis of the extracted register_agent_bundles()
body — no live service required.

Last updated: 2026-08-16 (inverted to lock in SEC-001; was 2026-05-13).
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

class TestSec001NoAdminApiDurablePath:
    """SEC-001: registration writes DIRECTLY to the durable stores. It must not
    reacquire the admin HTTP path the original 401 bug lived on."""

    @staticmethod
    def _code_only(body: str) -> str:
        """Strip comment lines before scanning.

        Required in BOTH directions, which is why every test in this class now
        routes through it:

        - Negative assertions: the SEC-001 payload DOCUMENTS what it removed
          ("no install_svc service account"), so a raw scan matches the
          explanation and reports a regression that is not there.
        - Positive assertions: a comment NAMING the thing satisfies the scan
          just as well as the code doing it. Applying this to only the negative
          half (as this file originally did) leaves the positive half hollow.

        Proven, not assumed — FIND-0813-016, pre-push code-quality review
        (Change Management 4.4): with SEC-001's durable path deleted outright
        from install.sh and only the explanatory comment left behind, all four
        tests still passed. The assertion was satisfied by install.sh:11430,
        a comment inside the extracted function.
        """
        return "\n".join(
            ln for ln in body.splitlines() if not ln.lstrip().startswith("#")
        )

    def _payload(self) -> str:
        """The registration function's CODE — never its prose."""
        return self._code_only(_extract_function("register_agent_bundles"))

    def test_uses_durable_store_and_registry(self):
        body = self._payload()
        assert "AgentDurableStore" in body, (
            "SEC-001: registration must write via AgentDurableStore (Postgres). "
            "If this is gone, the no-admin-API path has been reverted."
        )
        assert "AgentRegistry" in body, (
            "SEC-001: registration must populate AgentRegistry (Redis db/3)."
        )

    def test_no_admin_login_or_totp_or_stepup(self):
        """The backdoor-shaped surfaces SEC-001 removed must stay removed."""
        body = self._payload()
        for forbidden, why in (
            ("/auth/login",  "an admin session"),
            ("/auth/stepup", "a step-up elevation"),
            ("install_svc",  "the install_svc standing-admin service account"),
            ("pyotp",        "a TOTP code"),
        ):
            assert forbidden not in body, (
                f"SEC-001 REGRESSION: register_agent_bundles() reacquired {why} "
                f"({forbidden!r}). The durable path exists precisely so the installer "
                f"never holds admin credentials — see LAURA-2255-001 and the "
                f"install_svc standing-admin backdoor this replaced."
            )

    def test_no_caddy_hmac_secret_needed(self):
        """The HTTP stack is not touched, so the HMAC header is not needed.

        This is the inverse of the ORIGINAL assertion in this file. Keeping the
        old one would have demanded the return of a credential the current
        design deliberately does without.
        """
        body = self._payload()
        assert "X-Caddy-Verified-Secret" not in body, (
            "register_agent_bundles() sends X-Caddy-Verified-Secret again — that "
            "header only matters on the admin HTTP path SEC-001 removed. Its return "
            "means the durable path was reverted."
        )

    def test_runs_inside_the_mesh_isolated_backoffice_container(self):
        """The security argument for skipping HTTP auth is that this Python runs
        INSIDE backoffice (compose exec), on the data network only."""
        body = self._payload()
        assert "python3 -c" in body, "registration payload is no longer executed in-container"
        assert re.search(r"exec\b.*backoffice|backoffice.*exec", body), (
            "registration must run via compose exec INSIDE the backoffice container — "
            "that mesh isolation is what makes the no-admin-API path safe."
        )
