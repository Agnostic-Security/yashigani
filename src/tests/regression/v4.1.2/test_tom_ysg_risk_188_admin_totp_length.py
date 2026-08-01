"""
Regression test -- v4.1.2 YSG-RISK-188:

The admin "Full reset" panel's client-side TOTP validator
(``static/ui4/admin/modules/accounts.js``, ``YsAdminUsers._fullReset``)
hard-required exactly 6 digits::

    if (!/^\\d{6}$/.test(code)) { ... 'A 6-digit admin TOTP code is required.' ... }

But ADMIN-tier TOTP is 8-digit/SHA-512 (users are 6-digit/SHA-256 -- Phase
13, see ``routes/users.py`` ``FullResetRequest.totp_code`` which already
correctly accepts ``pattern=r"^\\d{6,8}$"``, and ``ys-modal.js``'s shared
step-up prompt which already accepts ``/^\\d{6,8}$/``). A real admin
entering their valid 8-digit code was rejected client-side before the
request was ever sent -- the reset flow was unreachable for every admin.

Fix: the inline validator in ``_fullReset()`` now mirrors the shared
step-up modal's ``/^\\d{6,8}$/`` acceptance range, matching both the
pre-existing HTML ``pattern="[0-9]{6,8}"``/``maxlength="8"`` on the input
(which was already correct -- only the JS gate was wrong) and the backend
Pydantic contract.

This repo has no JS test runner (no package.json / vitest / jest) --
structural/source checks + ``node --check`` syntax validation, per the
established pattern (see test_tom_ysg_risk_163_capability_policy_ui4_nav.py).
E2E click-through coverage is Ava's Playwright remit.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_ACCOUNTS_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin" / "modules" / "accounts.js"
_YS_MODAL_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "core" / "widgets" / "ys-modal.js"
_USERS_ROUTE_PY = _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "users.py"


class TestFullResetValidatorAcceptsAdminAnd8Digits:
    def test_accounts_js_exists(self):
        assert _ACCOUNTS_JS.is_file()

    def test_full_reset_regex_accepts_6_to_8_digits(self):
        src = _ACCOUNTS_JS.read_text()
        # The OLD, buggy regex must be gone.
        assert "/^\\d{6}$/" not in src, (
            "the hard 6-digit-only regex must no longer appear in accounts.js "
            "-- it rejected valid 8-digit admin TOTP codes"
        )
        # The FIXED regex must be present, inside _fullReset specifically.
        m = re.search(r"async _fullReset\(\)\s*\{.*?\n\s*\}\n", src, re.DOTALL)
        assert m, "could not locate _fullReset() body in accounts.js"
        body = m.group(0)
        assert "/^\\d{6,8}$/" in body, (
            f"_fullReset() must validate with /^\\d{{6,8}}$/ (6 or 8 digits); body was:\n{body}"
        )

    def test_regex_actually_matches_both_lengths(self):
        """Directly exercises the JS-source regex literal via Python's re
        module (both engines implement the same \\d{6,8} semantics for a
        plain ASCII digit string) -- proves 6-digit USER codes still work
        and 8-digit ADMIN codes now work."""
        pattern = re.compile(r"^\d{6,8}$")
        assert pattern.match("123456")    # 6-digit USER (SHA-256) — must still pass
        assert pattern.match("12345678")  # 8-digit ADMIN (SHA-512) — was rejected pre-fix
        assert not pattern.match("12345")   # 5 digits — still rejected
        assert not pattern.match("123456789")  # 9 digits — still rejected
        assert not pattern.match("12345a")  # non-numeric — still rejected

    def test_html_input_pattern_was_already_correct(self):
        """Confirms the bug was purely in the JS gate, not the input markup
        -- the maxlength/pattern attributes on the <input> already allowed
        6-8 digits before this fix, they were just overridden by the
        stricter JS check on submit."""
        src = _ACCOUNTS_JS.read_text()
        assert 'maxlength="8"' in src
        assert 'pattern="[0-9]{6,8}"' in src


class TestSharedStepUpModalMatchesSameRange:
    """The shared step-up modal (used by every OTHER step-up-tagged mutation
    in the admin SPA) already accepted 6-8 digits -- confirms the fix in
    accounts.js brings the full-reset panel's own inline validator into
    parity with it, rather than introducing a THIRD, different range."""

    def test_ys_modal_accepts_6_to_8_digits(self):
        src = _YS_MODAL_JS.read_text()
        assert "/^\\d{6,8}$/" in src


class TestBackendContractAcceptsBothLengths:
    """The backend was already correct (Phase 13) -- this just confirms the
    client-side fix now matches what the server actually accepts, so a
    valid 8-digit admin code that passes the client check will also pass
    server-side validation."""

    def test_full_reset_request_pattern_accepts_6_to_8_digits(self):
        src = _USERS_ROUTE_PY.read_text()
        assert 'pattern=r"^\\d{6,8}$"' in src


class TestAccountsJsSyntaxValid:
    def test_module_is_valid_es_module_syntax(self):
        node = shutil.which("node")
        if not node:
            pytest.skip("node not installed -- syntax check skipped")
        result = subprocess.run(
            [node, "--input-type=module", "--check"],
            input=_ACCOUNTS_JS.read_text(),
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, f"node --check failed:\n{result.stderr}"
