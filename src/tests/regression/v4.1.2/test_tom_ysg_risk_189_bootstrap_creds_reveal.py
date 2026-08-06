"""
Regression test -- v4.1.2 YSG-RISK-189:

``POST /admin/users`` returns ``temporary_password`` / ``totp_secret`` /
``totp_uri`` exactly once (``routes/users.py`` ``create_user``,
``UserCreateResponse`` -- the ONLY response type the BOPLA allowlist
permits to carry these fields, since there is no other channel to deliver
them). The admin ``YsAdminUsers._create()`` handler in
``static/ui4/admin/modules/accounts.js`` called ``reportMutate()`` (a toast
only) and discarded ``res.data`` entirely -- the bootstrap credentials were
silently dropped. An admin creating a user via the WebUI had no way to hand
the user their temporary password / TOTP secret; the only working path was
calling the API directly and reading the raw JSON response.

Fix: ``_create()`` now captures ``res.data.temporary_password`` /
``totp_secret`` / ``totp_uri`` into a new ``_bootstrap`` state field and
``_renderBootstrap()`` shows them in a dedicated one-time-reveal panel
(mirrors the existing "Full reset" / "Edit" panel pattern already used in
this file), with an explicit ``_dismissBootstrap()`` action. Not persisted
beyond in-memory Lit state; never logged; cleared on Dismiss or on the next
``_create()`` navigating away.

This repo has no JS test runner -- structural/source checks + ``node
--check`` syntax validation, per the established pattern (see
test_tom_ysg_risk_163_capability_policy_ui4_nav.py / RISK-188's sibling
test in this same regression batch).
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_ACCOUNTS_JS = _REPO_ROOT / "yashigani" / "backoffice" / "static" / "ui4" / "admin" / "modules" / "accounts.js"
_USERS_ROUTE_PY = _REPO_ROOT / "yashigani" / "backoffice" / "routes" / "users.py"
_BOPLA_PY = _REPO_ROOT / "yashigani" / "backoffice" / "schemas" / "bopla.py"


def _users_class_slice(src: str) -> str:
    """accounts.js defines TWO classes -- YsAdminAccounts (admin accounts,
    /admin/accounts) and YsAdminUsers (user accounts, /admin/users). RISK-189
    is specifically about user creation, so every lookup here must be scoped
    to the YsAdminUsers class body to avoid matching the sibling
    YsAdminAccounts._create()/_delete()/etc. of the same name."""
    start = src.index("export class YsAdminUsers")
    end = src.index("customElements.define('ys-admin-users'")
    return src[start:end]


def _extract_method(src: str, signature: str) -> str:
    """`signature` already includes the opening brace, e.g. 'async _create() {'."""
    m = re.search(re.escape(signature) + r".*?\n  \}\n", src, re.DOTALL)
    assert m, f"could not locate {signature!r} in the given slice"
    return m.group(0)


class TestCreateCapturesBootstrapCredentials:
    def test_accounts_js_exists(self):
        assert _ACCOUNTS_JS.is_file()

    def test_create_reads_response_data_not_just_toast(self):
        src = _users_class_slice(_ACCOUNTS_JS.read_text())
        body = _extract_method(src, "async _create() {")
        assert "res.data" in body, (
            "_create() must read res.data to capture the one-time bootstrap "
            "credentials -- previously it only called reportMutate() (toast) "
            "and discarded the response body"
        )
        assert "temporary_password" in body
        assert "totp_secret" in body

    def test_bootstrap_state_field_declared(self):
        src = _ACCOUNTS_JS.read_text()
        assert "_bootstrap:" in src and "state: true" in src
        assert "this._bootstrap = null;" in src, "constructor must initialise _bootstrap"

    def test_dismiss_handler_clears_state_not_just_hides(self):
        src = _users_class_slice(_ACCOUNTS_JS.read_text())
        assert "_dismissBootstrap()" in src
        body = _extract_method(src, "_dismissBootstrap() {")
        assert "this._bootstrap = null;" in body


class TestRenderBootstrapPanelWiredIntoView:
    def test_render_bootstrap_method_exists(self):
        src = _ACCOUNTS_JS.read_text()
        assert "_renderBootstrap()" in src

    def test_render_bootstrap_shows_all_three_bootstrap_fields(self):
        src = _users_class_slice(_ACCOUNTS_JS.read_text())
        m = re.search(r"_renderBootstrap\(\)\s*\{.*?\n  \}\n", src, re.DOTALL)
        assert m, "could not locate _renderBootstrap() in the YsAdminUsers class body"
        body = m.group(0)
        assert "b.temporary_password" in body
        assert "b.totp_secret" in body
        assert "b.totp_uri" in body
        assert "readonly" in body, "revealed fields should be readonly, not editable"

    def test_render_bootstrap_is_called_from_the_users_view(self):
        """Confirms the panel is actually mounted in render(), not orphaned."""
        src = _users_class_slice(_ACCOUNTS_JS.read_text())
        render_idx = src.index("render() {\n    if (this._loading) {")
        assert "${this._renderBootstrap()}" in src[render_idx:render_idx + 2000]


class TestBackendContractMatchesUiFieldNames:
    """Confirms the UI reads the EXACT field names the backend actually
    returns (BOPLA allowlist) -- a name mismatch would silently show blank
    fields instead of a hard error."""

    def test_user_create_response_fields(self):
        src = _BOPLA_PY.read_text()
        assert "temporary_password: str" in src
        assert "totp_secret: str" in src
        assert "totp_uri: str" in src

    def test_create_user_route_returns_user_create_response(self):
        src = _USERS_ROUTE_PY.read_text()
        assert "UserCreateResponse(" in src
        assert "temporary_password=temp_password" in src
        assert "totp_secret=totp.secret_b32" in src


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
