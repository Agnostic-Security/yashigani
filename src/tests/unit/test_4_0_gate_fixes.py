"""
Unit tests for Yashigani 4.0 release-gate fixes.

FIND-4.0-CHAT-001 — chat proxy: session-gated, SSE-streaming, no API key in browser.
FIND-4.0-UI-001   — TOTP inputs accept 6-8 digits (pattern / maxlength).
LAURA-V400-001    — RBAC mutation endpoints require StepUpAdminSession.
LAURA-V400-002    — Policy lifecycle operations emit audit events.
FIND-4.0-UI-002   — user-tier redirect_to = "/chat" (not "/").
"""
from __future__ import annotations

import os
import re



# ---------------------------------------------------------------------------
# FIND-4.0-UI-002 — auth.py user redirect
# ---------------------------------------------------------------------------

class TestUserTierRedirect:
    """user-tier login must redirect to /chat, not /."""

    def test_user_redirect_to_chat(self):
        """auth.py: user tier produces redirect_to='/chat'."""
        import pathlib
        auth_src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "auth.py"
        ).resolve().read_text()
        # Must contain redirect_to = "/chat" for user tier
        assert 'redirect_to = "/chat"' in auth_src, (
            "auth.py must set redirect_to='/chat' for user-tier logins (FIND-4.0-UI-002)"
        )
        # Must NOT contain bare redirect_to = "/" without "admin"
        # (the only "/" should be inside the /admin/ string)
        lines = auth_src.splitlines()
        user_redirect_lines = [
            ln for ln in lines
            if 'redirect_to = "/"' in ln and "admin" not in ln
        ]
        assert not user_redirect_lines, (
            f"Found redirect_to='/' for non-admin tier: {user_redirect_lines}"
        )


# ---------------------------------------------------------------------------
# FIND-4.0-UI-001 — TOTP input field patterns
# ---------------------------------------------------------------------------

class TestTotpInputFields:
    """Every TOTP input must accept 6-8 digits so both SHA256/6 and SHA512/8 work."""

    def _read_template(self, name: str) -> str:
        import pathlib
        return pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "templates", name
        ).resolve().read_text()

    def _check_no_old_pattern(self, content: str, label: str):
        # pattern="[0-9]{6}" with maxlength="6" must not appear (6-only locks out 8-digit admins)
        assert 'pattern="[0-9]{6}"' not in content, (
            f"{label}: found pattern='[0-9]{{6}}' — must be [0-9]{{6,8}} (FIND-4.0-UI-001)"
        )
        assert 'maxlength="6"' not in content, (
            f"{label}: found maxlength='6' on TOTP input — must be 8 (FIND-4.0-UI-001)"
        )

    def _check_new_pattern(self, content: str, label: str):
        assert 'pattern="[0-9]{6,8}"' in content, (
            f"{label}: missing pattern='[0-9]{{6,8}}' (FIND-4.0-UI-001)"
        )
        assert 'maxlength="8"' in content, (
            f"{label}: missing maxlength='8' (FIND-4.0-UI-001)"
        )

    def test_login_html(self):
        content = self._read_template("login.html")
        self._check_no_old_pattern(content, "login.html")
        self._check_new_pattern(content, "login.html")

    def test_user_login_html(self):
        content = self._read_template("user_login.html")
        self._check_no_old_pattern(content, "user_login.html")
        self._check_new_pattern(content, "user_login.html")

    def test_dashboard_stepup(self):
        content = self._read_template("dashboard.html")
        # The step-up modal input must accept 8 digits
        assert 'maxlength="8"' in content, (
            "dashboard.html step-up modal missing maxlength='8' (FIND-4.0-UI-001)"
        )
        assert 'pattern="[0-9]{6,8}"' in content, (
            "dashboard.html step-up modal missing pattern='[0-9]{6,8}' (FIND-4.0-UI-001)"
        )

    def test_ys_modal_js(self):
        """ys-modal.js promptStepUp must accept 6-8 digits in the regex and maxLength."""
        import pathlib
        modal_src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "static", "ui4",
            "core", "widgets", "ys-modal.js"
        ).resolve().read_text()
        assert "maxLength = 8" in modal_src, (
            "ys-modal.js: maxLength must be 8 (FIND-4.0-UI-001)"
        )
        assert r"/^\d{6,8}$/" in modal_src, (
            "ys-modal.js: submit validator must accept 6-8 digits (FIND-4.0-UI-001)"
        )
        # Old 6-only regex must be gone
        assert r"/^\d{6}$/" not in modal_src, (
            "ys-modal.js: old 6-only regex still present (FIND-4.0-UI-001)"
        )


# ---------------------------------------------------------------------------
# LAURA-V400-001 — RBAC mutations require StepUpAdminSession
# ---------------------------------------------------------------------------

class TestRbacStepUpGating:
    """RBAC mutation endpoints must declare StepUpAdminSession, not AdminSession."""

    def _rbac_source(self) -> str:
        import pathlib
        return pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "rbac.py"
        ).resolve().read_text()

    def test_create_group_stepup(self):
        src = self._rbac_source()
        # create_group must use StepUpAdminSession
        fn_block = re.search(
            r"async def create_group\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block, "create_group not found in rbac.py"
        assert "StepUpAdminSession" in fn_block.group(0), (
            "create_group must use StepUpAdminSession (LAURA-V400-001)"
        )

    def test_update_group_stepup(self):
        src = self._rbac_source()
        fn_block = re.search(
            r"async def update_group\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block
        assert "StepUpAdminSession" in fn_block.group(0)

    def test_delete_group_stepup(self):
        src = self._rbac_source()
        fn_block = re.search(
            r"async def delete_group\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block
        assert "StepUpAdminSession" in fn_block.group(0)

    def test_add_member_stepup(self):
        src = self._rbac_source()
        fn_block = re.search(
            r"async def add_member\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block
        assert "StepUpAdminSession" in fn_block.group(0)

    def test_remove_member_stepup(self):
        src = self._rbac_source()
        fn_block = re.search(
            r"async def remove_member\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block
        assert "StepUpAdminSession" in fn_block.group(0)

    def test_force_push_stepup(self):
        src = self._rbac_source()
        fn_block = re.search(
            r"async def force_push\(.*?(?=\nasync def|\Z)",
            src, re.DOTALL
        )
        assert fn_block
        assert "StepUpAdminSession" in fn_block.group(0)

    def test_read_endpoints_still_admin_session(self):
        """Read-only endpoints (list_groups, get_group, get_user_groups) must NOT require step-up."""
        src = self._rbac_source()
        for fn_name in ("list_groups", "get_group", "get_user_groups"):
            fn_block = re.search(
                rf"async def {fn_name}\(.*?(?=\nasync def|\Z)",
                src, re.DOTALL
            )
            assert fn_block, f"{fn_name} not found"
            block = fn_block.group(0)
            # Must NOT require step-up for reads
            assert "StepUpAdminSession" not in block, (
                f"{fn_name} incorrectly gates reads with StepUpAdminSession"
            )
            assert "AdminSession" in block


# ---------------------------------------------------------------------------
# LAURA-V400-002 — Policy ops emit audit events
# ---------------------------------------------------------------------------

class TestPolicyAuditEvents:
    """All policy state-changing routes must emit SHA-384 chain audit events."""

    def _policies_source(self) -> str:
        import pathlib
        return pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "policies.py"
        ).resolve().read_text()

    def _assert_emits(self, fn_name: str, event_cls: str):
        src = self._policies_source()
        fn_block = re.search(
            rf"async def {fn_name}\(.*?(?=\nasync def |\Z)",
            src, re.DOTALL
        )
        assert fn_block, f"{fn_name} not found in policies.py"
        block = fn_block.group(0)
        assert event_cls in block, (
            f"{fn_name} does not emit {event_cls} (LAURA-V400-002)"
        )
        assert "audit_writer" in block, (
            f"{fn_name} does not call audit_writer (LAURA-V400-002)"
        )

    def test_save_policy_audited(self):
        self._assert_emits("save_policy", "PolicySavedEvent")

    def test_duplicate_template_audited(self):
        self._assert_emits("duplicate_template", "PolicyDuplicatedEvent")

    def test_edit_custom_policy_rego_audited(self):
        self._assert_emits("edit_custom_policy_rego", "PolicyRegoEditedEvent")

    def test_edit_core_policy_audited(self):
        self._assert_emits("edit_core_policy", "PolicyCoreEditedEvent")

    def test_promote_policy_audited(self):
        self._assert_emits("promote_policy", "PolicyPromotedEvent")

    def test_archive_policy_audited(self):
        self._assert_emits("archive_policy", "PolicyArchivedEvent")

    def test_activate_policy_audited(self):
        self._assert_emits("activate_policy", "PolicyActivatedEvent")

    def test_bind_policy_audited(self):
        self._assert_emits("bind_policy", "PolicyBoundEvent")

    def test_unbind_policy_audited(self):
        self._assert_emits("unbind_policy", "PolicyUnboundEvent")

    def test_policy_event_types_registered(self):
        """All new event types must be registered in EventType enum."""
        from yashigani.audit.schema import EventType
        expected = [
            "POLICY_SAVED", "POLICY_DUPLICATED", "POLICY_REGO_EDITED",
            "POLICY_CORE_EDITED", "POLICY_PROMOTED", "POLICY_ARCHIVED",
            "POLICY_ACTIVATED", "POLICY_BOUND", "POLICY_UNBOUND",
        ]
        for name in expected:
            assert hasattr(EventType, name), (
                f"EventType.{name} missing from audit schema (LAURA-V400-002)"
            )

    def test_policy_event_dataclasses_importable(self):
        """All new AuditEvent dataclasses must import cleanly."""
        from yashigani.audit.schema import (
            PolicySavedEvent, PolicyBoundEvent,
        )
        # Smoke-instantiate each
        e = PolicySavedEvent(admin_account="admin@example.com", policy_name="test")
        assert e.event_type == "POLICY_SAVED"
        assert e.account_tier == "admin"

        e2 = PolicyBoundEvent(
            admin_account="admin@example.com",
            policy_name="test",
            scope_kind="user",
            scope_id="user@example.com",
            direction="ingress",
        )
        assert e2.event_type == "POLICY_BOUND"


# ---------------------------------------------------------------------------
# FIND-4.0-CHAT-001 — chat proxy: structural contract tests
# ---------------------------------------------------------------------------

class TestChatProxyContract:
    """The chat proxy must be wired in user_ui.py and the JS must point to it."""

    def test_proxy_route_registered(self):
        """user_ui.py must define POST /user/chat/completions."""
        import pathlib
        src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "user_ui.py"
        ).resolve().read_text()
        assert '"/user/chat/completions"' in src, (
            "user_ui.py missing POST /user/chat/completions route (FIND-4.0-CHAT-001)"
        )
        # Must use UserSession (not AdminSession)
        fn_block = re.search(
            r"async def user_chat_proxy\(.*?(?=\n@router|\nasync def |\Z)",
            src, re.DOTALL
        )
        assert fn_block, "user_chat_proxy function not found"
        block = fn_block.group(0)
        assert "UserSession" in block
        assert "StreamingResponse" in block
        assert "YASHIGANI_INTERNAL_BEARER" in block
        # 4.1 SEC-GAP-1: chat proxy forwards X-Yashigani-Identity-Id (idnt_ PK),
        # not the legacy X-OpenWebUI-User-Email header (OWUI removed in 4.x).
        # The header may be referenced via a module constant _YASHIGANI_IDENTITY_ID_HEADER.
        identity_header_used = (
            "X-Yashigani-Identity-Id" in block
            or "_YASHIGANI_IDENTITY_ID_HEADER" in block
        )
        assert identity_header_used, (
            "user_chat_proxy must forward X-Yashigani-Identity-Id (or _YASHIGANI_IDENTITY_ID_HEADER constant)"
        )
        # Explicitly ensure the old OWUI email header is NOT forwarded.
        assert "X-OpenWebUI-User-Email" not in block, (
            "user_chat_proxy must not forward X-OpenWebUI-User-Email in 4.x (OWUI removed)"
        )

    def test_proxy_fail_closed_on_missing_bearer(self):
        """Proxy must 503 when YASHIGANI_INTERNAL_BEARER is absent."""
        import pathlib
        src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "user_ui.py"
        ).resolve().read_text()
        fn_block = re.search(
            r"async def user_chat_proxy\(.*?(?=\n@router|\Z)",
            src, re.DOTALL
        )
        block = fn_block.group(0)
        # Fail-closed: 503 when bearer missing
        assert "HTTP_503_SERVICE_UNAVAILABLE" in block, (
            "user_chat_proxy must raise 503 when YASHIGANI_INTERNAL_BEARER is absent"
        )

    def test_chat_view_js_uses_proxy_path(self):
        """chat-view.js CHAT_PATH must point to /user/chat/completions, not /v1/chat/completions."""
        import pathlib
        js_src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "static",
            "ui4", "user", "chat-view.js"
        ).resolve().read_text()
        assert "CHAT_PATH = '/user/chat/completions'" in js_src, (
            "chat-view.js CHAT_PATH must be '/user/chat/completions' (FIND-4.0-CHAT-001)"
        )
        assert "CHAT_PATH = '/v1/chat/completions'" not in js_src, (
            "chat-view.js still references /v1/chat/completions directly (FIND-4.0-CHAT-001)"
        )

    def test_proxy_forwards_user_identity(self):
        """Proxy must inject X-Yashigani-Identity-Id (4.1+) resolved from session.account_id."""
        import pathlib
        src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "user_ui.py"
        ).resolve().read_text()
        # account_id is used to resolve the identity_id (idnt_ PK)
        assert "session.account_id" in src
        # 4.1 SEC-GAP-1: header must be X-Yashigani-Identity-Id (or its module constant)
        assert (
            '"X-Yashigani-Identity-Id"' in src
            or "_YASHIGANI_IDENTITY_ID_HEADER" in src
        ), "user_ui.py must forward X-Yashigani-Identity-Id (not X-OpenWebUI-User-Email)"
        # Old OWUI email header must be gone
        assert '"X-OpenWebUI-User-Email"' not in src, (
            "user_ui.py must not reference X-OpenWebUI-User-Email in 4.x"
        )

    def test_sse_content_type(self):
        """Proxy must return text/event-stream media type."""
        import pathlib
        src = pathlib.Path(
            os.path.dirname(__file__),
            "..", "..", "yashigani", "backoffice", "routes", "user_ui.py"
        ).resolve().read_text()
        assert "text/event-stream" in src
