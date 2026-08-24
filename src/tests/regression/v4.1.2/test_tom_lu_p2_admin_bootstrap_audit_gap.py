"""
Regression test -- v4.1.2 Lu P2 (GRC audit, 2026-08-16):

``backoffice.app._bootstrap_admin_accounts`` mints the admin1/admin2
break-glass pair -- the single most privileged act in the system's
lifetime -- with ZERO audit events. Only ``_log.info`` app-log lines
existed. Standing project rule
(feedback_compliance_events_in_audit_chain.md): compliance/security-
relevant events MUST land in the tamper-evident audit_events hash chain,
never app logs only.

Prior art read before this fix (see commit body for full detail):
  - docs/risk-register.yml: no existing entry for this exact gap.
  - git log -S"_bootstrap_admin_accounts": b4a6a2f788 (P0-2, relocated
    bootstrap into app.py, total_admin_count()==0 guard) and 3ee5ca5bf4b
    (dual-admin maker-checker: "Audit written BEFORE apply so record
    exists even if apply raises" -- the ordering this fix reuses).
  - routes/agents.py:533-549 AgentRegisteredEvent -- reference pattern for
    a typed audit event on a privileged registration action.
  - 4836425d (Tom, install.sh compose durable-write path) -- precedent for
    an actor label when no admin session exists ("install:system" /
    account_tier="system"); this fix uses an analogous but honestly-
    distinct label ("system:backoffice_bootstrap") since the mechanism is
    the FastAPI lifespan, not the installer script.

Fix (src/yashigani/backoffice/app.py + src/yashigani/audit/schema.py):
  - New EventType.ADMIN_ACCOUNT_BOOTSTRAPPED + AdminAccountBootstrappedEvent
    typed dataclass (never carries password/TOTP secret material -- only
    username + admin_slot + totp_provisioned bool).
  - state.audit_writer.write(...) is called BEFORE auth_service.create_admin()
    for each of admin1 (primary) and admin2 (backup), and is NOT wrapped in
    try/except -- AuditLogWriter.write() is documented to raise
    AuditWriteError on a sink failure ("the caller MUST abort their
    operation"); leaving it uncaught here fail-closes the FastAPI lifespan
    startup (CLAUDE.md SOP 1) instead of silently minting an unaudited
    admin account. Because the write precedes create_admin() and
    total_admin_count() == 0 still holds if create_admin() never ran, a
    crash-restart retries cleanly with no half-seeded, unaudited account
    persisting across the cycle.

This test module proves, on the CURRENT (fixed) tree:
  1. Both admin1 and admin2 bootstrap emit a typed AdminAccountBootstrappedEvent
     via state.audit_writer, with correct event_type / actor / admin_slot /
     totp_provisioned, and that the write happens BEFORE create_admin() (order
     assertion via a call-tracking mock).
  2. No credential material (plaintext password or TOTP secret) ever appears
     in the emitted event's serialised form.
  3. Fail-closed: when audit_writer.write() raises, _bootstrap_admin_accounts
     propagates the exception and NEVER calls auth_service.create_admin() --
     an audit failure must abort the privileged action, not silently succeed.
  4. Source-level: _bootstrap_admin_accounts contains no try/except at all
     (SOP 1 -- no swallowed exception can hide an audit-write failure).

See the commit body for the git-stash before/after proof that this test
FAILS against the pre-fix tree and PASSES against the fixed tree.
"""
from __future__ import annotations

import ast
import pathlib

import pytest


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
_APP_PY = _REPO_ROOT / "yashigani" / "backoffice" / "app.py"


def _get_bootstrap_fn_source() -> str:
    tree = ast.parse(_APP_PY.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_bootstrap_admin_accounts":
            lines = _APP_PY.read_text().splitlines()
            return "\n".join(lines[node.lineno - 1 : node.end_lineno])
    raise AssertionError("_bootstrap_admin_accounts not found in app.py")


# ---------------------------------------------------------------------------
# Shared fixtures / mocks
# ---------------------------------------------------------------------------

class _RecordingAuditWriter:
    """Mirrors AuditLogWriter's synchronous .write(event) -> None surface."""

    def __init__(self, raise_on_write: bool = False):
        self.events: list = []
        self._raise_on_write = raise_on_write

    def write(self, event):
        if self._raise_on_write:
            raise RuntimeError("simulated AuditWriteError -- sink unavailable")
        self.events.append(event)


class _OrderTrackingAuthService:
    """Records, for every create_admin() call, how many audit events had
    already been written at that instant -- proves write-before-create
    ordering without depending on wall-clock timestamps."""

    def __init__(self, writer: _RecordingAuditWriter):
        self._writer = writer
        self.create_admin_calls: list[tuple] = []  # (username, audit_count_at_call)
        self._admin_count = 0

    async def total_admin_count(self):
        return self._admin_count

    async def create_admin(self, username, auto_generate, plaintext_password,
                            force_password_change=True, force_totp_provision=True):
        self.create_admin_calls.append((username, len(self._writer.events)))
        self._admin_count += 1

    async def get_account(self, username):
        return None

    async def set_totp_secret_direct(self, username, secret, algorithm="SHA1"):
        pass


def _write_secret_files(tmpdir, admin2: bool = True):
    import os

    files = {
        "admin1_username": "admin1",
        "admin1_password": "s3cr3t-admin1-pw",
        "admin1_totp_secret": "JBSWY3DPEHPK3PXP",
    }
    if admin2:
        files.update(
            {
                "admin2_username": "admin2",
                "admin2_password": "s3cr3t-admin2-pw",
                "admin2_totp_secret": "KRSXG5CTMVRXEZLU",
            }
        )
    for name, value in files.items():
        path = os.path.join(tmpdir, name)
        with open(path, "w") as f:
            f.write(value)


def _make_state(tmpdir, writer):
    class _MockState:
        _auth_bootstrap = {
            "admin_username": "admin1",
            "initial_admin_password": "s3cr3t-admin1-pw",
            "secrets_dir": tmpdir,
        }
        audit_writer = writer

    return _MockState()


# ---------------------------------------------------------------------------
# 1. Both admins emit a typed event, correctly attributed, write-before-create
# ---------------------------------------------------------------------------

class TestBothAdminsEmitTypedAuditEvent:
    @pytest.mark.asyncio
    async def test_admin1_and_admin2_each_emit_bootstrapped_event(self):
        from yashigani.audit.schema import AdminAccountBootstrappedEvent, EventType, AccountTier
        from yashigani.backoffice.app import _bootstrap_admin_accounts

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_secret_files(tmpdir, admin2=True)
            writer = _RecordingAuditWriter()
            auth_svc = _OrderTrackingAuthService(writer)
            state = _make_state(tmpdir, writer)

            await _bootstrap_admin_accounts(auth_svc, state)

        bootstrap_events = [e for e in writer.events if isinstance(e, AdminAccountBootstrappedEvent)]
        assert len(bootstrap_events) == 2, (
            "Lu P2 REGRESSION: expected exactly one AdminAccountBootstrappedEvent "
            f"per admin account (admin1 + admin2), got {len(bootstrap_events)}"
        )

        by_slot = {e.admin_slot: e for e in bootstrap_events}
        assert set(by_slot) == {"primary", "backup"}

        primary = by_slot["primary"]
        assert primary.event_type == EventType.ADMIN_ACCOUNT_BOOTSTRAPPED
        assert primary.account_tier == AccountTier.SYSTEM
        assert primary.bootstrapped_username == "admin1"
        assert primary.totp_provisioned is True
        assert primary.bootstrap_path == "initial_bootstrap"
        assert primary.actor_account_id  # non-empty -- some system actor identity recorded

        backup = by_slot["backup"]
        assert backup.bootstrapped_username == "admin2"
        assert backup.totp_provisioned is True

    @pytest.mark.asyncio
    async def test_no_admin2_secrets_means_no_second_event(self):
        """admin2 is optional -- if the installer never provisioned admin2
        secrets, no phantom AdminAccountBootstrappedEvent should appear for it."""
        from yashigani.audit.schema import AdminAccountBootstrappedEvent
        from yashigani.backoffice.app import _bootstrap_admin_accounts

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_secret_files(tmpdir, admin2=False)
            writer = _RecordingAuditWriter()
            auth_svc = _OrderTrackingAuthService(writer)
            state = _make_state(tmpdir, writer)

            await _bootstrap_admin_accounts(auth_svc, state)

        bootstrap_events = [e for e in writer.events if isinstance(e, AdminAccountBootstrappedEvent)]
        assert len(bootstrap_events) == 1
        assert bootstrap_events[0].admin_slot == "primary"

    @pytest.mark.asyncio
    async def test_audit_write_precedes_create_admin_for_each_account(self):
        """Fail-closed ordering: the audit record for each account must
        already exist BEFORE that account's create_admin() call fires --
        so a crash between write() and create_admin() never leaves an
        admin created without a corresponding audit record."""
        from yashigani.backoffice.app import _bootstrap_admin_accounts

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_secret_files(tmpdir, admin2=True)
            writer = _RecordingAuditWriter()
            auth_svc = _OrderTrackingAuthService(writer)
            state = _make_state(tmpdir, writer)

            await _bootstrap_admin_accounts(auth_svc, state)

        assert len(auth_svc.create_admin_calls) == 2
        admin1_call = next(c for c in auth_svc.create_admin_calls if c[0] == "admin1")
        admin2_call = next(c for c in auth_svc.create_admin_calls if c[0] == "admin2")

        # At least 1 audit event must already be recorded by the time
        # create_admin("admin1", ...) fires (the admin1 bootstrap event).
        assert admin1_call[1] >= 1, (
            "Lu P2 REGRESSION: create_admin('admin1', ...) was called before "
            "any audit event was written -- audit must precede the privileged action."
        )
        # By the time create_admin("admin2", ...) fires, both the admin1 AND
        # admin2 bootstrap events must already be recorded.
        assert admin2_call[1] >= 2, (
            "Lu P2 REGRESSION: create_admin('admin2', ...) was called before "
            "its audit event was written."
        )


# ---------------------------------------------------------------------------
# 2. No credential material ever lands in the audit event
# ---------------------------------------------------------------------------

class TestNoCredentialMaterialInAuditEvent:
    @pytest.mark.asyncio
    async def test_password_and_totp_secret_never_appear_in_event(self):
        from yashigani.audit.schema import AdminAccountBootstrappedEvent
        from yashigani.backoffice.app import _bootstrap_admin_accounts

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_secret_files(tmpdir, admin2=True)
            writer = _RecordingAuditWriter()
            auth_svc = _OrderTrackingAuthService(writer)
            state = _make_state(tmpdir, writer)

            await _bootstrap_admin_accounts(auth_svc, state)

        secrets = {
            "s3cr3t-admin1-pw",
            "s3cr3t-admin2-pw",
            "JBSWY3DPEHPK3PXP",
            "KRSXG5CTMVRXEZLU",
        }

        bootstrap_events = [e for e in writer.events if isinstance(e, AdminAccountBootstrappedEvent)]
        assert bootstrap_events, "no bootstrap events captured -- fixture broken"

        for event in bootstrap_events:
            serialised = str(event.to_dict())
            for secret in secrets:
                assert secret not in serialised, (
                    f"CRITICAL: credential material {secret!r} leaked into "
                    f"AdminAccountBootstrappedEvent: {serialised}"
                )


# ---------------------------------------------------------------------------
# 3. Fail-closed: audit-write failure aborts bootstrap, admin is never created
# ---------------------------------------------------------------------------

class TestFailClosedOnAuditWriteFailure:
    @pytest.mark.asyncio
    async def test_audit_write_failure_propagates_and_blocks_create_admin(self):
        from yashigani.backoffice.app import _bootstrap_admin_accounts

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            _write_secret_files(tmpdir, admin2=True)
            writer = _RecordingAuditWriter(raise_on_write=True)
            auth_svc = _OrderTrackingAuthService(writer)
            state = _make_state(tmpdir, writer)

            with pytest.raises(RuntimeError, match="simulated AuditWriteError"):
                await _bootstrap_admin_accounts(auth_svc, state)

        assert auth_svc.create_admin_calls == [], (
            "SOP 1 REGRESSION: _bootstrap_admin_accounts must NOT call "
            "create_admin() when the audit write for that account failed -- "
            "an audit-sink failure must abort the privileged action, not be "
            "silently swallowed."
        )


# ---------------------------------------------------------------------------
# 4. Source-level: no exception handling can hide a swallowed audit failure
# ---------------------------------------------------------------------------

class TestNoExceptionSwallowingInBootstrap:
    def test_bootstrap_function_has_no_try_except(self):
        """AST-based (not substring) check: no ast.Try node anywhere in the
        function body -- the docstring itself legitimately discusses
        "try/except" in prose, so a raw substring check on "except" would
        false-positive on the documentation, not the code."""
        tree = ast.parse(_APP_PY.read_text())
        target_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "_bootstrap_admin_accounts":
                target_fn = node
                break
        assert target_fn is not None

        try_nodes = [n for n in ast.walk(target_fn) if isinstance(n, ast.Try)]
        assert try_nodes == [], (
            "SOP 1 REGRESSION: _bootstrap_admin_accounts must not wrap any "
            "step (especially the audit_writer.write() calls) in try/except "
            "-- a swallowed exception here could silently mint an unaudited "
            "admin account."
        )

    def test_bootstrap_function_writes_audit_event_for_each_admin(self):
        fn_src = _get_bootstrap_fn_source()
        assert fn_src.count("state.audit_writer.write(") == 2, (
            "Expected exactly two state.audit_writer.write(...) call sites "
            "(admin1 + admin2) in _bootstrap_admin_accounts."
        )
        assert "AdminAccountBootstrappedEvent" in fn_src
