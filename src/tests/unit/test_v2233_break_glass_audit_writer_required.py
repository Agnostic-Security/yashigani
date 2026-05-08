"""
Regression test — v2.23.3 micro-PR 2.

Gap: auth/break_glass.py init_break_glass(redis_client, audit_writer=None)
default allowed break-glass sessions to be initialised without an audit
writer, making all BREAK_GLASS_ACTIVATED and BREAK_GLASS_EXPIRED events
silently drop with no error.

Fix: make audit_writer a required positional argument (no default). The
entrypoint always supplies audit_writer; this converts a silent runtime
failure into a startup-time TypeError that surfaces immediately.

Closes: yashigani-retro#95 (partial — OWASP A09 / CMMC AU.L2-3.3.1)

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).parent.parent.parent / "yashigani"
_BREAK_GLASS_SRC = _SRC / "auth" / "break_glass.py"
_ENTRYPOINT_SRC = _SRC / "backoffice" / "entrypoint.py"


# ---------------------------------------------------------------------------
# AST structural tests
# ---------------------------------------------------------------------------

class TestInitBreakGlassSignatureAST:
    """Verify init_break_glass has no default for audit_writer."""

    def _get_init_fn(self) -> ast.FunctionDef:
        tree = ast.parse(_BREAK_GLASS_SRC.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "init_break_glass":
                return node
        pytest.fail("init_break_glass() not found in break_glass.py")

    def test_init_break_glass_exists(self):
        fn = self._get_init_fn()
        assert fn is not None

    def test_audit_writer_has_no_default(self):
        """
        audit_writer must be a required argument — no default value.

        ast.arguments.defaults corresponds to the LAST N positional args
        that have defaults. If defaults is non-empty and audit_writer is
        among the ones with a default, the fix was not applied.
        """
        fn = self._get_init_fn()
        args = fn.args
        # positional args (no self — module-level function)
        all_args = [a.arg for a in args.args]
        assert "audit_writer" in all_args, (
            "init_break_glass has no 'audit_writer' argument"
        )

        # defaults list covers the LAST len(defaults) positional args
        n_defaults = len(args.defaults)
        if n_defaults == 0:
            return  # all args required — test passes

        audit_idx = all_args.index("audit_writer")
        first_default_idx = len(all_args) - n_defaults
        has_default = audit_idx >= first_default_idx
        assert not has_default, (
            f"audit_writer has a default value — it must be required "
            f"(no default). Current defaults: {[ast.unparse(d) for d in args.defaults]}"
        )

    def test_audit_writer_is_not_kwonly_with_default(self):
        """audit_writer must not be a keyword-only arg with a default."""
        fn = self._get_init_fn()
        args = fn.args
        for kw_arg, default in zip(args.kwonlyargs, args.kw_defaults):
            if kw_arg.arg == "audit_writer" and default is not None:
                pytest.fail(
                    "audit_writer is a kwonly arg with a default — it must be required"
                )

    def test_two_positional_args(self):
        """init_break_glass should take exactly 2 positional args: redis_client, audit_writer."""
        fn = self._get_init_fn()
        args = [a.arg for a in fn.args.args]
        assert args == ["redis_client", "audit_writer"], (
            f"Expected ['redis_client', 'audit_writer'], got {args}"
        )


# ---------------------------------------------------------------------------
# Signature introspection tests (import the live module)
# ---------------------------------------------------------------------------

class TestInitBreakGlassSignatureLive:
    """Confirm the live function signature has no default for audit_writer."""

    def test_calling_without_audit_writer_raises_typeerror(self):
        """
        init_break_glass(redis_client) — missing required arg — must raise TypeError.
        This is the regression guard: previously it silently defaulted to None.
        """
        from yashigani.auth.break_glass import init_break_glass
        mock_redis = MagicMock()
        with pytest.raises(TypeError):
            init_break_glass(mock_redis)

    def test_calling_with_none_as_audit_writer_succeeds(self):
        """
        Explicitly passing None is still accepted (the manager handles it
        gracefully via the None-guard in _emit_activated/_emit_expired).
        This is different from omitting the argument entirely.
        """
        from yashigani.auth.break_glass import init_break_glass
        mock_redis = MagicMock()
        # Should not raise — None is a deliberate choice, not an omission.
        mgr = init_break_glass(mock_redis, None)
        assert mgr is not None

    def test_calling_with_real_audit_writer_succeeds(self):
        """Standard path: redis_client + audit_writer both provided."""
        from yashigani.auth.break_glass import init_break_glass
        mock_redis = MagicMock()
        mock_audit = MagicMock()
        mgr = init_break_glass(mock_redis, mock_audit)
        assert mgr is not None

    def test_signature_has_no_default_for_audit_writer(self):
        """inspect.signature confirms audit_writer has no default."""
        from yashigani.auth.break_glass import init_break_glass
        sig = inspect.signature(init_break_glass)
        param = sig.parameters["audit_writer"]
        assert param.default is inspect.Parameter.empty, (
            f"audit_writer has a default: {param.default!r} — "
            "it must be a required argument (no default)"
        )


# ---------------------------------------------------------------------------
# Call-site verification — entrypoint always passes audit_writer
# ---------------------------------------------------------------------------

class TestEntrypointCallSiteAST:
    """
    Verify that backoffice/entrypoint.py calls init_break_glass with two
    arguments and that audit_writer is one of them.
    """

    def _get_init_bg_call(self):
        """Return the AST Call node for init_break_glass(...)."""
        tree = ast.parse(_ENTRYPOINT_SRC.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "init_break_glass":
                    return node
                if isinstance(func, ast.Attribute) and func.attr == "init_break_glass":
                    return node
        return None

    def test_init_break_glass_called_in_entrypoint(self):
        """entrypoint.py must call init_break_glass (regression guard)."""
        call_node = self._get_init_bg_call()
        assert call_node is not None, (
            "init_break_glass() call not found in backoffice/entrypoint.py"
        )

    def test_entrypoint_passes_two_positional_args(self):
        """
        init_break_glass(redis_bg, audit_writer) must pass both arguments.
        If only one positional arg is passed, startup will now raise TypeError.
        """
        call_node = self._get_init_bg_call()
        assert call_node is not None
        n_args = len(call_node.args)
        assert n_args >= 2, (
            f"init_break_glass call in entrypoint passes {n_args} positional arg(s); "
            "expected 2 (redis_client, audit_writer)"
        )

    def test_entrypoint_passes_audit_writer_variable(self):
        """
        The second argument to init_break_glass must reference the audit_writer
        variable that was constructed earlier in _bootstrap().
        """
        call_node = self._get_init_bg_call()
        assert call_node is not None
        call_src = ast.unparse(call_node)
        assert "audit_writer" in call_src, (
            f"init_break_glass call in entrypoint does not mention audit_writer: {call_src!r}"
        )


# ---------------------------------------------------------------------------
# Behavioural tests — _emit_activated and _emit_expired guard patterns
# ---------------------------------------------------------------------------

class TestBreakGlassManagerEmitGuards:
    """
    _emit_activated and _emit_expired should remain correct after the
    signature change. Their None-guard is now dead code in normal usage
    (audit_writer is required), but must not cause breakage when explicitly
    passing None.
    """

    def test_emit_activated_does_not_raise_when_audit_is_none(self):
        """
        BreakGlassManager._emit_activated(audit=None) — the inner guard
        ``if self._audit is None: return`` must still work correctly.
        """
        from yashigani.auth.break_glass import BreakGlassManager
        import datetime
        mgr = BreakGlassManager(MagicMock(), None)
        # Must not raise
        mgr._emit_activated(
            "admin@example.com",
            4,
            datetime.datetime.now(tz=datetime.timezone.utc),
        )

    def test_emit_expired_does_not_raise_when_audit_is_none(self):
        """
        BreakGlassManager._emit_expired(audit=None) — guard must still work.
        """
        from yashigani.auth.break_glass import BreakGlassManager
        mgr = BreakGlassManager(MagicMock(), None)
        # Must not raise
        mgr._emit_expired("admin@example.com", is_auto=True, revoked_by="__auto_expire__")

    def test_emit_activated_calls_audit_write_when_writer_present(self):
        """With a real audit writer, _emit_activated must call write()."""
        from yashigani.auth.break_glass import BreakGlassManager
        import datetime
        mock_audit = MagicMock()
        mgr = BreakGlassManager(MagicMock(), mock_audit)
        mgr._emit_activated(
            "admin@example.com",
            4,
            datetime.datetime.now(tz=datetime.timezone.utc),
        )
        assert mock_audit.write.call_count == 1, (
            f"Expected 1 audit write from _emit_activated, got {mock_audit.write.call_count}"
        )

    def test_emit_expired_calls_audit_write_when_writer_present(self):
        """With a real audit writer, _emit_expired must call write()."""
        from yashigani.auth.break_glass import BreakGlassManager
        mock_audit = MagicMock()
        mgr = BreakGlassManager(MagicMock(), mock_audit)
        mgr._emit_expired("admin@example.com", is_auto=False, revoked_by="admin2@example.com")
        assert mock_audit.write.call_count == 1, (
            f"Expected 1 audit write from _emit_expired, got {mock_audit.write.call_count}"
        )
