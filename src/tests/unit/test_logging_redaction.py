"""
G1 (observability SOP, release-blocking) — global app-log redaction filter.

The audit path (yashigani.audit.masking.CredentialMasker) already scrubs
secrets before they hit disk/SIEM. The app-log path (stdout -> promtail ->
Loki) had NO equivalent global redaction. This suite proves
``yashigani.logging_redaction.RedactionFilter``:
  - Scrubs each secret class named in the ticket: passwords, TOTP secrets/
    codes, API keys/bearer tokens, licence keys/passphrases, Redis/Postgres
    URLs with embedded credentials, PEM private-key blocks.
  - Never drops a record (filter() always returns True).
  - Never raises — a broken/erroring redaction path emits the record
    UNMODIFIED rather than losing the log line or crashing the logger.
  - install_log_redaction() attaches to the root logger's HANDLER(s), not
    the Logger object — the only placement that actually intercepts
    records from child-module loggers on their way to stdout.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import logging

import pytest

from yashigani.logging_redaction import RedactionFilter, install_log_redaction


def _make_record(msg: str, args: tuple = ()) -> logging.LogRecord:
    return logging.LogRecord(
        name="yashigani.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


class TestPasswordRedaction:
    def test_labelled_password_redacted(self):
        rec = _make_record("login attempt password=hunter2ish for user admin1")
        RedactionFilter().filter(rec)
        assert "hunter2ish" not in rec.msg
        assert "cred:" in rec.msg

    def test_password_in_percent_args_redacted(self):
        """The secret value lives in args, the "password=" label lives in
        msg — they must be redacted TOGETHER (rendered first via
        record.getMessage()), not independently, or the label-matching
        regex never sees the value alongside its label."""
        rec = _make_record("login failed password=%s", ("Sup3rSecr3tPW!",))
        RedactionFilter().filter(rec)
        assert "Sup3rSecr3tPW!" not in rec.msg
        assert rec.args == ()
        assert "cred:" in rec.msg


class TestTotpRedaction:
    def test_totp_secret_redacted(self):
        rec = _make_record("provisioning totp_secret=JBSWY3DPEHPK3PXP for admin1")
        RedactionFilter().filter(rec)
        assert "JBSWY3DPEHPK3PXP" not in rec.msg
        assert "cred:" in rec.msg

    def test_totp_code_redacted(self):
        rec = _make_record("totp_code: 12345678 rejected (replay)")
        RedactionFilter().filter(rec)
        assert "12345678" not in rec.msg


class TestApiKeyAndBearerRedaction:
    def test_bearer_token_redacted(self):
        rec = _make_record(
            "request Authorization: Bearer abcdef0123456789ABCDEF0123456789abcd"
        )
        RedactionFilter().filter(rec)
        assert "abcdef0123456789ABCDEF0123456789abcd" not in rec.msg
        assert "Bearer" in rec.msg
        assert "cred:" in rec.msg

    def test_generic_64_hex_api_key_redacted(self):
        """This codebase's own API keys (identity/api_key.py::
        generate_api_key()) are 64-char hex — no ysg_-style prefix exists
        anywhere in the codebase (verified via grep) — so they must be
        caught by the generic hex pattern."""
        api_key = "a1b2c3d4e5f60718293a4b5c6d7e8f9" * 2  # 64 hex chars
        rec = _make_record(f"agent auth failed for api_key={api_key}")
        RedactionFilter().filter(rec)
        assert api_key not in rec.msg
        assert "cred:" in rec.msg

    def test_sk_prefixed_key_redacted(self):
        rec = _make_record("upstream call used key sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        RedactionFilter().filter(rec)
        assert "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" not in rec.msg


class TestLicenceRedaction:
    def test_license_key_redacted(self):
        rec = _make_record("activation failed license_key=abcd.efgh.ijkl.mnop")
        RedactionFilter().filter(rec)
        assert "abcd.efgh.ijkl.mnop" not in rec.msg
        assert "cred:" in rec.msg

    def test_license_content_redacted(self):
        rec = _make_record("license_content: XyZ123-blob-value rejected (bad chain)")
        RedactionFilter().filter(rec)
        assert "XyZ123-blob-value" not in rec.msg


class TestDbUrlRedaction:
    def test_redis_url_credentials_redacted(self):
        rec = _make_record(
            "connecting to redis://ysg_user:S3cretPW1@redis-primary:6380/3"
        )
        RedactionFilter().filter(rec)
        assert "S3cretPW1" not in rec.msg
        assert "ysg_user" in rec.msg  # user kept — routing-relevant, not secret
        assert "redis://" in rec.msg
        assert "cred:" in rec.msg

    def test_postgres_url_credentials_redacted(self):
        rec = _make_record(
            "pool init failed: postgresql://gateway_svc:hunter2pg@pg-primary:5432/yashigani"
        )
        RedactionFilter().filter(rec)
        assert "hunter2pg" not in rec.msg
        assert "postgresql://" in rec.msg


class TestPemBlockRedaction:
    def test_full_pem_private_key_block_redacted(self):
        pem = (
            "-----BEGIN EC PRIVATE KEY-----\n"
            "MIGkAgEBBDBsecretlinebodyexamplecontent1234567890abcdef==\n"
            "-----END EC PRIVATE KEY-----"
        )
        rec = _make_record(f"loaded gateway key:\n{pem}")
        RedactionFilter().filter(rec)
        assert "MIGkAgEBBDBsecretlinebodyexamplecontent1234567890abcdef==" not in rec.msg
        assert "BEGIN EC PRIVATE KEY" not in rec.msg  # whole block replaced
        assert "cred:" in rec.msg


class TestFailSafeNeverRaisesNeverDrops:
    def test_filter_always_returns_true(self):
        rec = _make_record("perfectly ordinary log line, nothing secret here")
        assert RedactionFilter().filter(rec) is True

    def test_filter_error_emits_record_unmodified_never_raises(self, monkeypatch):
        """If the redaction internals raise, the filter must catch it,
        NEVER propagate, and leave the record's original content intact
        rather than corrupting or dropping it."""
        import yashigani.logging_redaction as lr_module

        def _boom(text):
            raise RuntimeError("simulated redaction failure")

        monkeypatch.setattr(lr_module, "_redact_text", _boom)

        rec = _make_record("password=should_survive_because_filter_is_broken")
        result = RedactionFilter().filter(rec)

        assert result is True  # never dropped
        assert rec.msg == "password=should_survive_because_filter_is_broken"

    def test_non_string_args_render_correctly_and_args_cleared(self):
        """%-style args (ints, objects) are rendered via the record's
        ORIGINAL msg/args (record.getMessage(), using unredacted values —
        never itself logged) BEFORE redaction runs, so %d/%r formatting is
        applied correctly; args is then cleared since record.msg holds the
        final rendered+redacted text (prevents a downstream handler from
        re-applying % formatting to text that may contain literal '%')."""
        rec = _make_record("count=%d obj=%r", (5, {"a": 1}))
        RedactionFilter().filter(rec)
        assert rec.args == ()
        assert rec.msg == "count=5 obj={'a': 1}"


class TestInstallOnRootHandler:
    def test_installs_on_handler_not_logger(self):
        """install_log_redaction must attach the filter to the Logger's
        HANDLER objects, not the Logger itself — Logger-level filters only
        see records logged directly against that logger, never records
        from child loggers that merely propagate to its handlers."""
        test_logger = logging.getLogger("yashigani.test.redaction.install")
        test_logger.handlers.clear()
        handler = logging.StreamHandler()
        test_logger.addHandler(handler)

        install_log_redaction(root_logger=test_logger)

        assert any(isinstance(f, RedactionFilter) for f in handler.filters)
        assert not any(isinstance(f, RedactionFilter) for f in test_logger.filters)

    def test_install_is_idempotent_per_handler(self):
        test_logger = logging.getLogger("yashigani.test.redaction.idempotent")
        test_logger.handlers.clear()
        handler = logging.StreamHandler()
        test_logger.addHandler(handler)

        install_log_redaction(root_logger=test_logger)
        install_log_redaction(root_logger=test_logger)

        redaction_filters = [f for f in handler.filters if isinstance(f, RedactionFilter)]
        assert len(redaction_filters) == 1

    def test_child_logger_record_reaches_root_handler_redacted(self, capsys):
        """End-to-end: a CHILD logger (module-level, like every
        `logging.getLogger(__name__)` call site in the codebase) emits a
        secret; it propagates to the root-equivalent test logger's
        StreamHandler and arrives redacted — proving the "every module
        logger inherits it" claim."""
        import sys

        parent_logger = logging.getLogger("yashigani.test.redaction.e2e")
        parent_logger.handlers.clear()
        parent_logger.propagate = False
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        parent_logger.addHandler(handler)
        parent_logger.setLevel(logging.INFO)

        install_log_redaction(root_logger=parent_logger)

        child_logger = logging.getLogger("yashigani.test.redaction.e2e.child_module")
        child_logger.setLevel(logging.INFO)
        child_logger.info("db connect failed: redis://user:leaked_pw_123@host:6379")

        captured = capsys.readouterr()
        assert "leaked_pw_123" not in captured.out
        assert "cred:" in captured.out
