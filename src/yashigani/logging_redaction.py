"""
Yashigani — global application-log redaction filter (G1, observability SOP).

The audit path (yashigani.audit.masking.CredentialMasker) already scrubs
every AuditEvent before it reaches disk/SIEM. The app-log path (stdout ->
promtail -> Loki) had NO equivalent — any module logger could emit a
secret (a password, TOTP code, API key, licence key, a Redis/Postgres DSN
with embedded credentials, or a PEM private-key block) in plaintext to
stdout, which is scraped and shipped to Loki with no redaction step in
between.

This module provides a single ``logging.Filter`` (``RedactionFilter``)
that is attached to the ROOT logger's HANDLER(s) in both
``gateway/entrypoint.py`` and ``backoffice/entrypoint.py`` (via
``install_log_redaction()``), so every module logger's records — which
propagate up to the root logger's handler for formatting/emission — pass
through it, regardless of which module created the record.

IMPORTANT — filters attach to the HANDLER, not the Logger object:
``logging.Logger.callHandlers()`` walks the propagation chain invoking
each ANCESTOR HANDLER directly; it does NOT re-run each ancestor Logger's
own ``Logger.filters``. A filter added via ``logging.getLogger().addFilter()``
would therefore only ever see records logged directly against the root
logger (rare) and miss every child-module logger record. Attaching the
filter to the root logger's Handler instances (the objects
``logging.basicConfig()`` installs) is what actually intercepts every
record on its way to stdout.

Design:
  - Reuses ``yashigani.audit.masking.CredentialMasker`` — the SAME
    credential-fingerprint replacement (``cred:<12 hex chars>``,
    correlatable, never plaintext — see
    ``yashigani.common.credential_fingerprint``) already used on the audit
    path — for JWTs, Bearer/Basic auth headers, labelled
    password/passwd/pwd disclosure, vendor key prefixes (sk-/ghp_/glpat-/
    AKIA-), and generic 32-64 char hex secrets. This codebase's own API
    keys (``yashigani.identity.api_key.generate_api_key()``) are 64-char
    hex strings with NO vendor-style prefix (verified 2026-07-31 — no
    ``ysg_``-prefixed key format exists anywhere in the codebase), so they
    are caught by the generic hex pattern.
  - Adds a small set of supplementary patterns this filter needs that the
    audit masker does not carry in the same shape (the audit schema
    strips these into dedicated, always-fingerprinted TYPED fields instead
    of relying on free-text pattern matching):
      * Full PEM private-key BLOCK (header + base64 body + footer). The
        audit masker's PEM pattern only replaces the ``-----BEGIN...-----``
        header line, leaving the key body untouched — harmless there
        because typed audit fields never carry raw PEM bodies, but an app
        log line built by ``f"key={pem}"`` would leak the body verbatim.
      * Redis/Postgres URLs with embedded credentials
        (``redis://user:pass@host``, ``postgresql://user:pass@host``).
      * Labelled TOTP secret/code (base32/digit values — not hex, so the
        generic hex pattern in CredentialMasker does not catch them).
      * Labelled licence key/content/passphrase.

Fail-safe by construction (this IS the failure-mode this filter must not
become itself): a broken filter must never kill logging.
  - NEVER drops a record — ``filter()`` always returns True.
  - NEVER raises — any exception during redaction is caught and the
    record is emitted UNMODIFIED rather than losing the log line
    entirely. See ``test_logging_redaction.py::
    test_filter_error_emits_record_unmodified_never_raises``.

Author: Tom. Last updated: 2026-07-31.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from yashigani.audit.masking import CredentialMasker
from yashigani.common.credential_fingerprint import credential_fingerprint

_masker = CredentialMasker()


# ---------------------------------------------------------------------------
# Supplementary patterns — see module docstring for why these live here
# rather than in yashigani.audit.masking.
# ---------------------------------------------------------------------------

def _fingerprint_whole(match: "re.Match[str]") -> str:
    return credential_fingerprint(match.group(0))


def _fingerprint_labelled(match: "re.Match[str]") -> str:
    """Replacement for ``label: value`` / ``label=value`` patterns — keeps
    the label (log structure stays legible) and fingerprints the value."""
    return f"{match.group(1)}={credential_fingerprint(match.group(2))}"


def _fingerprint_db_url(match: "re.Match[str]") -> str:
    """Replacement for scheme://user:pass@host — keeps scheme + user
    (routing-relevant, not secret), fingerprints the password only."""
    return f"{match.group(1)}://{match.group(2)}:{credential_fingerprint(match.group(3))}@"


_EXTRA_PATTERNS: list[tuple["re.Pattern[str]", Any]] = [
    # Full PEM private-key BLOCK — header, base64 body, footer. DOTALL so
    # the body (the actual secret bytes) is included in the match, not
    # just the header line.
    (
        re.compile(
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            re.DOTALL,
        ),
        _fingerprint_whole,
    ),
    # Redis / Postgres (and TLS variants) URLs with embedded credentials.
    (
        re.compile(r"\b(rediss?|postgres(?:ql)?)://([^:@/\s]+):([^@/\s]+)@"),
        _fingerprint_db_url,
    ),
    # Labelled TOTP secret / code — base32 secrets and numeric codes are not
    # hex, so CredentialMasker's generic 32-64 char hex pattern misses them.
    (
        re.compile(
            r"(?i)\b(totp_secret|totp_code)\b\s*(?:is\s+|[:=]\s*)['\"]?([A-Za-z0-9+/=]+)"
        ),
        _fingerprint_labelled,
    ),
    # Labelled licence key / content / passphrase.
    (
        re.compile(
            r"(?i)\b(license_key|license_content|licence_key|licence_content|"
            r"passphrase)\b\s*(?:is\s+|[:=]\s*)['\"]?([^\s'\",;]+)"
        ),
        _fingerprint_labelled,
    ),
]


def _redact_text(text: str) -> str:
    """Apply the supplementary patterns above, THEN the shared audit-path
    masker. Order matters: CredentialMasker's own PEM pattern matches only
    the ``-----BEGIN...-----`` header line (by design, for the audit
    schema — see this module's docstring); if it ran first it would
    replace the header with a fingerprint BEFORE our DOTALL full-block
    pattern gets a chance to match, leaving the key body in plaintext.
    Running the structural patterns (full PEM block, DB-URL credential
    splitting) first, then the generic catch-all patterns (hex, Bearer,
    labelled password) second, ensures the more specific structure is
    captured intact."""
    for pattern, replacement in _EXTRA_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _masker.mask_string(text)
    return text


class RedactionFilter(logging.Filter):
    """Global stdout/app-log secret-redaction filter. See module docstring.

    Attach to logging Handler instances (NOT Logger objects) via
    ``install_log_redaction()`` below.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact_record(record)
        except Exception:
            # The filter itself must never take down logging. If redaction
            # fails for any reason, emit the record UNMODIFIED rather than
            # raising (which would propagate out of Handler.handle() and
            # potentially abort the log call) or dropping it (which would
            # silently destroy observability). A record that failed to be
            # redacted at least is not LOST.
            pass
        return True

    @staticmethod
    def _redact_record(record: logging.LogRecord) -> None:
        if record.args:
            # Labels and values are frequently split across msg/args in
            # %-style logging (e.g. "password=%s", (secret,)) — redacting
            # each independently would miss cases where the label pattern
            # match requires both halves in the SAME string. Render the
            # full message first (record.getMessage() applies msg % args
            # using the ORIGINAL, unredacted values — never logged), then
            # redact the rendered string as a whole and clear args so
            # downstream handlers don't re-apply % formatting to text that
            # may now contain literal '%' characters from a fingerprint or
            # unrelated content.
            rendered = record.getMessage()
            record.msg = _redact_text(rendered)
            record.args = ()
        elif isinstance(record.msg, str):
            record.msg = _redact_text(record.msg)


def install_log_redaction(root_logger: "logging.Logger | None" = None) -> RedactionFilter:
    """Attach a ``RedactionFilter`` to every handler currently on the root
    logger (or ``root_logger`` if supplied — used by tests).

    Must be called AFTER ``logging.basicConfig()`` (or whatever installs
    the process's stdout handler) so ``root_logger.handlers`` is
    non-empty. Idempotent per-handler: if a handler already has a
    ``RedactionFilter`` instance attached, a second one is not added.

    Returns the filter instance (mainly for tests).
    """
    logger = root_logger if root_logger is not None else logging.getLogger()
    the_filter = RedactionFilter()
    for handler in logger.handlers:
        if not any(isinstance(f, RedactionFilter) for f in handler.filters):
            handler.addFilter(the_filter)
    return the_filter


__all__ = ["RedactionFilter", "install_log_redaction"]
