"""Unified user-facing security alert envelope.

Every Yashigani enforcement point returns the same ``yashigani_alert`` shape so
the end user — human OR non-human agent — always gets a consistent, plain-English
explanation: what was done (action), which direction the threat came from, why
(reason), which rule fired, and (for policy denials) the OPA policy id. This both
educates and deters.

See AgnosticSecurity/Products/Yashigani/opa-decision-contract-and-user-alerts.md.
"""
from __future__ import annotations

import datetime

# Action taxonomy
ACTION_BLOCKED = "BLOCKED"    # request/response stopped entirely
ACTION_REDACTED = "REDACTED"  # continued, sensitive data masked
ACTION_MODIFIED = "MODIFIED"  # continued, risky span removed (sanitised)
ACTION_DENIED = "DENIED"      # stopped by policy (OPA)

# Direction: did the threat come from the caller's prompt or from the tool?
DIRECTION_FROM_YOU = "from_you"
DIRECTION_FROM_TOOL = "from_tool"

_DEFAULT_DENY_CODE = 403


def valid_http_code(code, default: int = _DEFAULT_DENY_CODE) -> int:
    """Clamp to a real HTTP status code (1xx–5xx per RFC 9110); else ``default``."""
    try:
        c = int(code)
    except (TypeError, ValueError):
        return default
    return c if 100 <= c <= 599 else default


def build_alert(
    action: str,
    reason: str,
    *,
    rule: str | None = None,
    direction: str | None = None,
    policy_id: str | None = None,
    request_id: str | None = None,
) -> dict:
    """Build the response body for a blocking action (replaces the result)."""
    alert: dict = {"action": action, "reason": reason}
    if direction:
        alert["direction"] = direction
    if rule:
        alert["rule"] = rule
    if policy_id:
        alert["policy_id"] = policy_id
    if request_id:
        alert["request_id"] = request_id
    alert["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {"yashigani_alert": alert, "result": None}


def alert_headers(
    action: str,
    *,
    rule: str | None = None,
    policy_id: str | None = None,
    reason: str | None = None,
) -> dict:
    """Header form for NON-blocking actions (e.g. PII redaction) — the real
    result still reaches the caller, but the alert metadata travels alongside.
    """
    def _hdr_safe(v: str) -> str:
        # Strip BOTH CR and LF (response-splitting / header-injection defence,
        # LAURA-2253-ALERT-001) and force ascii single-line. Applied to every
        # header value, not just reason, so future non-static call sites are safe.
        return (
            v.replace("\r", " ").replace("\n", " ")
            .encode("ascii", "replace").decode("ascii")
        )

    headers = {"X-Yashigani-Alert-Action": _hdr_safe(action)}
    if rule:
        headers["X-Yashigani-Alert-Rule"] = _hdr_safe(rule)
    if policy_id:
        headers["X-Yashigani-Alert-Policy-Id"] = _hdr_safe(policy_id)
    if reason:
        headers["X-Yashigani-Alert-Reason"] = _hdr_safe(reason)
    return headers
