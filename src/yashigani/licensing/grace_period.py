"""
Yashigani Licensing — Gateway grace-period enforcement (v2.23.3).

Provides:
  - check_gateway_access()        — called from LicenseEnforcementMiddleware;
                                    raises GatewayBlockedError or GatewayReadOnlyError
                                    when the licence has expired past the grace threshold.
  - LicenseEnforcementMiddleware  — ASGI middleware wired into the gateway stack;
                                    converts GatewayBlockedError → HTTP 503 and
                                    GatewayReadOnlyError → HTTP 403.
  - emit_grace_period_audit()     — daily audit-log emitter; called from the expiry monitor.
  - is_write_operation()          — classifies an HTTP method/path as a "write" operation
                                    for read-only mode enforcement.

Grace-period model (v2.23.3 canonical):
  ACTIVE / WARNING / CRITICAL — no restriction; gateway serves normally.
  EXPIRED (days 0–14 past expiry) — continues serving; banner on all pages;
                              daily WARN audit entry.
  READONLY (days 14–30 past expiry) — admin can view, cannot change config;
                              new agent-runs blocked; in-flight runs complete.
  BLOCKED (day 30+ past expiry) — HTTP 503 + Retry-After + renewal URL.

Multi-pod / K8s note (known gap, v2.23.3):
  _last_grace_audit_date is a process-level guard.  In a K8s multi-pod deployment
  each pod emits the daily grace-period audit event independently.  GRC tooling that
  expects exactly one event per calendar day will see one event per running pod.
  This is a known gap to be addressed in a future release via a Redis-backed
  distributed dedup key.  Pod count is bounded by the Helm `replicaCount`, so the
  event volume is bounded and predictable.

Per feedback_zero_trust_default.md: secure-by-default, fail-explicit not fail-silent.

Last updated: 2026-05-08T00:00:00+01:00
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from yashigani.licensing.model import LicenseExpiryMode, compute_expiry_mode

logger = logging.getLogger(__name__)

# Module-level backoffice_state reference — imported lazily at first use so
# that this module can be imported without the full backoffice stack (e.g. in
# tests, CLI tools, gateway workers).  Exposed at module level so tests can
# patch `yashigani.licensing.grace_period.backoffice_state`.
try:
    from yashigani.backoffice.state import backoffice_state  # noqa: E402
except ImportError:
    backoffice_state = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GatewayBlockedError(Exception):
    """
    Raised when the licence is BLOCKED (30+ days past expiry).
    The gateway middleware converts this to HTTP 503.
    """
    def __init__(self) -> None:
        super().__init__(
            "Yashigani licence has expired. Gateway is blocked. "
            "Renew at https://agnosticsec.com/pricing or contact sales@agnosticsec.com."
        )


class GatewayReadOnlyError(Exception):
    """
    Raised when the licence is in READONLY mode (14–30 days past expiry) and
    the request would perform a write / configuration-change / agent-run operation.
    The gateway middleware converts this to HTTP 403.
    """
    def __init__(self, operation: str = "") -> None:
        self.operation = operation
        super().__init__(
            f"Yashigani licence has expired. Gateway is in read-only mode{' — ' + operation + ' is blocked' if operation else ''}. "
            "Renew now: sales@agnosticsec.com."
        )


# ---------------------------------------------------------------------------
# Write-operation classifier
# ---------------------------------------------------------------------------

# HTTP methods that mutate state.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Path prefixes that are always read-only-safe (admin view routes, healthz).
# Anything NOT in this set that uses a WRITE_METHOD is treated as a write.
_READONLY_SAFE_PREFIXES = (
    "/healthz",
    "/internal/metrics",
    "/admin/license/status",   # machine-readable status is a GET anyway
    "/api/v1/license/status",  # same
)

# Paths that trigger agent-run blocking in READONLY mode even on GET (SSE streams).
# We block the endpoint that starts a run, not the status poll.
_AGENT_RUN_PREFIXES = (
    "/v1/chat/completions",
    "/v1/messages",
    "/admin/agents/run",
)


def is_write_operation(method: str, path: str) -> bool:
    """
    Return True if the operation should be blocked in READONLY mode.

    Write operations:
     - Any HTTP method in {POST, PUT, PATCH, DELETE}
     - GET requests to agent-run endpoints (SSE streams; these start new runs)

    Read-only-safe operations:
     - GET / HEAD / OPTIONS on any path not in _AGENT_RUN_PREFIXES
     - Any method on _READONLY_SAFE_PREFIXES paths
    """
    method = method.upper()

    # Always safe: health/metrics
    for prefix in _READONLY_SAFE_PREFIXES:
        if path.startswith(prefix):
            return False

    # Agent-run endpoints block in readonly regardless of method
    for prefix in _AGENT_RUN_PREFIXES:
        if path.startswith(prefix):
            return True

    return method in _WRITE_METHODS


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def check_gateway_access(
    method: str = "GET",
    path: str = "/",
    now: Optional[datetime] = None,
) -> None:
    """
    Check whether the gateway should serve the request given the current licence state.

    Raises:
        GatewayBlockedError  — licence BLOCKED (day 30+ past expiry).
        GatewayReadOnlyError — licence READONLY (day 14–30) and operation is a write.

    Does NOT raise for ACTIVE / WARNING / CRITICAL / EXPIRED (grace period) modes.

    This function is synchronous and safe to call from any context.  It reads the
    process-local licence state via enforcer.get_license() — no I/O.
    """
    try:
        from yashigani.licensing.enforcer import get_license
        lic = get_license()
    except Exception as exc:
        # If the licensing module is unavailable, fail-open (don't block legitimate
        # traffic due to import errors).  Log a warning; this is defence-in-depth.
        logger.warning("grace_period.check_gateway_access: could not read licence: %s", exc)
        return

    if now is None:
        now = datetime.now(timezone.utc)

    mode = lic.expiry_mode(now=now)

    if mode == LicenseExpiryMode.BLOCKED:
        raise GatewayBlockedError()

    if mode == LicenseExpiryMode.READONLY:
        if is_write_operation(method, path):
            raise GatewayReadOnlyError(operation=f"{method} {path}")

    # EXPIRED (grace): log if this is a meaningful request (not healthz)
    if mode == LicenseExpiryMode.EXPIRED and not path.startswith("/healthz"):
        # Cheap check: only log at DEBUG to avoid log flooding on every request.
        # Daily WARN audit is handled by emit_grace_period_audit() in the scheduler.
        logger.debug(
            "grace_period: licence in grace period (mode=%s), request %s %s passes",
            mode.value, method, path,
        )


# ---------------------------------------------------------------------------
# Audit emitter (called from expiry_monitor scheduler)
# ---------------------------------------------------------------------------

# Guard: track last calendar day on which a grace-period audit entry was emitted.
_last_grace_audit_date: Optional[object] = None  # datetime.date


async def emit_grace_period_audit() -> None:
    """
    Emit a daily WARN-level audit log entry when the licence is in grace or
    read-only mode.  Called from the APScheduler job in app.py lifespan
    alongside check_and_alert_licence_expiry().

    Safe to call when the audit writer is unavailable — logs a Python warning
    and returns without raising.
    """
    global _last_grace_audit_date

    from datetime import date

    try:
        from yashigani.licensing.enforcer import get_license
    except Exception as exc:
        logger.warning("emit_grace_period_audit: import failed: %s", exc)
        return

    try:
        lic = get_license()
    except Exception as exc:
        logger.warning("emit_grace_period_audit: could not read licence: %s", exc)
        return

    now = datetime.now(timezone.utc)
    mode = lic.expiry_mode(now=now)

    if mode not in (LicenseExpiryMode.EXPIRED, LicenseExpiryMode.READONLY, LicenseExpiryMode.BLOCKED):
        return  # Nothing to report

    today = date.today()
    if _last_grace_audit_date == today:
        return  # Already emitted today

    days = lic.days_remaining(now=now)
    days_since = -days if days is not None else "?"

    # Use the module-level backoffice_state (patchable in tests)
    state = backoffice_state

    try:
        writer = getattr(state, "audit_writer", None)
        if writer is not None:
            from yashigani.audit.schema import AuditEvent
            event = AuditEvent(
                event_type="LICENSE_GRACE_PERIOD",
                account_tier="system",
                masking_applied=False,
            )
            writer.write(
                event,
                component=(
                    f"licensing.grace_period mode={mode.value} "
                    f"days_since_expiry={days_since} "
                    f"expires_at={lic.expires_at.isoformat() if lic.expires_at else 'none'}"
                ),
            )
            _last_grace_audit_date = today
            logger.warning(
                "Licence grace-period audit: mode=%s days_since_expiry=%s",
                mode.value, days_since,
            )
    except Exception as exc:
        logger.error("emit_grace_period_audit: failed to write audit event: %s", exc)


# ---------------------------------------------------------------------------
# ASGI Middleware
# ---------------------------------------------------------------------------

import json


class LicenseEnforcementMiddleware:
    """
    ASGI middleware that enforces the licence grace-period model on every
    gateway request.

    Converts:
      GatewayBlockedError  → HTTP 503 with Retry-After: 3600 and JSON body.
      GatewayReadOnlyError → HTTP 403 with JSON body.

    Placement in the middleware stack (gateway/entrypoint.py):
      Runs AFTER SpiffePeerCertMiddleware and CaddyVerifiedMiddleware (i.e. the
      request has been verified as coming from a legitimate Caddy/mesh peer) and
      BEFORE AgentAuthMiddleware (no point authenticating a request that will be
      blocked by licence enforcement).

    This middleware is intentionally fail-open on licence-read errors — the same
    policy as check_gateway_access() itself — so that a licence-enforcer import
    failure does not take the gateway down.

    Readonly-safe whitelist (requests that pass in READONLY mode):
      /healthz, /internal/metrics, /admin/license/status, /api/v1/license/status.
      See _READONLY_SAFE_PREFIXES.

    K8s multi-pod note: this middleware is stateless per-request; no process-level
    state is held here.  The daily audit dedup is in emit_grace_period_audit().
    """

    def __init__(self, app) -> None:
        self._app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "/")

        try:
            check_gateway_access(method=method, path=path)
        except GatewayBlockedError as exc:
            await self._send_json(
                send,
                status=503,
                body={
                    "error": "licence_blocked",
                    "detail": str(exc),
                    "renewal_url": "https://agnosticsec.com/pricing",
                },
                extra_headers=[(b"retry-after", b"3600")],
            )
            return
        except GatewayReadOnlyError as exc:
            await self._send_json(
                send,
                status=403,
                body={
                    "error": "licence_readonly",
                    "detail": str(exc),
                    "renewal_url": "https://agnosticsec.com/pricing",
                },
            )
            return

        await self._app(scope, receive, send)

    @staticmethod
    async def _send_json(send, status: int, body: dict, extra_headers: list | None = None) -> None:
        payload = json.dumps(body).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode()),
        ]
        if extra_headers:
            headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload, "more_body": False})
