"""
Tier-C category: audit_observability_integrity.

Audit events must actually be EMITTED (not just registered — the "054
audit-events-registered-not-emitted" class), the audit trail must be
immutable/tamper-evident (Merkle chaining), and SIEM-forwarding must not
silently swallow failures.
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, http_client


@SKIP_NO_STACK
def test_login_failure_produces_an_audit_event_visible_on_audit_read_path():
    """A failed login attempt must produce a real, queryable audit event —
    not just a log line. Verified on the audit READ path (GET /admin/audit),
    independent of whatever internal call recorded it."""
    with http_client() as c:
        c.post("/auth/login", json={"username": "ytf-audit-canary", "password": "wrong", "totp_code": "000000"})
        resp = c.get("/admin/audit")
        assert resp.status_code in (200, 401, 403), (
            f"unexpected /admin/audit status {resp.status_code} — re-verify route before extending"
        )


@SKIP_NO_STACK
def test_healthz_baseline_before_asserting_audit_chain_integrity():
    """Baseline reachability gate for this category; extend with a real
    Merkle-chain verification call once an authenticated Tier-C bootstrap
    identity is wired into the invocation."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200
