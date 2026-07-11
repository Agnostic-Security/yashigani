"""
DP-Y-004 — Single-use capability-handle gate.

Defensive publication §3.1: "A handle authorises ONE reversal (or one map
download) and is then CONSUMED; a replayed handle is rejected."

Tests (machine-judged binary PASS/FAIL):

  H1  first reveal succeeds — table returned, consumed flag set
  H2  second use of same handle rejected — 409 handle_already_consumed
  H3  concurrent double-use does not double-succeed — exactly one winner

  GAP-1  expired CorrespondenceTable rejected 404 + plaintext proactively
         dropped (DP-Y-004 §3.1 "within the TTL" invariant)
  GAP-2  sequential replay after burn emits a replay audit event (the audit
         log must distinguish "burned+replayed" from "never had a table")

All tests exercise ``_detokenize_gate`` from
``yashigani.backoffice.routes.documents`` directly, mocking:
  - ``_admin_in_detokenize_role`` → True (RBAC passes)
  - ``YASHIGANI_TENANT_ID`` env var  (tenant binding)
  - ``backoffice_state.rbac_store``  (to keep gate-flow in _detokenize_gate)

The ``CorrespondenceTable`` is a plain Python dataclass — no DB/network
involved.

Last updated: 2026-07-02
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from yashigani.backoffice.routes.documents import _detokenize_gate
from yashigani.documents.pseudonymize import CorrespondenceTable

# ── Fixtures ──────────────────────────────────────────────────────────────────

TENANT = "default"
ACCOUNT = "admin-uuid-001"
ROLE = "data-scientists"

#: Default TTL used by all H1/H2/H3 fixtures (large — well within TTL).
_DEFAULT_TTL_S = 3600


def _table(
    *,
    account: str = ACCOUNT,
    tenant: str = TENANT,
    role: str = ROLE,
    ttl_s: int = _DEFAULT_TTL_S,
    expired: bool = False,
) -> CorrespondenceTable:
    """Build a fresh unconsumed CorrespondenceTable bound to *account*/*tenant*.

    ``ttl_s`` sets the plaintext TTL (DP-Y-004 §3.1).  ``expired=True``
    backdates ``created_at`` so the table is already past its TTL — used by
    GAP-1 tests.  ``ttl_s`` must be > 0 for a non-expired table."""
    now = time.monotonic()
    created_at = (now - ttl_s - 10) if expired else now
    t = CorrespondenceTable(
        rows={"tok_aabbcc": "Alice Johnson", "tok_ddeeff": "Bob Smith"},
        detokenize_rbac_role=role,
        doc_hash="sha256:deadbeef" * 4,
        owner_identity=account,
        tenant=tenant,
        created_at=created_at,
        ttl_s=ttl_s,
    )
    # consumed defaults to False (init=False field — construction starts clean)
    assert not t.consumed
    return t


@dataclass
class _FakeResult:
    """Minimal stand-in for the DocumentProcessingResult held in the result index."""
    correspondence_table: CorrespondenceTable | None


def _session(account: str = ACCOUNT):
    """Minimal session stub with account_id."""
    s = MagicMock()
    s.account_id = account
    return s


# ── Shared patch context ────────────────────────────────────────────────────

def _gate_env():
    """Patch context manager: RBAC role check → True, tenant env set."""
    rbac_patch = patch(
        "yashigani.backoffice.routes.documents._admin_in_detokenize_role",
        new=AsyncMock(return_value=True),
    )
    env_patch = patch.dict("os.environ", {"YASHIGANI_TENANT_ID": TENANT})
    return rbac_patch, env_patch


# ── H1 — First reveal succeeds ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_h1_first_reveal_succeeds():
    """H1: first authorised call returns (table, role) and sets consumed=True."""
    table = _table()
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        out_table, out_role = await _detokenize_gate(result, "req-001", session, surface="json")

    # Correct table returned
    assert out_table is table
    assert out_role == ROLE
    # All tokens present in the returned table
    assert "tok_aabbcc" in out_table.rows
    assert "tok_ddeeff" in out_table.rows
    # Consumed flag set after first successful reveal
    assert table.consumed is True


# ── H2 — Second use of same handle rejected ───────────────────────────────────


@pytest.mark.asyncio
async def test_h2_second_use_rejected_409():
    """H2: replaying the same handle raises 409 handle_already_consumed."""
    table = _table()
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        # First call — must succeed
        first_table, _ = await _detokenize_gate(result, "req-002", session, surface="json")
        assert first_table.consumed is True

        # Second call on the SAME result (same table object, consumed=True)
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "req-002", session, surface="json")

    err = exc_info.value
    assert err.status_code == 409
    detail = err.detail
    assert detail["error"] == "handle_already_consumed"
    # Message should reference DP-Y-004
    assert "DP-Y-004" in detail["message"]


@pytest.mark.asyncio
async def test_h2_csv_surface_also_rejected_after_json_reveal():
    """H2b: a CSV surface attempt after JSON reveal is rejected — both surfaces share the same gate."""
    table = _table()
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        await _detokenize_gate(result, "req-003", session, surface="json")
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "req-003", session, surface="csv")

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail["error"] == "handle_already_consumed"


# ── H3 — Concurrent double-use does not double-succeed ────────────────────────


@pytest.mark.asyncio
async def test_h3_concurrent_double_use_exactly_one_winner():
    """H3: two concurrent coroutines calling the gate on the same table — exactly
    one wins (returns the table) and exactly one loses (409).

    Atomicity: ``_detokenize_gate`` has no ``await`` between the ``if
    table.consumed`` check and the ``table.consumed = True`` assignment.  In the
    single-threaded asyncio event loop, a synchronous block is non-preemptible —
    the first coroutine that reaches the gate wins and the second is rejected,
    never both winning.
    """
    table = _table()
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()

    outcomes: list[str] = []  # "ok" or "rejected"

    async def try_reveal():
        try:
            await _detokenize_gate(result, "req-004", session, surface="json")
            outcomes.append("ok")
        except HTTPException as exc:
            if exc.status_code == 409 and exc.detail.get("error") == "handle_already_consumed":
                outcomes.append("rejected")
            else:
                raise  # unexpected error — re-raise to fail the test

    with rbac, env:
        await asyncio.gather(try_reveal(), try_reveal())

    assert len(outcomes) == 2, f"expected 2 outcomes, got {outcomes}"
    assert outcomes.count("ok") == 1, f"expected exactly 1 winner, got {outcomes}"
    assert outcomes.count("rejected") == 1, f"expected exactly 1 rejection, got {outcomes}"
    # The table must be consumed after the race
    assert table.consumed is True


# ── Guard: consumed flag starts False on every fresh table ────────────────────


def test_correspondence_table_starts_unconsumed():
    """Fresh CorrespondenceTable always starts with consumed=False (init=False field)."""
    for _ in range(5):
        t = _table()
        assert t.consumed is False


# ── Guard: no_correspondence_table → 404, not 409 ────────────────────────────


@pytest.mark.asyncio
async def test_no_table_gives_404_not_consumed_error():
    """A result with no correspondence_table raises 404, not the 409 consumed error."""
    result = _FakeResult(correspondence_table=None)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "req-005", session, surface="json")

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail["error"] == "no_correspondence_table"


# ── GAP-1 — CorrespondenceTable TTL (DP-Y-004 §3.1 "within the TTL") ─────────


@pytest.mark.asyncio
async def test_gap1_expired_table_returns_404_and_drops_plaintext():
    """GAP-1: an expired CorrespondenceTable is rejected 404 and the plaintext
    is proactively dropped from the result (DP-Y-004 §3.1 TTL invariant)."""
    table = _table(ttl_s=300, expired=True)  # created_at 310s in the past
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "req-gap1-exp", session, surface="json")

    err = exc_info.value
    assert err.status_code == 404
    assert err.detail["error"] == "no_correspondence_table"
    # Proactive drop: plaintext must be gone from the result after expiry.
    assert result.correspondence_table is None


@pytest.mark.asyncio
async def test_gap1_within_ttl_reveals_successfully():
    """GAP-1: a table within its TTL still reveals successfully."""
    table = _table(ttl_s=3600)  # expires in 3600s from now
    result = _FakeResult(correspondence_table=table)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        out_table, out_role = await _detokenize_gate(
            result, "req-gap1-ok", session, surface="json"
        )

    assert out_table is table
    assert out_role == ROLE
    assert "tok_aabbcc" in out_table.rows


@pytest.mark.asyncio
async def test_gap1_fail_closed_when_ttl_metadata_missing():
    """GAP-1: fail-closed when created_at=0.0 or ttl_s=0 — treated as expired.

    A table constructed without TTL metadata (e.g. created by code predating
    the GAP-1 fix) must not be retrievable indefinitely.  Missing metadata is
    treated as expired (fail-closed), never as fresh."""
    # Directly construct with default TTL fields (both 0 — the fail-closed case).
    table_no_ttl = CorrespondenceTable(
        rows={"tok_aabbcc": "Alice"},
        detokenize_rbac_role=ROLE,
        doc_hash="sha256:deadbeef",
        owner_identity=ACCOUNT,
        tenant=TENANT,
        # created_at defaults to 0.0 and ttl_s defaults to 0 — missing metadata
    )
    result = _FakeResult(correspondence_table=table_no_ttl)
    session = _session()

    rbac, env = _gate_env()
    with rbac, env:
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(
                result, "req-gap1-no-ttl", session, surface="json"
            )

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail["error"] == "no_correspondence_table"
    # Proactive drop on missing-TTL path too.
    assert result.correspondence_table is None


def test_gap1_expired_method_unit():
    """Unit: CorrespondenceTable._expired() returns True for expired/missing TTL."""
    now = time.monotonic()

    # Well within TTL.
    t_fresh = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=now, ttl_s=3600,
    )
    assert not t_fresh._expired()
    # Exact boundary: elapsed == ttl_s → expired (>= comparison).
    t_boundary = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=now - 3600, ttl_s=3600,
    )
    assert t_boundary._expired()
    # Past TTL.
    t_expired = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=now - 400, ttl_s=300,
    )
    assert t_expired._expired()
    # Fail-closed: missing created_at (0.0).
    t_no_ts = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=0.0, ttl_s=300,
    )
    assert t_no_ts._expired()
    # Fail-closed: missing ttl_s (0).
    t_no_ttl = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=now, ttl_s=0,
    )
    assert t_no_ttl._expired()
    # Injected now: test with explicit clock.
    t_inject = CorrespondenceTable(
        rows={}, detokenize_rbac_role=ROLE, created_at=1000.0, ttl_s=300,
    )
    assert not t_inject._expired(now=1200.0)   # 200s elapsed < 300s TTL
    assert t_inject._expired(now=1301.0)        # 301s elapsed >= 300s TTL


# ── GAP-2 — Sequential-replay audit (DP-Y-004 §3.1 replay audit invariant) ───


@pytest.mark.asyncio
async def test_gap2_sequential_replay_emits_audit_event():
    """GAP-2 (DP-Y-004 §3.1): after a table is burned via ``_burn_correspondence_table``,
    a second call to ``_detokenize_gate`` on the same request_id emits a replay
    audit event — so the audit log distinguishes "burned+replayed" from "never
    had a table."  The response is still 404 (no information leakage)."""
    import yashigani.backoffice.routes.documents as doc_module
    from yashigani.backoffice.routes.documents import _burn_correspondence_table

    request_id = "req-gap2-sequential-replay-001"
    table = _table()
    result = _FakeResult(correspondence_table=table)
    session = _session()

    try:
        # Step 1: first reveal succeeds.
        rbac, env = _gate_env()
        with rbac, env:
            out_table, _ = await _detokenize_gate(
                result, request_id, session, surface="json"
            )
        assert out_table.consumed is True

        # Step 2: simulate burn (as the route does after _detokenize_gate).
        _burn_correspondence_table(result, request_id)
        assert result.correspondence_table is None
        assert request_id in doc_module._burned, "burn must add to _burned"

        # Step 3: sequential replay — table is None + request_id in _burned.
        audit_calls: list[str] = []

        with patch(
            "yashigani.backoffice.routes.documents._audit_handle_replay",
            side_effect=lambda s, rid: audit_calls.append(rid),
        ):
            rbac2, env2 = _gate_env()
            with rbac2, env2:
                with pytest.raises(HTTPException) as exc_info:
                    await _detokenize_gate(
                        result, request_id, session, surface="json"
                    )

        # Still 404 — the caller sees no difference from "never had a table".
        assert exc_info.value.status_code == 404
        assert exc_info.value.detail["error"] == "no_correspondence_table"
        # But the audit event MUST have fired.
        assert request_id in audit_calls, (
            f"Expected replay audit for {request_id}, got calls={audit_calls}"
        )

    finally:
        # Clean up module-level _burned to avoid cross-test pollution.
        doc_module._burned.discard(request_id)


@pytest.mark.asyncio
async def test_gap2_unrelated_miss_does_not_emit_replay_audit():
    """GAP-2: a result that never had a table (not a burn — just absent) does
    NOT emit a replay audit event.  The audit must distinguish a real replay
    from an unrelated 404."""
    result = _FakeResult(correspondence_table=None)
    session = _session()
    request_id = "req-gap2-never-had-table-001"

    audit_calls: list[str] = []

    with patch(
        "yashigani.backoffice.routes.documents._audit_handle_replay",
        side_effect=lambda s, rid: audit_calls.append(rid),
    ):
        rbac, env = _gate_env()
        with rbac, env:
            with pytest.raises(HTTPException) as exc_info:
                await _detokenize_gate(result, request_id, session, surface="json")

    assert exc_info.value.status_code == 404
    # No replay audit for a request_id that was never in _burned.
    assert audit_calls == [], (
        f"Unexpected replay audit for an unrelated miss: {audit_calls}"
    )
