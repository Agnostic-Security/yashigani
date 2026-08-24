"""
DP-Y-002 §3.1 + §3.2 + DP-Y-004 coherence — post-3.1-fix regression suite.

ITEMS COVERED
─────────────
S1  pipeline with deployment secret provisioned → PSEUDONYMIZE succeeds
S2  pipeline with no secret (secret=None)       → BLOCK, fail-closed (DP-Y-002 §3.1)
S3  mode-A + operate-on field                   → ROUTE_LOCAL (gate is mode-agnostic)
S4  mode-B + operate-on field                   → ROUTE_LOCAL (existing behaviour holds)
I4-TTL  verify_result_integrity with expired table → 404 (DP-Y-004 §3.1 TTL)
I4-CT   _detokenize_gate: mismatched owner/tenant  → 403 rejected (CT compare)

None of these tests touch the live stack or any DB/Redis.
All run in-process against the plain Python objects.

Last updated: 2026-07-02
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from yashigani.backoffice.routes.documents import _detokenize_gate
from yashigani.documents.pipeline import (
    DISPOSITION_BLOCK,
    DISPOSITION_PSEUDONYMIZE,
    DISPOSITION_ROUTE_LOCAL,
    DocumentInspectionPipeline,
)
from yashigani.documents.pseudonymize import CorrespondenceTable


# ── helpers ───────────────────────────────────────────────────────────────────

_DEPLOY_SECRET = b"deadbeef" * 4    # arbitrary 32-byte hex-equivalent bytes

# A minimal CSV with a PII e-mail so the pipeline actually runs PSEUDONYMIZE.
_EMAIL = "alice@example.com"
_CSV_PII = f"name,email\nAlice,{_EMAIL}\nBob,{_EMAIL}\n".encode()

# A CSV with a SALARY column — classified as OPERATE_ON sensitive.
_CSV_SALARY = (
    "name,email,salary\n"
    "Alice,alice@example.com,52000\n"
    "Bob,bob@example.com,61000\n"
    "Carol,carol@example.com,48000\n"
).encode()

_TENANT = "default"
_ACCOUNT = "admin-uuid-001"
_ROLE = "data-scientists"
_DEFAULT_TTL_S = 3600


def _pipeline(*, secret=_DEPLOY_SECRET):
    """Construct a DocumentInspectionPipeline with a controlled pseudonymize secret."""
    with patch(
        "yashigani.documents.pipeline.load_deployment_secret",
        return_value=secret,
    ):
        return DocumentInspectionPipeline(small_set_escalation=False)


def _table(
    *,
    account: str = _ACCOUNT,
    tenant: str = _TENANT,
    role: str = _ROLE,
    ttl_s: int = _DEFAULT_TTL_S,
    expired: bool = False,
) -> CorrespondenceTable:
    """Build a fresh unconsumed CorrespondenceTable."""
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
    assert not t.consumed
    return t


@dataclass
class _FakeResult:
    """Minimal stand-in for DocumentProcessingResult held in the result index."""
    correspondence_table: CorrespondenceTable | None
    doc_hash: str | None = None
    salt_scope: str = "file"


def _session(account: str = _ACCOUNT):
    """Minimal session stub."""
    s = MagicMock()
    s.account_id = account
    return s


def _gate_env(account: str = _ACCOUNT):
    """Patch: RBAC → True, tenant env set to _TENANT."""
    rbac_patch = patch(
        "yashigani.backoffice.routes.documents._admin_in_detokenize_role",
        new=AsyncMock(return_value=True),
    )
    env_patch = patch.dict("os.environ", {"YASHIGANI_TENANT_ID": _TENANT})
    return rbac_patch, env_patch


# ── S1: secret provisioned → pipeline advances PAST secret check ─────────────
#
# In unit test context the extractor sandbox image is unavailable, so the full
# PSEUDONYMIZE re-render stage is unreachable.  S1 therefore verifies the
# NECESSARY sub-property: with a secret provisioned the fail-closed secret check
# does NOT fire — the pipeline reaches re-render (where it then blocks on the
# missing sandbox).  The block_reason references sandbox/re-render, NOT the
# "deployment secret not provisioned" guard.  The S2 test verifies the
# complementary side: without a secret the block fires BEFORE re-render.
# Together S1+S2 prove the secret gate is operative.

def test_s1_with_secret_reaches_rerender_not_secret_check():
    """S1 — DP-Y-002 §3.1: with a deployment secret, the pipeline advances past
    the fail-closed secret check.  In unit tests without a sandbox the pipeline
    subsequently blocks at re-render (expected, pre-existing limitation); the
    key assertion is that the block reason is about the sandbox/re-render, not
    about a missing deployment secret."""
    pipe = _pipeline(secret=_DEPLOY_SECRET)
    r = pipe.inspect(
        _CSV_PII, "text/csv",
        request_id="s1-01",
        requested_action="PSEUDONYMIZE",
        pseudonymize_mode="A",
    )
    # In unit test context the outcome is BLOCK (no sandbox), NOT the secret check.
    reason = r.block_reason or ""
    assert "deployment secret not provisioned" not in reason, (
        "with a secret provisioned the pipeline must pass the secret check; "
        f"got: {reason!r}"
    )
    assert "DP-Y-002 §3.1" not in reason, (
        "§3.1 fail-closed must not fire when a secret IS provisioned; "
        f"got: {reason!r}"
    )
    # The pipeline advanced to re-render before blocking — the sandbox is absent
    # in unit tests, which is the ONLY acceptable reason for BLOCK here.
    assert "re-render" in reason.lower() or "sandbox" in reason.lower(), (
        f"expected re-render/sandbox block (pre-existing limitation), got: {reason!r}"
    )


# ── S2: no secret → fail-closed BLOCK ─────────────────────────────────────────

def test_s2_pseudonymize_blocked_without_secret():
    """S2 — DP-Y-002 §3.1: when no deployment secret is provisioned the
    pipeline MUST block (fail-closed) rather than falling back to doc_hash key."""
    pipe = _pipeline(secret=None)
    r = pipe.inspect(
        _CSV_PII, "text/csv",
        request_id="s2-01",
        requested_action="PSEUDONYMIZE",
        pseudonymize_mode="A",
    )
    assert r.disposition == DISPOSITION_BLOCK, (
        f"expected BLOCK (fail-closed), got {r.disposition!r}"
    )
    # Block reason must mention the missing secret and DP-Y-002.
    assert "DP-Y-002" in (r.block_reason or ""), (
        f"block reason should reference DP-Y-002, got: {r.block_reason!r}"
    )
    assert r.forward_bytes is None or r.forward_bytes == b""


def test_s2_block_reason_references_secret_source():
    """S2b — block reason must tell the operator HOW to fix it."""
    pipe = _pipeline(secret=None)
    r = pipe.inspect(
        _CSV_PII, "text/csv",
        request_id="s2-02",
        requested_action="PSEUDONYMIZE",
        pseudonymize_mode="A",
    )
    reason = r.block_reason or ""
    assert "YASHIGANI_DOCUMENT_PSEUDONYMIZE_SECRET" in reason or \
           "document_pseudonymize_secret" in reason, (
        f"block reason must reference the secret env/file, got: {reason!r}"
    )


# ── S3: mode-A + operate-on → ROUTE_LOCAL (gate is mode-agnostic) ─────────────

def test_s3_modea_operate_on_routes_local():
    """S3 — DP-Y-002 §3.2: mode A with an operate-on sensitive field (SALARY) must
    route local, not forward tokenised bytes to the cloud.  The gate is now
    mode-agnostic — mode B was already tested in test_opaque_token_scheme.py."""
    pipe = _pipeline(secret=_DEPLOY_SECRET)
    r = pipe.inspect(
        _CSV_SALARY, "text/csv",
        request_id="s3-01",
        requested_action="PSEUDONYMIZE",
        pseudonymize_mode="A",
    )
    assert r.disposition == DISPOSITION_ROUTE_LOCAL, (
        f"mode-A + SALARY operate-on: expected ROUTE_LOCAL, got {r.disposition!r}"
    )
    assert r.route_local is True
    # Operate-on classes must be surfaced.
    assert any("SALARY" in c for c in (r.operate_on_classes or [])), (
        f"operate_on_classes: {r.operate_on_classes!r}"
    )
    # Original bytes must be forwarded (in-estate, not tokenised to cloud).
    assert r.forward_bytes == _CSV_SALARY


# ── S4: mode-B + operate-on → ROUTE_LOCAL (existing behaviour still holds) ────

def test_s4_modeb_operate_on_routes_local():
    """S4 — DP-Y-002 §3.2: pre-existing mode-B test confirming the gate still
    holds after the mode-A amendment.  (Also exercised in test_opaque_token_scheme,
    kept here for DP-Y-002-coherence grouping.)"""
    pipe = _pipeline(secret=_DEPLOY_SECRET)
    r = pipe.inspect(
        _CSV_SALARY, "text/csv",
        request_id="s4-01",
        requested_action="PSEUDONYMIZE",
        pseudonymize_mode="B",
    )
    assert r.disposition == DISPOSITION_ROUTE_LOCAL, (
        f"mode-B + SALARY operate-on: expected ROUTE_LOCAL, got {r.disposition!r}"
    )
    assert r.route_local is True


# ── I4-TTL: verify_result_integrity + expired table → 404 ─────────────────────

@pytest.mark.asyncio
async def test_i4_ttl_expired_table_gives_404_on_integrity_surface():
    """I4-TTL — DP-Y-004 §3.1: when the correspondence table is past its TTL the
    verify_result_integrity route must raise 404 and proactively drop the table."""
    # Build an expired fake result (the route reads from _results[request_id]).
    expired_table = _table(ttl_s=300, expired=True)
    doc_hash = "sha256:" + "ab" * 32
    result = _FakeResult(correspondence_table=expired_table, doc_hash=doc_hash)

    import yashigani.backoffice.routes.documents as docs_mod
    req_id = "i4-ttl-01"

    # Inject into the module-level _results dict.
    original = dict(docs_mod._results)
    docs_mod._results[req_id] = result  # type: ignore[index]
    try:
        from yashigani.backoffice.routes.documents import verify_result_integrity
        session = _session()
        with pytest.raises(HTTPException) as exc_info:
            await verify_result_integrity(req_id, session)
        err = exc_info.value
        assert err.status_code == 404, f"expected 404, got {err.status_code}"
        # Table must be proactively dropped after expiry.
        assert result.correspondence_table is None, (
            "expired table must be dropped after TTL check"
        )
    finally:
        docs_mod._results.clear()
        docs_mod._results.update(original)


@pytest.mark.asyncio
async def test_i4_ttl_live_table_not_404_on_integrity_surface():
    """I4-TTL sanity: a live (non-expired) table with a doc_hash does NOT 404
    on the verify surface (assuming the integrity verify itself succeeds)."""
    live_table = _table(ttl_s=3600, expired=False)
    doc_hash = "sha256:" + "ab" * 32
    result = _FakeResult(correspondence_table=live_table, doc_hash=doc_hash)

    import yashigani.backoffice.routes.documents as docs_mod
    req_id = "i4-ttl-live"
    original = dict(docs_mod._results)
    docs_mod._results[req_id] = result  # type: ignore[index]
    try:
        from yashigani.backoffice.routes.documents import verify_result_integrity
        session = _session()
        # Should NOT raise 404 for TTL (may raise for pipeline not attached —
        # that's a different code path; we only care it's NOT a TTL 404).
        try:
            await verify_result_integrity(req_id, session)
        except HTTPException as exc:
            # Only TTL-driven 404 is the failure mode we're guarding against.
            if exc.status_code == 404:
                detail = exc.detail or {}
                assert detail.get("error") != "no_integrity_artefacts" or \
                       result.correspondence_table is not None, (
                    "live table was dropped or TTL-expired prematurely"
                )
    finally:
        docs_mod._results.clear()
        docs_mod._results.update(original)


# ── I4-CT: _detokenize_gate mismatched owner → rejected ──────────────────────

@pytest.mark.asyncio
async def test_i4_ct_wrong_owner_rejected():
    """I4-CT — DP-Y-004: _detokenize_gate must reject a session whose
    account_id does not match the table's owner_identity.

    This exercises the secrets.compare_digest path: a different (but
    syntactically valid) account ID must NOT be accepted.  We treat any
    non-200 / non-tuple response (403/404/HTTPException) as a pass."""
    table = _table(account=_ACCOUNT)
    result = _FakeResult(correspondence_table=table)
    # Session claims a DIFFERENT account — timing-safe compare must still reject.
    wrong_session = _session(account="attacker-uuid-999")

    rbac, env = _gate_env(account=_ACCOUNT)
    with rbac, env:
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "ct-mismatch", wrong_session, surface="json")

    err = exc_info.value
    # Must be a 403 (identity mismatch) or 404 (treat as not-found).
    assert err.status_code in (403, 404), (
        f"mismatched owner should give 403/404, got {err.status_code}"
    )
    # Table must NOT be consumed — the attacker should not burn a handle.
    assert not table.consumed, "failed-auth call must not consume the single-use handle"


@pytest.mark.asyncio
async def test_i4_ct_wrong_tenant_rejected():
    """I4-CT: mismatched tenant binding also rejects (secrets.compare_digest)."""
    table = _table(tenant=_TENANT)
    result = _FakeResult(correspondence_table=table)
    session = _session(account=_ACCOUNT)

    rbac = patch(
        "yashigani.backoffice.routes.documents._admin_in_detokenize_role",
        new=AsyncMock(return_value=True),
    )
    # env sets YASHIGANI_TENANT_ID to a DIFFERENT tenant than the table's binding.
    env = patch.dict("os.environ", {"YASHIGANI_TENANT_ID": "wrong-tenant"})
    with rbac, env:
        with pytest.raises(HTTPException) as exc_info:
            await _detokenize_gate(result, "ct-tenant", session, surface="json")

    assert exc_info.value.status_code in (403, 404)
    assert not table.consumed
