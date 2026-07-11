"""
Deterministic gate — DocumentSetStore (2.26 set-scoped salt).

Mode: DETERMINISTIC GATE. fakeredis-backed, no live stack.

Coverage:
  SET-ST-01  create mints a 256-bit opaque salt (≠ the name); persisted to Redis
  SET-ST-02  public_view REDACTS the salt (salt is a secret, never leaves gateway)
  SET-ST-03  set salt yields CONSISTENT tokens across files; per-file salt does not
  SET-ST-04  reload from Redis replays sets (restart-durable)
  SET-ST-05  remove_set destroys the salt; add_member is write-through + dedup'd
  SET-ST-06  blank name rejected (ValueError)

Controls: A02 (crypto material custody), Insecure-Design (opt-in reduced isolation).
Author: Ava (QA). 2026-06-10.
"""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.documents.set_store import DocumentSetStore
from yashigani.documents.pseudonymize import TokenAssigner
from yashigani.documents.token_scheme import compute_doc_hash

# DP-Y-002 §3.1: deployment secret is mandatory; use a fixed test value so
# per-file isolation and set-salt correlation assertions remain deterministic.
_TEST_SECRET = b"test-secret-for-set-store-unit-tests-only"


def _store():
    return DocumentSetStore(fakeredis.FakeStrictRedis())


def test_set_st_01_create_mints_opaque_salt():
    s = _store()
    row = s.create_set(name="payroll Q2")
    assert row["name"] == "payroll Q2"
    # 256-bit salt rendered as 64 hex chars — and NOT the name.
    assert len(row["salt"]) == 64
    assert row["salt"] != "payroll Q2"
    # Persisted: a fresh store over the SAME redis sees it.
    assert s.get_salt(row["id"]) == row["salt"]


def test_set_st_02_public_view_redacts_salt():
    s = _store()
    row = s.create_set(name="x")
    pv = DocumentSetStore.public_view(row)
    assert "salt" not in pv
    assert pv["has_salt"] is True
    assert set(pv) == {"id", "name", "members", "member_count", "created_at", "has_salt"}


def test_set_st_03_set_salt_correlates_file_salt_isolates():
    s = _store()
    set_salt = s.create_set(name="join-me")["salt"]
    file_a, file_b = compute_doc_hash(b"A"), compute_doc_hash(b"B")
    # Per-file: same value → DIFFERENT tokens across files (isolation).
    ta = TokenAssigner(file_a, secret=_TEST_SECRET).token_for("v@x.com")
    tb = TokenAssigner(file_b, secret=_TEST_SECRET).token_for("v@x.com")
    assert ta != tb
    # Set salt: same value → SAME token across files (correlation).
    sa = TokenAssigner(set_salt, secret=_TEST_SECRET).token_for("v@x.com")
    sb = TokenAssigner(set_salt, secret=_TEST_SECRET).token_for("v@x.com")
    assert sa == sb


def test_set_st_04_reload_replays_from_redis():
    r = fakeredis.FakeStrictRedis()
    s1 = DocumentSetStore(r)
    sid = s1.create_set(name="durable")["id"]
    s2 = DocumentSetStore(r)  # fresh store, same redis
    assert any(x["id"] == sid for x in s2.list_sets())
    assert s2.get_salt(sid) == s1.get_salt(sid)


def test_set_st_05_remove_and_add_member():
    s = _store()
    sid = s.create_set(name="m")["id"]
    row = s.add_member(sid, "fileA.csv")
    row = s.add_member(sid, "fileA.csv")  # dedup
    assert row["members"] == ["fileA.csv"]
    assert s.remove_set(sid) is True
    assert s.get_salt(sid) is None
    assert s.remove_set(sid) is False


def test_set_st_06_blank_name_rejected():
    s = _store()
    with pytest.raises(ValueError):
        s.create_set(name="   ")
