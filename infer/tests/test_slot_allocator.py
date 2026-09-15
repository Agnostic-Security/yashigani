# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Per-user KV slot assignment — the C1 `id_slot` leg (YSG-RISK-313).

Tiago 2026-09-15: "cache is per user".

The invariant under test is narrow and total:

    a slot handed to a user never contains a different user's KV cache.

Everything else — LRU order, capacity, quarantine — is in service of that.
The dangerous moment is recycling, so most of these tests are about what
happens when a slot changes hands, and specifically what happens when the
erase that is supposed to make that safe fails.
"""

from __future__ import annotations

import threading

import pytest

from kuroshio.supervisor.slots import SlotAllocator, SlotEraseFailed


class FakeEraser:
    def __init__(self, *, fail_on: set[int] | None = None) -> None:
        self.erased: list[int] = []
        self.fail_on = fail_on or set()

    def erase(self, port: int, slot: int) -> None:
        if slot in self.fail_on:
            raise RuntimeError(f"upstream refused to erase slot {slot}")
        self.erased.append(slot)


def _alloc(n_slots: int = 2, **kw: object) -> tuple[SlotAllocator, FakeEraser]:
    eraser = FakeEraser(**kw)  # type: ignore[arg-type]
    return SlotAllocator(n_slots=n_slots, eraser=eraser, port=39000), eraser


# --- one user, one slot ------------------------------------------------------


def test_a_user_keeps_the_same_slot() -> None:
    """The whole point: a user's prefix is reusable only because they come back
    to the same slot."""
    a, _ = _alloc()
    assert a.acquire("alice") == a.acquire("alice") == a.acquire("alice")


def test_different_users_get_different_slots() -> None:
    a, _ = _alloc()
    assert a.acquire("alice") != a.acquire("bob")


def test_empty_identity_is_refused() -> None:
    """An empty identity would collapse every anonymous caller onto one shared
    slot — precisely the shared-cache posture this replaces."""
    a, _ = _alloc()
    for bad in ("", "   "):
        with pytest.raises(ValueError, match="non-empty identity"):
            a.acquire(bad)


# --- recycling: the dangerous moment ----------------------------------------


def test_slot_is_erased_before_a_new_user_receives_it() -> None:
    a, eraser = _alloc(n_slots=2)
    alice = a.acquire("alice")
    a.acquire("bob")
    carol = a.acquire("carol")  # forces eviction of alice (LRU)
    assert carol == alice, "carol should have taken alice's recycled slot"
    assert eraser.erased == [alice], "the slot must be erased before hand-over"


def test_lru_is_the_eviction_order() -> None:
    a, _ = _alloc(n_slots=2)
    alice = a.acquire("alice")
    a.acquire("bob")
    a.acquire("alice")  # alice is now most-recently-used, bob is LRU
    carol = a.acquire("carol")
    assert carol != alice, "the most recently used user must not be evicted"


def test_evicted_user_gets_a_fresh_slot_not_their_old_one() -> None:
    a, _ = _alloc(n_slots=1)
    alice = a.acquire("alice")
    a.acquire("bob")
    assert a.assigned_slot("alice") is None, "alice must no longer hold a slot"
    # alice returning takes bob's slot, which is erased on the way
    assert a.acquire("alice") == alice


# --- fail-closed: the leak this module exists to prevent --------------------


def test_failed_erase_refuses_to_hand_over_the_slot() -> None:
    a, _ = _alloc(n_slots=1, fail_on={0})
    a.acquire("alice")
    with pytest.raises(SlotEraseFailed, match="may still hold"):
        a.acquire("bob")


def test_a_slot_whose_erase_failed_is_never_handed_out_later() -> None:
    """The bug this test exists for: quarantine vs free.

    On a failed erase it is tempting to return the slot to the free list. But
    slots come off the free list WITHOUT being erased — that is what makes the
    free list fast — so freeing an uncleared slot leaks the previous user's
    cache to whoever takes it next. It must be quarantined instead.
    """
    a, eraser = _alloc(n_slots=1, fail_on={0})
    a.acquire("alice")
    with pytest.raises(SlotEraseFailed):
        a.acquire("bob")
    # Bob retries. He must NOT now silently receive alice's uncleared slot.
    with pytest.raises(SlotEraseFailed):
        a.acquire("bob")
    assert eraser.erased == [], "no erase ever succeeded, so no hand-over may have happened"


def test_quarantined_slot_returns_to_service_once_erase_succeeds() -> None:
    """Fail-closed must not mean fail-forever: a transient upstream error
    should cost availability, not the slot."""
    a, eraser = _alloc(n_slots=1, fail_on={0})
    a.acquire("alice")
    with pytest.raises(SlotEraseFailed):
        a.acquire("bob")
    eraser.fail_on = set()  # upstream recovers
    assert a.acquire("bob") == 0
    assert eraser.erased == [0], "the slot must be erased on the way back into service"


def test_all_slots_quarantined_refuses_rather_than_serving_dirty() -> None:
    a, _ = _alloc(n_slots=1, fail_on={0})
    a.acquire("alice")
    with pytest.raises(SlotEraseFailed):
        a.acquire("bob")
    with pytest.raises(SlotEraseFailed, match="quarantined"):
        a.acquire("dave")


# --- release -----------------------------------------------------------------


def test_release_erases_so_a_departing_user_leaves_nothing_behind() -> None:
    a, eraser = _alloc(n_slots=2)
    slot = a.acquire("alice")
    a.release("alice")
    assert eraser.erased == [slot]
    assert a.assigned_slot("alice") is None


def test_release_of_an_unknown_user_is_a_no_op() -> None:
    a, eraser = _alloc()
    a.release("nobody")
    assert eraser.erased == []


def test_failed_release_quarantines_rather_than_freeing() -> None:
    a, _ = _alloc(n_slots=1, fail_on={0})
    a.acquire("alice")
    with pytest.raises(SlotEraseFailed):
        a.release("alice")
    # The slot must not have silently rejoined the free pool.
    with pytest.raises(SlotEraseFailed):
        a.acquire("bob")


# --- concurrency -------------------------------------------------------------


def test_two_users_never_share_a_slot_under_concurrent_acquire() -> None:
    """Racing for the last free slot and both winning is the leak with extra
    steps, so assignment is locked."""
    a, _ = _alloc(n_slots=8)
    results: dict[str, int] = {}
    lock = threading.Lock()

    def grab(name: str) -> None:
        slot = a.acquire(name)
        with lock:
            results[name] = slot

    threads = [threading.Thread(target=grab, args=(f"user{i}",)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(set(results.values())) == 8, f"slots were double-assigned: {results}"


def test_n_slots_must_be_positive() -> None:
    with pytest.raises(ValueError):
        SlotAllocator(n_slots=0, eraser=FakeEraser(), port=39000)


# --- the flag that makes erase work at all ----------------------------------


def _build_args(**kw: object) -> list[str]:
    from pathlib import Path

    from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
    from kuroshio.supervisor.supervisor import LoadConfig, Supervisor

    class _NullRunner:
        def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> object:
            raise AssertionError("not spawned")

    sha = "a" * 64
    model = ResolvedModel(
        sha256=sha,
        blob_path=Path(f"/blobs/{sha}.gguf"),
        metadata={"name": "m"},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="x", sha256=sha),
    )
    sup = Supervisor(process_runner=_NullRunner(), llama_server_binary="llama-server")
    return sup.build_args(model, LoadConfig(**kw), 39000)  # type: ignore[arg-type]


def test_slot_save_path_is_not_emitted_by_default() -> None:
    """It unlocks save/restore on /slots — a cross-user KV transfer primitive
    (YSG-RISK-315) — so it is opt-in with the per-user cache, never a default."""
    assert "--slot-save-path" not in _build_args(per_user_context=8192)


def test_slot_save_path_is_emitted_when_the_per_user_cache_needs_it() -> None:
    """Without this flag `action=erase` answers 501 (measured), so the allocator
    could not clear a slot before recycling it between users."""
    args = _build_args(per_user_context=8192, slot_save_path="/var/lib/kuroshio/slots")
    assert args[args.index("--slot-save-path") + 1] == "/var/lib/kuroshio/slots"
