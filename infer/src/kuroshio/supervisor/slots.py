# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Per-user KV slot assignment — the C1 `id_slot` leg (YSG-RISK-313).

Tiago 2026-09-15: "cache is per user".

The 5.0 design records C1 session-isolation as three controls and marks
per-tenant `id_slot` as wired. It was not: the identifier appeared nowhere in
the tree. Isolation rested entirely on `cache_prompt=false`, which closes the
prefix-reuse channel by never reusing anything — correct, but it buys isolation
by throwing the cache away, and it is a single boolean whose flip leaks across
users with every test still green (YSG-RISK-314).

This is the missing leg. It makes the cache per-user rather than absent:

  - each user is pinned to one llama-server slot (`id_slot`), so prefix reuse
    can only ever hit that user's own history;
  - when a slot is recycled from one user to another it is ERASED first, so the
    incoming user cannot hit the outgoing user's cached prefix.

Mechanism measured against the pinned Metal build, not assumed:

  - `id_slot` targeting is honoured: requested slot 1 -> served by slot 1,
    slot 2 -> slot 2.
  - `POST /slots/{id}?action=erase` -> **501** without `--slot-save-path`,
    **200** with it.
  - erase genuinely drops the prefix: same prompt, same slot, `prompt_n=8`
    (full reprocess) after erase versus `prompt_n=1` (cache hit) without.
  - `/slots` does not expose prompt text in this build — only `id` and
    `is_processing`.

The catch, and why `--slot-save-path` is not simply switched on: that one flag
also unlocks `save` and `restore` on the same endpoint, which together are a
cross-user KV transfer primitive. Our shim does not proxy `/slots`, and the
`/v1/{path:path}` traversal that could have reached it is now closed
(YSG-RISK-315) — that fix landed before this module, deliberately.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Protocol


class SlotEraseFailed(RuntimeError):
    """Raised when a slot could not be cleared before being handed to a new user.

    This is always fail-closed. If we cannot prove the outgoing user's KV is
    gone, the incoming user does not get the slot — serving anyway would hand
    them a cache primed with someone else's prompts, which is the exact leak
    this module exists to prevent.
    """


class SlotEraser(Protocol):
    """Clears one slot's KV cache. Injectable so tests need no live server."""

    def erase(self, port: int, slot: int) -> None: ...


class SlotAllocator:
    """Assigns llama-server slots to users, one user per slot.

    Slots are a fixed resource (`--parallel N`), so with more users than slots
    they must be recycled. Recycling is the dangerous moment and the reason
    this class exists rather than a bare dict: the slot is erased on the way
    out, before the next user touches it.

    Least-recently-used is the eviction order, so the user most likely to still
    benefit from their warm prefix keeps it.
    """

    def __init__(self, *, n_slots: int, eraser: SlotEraser, port: int) -> None:
        if n_slots < 1:
            raise ValueError(f"n_slots must be >= 1, got {n_slots}")
        self._n_slots = n_slots
        self._eraser = eraser
        self._port = port
        # user_id -> slot, in least-recently-used-first order
        self._assigned: OrderedDict[str, int] = OrderedDict()
        # INVARIANT: every slot in `_free` is safe to hand to any user — it has
        # either never been used or has been successfully erased. Nothing enters
        # this list on a failed erase.
        self._free: list[int] = list(range(n_slots))
        # Slots whose erase failed. They hold unknown KV state, so they are NOT
        # free; they are retried before any eviction and only rejoin `_free`
        # once an erase actually succeeds. Quarantining rather than freeing is
        # the difference between degraded capacity and a cross-user leak.
        self._quarantined: list[int] = []
        # Assignment must be atomic: two concurrent requests from different
        # users racing for the last free slot could otherwise both be handed
        # it, which is the leak with extra steps.
        self._lock = threading.Lock()

    @property
    def n_slots(self) -> int:
        return self._n_slots

    def acquire(self, user_id: str) -> int:
        """Return this user's slot, allocating or recycling one if needed.

        Raises `SlotEraseFailed` if a recycled slot could not be cleared.
        """
        if not user_id or not user_id.strip():
            # An empty identity would collapse every anonymous caller onto one
            # shared slot, i.e. exactly the shared-cache posture this replaces.
            raise ValueError("user_id must be a non-empty identity")

        with self._lock:
            existing = self._assigned.get(user_id)
            if existing is not None:
                self._assigned.move_to_end(user_id)
                return existing

            if self._free:
                slot = self._free.pop(0)
                self._assigned[user_id] = slot
                return slot

            # Before evicting anyone, try to recover a quarantined slot — a
            # transient erase failure should not cost a user their slot.
            for slot in list(self._quarantined):
                try:
                    self._eraser.erase(self._port, slot)
                except Exception:
                    continue
                self._quarantined.remove(slot)
                self._assigned[user_id] = slot
                return slot

            if not self._assigned:
                # Every slot is quarantined and none could be cleared.
                raise SlotEraseFailed(
                    f"no slot can be given to {user_id!r}: all {self._n_slots} are "
                    "quarantined after failed erases and none could be cleared. "
                    "Refusing to serve from a slot that may hold another user's KV cache."
                )

            # Recycle the least-recently-used user's slot.
            evicted_user, slot = self._assigned.popitem(last=False)
            try:
                self._eraser.erase(self._port, slot)
            except Exception as exc:
                # Fail closed. The slot does NOT go back to `_free` — a slot in
                # `_free` is handed out without erasing, so freeing it here
                # would leak the evicted user's cache to whoever takes it next.
                self._quarantined.append(slot)
                raise SlotEraseFailed(
                    f"could not clear slot {slot} when recycling it from user "
                    f"{evicted_user!r} to {user_id!r}: {exc}. Refusing to hand over a "
                    "slot that may still hold the previous user's KV cache; it is "
                    "quarantined until an erase succeeds."
                ) from exc
            self._assigned[user_id] = slot
            return slot

    def release(self, user_id: str) -> None:
        """Give up a user's slot, erasing it first.

        Used on logout/session end so a departing user's prefix does not sit in
        the cache waiting for whoever gets the slot next.
        """
        with self._lock:
            slot = self._assigned.pop(user_id, None)
            if slot is None:
                return
            try:
                self._eraser.erase(self._port, slot)
            except Exception as exc:
                # Same invariant as acquire(): an uncleared slot must never
                # reach `_free`, because `_free` is handed out without erasing.
                self._quarantined.append(slot)
                raise SlotEraseFailed(
                    f"could not clear slot {slot} on release by {user_id!r}: {exc}. "
                    "Quarantined until an erase succeeds."
                ) from exc
            self._free.append(slot)

    def assigned_slot(self, user_id: str) -> int | None:
        with self._lock:
            return self._assigned.get(user_id)
