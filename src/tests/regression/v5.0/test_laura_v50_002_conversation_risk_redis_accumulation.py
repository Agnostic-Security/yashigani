"""
Regression test — LAURA-V50-002 companion: proves the multi-turn
conversation-risk accumulator actually ACCUMULATES across observe() calls
when backed by a reachable Redis, using fakeredis as an in-memory
redis-protocol-compatible stand-in for a live TLS Redis.

What this test proves:
  - With a working Redis client, ConversationRiskTracker.observe() persists
    state via _save()/_load() (yashigani:convrisk:<session> key) and a
    sustained slow-burn sequence escalates to ACTION_BLOCK within the same
    handful of turns as the in-memory (no-Redis) path — i.e. the store being
    reachable does not change tracker semantics, it just makes them durable
    and shared across replicas (the whole point of the Redis-backed mode).
  - Two independent ConversationRiskTracker instances sharing the SAME
    fakeredis client (simulating two gateway replicas behind a load
    balancer) see the SAME accumulated state — proving cross-replica sharing
    actually works when the connection is reachable.

What this test does NOT prove (explicitly out of scope / unverified here):
  - TLS negotiation itself — fakeredis is a plaintext in-memory server; it
    proves the ConversationRiskTracker <-> redis-client CONTRACT works
    correctly when the client is reachable, not that rediss:// TLS
    handshake + client-cert auth succeeds against the real Redis container.
    That requires the live/mocked TLS stack (see LAURA-V50-002 report,
    "verified/unverified split").
  - The exact production redis-py client object constructed by
    _gw_redis_url(1) in entrypoint.py (see
    test_laura_v50_002_redis_tls_urls.py for that — pure URL-construction
    proof via build_redis_url()).

Before the fix, the equivalent live reproduction (8 consecutive role-shift
turns, same session) never escalated because _r.get()/_r.set() threw
ConnectionRefusedError on every call (unreachable Redis), silently falling
back to a FRESH accumulator every single request (see LAURA-V50-002 report,
"Multi-turn conversation-risk accumulator" repro section).
"""
from __future__ import annotations

import pytest

fakeredis = pytest.importorskip("fakeredis")

from yashigani.inspection.conversation_risk import (
    ACTION_ALLOW,
    ACTION_BLOCK,
    ConversationRiskTracker,
    TurnSignals,
)


def _attack_turn():
    return TurnSignals(mechanical_soft=0.6, llm_suspicion=0.7,
                        instruction_shaped=True, role_shift=True)


def _benign_turn():
    return TurnSignals()


class TestRedisBackedAccumulationWorks:
    def test_sustained_attack_escalates_with_working_redis(self):
        r = fakeredis.FakeRedis()
        tracker = ConversationRiskTracker(redis_client=r)
        actions = [tracker.observe("session-a", _attack_turn()).action
                   for _ in range(8)]
        assert ACTION_BLOCK in actions, (
            "8 sustained attack turns against a REACHABLE Redis-backed "
            "tracker never escalated to BLOCK — accumulation is broken "
            "even with a working connection"
        )

    def test_benign_conversation_never_escalates_with_working_redis(self):
        r = fakeredis.FakeRedis()
        tracker = ConversationRiskTracker(redis_client=r)
        actions = [tracker.observe("session-b", _benign_turn()).action
                   for _ in range(8)]
        assert all(a == ACTION_ALLOW for a in actions)

    def test_state_is_actually_written_to_redis_not_silently_dropped(self):
        r = fakeredis.FakeRedis()
        tracker = ConversationRiskTracker(redis_client=r)
        tracker.observe("session-c", _attack_turn())
        key = tracker._REDIS_PREFIX + "session-c"
        assert r.exists(key), (
            "observe() did not persist accumulator state to Redis — the "
            "exact silent-reset failure mode LAURA-V50-002 describes"
        )

    def test_score_survives_across_independent_tracker_instances(self):
        """Simulates two gateway replicas sharing one Redis: turn 1 lands on
        replica A's tracker instance, turn 2 on replica B's — the score must
        still accumulate, not reset, because both share the same store."""
        r = fakeredis.FakeRedis()
        tracker_replica_a = ConversationRiskTracker(redis_client=r)
        tracker_replica_b = ConversationRiskTracker(redis_client=r)

        v1 = tracker_replica_a.observe("session-d", _attack_turn())
        v2 = tracker_replica_b.observe("session-d", _attack_turn())

        assert v2.turn_count == 2, (
            "turn count did not accumulate across independent tracker "
            "instances sharing the same Redis client — cross-replica "
            "sharing is broken"
        )
        assert v2.accumulated_score > v1.accumulated_score, (
            "score did not grow across replicas sharing the same session — "
            "state was reset instead of accumulated"
        )

    def test_reset_clears_shared_state(self):
        r = fakeredis.FakeRedis()
        tracker = ConversationRiskTracker(redis_client=r)
        tracker.observe("session-e", _attack_turn())
        tracker.reset("session-e")
        assert tracker.score_for("session-e") == 0.0
