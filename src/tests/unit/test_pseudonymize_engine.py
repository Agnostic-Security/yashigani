"""
Host-side PSEUDONYMIZE engine tests (plan §5.3, red-team F2/F3/F5).

Covers the crown-jewel machinery that NEVER enters the jail:
  - TokenAssigner consistency/coherence (same value -> same token; type-tagged);
  - ReplacerMap (F5): unguessable handle, AES-256-GCM encryption, TTL fail-close,
    handle-mismatch rejection, and the map NEVER appearing in a serialised form;
  - CorrespondenceTable + local_remerge (mode A, §5.3.1);
  - PositionBinder (mode B, F3): egress-count binding + over-restore fail-closed.
"""
from __future__ import annotations

import pytest

from yashigani.documents.pseudonymize import (
    CorrespondenceTable,
    PositionBinder,
    ReplacerMap,
    ReplacerMapExpiredError,
    TokenAssigner,
    build_pseudonymize_plan,
    build_redact_plan,
    local_remerge,
)
from yashigani.documents.datamatch import DataMatch
from yashigani.documents.transform import SpanAction


# ---------------------------------------------------------------------------
# TokenAssigner — consistency, coherence, type-tagging (§5.3a, F2).
# ---------------------------------------------------------------------------

def test_same_value_same_token_distinct_values_distinct():
    a = TokenAssigner()
    t1 = a.token_for("Alice Smith", "PII.PERSON")
    t2 = a.token_for("Alice Smith", "PII.PERSON")   # repeat → same token
    t3 = a.token_for("Bob Jones", "PII.PERSON")     # distinct → distinct token
    assert t1 == t2
    assert t1 != t3
    assert t1 == "[PERSON_1]" and t3 == "[PERSON_2]"


def test_tokens_are_type_tagged_per_class():
    a = TokenAssigner()
    assert a.token_for("x@y.com", "PII.EMAIL") == "[EMAIL_1]"
    assert a.token_for("GB29NWBK", "PII.IBAN") == "[IBAN_1]"
    # Long class names normalise to short tags.
    assert a.token_for("4111111111111111", "PII.CREDIT_CARD") == "[CARD_1]"
    assert a.token_for("1990-01-01", "PII.DATE_OF_BIRTH") == "[DOB_1]"


def test_reverse_map_is_a_copy_not_a_live_ref():
    a = TokenAssigner()
    a.token_for("secret", "PII.EMAIL")
    m = a.reverse_map
    m["[EMAIL_1]"] = "tampered"
    assert a.reverse_map["[EMAIL_1]"] == "secret"


# ---------------------------------------------------------------------------
# ReplacerMap — F5 crown-jewel custody.
# ---------------------------------------------------------------------------

def _map_with(reverse: dict, **kw) -> ReplacerMap:
    return ReplacerMap.create(reverse, detokenize_rbac_role="reverser", **kw)


def test_handle_is_unguessable_and_not_request_id():
    m1 = _map_with({"[PERSON_1]": "Alice"})
    m2 = _map_with({"[PERSON_1]": "Alice"})
    # Two maps over identical content get DIFFERENT high-entropy handles.
    assert m1.handle != m2.handle
    assert len(m1.handle) >= 40  # token_urlsafe(32) ~ 43 chars
    # Definitely not a request-id shaped value.
    assert "req" not in m1.handle.lower()


def test_reveal_requires_exact_handle():
    m = _map_with({"[PERSON_1]": "Alice"})
    assert m.reveal(m.handle) == {"[PERSON_1]": "Alice"}
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal("wrong-handle")


def test_ttl_expiry_fails_closed():
    # now-injection: created at t=0, ttl=10, reveal at t=15 → expired.
    m = ReplacerMap.create(
        {"[PERSON_1]": "Alice"}, detokenize_rbac_role="reverser", ttl_s=10, now=0.0,
    )
    assert m.reveal(m.handle, now=5.0) == {"[PERSON_1]": "Alice"}
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, now=15.0)


def test_destroy_fails_closed_and_zeroes():
    m = _map_with({"[PERSON_1]": "Alice"})
    m.destroy()
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle)


def test_map_plaintext_never_in_object_repr():
    # F5/F12: the cleartext original must not be reconstructable from the at-rest
    # object state (only ciphertext + nonce are held). repr() must not leak it.
    m = _map_with({"[PERSON_1]": "Alice-Cleartext-Secret"})
    blob = repr(m) + str(m.__dict__.get("_ciphertext", b""))
    assert "Alice-Cleartext-Secret" not in repr(m)
    # The ciphertext bytes must not contain the plaintext.
    assert b"Alice-Cleartext-Secret" not in m._ciphertext


# ---------------------------------------------------------------------------
# Mode A — correspondence table + local re-merge (§5.3.1).
# ---------------------------------------------------------------------------

def test_correspondence_table_and_local_remerge():
    a = TokenAssigner()
    a.token_for("Alice", "PII.PERSON")
    a.token_for("Bob", "PII.PERSON")
    table = CorrespondenceTable.from_assigner(a, detokenize_rbac_role="reverser")
    assert table.rows == {"[PERSON_1]": "Alice", "[PERSON_2]": "Bob"}

    tokenized = "Email [PERSON_1] and [PERSON_2]; cc [PERSON_1]."
    restored = local_remerge(tokenized, table.rows)
    assert restored == "Email Alice and Bob; cc Alice."


def test_local_remerge_longest_token_first():
    # [PERSON_10] must not be partially matched by [PERSON_1].
    table = {"[PERSON_1]": "Alice", "[PERSON_10]": "Zoe"}
    out = local_remerge("[PERSON_10] and [PERSON_1]", table)
    assert out == "Zoe and Alice"


# ---------------------------------------------------------------------------
# Mode B — position/count binding (F3).
# ---------------------------------------------------------------------------

def test_position_binder_count_bound_restore():
    b = PositionBinder()
    b.record_egress("[PERSON_1]", "Alice", count=1)
    # Legit response references the token once → restored.
    out, over = b.restore("The CFO is [PERSON_1].")
    assert out == "The CFO is Alice." and over == []


def test_position_binder_over_restore_fails_closed():
    b = PositionBinder()
    b.record_egress("[PERSON_1]", "Alice", count=1)  # sent ONCE
    # Attacker echoes it 3× to exfil → only 1 restored, token flagged over-restore.
    out, over = b.restore("[PERSON_1] [PERSON_1] [PERSON_1]")
    assert over == ["[PERSON_1]"]
    assert out.count("Alice") == 1  # capped at egress count
    assert out.count("[PERSON_1]") == 2  # surplus left as tokens (not leaked)


def test_position_binder_unknown_token_left_as_is():
    b = PositionBinder()
    b.record_egress("[PERSON_1]", "Alice", count=1)
    out, over = b.restore("hallucinated [PERSON_99]")
    assert "[PERSON_99]" in out  # unknown token never guessed (§5.4)
    assert over == []


# ---------------------------------------------------------------------------
# L-02 — position/provenance binding defeats the namespace-dump attack.
# ---------------------------------------------------------------------------

def _egress_directory(b: PositionBinder, names: list[str]) -> str:
    """Tokenize a benign source sentence and record each token bound to the
    egress CONTEXT it was emitted in (what the pipeline does on egress).
    Returns the FINAL tokenized payload that legitimately left the gateway."""
    # A plausible benign egress: a narrative the user actually asked about.
    egress = "Onboarding notes: " + ", ".join(
        f"{n} joined the team" for n in names
    )
    tokenized = egress
    for i, name in enumerate(names, 1):
        tokenized = tokenized.replace(name, f"[PERSON_{i}]")
    # Record each token against the FINAL egress payload (its true egress
    # context — every other name is also tokenized by the time it ships). The
    # no-span call form records every occurrence in egress_text as valid.
    for i, name in enumerate(names, 1):
        b.record_egress(f"[PERSON_{i}]", name, count=1, egress_text=tokenized)
    return tokenized


def test_position_binder_blocks_namespace_dump_attack():
    """Laura's PROVEN L-02 attack: a malicious cloud response replays each in-map
    token EXACTLY ONCE (within the count budget) in an attacker-framed sentence
    to reconstruct the whole real-value set. Position binding must reject every
    replay because none lands in the egress context the token was issued in."""
    # 20 distinct, non-prefix-colliding names (the demo worst case).
    names = [f"Employee-{chr(64 + i)}{i:02d}" for i in range(1, 21)]
    b = PositionBinder()
    _egress_directory(b, names)

    # The attacker, having learned the [PERSON_1..20] namespace, replays each
    # token once in a sentence the user never asked for.
    attack = "Full staff directory: " + " ".join(
        f"[PERSON_{i}]" for i in range(1, 21)
    )
    restored, flags = b.restore(attack)

    # NOT A SINGLE real name is restored into the attacker sentence.
    for name in names:
        assert name not in restored, f"namespace dump leaked {name!r}"
    # Every replayed token is left as a token and flagged as a foreign-position
    # rejection (the round-trip fails closed in the pipeline).
    assert flags, "foreign-position replays must be flagged, not silently dropped"
    assert all(f"[PERSON_{i}]" in restored for i in range(1, 21))


def test_position_binder_restores_at_consistent_position():
    """The legitimate round-trip: the model echoes a token in the SAME context it
    was sent in → restored. (Position binding must not break the happy path.)"""
    names = ["Alice", "Bob", "Carol"]
    b = PositionBinder()
    tokenized = _egress_directory(b, names)
    # The model returns the egress payload essentially unchanged (it reasoned
    # over it and handed it back in the same frame).
    restored, flags = b.restore(tokenized)
    assert restored.count("Alice") == 1
    assert restored.count("Bob") == 1
    assert restored.count("Carol") == 1
    assert flags == []


def test_position_binder_rejects_moved_token_even_within_count():
    """A single token sent once, replayed once but in a DIFFERENT position, is
    refused — the count budget alone would have allowed it (L-02 core)."""
    b = PositionBinder()
    egress = "The new hire is Dana, starting Monday."
    idx = egress.find("Dana")
    tokenized = egress[:idx] + "[PERSON_1]" + egress[idx + len("Dana"):]
    b.record_egress("[PERSON_1]", "Dana", count=1,
                    egress_text=tokenized, span=(idx, idx + len("[PERSON_1]")))

    # Same token, within count budget, but in an attacker exfil frame.
    attack = "EXFIL TARGET ACQUIRED: [PERSON_1] is the CEO."
    restored, flags = b.restore(attack)
    assert "Dana" not in restored
    assert "[PERSON_1]" in restored
    assert flags == ["[PERSON_1]"]


# ---------------------------------------------------------------------------
# Plan builders — DataMatch -> RenderPlan.
# ---------------------------------------------------------------------------

def _match(loc: str, cls: str = "PII.EMAIL") -> DataMatch:
    return DataMatch(data_class=cls, qi=False, instance="ma****ed",
                     location=loc, char_start=0, char_end=5)


def test_build_redact_plan_strips_segment_location_and_span():
    m = _match("EMAIL:row=1,col=2:span=0-5")
    plan = build_redact_plan([m], {m.location: "a@b.com"})
    assert len(plan.spans) == 1
    s = plan.spans[0]
    assert s.segment_location == "row=1,col=2"  # kind + span stripped
    assert s.original == "a@b.com"
    assert s.action == SpanAction.REDACT
    assert plan.strip_hidden_and_metadata is True


def test_build_pseudonymize_plan_assigns_consistent_tokens():
    m1 = _match("EMAIL:row=1,col=2:span=0-5")
    m2 = _match("EMAIL:row=2,col=2:span=0-5")
    a = TokenAssigner()
    plan = build_pseudonymize_plan(
        [m1, m2], {m1.location: "a@b.com", m2.location: "a@b.com"}, a,
    )
    # Same original in two cells → same token (coherence).
    assert plan.spans[0].token == plan.spans[1].token == "[EMAIL_1]"
    assert a.reverse_map == {"[EMAIL_1]": "a@b.com"}
