"""
Host-side PSEUDONYMIZE engine tests (plan §5.3, opaque token scheme DECIDED 2026-06-10).

Covers the crown-jewel machinery that NEVER enters the jail:
  - OpaqueTokenAssigner: opaque, per-file-salted, value-keyed tokens — same value
    -> same token WITHIN a doc (coherence); same value in two docs -> DIFFERENT
    tokens (per-file uniqueness); tokens leak NO class / count (Laura's finding);
  - ReplacerMap (F5): unguessable handle, AES-256-GCM encryption, TTL fail-close,
    handle-mismatch rejection, and the map NEVER appearing in a serialised form;
  - CorrespondenceTable + local_remerge (mode A, §5.3.1) + doc_hash header;
  - PositionBinder (mode B, F3/L-02): egress-count + position binding, echo guard.
"""
from __future__ import annotations

import re

import pytest

from yashigani.documents.pseudonymize import (
    CorrespondenceTable,
    EchoEgressError,
    OpaqueTokenAssigner,
    PositionBinder,
    ReplacerMap,
    ReplacerMapExpiredError,
    ReplacerMapIdentityError,
    TokenAssigner,
    build_pseudonymize_plan,
    build_redact_plan,
    is_pseudonymization_token,
    local_remerge,
)
from yashigani.documents.datamatch import DataMatch
from yashigani.documents.token_scheme import (
    TOKEN_CHARS,
    compute_doc_hash,
    derive_token,
    token_matches_doc,
)
from yashigani.documents.transform import SpanAction


# A fixed per-file salt for deterministic tests (a SHA-256 hex of some bytes).
_SALT_A = compute_doc_hash(b"document-A-original-bytes")
_SALT_B = compute_doc_hash(b"document-B-original-bytes")
_SECRET = b"deployment-secret-0123456789abcdef"
_OPAQUE_RE = re.compile(rf"^[a-z2-7]{{{TOKEN_CHARS}}}$")


def _assigner(salt: str = _SALT_A, secret: bytes | None = _SECRET) -> OpaqueTokenAssigner:
    return OpaqueTokenAssigner(salt, secret=secret)


# ---------------------------------------------------------------------------
# OpaqueTokenAssigner — opacity, coherence, per-file uniqueness (DECIDED 2026-06-10).
# ---------------------------------------------------------------------------

def test_token_is_opaque_no_class_or_count_leak():
    """Laura's finding: the token must reveal neither the data class nor a count.
    Opaque token = 12 lowercase base32 chars, no [TAG_N] structure."""
    a = _assigner()
    t_email = a.token_for("x@y.com", "PII.EMAIL")
    t_person = a.token_for("Alice Smith", "PII.PERSON_NAME")
    t_card = a.token_for("4111111111111111", "PII.CREDIT_CARD")
    for t in (t_email, t_person, t_card):
        assert _OPAQUE_RE.match(t), f"token {t!r} is not opaque base32"
        # No class tag, no counter, no brackets.
        assert "[" not in t and "_" not in t and "EMAIL" not in t.upper()
    # The three tokens for different values/classes are unrelated strings.
    assert len({t_email, t_person, t_card}) == 3


def test_same_value_same_token_within_doc_distinct_values_distinct():
    """Coherence (§5.3a): same value -> same token in the SAME doc; distinct -> distinct."""
    a = _assigner()
    t1 = a.token_for("Alice Smith", "PII.PERSON_NAME")
    t2 = a.token_for("Alice Smith", "PII.PERSON_NAME")  # repeat → same token
    t3 = a.token_for("Bob Jones", "PII.PERSON_NAME")    # distinct → distinct token
    assert t1 == t2
    assert t1 != t3


def test_same_value_two_docs_different_tokens():
    """Per-file uniqueness: the SAME value in two documents (different salts)
    derives DIFFERENT tokens — defeats cross-file correlation / dictionary."""
    a = _assigner(salt=_SALT_A)
    b = _assigner(salt=_SALT_B)
    ta = a.token_for("alice@corp.com", "PII.EMAIL")
    tb = b.token_for("alice@corp.com", "PII.EMAIL")
    assert ta != tb, "same value in two docs must derive different tokens"


def test_token_is_deterministic_for_same_salt_value_secret():
    """Stable derivation on retry (same doc tokenizes identically)."""
    a1 = _assigner()
    a2 = _assigner()
    assert a1.token_for("alice@corp.com", "PII.EMAIL") == a2.token_for(
        "alice@corp.com", "PII.EMAIL"
    )


def test_keyed_tokens_are_per_file_unique_and_opaque():
    """Mandatory deployment secret (DP-Y-002 §3.1): tokens are opaque +
    per-file-unique — different salts → different tokens for the same value."""
    a = OpaqueTokenAssigner(_SALT_A, secret=_SECRET)
    b = OpaqueTokenAssigner(_SALT_B, secret=_SECRET)
    ta = a.token_for("alice@corp.com", "PII.EMAIL")
    tb = b.token_for("alice@corp.com", "PII.EMAIL")
    assert _OPAQUE_RE.match(ta)
    assert ta != tb  # per-file unique: different salts → different tokens


def test_secret_changes_token_unlinkability_across_deployments():
    """Different deployment secrets over the same salt+value → different tokens
    (cross-deployment unlinkability the keyed form adds over salt-only)."""
    a = OpaqueTokenAssigner(_SALT_A, secret=b"secret-one")
    b = OpaqueTokenAssigner(_SALT_A, secret=b"secret-two")
    assert a.token_for("v", "PII.EMAIL") != b.token_for("v", "PII.EMAIL")


def test_reverse_map_is_a_copy_not_a_live_ref():
    a = _assigner()
    tok = a.token_for("secret", "PII.EMAIL")
    m = a.reverse_map
    m[tok] = "tampered"
    assert a.reverse_map[tok] == "secret"


def test_is_pseudonymization_token_matches_opaque_shape():
    a = _assigner()
    tok = a.token_for("Alice", "PII.PERSON_NAME")
    assert is_pseudonymization_token(tok)
    assert not is_pseudonymization_token("Alice Smith")
    assert not is_pseudonymization_token("[PERSON_1]")  # old shape is NOT ours now


def test_backcompat_alias_resolves_to_opaque():
    assert TokenAssigner is OpaqueTokenAssigner


# ---------------------------------------------------------------------------
# token_scheme primitives — derivation + integrity.
# ---------------------------------------------------------------------------

def test_derive_token_length_and_alphabet():
    t = derive_token(_SALT_A, "value", secret=_SECRET)
    assert _OPAQUE_RE.match(t)


def test_token_matches_doc_accepts_own_salt_rejects_foreign():
    """Integrity / cross-file splice: a token derived under salt A validates under
    salt A but NOT under salt B (foreign-salt rejection)."""
    tok = derive_token(_SALT_A, "alice@corp.com", secret=_SECRET)
    assert token_matches_doc(tok, "alice@corp.com", _SALT_A, secret=_SECRET)
    assert not token_matches_doc(tok, "alice@corp.com", _SALT_B, secret=_SECRET)


# ---------------------------------------------------------------------------
# ReplacerMap — F5 crown-jewel custody.
# ---------------------------------------------------------------------------

#: Default identity+tenant binding for the crown-jewel custody tests (G-NEW-2).
_OWNER = "acct-alice"
_TENANT = "default"


def _map_with(reverse: dict, **kw) -> ReplacerMap:
    kw.setdefault("owner_identity", _OWNER)
    kw.setdefault("tenant", _TENANT)
    return ReplacerMap.create(reverse, detokenize_rbac_role="reverser", **kw)


def test_handle_is_unguessable_and_not_request_id():
    m1 = _map_with({"aaaaaaaaaaaa": "Alice"})
    m2 = _map_with({"aaaaaaaaaaaa": "Alice"})
    assert m1.handle != m2.handle
    assert len(m1.handle) >= 40  # token_urlsafe(32) ~ 43 chars
    assert "req" not in m1.handle.lower()


def test_reveal_requires_exact_handle():
    m = _map_with({"aaaaaaaaaaaa": "Alice"}, single_use=False)
    assert m.reveal(m.handle, identity=_OWNER, tenant=_TENANT) == {"aaaaaaaaaaaa": "Alice"}
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal("wrong-handle", identity=_OWNER, tenant=_TENANT)


def test_ttl_expiry_fails_closed():
    m = ReplacerMap.create(
        {"aaaaaaaaaaaa": "Alice"}, detokenize_rbac_role="reverser",
        owner_identity=_OWNER, tenant=_TENANT, single_use=False, ttl_s=10, now=0.0,
    )
    assert m.reveal(m.handle, identity=_OWNER, tenant=_TENANT, now=5.0) == {"aaaaaaaaaaaa": "Alice"}
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, identity=_OWNER, tenant=_TENANT, now=15.0)


def test_destroy_fails_closed_and_zeroes():
    m = _map_with({"aaaaaaaaaaaa": "Alice"})
    m.destroy()
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, identity=_OWNER, tenant=_TENANT)


def test_map_plaintext_never_in_object_repr():
    m = _map_with({"aaaaaaaaaaaa": "Alice-Cleartext-Secret"})
    assert "Alice-Cleartext-Secret" not in repr(m)
    assert b"Alice-Cleartext-Secret" not in m._ciphertext


# ---------------------------------------------------------------------------
# G-NEW-2 / R5 — identity + tenant binding (BOLA/IDOR close) + single-use.
# ---------------------------------------------------------------------------

def test_reveal_cross_identity_fails_closed():
    """A DIFFERENT principal holding the handle cannot reveal (BOLA close)."""
    m = _map_with({"aaaaaaaaaaaa": "Alice"}, single_use=False)
    # Correct identity+tenant reveals.
    assert m.reveal(m.handle, identity=_OWNER, tenant=_TENANT) == {"aaaaaaaaaaaa": "Alice"}
    # Another admin's identity — even with the right handle + tenant — fails closed.
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity="acct-mallory", tenant=_TENANT)


def test_reveal_cross_tenant_fails_closed():
    """A handle from tenant A is inert in tenant B (cross-tenant close)."""
    m = _map_with({"aaaaaaaaaaaa": "Alice"}, single_use=False)
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity=_OWNER, tenant="tenant-b")


def test_reveal_unbound_map_via_identity_path_fails_closed():
    """An UNBOUND map (no owner) is NOT retrievable through the identity path."""
    m = ReplacerMap.create(
        {"aaaaaaaaaaaa": "Alice"}, detokenize_rbac_role="reverser", single_use=False,
    )  # no owner_identity/tenant
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity=_OWNER, tenant=_TENANT)
    # The gateway-internal (mode-B) path reveals it.
    assert m.reveal_unbound(m.handle) == {"aaaaaaaaaaaa": "Alice"}


def test_reveal_unbound_refuses_identity_bound_map():
    """A bound map must NOT be revealable via the unbound (no-check) path."""
    m = _map_with({"aaaaaaaaaaaa": "Alice"})
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal_unbound(m.handle)


def test_single_use_burns_after_read():
    """Burn-after-read: a second reveal of a single-use map fails closed (replay)."""
    m = _map_with({"aaaaaaaaaaaa": "Alice"}, single_use=True)
    assert m.reveal(m.handle, identity=_OWNER, tenant=_TENANT) == {"aaaaaaaaaaaa": "Alice"}
    # Replay with the SAME (valid) handle + identity + tenant now fails closed.
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, identity=_OWNER, tenant=_TENANT)


def test_aad_binds_ciphertext_to_identity():
    """Identity+tenant are folded into the AEAD AAD: tampering the binding makes
    the crypto itself fail, not merely the application check (defence in depth)."""
    m = _map_with({"aaaaaaaaaaaa": "Alice"}, single_use=False)
    # Decrypt with a forged (wrong) AAD raises at the cryptography layer.
    from cryptography.exceptions import InvalidTag
    with pytest.raises(InvalidTag):
        m._decrypt(m.handle, "acct-mallory", _TENANT)


# ---------------------------------------------------------------------------
# Mode A — correspondence table (+ doc_hash header) + local re-merge (§5.3.1).
# ---------------------------------------------------------------------------

def test_correspondence_table_carries_doc_hash_and_local_remerge():
    a = _assigner()
    t_alice = a.token_for("Alice", "PII.PERSON_NAME")
    t_bob = a.token_for("Bob", "PII.PERSON_NAME")
    table = CorrespondenceTable.from_assigner(a, detokenize_rbac_role="reverser")
    assert table.doc_hash == _SALT_A
    assert table.rows == {t_alice: "Alice", t_bob: "Bob"}
    # The mapping-file CSV header binds the table to its source document.
    assert f"# doc_hash={_SALT_A}" in table.to_csv()

    tokenized = f"Email {t_alice} and {t_bob}; cc {t_alice}."
    restored = local_remerge(tokenized, table.rows)
    assert restored == "Email Alice and Bob; cc Alice."


# ---------------------------------------------------------------------------
# Mode B — position/count binding (F3/L-02) with OPAQUE tokens.
# ---------------------------------------------------------------------------

def _tok(name: str, salt: str = _SALT_A) -> str:
    return derive_token(salt, name, secret=_SECRET)


def test_position_binder_count_bound_restore():
    b = PositionBinder()
    tok = _tok("Alice")
    b.record_egress(tok, "Alice", count=1)
    out, over = b.restore(f"The CFO is {tok}.")
    assert out == "The CFO is Alice." and over == []


def test_position_binder_over_restore_fails_closed():
    b = PositionBinder()
    tok = _tok("Alice")
    b.record_egress(tok, "Alice", count=1)  # sent ONCE
    out, over = b.restore(f"{tok} {tok} {tok}")
    assert over == [tok]
    assert out.count("Alice") == 1
    assert out.count(tok) == 2  # surplus left as tokens (not leaked)


def test_position_binder_unknown_token_left_as_is():
    b = PositionBinder()
    b.record_egress(_tok("Alice"), "Alice", count=1)
    fake = "zzzzzzzzzzzz"  # opaque-shaped but never issued
    out, over = b.restore(f"hallucinated {fake}")
    assert fake in out  # unknown token never guessed (§5.4)
    assert over == []


def _egress_directory(b: PositionBinder, names: list[str]) -> tuple[str, dict[str, str]]:
    """Tokenize a benign source sentence with OPAQUE tokens and record each token
    bound to the egress CONTEXT it was emitted in.  Returns (tokenized, name->tok)."""
    name_to_tok = {n: _tok(n) for n in names}
    egress = "Onboarding notes: " + ", ".join(f"{n} joined the team" for n in names)
    tokenized = egress
    for n in names:
        tokenized = tokenized.replace(n, name_to_tok[n])
    for n in names:
        b.record_egress(name_to_tok[n], n, count=1, egress_text=tokenized)
    return tokenized, name_to_tok


def test_position_binder_blocks_namespace_dump_attack():
    """L-02: a malicious response replays each in-map token once in an attacker
    sentence — position binding rejects every replay (foreign context)."""
    names = [f"Employee-{chr(64 + i)}{i:02d}" for i in range(1, 21)]
    b = PositionBinder()
    _, name_to_tok = _egress_directory(b, names)
    attack = "Full staff directory: " + " ".join(name_to_tok[n] for n in names)
    restored, flags = b.restore(attack)
    for name in names:
        assert name not in restored, f"namespace dump leaked {name!r}"
    assert flags
    assert all(name_to_tok[n] in restored for n in names)


def test_position_binder_restores_at_consistent_position():
    names = ["Alice", "Bob", "Carol"]
    b = PositionBinder()
    tokenized, name_to_tok = _egress_directory(b, names)
    bob_tok = name_to_tok["Bob"]
    idx = tokenized.find(bob_tok)
    answer = tokenized[max(0, idx - 24): idx + len(bob_tok) + 24]
    restored, flags = b.restore(answer)
    assert restored.count("Bob") == 1
    assert "Alice" not in restored
    assert flags == []


def test_position_binder_rejects_verbatim_egress_echo():
    names = ["Alice", "Bob", "Carol", "Dave", "Erin"]
    b = PositionBinder()
    tokenized, _ = _egress_directory(b, names)
    b.record_egress_frame(tokenized)
    with pytest.raises(EchoEgressError):
        b.restore(tokenized)


def test_position_binder_echo_with_prose_wrapper_still_rejected():
    names = ["Alice", "Bob", "Carol", "Dave"]
    b = PositionBinder()
    tokenized, _ = _egress_directory(b, names)
    b.record_egress_frame(tokenized)
    crafted = "Sure, here is the document you sent:\n\n" + tokenized + "\n\nHope that helps!"
    with pytest.raises(EchoEgressError):
        b.restore(crafted)


def test_position_binder_bounded_restoration_caps_namespace_harvest():
    names = [f"Person{chr(64 + i)}" for i in range(1, 11)]
    b = PositionBinder()
    tokenized, _ = _egress_directory(b, names)
    restored, flags = b.restore(tokenized)
    restored_names = [n for n in names if n in restored]
    assert len(restored_names) <= 5, "bounded restoration cap exceeded"
    assert flags


def test_position_binder_genuine_small_answer_under_cap_unaffected():
    names = [f"Person{chr(64 + i)}" for i in range(1, 11)]
    b = PositionBinder()
    tokenized, name_to_tok = _egress_directory(b, names)
    btok = name_to_tok["PersonB"]
    idx = tokenized.find(btok)
    answer = tokenized[max(0, idx - 24): idx + len(btok) + 24]
    restored, flags = b.restore(answer)
    assert restored.count("PersonB") == 1
    assert flags == []


def test_position_binder_rejects_moved_token_even_within_count():
    b = PositionBinder()
    tok = _tok("Dana")
    egress = "The new hire is Dana, starting Monday."
    idx = egress.find("Dana")
    tokenized = egress[:idx] + tok + egress[idx + len("Dana"):]
    b.record_egress(tok, "Dana", count=1, egress_text=tokenized,
                    span=(idx, idx + len(tok)))
    attack = f"EXFIL TARGET ACQUIRED: {tok} is the CEO."
    restored, flags = b.restore(attack)
    assert "Dana" not in restored
    assert tok in restored
    assert flags == [tok]


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
    assert s.segment_location == "row=1,col=2"
    assert s.original == "a@b.com"
    assert s.action == SpanAction.REDACT
    assert plan.strip_hidden_and_metadata is True


def test_build_pseudonymize_plan_assigns_consistent_opaque_tokens():
    m1 = _match("EMAIL:row=1,col=2:span=0-5")
    m2 = _match("EMAIL:row=2,col=2:span=0-5")
    a = _assigner()
    plan = build_pseudonymize_plan(
        [m1, m2], {m1.location: "a@b.com", m2.location: "a@b.com"}, a,
    )
    # Same original in two cells → same opaque token (coherence).
    assert plan.spans[0].token == plan.spans[1].token
    assert _OPAQUE_RE.match(plan.spans[0].token)
    assert a.reverse_map == {plan.spans[0].token: "a@b.com"}
