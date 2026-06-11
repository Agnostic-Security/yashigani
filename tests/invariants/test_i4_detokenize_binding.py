"""
I4 — De-tokenize is identity+tenant-bound, single-use, and leak-free.

INVARIANT (must ALWAYS hold): reversing pseudonymisation (the crown-jewel read)
requires (a) the exact capability handle, AND (b) the SAME identity + tenant the
map was bound to at mint time; it is single-use (burn-after-read). A
cross-identity / cross-tenant / unbound presentation FAILS CLOSED, and the handle
/ plaintext secret is never returned on a denial.

Why an invariant: this is the BOLA/IDOR boundary on the reversible-tokenisation
feature. A leaked handle replayed by another principal, a role-downgraded caller,
or a cross-tenant caller must NOT reveal the originals. If this binding ever
weakens, pseudonymisation's "reversible only by the owner under step-up" claim
(Petra R5 / G-NEW-2) breaks.

Asserted here: the ``ReplacerMap`` reveal contract — round-trip succeeds only for
the bound identity+tenant; every mismatch raises a fail-closed error; burn-after-
read defeats replay; an unbound map is not retrievable via the identity-checked
path. (The route-level step-up TOTP + RBAC gate is covered in src/tests; this
locks the cryptographic binding primitive itself.)

LIVE-PROOF (#44): a live cross-principal / cross-tenant reveal probe over the wire
(present another principal's handle to /admin documents de-tokenize, expect deny)
is the VM item; here we prove the binding at the data structure.
"""
from __future__ import annotations

import pytest

from yashigani.documents.pseudonymize import (
    ReplacerMap,
    ReplacerMapExpiredError,
    ReplacerMapIdentityError,
)

OWNER = "alice@tenant-a"
TENANT = "tenant-a"
REVERSE = {"TOKEN_AAAA": "Jane Doe", "TOKEN_BBBB": "AC-12345"}


def _mint(**over) -> ReplacerMap:
    kw = dict(
        reverse_map=dict(REVERSE),
        detokenize_rbac_role="admin",
        owner_identity=OWNER,
        tenant=TENANT,
        single_use=True,
    )
    kw.update(over)
    return ReplacerMap.create(**kw)


def test_bound_owner_reveals_originals() -> None:
    """The bound identity+tenant with the right handle reveals the originals."""
    m = _mint()
    out = m.reveal(m.handle, identity=OWNER, tenant=TENANT)
    assert out == REVERSE


def test_cross_identity_reveal_denied() -> None:
    """Another principal presenting the (leaked) handle is denied fail-closed."""
    m = _mint()
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity="mallory@tenant-a", tenant=TENANT)


def test_cross_tenant_reveal_denied() -> None:
    """Same identity name, different tenant ⇒ denied (tenant isolation)."""
    m = _mint()
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity=OWNER, tenant="tenant-b")


def test_wrong_handle_denied_uniformly() -> None:
    """A wrong handle is rejected (uniform fail-closed error, no oracle)."""
    m = _mint()
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal("not-the-handle", identity=OWNER, tenant=TENANT)


def test_single_use_burn_after_read_defeats_replay() -> None:
    """A single-use map is destroyed on first successful reveal — a replay within
    the TTL fails closed."""
    m = _mint(single_use=True)
    assert m.reveal(m.handle, identity=OWNER, tenant=TENANT) == REVERSE
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, identity=OWNER, tenant=TENANT)


def test_unbound_map_not_retrievable_via_identity_path() -> None:
    """An UNBOUND (empty owner) map must NOT be revealable through the
    identity-checked path — closes the 'present empty identity' bypass."""
    m = _mint(owner_identity="", tenant="")
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal(m.handle, identity="", tenant="")


def test_identity_bound_map_refused_on_unbound_path() -> None:
    """The gateway-internal reveal_unbound refuses an identity-bound map (so a
    bound map can only be read through the identity-checked path)."""
    m = _mint()
    with pytest.raises(ReplacerMapIdentityError):
        m.reveal_unbound(m.handle)


def test_destroyed_map_fails_closed_and_leaks_nothing() -> None:
    """After destroy(), reveal fails closed and key material is zeroed (no
    plaintext / handle leak on a denied path)."""
    m = _mint()
    m.destroy()
    with pytest.raises(ReplacerMapExpiredError):
        m.reveal(m.handle, identity=OWNER, tenant=TENANT)
    # internal key/ciphertext zeroed — no residual secret on the object
    assert m._key == b""
    assert m._ciphertext == b""


def test_handle_is_high_entropy_not_request_id() -> None:
    """The capability handle is a fresh high-entropy secret (F5), not a guessable
    identifier — two mints never collide and the handle is long."""
    a, b = _mint(), _mint()
    assert a.handle != b.handle
    assert len(a.handle) >= 32
