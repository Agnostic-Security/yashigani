"""
Regression test -- v4.1.2 WebAuthn production 500 (conformance suite
finding, YCS-20260723-v4.1.2-CONFORMANCE bug 1).

Root cause (verified against the REAL installed py-webauthn, not a
hypothesis): `pyproject.toml` pinned `webauthn>=2.1` with no upper bound.
`auth/webauthn.py` and `auth/pg_webauthn.py` referenced
`webauthn.AuthenticatorSelectionCriteria`, `webauthn.UserVerificationRequirement`,
`webauthn.AttestationConveyancePreference`, `webauthn.RegistrationCredential`,
and `webauthn.AuthenticationCredential` at the TOP LEVEL of the `webauthn`
module, plus called the now-removed `RegistrationCredential.parse_raw()` /
`AuthenticationCredential.parse_raw()` classmethods.

GROUND-TRUTH CHECK (this session, scratchpad venvs, real PyPI, no private
index configured anywhere in this repo):
  - webauthn==2.7.1 (the version uv.lock actually resolves for the >=2.1
    pin) does NOT expose any of the five names above at top level -- they
    live under `webauthn.helpers.structs`.
  - webauthn==2.1.0 (the floor of the OLD pin) ALSO does not expose them.
  - No webauthn>=3.0.0 exists on PyPI as of this check (highest real release
    at time of writing: 2.8.0a1). The conformance suite's "resolves
    webauthn==3.0.0" narrative describes the *shape* of the break correctly
    (top-level attrs moved to helpers.structs) but the version number in the
    docstring does not match what this repo's unbounded pin actually
    resolves to. The break is real and reproducible RIGHT NOW at the locked
    2.7.1 -- not a future risk.
  - `RegistrationCredential`/`AuthenticationCredential` at 2.7.1 have no
    `parse_raw` classmethod at all (verified: `hasattr(RegistrationCredential,
    "parse_raw") is False`). `verify_registration_response()` /
    `verify_authentication_response()` instead accept `credential` as
    `Union[str, dict, RegistrationCredential]` directly, parsing internally.

FIX: ported auth/webauthn.py + auth/pg_webauthn.py to import the structs from
`webauthn.helpers.structs` and to pass credential_response dicts directly to
verify_registration_response()/verify_authentication_response() instead of
manually constructing (now-nonexistent) parsed objects. Pin tightened to
`webauthn>=2.1,<3` as a defence-in-depth ceiling (does not itself fix
anything -- the API port is the actual fix, proven below against the real
library with NO mocking of `_import_webauthn`).

These tests import and exercise the REAL py-webauthn package (no
`_import_webauthn` monkeypatch, unlike src/tests/unit/test_v233_webauthn_unit.py
which mocks the whole module and therefore could never have caught this).

Last updated: 2026-07-23T00:00:00+00:00
"""
from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Ground-truth: prove the installed library's actual shape (guards against
# this test suite itself going stale if the pin/lock changes again).
# ---------------------------------------------------------------------------


def test_top_level_webauthn_module_lacks_the_five_names():
    """Documents WHY the old code broke -- top-level access to these five
    names must fail on the currently locked/installed webauthn version."""
    import webauthn

    for name in (
        "AuthenticatorSelectionCriteria",
        "UserVerificationRequirement",
        "AttestationConveyancePreference",
        "RegistrationCredential",
        "AuthenticationCredential",
    ):
        assert not hasattr(webauthn, name), (
            f"webauthn.{name} now exists at top level -- if py-webauthn "
            "restored top-level re-exports, the ported code (which imports "
            "from webauthn.helpers.structs) still works since that path is "
            "unaffected either way, but this test's ground-truth premise "
            "should be re-verified."
        )


def test_helpers_structs_has_the_five_names():
    """The location the ported code now imports from."""
    from webauthn.helpers import structs

    for name in (
        "AuthenticatorSelectionCriteria",
        "UserVerificationRequirement",
        "AttestationConveyancePreference",
        "RegistrationCredential",
        "AuthenticationCredential",
    ):
        assert hasattr(structs, name)


def test_registration_credential_has_no_parse_raw_classmethod():
    """Documents WHY `.parse_raw()` calls raised AttributeError in prod."""
    from webauthn.helpers.structs import AuthenticationCredential, RegistrationCredential

    assert not hasattr(RegistrationCredential, "parse_raw")
    assert not hasattr(AuthenticationCredential, "parse_raw")


# ---------------------------------------------------------------------------
# The actual regression: begin_registration / begin_authentication against
# the REAL WebAuthnService (auth/webauthn.py) must not 500 / AttributeError.
# ---------------------------------------------------------------------------


class TestWebAuthnServiceRealLibraryNoServerError:
    """Exercises yashigani.auth.webauthn.WebAuthnService with the genuine
    py-webauthn package -- no mocking of `_import_webauthn`. This is the
    exact gap in src/tests/unit/test_v233_webauthn_unit.py, which mocks
    `_import_webauthn` and therefore never called real py-webauthn code."""

    def _service(self):
        from yashigani.auth.webauthn import WebAuthnConfig, WebAuthnService

        return WebAuthnService(WebAuthnConfig(rp_id="example.test"))

    def test_begin_registration_returns_valid_options_no_attributeerror(self):
        svc = self._service()
        options_json = svc.begin_registration(user_id="user-1", user_name="alice")
        # options_to_json returns a JSON string -- must parse and contain the
        # ceremony fields a browser needs.
        parsed = json.loads(options_json)
        assert "challenge" in parsed
        assert "rp" in parsed
        assert "authenticatorSelection" in parsed

    def test_begin_authentication_returns_valid_options_no_attributeerror(self):
        svc = self._service()
        options_json = svc.begin_authentication(user_id="user-1")
        parsed = json.loads(options_json)
        assert "challenge" in parsed

    def test_complete_registration_bad_assertion_raises_valueerror_not_attributeerror(self):
        """Before the fix, this call never reached verification logic at all --
        it AttributeError'd inside .parse_raw(). After the fix, a garbage
        assertion must fail cleanly with the wrapped ValueError (expected
        verification failure), never AttributeError (broken dependency)."""
        svc = self._service()
        svc.begin_registration(user_id="user-2", user_name="bob")  # issues challenge

        with pytest.raises(ValueError, match="WebAuthn registration verification failed"):
            svc.complete_registration(
                user_id="user-2",
                credential_response={
                    "id": "AAAA",
                    "rawId": "AAAA",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30=",
                        "attestationObject": "e30=",
                    },
                },
                expected_origin="https://example.test",
            )

    def test_complete_authentication_bad_assertion_raises_valueerror_not_attributeerror(self):
        """Same proof for the authentication ceremony. A credential is seeded
        directly into the in-memory store so the code path reaches
        verify_authentication_response() (past the "credential not found"
        early-return)."""
        from yashigani.auth.webauthn import WebAuthnCredential

        svc = self._service()
        svc.begin_authentication(user_id="user-3")  # issues challenge

        raw_credential_id = b"\x01\x02\x03\x04"
        svc._credential_store.add(
            WebAuthnCredential(
                id="cred-uuid-1",
                user_id="user-3",
                credential_id=raw_credential_id,
                public_key=b"\x00" * 32,
                sign_count=5,
                aaguid="00000000000000000000000000000000",
                name="Test Key",
            )
        )

        import base64

        raw_id_b64 = base64.urlsafe_b64encode(raw_credential_id).decode().rstrip("=")

        with pytest.raises(ValueError, match="WebAuthn authentication verification failed"):
            svc.complete_authentication(
                user_id="user-3",
                credential_response={
                    "id": raw_id_b64,
                    "rawId": raw_id_b64,
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30=",
                        "authenticatorData": "e30=",
                        "signature": "e30=",
                    },
                },
                expected_origin="https://example.test",
            )


class TestPgWebAuthnServiceRealLibraryNoServerError:
    """Same proof for auth/pg_webauthn.py's PgWebAuthnService -- the
    PRODUCTION v1 API path (webauthn_v1.py). Postgres calls
    (PgWebAuthnCredentialStore) are monkeypatched to in-memory async stubs
    since no live Postgres is available offline; the py-webauthn library
    calls themselves are 100% real, which is the only thing this bug
    affects."""

    def _service(self, monkeypatch, existing_credentials=None):
        from yashigani.auth.pg_webauthn import (
            PgWebAuthnCredentialStore,
            PgWebAuthnService,
            RedisWebAuthnChallengeStore,
        )
        from yashigani.auth.webauthn import WebAuthnConfig

        creds = existing_credentials or []

        async def _list_for_user(self, user_id):
            return [c for c in creds if c.user_id == user_id]

        async def _get_by_credential_id(self, credential_id):
            for c in creds:
                if c.credential_id == credential_id:
                    return c
            return None

        monkeypatch.setattr(PgWebAuthnCredentialStore, "list_for_user", _list_for_user)
        monkeypatch.setattr(
            PgWebAuthnCredentialStore, "get_by_credential_id", _get_by_credential_id
        )

        class _FakeRedis:
            def __init__(self):
                self._store: dict[str, bytes] = {}

            def set(self, key, value, ex=None):
                self._store[key] = value

            def getdel(self, key):
                return self._store.pop(key, None)

        challenge_store = RedisWebAuthnChallengeStore(_FakeRedis())
        return PgWebAuthnService(
            config=WebAuthnConfig(rp_id="example.test"),
            pg_store=PgWebAuthnCredentialStore(),
            challenge_store=challenge_store,
        )

    @pytest.mark.asyncio
    async def test_begin_registration_returns_valid_options_no_attributeerror(self, monkeypatch):
        svc = self._service(monkeypatch)
        options_json = await svc.begin_registration(user_id="admin-1", user_name="admin@example.com")
        parsed = json.loads(options_json)
        assert "challenge" in parsed
        assert "authenticatorSelection" in parsed

    @pytest.mark.asyncio
    async def test_begin_authentication_returns_valid_options_no_attributeerror(self, monkeypatch):
        from yashigani.auth.webauthn import WebAuthnCredential

        existing = [
            WebAuthnCredential(
                id="cred-uuid-2",
                user_id="admin-1",
                credential_id=b"\xaa\xbb",
                public_key=b"\x00" * 32,
                sign_count=1,
                aaguid="00000000000000000000000000000000",
                name="Admin Key",
            )
        ]
        svc = self._service(monkeypatch, existing_credentials=existing)
        options_json = await svc.begin_authentication(user_id="admin-1")
        parsed = json.loads(options_json)
        assert "challenge" in parsed

    @pytest.mark.asyncio
    async def test_complete_registration_bad_assertion_raises_valueerror_not_attributeerror(
        self, monkeypatch
    ):
        svc = self._service(monkeypatch)
        await svc.begin_registration(user_id="admin-2", user_name="admin2@example.com")

        with pytest.raises(ValueError, match="WebAuthn registration verification failed"):
            await svc.complete_registration(
                user_id="admin-2",
                credential_response={
                    "id": "AAAA",
                    "rawId": "AAAA",
                    "type": "public-key",
                    "response": {
                        "clientDataJSON": "e30=",
                        "attestationObject": "e30=",
                    },
                },
                expected_origin="https://example.test",
            )
