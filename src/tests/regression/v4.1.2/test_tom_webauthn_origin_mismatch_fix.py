"""
Regression test -- v4.1.2 WebAuthn origin mismatch (Ava, live CDP virtual
authenticator test, podman): register/start -> 200, register/finish -> 400
`InvalidRegistrationResponse: Unexpected client data origin
"https://localhost:8443", expected "https://backoffice:8443"`.

Root cause: `src/yashigani/backoffice/routes/webauthn_v1.py`'s
`_expected_origin()` derived the expected WebAuthn origin from the raw
`Host` header the backoffice PROCESS sees -- which on the Caddy->backoffice
reverse_proxy leg is the internal upstream dial address ("backoffice:8443"),
never the address the browser actually navigated to and signed into
clientDataJSON.origin. Every register/authenticate ceremony failed 100% of
the time as a result.

Fix (this commit):
  - Caddy now forwards `X-Forwarded-Host {host}` (the ORIGINAL inbound
    Host -- i.e. what the browser sent) on every backoffice reverse_proxy
    block, in docker/Caddyfile.{selfsigned,acme,ca} AND the Helm-rendered
    equivalent in helm/yashigani/templates/configmaps.yaml. `header_up ...
    {host}` uses Caddy's "set" semantics, which unconditionally overwrites
    any client-supplied X-Forwarded-Host before it reaches backoffice.
  - `_expected_origin()` now prefers X-Forwarded-Host over the raw Host
    header, and validates the derived hostname against an allowlist built
    from YASHIGANI_TLS_DOMAIN (the operator's configured public domain)
    plus "localhost" -- Caddy's public edge is path-routed, not
    host-vhosted, so an arbitrary client-supplied Host must not be
    silently trusted as the expected_origin (that would defeat WebAuthn's
    anti-phishing origin check entirely).
  - `WebAuthnConfig.rp_id` (auth/webauthn.py + build_pg_webauthn_service()
    in auth/pg_webauthn.py) now defaults to YASHIGANI_TLS_DOMAIN instead of
    a hardcoded "localhost", so a real configured --domain also satisfies
    the WebAuthn spec's rp_id-must-be-origin-suffix requirement.

These tests exercise the REAL py_webauthn (2.7.1, matching the locked
resolve) + cbor2 + cryptography libraries -- a full simulated FIDO2
authenticator ceremony (registration AND authentication), no mocking of
`_import_webauthn` or of `verify_registration_response` /
`verify_authentication_response`. This proves the ceremony COMPLETES with
the fixed `_expected_origin()` value, and that it FAILS with the OLD
(buggy) internal-Host-derived value -- reproducing Ava's exact bug and
proving the fix closes it.

Last updated: 2026-07-24T00:00:00+00:00
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from starlette.requests import Request


# ---------------------------------------------------------------------------
# Part 1 -- _expected_origin() unit tests (webauthn_v1.py)
# ---------------------------------------------------------------------------


def _fake_request(headers: dict[str, str]) -> Request:
    """Build a bare Starlette Request carrying only the given headers --
    enough for _expected_origin(), which only reads request.headers /
    request.url.scheme / request.url.netloc."""
    encoded = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/admin/webauthn/register/finish",
        "headers": encoded,
        "scheme": "http",  # deliberately NOT https -- proves we don't trust this either
        "server": ("backoffice", 8443),
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
    }
    return Request(scope)


class TestExpectedOriginPrefersForwardedHost:
    def test_internal_host_alone_is_ignored_uses_forwarded_host(self, monkeypatch):
        """The exact bug: raw Host = 'backoffice:8443' (internal upstream
        dial address), but Caddy has set X-Forwarded-Host = 'localhost:8443'
        (what the browser actually navigated to). Must resolve to the
        EXTERNAL origin, not the internal one."""
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "localhost")
        from yashigani.backoffice.routes.webauthn_v1 import _expected_origin

        request = _fake_request(
            {
                "host": "backoffice:8443",
                "x-forwarded-host": "localhost:8443",
                "x-forwarded-proto": "https",
            }
        )
        origin = _expected_origin(request)
        assert origin == "https://localhost:8443"
        assert origin != "https://backoffice:8443"

    def test_configured_real_domain_resolves(self, monkeypatch):
        """A real operator-configured --domain must also resolve correctly,
        not just the default 'localhost' self-signed alias."""
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        from yashigani.backoffice.routes.webauthn_v1 import _expected_origin

        request = _fake_request(
            {
                "host": "backoffice:8443",
                "x-forwarded-host": "yashigani.example.com",
                "x-forwarded-proto": "https",
            }
        )
        origin = _expected_origin(request)
        assert origin == "https://yashigani.example.com"

    def test_no_caddy_in_front_falls_back_to_raw_host(self, monkeypatch):
        """Direct-to-backoffice access (local dev/test, no reverse proxy) --
        no X-Forwarded-Host present, falls back to the raw Host header."""
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "localhost")
        from yashigani.backoffice.routes.webauthn_v1 import _expected_origin

        request = _fake_request({"host": "localhost:8443"})
        origin = _expected_origin(request)
        assert origin == "http://localhost:8443"  # falls back to scope scheme too

    def test_arbitrary_attacker_host_rejected(self, monkeypatch):
        """Caddy's public edge is path-routed, not host-vhosted -- an
        attacker-supplied Host/X-Forwarded-Host that does NOT match the
        configured allowlist (YASHIGANI_TLS_DOMAIN + 'localhost') must be
        rejected, not silently trusted as expected_origin (that would
        defeat WebAuthn's anti-phishing origin check)."""
        monkeypatch.setenv("YASHIGANI_TLS_DOMAIN", "yashigani.example.com")
        from yashigani.backoffice.routes.webauthn_v1 import _expected_origin

        request = _fake_request(
            {
                "host": "backoffice:8443",
                "x-forwarded-host": "evil.attacker.example",
                "x-forwarded-proto": "https",
            }
        )
        with pytest.raises(ValueError, match="not in configured allowlist"):
            _expected_origin(request)


# ---------------------------------------------------------------------------
# Part 2 -- full simulated FIDO2 ceremony against the REAL py_webauthn
# library (registration AND authentication), proving completion with the
# FIXED origin and failure with the OLD (buggy) internal-Host origin.
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _build_registration_response(rp_id: str, challenge_b64url: str, origin: str):
    """Simulate a FIDO2 authenticator's registration (attestation) response
    using attestation format "none" (no signature needed in attStmt -- the
    format explicitly carries no attestation statement, only the origin/
    challenge/rpIdHash checks apply, which is exactly what this bug broke).
    Returns (credential_response_dict, private_key, credential_id_bytes).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = private_key.public_key().public_numbers()
    x = pub_numbers.x.to_bytes(32, "big")
    y = pub_numbers.y.to_bytes(32, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})

    credential_id = secrets.token_bytes(32)
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = 0x41  # UP (0x01) + AT (0x40) -- attested credential data present
    sign_count = (0).to_bytes(4, "big")
    attested_cred_data = (
        b"\x00" * 16  # aaguid
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cose_key
    )
    auth_data = rp_id_hash + bytes([flags]) + sign_count + attested_cred_data
    attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})

    client_data = {
        "type": "webauthn.create",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_bytes = json.dumps(client_data).encode()

    credential_response = {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(client_data_bytes),
            "attestationObject": _b64url(attestation_object),
        },
    }
    return credential_response, private_key, credential_id


def _build_authentication_response(
    rp_id: str,
    challenge_b64url: str,
    origin: str,
    private_key,
    credential_id: bytes,
    sign_count: int,
):
    """Simulate the same authenticator's assertion (authentication)
    response -- real ECDSA-SHA256 signature over authenticatorData ||
    SHA256(clientDataJSON), matching what a genuine FIDO2 device produces.
    """
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    flags = 0x01  # UP only -- no attested credential data on assertions
    auth_data = rp_id_hash + bytes([flags]) + sign_count.to_bytes(4, "big")

    client_data = {
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": False,
    }
    client_data_bytes = json.dumps(client_data).encode()
    client_data_hash = hashlib.sha256(client_data_bytes).digest()

    signature = private_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))

    return {
        "id": _b64url(credential_id),
        "rawId": _b64url(credential_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64url(client_data_bytes),
            "authenticatorData": _b64url(auth_data),
            "signature": _b64url(signature),
        },
    }


class _InMemoryPgStore:
    """Backs PgWebAuthnCredentialStore's methods with a plain list -- lets a
    single test drive register -> then -> authenticate against the exact
    same in-memory "row"."""

    def __init__(self):
        self.rows = []

    async def add(self, credential, transports=None):
        self.rows.append(credential)

    async def list_for_user(self, user_id):
        return [c for c in self.rows if c.user_id == user_id]

    async def get_by_credential_id(self, credential_id):
        for c in self.rows:
            if c.credential_id == credential_id:
                return c
        return None

    async def update_sign_count(self, credential_id, new_sign_count):
        for c in self.rows:
            if c.credential_id == credential_id:
                c.sign_count = new_sign_count


def _build_service(monkeypatch, rp_id: str, store: _InMemoryPgStore):
    from yashigani.auth.pg_webauthn import (
        PgWebAuthnCredentialStore,
        PgWebAuthnService,
        RedisWebAuthnChallengeStore,
    )
    from yashigani.auth.webauthn import WebAuthnConfig

    monkeypatch.setattr(PgWebAuthnCredentialStore, "add", store.add)
    monkeypatch.setattr(PgWebAuthnCredentialStore, "list_for_user", store.list_for_user)
    monkeypatch.setattr(
        PgWebAuthnCredentialStore, "get_by_credential_id", store.get_by_credential_id
    )
    monkeypatch.setattr(
        PgWebAuthnCredentialStore, "update_sign_count", store.update_sign_count
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
        config=WebAuthnConfig(rp_id=rp_id),
        pg_store=PgWebAuthnCredentialStore(),
        challenge_store=challenge_store,
    )


class TestFullCeremonyCompletesWithFixedOrigin:
    """Reproduces Ava's live bug end-to-end: with the FIXED external origin
    (what the browser actually signed), registration AND authentication
    complete cleanly; with the OLD internal-Host origin, they 400/401 with
    the exact InvalidRegistrationResponse origin-mismatch this bug caused.
    """

    RP_ID = "localhost"
    EXTERNAL_ORIGIN = "https://localhost:8443"
    INTERNAL_ORIGIN = "https://backoffice:8443"  # the OLD, buggy value

    @pytest.mark.asyncio
    async def test_registration_completes_with_external_origin(self, monkeypatch):
        store = _InMemoryPgStore()
        svc = _build_service(monkeypatch, self.RP_ID, store)

        options_json = await svc.begin_registration(user_id="admin-1", user_name="admin@example.com")
        options = json.loads(options_json)
        challenge_b64url = options["challenge"]

        credential_response, _priv, _cred_id = _build_registration_response(
            rp_id=self.RP_ID, challenge_b64url=challenge_b64url, origin=self.EXTERNAL_ORIGIN
        )

        credential = await svc.complete_registration(
            user_id="admin-1",
            credential_response=credential_response,
            expected_origin=self.EXTERNAL_ORIGIN,
        )
        assert credential.user_id == "admin-1"
        assert len(store.rows) == 1

    @pytest.mark.asyncio
    async def test_registration_fails_with_old_internal_host_origin(self, monkeypatch):
        """The exact bug reproduction: browser signs the EXTERNAL origin,
        but the (pre-fix) backend derived expected_origin from the internal
        upstream Host. verify_registration_response must then reject with
        an origin-mismatch ValueError -- proving the old code's failure
        mode and that origin correctness, not credential validity, is what
        gates this ceremony."""
        store = _InMemoryPgStore()
        svc = _build_service(monkeypatch, self.RP_ID, store)

        options_json = await svc.begin_registration(user_id="admin-2", user_name="admin2@example.com")
        options = json.loads(options_json)
        challenge_b64url = options["challenge"]

        # Browser signs the EXTERNAL origin (correct, unavoidable -- that's
        # what the browser's URL bar shows), but we pass the OLD buggy
        # internal-Host value as expected_origin, exactly reproducing what
        # the pre-fix _expected_origin() would have computed.
        credential_response, _priv, _cred_id = _build_registration_response(
            rp_id=self.RP_ID, challenge_b64url=challenge_b64url, origin=self.EXTERNAL_ORIGIN
        )

        with pytest.raises(ValueError, match="WebAuthn registration verification failed"):
            await svc.complete_registration(
                user_id="admin-2",
                credential_response=credential_response,
                expected_origin=self.INTERNAL_ORIGIN,  # the bug
            )

    @pytest.mark.asyncio
    async def test_authentication_completes_with_external_origin_after_registration(
        self, monkeypatch
    ):
        """End-to-end: register with the fixed external origin, then
        authenticate (real ECDSA signature verified against the stored
        public key) -- also with the fixed external origin. Both ceremony
        halves must complete with zero origin-mismatch errors."""
        store = _InMemoryPgStore()
        svc = _build_service(monkeypatch, self.RP_ID, store)

        reg_options = json.loads(
            await svc.begin_registration(user_id="admin-3", user_name="admin3@example.com")
        )
        credential_response, private_key, credential_id = _build_registration_response(
            rp_id=self.RP_ID,
            challenge_b64url=reg_options["challenge"],
            origin=self.EXTERNAL_ORIGIN,
        )
        credential = await svc.complete_registration(
            user_id="admin-3",
            credential_response=credential_response,
            expected_origin=self.EXTERNAL_ORIGIN,
        )

        original_sign_count = credential.sign_count  # capture BEFORE the
        # mutating update below -- `credential` and `store.rows[0]` are the
        # SAME object (complete_registration's return value is the exact
        # instance passed to store.add()), so reading it after the update
        # would already reflect the new value.

        auth_options = json.loads(await svc.begin_authentication(user_id="admin-3"))
        auth_response = _build_authentication_response(
            rp_id=self.RP_ID,
            challenge_b64url=auth_options["challenge"],
            origin=self.EXTERNAL_ORIGIN,
            private_key=private_key,
            credential_id=credential_id,
            sign_count=original_sign_count + 1,
        )

        verified_user_id = await svc.complete_authentication(
            user_id="admin-3",
            credential_response=auth_response,
            expected_origin=self.EXTERNAL_ORIGIN,
        )
        assert verified_user_id == "admin-3"
        assert store.rows[0].sign_count == original_sign_count + 1
