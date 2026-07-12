"""Yashigani Audit — Crypto-Shred Erasure (GDPR Art 17 over the tamper-evident chain).

Reconciles a data-subject erasure request with the append-only SHA-384 Merkle
audit chain by *crypto-shredding*: subject-identifying fields in an audit event
are stored encrypted under a **per-subject Data Encryption Key (DEK)**; erasure =
destroy that DEK, rendering the ciphertext permanently unrecoverable while the
chain leaf hash (which covers the *ciphertext*) stays valid and verifiable.

Design: Products/Yashigani/crypto-shred-erasure-design-5.0-20260712.md
Integration scoping (Tom, 2026-07-12): sealing runs in ``AuditLogWriter.write()``
**after** credential masking and **before** ``event.to_dict()`` — so file, DB and
SIEM all receive identical ciphertext, and both hash sites cover the sealed dict.

Key hierarchy (Nico crypto-verified 2026-07-12):
    KMS secret-store  ->  per-TENANT KEK (32B, stored in KMS)
                            ->  per-SUBJECT DEK (32B random, AES-256-GCM-wrapped
                                by the KEK, stored BY US in Redis + Postgres)

Why DEKs are stored by us and not in KMS: destroying a DEK must be a real,
immediate hard-delete (Redis ``DEL`` + Postgres ``DELETE``) with no KMS
soft-delete/recovery window. The KEK stays in KMS; the DEK is the shred unit.

FIPS: AES-256-GCM via ``cryptography`` (OpenSSL FIPS provider, CMVP #4985 under
``FIPS_MODE=1``); random 96-bit GCM nonce per seal; SHA-256 for subject-id
derivation. DEKs are RANDOM (never KDF-derived) so they can be truly destroyed.

Honesty (Lu GRC gate): crypto-shred is a defensible technique reconciling erasure
with tamper-evidence, NOT a regulator-certified substitute for statutory erasure
(WP29 05/2014 treats key-retained encryption as pseudonymisation). Acceptance as
"erasure" is unconfirmed for PIPL/DPDP/PIPA/APPI. It shreds only data placed under
a managed key; it pairs with (does not replace) egress DLP.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import secrets
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# ── Envelope format ────────────────────────────────────────────────────────
_ENVELOPE_TAG = "cs"          # marker key identifying a crypto-shred envelope
_ENVELOPE_VER = "v1"
_ALG = "A256GCM"

# ── Subject-field selection (Tom integration scoping 2026-07-12) ───────────
# Human data-subject identifiers that must be sealed when present on an event.
# NOTE the deliberate human-vs-NHI split: agent/SPIFFE identifiers are NOT GDPR
# subjects and must NOT be sealed (they are needed cleartext for security ops).
_HUMAN_SUBJECT_FIELDS: frozenset[str] = frozenset({
    "admin_account",
    "user_handle",
    "target_user_handle",
    "target_account",
    "email",
    "operator_identity",
    # human identity_id family (accountable human principal — schema.py:3825 etc.)
    "owner_identity_id",
    "user_identity_id",
    "on_behalf_of_identity_id",
    "target_identity_id",
})

# Fields named like an identity but which carry a NON-HUMAN (agent/SPIFFE)
# identifier — never sealed. ``McpCallEvent.identity_id`` is a resolved SPIFFE
# slug (schema.py:3052), an agent, not a data subject.
_NHI_FIELDS: frozenset[str] = frozenset({
    "identity_id",       # bare identity_id on agent-call events = SPIFFE slug
    "agent_id",
    "spiffe_id",
    "nhi_id",
    "provenance_id",
})

# ``scope_id`` is PII only when the sibling ``scope`` field == "user"
# (else it is an org_id / group_id). Sealed conditionally.
_CONDITIONAL_SCOPE_FIELD = "scope_id"
_CONDITIONAL_SCOPE_GUARD = "scope"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(txt: str) -> bytes:
    return base64.b64decode(txt.encode("ascii"))


def _tenant_salt() -> bytes:
    """Stable per-deployment salt for deriving subject ids from raw identifiers.

    Sourced from the deployment secret so subject-id derivation is deterministic
    within a deployment but not correlatable across deployments.
    """
    seed = os.environ.get("YASHIGANI_SUBJECT_ID_SALT") or os.environ.get(
        "YASHIGANI_INSTANCE_SALT", ""
    )
    return hashlib.sha256(("cryptoshred-subject-id::" + seed).encode("utf-8")).digest()


def derive_subject_id(tenant_id: str, raw_identifier: str) -> str:
    """Canonical subject id for a data subject.

    ``idnt_``-prefixed identity ids (the 4.1.1-unified canonical PK) are used
    verbatim; any other raw identifier (email, handle) is mapped to an opaque,
    non-reversible ``subj_`` id via HMAC-SHA256 so the subject-index never stores
    the raw value and two events for the same person collapse to one DEK.
    """
    raw = (raw_identifier or "").strip()
    if raw.startswith("idnt_"):
        return raw
    norm = raw.lower()
    mac = hmac.new(_tenant_salt(), f"{tenant_id}::{norm}".encode("utf-8"), hashlib.sha256)
    return "subj_" + mac.hexdigest()[:32]


def is_envelope(value: object) -> bool:
    """True if *value* is already a crypto-shred envelope (idempotent seal)."""
    if not isinstance(value, str) or _ENVELOPE_TAG not in value:
        return False
    try:
        d = json.loads(value)
        return isinstance(d, dict) and d.get(_ENVELOPE_TAG) == _ENVELOPE_VER
    except (ValueError, TypeError):
        return False


class CryptoShredError(Exception):
    """Base error for the crypto-shred subsystem."""


class SubjectShreddedError(CryptoShredError):
    """Raised on an attempt to seal/unseal under a DEK that has been destroyed."""


class CryptoShredKeyStore:
    """Per-tenant KEK (in KMS) + per-subject DEK (wrapped, stored by us).

    Storage mirrors ``identity/durable_store.py``: Redis is the hot path; a
    Postgres table (``subject_dek_store``, migration 0028) is the durable mirror,
    holding **wrapped DEKs only** — never a plaintext DEK, never a KEK.

    The DEK is the unit of erasure: destroying it (Redis ``DEL`` + Postgres
    ``DELETE``) makes every sink's ciphertext for that subject inert.
    """

    _KEK_KMS_KEY = "cryptoshred:kek:{tenant}"
    _DEK_REDIS = "cryptoshred:dek:{tenant}:{subject}"      # wrapped DEK (b64 json)
    _INDEX_REDIS = "cryptoshred:index:{tenant}:{subject}"   # subject-index hash

    def __init__(self, redis_client, kms_provider, dsn: Optional[str] = None) -> None:
        self._r = redis_client
        self._kms = kms_provider
        self._dsn = dsn
        self._kek_cache: dict[str, bytes] = {}   # tenant -> KEK bytes (in-process)
        self._dek_cache: dict[str, bytes] = {}   # "tenant:subject" -> DEK bytes

    # ── KEK (per-tenant, in KMS) ────────────────────────────────────────────
    def _get_or_create_kek(self, tenant_id: str) -> bytes:
        if tenant_id in self._kek_cache:
            return self._kek_cache[tenant_id]
        key = self._KEK_KMS_KEY.format(tenant=tenant_id)
        try:
            kek = _b64d(self._kms.get_secret(key))
        except Exception:  # KeyNotFoundError or provider miss -> mint one
            kek = AESGCM.generate_key(bit_length=256)
            self._kms.set_secret(key, _b64e(kek))
            logger.info("crypto_shred: minted per-tenant KEK for %s", tenant_id)
        self._kek_cache[tenant_id] = kek
        return kek

    # ── DEK (per-subject, wrapped by KEK, stored by us) ─────────────────────
    def _wrap_dek(self, kek: bytes, dek: bytes, subject_id: str) -> str:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(kek).encrypt(nonce, dek, subject_id.encode("utf-8"))
        return json.dumps({"n": _b64e(nonce), "w": _b64e(ct)}, separators=(",", ":"))

    def _unwrap_dek(self, kek: bytes, wrapped: str, subject_id: str) -> bytes:
        d = json.loads(wrapped)
        return AESGCM(kek).decrypt(_b64d(d["n"]), _b64d(d["w"]), subject_id.encode("utf-8"))

    def get_or_create_dek(self, tenant_id: str, subject_id: str) -> bytes:
        cache_key = f"{tenant_id}:{subject_id}"
        if cache_key in self._dek_cache:
            return self._dek_cache[cache_key]
        redis_key = self._DEK_REDIS.format(tenant=tenant_id, subject=subject_id)
        kek = self._get_or_create_kek(tenant_id)
        wrapped = self._r.get(redis_key)
        if wrapped is not None:
            wrapped = wrapped.decode("utf-8") if isinstance(wrapped, bytes) else wrapped
            dek = self._unwrap_dek(kek, wrapped, subject_id)
        else:
            dek = AESGCM.generate_key(bit_length=256)
            wrapped = self._wrap_dek(kek, dek, subject_id)
            self._r.set(redis_key, wrapped)
            self._mirror_dek_durable(tenant_id, subject_id, wrapped)
            self._index_touch(tenant_id, subject_id, created=True)
        self._dek_cache[cache_key] = dek
        return dek

    def get_dek_if_active(self, tenant_id: str, subject_id: str) -> Optional[bytes]:
        """Return the DEK, or None if the subject has been shredded (for unseal)."""
        cache_key = f"{tenant_id}:{subject_id}"
        if cache_key in self._dek_cache:
            return self._dek_cache[cache_key]
        redis_key = self._DEK_REDIS.format(tenant=tenant_id, subject=subject_id)
        wrapped = self._r.get(redis_key)
        if wrapped is None:
            return None
        wrapped = wrapped.decode("utf-8") if isinstance(wrapped, bytes) else wrapped
        dek = self._unwrap_dek(self._get_or_create_kek(tenant_id), wrapped, subject_id)
        self._dek_cache[cache_key] = dek
        return dek

    def destroy_dek(self, tenant_id: str, subject_id: str) -> bool:
        """Hard-destroy a subject's DEK across all stores → crypto-shred.

        Returns True if a DEK was present and destroyed. Idempotent.
        """
        cache_key = f"{tenant_id}:{subject_id}"
        self._dek_cache.pop(cache_key, None)
        redis_key = self._DEK_REDIS.format(tenant=tenant_id, subject=subject_id)
        existed = bool(self._r.delete(redis_key))
        self._purge_dek_durable(tenant_id, subject_id)
        self._index_touch(tenant_id, subject_id, shredded=True)
        logger.info(
            "crypto_shred: DEK destroyed tenant=%s subject=%s existed=%s",
            tenant_id, subject_id, existed,
        )
        return existed

    # ── Subject-index (Redis hash) ──────────────────────────────────────────
    def _index_touch(self, tenant_id: str, subject_id: str, *,
                     created: bool = False, shredded: bool = False) -> None:
        key = self._INDEX_REDIS.format(tenant=tenant_id, subject=subject_id)
        if shredded:
            self._r.hset(key, "status", "shredded")
        elif created:
            self._r.hset(key, mapping={"status": "active", "subject_id": subject_id})

    def index_status(self, tenant_id: str, subject_id: str) -> Optional[str]:
        key = self._INDEX_REDIS.format(tenant=tenant_id, subject=subject_id)
        val = self._r.hget(key, "status")
        return (val.decode("utf-8") if isinstance(val, bytes) else val) if val else None

    # ── Postgres durable mirror (wrapped DEKs only) ─────────────────────────
    # Mirrors identity/durable_store.py: short-lived sync psycopg2, fail-loud,
    # ON CONFLICT upsert. Table subject_dek_store(tenant_id, subject_id,
    # wrapped_dek, status, created_at, shredded_at) — migration 0028.
    def _direct_dsn(self) -> str:
        return self._dsn or os.environ.get("YASHIGANI_DB_DSN_DIRECT") \
            or os.environ.get("YASHIGANI_DB_DSN", "")

    def _mirror_dek_durable(self, tenant_id: str, subject_id: str, wrapped: str) -> None:
        dsn = self._direct_dsn()
        if not dsn or "{{" in dsn:
            return  # no usable DSN yet (pre-pool); Redis remains authoritative
        try:
            from yashigani.db.postgres import connect_with_retry_sync
            conn = connect_with_retry_sync(dsn, max_attempts=3, backoff_s=2.0)
            try:
                with conn, conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO subject_dek_store "
                        "(tenant_id, subject_id, wrapped_dek, status) "
                        "VALUES (%s,%s,%s,'active') "
                        "ON CONFLICT (tenant_id, subject_id) DO UPDATE "
                        "SET wrapped_dek=EXCLUDED.wrapped_dek, status='active'",
                        (tenant_id, subject_id, wrapped),
                    )
            finally:
                conn.close()
        except Exception as exc:  # fail-loud like durable_store
            logger.error("crypto_shred: durable DEK mirror failed %s/%s: %s",
                         tenant_id, subject_id, exc)
            raise

    def _purge_dek_durable(self, tenant_id: str, subject_id: str) -> None:
        dsn = self._direct_dsn()
        if not dsn or "{{" in dsn:
            return
        try:
            from yashigani.db.postgres import connect_with_retry_sync
            conn = connect_with_retry_sync(dsn, max_attempts=3, backoff_s=2.0)
            try:
                with conn, conn.cursor() as cur:
                    # DELETE the wrapped DEK (hard shred); keep a tombstone row.
                    cur.execute(
                        "UPDATE subject_dek_store "
                        "SET wrapped_dek=NULL, status='shredded', "
                        "shredded_at=now() WHERE tenant_id=%s AND subject_id=%s",
                        (tenant_id, subject_id),
                    )
            finally:
                conn.close()
        except Exception as exc:
            logger.error("crypto_shred: durable DEK purge failed %s/%s: %s",
                         tenant_id, subject_id, exc)
            raise


class Shredder:
    """Seals subject fields on an audit event and performs subject erasure.

    ``seal(event)`` is called from ``AuditLogWriter.write()`` after masking and
    before ``to_dict()``. It mutates the (frozen) dataclass in place via
    ``object.__setattr__`` and returns it.
    """

    def __init__(self, key_store: CryptoShredKeyStore) -> None:
        self._ks = key_store

    # ── sealing ─────────────────────────────────────────────────────────────
    def _seal_value(self, tenant_id: str, subject_id: str, field: str, plaintext: str) -> str:
        dek = self._ks.get_or_create_dek(tenant_id, subject_id)
        nonce = secrets.token_bytes(12)  # random 96-bit GCM nonce per seal
        aad = f"{tenant_id}:{subject_id}:{field}".encode("utf-8")
        ct = AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), aad)
        return json.dumps(
            {_ENVELOPE_TAG: _ENVELOPE_VER, "alg": _ALG, "kid": subject_id,
             "n": _b64e(nonce), "ct": _b64e(ct)},
            separators=(",", ":"),
        )

    def unseal_value(self, tenant_id: str, envelope: str, field: str) -> Optional[str]:
        """Decrypt a sealed value for an authorised DSAR read.

        Returns None if the subject has been shredded (DEK destroyed) — which is
        the correct post-erasure answer: the data is irrecoverable.
        """
        if not is_envelope(envelope):
            return envelope
        d = json.loads(envelope)
        subject_id = d["kid"]
        dek = self._ks.get_dek_if_active(tenant_id, subject_id)
        if dek is None:
            return None  # shredded
        aad = f"{tenant_id}:{subject_id}:{field}".encode("utf-8")
        return AESGCM(dek).decrypt(_b64d(d["n"]), _b64d(d["ct"]), aad).decode("utf-8")

    def _fields_to_seal(self, event) -> list[tuple[str, str]]:
        """Return (field_name, plaintext) pairs to seal on this event.

        Human-subject allowlist minus the NHI exclusion, plus conditional
        ``scope_id``. Skips empty values and already-sealed envelopes.
        """
        out: list[tuple[str, str]] = []
        for f in dataclasses.fields(event):
            name = f.name
            val = getattr(event, name, None)
            if not isinstance(val, str) or not val or is_envelope(val):
                continue
            if name in _NHI_FIELDS:
                continue
            if name in _HUMAN_SUBJECT_FIELDS:
                out.append((name, val))
            elif name == _CONDITIONAL_SCOPE_FIELD:
                if getattr(event, _CONDITIONAL_SCOPE_GUARD, None) == "user":
                    out.append((name, val))
        return out

    def seal(self, event, tenant_id: Optional[str] = None):
        """Seal subject fields on *event* in place; return the mutated event.

        Fail-open is NOT acceptable for a privacy control, but neither is losing
        the audit event: on a seal error we leave the field cleartext and emit a
        loud error so monitoring catches it (the event still records; the gap is
        alertable) — this matches the audit subsystem's never-drop-the-event rule.
        """
        if not dataclasses.is_dataclass(event):
            return event
        tenant = tenant_id or getattr(event, "tenant_id", None) or "default"
        try:
            pairs = self._fields_to_seal(event)
        except Exception as exc:
            logger.error("crypto_shred: field selection failed: %s", exc)
            return event
        for field, plaintext in pairs:
            subject_id = derive_subject_id(tenant, plaintext)
            try:
                sealed = self._seal_value(tenant, subject_id, field, plaintext)
                object.__setattr__(event, field, sealed)
            except Exception as exc:
                logger.error("crypto_shred: seal failed field=%s subject=%s: %s",
                             field, subject_id, exc)
        return event

    # ── erasure ─────────────────────────────────────────────────────────────
    def erase_subject(self, tenant_id: str, subject_id: str) -> dict:
        """Crypto-shred a data subject: destroy the DEK across all stores.

        Returns an erasure certificate (for the DSAR trail + the SUBJECT_ERASED
        tombstone). The ciphertext in every sink is now inert; the hash chain is
        unaffected because it covers ciphertext.
        """
        existed = self._ks.destroy_dek(tenant_id, subject_id)
        return {
            "subject_id": subject_id,
            "tenant_id": tenant_id,
            "shredded": True,
            "dek_existed": existed,
        }
