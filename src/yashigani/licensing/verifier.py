"""
Offline license verifier — ECDSA P-256 (migrating to ML-DSA-65 when cryptography ships FIPS 204).

Last updated: 2026-04-27T21:53:12+01:00

License file format:
    v4 (current): {base64url(utf8(json_payload))}.{base64url(primary_signature)}.{base64url(counter_signature)}

v3 format (2-segment, primary signature only) is NO LONGER ACCEPTED.
LAURA-V231-003: dropping v3 support makes the counter-signature mandatory — an
attacker with primary-key compromise cannot issue accepted licenses.

Current key algorithm: ECDSA P-256 (SHA-256).
Future: ML-DSA-65 (FIPS 204 / CRYSTALS-Dilithium Level 3) — pending cryptography library support.
The verifier is algorithm-agnostic: load_pem_public_key() + .verify() dispatches by key type.

Payload versions:
    v1 — max_agents, max_orgs only
    v2 — adds max_users (renamed to max_end_users in v3)
    v3 — max_agents, max_end_users, max_admin_seats, max_orgs, key_alg (current)

Backwards compat: v1/v2 payloads missing new fields fall back to
TIER_DEFAULTS[tier] so existing customer license files keep working.
(These are payload versions, distinct from the license-file format version above.)

Fail-open on corrupt/unparseable licenses; fail-closed on invalid signatures.
All licenses must be in v4 format (3-segment). 2-segment licenses are rejected
with error "license_format_too_old".

Self-integrity check
--------------------
At module load this file computes its own SHA-256 digest and compares it against
_integrity.VERIFIER_HASH.  A mismatch (when the hash is not a placeholder)
indicates post-build tampering.  The system logs a CRITICAL alert and forces
COMMUNITY tier for any subsequently verified license.

Requires: cryptography>=42.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    TIER_DEFAULTS,
    LicenseFeature,
    LicenseState,
    LicenseTier,
)
from yashigani.licensing import _integrity

logger = logging.getLogger(__name__)

# ECDSA P-256 production public key — private key stored in KMS.
# Will migrate to ML-DSA-65 (FIPS 204) when cryptography library ships support.
_PUBLIC_KEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9v3e5INc8Mr7yoN5rSsaJROahk58
HPYAxfkKlcJDVSH47HIERSL19ceu3JVS28uHRJw1WJ13JbUYI/vWAE1zNQ==
-----END PUBLIC KEY-----
"""

_PLACEHOLDER_MARKER = "PLACEHOLDER_YASHIGANI_PUBLIC_KEY_MLDSA65"
_placeholder_warned = False

# ---------------------------------------------------------------------------
# Self-integrity state (set at module load)
# ---------------------------------------------------------------------------

# True when tamper detection has fired for this process lifetime.
_integrity_violated = False


def _check_self_integrity() -> None:
    """
    Compute SHA-256 of this source file and compare against _integrity.VERIFIER_HASH.

    Skipped (fail-open) when the hash constant is still a placeholder.
    Sets _integrity_violated = True on mismatch, which causes verify_license()
    to return COMMUNITY tier for all calls in this process.
    """
    global _integrity_violated

    if _integrity.is_verifier_hash_placeholder():
        # #104 (LICENSE-2024-002 / CVSS 9.1) — placeholder skip is only
        # permitted in dev/CI builds (YASHIGANI_ENV=dev).  In any other
        # environment a placeholder hash means the build pipeline failed to
        # embed the real hash; treat that as a tamper event (fail-closed).
        if os.environ.get("YASHIGANI_ENV") != "dev":
            _integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: VERIFIER_HASH is still a placeholder "
                "in a non-dev environment — build pipeline did not embed hash; "
                "forcing COMMUNITY tier (LICENSE-2024-002)"
            )
        return

    try:
        source_path = Path(__file__)
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    except Exception as exc:
        # Cannot read own source — treat as suspicious but do not crash the
        # process.  Log a warning; do not set _integrity_violated (benefit of
        # doubt — compiled .pyc or unusual packaging).
        logger.warning(
            "License integrity: could not read own source for hash check: %s", exc
        )
        return

    if digest != _integrity.VERIFIER_HASH:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: verifier.py has been tampered with "
            "(expected=%s, actual=%s)",
            _integrity.VERIFIER_HASH,
            digest,
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="self_hash",
            expected_hash=_integrity.VERIFIER_HASH,
            actual_hash=digest,
        )


def _emit_licence_integrity_violation_event(
    module: str,
    check_type: str,
    expected_hash: str,
    actual_hash: str,
    classification: str = "unknown",
) -> None:
    """
    Write a typed LicenceIntegrityViolationEvent if an AuditLogWriter is available.

    Wrapped in a broad except so that a missing / uninitialised audit subsystem
    never blocks the integrity check result.  The CRITICAL log is the primary alert;
    audit is defence-in-depth.
    """
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None

        if writer is None:
            return

        event = LicenceIntegrityViolationEvent(
            module=module,
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        )
        event._internal_classification = classification
        writer.write(event)
    except Exception:
        pass  # audit subsystem unavailable — integrity violation already logged via CRITICAL


# ---------------------------------------------------------------------------
# T6: KDF-derived integrity token
# ---------------------------------------------------------------------------

def _derive_integrity_token(hash_bundle_str: str, licence_id: str, seat_policy: str) -> bytes:
    """
    Derive a 32-byte integrity token using HKDF-SHA-256.

    IKM  = SHA-256(hash_bundle_str.encode("utf-8"))
    salt = SHA-256(licence_id.encode("utf-8") + seat_policy.encode("utf-8"))
    info = b"yashigani-integrity-v1"
    L    = 32

    DG-01: inputs are ONLY (hash_bundle_str, licence_id, seat_policy) — no CA fingerprint.
    DG-03: Community seat_policy is "20,5,2".
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.hashes import SHA256 as CryptoSHA256
    from cryptography.hazmat.backends import default_backend

    ikm = hashlib.sha256(hash_bundle_str.encode("utf-8")).digest()
    salt = hashlib.sha256(
        licence_id.encode("utf-8") + seat_policy.encode("utf-8")
    ).digest()
    hkdf = HKDF(
        algorithm=CryptoSHA256(),
        length=32,
        salt=salt,
        info=b"yashigani-integrity-v1",
        backend=default_backend(),
    )
    return hkdf.derive(ikm)


def _check_hash_bundle_attestation() -> None:
    """
    T6: Verify HASH_BUNDLE_SIG is a valid ECDSA P-256 signature over the canonical
    hash-bundle string.  Sets _integrity_violated on failure.

    Placeholder behaviour:
      - If is_any_hash_placeholder() → skip (dev) / fail-closed (prod).
      - If is_bundle_sig_placeholder() → skip (dev) / fail-closed (prod).
    """
    global _integrity_violated

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if _integrity.is_any_hash_placeholder():
        if is_dev:
            return  # dev: skip
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: one or more file hashes are still placeholders "
            "in a non-dev environment — hash bundle attestation cannot proceed; "
            "forcing COMMUNITY tier (T6)"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="bundle_sig",
            expected_hash="<real_hash>",
            actual_hash="<placeholder>",
        )
        return

    if _integrity.is_bundle_sig_placeholder():
        if is_dev:
            return  # dev: skip
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: HASH_BUNDLE_SIG is still a placeholder "
            "in a non-dev environment — build pipeline did not embed bundle signature; "
            "forcing COMMUNITY tier (T6)"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="bundle_sig",
            expected_hash="<sig>",
            actual_hash="<placeholder>",
        )
        return

    # Build canonical bundle string (sorted by key name, 5 module hashes only).
    # DESIGN-NOTE (Su 2026-06-15): INTEGRITY_HASH is intentionally excluded from
    # the signed bundle.  Including it creates an unresolvable circularity in the
    # injection pipeline: INTEGRITY_HASH covers the final _integrity.py (including
    # HASH_BUNDLE_SIG), but HASH_BUNDLE_SIG must be signed before INTEGRITY_HASH
    # is finalized.  INTEGRITY_HASH already receives independent protection via the
    # enforcer cross-check (_check_enforcer_integrity → cross-checks _integrity.py
    # hash via INTEGRITY_HASH), which catches any attacker who patches _integrity.py
    # to substitute their own bundle sig.  The 5-module bundle covers all module
    # files that gate the licence; _integrity.py tamper evidence comes from the
    # enforcer cross-check path.  Security goal is identical to Nico's §2.4 design.
    bundle_str = "\n".join([
        f"AGENTS_REGISTRY_HASH={_integrity.AGENTS_REGISTRY_HASH}",
        f"ENFORCER_HASH={_integrity.ENFORCER_HASH}",
        f"IDENTITY_REGISTRY_HASH={_integrity.IDENTITY_REGISTRY_HASH}",
        f"LOADER_HASH={_integrity.LOADER_HASH}",
        f"VERIFIER_HASH={_integrity.VERIFIER_HASH}",
    ])

    try:
        import base64 as _b64
        sig_bytes = _b64.b64decode(_integrity.HASH_BUNDLE_SIG + "==")
    except Exception:
        try:
            sig_bytes = bytes.fromhex(_integrity.HASH_BUNDLE_SIG)
        except Exception:
            _integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: HASH_BUNDLE_SIG is not valid base64 or hex — "
                "forcing COMMUNITY tier (T6)"
            )
            _emit_licence_integrity_violation_event(
                module="verifier",
                check_type="bundle_sig",
                expected_hash="<valid_sig>",
                actual_hash="<unparseable>",
            )
            return

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
        from cryptography.hazmat.primitives.hashes import SHA256 as CryptoSHA256
        from cryptography.exceptions import InvalidSignature

        if _integrity.is_counter_key_placeholder():
            if is_dev:
                return
            _integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: cannot verify bundle signature — "
                "COUNTER_PUBLIC_KEY_PEM is placeholder in non-dev environment (T6)"
            )
            _emit_licence_integrity_violation_event(
                module="verifier",
                check_type="bundle_sig",
                expected_hash="<key>",
                actual_hash="<placeholder>",
            )
            return

        pub_key = load_pem_public_key(_integrity.COUNTER_PUBLIC_KEY_PEM.encode("utf-8"))
        if not isinstance(pub_key, EllipticCurvePublicKey):
            raise ValueError(f"Not an EC key: {type(pub_key).__name__}")

        bundle_digest = hashlib.sha256(bundle_str.encode("utf-8")).digest()
        pub_key.verify(sig_bytes, bundle_digest, ECDSA(CryptoSHA256()))
        # Signature valid — no action

    except InvalidSignature:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: hash bundle signature verification failed — "
            "binary may have been tampered with; forcing COMMUNITY tier (T6). "
            "License integrity check failed — system restrained to Community limits. "
            "Contact support@agnosticsec.com or re-activate."
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="bundle_sig",
            expected_hash=_integrity.HASH_BUNDLE_SIG[:16],
            actual_hash="<invalid>",
        )
    except Exception as exc:
        logger.warning("License integrity: bundle attestation check failed unexpectedly: %s", exc)
        if not is_dev:
            _integrity_violated = True


def _check_kdf_token() -> None:
    """
    T7: Verify EXPECTED_TOKEN_HMAC matches SHA-256(token || b"yashigani-kdf-gate-v1")
    where token = _derive_integrity_token(bundle_str, "", "20,5,2").

    Placeholder behaviour: skip (dev) / fail-closed (prod).
    """
    global _integrity_violated

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if _integrity.is_kdf_token_placeholder():
        if is_dev:
            return
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: EXPECTED_TOKEN_HMAC is still a placeholder "
            "in a non-dev environment; forcing COMMUNITY tier (T7)"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="kdf_token",
            expected_hash="<hmac>",
            actual_hash="<placeholder>",
        )
        return

    if _integrity.is_any_hash_placeholder():
        if is_dev:
            return
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: KDF token check skipped — hash placeholders "
            "in non-dev; forcing COMMUNITY tier (T7)"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="kdf_token",
            expected_hash="<token>",
            actual_hash="<placeholder>",
        )
        return

    try:
        # 5-module bundle (INTEGRITY_HASH excluded — see DESIGN-NOTE in _check_hash_bundle_attestation)
        bundle_str = "\n".join([
            f"AGENTS_REGISTRY_HASH={_integrity.AGENTS_REGISTRY_HASH}",
            f"ENFORCER_HASH={_integrity.ENFORCER_HASH}",
            f"IDENTITY_REGISTRY_HASH={_integrity.IDENTITY_REGISTRY_HASH}",
            f"LOADER_HASH={_integrity.LOADER_HASH}",
            f"VERIFIER_HASH={_integrity.VERIFIER_HASH}",
        ])
        # DG-01 + DG-03: Community KDF uses licence_id="" and seat_policy="20,5,2"
        token = _derive_integrity_token(bundle_str, "", "20,5,2")
        actual_hmac = hashlib.sha256(token + b"yashigani-kdf-gate-v1").hexdigest()

        expected = _integrity.EXPECTED_TOKEN_HMAC.strip()
        if actual_hmac != expected:
            _integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: KDF token mismatch — "
                "expected=%s actual=%s; forcing COMMUNITY tier (T7). "
                "License integrity check failed — system restrained to Community limits. "
                "Contact support@agnosticsec.com or re-activate.",
                expected[:16],
                actual_hmac[:16],
            )
            _emit_licence_integrity_violation_event(
                module="verifier",
                check_type="kdf_token",
                expected_hash=expected[:16],
                actual_hash=actual_hmac[:16],
            )
    except Exception as exc:
        logger.warning("License integrity: KDF token check failed unexpectedly: %s", exc)
        if not is_dev:
            _integrity_violated = True


def get_integrity_status() -> bool:
    """Return True if the integrity has been violated in this process."""
    return _integrity_violated


# Run at module load.
_check_self_integrity()
_check_hash_bundle_attestation()
_check_kdf_token()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (no padding required)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _is_placeholder() -> bool:
    return _PLACEHOLDER_MARKER in _PUBLIC_KEY_PEM


def _warn_placeholder_once() -> None:
    global _placeholder_warned
    if not _placeholder_warned:
        logger.warning(
            "Yashigani license verifier: public key is a placeholder — "
            "all license files will be ignored and COMMUNITY tier will be used. "
            "Replace _PUBLIC_KEY_PEM in verifier.py before release."
        )
        _placeholder_warned = True


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


# Sentinel used by enterprise tier to signal "unlimited".  -1 is the documented
# value; we preserve it through _safe_int so enforcer can treat it specially.
_UNLIMITED_SENTINEL = -1

# Sanity ceiling: no license should grant more than 10 million seats of any type.
# A value above this (other than the -1 unlimited sentinel) indicates a corrupt
# or adversarially crafted payload and is clamped to COMMUNITY defaults.
_SEAT_CEILING = 10_000_000


def _safe_int(value: object, default: int) -> int:
    """
    Coerce *value* to int; return *default* on any failure.

    Handles:
      - None / missing field
      - Empty string or whitespace-only string
      - Non-numeric strings ("abc", "null", etc.)
      - Float (truncated to int via int())
      - Negative values other than the documented -1 unlimited sentinel
        → clamp to *default* (LAURA-LICENSE-08: negative seat counts are
        adversarial — they would bypass enforcer's >= check entirely)
      - Values above _SEAT_CEILING that are not -1 → clamp to *default*

    Never raises. Prevents LAURA-V231-002 DoS-on-boot via null seat fields.
    Prevents LAURA-LICENSE-08 negative-seat bypass.
    """
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return default
    try:
        result = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default

    # Preserve the -1 unlimited sentinel without clamping.
    if result == _UNLIMITED_SENTINEL:
        return result

    # LAURA-LICENSE-08: any other negative value is adversarial (a seat count
    # of -2 would satisfy enforcer's `current >= max_agents` check with any
    # positive current count, bypassing the limit entirely). Clamp to default.
    if result < 0:
        logger.warning(
            "License verifier: negative seat field value %d — "
            "using tier default %d (LAURA-LICENSE-08)",
            result, default,
        )
        return default

    # Reject implausibly large values (corrupt / adversarial payload).
    if result > _SEAT_CEILING:
        logger.warning(
            "License verifier: seat field value %d exceeds ceiling %d — "
            "using tier default %d",
            result, _SEAT_CEILING, default,
        )
        return default

    return result


def _build_license_state(payload: dict, valid: bool, error: Optional[str] = None) -> LicenseState:
    tier_str = payload.get("tier", "community")
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        tier = LicenseTier.COMMUNITY
        tier_str = "community"

    # GROUP-5-3: canary sentinel — this tier must never appear in a verifiable
    # license. If we receive one it means someone has issued a canary token to
    # probe for patched verifiers. Reject with a specific error so monitoring
    # can alert on it. Map to COMMUNITY (fail-closed).
    if tier == LicenseTier.CANARY:
        logger.critical(
            "License verifier: CANARY tier token presented — potential verifier-patch "
            "probe detected (GROUP-5-3); forcing COMMUNITY"
        )
        return _community_invalid("canary_token_rejected")

    # Coerce string feature values to LicenseFeature enum; unknown strings are silently dropped
    # for forwards-compat (new features added server-side before client ships).
    features_raw = payload.get("features", [])
    if isinstance(features_raw, list):
        coerced: list[LicenseFeature] = []
        for f in features_raw:
            try:
                coerced.append(LicenseFeature(f))
            except ValueError:
                pass
        features: frozenset[LicenseFeature] = frozenset(coerced)
    else:
        features = frozenset()

    issued_at = _parse_datetime(payload.get("issued_at")) or datetime(2020, 1, 1, tzinfo=timezone.utc)
    expires_at = _parse_datetime(payload.get("expires_at"))

    # GROUP-1-2: License Service produces {"domains": ["x.com"]} not {"org_domain": "x.com"}.
    # Read domains[0] first; fall back to legacy org_domain key for older payloads.
    domains_list = payload.get("domains")
    if isinstance(domains_list, list) and domains_list:
        org_domain = str(domains_list[0])
    else:
        org_domain = payload.get("org_domain", "*")
    if not org_domain:
        org_domain = "*"

    # LAURA-LIMIT-DOMAINS-02: wildcard domain is only valid for Community and
    # Academic/Nonprofit tiers. Paid tiers (Starter, Professional, Professional Plus,
    # Enterprise) must have a specific domain binding. A wildcard on a paid tier means
    # the license was issued without domain binding and could be replayed to any deployment.
    if (
        valid
        and org_domain == "*"
        and tier not in (LicenseTier.COMMUNITY, LicenseTier.ACADEMIC_NONPROFIT)
    ):
        logger.warning(
            "License verifier: paid tier %r has wildcard org_domain — "
            "rejecting (LAURA-LIMIT-DOMAINS-02)",
            tier_str,
        )
        return _community_invalid("wildcard_domain_not_permitted_for_paid_tier")

    # Resolve limits with backwards-compat fallback to tier defaults.
    # _safe_int guards against null/None/empty/non-numeric values in any field
    # (LAURA-V231-002: null seat fields previously caused TypeError → DoS on boot).
    defaults = TIER_DEFAULTS.get(tier_str, TIER_DEFAULTS["community"])
    max_agents      = _safe_int(payload.get("max_agents"),                                       defaults["max_agents"])
    max_end_users   = _safe_int(payload.get("max_end_users", payload.get("max_users")),          defaults["max_end_users"])
    max_admin_seats = _safe_int(payload.get("max_admin_seats"),                                  defaults["max_admin_seats"])
    max_orgs        = _safe_int(payload.get("max_orgs"),                                         defaults["max_orgs"])

    return LicenseState(
        tier=tier,
        org_domain=org_domain,
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=features,
        issued_at=issued_at,
        expires_at=expires_at,
        license_id=payload.get("license_id"),
        valid=valid,
        error=error,
    )


def _community_invalid(error: str) -> LicenseState:
    """Return a typed invalid LicenseState using community defaults."""
    d = TIER_DEFAULTS["community"]
    return LicenseState(
        tier=LicenseTier.COMMUNITY,
        org_domain="*",
        max_agents=d["max_agents"],
        max_end_users=d["max_end_users"],
        max_admin_seats=d["max_admin_seats"],
        max_orgs=d["max_orgs"],
        features=frozenset(),
        issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expires_at=None,
        license_id=None,
        valid=False,
        error=error,
    )


# ---------------------------------------------------------------------------
# Counter-signature verification (v4 format)
# ---------------------------------------------------------------------------

def _compute_counter_sig_message(payload_bytes: bytes, primary_public_key_pem: str) -> bytes:
    """
    Return the message that the counter-signature covers.

    counter_sig_message = sha256(payload_bytes + sha256(primary_public_key_pem_bytes))

    Using the SHA-256 of the primary public key (rather than the raw PEM) as the
    binding value avoids embedding a variable-length PEM blob in the signed
    message while still tying the counter-signature irrevocably to one specific
    primary key.
    """
    pem_bytes = primary_public_key_pem.encode("utf-8")
    pem_hash = hashlib.sha256(pem_bytes).digest()
    combined = payload_bytes + pem_hash
    return hashlib.sha256(combined).digest()


def _verify_counter_signature(
    payload_bytes: bytes,
    primary_public_key_pem: str,
    counter_sig_bytes: bytes,
) -> bool:
    """
    Verify the counter-signature for a v4 license.

    Returns True on success, False on any failure (including invalid signature,
    missing key, or crypto errors).

    Skips verification and returns True when COUNTER_PUBLIC_KEY_PEM is still a
    placeholder — allows dev/CI builds to issue v4 licenses without a real
    counter-signing key.
    """
    if _integrity.is_counter_key_placeholder():
        # #103 (LICENSE-2024-001 / CVSS 9.1) — placeholder skip is NOT
        # permitted here regardless of YASHIGANI_ENV.  The dev/placeholder
        # case is already handled by _check_hash_bundle_attestation() which
        # skips bundle-sig verification in dev and fails closed in prod.
        # _verify_counter_signature() must NEVER have its own env-based skip:
        # a runtime YASHIGANI_ENV=dev override (docker run -e / Helm) must
        # not bypass counter-sig crypto in a prod image (IMPL-01).
        logger.critical(
            "License verifier: COUNTER_PUBLIC_KEY_PEM is still a placeholder "
            "— build pipeline did not embed counter key; "
            "failing counter-signature (LICENSE-2024-001 / IMPL-01)"
        )
        # Fall through — attempt to parse placeholder string as PEM,
        # which will raise an exception and trigger the return-False path.

    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
        from cryptography.hazmat.primitives.hashes import SHA256
        from cryptography.exceptions import InvalidSignature

        _raw_counter_key = load_pem_public_key(
            _integrity.COUNTER_PUBLIC_KEY_PEM.encode("utf-8")
        )
        if not isinstance(_raw_counter_key, EllipticCurvePublicKey):
            raise ValueError(
                f"Counter public key is not EC: {type(_raw_counter_key).__name__}"
            )
        counter_public_key: EllipticCurvePublicKey = _raw_counter_key
        message = _compute_counter_sig_message(payload_bytes, primary_public_key_pem)
        # message is already a 32-byte digest; sign/verify with Prehashed would
        # be cleaner but ECDSA(SHA256()) on a 32-byte input is also correct and
        # keeps the call-site identical to the primary signature path.
        counter_public_key.verify(counter_sig_bytes, message, ECDSA(SHA256()))
        return True
    except InvalidSignature:
        logger.warning("License verifier: counter-signature verification failed")
        return False
    except Exception as exc:
        logger.warning(
            "License verifier: unexpected error during counter-signature verification: %s", exc
        )
        return False


# ---------------------------------------------------------------------------
# Primary verification helpers (shared between v3 and v4)
# ---------------------------------------------------------------------------

def _verify_primary_signature(payload_bytes: bytes, sig_bytes: bytes) -> bool:
    """
    Verify the primary ECDSA P-256 signature.

    Returns True on success, False on InvalidSignature, raises on other errors.

    Note (ASVS 11.2.4): ECDSA verification via the ``cryptography`` library
    delegates to OpenSSL's constant-time C implementation. The verify() call
    raises InvalidSignature on mismatch — no timing-vulnerable byte comparison
    occurs at the Python level.

    Algorithm allowlist (Compliance review finding #11): we dispatch verify() only
    when the embedded public key is EllipticCurvePublicKey on curve SECP256R1
    (aka P-256 / NIST P-256 / prime256v1). Any other key type — even if it
    parses successfully from the bundled PEM — raises RuntimeError before
    reaching verify(). This defends against future key-type confusion when
    we add ML-DSA / Ed25519 alternative key slots to the licence format.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA,
        EllipticCurvePublicKey,
        SECP256R1,
    )
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.exceptions import InvalidSignature

    public_key = load_pem_public_key(_PUBLIC_KEY_PEM.encode("utf-8"))

    # Explicit allowlist: must be an EC public key on P-256. Refuse to verify
    # with any other key type. Without this gate the cryptography library
    # would happily accept (for example) an RSA or Ed25519 key at the same
    # PEM slot and silently change the algorithm envelope, an attack class
    # known as "key-type confusion".
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise RuntimeError(
            f"License verifier: unexpected public key type "
            f"{type(public_key).__name__}; expected EllipticCurvePublicKey"
        )
    if not isinstance(public_key.curve, SECP256R1):
        raise RuntimeError(
            f"License verifier: unexpected curve "
            f"{public_key.curve.name}; expected secp256r1"
        )

    try:
        public_key.verify(sig_bytes, payload_bytes, ECDSA(SHA256()))
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_license(content: str) -> LicenseState:
    """
    Verify a license string and return a LicenseState.

    Format detection:
        3 dot-separated segments → v4 (payload + primary sig + counter sig) — ONLY accepted format
        2 dot-separated segments → rejected: "license_format_too_old" (LAURA-V231-003)
        Anything else            → fail-open (COMMUNITY_LICENSE)

    Security behaviour:
        - v4 licenses: both primary and counter-signature must pass.
          A counter-signature failure returns LicenseState(valid=False,
          error="counter_signature_invalid") — never falls back to v3.
        - 2-segment (v3) licenses are always rejected — counter-signature is mandatory.
          This closes the LAURA-V231-003 bypass: primary-key compromise alone is not
          sufficient to issue accepted licenses.
        - Tampered verifier (integrity violation at module load): all licenses
          are downgraded to COMMUNITY tier regardless of signature validity.

    Returns COMMUNITY_LICENSE if the public key is a placeholder.
    Returns LicenseState(valid=False, error="license_format_too_old") for 2-segment licenses.
    Returns LicenseState(valid=False, error="invalid_signature") for bad primary sigs.
    Returns LicenseState(valid=False, error="counter_signature_invalid") for bad counter sigs.
    Returns LicenseState(valid=False, error="license_expired") for expired licenses.
    Returns COMMUNITY_LICENSE (fail-open) for any other parse/crypto error.

    Requires: cryptography>=42.
    """
    # If the verifier itself has been tampered with, deny all non-community access.
    if _integrity_violated:
        return COMMUNITY_LICENSE

    if _is_placeholder():
        _warn_placeholder_once()
        return COMMUNITY_LICENSE

    content = content.strip()

    # Determine format version by dot count.
    segments = content.split(".")
    if len(segments) == 3:
        return _verify_v4(segments[0], segments[1], segments[2])
    elif len(segments) == 2:
        # LAURA-V231-003: v3 format (2-segment, no counter-signature) is no longer
        # accepted. Counter-signature is mandatory; reject clearly so tooling can
        # report a useful error to the admin.
        logger.warning(
            "License verifier: rejected 2-segment license — v3 format is no longer "
            "supported; re-issue license in v4 format (LAURA-V231-003)"
        )
        return _community_invalid("license_format_too_old")
    else:
        logger.warning("License verifier: unexpected segment count (%d) in license content", len(segments))
        return COMMUNITY_LICENSE


def _verify_v4(payload_b64: str, sig_b64: str, counter_sig_b64: str) -> LicenseState:
    """Verify a v4 license (primary signature + counter-signature)."""
    try:
        payload_bytes = base64url_decode(payload_b64)
        sig_bytes = base64url_decode(sig_b64)
        counter_sig_bytes = base64url_decode(counter_sig_b64)
    except Exception as exc:
        logger.warning("License verifier: base64url decode failed: %s", exc)
        return COMMUNITY_LICENSE

    # Primary signature first.
    try:
        valid_primary = _verify_primary_signature(payload_bytes, sig_bytes)
    except Exception as exc:
        logger.warning("License verifier: unexpected error during primary verification: %s", exc)
        return COMMUNITY_LICENSE

    if not valid_primary:
        logger.warning("License verifier: primary signature verification failed (v4)")
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            return _build_license_state(payload, valid=False, error="invalid_signature")
        except Exception:
            return _community_invalid("invalid_signature")

    # Counter-signature — never fall back to v3 on failure.
    if not _verify_counter_signature(payload_bytes, _PUBLIC_KEY_PEM, counter_sig_bytes):
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            return _build_license_state(payload, valid=False, error="counter_signature_invalid")
        except Exception:
            return _community_invalid("counter_signature_invalid")

    return _parse_and_finalise(payload_bytes)


def _parse_and_finalise(payload_bytes: bytes) -> LicenseState:
    """Parse payload JSON and apply expiry check.  Called after all signatures pass."""
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        logger.warning("License verifier: JSON parse error after valid signature: %s", exc)
        return COMMUNITY_LICENSE

    try:
        license_state = _build_license_state(payload, valid=True)
    except Exception as exc:
        # Defensive catch: _build_license_state should not raise with _safe_int in place,
        # but guard against any future field additions or model changes (LAURA-V231-002).
        logger.warning(
            "License verifier: unexpected error building license state after valid signature: %s "
            "— failing to COMMUNITY tier",
            exc,
        )
        return COMMUNITY_LICENSE

    if license_state.is_expired():
        return LicenseState(
            tier=license_state.tier,
            org_domain=license_state.org_domain,
            max_agents=license_state.max_agents,
            max_end_users=license_state.max_end_users,
            max_admin_seats=license_state.max_admin_seats,
            max_orgs=license_state.max_orgs,
            features=license_state.features,
            issued_at=license_state.issued_at,
            expires_at=license_state.expires_at,
            license_id=license_state.license_id,
            valid=False,
            error="license_expired",
        )

    return license_state
