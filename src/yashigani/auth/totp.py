"""
Yashigani Auth — Role-tiered TOTP (RFC 4226 / RFC 6238).
OWASP ASVS V2.8: per-account seeds, replay prevention, one-time display.

ROLE TIERS (Phase 13, Yashigani 3.1):
  Users  → HMAC-SHA-256, 6 digits   (TOTP_ALGO_SHA256 / TOTP_DIGITS_USER)
  Admins → HMAC-SHA-512, 8 digits   (TOTP_ALGO_SHA512 / TOTP_DIGITS_ADMIN)

LEGACY MIGRATION:
  Pre-3.1 accounts enrolled with SHA-1/6-digit TOTP are identified by
  ``totp_algorithm == LEGACY_TOTP_ALGO`` ("SHA1") on the AccountRecord.
  The authenticate() path detects this and forces re-enrolment transparently
  (``force_totp_provision`` is set to True in the DB; the user's next login
  issues a ``totp_provision_required`` response and redirects to provisioning).
  Dual-admin safety: all admins can re-enrol concurrently — the password-only
  provisioning session is issued before TOTP is required, so no admin is
  locked out.

CRYPTO NOTES (Nico-grade):
  - Implemented directly in terms of RFC 4226 §5 (HMAC-OTP) and RFC 6238
    §4 (TOTP = time-stepped HOTP) to avoid silent algorithm mismatches that
    can occur when relying on pyotp's optional digest parameter.
  - HMAC-SHA-256/512: no known exploitable weaknesses for OTP use.
    HMAC collision resistance is independent of SHA-1 prefix attacks (RFC
    2104 §5). NIST SP 800-132 endorses HMAC-SHA-256/512.
  - Dynamic truncation: offset = HMAC[-1] & 0x0F; extract 4 bytes at that
    offset; mask 0x7FFFFFFF; mod 10^digits (RFC 4226 §5.3). Works identically
    for any HMAC digest length ≥ 20 bytes (SHA-1, SHA-256, SHA-512 all
    satisfy this).
  - Constant-time comparison via hmac.compare_digest (ASVS V11.2.4).
  - Replay prevention: matched-window key stamped in used_codes_cache
    (AVA-A006 / ASVS V2.8.3).

AUTHENTICATOR APP:
  SHA-1 is NOT supported for new enrolments. The role-tiered
  SHA-256/SHA-512 algorithms require an authenticator app that reads the
  ``algorithm`` parameter from the ``otpauth://`` URI and applies it.
  Classic Google Authenticator (SHA-1 only) is NOT compatible.

  Recommended: **agnosticOTP** — supports SHA-256/512, 6/8 digits, reads
  all standard ``otpauth://`` URI parameters. Available for iOS and Android.

Last updated: 2026-06-28T00:00:00+01:00
Phase 13: role-tiered TOTP (SHA256/6 for users, SHA512/8 for admins).
AVA-A006 fix (2026-04-30): window_key encodes the MATCHED window (ASVS V2.8.3).
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac_mod
import io
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Role-tier constants
# ---------------------------------------------------------------------------

TOTP_ALGO_SHA1: str = "SHA1"       # Legacy — triggers forced re-enrolment
TOTP_ALGO_SHA256: str = "SHA256"   # Users (Phase 13)
TOTP_ALGO_SHA512: str = "SHA512"   # Admins (Phase 13)

LEGACY_TOTP_ALGO: str = TOTP_ALGO_SHA1  # Sentinel for pre-3.1 enrolments

#: Maps account_tier → TOTP algorithm.  Missing tiers fall back to user.
ROLE_TOTP_ALGO: dict[str, str] = {
    "admin": TOTP_ALGO_SHA512,
    "user": TOTP_ALGO_SHA256,
}

#: Maps account_tier → digit count.
ROLE_TOTP_DIGITS: dict[str, int] = {
    "admin": 8,
    "user": 6,
}

TOTP_DIGITS_ADMIN: int = 8
TOTP_DIGITS_USER: int = 6

# Digest constructors keyed by algorithm name.
_DIGEST_MAP: dict[str, "type"] = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_FORMAT = "{:04X}-{:04X}-{:04X}"  # XXXX-XXXX-XXXX


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TotpProvisioning:
    """Returned once at provisioning. Values shown once, never stored."""
    secret_b32: str             # base32 secret — display only, then discard
    provisioning_uri: str       # otpauth:// URI for QR code
    qr_code_png_b64: str        # base64-encoded PNG for browser display
    recovery_codes: list[str]   # 8 plaintext codes — display once
    algorithm: str = TOTP_ALGO_SHA256   # algorithm used in this provisioning
    digits: int = TOTP_DIGITS_USER      # digit count


@dataclass
class RecoveryCodeSet:
    """Stored form of recovery codes (hashes only)."""
    hashes: list[str]           # Argon2id hash of each code
    used: list[bool]            # parallel list — True = already used


# ---------------------------------------------------------------------------
# Secret generation
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a cryptographically random base32 TOTP secret (160-bit / 20 bytes)."""
    # 20 random bytes → 160 bits → standard TOTP seed size per RFC 4226 §4.
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Raw RFC 4226 / RFC 6238 TOTP implementation
# ---------------------------------------------------------------------------

def _decode_secret(secret_b32: str) -> bytes:
    """Decode a base32 TOTP secret (padding-tolerant) to raw bytes."""
    s = secret_b32.upper().strip()
    # RFC 4648 requires padding to a multiple of 8 characters.
    padding = (-len(s)) % 8
    return base64.b32decode(s + "=" * padding)


def _totp_at(secret_b32: str, ts: int, algorithm: str, digits: int) -> str:
    """
    RFC 4226 §5 + RFC 6238 §4: compute the TOTP code for one time-slot.

    secret_b32  — base32-encoded TOTP secret.
    ts          — Unix timestamp (seconds); code is for the 30-second window
                  that contains ts (counter = ts // 30).
    algorithm   — "SHA1", "SHA256", or "SHA512".
    digits      — 6 or 8 output digits.

    Returns a zero-padded decimal string of exactly ``digits`` characters.
    """
    key = _decode_secret(secret_b32)
    counter = ts // 30
    msg = struct.pack(">Q", counter)          # 8-byte big-endian counter

    digest_fn = _DIGEST_MAP.get(algorithm.upper(), hashlib.sha256)
    h = bytearray(_hmac_mod.new(key, msg, digest_fn).digest())

    # Dynamic truncation (RFC 4226 §5.3).
    offset = h[-1] & 0x0F
    p = struct.unpack(">I", bytes(h[offset: offset + 4]))[0]
    code_int = p & 0x7FFFFFFF
    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


# ---------------------------------------------------------------------------
# Provisioning
# ---------------------------------------------------------------------------

def generate_provisioning(
    account_name: str,
    issuer: str = "Yashigani",
    existing_secret: Optional[str] = None,
    algorithm: str = TOTP_ALGO_SHA256,
    digits: int = TOTP_DIGITS_USER,
) -> TotpProvisioning:
    """
    Generate TOTP provisioning data for the given role tier. Call once; display once.

    algorithm   — "SHA256" (users) or "SHA512" (admins).
    digits      — 6 (users) or 8 (admins).
    existing_secret — supply to re-provision with the SAME secret (e.g. after a
                      forced re-enrolment on upgrade; normally omit for a fresh seed).
    """
    secret = existing_secret or generate_totp_secret()
    uri = _build_otpauth_uri(
        account_name=account_name,
        issuer=issuer,
        secret=secret,
        algorithm=algorithm,
        digits=digits,
    )
    qr_b64 = _generate_qr_b64(uri)
    codes = _generate_recovery_codes()

    return TotpProvisioning(
        secret_b32=secret,
        provisioning_uri=uri,
        qr_code_png_b64=qr_b64,
        recovery_codes=codes,
        algorithm=algorithm,
        digits=digits,
    )


def _build_otpauth_uri(
    account_name: str,
    issuer: str,
    secret: str,
    algorithm: str,
    digits: int,
    period: int = 30,
) -> str:
    """
    Build a standard otpauth:// URI per the Google Authenticator Key URI format.

    https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    All fields are explicitly encoded so the authenticator app applies the
    correct HMAC algorithm and digit count.
    """
    label = quote(f"{issuer}:{account_name}", safe="")
    params = (
        f"secret={secret}"
        f"&issuer={quote(issuer)}"
        f"&algorithm={algorithm.upper()}"
        f"&digits={digits}"
        f"&period={period}"
    )
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _constant_time_otp_check(expected: str, actual: str) -> bool:
    """
    Constant-time comparison of OTP strings (ASVS V11.2.4).
    Prevents timing side-channel attacks on TOTP verification.
    """
    return _hmac_mod.compare_digest(expected.encode("utf-8"), actual.encode("utf-8"))


def verify_totp(
    secret_b32: str,
    code: str,
    used_codes_cache: "set[str]",
    algorithm: str = TOTP_ALGO_SHA1,
    digits: int = 6,
) -> bool:
    """
    Verify a TOTP code. Returns True on valid, unused code.

    algorithm / digits — must match the algorithm and digit count used when
    the account was enrolled.  Defaults to SHA1/6 (legacy) so callers that
    have not yet been updated still work during the migration window.  New
    enrolments must pass the role-appropriate values explicitly.

    Replay prevention: adds the MATCHED window key to used_codes_cache on
    success.  AVA-A006 / ASVS V2.8.3: window_key is derived from the
    timestamp of the MATCHED offset window, not always the current wall-clock
    window, so cross-window replays are correctly blocked.

    Algorithm isolation: a code computed with the wrong algorithm or wrong
    digit count will NOT match (distinct HMAC functions / distinct moduli
    produce different code strings; constant-time comparison rejects them).
    """
    if not secret_b32 or not code:
        return False

    now_ts = int(time.time())
    algo_upper = algorithm.upper()

    for offset in range(-1, 2):  # valid_window=1 means [-1, 0, +1]
        candidate_ts = now_ts + offset * 30
        expected = _totp_at(secret_b32, candidate_ts, algo_upper, digits)
        if _constant_time_otp_check(expected, code):
            # Derive the replay-cache key from the matched window's slot.
            matched_window_key = f"{secret_b32}:{candidate_ts // 30}"
            if matched_window_key in used_codes_cache:
                return False  # replay of this specific window slot
            used_codes_cache.add(matched_window_key)
            return True
    return False


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

def generate_recovery_code_set(plaintext_codes: list[str]) -> RecoveryCodeSet:
    """Hash recovery codes for storage. Plaintext is discarded after this call."""
    from yashigani.auth.password import _hasher
    hashes = [_hasher().hash(code) for code in plaintext_codes]
    return RecoveryCodeSet(hashes=hashes, used=[False] * len(hashes))


def verify_recovery_code(
    code: str,
    code_set: RecoveryCodeSet,
) -> tuple[bool, int]:
    """
    Verify a recovery code against the stored hash set.
    Returns (matched, index). If matched, caller must mark code_set.used[index]=True.
    """
    from yashigani.auth.password import verify_password
    for i, (h, used) in enumerate(zip(code_set.hashes, code_set.used)):
        if used:
            continue
        if verify_password(code, h):
            return True, i
    return False, -1


def codes_remaining(code_set: RecoveryCodeSet) -> int:
    return sum(1 for u in code_set.used if not u)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_recovery_codes() -> list[str]:
    codes = []
    for _ in range(_RECOVERY_CODE_COUNT):
        a = secrets.randbits(16)
        b = secrets.randbits(16)
        c = secrets.randbits(16)
        codes.append(_RECOVERY_CODE_FORMAT.format(a, b, c))
    return codes


def _generate_qr_b64(uri: str) -> str:
    try:
        import qrcode  # type: ignore[import]
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        # QR generation is non-critical — return empty string if unavailable
        return ""
