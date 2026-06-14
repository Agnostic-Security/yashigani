"""
Yashigani Auth — TOTP (RFC 6238) + 8-code recovery system.
OWASP ASVS V2.8: per-account seeds, replay prevention, one-time display.
Uses HMAC-SHA1 per RFC 6238 default for universal authenticator-app
compatibility (Google Authenticator, Authy, Microsoft Authenticator, Aegis,
1Password, etc.). HMAC-SHA1 is cryptographically secure for OTP use: SHA-1
collision attacks (SHAttered, 2017) apply to Merkle-Damgård prefix collisions
in signed certificates, not to HMAC. RFC 2104 HMAC with SHA-1 has no known
exploitable weaknesses for 6-digit OTP generation. NIST SP 800-63B and
FIPS 140-2 permit HMAC-SHA1 for TOTP. The prior SHA-256 implementation was
a usability blocker: 19/20 test users' OTP apps either silently defaulted to
SHA-1 (producing non-matching codes) or did not support SHA-256 TOTP at all.
See YSG-RISK-078.
All code comparisons use hmac.compare_digest (ASVS 11.2.4).

Last updated: 2026-06-14T00:00:00+01:00
AVA-A006 fix (2026-04-30): window_key now encodes the MATCHED window (not
always the current window). Without this, a code used at window T−1 inserted
key T−1 into the replay cache, but a replay at window T checked key T (not
cached), allowing the same code to be accepted again. Fix: derive window_key
from the matched offset's timestamp so the replay cache blocks cross-window
replays. ASVS V2.8.3.
"""
from __future__ import annotations

import base64
import hmac as _hmac_mod
import io
import secrets
import time
from dataclasses import dataclass
from typing import Optional


def _import_pyotp():
    try:
        import pyotp
        return pyotp
    except ImportError as exc:
        raise ImportError(
            "pyotp is required. Install with: pip install pyotp"
        ) from exc


def _import_qrcode():
    try:
        import qrcode
        return qrcode
    except ImportError as exc:
        raise ImportError(
            "qrcode is required. Install with: pip install qrcode[pil]"
        ) from exc


_RECOVERY_CODE_COUNT = 8
_RECOVERY_CODE_FORMAT = "{:04X}-{:04X}-{:04X}"  # XXXX-XXXX-XXXX


@dataclass
class TotpProvisioning:
    """Returned once at provisioning. Values shown once, never stored."""
    secret_b32: str             # base32 secret — display only, then discard
    provisioning_uri: str       # otpauth:// URI for QR code
    qr_code_png_b64: str        # base64-encoded PNG for browser display
    recovery_codes: list[str]   # 8 plaintext codes — display once


@dataclass
class RecoveryCodeSet:
    """Stored form of recovery codes (hashes only)."""
    hashes: list[str]           # Argon2id hash of each code
    used: list[bool]            # parallel list — True = already used


def generate_totp_secret() -> str:
    """Generate a cryptographically random base32 TOTP secret."""
    pyotp = _import_pyotp()
    return pyotp.random_base32()


def generate_provisioning(
    account_name: str,
    issuer: str = "Yashigani",
    existing_secret: Optional[str] = None,
) -> TotpProvisioning:
    """
    Generate TOTP provisioning data. Call once; display once.
    existing_secret allows re-provisioning with a forced new seed.
    """
    pyotp = _import_pyotp()
    secret = existing_secret or generate_totp_secret()
    totp = pyotp.TOTP(secret, issuer=issuer)
    uri = totp.provisioning_uri(name=account_name, issuer_name=issuer)

    qr_b64 = _generate_qr_b64(uri)
    codes = _generate_recovery_codes()

    return TotpProvisioning(
        secret_b32=secret,
        provisioning_uri=uri,
        qr_code_png_b64=qr_b64,
        recovery_codes=codes,
    )


def _constant_time_otp_check(expected: str, actual: str) -> bool:
    """
    Constant-time comparison of OTP strings (ASVS 11.2.4).
    Prevents timing side-channel attacks on TOTP verification.
    """
    return _hmac_mod.compare_digest(expected.encode("utf-8"), actual.encode("utf-8"))


def verify_totp(secret_b32: str, code: str, used_codes_cache: set[str]) -> bool:
    """
    Verify a TOTP code. Returns True on valid, unused code.
    Replay prevention: adds the MATCHED window key to used_codes_cache on success.
    Uses constant-time comparison to prevent timing side-channels (ASVS 11.2.4).

    AVA-A006 / ASVS V2.8.3 fix (2026-04-30):
    window_key is derived from the timestamp of the MATCHED offset window, not
    always the current wall-clock window.  Previously, accepting a T−1 code
    inserted key {secret}:{T-1} into the cache, but a replay at window T checked
    key {secret}:{T} (not cached) → replay succeeded.

    Now: the window_key encodes the matched window's timestamp so that:
    - A code accepted at T−1 inserts {secret}:{T-1//30}.
    - A replay at T generates the same T-1 code (±1 window accepts it) but the
      check for {secret}:{(T-1)//30} — which is the key for offset -1 — is
      already in the cache → replay is correctly rejected.
    """
    pyotp = _import_pyotp()
    totp = pyotp.TOTP(secret_b32)
    # Generate expected codes for the valid window (±1) and check replay cache
    # using the MATCHED window's key (not always current window).
    now_ts = int(time.time())
    for offset in range(-1, 2):  # valid_window=1 means [-1, 0, +1]
        candidate_ts = now_ts + offset * 30
        expected = totp.at(candidate_ts)
        if _constant_time_otp_check(expected, code):
            # Derive the replay-cache key from the matched window's slot.
            matched_window_key = f"{secret_b32}:{candidate_ts // 30}"
            if matched_window_key in used_codes_cache:
                return False  # replay of this specific window slot
            used_codes_cache.add(matched_window_key)
            return True
    return False


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
        qrcode = _import_qrcode()
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
