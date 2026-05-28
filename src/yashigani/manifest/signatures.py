"""
Yashigani Manifest — Signature verification (M7).

Two code paths keyed on ``signature.algorithm``:

  cosign-bundled-key  — non-FIPS / air-gap path.
                        ``cosign verify-blob --key <bundled-key>``
                        Hard FAIL on any non-zero cosign exit.
                        Bundled public key: ``keys/manifest-signing.pub``
                        (installed alongside this package).

  rsa-pss-3072-sha384 — FIPS path.
                        RSA-PSS-3072/SHA-384 via the ``cryptography`` library
                        (cryptography>=42 uses OpenSSL; in FIPS deployments the
                        OpenSSL FIPS Provider CMVP #4985 is active at process
                        start — we do NOT load the provider here; it is the
                        operator's responsibility).
                        PSS salt length: DIGEST_LENGTH (48 bytes for SHA-384),
                        per FIPS 186-5 §5.4 cap of hLen.
                        Nico review hook: see ``_verify_rsa_pss`` docstring.

Environment gate:
  YSG_REQUIRE_SIGNED_MANIFEST=
    unset / "warn"  → WARN in dev (default)
    "fail"          → FAIL (required for CI / prod)

FIPS mode algorithm gate:
  When YASHIGANI_FIPS=1, only ``rsa-pss-3072-sha384`` is permitted.
  Any other algorithm — including unknown/future values — is an
  unconditional hard-fail regardless of YSG_REQUIRE_SIGNED_MANIFEST.
  The warn/skip enforcement level does NOT apply to FIPS algorithm checks
  (FIX-2 — Nico gate).

Decisions:
  - decision #8: setrlimit v1, seccomp-bpf v2
  - Nico NICO-005: cosign blocked in FIPS mode
  - §7 conflict resolution: cosign bundled-key for non-FIPS/air-gap;
    RSA-PSS-3072 for FIPS.  Lu's keyless-Rekor is acknowledged but
    v2 only (network dependency / air-gap incompatible).

Nico review hook (M7 FIPS path):
  _verify_rsa_pss() uses cryptography.hazmat RSA-PSS + SHA-384.
  Before enabling in production FIPS mode, Nico must confirm:
    1. OpenSSL FIPS Provider CMVP #4985 is loaded (YASHIGANI_FIPS=1 gate).
    2. RSA key size is exactly 3072 bits (assert_rsa_3072 guard enforces this).
    3. PSS salt length is PSS.DIGEST_LENGTH (= hLen = 48 bytes for SHA-384),
       per FIPS 186-5 §5.4.  MAX_LENGTH MUST NOT be used in FIPS mode.
  Tag this module for Nico sign-off before any FIPS deployment.

Last updated: 2026-05-28T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Bundled cosign public key shipped alongside this package.
_BUNDLED_COSIGN_KEY: Path = Path(__file__).parent / "keys" / "manifest-signing.pub"

# Environment variable that controls signature enforcement level.
_ENV_REQUIRE_SIGNED = "YSG_REQUIRE_SIGNED_MANIFEST"

# FIPS environment variable (set by install.sh when FIPS Provider is loaded).
_ENV_FIPS = "YASHIGANI_FIPS"

# Nico review hook constant — do not remove.
_NICO_REVIEW_REQUIRED = (
    "FIPS RSA-PSS path requires Nico sign-off before production deployment. "
    "Confirm: OpenSSL FIPS Provider CMVP #4985 loaded, RSA-3072, "
    "PSS.DIGEST_LENGTH (= hLen = 48 bytes for SHA-384, per FIPS 186-5 §5.4)."
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ManifestSignatureError(ValueError):
    """Raised when manifest signature verification fails (M7)."""

    def __init__(self, detail: str, algorithm: str = "") -> None:
        self.detail = detail
        self.algorithm = algorithm
        super().__init__("[M7_signature] %s" % detail)


# ---------------------------------------------------------------------------
# Enforcement-level helpers
# ---------------------------------------------------------------------------


def _enforcement_level() -> str:
    """
    Return 'fail', 'warn', or 'skip' based on YSG_REQUIRE_SIGNED_MANIFEST.

    Default (unset / empty) = 'warn' in dev.
    Set to 'fail' for CI / prod.
    """
    val = os.environ.get(_ENV_REQUIRE_SIGNED, "").strip().lower()
    if val in ("fail", "1", "true", "yes"):
        return "fail"
    if val in ("skip", "off", "false", "0"):
        return "skip"
    return "warn"


def _is_fips_mode() -> bool:
    """Return True if YASHIGANI_FIPS=1 is set in the environment."""
    return os.environ.get(_ENV_FIPS, "").strip() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Cosign path (non-FIPS / air-gap)
# ---------------------------------------------------------------------------


def _verify_cosign(manifest_bytes: bytes, signature_hex: str) -> None:
    """
    Verify a cosign bundled-key signature.

    ``cosign verify-blob --key <bundled-key> --signature <sig-file> <manifest-file>``

    Hard FAIL on any non-zero cosign exit (Su-003 / M7).
    The bundled public key must be present at installation time.

    Args:
        manifest_bytes: The canonical manifest bytes to verify.
        signature_hex:  Hex-encoded cosign bundle / detached signature.

    Raises:
        ManifestSignatureError on any verification failure.
    """
    if not _BUNDLED_COSIGN_KEY.is_file():
        raise ManifestSignatureError(
            "bundled cosign public key not found at %s" % _BUNDLED_COSIGN_KEY,
            algorithm="cosign-bundled-key",
        )

    # Decode signature bytes from hex
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ManifestSignatureError(
            "signature_hex is not valid hex: %s" % exc,
            algorithm="cosign-bundled-key",
        ) from exc

    # Write manifest + signature to temp files (cosign requires file paths).
    # tempfile.NamedTemporaryFile is used with delete=False so we control
    # cleanup; files are removed in finally regardless.
    manifest_path: Optional[Path] = None
    sig_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as mf:
            manifest_path = Path(mf.name)
            mf.write(manifest_bytes)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as sf:
            sig_path = Path(sf.name)
            sf.write(sig_bytes)

        cmd = [
            "cosign",
            "verify-blob",
            "--key", str(_BUNDLED_COSIGN_KEY),
            "--signature", str(sig_path),
            str(manifest_path),
        ]
        result = subprocess.run(  # noqa: S603 — trusted fixed args
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise ManifestSignatureError(
                "cosign verification failed (exit %d): %s"
                % (result.returncode, result.stderr.strip()[:256]),
                algorithm="cosign-bundled-key",
            )
    except FileNotFoundError:
        raise ManifestSignatureError(
            "cosign binary not found in PATH; install cosign or set "
            "YSG_REQUIRE_SIGNED_MANIFEST=skip to bypass (dev only)",
            algorithm="cosign-bundled-key",
        )
    except subprocess.TimeoutExpired:
        raise ManifestSignatureError(
            "cosign verification timed out (30 s)",
            algorithm="cosign-bundled-key",
        )
    finally:
        if manifest_path and manifest_path.exists():
            manifest_path.unlink(missing_ok=True)
        if sig_path and sig_path.exists():
            sig_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# RSA-PSS path (FIPS)
# ---------------------------------------------------------------------------


def _assert_rsa_3072(public_key: object) -> None:
    """
    Guard: assert the RSA key is exactly 3072 bits.

    Nico review hook — do not remove this check.  CMVP #4985 (OpenSSL FIPS
    Provider) approves RSA >= 2048; RSA-3072 is the Yashigani policy floor
    (128-bit security target), not a CMVP requirement.  Smaller keys fail
    this assertion.
    """
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey  # noqa: PLC0415
    if not isinstance(public_key, RSAPublicKey):
        raise ManifestSignatureError(
            "FIPS path requires an RSA public key; got %s" % type(public_key).__name__,
            algorithm="rsa-pss-3072-sha384",
        )
    key_size = public_key.key_size
    if key_size != 3072:
        raise ManifestSignatureError(
            "FIPS RSA key must be exactly 3072 bits; got %d bits" % key_size,
            algorithm="rsa-pss-3072-sha384",
        )


def _verify_rsa_pss(
    manifest_bytes: bytes,
    signature_hex: str,
    public_key_pem: bytes,
) -> None:
    """
    Verify an RSA-PSS-3072/SHA-384 signature (FIPS path).

    # Nico review hook: THIS FUNCTION requires Nico sign-off before use in
    # production FIPS mode.  See module docstring / _NICO_REVIEW_REQUIRED.
    # PSS salt length MUST be DIGEST_LENGTH (hLen = 48 bytes for SHA-384)
    # per FIPS 186-5 §5.4.  MAX_LENGTH (333 bytes for RSA-3072/SHA-384)
    # EXCEEDS the FIPS cap and must NOT be used here.

    Args:
        manifest_bytes: The canonical manifest bytes.
        signature_hex:  Hex-encoded DER-format RSA-PSS signature.
        public_key_pem: PEM-encoded RSA-3072 public key.

    Raises:
        ManifestSignatureError on verification failure.
    """
    if not _is_fips_mode():
        # FIPS path was selected but YASHIGANI_FIPS is not set.
        # This should not happen in well-configured deployments.
        _log.warning(
            "rsa-pss-3072-sha384 signature path invoked without YASHIGANI_FIPS=1. "
            "Proceeding, but FIPS Provider may not be loaded. %s",
            _NICO_REVIEW_REQUIRED,
        )

    try:
        from cryptography.hazmat.primitives import hashes, serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    except ImportError as exc:
        raise ManifestSignatureError(
            "cryptography library not available for FIPS path: %s" % exc,
            algorithm="rsa-pss-3072-sha384",
        ) from exc

    # Decode signature
    try:
        sig_bytes = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise ManifestSignatureError(
            "signature_hex is not valid hex: %s" % exc,
            algorithm="rsa-pss-3072-sha384",
        ) from exc

    # Load the public key
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise ManifestSignatureError(
            "failed to load RSA public key: %s" % exc,
            algorithm="rsa-pss-3072-sha384",
        ) from exc

    # Nico review hook — enforce key size
    _assert_rsa_3072(public_key)

    # After _assert_rsa_3072 we know this is an RSAPublicKey; cast for mypy.
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey as _RSAPublicKey  # noqa: PLC0415
    rsa_public_key: _RSAPublicKey = public_key  # type: ignore[assignment]

    # Verify RSA-PSS / SHA-384.
    # salt_length=DIGEST_LENGTH (48 bytes for SHA-384) is mandated by
    # FIPS 186-5 §5.4 (salt length ≤ hLen).  Using MAX_LENGTH (333 bytes
    # for RSA-3072/SHA-384) would EXCEED the FIPS cap and is NOT permitted.
    try:
        rsa_public_key.verify(
            sig_bytes,
            manifest_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.DIGEST_LENGTH,
            ),
            hashes.SHA384(),
        )
    except InvalidSignature as exc:
        raise ManifestSignatureError(
            "RSA-PSS-3072/SHA-384 signature verification failed",
            algorithm="rsa-pss-3072-sha384",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise ManifestSignatureError(
            "RSA-PSS verification error: %s" % str(exc)[:256],
            algorithm="rsa-pss-3072-sha384",
        ) from exc


# ---------------------------------------------------------------------------
# Public verification dispatcher
# ---------------------------------------------------------------------------


def verify_manifest_signature(
    manifest_bytes: bytes,
    parsed: dict,
    *,
    fips_public_key_pem: Optional[bytes] = None,
) -> None:
    """
    Verify the manifest signature based on ``spec.signature.algorithm``.

    Branches on ``signature.algorithm``:
      - ``cosign-bundled-key``: runs cosign CLI against bundled public key.
      - ``rsa-pss-3072-sha384``: uses cryptography library (FIPS path).

    Enforcement level is controlled by ``YSG_REQUIRE_SIGNED_MANIFEST``:
      - ``fail``: ManifestSignatureError is raised on any failure (CI/prod).
      - ``warn`` (default): signature failures are logged as WARNING.
      - ``skip``: signature check is skipped entirely (dev/test only).

    Args:
        manifest_bytes:      The raw canonical bytes of the manifest.
        parsed:              The parsed manifest dict.
        fips_public_key_pem: Required for rsa-pss-3072-sha384 path.

    Raises:
        ManifestSignatureError: if enforcement=fail and verification fails.
    """
    level = _enforcement_level()

    # FIX-2 (Nico BLOCK): In FIPS mode, the algorithm gate is unconditional.
    # It fires BEFORE the skip-return so that a FIPS deployment with
    # YSG_REQUIRE_SIGNED_MANIFEST=skip cannot smuggle a non-FIPS algorithm
    # through.  The guard only fires when a signature block is present with a
    # non-rsa-pss-3072-sha384 algorithm.
    sig_block = (parsed.get("spec") or {}).get("signature")
    if sig_block and _is_fips_mode():
        _algorithm_early = sig_block.get("algorithm", "")
        if _algorithm_early and _algorithm_early != "rsa-pss-3072-sha384":
            raise ManifestSignatureError(
                "FIPS mode requires algorithm rsa-pss-3072-sha384; "
                "algorithm %r is not permitted in FIPS mode (Nico NICO-005 / FIX-2). "
                "This error is unconditional — YSG_REQUIRE_SIGNED_MANIFEST level does not apply."
                % _algorithm_early,
                algorithm=_algorithm_early,
            )

    if level == "skip":
        _log.info("M7: manifest signature check skipped (YSG_REQUIRE_SIGNED_MANIFEST=skip)")
        return

    if not sig_block:
        msg = (
            "manifest has no spec.signature block; "
            "all production manifests must be signed (M7 / YSG_REQUIRE_SIGNED_MANIFEST)"
        )
        if level == "fail":
            raise ManifestSignatureError(msg)
        _log.warning("M7 signature WARNING: %s", msg)
        return

    algorithm = sig_block.get("algorithm", "")
    signature_hex = sig_block.get("signature_hex", "")

    if not algorithm:
        _handle_error(
            level,
            ManifestSignatureError("spec.signature.algorithm is required (M7)", algorithm=""),
        )
        return

    if not signature_hex:
        _handle_error(
            level,
            ManifestSignatureError("spec.signature.signature_hex is required (M7)", algorithm=algorithm),
        )
        return

    # At this point, FIPS-mode non-rsa-pss-3072-sha384 is already guarded above.
    try:
        if algorithm == "cosign-bundled-key":
            # FIPS guard above already handles this case; this branch is
            # only reachable in non-FIPS mode.
            _verify_cosign(manifest_bytes, signature_hex)
            _log.info("M7: cosign-bundled-key signature verified OK")

        elif algorithm == "rsa-pss-3072-sha384":
            if fips_public_key_pem is None:
                raise ManifestSignatureError(
                    "rsa-pss-3072-sha384 path requires fips_public_key_pem to be supplied",
                    algorithm="rsa-pss-3072-sha384",
                )
            _verify_rsa_pss(manifest_bytes, signature_hex, fips_public_key_pem)
            _log.info("M7: RSA-PSS-3072/SHA-384 signature verified OK (FIPS path)")

        else:
            raise ManifestSignatureError(
                "unknown signature algorithm %r; expected cosign-bundled-key or rsa-pss-3072-sha384"
                % algorithm,
                algorithm=algorithm,
            )
    except ManifestSignatureError as exc:
        _handle_error(level, exc)


def _handle_error(level: str, exc: ManifestSignatureError) -> None:
    """Apply enforcement level: fail → re-raise; warn → log warning."""
    if level == "fail":
        raise exc
    _log.warning("M7 signature WARNING: %s", exc.detail)
