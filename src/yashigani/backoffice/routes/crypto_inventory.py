"""
Yashigani Backoffice — Cryptographic inventory endpoint (ASVS 11.1.3).

GET /admin/crypto/inventory — returns a JSON document listing every
cryptographic algorithm in use, deprecated algorithms, post-quantum
status, and compliance references.

Admin-authenticated. Useful for compliance audits and procurement teams.

Auth note (2026-05-02): Added require_admin_session dependency to the handler.
The endpoint was declared as admin-authenticated in the docstring but had no
actual auth dependency — no Depends(), no router-level guard, no middleware
covering /admin/crypto/*. The CryptoBoM is not itself a secret (it describes
algorithm choices, not key material) but exposing it unauthenticated leaks
reconnaissance data to unauthenticated callers (OWASP API1:2023 / ASVS V4.1.1).

FIPS attestation (2026-05-27 — Nico N-002 / v2.25.0 P2 B9):
Added fips_mode_active (bool) and cmvp_cert (str | None) fields to the
inventory response so operators queried by auditors can cite a runtime
artefact proving FIPS mode was active at request time.
  - fips_mode_active: True when FIPS_MODE env var is "1", False otherwise.
  - cmvp_cert: value of YASHIGANI_CMVP_CERT env var (e.g. "#4985") or None.
    Operators running a FIPS-validated image (CMVP #4985 or similar) should
    set YASHIGANI_CMVP_CERT to the applicable certificate number.
Also sets the Prometheus gauge yashigani_fips_mode_active (1/0) at module
load time so auditors can query historical FIPS status from the time-series.

Last updated: 2026-07-04T00:00:00+00:00
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from yashigani.backoffice.middleware import require_admin_session

router = APIRouter()

# ---------------------------------------------------------------------------
# Runtime FIPS attestation — read once at module load (Nico N-002)
# ---------------------------------------------------------------------------
# NOTE (Iris drift gate, v2.25.0 P2): both _FIPS_MODE_ACTIVE and the
# Prometheus gauge are set at module-load time and reflect the FIPS state at
# pod startup, NOT a live value. If an operator changes fips.mode via helm
# upgrade (or YSG_FIPS_MODE in compose) WITHOUT restarting the backoffice
# pod/container, the attestation reports the old value until the process
# recycles. This matches how every other module-level metric in this codebase
# behaves and is the intended trade-off — FIPS mode is a startup property of
# the OpenSSL provider chain, not a per-request switch.

_FIPS_MODE_ACTIVE: bool = os.environ.get("FIPS_MODE", "0") == "1"
_CMVP_CERT: str | None = os.environ.get("YASHIGANI_CMVP_CERT") or None

# Set the Prometheus gauge so auditors can query historical FIPS status.
try:
    from yashigani.metrics.registry import fips_mode_active as _fips_gauge
    _fips_gauge.set(1 if _FIPS_MODE_ACTIVE else 0)
except Exception:
    pass  # prometheus_client not installed — safe to skip

_CRYPTO_INVENTORY = {
    "algorithms": [
        {"name": "Argon2id", "usage": "password hashing", "strength": "256-bit"},
        {"name": "ECDSA P-256", "usage": "license signing", "strength": "128-bit equivalent"},
        # pgcrypto pgp_sym_encrypt uses OpenPGP symmetric format (CFB mode), NOT GCM.
        # cipher-algo=aes256 pin applied via PGP_SYM_OPTS (Issue #144).
        {"name": "AES-256-CFB (OpenPGP)", "usage": "database column encryption (pgcrypto pgp_sym_encrypt)", "strength": "256-bit"},
        # Application-layer AESGCM — distinct from the pgcrypto path above.
        {"name": "AES-256-GCM", "usage": "document pseudonymization map encryption; on-demand backup bundle encryption", "strength": "256-bit"},
        # Phase 13 (v3.1): role-tiered TOTP.  HMAC-SHA-1 is NOT deployed for
        # new enrolments — it is only a legacy-detection sentinel that triggers
        # forced re-enrolment.  Ground truth: auth/totp.py TOTP_ALGO_SHA256
        # (users, 6-digit) and TOTP_ALGO_SHA512 (admins, 8-digit).
        {"name": "HMAC-SHA-256", "usage": "TOTP digest — user tier (6-digit, 30-second period; HMAC-SHA-1 NOT deployed)", "strength": "256-bit"},
        {"name": "HMAC-SHA-512", "usage": "TOTP digest — admin tier (8-digit, 30-second period)", "strength": "512-bit"},
        {"name": "SHA-256", "usage": "HMAC email hashing", "strength": "256-bit"},
        {"name": "SHA-384", "usage": "audit chain integrity", "strength": "384-bit"},
        {"name": "X25519+ML-KEM-768", "usage": "TLS key exchange (hybrid PQ)", "strength": "256-bit + PQ"},
        {"name": "bcrypt", "usage": "agent token hashing", "strength": "184-bit"},
        {"name": "HMAC-SHA256", "usage": "email hashing, API signing", "strength": "256-bit"},
        {"name": "ChaCha20 (CSPRNG)", "usage": "session token generation (via /dev/urandom)", "strength": "256-bit"},
    ],
    "deprecated": [],
    "post_quantum": [
        "ML-KEM-768 (key exchange)",
        "ML-DSA-65 (planned for license signing)",
    ],
    "compliance": "NIST SP 800-131A Rev 2, OWASP ASVS v5 V11",
}


@router.get("/crypto/inventory")
async def crypto_inventory(session=Depends(require_admin_session)):
    """
    Return the full cryptographic algorithm inventory.
    ASVS 11.1.3 — all algorithms, strength levels, and PQ readiness.
    Requires admin session.

    Includes runtime FIPS attestation fields (Nico N-002 / v2.25.0 P2 B9):
      fips_mode_active — True if FIPS_MODE=1 is active in this container.
      cmvp_cert        — CMVP certificate number string (e.g. "#4985") or null.
    """
    payload = dict(_CRYPTO_INVENTORY)
    payload["fips_mode_active"] = _FIPS_MODE_ACTIVE
    payload["cmvp_cert"] = _CMVP_CERT
    return JSONResponse(content=payload)
