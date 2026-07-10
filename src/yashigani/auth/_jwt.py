"""
Per-tenant JWT signing key isolation — YSG-RISK-109.

Provides HKDF-based derivation of per-tenant ES384 (ECDSA P-384) signing keys
from a single install-wide root key.  Each tenant gets a cryptographically
independent P-384 key: knowing any one derived key yields no information about
another tenant's key or the root key (HKDF one-way PRF property).

Derivation spec (Nico-aligned):
  Algorithm : HKDF-SHA384 (RFC 5869)
  IKM       : 48-byte big-endian encoding of root key's private scalar
  salt      : b"yashigani-tenant-jwt-v1" (fixed, context-specific)
  info      : b"tenant:" + tenant_id.encode("utf-8")
  length    : 64 bytes (512 bits) — reduction mod n gives per-value bias
              < 2^{-128} (NIST SP 800-56A §6.3.2.2 compliant)
  output d  : int.from_bytes(hkdf_output, "big") % secp384r1_order
              if d == 0 → d = 1  (probability ≈ 2^{-384}; logged as anomaly)
  tenant_key: ec.derive_private_key(d, SECP384R1())

Security properties:
  Tenant isolation  — different tenant_id values yield statistically
                      independent P-384 keys; cross-tenant forgery is infeasible.
  One-way           — the root key cannot be recovered from any derived key.
  Deterministic     — same root + tenant_id always yields the same key,
                      enabling consistent kid across replicas (Nico kid-stability).

Residuals (documented in YSG-RISK-109):
  Root key compromise — if the install-wide root key is leaked, all tenant keys
    can be re-derived (deterministic construction).  Mitigated by KMS-backed
    root key with HSM binding in production (Nico §2 requirement).
  YASHIGANI_INTERNAL_BEARER — remains install-wide; per-tenant scoping deferred
    (would require Caddyfile + agent-bundle changes). Tracked as YSG-RISK-109 residual.
  caddy_internal_hmac — step-up JWTs and operator tokens remain install-wide.
    Tracked as YSG-RISK-109 residual.

Usage (McpJwtIssuer — mcp/_jwt.py):
  After loading the root key via env / file / ephemeral, call:
    tenant_key = derive_tenant_ec_key(root_key, self._tenant_id)
  and use tenant_key as the actual signing / public key for this issuer instance.
"""
from __future__ import annotations

import logging
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    SECP384R1,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Curve constants
# ---------------------------------------------------------------------------

# secp384r1 / NIST P-384 curve order n
# Source: NIST FIPS 186-5, Appendix D.1.2.4 / SEC2 v2.0 §2.6.1
# Hex : FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC7634D81F4372D
#        DF581A0DB248B0A77AECEC196ACCC52973
# This is a well-known, publicly specified constant; any change to this value
# is a critical security defect (tokens become unverifiable or forgeable).
_SECP384R1_ORDER: int = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
)

# ---------------------------------------------------------------------------
# Derivation context constants
# ---------------------------------------------------------------------------

#: Fixed salt for all Yashigani tenant-key derivations (context-specific binding).
#: Never change this value on a deployed system — it would invalidate all JWKS.
_HKDF_SALT: bytes = b"yashigani-tenant-jwt-v1"

#: Info prefix — per-tenant diversification.
_HKDF_INFO_PREFIX: bytes = b"tenant:"

#: HKDF output length (bytes).  64 bytes (512 bits) gives bias < 2^{-128} after
#: reduction mod the 384-bit secp384r1 order n.
_HKDF_OUTPUT_BYTES: int = 64


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def derive_tenant_ec_key(
    root_key: EllipticCurvePrivateKey,
    tenant_id: str,
) -> EllipticCurvePrivateKey:
    """
    Derive a deterministic, per-tenant P-384 signing key from *root_key*.

    Parameters
    ----------
    root_key:
        Install-wide P-384 root key (loaded from docker secret / KMS / env).
        Must be a secp384r1 key.

    tenant_id:
        Non-empty string that identifies the tenant.  Different values yield
        cryptographically independent keys; the same value always yields the
        same key (from the same root).

    Returns
    -------
    EllipticCurvePrivateKey
        A fresh secp384r1 private key scoped to *tenant_id*.

    Raises
    ------
    TypeError
        If *root_key* is not an EllipticCurvePrivateKey.
    ValueError
        If *root_key* does not use the secp384r1 curve, or if *tenant_id* is
        empty.

    Notes
    -----
    The HKDF is applied to the *private scalar* of the root key (48-byte
    big-endian encoding), not to the PEM bytes.  This ensures the derivation
    is independent of PEM encoding choices.
    """
    if not isinstance(root_key, EllipticCurvePrivateKey):
        raise TypeError(
            f"root_key must be an EllipticCurvePrivateKey; got {type(root_key).__name__}"
        )
    if not isinstance(root_key.curve, SECP384R1):
        raise ValueError(
            f"root_key must use secp384r1 (P-384); "
            f"got {type(root_key.curve).__name__}. "
            "Nico spec §1: ES384 only."
        )
    if not tenant_id or not tenant_id.strip():
        raise ValueError(
            "tenant_id must be a non-empty string for per-tenant key derivation."
        )

    # --- Step 1: extract IKM from root key private scalar ---
    # EllipticCurvePrivateNumbers.private_value is the private scalar d ∈ [1, n-1].
    # We encode it as 48 bytes (the byte length of P-384 integers, big-endian).
    root_private_value: int = root_key.private_numbers().private_value
    ikm: bytes = root_private_value.to_bytes(48, "big")

    # --- Step 2: HKDF-SHA384 with tenant-specific info ---
    info: bytes = _HKDF_INFO_PREFIX + tenant_id.encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=_HKDF_OUTPUT_BYTES,
        salt=_HKDF_SALT,
        info=info,
    )
    derived: bytes = hkdf.derive(ikm)

    # --- Step 3: reduce mod n to produce the tenant private scalar ---
    # 512-bit input mod 384-bit order: bias ≈ 2^{-128}; negligible.
    d: int = int.from_bytes(derived, "big") % _SECP384R1_ORDER
    if d == 0:
        # Probability ≈ 2^{-384}: effectively impossible in practice.
        # If it ever occurs, a zero private scalar indicates a severe anomaly
        # (would violate the curve constraint d ∈ [1, n-1]).
        _log.warning(
            "derive_tenant_ec_key: HKDF produced d=0 for tenant_id=%r (P ~2^-384). "
            "Using d=1 as a safe fallback.  This is a configuration anomaly; "
            "rotate the root key immediately and report to security@agnosticsec.com.",
            tenant_id,
        )
        d = 1

    return ec.derive_private_key(d, SECP384R1())


class TenantJwtKeyStore:
    """
    In-process cache of per-tenant P-384 signing keys derived from a single root.

    Construct once at process startup with the install-wide root key (loaded
    from /run/secrets/mcp_identity_signing_key or equivalent KMS).  Call
    :meth:`get_key` to retrieve (or lazily derive-and-cache) the per-tenant key.

    Thread-safety: derivation is deterministic and the cache is a plain dict.
    In CPython, dict reads/writes under the GIL are safe from data races for
    single-assignment values.  If multi-threaded use without the GIL becomes
    a concern, wrap ``_cache`` access with a threading.Lock.

    Example::

        store = TenantJwtKeyStore(root_key)
        key_a = store.get_key("tenant-a")
        key_b = store.get_key("tenant-b")
        assert key_a != key_b            # cryptographically independent
        assert store.get_key("tenant-a") is key_a  # cached — same object

    Residual (YSG-RISK-109): the root key is held in memory.  Compromise of
    the process memory leaks all derived keys.  In production the root key
    should be KMS-backed so the raw private scalar never appears in process
    memory beyond the derivation step.
    """

    def __init__(self, root_key: EllipticCurvePrivateKey) -> None:
        if not isinstance(root_key, EllipticCurvePrivateKey):
            raise TypeError(
                f"TenantJwtKeyStore: root_key must be an EllipticCurvePrivateKey; "
                f"got {type(root_key).__name__}"
            )
        if not isinstance(root_key.curve, SECP384R1):
            raise ValueError(
                f"TenantJwtKeyStore: root_key must use secp384r1; "
                f"got {type(root_key.curve).__name__}"
            )
        self._root = root_key
        self._cache: dict[str, EllipticCurvePrivateKey] = {}

    def get_key(self, tenant_id: str) -> EllipticCurvePrivateKey:
        """
        Return the derived P-384 key for *tenant_id*.

        On first call for a given *tenant_id*, derives and caches the key.
        Subsequent calls return the cached key (same object) without re-deriving.
        """
        if tenant_id not in self._cache:
            self._cache[tenant_id] = derive_tenant_ec_key(self._root, tenant_id)
            _log.debug(
                "TenantJwtKeyStore: derived + cached signing key for tenant_id=%r",
                tenant_id,
            )
        return self._cache[tenant_id]

    @property
    def tenant_ids(self) -> list[str]:
        """Return the list of tenant_ids whose keys are currently cached."""
        return list(self._cache.keys())
