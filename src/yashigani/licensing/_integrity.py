"""
License anti-tampering — integrity constants.

This module holds constants that are PLACEHOLDERS in source control and are
replaced at Docker build time by the build pipeline:

  VERIFIER_HASH
      SHA-256 hex digest of src/yashigani/licensing/verifier.py

  ENFORCER_HASH
      SHA-256 hex digest of src/yashigani/licensing/enforcer.py

  LOADER_HASH
      SHA-256 hex digest of src/yashigani/licensing/loader.py

  INTEGRITY_HASH
      SHA-256 hex digest of this file (src/yashigani/licensing/_integrity.py)

  AGENTS_REGISTRY_HASH
      SHA-256 hex digest of src/yashigani/agents/registry.py

  IDENTITY_REGISTRY_HASH
      SHA-256 hex digest of src/yashigani/identity/registry.py

  COUNTER_PUBLIC_KEY_PEM
      ECDSA P-256 public key (PEM) for the counter-signing keypair. The
      matching private key is held exclusively by the Yashigani signing
      infrastructure and never leaves it.

Placeholder sentinel
--------------------
When any constant still contains _PLACEHOLDER_INTEGRITY the verifier
treats that check as disabled (fail-open) in dev; fail-closed in prod.

Build pipeline contract
-----------------------
The build script must:
  1. Compute SHA-256(file) AFTER all edits are finalised.
  2. Replace the placeholder strings in this file with the real values.
  3. Rebuild / reinstall the package so the updated constants are imported.

Do NOT embed the real counter private key here or anywhere in the image.
"""
from __future__ import annotations

# Sentinel value. All placeholder constants must contain this string.
_PLACEHOLDER_INTEGRITY = "PLACEHOLDER_YASHIGANI_INTEGRITY"

# ---------------------------------------------------------------------------
# VERIFIER_HASH
# Replace with: sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
VERIFIER_HASH: str = _PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH"

# ---------------------------------------------------------------------------
# ENFORCER_HASH
# Replace with: sha256sum src/yashigani/licensing/enforcer.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
ENFORCER_HASH: str = _PLACEHOLDER_INTEGRITY + "_ENFORCER_HASH"

# ---------------------------------------------------------------------------
# LOADER_HASH
# Replace with: sha256sum src/yashigani/licensing/loader.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
LOADER_HASH: str = _PLACEHOLDER_INTEGRITY + "_LOADER_HASH"

# ---------------------------------------------------------------------------
# INTEGRITY_HASH (self-referential — computed over this file before replacement)
# Replace with: sha256sum src/yashigani/licensing/_integrity.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
INTEGRITY_HASH: str = _PLACEHOLDER_INTEGRITY + "_INTEGRITY_HASH"

# ---------------------------------------------------------------------------
# AGENTS_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/agents/registry.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
AGENTS_REGISTRY_HASH: str = _PLACEHOLDER_INTEGRITY + "_AGENTS_REGISTRY_HASH"

# ---------------------------------------------------------------------------
# IDENTITY_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/identity/registry.py | cut -d' ' -f1
# ---------------------------------------------------------------------------
IDENTITY_REGISTRY_HASH: str = _PLACEHOLDER_INTEGRITY + "_IDENTITY_REGISTRY_HASH"

# ---------------------------------------------------------------------------
# COUNTER_PUBLIC_KEY_PEM
# Replace with the output of:
#   python scripts/keygen.py --out-dir keys/
#   cat keys/yashigani_counter_public.pem
# ---------------------------------------------------------------------------
COUNTER_PUBLIC_KEY_PEM: str = _PLACEHOLDER_INTEGRITY + "_COUNTER_KEY"

# ---------------------------------------------------------------------------
# HASH_BUNDLE_SIG
# Replace with the ECDSA P-256 signature over SHA-256 of the canonical hash-bundle string.
# Produced by: python scripts/sign_bundle.py --key keys/yashigani_counter_private.pem
# ---------------------------------------------------------------------------
HASH_BUNDLE_SIG: str = _PLACEHOLDER_INTEGRITY + "_HASH_BUNDLE_SIG"

# ---------------------------------------------------------------------------
# EXPECTED_TOKEN_HMAC
# Replace with: SHA-256(derive_integrity_token(bundle_str, "", "20,5,2") || b"yashigani-kdf-gate-v1")
# Produced by: python scripts/compute_kdf_token.py
# ---------------------------------------------------------------------------
EXPECTED_TOKEN_HMAC: str = _PLACEHOLDER_INTEGRITY + "_EXPECTED_TOKEN_HMAC"


def is_verifier_hash_placeholder() -> bool:
    """Return True when VERIFIER_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in VERIFIER_HASH


def is_counter_key_placeholder() -> bool:
    """Return True when COUNTER_PUBLIC_KEY_PEM has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in COUNTER_PUBLIC_KEY_PEM


def is_any_hash_placeholder() -> bool:
    """Return True when ANY of the six file hashes is still a placeholder.

    Used by _check_self_integrity() to detect incomplete build pipeline runs
    in non-dev environments (GROUP-3-1 v2.23.2).
    """
    return (
        _PLACEHOLDER_INTEGRITY in VERIFIER_HASH
        or _PLACEHOLDER_INTEGRITY in ENFORCER_HASH
        or _PLACEHOLDER_INTEGRITY in LOADER_HASH
        or _PLACEHOLDER_INTEGRITY in INTEGRITY_HASH
        or _PLACEHOLDER_INTEGRITY in AGENTS_REGISTRY_HASH
        or _PLACEHOLDER_INTEGRITY in IDENTITY_REGISTRY_HASH
    )


def is_bundle_sig_placeholder() -> bool:
    """Return True when HASH_BUNDLE_SIG has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in HASH_BUNDLE_SIG


def is_kdf_token_placeholder() -> bool:
    """Return True when EXPECTED_TOKEN_HMAC has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in EXPECTED_TOKEN_HMAC


def is_enforcer_hash_placeholder() -> bool:
    """Return True when ENFORCER_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in ENFORCER_HASH


def is_loader_hash_placeholder() -> bool:
    """Return True when LOADER_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in LOADER_HASH


def is_agents_registry_hash_placeholder() -> bool:
    """Return True when AGENTS_REGISTRY_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in AGENTS_REGISTRY_HASH


def is_identity_registry_hash_placeholder() -> bool:
    """Return True when IDENTITY_REGISTRY_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in IDENTITY_REGISTRY_HASH
