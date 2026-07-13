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

Above (T1-T4 self-hash bundle): unchanged v1 mechanism — SHA-256 file
hashes, independent of the licence-hardening-v2 chain design.

Licence-hardening-v2 chain constants (design doc §2.2/§3.1/§3.3 — supersede
the v1 COUNTER_PUBLIC_KEY_PEM/HASH_BUNDLE_SIG/EXPECTED_TOKEN_HMAC scheme
this build embedded before):

  MASTER_ANCHOR_SET_JSON
      JSON list of anchor_set_entry dicts (design §2.2) — the embedded
      trust-anchor SET every build ships. Each entry:
      {"anchor_id", "pubkey_pem", "alg", "status", "added"}.
      Parsed via chain.build_integrity.anchor_set_from_json().

  CODE_LEAF_CERT_JSON
      This release's code-role leaf_cert (design §3.1), canonical dict as
      JSON. Parsed via chain.build_integrity.leaf_cert_from_json().

  CODE_LEAF_CERT_SIG
      base64 — the MASTER's signature over CODE_LEAF_CERT_JSON's signing
      digest (design §3.1: leaf_cert_sig = Signer(master).sign(digest)).

  BUNDLE_SIG
      base64 — the release's code leaf's signature over the six-file hash
      bundle (design §3.3: bundle_sig = Signer(code leaf).sign(digest)).
      Verified via chain.build_integrity.verify_build_integrity_chain().

  KILL_LIST_JSON
      JSON list of kill-list entries (design §6.1), bundled with each
      release. Defaults to "[]" (empty — a SAFE default, unlike the
      anchor-set/leaf-cert/sig placeholders above, which must fail-closed
      when unset). Parsed via chain.build_integrity.kill_list_from_json().

  CLIENT_DOMAIN_REGISTRY_JSON
      JSON object {client_id: registered_org_domain}. Defaults to "{}"
      (empty — a SAFE default; verify_licence_v5()'s org_domain-registry
      binding degrades gracefully to "not enforced for this client" when
      there is no entry, per the SEAM note in chain/licence_v5.py — this
      registry is not yet populated by any build-tooling in Phase B-CORE;
      Su's licgen/registry work is the intended writer).

Placeholder sentinel
--------------------
When any hash/chain constant still contains _PLACEHOLDER_INTEGRITY the
verifier treats that check as disabled (fail-open) in dev; fail-closed in
prod. KILL_LIST_JSON and CLIENT_DOMAIN_REGISTRY_JSON are the two exceptions
noted above — their unset/empty state is itself a safe value, not a
placeholder requiring build-time substitution.

Build pipeline contract
-----------------------
The build script must:
  1. Compute SHA-256(file) AFTER all edits are finalised (T1-T4 hashes).
  2. Mint/obtain this release's code leaf_cert + leaf_cert_sig from the
     master (Su's `licgen new-leaf` / `licgen sign-build`).
  3. Sign the six-file hash bundle with the code leaf -> BUNDLE_SIG.
  4. Emit the current trust-anchor SET (Su's `licgen`/registry tooling) ->
     MASTER_ANCHOR_SET_JSON.
  5. Replace the placeholder strings in this file with the real values.
  6. Rebuild / reinstall the package so the updated constants are imported.

Do NOT embed any private key here or anywhere in the image — only public
keys, certs, and signatures.
"""
from __future__ import annotations

# Sentinel value. All placeholder constants must contain this string.
_PLACEHOLDER_INTEGRITY = "PLACEHOLDER_YASHIGANI_INTEGRITY"

# ---------------------------------------------------------------------------
# T1-T4 per-module self-hashes (v1 mechanism, unchanged by licence-hardening-v2)
# ---------------------------------------------------------------------------

# VERIFIER_HASH
# Replace with: sha256sum src/yashigani/licensing/verifier.py | cut -d' ' -f1
VERIFIER_HASH: str = _PLACEHOLDER_INTEGRITY + "_VERIFIER_HASH"

# ENFORCER_HASH
# Replace with: sha256sum src/yashigani/licensing/enforcer.py | cut -d' ' -f1
ENFORCER_HASH: str = _PLACEHOLDER_INTEGRITY + "_ENFORCER_HASH"

# LOADER_HASH
# Replace with: sha256sum src/yashigani/licensing/loader.py | cut -d' ' -f1
LOADER_HASH: str = _PLACEHOLDER_INTEGRITY + "_LOADER_HASH"

# INTEGRITY_HASH (self-referential — computed over this file before replacement)
# Replace with: sha256sum src/yashigani/licensing/_integrity.py | cut -d' ' -f1
INTEGRITY_HASH: str = _PLACEHOLDER_INTEGRITY + "_INTEGRITY_HASH"

# AGENTS_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/agents/registry.py | cut -d' ' -f1
AGENTS_REGISTRY_HASH: str = _PLACEHOLDER_INTEGRITY + "_AGENTS_REGISTRY_HASH"

# IDENTITY_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/identity/registry.py | cut -d' ' -f1
IDENTITY_REGISTRY_HASH: str = _PLACEHOLDER_INTEGRITY + "_IDENTITY_REGISTRY_HASH"

# ---------------------------------------------------------------------------
# Licence-hardening-v2 chain constants (design §2.2/§3.1/§3.3, §4a)
# ---------------------------------------------------------------------------

# MASTER_ANCHOR_SET_JSON
# Emit via: licgen anchor-set emit  (Su tooling — design "MASTER-ROTATION READINESS")
MASTER_ANCHOR_SET_JSON: str = _PLACEHOLDER_INTEGRITY + "_MASTER_ANCHOR_SET_JSON"

# CODE_LEAF_CERT_JSON
# Emit via: licgen new-leaf --channel prod --version <x.y.z>
CODE_LEAF_CERT_JSON: str = _PLACEHOLDER_INTEGRITY + "_CODE_LEAF_CERT_JSON"

# CODE_LEAF_CERT_SIG
# Emitted alongside CODE_LEAF_CERT_JSON by the same `licgen new-leaf` call — the
# master's signature over CODE_LEAF_CERT_JSON's signing digest.
CODE_LEAF_CERT_SIG: str = _PLACEHOLDER_INTEGRITY + "_CODE_LEAF_CERT_SIG"

# BUNDLE_SIG
# Emit via: licgen sign-build --channel prod --version <x.y.z>
# (supersedes the v1 HASH_BUNDLE_SIG produced by scripts/sign_bundle.py against
# the old counter key — same constant name, new chain-based signer/scheme).
BUNDLE_SIG: str = _PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"

# KILL_LIST_JSON
# Bundled with every release. SAFE DEFAULT: "[]" (empty — nothing revoked).
# This is NOT a fail-closed placeholder like the constants above; an
# unpopulated kill-list is a legitimate, safe state (see module docstring).
KILL_LIST_JSON: str = "[]"

# CLIENT_DOMAIN_REGISTRY_JSON
# {client_id: registered_org_domain}. SAFE DEFAULT: "{}" (empty — see
# chain/licence_v5.py's SEAM note; verify_licence_v5() degrades gracefully
# per-client when this registry has no entry for that client).
CLIENT_DOMAIN_REGISTRY_JSON: str = "{}"


def is_verifier_hash_placeholder() -> bool:
    """Return True when VERIFIER_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in VERIFIER_HASH


def is_any_hash_placeholder() -> bool:
    """Return True when ANY of the six T1-T4 file hashes is still a placeholder.

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


def is_master_anchor_set_placeholder() -> bool:
    """Return True when MASTER_ANCHOR_SET_JSON has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in MASTER_ANCHOR_SET_JSON


def is_code_leaf_cert_placeholder() -> bool:
    """Return True when CODE_LEAF_CERT_JSON has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in CODE_LEAF_CERT_JSON


def is_code_leaf_cert_sig_placeholder() -> bool:
    """Return True when CODE_LEAF_CERT_SIG has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in CODE_LEAF_CERT_SIG


def is_bundle_sig_placeholder() -> bool:
    """Return True when BUNDLE_SIG has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in BUNDLE_SIG


def is_any_chain_placeholder() -> bool:
    """Return True when ANY of the chain-based build-integrity constants
    (anchor set / code leaf cert / leaf cert sig / bundle sig) is still a
    placeholder. Used by verifier.py's build-integrity chain check
    (§4a) at module load — mirrors is_any_hash_placeholder()'s role for
    the T1-T4 bundle. KILL_LIST_JSON and CLIENT_DOMAIN_REGISTRY_JSON are
    deliberately excluded (see module docstring — their unset state is a
    safe default, not a placeholder)."""
    return (
        is_master_anchor_set_placeholder()
        or is_code_leaf_cert_placeholder()
        or is_code_leaf_cert_sig_placeholder()
        or is_bundle_sig_placeholder()
    )
