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
      Self-referential SHA-256 hex digest of this file
      (src/yashigani/licensing/_integrity.py), computed with the
      "blank-then-hash" convention: the INTEGRITY_HASH line's own value and
      the BUNDLE_SIG line's own value are both replaced with a fixed
      placeholder before hashing (avoids the chicken-and-egg problem of a
      hash containing itself). Wired 2026-07-15 (LAURA-V2-002 fix — this
      constant was previously computed by the build pipeline but never
      independently re-derived or compared by anything at verify time,
      making it dead code; a docstring claim that it was "already protected
      via the enforcer cross-check" was FALSE — grepped, no such cross-check
      existed). The live re-derivation and comparison now live OUTSIDE this
      file, in verifier.py's _compute_integrity_self_hash()/
      _compute_live_hash_bundle_str() — deliberately not here, so that a
      tampered _integrity.py cannot also patch the function used to check
      it. INTEGRITY_HASH is folded in as the 6th line of the same bundle
      BUNDLE_SIG signs, which means every OTHER constant in this file
      (kill-list, client-domain registry, anchor-set, code leaf_cert/sig —
      everything except INTEGRITY_HASH's and BUNDLE_SIG's own lines) is now
      transitively covered by that signature too: editing any of them
      without re-signing invalidates either the live INTEGRITY_HASH
      comparison, the BUNDLE_SIG check, or both.

  AGENTS_REGISTRY_HASH
      SHA-256 hex digest of src/yashigani/agents/registry.py

  IDENTITY_REGISTRY_HASH
      SHA-256 hex digest of src/yashigani/identity/registry.py

Above (T1-T4 self-hash bundle): unchanged v1 mechanism — SHA-256 file
hashes, independent of the licence-hardening-v2 chain design.

Point-of-use (POU) protected files — added 2026-07-16 (LAURA-V2-001
follow-up: "replacing require_feature()'s whole body still yields the
feature"). These are the files that do the ACTUAL privileged work of a
licence-gated capability (OIDC/SAML/SCIM), not just the shared enforcer.py
gate. Each is covered by verifier.py's live, external, signed-bundle
re-derivation exactly like the T1-T4 files above — so tampering with any of
them (including deleting their own local point-of-use guard, see each
file's `_licence_hard_gate()`) is independently detected by verifier.py, a
SEPARATE file the edit never touches:

  OIDC_MODULE_HASH
      SHA-256 hex digest of src/yashigani/sso/oidc.py

  SAML_MODULE_HASH
      SHA-256 hex digest of src/yashigani/sso/saml.py

  SSO_ROUTES_HASH
      SHA-256 hex digest of src/yashigani/backoffice/routes/sso.py

  SCIM_ROUTES_HASH
      SHA-256 hex digest of src/yashigani/backoffice/routes/scim.py

  GATE_MIDDLEWARE_HASH
      SHA-256 hex digest of src/yashigani/licensing/gate_middleware.py
      (the independent ASGI-layer gate — a THIRD, cross-cutting layer,
      external to both the route file and the provider file, so patching
      either of those alone still leaves this layer blocking).

Mesh FULL topology — Phase D, 2026-07-17 (LAURA-V2-003 RE-VERIFY hardening:
Laura's independent re-verify of the Phase C ring proved "any 1-5 file edit
is caught" FALSE — she found a live, silent 3-file {verifier.py,
enforcer.py, gate_middleware.py} SCIM bypass and a 4-file {..., routes/
sso.py} SAML bypass, both well below the accepted ceiling. Root cause: a
ring only gives each file 2 neighbours; for a release's random permutation,
a specific gate's 2 neighbours often did NOT include the actual touched
files, and its fallback — verifier.get_integrity_status()/
enforcer.get_enforcer_integrity_status() — was exactly the pair already
neutered by the same edit. "Some detector fires somewhere" != "the gate
deciding THIS feature is blocked".

Fix (Phase D): verifier.py, enforcer.py, gate_middleware.py, sso/oidc.py,
sso/saml.py, backoffice/routes/sso.py, and backoffice/routes/scim.py — ALL
SEVEN files, sso/saml.py now a full member for the first time — each carry
their OWN independently-authored (distinct code shape per file — not
copy-pasted, not a shared function) inline check of EVERY OTHER mesh
member's bytes (a COMPLETE graph, not a ring: 6 peer-checks per file, not
2). Each gate's enforcement decision is derived SOLELY from its own inline
full-mesh result — none of the 5 point-of-use gates (gate_middleware.py,
oidc.py, saml.py, routes/sso.py, routes/scim.py) route their decision
through verifier.get_integrity_status()/enforcer.get_enforcer_integrity_
status() any more; those getters remain as accessors to verifier.py's/
enforcer.py's own state (used by unrelated T1-T4 aggregation in
enforcer._any_integrity_violated()), but no OTHER gate's tamper decision
depends on calling them. See verifier.py's module-level comment above
_check_mesh_full() for the full completeness rationale.

  MESH_TOPOLOGY_JSON
      {"version": "<release>", "seed": "<hex>", "member_order": [seven role
      names, a permutation of VERIFIER/ENFORCER/GATE_MIDDLEWARE/OIDC/SAML/
      SSO_ROUTES/SCIM_ROUTES]}. Deterministically derived per-release from
      (version, seed) by licensing/chain/mesh_topology.py:
      compute_mesh_order() — invoked ONLY by scripts/inject_hashes.sh at
      build time, never by any runtime file. Phase D: member_order no
      longer selects WHO checks WHOM (every member checks every other
      member unconditionally, regardless of order) — it only determines
      each file's own PEER-ITERATION order, kept for per-build
      POLYMORPHISM/strip-script resistance, not for detection completeness
      (completeness holds identically for every possible permutation, and
      would hold even with member_order fixed/absent — it is retained
      as a signed, checked constant anyway so a malformed/placeholder value
      is still treated as tamper, fail-closed in non-dev, by every mesh
      file). Transitively covered by INTEGRITY_HASH like every other
      constant in this file — no separate signature needed.

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

Root-of-trust pin (LAURA-V2-005, 2026-07-17)
---------------------------------------------
Everything in THIS file — including MASTER_ANCHOR_SET_JSON, CODE_LEAF_CERT_
JSON/SIG and BUNDLE_SIG above — is a trust STATEMENT, not a trust FACT: it
is attacker-writable local source, exactly like every other constant here.
Laura's LAURA-V2-005 finding proved that an attacker with local write access
could edit ONLY this file — mint their own master keypair, embed it as
MASTER_ANCHOR_SET_JSON, self-certify a CODE leaf under it, recompute
INTEGRITY_HASH/BUNDLE_SIG (both trivially self-consistent, since they hold
the private keys they signed with) — and self-issue an ENTERPRISE licence,
with every one of the 7 mesh files (verifier.py/enforcer.py/gate_middleware.
py/sso/oidc.py/sso/saml.py/backoffice/routes/{sso,scim}.py) reporting clean,
because none of them looks at this file's bytes at all.

Fixed by moving the root of trust OUTSIDE this file entirely:
  1. verifier.py hardcodes the REAL master anchor pubkey(s) as a Python
     literal (`_PINNED_MASTER_ANCHOR_PEMS`) and requires every anchor
     MASTER_ANCHOR_SET_JSON claims to be currently trusted to match one of
     them, by re-encoded DER bytes (`_anchor_set_is_pinned()`). A forged
     anchor set fails this regardless of internal self-consistency.
  2. Each of the 7 mesh files ALSO carries its own hardcoded expected hash
     of this file's root-of-trust fields (MASTER_ANCHOR_SET_JSON/
     CODE_LEAF_CERT_JSON/CODE_LEAF_CERT_SIG/KILL_LIST_JSON/CLIENT_DOMAIN_
     REGISTRY_JSON — see `_EXPECTED_INTEGRITY_ROOT_HASH` in each of those
     files) — this file cannot carry the expected hash of its own root data
     (circular), so the expected value lives in the mesh files instead,
     injected at build time BEFORE those files' own SHA-256 is computed.
     Edits to THIS file's root-of-trust fields alone are now caught by
     EVERY one of the 7 mesh files independently, even without touching any
     signature.
Together: an attacker can no longer substitute the root of trust by editing
only this file. Substitution now requires either the real master private
key, or a coordinated edit of this file PLUS at least one of the 7
mesh-protected files (which the existing mesh already catches).

Placeholder sentinel
--------------------
When any hash/chain constant still contains _PLACEHOLDER_INTEGRITY the
verifier treats that check as disabled (fail-open) in dev; fail-closed in
prod. KILL_LIST_JSON and CLIENT_DOMAIN_REGISTRY_JSON are the two exceptions
noted above — their unset/empty state is itself a safe value, not a
placeholder requiring build-time substitution.

Build pipeline contract (scripts/inject_hashes.sh, updated 2026-07-15 for the
LAURA-V2-001/002 fix — INTEGRITY_HASH now folded into the signed bundle)
-----------------------------------------------------------------------
The build script must, IN THIS ORDER:
  1. Compute SHA-256(file) for each of the 5 T1-T4 protected files.
  2. Mint/obtain this release's code leaf_cert + leaf_cert_sig from the
     master (Su's `licgen new-leaf` / `licgen sign-build`).
  3. Embed the current trust-anchor SET (Su's `licgen`/registry tooling) ->
     MASTER_ANCHOR_SET_JSON, plus KILL_LIST_JSON/CLIENT_DOMAIN_REGISTRY_JSON
     if provided.
  4. Compute INTEGRITY_HASH — the "blank-then-hash" self-referential digest
     of THIS file's current bytes (step 1-3 output already embedded; the
     INTEGRITY_HASH and BUNDLE_SIG lines themselves are blanked before
     hashing, so their current placeholder/prior values don't matter) —
     using the SAME algorithm as verifier._compute_integrity_self_hash().
     Embed it.
  5. Build the SIX-line canonical bundle string (5 T1-T4 hashes +
     INTEGRITY_HASH, sorted by key) and sign it with the code leaf ->
     BUNDLE_SIG. Embed it (this write does NOT change what INTEGRITY_HASH
     would recompute to, since BUNDLE_SIG's own line is blanked).
  6. Assert no placeholder strings remain, then rebuild / reinstall the
     package so the updated constants are imported.

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
VERIFIER_HASH: str = "672a953affc17dca342506c996d29cca693c8613f453be123acc7d1a7764629d"

# ENFORCER_HASH
# Replace with: sha256sum src/yashigani/licensing/enforcer.py | cut -d' ' -f1
ENFORCER_HASH: str = "1584d7da63903cfab926aba639bc08c90b3249c3180af9ca0a3864c2e8fa85d1"

# LOADER_HASH
# Replace with: sha256sum src/yashigani/licensing/loader.py | cut -d' ' -f1
LOADER_HASH: str = "b2210667a345b82969014440d17d8ea2624732793d9c8f528d0ceb2ed4aa7034"

# INTEGRITY_HASH (self-referential — computed over this file before replacement)
# Replace with: sha256sum src/yashigani/licensing/_integrity.py | cut -d' ' -f1
INTEGRITY_HASH: str = "ec06279b9f8a21e8a9261af4154e660d92e0da2623a9f63a0756e6312d140d2d"

# AGENTS_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/agents/registry.py | cut -d' ' -f1
AGENTS_REGISTRY_HASH: str = "869174fbc128dddcadde3df98c1f550e1cb42abeedc68864cfe0ab548757e177"

# IDENTITY_REGISTRY_HASH
# Replace with: sha256sum src/yashigani/identity/registry.py | cut -d' ' -f1
IDENTITY_REGISTRY_HASH: str = "4552eb7a567cc5f3dd82f8a49b2bb8a9a6bd9dccf9bc16f3ba8f3759e15d71ad"

# ---------------------------------------------------------------------------
# Point-of-use (POU) protected-file hashes — 2026-07-16, LAURA-V2-001
# follow-up. Same mechanism as T1-T4 above; separate section only to keep
# the historical T1-T4 naming intact.
# ---------------------------------------------------------------------------

# OIDC_MODULE_HASH
# Replace with: sha256sum src/yashigani/sso/oidc.py | cut -d' ' -f1
OIDC_MODULE_HASH: str = "95decf0af5940f0883385fd8880a756405eaa15c0a9c50c510e05bf6ad7f38bf"

# SAML_MODULE_HASH
# Replace with: sha256sum src/yashigani/sso/saml.py | cut -d' ' -f1
SAML_MODULE_HASH: str = "6ec6de22026f3087653eed3374449a612a366271ea1af3eae98354331a9ab98d"

# SSO_ROUTES_HASH
# Replace with: sha256sum src/yashigani/backoffice/routes/sso.py | cut -d' ' -f1
SSO_ROUTES_HASH: str = "4220eb6865a35e9badd6f3c680ec307495202f1a95fdb2ea0685d0ea5966536d"

# SCIM_ROUTES_HASH
# Replace with: sha256sum src/yashigani/backoffice/routes/scim.py | cut -d' ' -f1
SCIM_ROUTES_HASH: str = "5cba251290f9769553b2a381cfb07806a81a6617b31e507b30cb6d4a3884b530"

# GATE_MIDDLEWARE_HASH
# Replace with: sha256sum src/yashigani/licensing/gate_middleware.py | cut -d' ' -f1
GATE_MIDDLEWARE_HASH: str = "b43d82ed8072e3a2ccbc5429dd1582e03a6a2433ec28ab4c4cbc76d41efa3d0d"

# ---------------------------------------------------------------------------
# Mesh FULL topology — Phase D, 2026-07-17 (LAURA-V2-003 RE-VERIFY
# hardening, complete graph over 7 members, supersedes Phase C's ring). See
# module docstring above. Computed ONLY by scripts/inject_hashes.sh via
# licensing/chain/mesh_topology.py:compute_mesh_order() — never at runtime.
# ---------------------------------------------------------------------------

# MESH_TOPOLOGY_JSON
# Emit via: PYTHONPATH=src python3 -c "from yashigani.licensing.chain.mesh_topology
# import compute_mesh_order; import json; print(json.dumps({'version': V,
# 'seed': S, 'member_order': compute_mesh_order(V, S)}))"  (scripts/inject_hashes.sh
# Step 3c does this automatically; MESH_SEED auto-generates if unset).
MESH_TOPOLOGY_JSON: str = "{\"member_order\":[\"GATE_MIDDLEWARE\",\"VERIFIER\",\"OIDC\",\"SSO_ROUTES\",\"SCIM_ROUTES\",\"SAML\",\"ENFORCER\"],\"seed\":\"29097ff64ef4e63d667eec33443f7e3c\",\"version\":\"0.0.0-unset\"}"

# ---------------------------------------------------------------------------
# Licence-hardening-v2 chain constants (design §2.2/§3.1/§3.3, §4a)
# ---------------------------------------------------------------------------

# MASTER_ANCHOR_SET_JSON
# Emit via: licgen anchor-set emit  (Su tooling — design "MASTER-ROTATION READINESS")
MASTER_ANCHOR_SET_JSON: str = "[{\"added\":\"2026-07-28T00:24:12.849409+00:00\",\"alg\":\"ecdsa-p384-sha384\",\"anchor_id\":\"M-v5-demo\",\"pubkey_pem\":\"-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbSQPx0WXGRjO5/gkr0eKKAw8mTKXH/n8\\nKA0OSke+edue6ZepTzBbBUvwBPtQ7CL+wZguuUuOgOpvCUPpyJglQyY/2EQrrAIA\\nPmJOWvM1TdxpDHpBNvBenQKH+Mm5RA4m\\n-----END PUBLIC KEY-----\\n\",\"status\":\"active\"}]"

# CODE_LEAF_CERT_JSON
# Emit via: licgen new-leaf --channel prod --version <x.y.z>
CODE_LEAF_CERT_JSON: str = "{\"alg\":\"ecdsa-p384-sha384\",\"client_id\":\"*\",\"csr_pop\":{\"client_id\":\"*\",\"csr_self_sig\":\"MGYCMQDOBXOsT8BrlH6lV5xCrz6Ar02USyvI777VAOtCVJwcCdpALwjscNyoQBKygPJhNXQCMQD+UOEqvN3wz5Hf3fKfJECSR5mCP3V6su4rc+gFCnb9jY16a9hfqNM0e9o41Ji/QP8=\",\"leaf_pubkey_pem\":\"-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEi/nzaxBlSb7WpWczQPKkqXPQIzawBJW2\\nBeXEnkduARFM9rwt80w7b9mb9D4/Yg9XOn2zJiLG7dVgErchcrlDMpv0LS+FLUMA\\nyIz+lhUoT49fXGANnqanswcMbBcMglW0\\n-----END PUBLIC KEY-----\\n\",\"role\":\"code\"},\"leaf_pubkey_pem\":\"-----BEGIN PUBLIC KEY-----\\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEi/nzaxBlSb7WpWczQPKkqXPQIzawBJW2\\nBeXEnkduARFM9rwt80w7b9mb9D4/Yg9XOn2zJiLG7dVgErchcrlDMpv0LS+FLUMA\\nyIz+lhUoT49fXGANnqanswcMbBcMglW0\\n-----END PUBLIC KEY-----\\n\",\"not_after\":\"2026-08-27T00:24:35.897246+00:00\",\"not_before\":\"2026-07-28T00:24:35.897246+00:00\",\"release\":\"5.0.0\",\"role\":\"code\",\"serial\":\"code-5.0.0-20260728002435\",\"signed_at\":\"2026-07-28T00:24:35.897246+00:00\"}"

# CODE_LEAF_CERT_SIG
# Emitted alongside CODE_LEAF_CERT_JSON by the same `licgen new-leaf` call — the
# master's signature over CODE_LEAF_CERT_JSON's signing digest.
CODE_LEAF_CERT_SIG: str = "MGYCMQCcY8pM4eJD8Uocpx3JEsqWd6WPHrVzS5qeiZ0vKWtZZVeyX7g4vihL0SFUdRu2RLcCMQDi45EX63Ub8AConMW1+W8RZuVB2RIu98etEyQBSMFik7927NWCual/7v1P65mj32c="

# BUNDLE_SIG
# Emit via: licgen sign-build --channel prod --version <x.y.z>
# (supersedes the v1 HASH_BUNDLE_SIG produced by scripts/sign_bundle.py against
# the old counter key — same constant name, new chain-based signer/scheme).
BUNDLE_SIG: str = "MGQCMFUHPTLK6lep9FkDiezTehg4tm7HhfxzKC4cWZb93lso0CMLBPPHCGcKRDe0tlPlswIwByWuXzXOy+RuL/FmV43tlrQFntYXyl+FwLxqeU6HdILNH0x8mRJ5azjg+Be7lZV2"

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
    """Return True when ANY of the eleven T1-T4 + POU file hashes is still a
    placeholder.

    Used by _check_self_integrity() to detect incomplete build pipeline runs
    in non-dev environments (GROUP-3-1 v2.23.2). Extended 2026-07-16
    (LAURA-V2-001 follow-up) to also cover the point-of-use protected files
    (OIDC/SAML/SSO-routes/SCIM-routes/gate-middleware) — an incomplete build
    that never embedded THEIR hashes must fail closed exactly like a missing
    ENFORCER_HASH does today.
    """
    return (
        _PLACEHOLDER_INTEGRITY in VERIFIER_HASH
        or _PLACEHOLDER_INTEGRITY in ENFORCER_HASH
        or _PLACEHOLDER_INTEGRITY in LOADER_HASH
        or _PLACEHOLDER_INTEGRITY in INTEGRITY_HASH
        or _PLACEHOLDER_INTEGRITY in AGENTS_REGISTRY_HASH
        or _PLACEHOLDER_INTEGRITY in IDENTITY_REGISTRY_HASH
        or _PLACEHOLDER_INTEGRITY in OIDC_MODULE_HASH
        or _PLACEHOLDER_INTEGRITY in SAML_MODULE_HASH
        or _PLACEHOLDER_INTEGRITY in SSO_ROUTES_HASH
        or _PLACEHOLDER_INTEGRITY in SCIM_ROUTES_HASH
        or _PLACEHOLDER_INTEGRITY in GATE_MIDDLEWARE_HASH
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


def is_oidc_module_hash_placeholder() -> bool:
    """Return True when OIDC_MODULE_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in OIDC_MODULE_HASH


def is_saml_module_hash_placeholder() -> bool:
    """Return True when SAML_MODULE_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in SAML_MODULE_HASH


def is_sso_routes_hash_placeholder() -> bool:
    """Return True when SSO_ROUTES_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in SSO_ROUTES_HASH


def is_scim_routes_hash_placeholder() -> bool:
    """Return True when SCIM_ROUTES_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in SCIM_ROUTES_HASH


def is_gate_middleware_hash_placeholder() -> bool:
    """Return True when GATE_MIDDLEWARE_HASH has not been set at build time."""
    return _PLACEHOLDER_INTEGRITY in GATE_MIDDLEWARE_HASH


def is_mesh_topology_placeholder() -> bool:
    """Return True when MESH_TOPOLOGY_JSON has not been set at build time.

    Checked independently by each of the 7 mesh full-check files
    (LAURA-V2-003 Phase D hardening) before trusting the member order it
    encodes — a placeholder/missing topology is treated as tamper
    (fail-closed in non-dev), never silently skipped."""
    return _PLACEHOLDER_INTEGRITY in MESH_TOPOLOGY_JSON


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
