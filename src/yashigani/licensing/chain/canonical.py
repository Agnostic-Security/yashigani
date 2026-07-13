"""
Yashigani licence-hardening v2 — canonical serialisation + domain separation.

Ref: design doc "FINAL MODEL" + ROUND-3/ROUND-4 fixes:
    "strict-JSON canonicalisation (sort_keys, separators=(",",":"), ensure_ascii,
     PEM as a JSON string); domain-separation context tags ... prefixed before
     hashing in each context."

Every signed structure in the chain (leaf_cert, licence payload, build bundle,
audit checkpoint) is hashed as:

    digest = SHA384( context_tag_bytes || <context-specific bytes> )

The context tag is ALWAYS the first thing hashed. This prevents cross-context
signature reuse — a leaf_cert signature can never be replayed as a valid
licence-payload signature (or vice versa) because the tag is baked into what
was actually signed, not carried alongside it as an unsigned label.

Hashing floor: SHA-384 everywhere in this module (design doc: "SHA-512 at the
top tier, SHA-384 hard floor, everywhere ... SHA-256 retired from this
design"). SHA-512 is exposed for callers that explicitly want the top tier
(none inside Phase A) but is not the default.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

# ---------------------------------------------------------------------------
# Domain-separation context tags (design doc, verbatim).
# ---------------------------------------------------------------------------
CTX_LEAF_CERT = "YSG-LEAF-CERT-v1"
CTX_LICENCE_PAYLOAD = "YSG-LICENCE-PAYLOAD-v5"
CTX_BUNDLE = "YSG-BUNDLE-v2"
# Audit checkpoint tag (design doc references "the audit checkpoint tag" without
# pinning a literal string outside the unified-chain build; -v1 chosen here so
# Captain's audit-leaf work (round-4 unified chain) has a stable constant to
# import rather than inventing its own. Flagged in the Phase A report as a
# naming choice, not a locked decision — trivial to bump to -v2 pre-ship if
# Nico/Tiago want a different literal.
CTX_AUDIT_CHECKPOINT = "YSG-AUDIT-CHECKPOINT-v1"
# Generic leaf-provisioning CSR/PoP tag (Phase B / Su, licence-hardening-v2 dispatch
# "Master signs the leaf_cert ... csr_pop"). Generalises LOCKED DECISIONS bullet 9
# ("Leaf provisioning uses a self-signed CSR (proof-of-possession)") to CODE and
# LICENCE leaf minting (keygen.py / licgen new-leaf). Deliberately DISTINCT from
# "YSG-AUDIT-CSR-v1" (§3.4.1) — that literal tag is reserved for the audit-leaf
# onboarding CSR tool, which is explicit Phase C / out-of-scope here; using a
# different tag avoids any digest collision with that future work.
CTX_LEAF_CSR = "YSG-LEAF-CSR-v1"


def canonical(obj: Any) -> str:
    """Strict-JSON canonical serialisation.

    - sort_keys=True        deterministic key order regardless of dict construction order
    - separators=(",", ":") no incidental whitespace
    - ensure_ascii=True     PEM/unicode content is escaped, never raw-emitted;
                             two different byte-for-byte-different unicode
                             representations of the same string cannot produce
                             different canonical output
    - PEM values are ordinary JSON strings (newlines become \\n escapes) — no
      special-casing required; json.dumps already does the right thing.

    This function is pure and MUST stay pure: it is called on both the signing
    side and the verifying side, and any nondeterminism (locale-dependent
    float formatting, unsorted dict iteration, etc.) breaks the chain.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def domain_separated_digest(context_tag: str, *parts: bytes, top_tier: bool = False) -> bytes:
    """Compute SHA-384 (default) or SHA-512 (top_tier=True) of
    context_tag || parts[0] || parts[1] || ...

    This is the one place the "prefixed before hashing in each context" rule
    is implemented; every *_signing_digest() helper below is a thin,
    named wrapper around this function so call sites read like the design
    doc's own formulas.
    """
    hash_fn = hashlib.sha512 if top_tier else hashlib.sha384
    h = hash_fn()
    h.update(context_tag.encode("utf-8"))
    for part in parts:
        h.update(part)
    return h.digest()


def leaf_cert_signing_digest(leaf_cert_canonical_dict: dict) -> bytes:
    """digest = SHA384( CTX_LEAF_CERT || canonical(leaf_cert) )

    This is the message the MASTER signs to produce leaf_cert_sig (design
    doc §"leaf_cert schema": `leaf_cert_sig = master.sign(SHA384(ctx‖canonical(leaf_cert)))`).
    """
    payload_bytes = canonical(leaf_cert_canonical_dict).encode("utf-8")
    return domain_separated_digest(CTX_LEAF_CERT, payload_bytes)


def licence_payload_signing_digest(payload_bytes: bytes, leaf_cert_canonical_dict: dict) -> bytes:
    """digest = SHA384( CTX_LICENCE_PAYLOAD || payload_bytes || SHA384(canonical(leaf_cert)) )

    This is the message the LEAF signs to produce leaf_sig. Binding the inner
    SHA-384 of the leaf_cert into the digest is what makes leaf_sig
    non-transferable to a different (even validly master-signed) leaf_cert —
    design doc: "leaf_sig binds to the leaf cert: sign(leaf, ctx‖payload‖
    SHA384(canonical(leaf_cert)))".
    """
    leaf_cert_bytes = canonical(leaf_cert_canonical_dict).encode("utf-8")
    leaf_cert_digest = hashlib.sha384(leaf_cert_bytes).digest()
    return domain_separated_digest(CTX_LICENCE_PAYLOAD, payload_bytes, leaf_cert_digest)


def bundle_signing_digest(bundle_str: str) -> bytes:
    """digest = SHA384( CTX_BUNDLE || bundle_str )

    Signs the build hash-bundle string (Su/Captain territory in Phase B —
    exposed here so the digest formula is defined exactly once).
    """
    return domain_separated_digest(CTX_BUNDLE, bundle_str.encode("utf-8"))


def leaf_csr_signing_digest(csr_pop_payload_canonical_dict: dict) -> bytes:
    """digest = SHA384( CTX_LEAF_CSR || canonical(csr_pop_payload) )

    The message a NEW leaf's own private key signs to produce csr_self_sig —
    the proof-of-possession the master verifies BEFORE certifying that leaf
    (design doc §3.4.1 pattern, generalised here to code/licence leaves per
    LOCKED DECISIONS bullet 9). csr_pop_payload is typically
    {"leaf_pubkey_pem":..., "client_id":..., "role":...}.
    """
    payload_bytes = canonical(csr_pop_payload_canonical_dict).encode("utf-8")
    return domain_separated_digest(CTX_LEAF_CSR, payload_bytes)


def audit_checkpoint_signing_digest(
    date: str, tenant: str, event_count: int, merkle_root: bytes, alg: str
) -> bytes:
    """digest = SHA384( CTX_AUDIT_CHECKPOINT || date || tenant || event_count || merkle_root || alg )

    ROUND-4 fix (Laura R4-F1 + Nico): "Widen the signed checkpoint scope:
    today it signs SHA384(merkle_root) ALONE — must sign
    date‖tenant‖event_count‖merkle_root + domain-separation tag + alg."
    Field separators (`|`) between the variable-length string fields prevent
    the classic length-extension-style ambiguity of naive concatenation
    (e.g. tenant="ab"+event_count="1" colliding with tenant="a"+event_count="b1").
    """
    fields = f"{date}|{tenant}|{event_count}|".encode("utf-8")
    alg_bytes = f"|{alg}".encode("utf-8")
    return domain_separated_digest(CTX_AUDIT_CHECKPOINT, fields, merkle_root, alg_bytes)
