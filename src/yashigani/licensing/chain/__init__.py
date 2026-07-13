"""
Yashigani licence-hardening v2 — shared crypto-agile PKI foundation.

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md

Phase A deliverable: the primitives Su (keygen/licgen/install) and Captain
(KMS/channel) build on top of — canonical serialisation, domain-separation
context tags, the closed algorithm enum + crypto-agile dispatch, the
leaf_cert schema, the Signer backend interface, and the trust-anchor set.

Phase B (NOT this module) wires these into: the full verifier chain
(leaf_cert -> master), v5 licence sign/verify end-to-end, `_integrity.py`'s
master-embed + leaf_cert, and `keygen`/`licgen` CLI tooling.
"""
from __future__ import annotations

from yashigani.licensing.chain.algorithms import (
    HASH_FLOOR,
    HASH_TOP_TIER,
    IMPLEMENTED_ALGORITHMS,
    Alg,
    AlgorithmUnavailableError,
    RoleMismatchError,
    UnknownAlgorithmError,
    decode_hybrid_signature,
    der_to_raw_rs,
    encode_hybrid_signature,
    hybrid_both_must_verify,
    raw_rs_to_der,
    sign_message,
    verify_signature,
)
from yashigani.licensing.chain.anchors import AnchorSet, AnchorStatus, TrustAnchor
from yashigani.licensing.chain.canonical import (
    CTX_AUDIT_CHECKPOINT,
    CTX_BUNDLE,
    CTX_LEAF_CERT,
    CTX_LICENCE_PAYLOAD,
    audit_checkpoint_signing_digest,
    bundle_signing_digest,
    canonical,
    domain_separated_digest,
    leaf_cert_signing_digest,
    licence_payload_signing_digest,
)
from yashigani.licensing.chain.leaf_cert import SHARED_CLIENT_ID, LeafCert, Role
from yashigani.licensing.chain.signer import KmsSigner, PemSigner, PivSigner, Signer

__all__ = [
    # algorithms
    "HASH_FLOOR",
    "HASH_TOP_TIER",
    "IMPLEMENTED_ALGORITHMS",
    "Alg",
    "AlgorithmUnavailableError",
    "RoleMismatchError",
    "UnknownAlgorithmError",
    "decode_hybrid_signature",
    "der_to_raw_rs",
    "encode_hybrid_signature",
    "hybrid_both_must_verify",
    "raw_rs_to_der",
    "sign_message",
    "verify_signature",
    # anchors
    "AnchorSet",
    "AnchorStatus",
    "TrustAnchor",
    # canonical
    "CTX_AUDIT_CHECKPOINT",
    "CTX_BUNDLE",
    "CTX_LEAF_CERT",
    "CTX_LICENCE_PAYLOAD",
    "audit_checkpoint_signing_digest",
    "bundle_signing_digest",
    "canonical",
    "domain_separated_digest",
    "leaf_cert_signing_digest",
    "licence_payload_signing_digest",
    # leaf_cert
    "SHARED_CLIENT_ID",
    "LeafCert",
    "Role",
    # signer
    "KmsSigner",
    "PemSigner",
    "PivSigner",
    "Signer",
]
