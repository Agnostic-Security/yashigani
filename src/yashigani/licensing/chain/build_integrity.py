"""
Yashigani licence-hardening v2 — build-integrity chain verify (§4a).

Ref: design doc §4a (Build-integrity verify) + §3.3 (Build hash-bundle).

    1. Load the embedded anchor-SET + this build's leaf_cert (role=code) +
       leaf_cert_sig + bundle_sig.
    2. leaf_cert.role == "code" — reject any other role.
    3. Validate leaf_cert_sig against any anchor with status in
       {active, retiring}.
    4. Kill-list: leaf:<serial>, master-anchor:<anchor_id used> — IMMEDIATE,
       any hit fails.
    5. Verify bundle_sig against leaf_cert.leaf_pubkey_pem, dispatch by
       leaf_cert.alg (hybrid = both components mandatory, no isolated
       sub-verify).
    6. Per-module self-hashes (v1 T1-T4, unchanged) — NOT this module's
       concern; those checks already exist independently in verifier.py,
       enforcer.py, agents/registry.py, identity/registry.py and are wired
       at each of those modules' own import time. This module covers steps
       1-5 only — the chain-based half of §4a that supersedes the old
       counter-key/HASH_BUNDLE_SIG/EXPECTED_TOKEN_HMAC mechanism.

Any failure -> integrity_violated (Community + persistent tamper banner,
§5). Build integrity is perpetual — no verify-time expiry on the build
itself (leaf_cert.not_before/not_after is signing-side only, §2).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

from yashigani.licensing.chain.algorithms import (
    Alg,
    AlgorithmUnavailableError,
    UnknownAlgorithmError,
    verify_signature,
)
from yashigani.licensing.chain.anchors import AnchorSet
from yashigani.licensing.chain.canonical import bundle_signing_digest
from yashigani.licensing.chain.kill_list import KillList
from yashigani.licensing.chain.leaf_cert import LeafCert, Role

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuildIntegrityResult:
    valid: bool
    error: Optional[str]


def verify_build_integrity_chain(
    anchor_set: AnchorSet,
    code_leaf_cert: LeafCert,
    code_leaf_cert_sig: bytes,
    bundle_str: str,
    bundle_sig: bytes,
    kill_list: KillList,
) -> BuildIntegrityResult:
    """§4a steps 1-5 — the chain-based half of build-integrity verify.

    Never raises for adversarial/malformed input; every failure path returns
    a typed BuildIntegrityResult(valid=False, error=...) so the caller
    (verifier.py's module-load check) can log + set _integrity_violated
    without risking an uncaught exception crashing import.
    """
    # Step 2 — role check.
    if code_leaf_cert.role != Role.CODE:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: embedded build leaf_cert.role=%s, expected code",
            code_leaf_cert.role.value,
        )
        return BuildIntegrityResult(valid=False, error="wrong_leaf_role")

    # Step 3 — leaf_cert_sig chains to any active/retiring anchor.
    matched_anchor = anchor_set.validate_leaf_cert(code_leaf_cert, code_leaf_cert_sig)
    if matched_anchor is None:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: build leaf_cert does not chain to any trusted "
            "master anchor — binary may have been tampered with or re-signed under an "
            "untrusted key"
        )
        return BuildIntegrityResult(valid=False, error="leaf_cert_untrusted")

    # Step 4 — kill-list, IMMEDIATE namespaces.
    if kill_list.is_revoked_immediate("leaf", code_leaf_cert.serial):
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: build leaf serial %r is revoked (kill-list)",
            code_leaf_cert.serial,
        )
        return BuildIntegrityResult(valid=False, error="leaf_revoked")
    if kill_list.is_revoked_immediate("master-anchor", matched_anchor.anchor_id):
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: master anchor %r used to validate this build is "
            "revoked (kill-list)",
            matched_anchor.anchor_id,
        )
        return BuildIntegrityResult(valid=False, error="master_anchor_revoked")

    # Step 5 — bundle_sig verify, dispatch by leaf_cert.alg. Hybrid exposes
    # no isolated sub-verify path (chain.algorithms.verify_signature already
    # enforces this — see its module docstring).
    try:
        digest = bundle_signing_digest(bundle_str)
        bundle_sig_valid = verify_signature(
            code_leaf_cert.alg, code_leaf_cert.leaf_pubkey_pem, digest, bundle_sig
        )
    except (AlgorithmUnavailableError, UnknownAlgorithmError) as exc:
        logger.critical("LICENSE INTEGRITY VIOLATION: %s", exc)
        return BuildIntegrityResult(valid=False, error="alg_unavailable_or_unknown")
    except Exception as exc:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: unexpected error verifying bundle_sig: %s", exc
        )
        return BuildIntegrityResult(valid=False, error="bundle_sig_error")

    if not bundle_sig_valid:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: hash bundle signature verification failed against "
            "the build's own code leaf — binary may have been tampered with"
        )
        return BuildIntegrityResult(valid=False, error="invalid_bundle_sig")

    return BuildIntegrityResult(valid=True, error=None)


# ---------------------------------------------------------------------------
# JSON (de)serialisation helpers for the values _integrity.py embeds at
# build time (a JSON list of anchor_set_entry dicts, and a single leaf_cert
# canonical dict) — kept here so verifier.py has one place to import from.
# ---------------------------------------------------------------------------

def anchor_set_from_json(raw_json: str) -> AnchorSet:
    """Parse _integrity.MASTER_ANCHOR_SET_JSON into an AnchorSet.

    Raises ValueError/json.JSONDecodeError on malformed input — callers
    (verifier.py module-load check) must catch and treat as integrity
    violation, never let this propagate to crash import.
    """
    from datetime import datetime as _dt

    from yashigani.licensing.chain.anchors import AnchorStatus, TrustAnchor

    raw = json.loads(raw_json)
    anchors = [
        TrustAnchor(
            anchor_id=entry["anchor_id"],
            pubkey_pem=entry["pubkey_pem"],
            alg=Alg.from_wire(entry["alg"]),
            status=AnchorStatus(entry["status"]),
            added=_dt.fromisoformat(entry["added"]),
        )
        for entry in raw
    ]
    return AnchorSet(anchors)


def leaf_cert_from_json(raw_json: str) -> LeafCert:
    """Parse _integrity.CODE_LEAF_CERT_JSON (a canonical leaf_cert dict) into
    a LeafCert."""
    return LeafCert.from_canonical_dict(json.loads(raw_json))


def kill_list_from_json(raw_json: str) -> KillList:
    """Parse _integrity.KILL_LIST_JSON. Defaults (empty string / "[]") to an
    empty kill-list — an empty kill-list is a SAFE default (nothing
    revoked), unlike the anchor-set/leaf-cert placeholders which must
    fail-closed when unset."""
    if not raw_json or not raw_json.strip():
        return KillList.empty()
    return KillList.from_canonical_list(json.loads(raw_json))
