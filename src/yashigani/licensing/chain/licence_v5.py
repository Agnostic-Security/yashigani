"""
Yashigani licence-hardening v2 — v5 licence format (sign + parse + verify).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §3.2 (Licence format v5) + §4b (Licence v5 verify) + §5 (Fail-modes) +
     §6 (kill-list).

Wire format (4 dot-separated base64url segments — NOT 3, unlike the old v4
format this supersedes):

    base64url(payload) . base64url(leaf_sig) . base64url(canonical(leaf_cert)) . base64url(leaf_cert_sig)

`payload` fields (§3.2): org_domain, tier, seats (carried here as the
existing v4 seat/limit fields — max_agents, max_end_users, max_admin_seats,
max_orgs — plus `features` and `issued_at`, unchanged from v4 so
verifier._build_license_state()'s existing field-resolution logic keeps
working unmodified), expires_at, client_id, licence_serial, signed_at, alg.

digest = SHA384( CTX_LICENCE_PAYLOAD || payload_bytes || SHA384(canonical(leaf_cert)) )
leaf_sig = Signer(licence leaf).sign(digest)

v3/v4 are DROPPED — this module only ever produces/accepts v5. There is no
downgrade path: `parse_licence_v5()` raises on anything that isn't exactly
4 dot-separated segments, and the caller (verifier.py) must reject anything
else outright (§3.2: "v3/v4 dropped — v5 mandatory, no downgrade path").
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from yashigani.licensing.chain.algorithms import (
    Alg,
    AlgorithmUnavailableError,
    UnknownAlgorithmError,
    verify_signature,
)
from yashigani.licensing.chain.anchors import AnchorSet
from yashigani.licensing.chain.canonical import canonical, licence_payload_signing_digest
from yashigani.licensing.chain.kill_list import KillList
from yashigani.licensing.chain.leaf_cert import LeafCert, Role
from yashigani.licensing.chain.signer import Signer

logger = logging.getLogger(__name__)

LICENCE_WIRE_SEGMENTS = 4


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


# ---------------------------------------------------------------------------
# Payload construction (sign-side helper — used by scripts/sign_license.py)
# ---------------------------------------------------------------------------

def build_licence_payload_v5(
    *,
    org_domain: str,
    tier: str,
    client_id: str,
    licence_serial: str,
    alg: Alg = Alg.ECDSA_P384_SHA384,
    max_agents: int,
    max_end_users: int,
    max_admin_seats: int,
    max_orgs: int,
    features: Optional[list[str]] = None,
    issued_at: Optional[datetime] = None,
    expires_at: datetime,
    signed_at: Optional[datetime] = None,
) -> dict:
    """Build the v5 payload dict per §3.2.

    Field-set judgement call (flagged for Nico/Tiago, consistent with Phase
    A's own flagged judgement calls): the design's §3.2 prose lists the
    payload fields as "org_domain, tier, seats, ... # v4 fields, carried
    forward unchanged". "seats" is shorthand in the prose for the existing
    v4 per-dimension seat/limit fields (max_agents, max_end_users,
    max_admin_seats, max_orgs) plus `features` — there is no single literal
    `seats` field in the shipped v4 payload to carry forward verbatim, so
    this function keeps the actual v4 field names (max_agents etc.) rather
    than inventing a new `seats` container, which would break
    verifier._build_license_state()'s existing (unchanged, in-scope-frozen)
    resolution logic for those fields.
    """
    now = datetime.now(timezone.utc)
    return {
        "org_domain": org_domain,
        "tier": tier,
        "max_agents": max_agents,
        "max_end_users": max_end_users,
        "max_admin_seats": max_admin_seats,
        "max_orgs": max_orgs,
        "features": features if features is not None else [],
        "issued_at": (issued_at or now).astimezone(timezone.utc).isoformat(),
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
        "client_id": client_id,
        "licence_serial": licence_serial,
        "signed_at": (signed_at or now).astimezone(timezone.utc).isoformat(),
        "alg": alg.value,
    }


# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------

def sign_licence_v5(
    payload: dict,
    licence_signer: Signer,
    leaf_cert: LeafCert,
    leaf_cert_sig: bytes,
) -> str:
    """Produce the 4-segment v5 wire string.

    `licence_signer` MUST be provisioned for Role.LICENCE and its public key
    MUST equal leaf_cert.leaf_pubkey_pem (caller's responsibility — sign_message
    dispatch will simply produce a signature that fails to verify against
    leaf_cert.leaf_pubkey_pem later if they don't match; that is exercised in
    the round-trip test).
    """
    if leaf_cert.role != Role.LICENCE:
        raise ValueError(
            f"sign_licence_v5 requires a leaf_cert with role=licence; got {leaf_cert.role.value}"
        )
    payload_bytes = canonical(payload).encode("utf-8")
    digest = licence_payload_signing_digest(payload_bytes, leaf_cert.to_canonical_dict())
    leaf_sig = licence_signer.sign(Role.LICENCE, "YSG-LICENCE-PAYLOAD-v5", digest)

    leaf_cert_bytes = canonical(leaf_cert.to_canonical_dict()).encode("utf-8")

    return ".".join(
        [
            base64url_encode(payload_bytes),
            base64url_encode(leaf_sig),
            base64url_encode(leaf_cert_bytes),
            base64url_encode(leaf_cert_sig),
        ]
    )


# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParsedLicenceV5:
    payload: dict
    payload_bytes: bytes
    leaf_sig: bytes
    leaf_cert: LeafCert
    leaf_cert_sig: bytes


class LicenceV5FormatError(ValueError):
    """Raised by parse_licence_v5() on any malformed input — including the
    deliberate v3/v4 downgrade-rejection path (wrong segment count)."""


def parse_licence_v5(content: str) -> ParsedLicenceV5:
    """Parse a `.ysg` string into its 4 components.

    Raises LicenceV5FormatError on anything that isn't exactly
    LICENCE_WIRE_SEGMENTS (4) dot-separated segments, or that fails to
    base64url-decode / JSON-parse. This is the "no downgrade path" gate:
    a 2-segment (old v3) or 3-segment (old v4) string is rejected here,
    before any signature is even attempted.
    """
    segments = content.strip().split(".")
    if len(segments) != LICENCE_WIRE_SEGMENTS:
        raise LicenceV5FormatError(
            f"expected {LICENCE_WIRE_SEGMENTS} dot-separated segments (v5), got "
            f"{len(segments)} — v3/v4 formats are no longer accepted (no downgrade path)"
        )

    payload_b64, leaf_sig_b64, leaf_cert_b64, leaf_cert_sig_b64 = segments

    try:
        payload_bytes = base64url_decode(payload_b64)
        leaf_sig = base64url_decode(leaf_sig_b64)
        leaf_cert_bytes = base64url_decode(leaf_cert_b64)
        leaf_cert_sig = base64url_decode(leaf_cert_sig_b64)
    except Exception as exc:
        raise LicenceV5FormatError(f"base64url decode failed: {exc}") from exc

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise LicenceV5FormatError(f"payload JSON parse failed: {exc}") from exc

    try:
        leaf_cert_dict = json.loads(leaf_cert_bytes.decode("utf-8"))
        leaf_cert = LeafCert.from_canonical_dict(leaf_cert_dict)
    except Exception as exc:
        raise LicenceV5FormatError(f"leaf_cert parse failed: {exc}") from exc

    return ParsedLicenceV5(
        payload=payload,
        payload_bytes=payload_bytes,
        leaf_sig=leaf_sig,
        leaf_cert=leaf_cert,
        leaf_cert_sig=leaf_cert_sig,
    )


# ---------------------------------------------------------------------------
# Verify (§4b)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LicenceV5VerifyResult:
    valid: bool
    payload: Optional[dict]
    error: Optional[str]


def verify_licence_v5(
    content: str,
    anchor_set: AnchorSet,
    kill_list: KillList,
    client_domain_registry: Optional[dict[str, str]] = None,
    now: Optional[datetime] = None,
) -> LicenceV5VerifyResult:
    """§4b Licence v5 verify — implemented exactly to spec, steps 1-8.

    Any failure returns valid=False with a machine-readable `error` string;
    the caller (verifier.py) maps this to COMMUNITY_LICENSE per §5 — this
    function itself never raises for adversarial/malformed input (LAURA-
    V231-002 discipline: fail-closed to an error result, never crash the
    caller).

    `client_domain_registry` (client_id -> registered org_domain) is an
    OPTIONAL parameter — see the SEAM note in sign_license.py / the Phase B
    delivery report: the design's step 5 requires binding payload.org_domain
    to "that client_id's registered domain", but no client<->domain registry
    exists in this codebase yet (Su/licgen "Key registry" territory, design
    §"Key-management & KMS-migration abstraction" item 2). When the registry
    is None or has no entry for this client_id, that half of step 5 is
    skipped with a WARNING (the mandatory payload.client_id==leaf_cert.
    client_id self-consistency check ALWAYS runs — that is the primary
    Laura R3-F1 anti-cross-client-forgery property and needs no registry).
    """
    if now is None:
        now = datetime.now(timezone.utc)

    try:
        parsed = parse_licence_v5(content)
    except LicenceV5FormatError as exc:
        logger.warning("Licence v5 verify: parse failed: %s", exc)
        return LicenceV5VerifyResult(valid=False, payload=None, error="licence_format_invalid")
    except Exception as exc:  # defensive — never let a parse bug crash the caller
        logger.warning("Licence v5 verify: unexpected parse error: %s", exc)
        return LicenceV5VerifyResult(valid=False, payload=None, error="licence_format_invalid")

    # Step 2 — role check.
    if parsed.leaf_cert.role != Role.LICENCE:
        logger.warning(
            "Licence v5 verify: leaf_cert.role=%s, expected licence — rejecting",
            parsed.leaf_cert.role.value,
        )
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="wrong_leaf_role")

    # Step 3 — leaf_cert_sig chains to any active/retiring anchor.
    matched_anchor = anchor_set.validate_leaf_cert(parsed.leaf_cert, parsed.leaf_cert_sig)
    if matched_anchor is None:
        logger.warning("Licence v5 verify: leaf_cert does not chain to any trusted anchor")
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="leaf_cert_untrusted")

    # Step 4 — kill-list, IMMEDIATE namespaces.
    licence_serial = parsed.payload.get("licence_serial")
    if kill_list.is_revoked_immediate("leaf", parsed.leaf_cert.serial):
        logger.warning("Licence v5 verify: leaf serial %r is revoked", parsed.leaf_cert.serial)
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="leaf_revoked")
    if licence_serial and kill_list.is_revoked_immediate("licence", str(licence_serial)):
        logger.warning("Licence v5 verify: licence serial %r is revoked", licence_serial)
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="licence_revoked")
    if kill_list.is_revoked_immediate("client", parsed.leaf_cert.client_id):
        logger.warning(
            "Licence v5 verify: client %r licence leaf is revoked", parsed.leaf_cert.client_id
        )
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="client_revoked")
    if kill_list.is_revoked_immediate("master-anchor", matched_anchor.anchor_id):
        logger.warning(
            "Licence v5 verify: master anchor %r used to validate this leaf is revoked",
            matched_anchor.anchor_id,
        )
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="master_anchor_revoked")

    # Step 5 — client_id bind (ROUND-3 fix 1, BLOCKING).
    payload_client_id = parsed.payload.get("client_id")
    if payload_client_id != parsed.leaf_cert.client_id:
        logger.warning(
            "Licence v5 verify: payload.client_id=%r != leaf_cert.client_id=%r — "
            "cross-client forgery attempt (Laura R3-F1)",
            payload_client_id,
            parsed.leaf_cert.client_id,
        )
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="client_id_mismatch")

    payload_org_domain = parsed.payload.get("org_domain")
    if client_domain_registry is not None:
        registered_domain = client_domain_registry.get(parsed.leaf_cert.client_id)
        if registered_domain is not None and registered_domain != payload_org_domain:
            logger.warning(
                "Licence v5 verify: payload.org_domain=%r does not match client %r's "
                "registered domain %r",
                payload_org_domain,
                parsed.leaf_cert.client_id,
                registered_domain,
            )
            return LicenceV5VerifyResult(
                valid=False, payload=parsed.payload, error="org_domain_registry_mismatch"
            )
        if registered_domain is None:
            logger.warning(
                "Licence v5 verify: no registered domain for client_id=%r — "
                "org_domain binding not enforced (registry not yet populated for this client)",
                parsed.leaf_cert.client_id,
            )
    else:
        logger.debug(
            "Licence v5 verify: no client_domain_registry supplied — org_domain binding "
            "not enforced beyond payload.client_id==leaf_cert.client_id self-consistency"
        )

    # Step 6 — leaf_sig verify, dispatch by payload.alg.
    try:
        alg = Alg.from_wire(parsed.payload.get("alg", ""))
    except UnknownAlgorithmError as exc:
        logger.warning("Licence v5 verify: %s", exc)
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="unknown_alg")

    digest = licence_payload_signing_digest(parsed.payload_bytes, parsed.leaf_cert.to_canonical_dict())
    try:
        leaf_sig_valid = verify_signature(
            alg, parsed.leaf_cert.leaf_pubkey_pem, digest, parsed.leaf_sig
        )
    except AlgorithmUnavailableError as exc:
        logger.warning("Licence v5 verify: %s", exc)
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="alg_unavailable")
    except Exception as exc:
        logger.warning("Licence v5 verify: unexpected error verifying leaf_sig: %s", exc)
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="leaf_sig_error")

    if not leaf_sig_valid:
        logger.warning("Licence v5 verify: leaf_sig invalid")
        return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="invalid_signature")

    # Step 7 — the licence's OWN term. leaf_cert.not_before/not_after is
    # NEVER checked here (§2 — signing-side only).
    expires_at_str = parsed.payload.get("expires_at")
    if expires_at_str:
        try:
            expires_at = datetime.fromisoformat(str(expires_at_str).replace("Z", "+00:00"))
        except Exception:
            logger.warning("Licence v5 verify: unparsable expires_at=%r", expires_at_str)
            return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="invalid_expiry")
        if now > expires_at:
            return LicenceV5VerifyResult(valid=False, payload=parsed.payload, error="license_expired")

    # Step 8 — org_domain/tier/seats are bound from payload by the caller
    # (verifier._build_license_state()), unchanged from v4.
    return LicenceV5VerifyResult(valid=True, payload=parsed.payload, error=None)
