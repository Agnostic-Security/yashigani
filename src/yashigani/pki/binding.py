"""
Change-prevention binding for agent/MCP instance leaves (v4.1 Phase 1a, GAP-2).

An approved instance's leaf cert must cryptographically bind WHAT was approved
(the tool surface + the container image) to WHO the instance is (the per-instance
SPIFFE identity).  A swapped image or a modified tool surface then breaks the
binding — the running instance can no longer present a leaf whose binding digest
matches what the verifier (sidecar / OPA Phase 2) recomputes, and is denied
``IDENTITY_BINDING_BROKEN``.

X.509 extension contract (FIXED — consumers build against this; import the
``BINDING_EXTENSION_OID`` / ``BINDING_EXTENSION_OID_DOTTED`` constants, never
inline the dotted literal):

  OID:       1.2.840.113556.1.8000.2554.47329.46511.38394.19003.33869.4847.39857.49952.1
             Derived from the SAME provenance UUID
             b8e1b5af-95fa-4a3b-844d-12ef9bb1c320 as the original Phase 1a
             arc, split into eight 16-bit arcs under Microsoft's public
             self-assignment arc 1.2.840.113556.1.8000.2554 (the arc owner
             explicitly delegates this space for GUID-derived self-generated
             OIDs — no false registration claim; uniqueness inherited from
             the UUID).  Sub-arc .1 = change-prevention binding digest.

             Phase 1b-i AMENDMENT (Captain, 2026-07-05 — Nico to ratify):
             the original X.667 form 2.25.245749903045077406250620676131142091552.1
             encodes the UUID as ONE ~2^127 arc.  Go's crypto/x509 stores OID
             arcs as machine ints and REJECTS any certificate whose extension
             OID has an arc > 2^31-1 — empirically proven against Caddy
             ``require_and_verify``: arc 2^31-1 → accepted, arc 2^32-1 →
             ``decode_error`` handshake abort, X.667 UUID arc → same abort,
             with criticality irrelevant.  Every X.667 single-UUID arc is
             therefore unusable in any cert a Go TLS stack must parse
             (Caddy, gateway mesh listeners, OPA).  PROPER long-term fix:
             register an Agnostic Security IANA PEN (free) and move to
             1.3.6.1.4.1.<PEN>.1.1 in a coordinated rotation.

  Critical:  False (v4.1 Phase 1b-i decision — supersedes the Phase 1a brief).
             RATIONALE: RFC 5280 path validators that do not recognise a
             CRITICAL OID MUST reject the cert — Go crypto/x509 ``Verify``
             (Caddy ``require_and_verify``) and strict OpenSSL both do.  The
             architecture enforces change-prevention at the OPA layer (the
             binding digest is an OPA *input*, recomputed from registry
             state), NOT at TLS path validation — so the extension is
             informational to TLS stacks and MUST be non-critical or every
             Go-based mesh verifier (Caddy fronting gateway/backoffice/OPA)
             would refuse the per-instance leaf outright.  Verified
             empirically against Caddy ``client_auth require_and_verify``
             (Phase 1b-i handshake proof: critical → TLS alert
             ``bad certificate``; non-critical → accepted).
  extnValue: the raw ASCII bytes ``sha384:<96 lowercase hex chars>``
             (no inner DER wrapping — cryptography's UnrecognizedExtension
             emits the bytes directly as the extension's OCTET STRING body).

Digest construction:

  binding = "sha384:" + hex( SHA-384( utf8(image_digest) || 0x00 || utf8(scope_hash) ) )

  - ``image_digest``: the OCI image digest pinned at approve time (e.g.
    ``sha256:abcd...``).  Empty string when no digest has been pinned yet —
    the binding then covers the tool surface only, and the verifier knows
    the image slot was unpinned (it recomputes with the same empty input
    from registry state; it does NOT skip the check).
  - ``scope_hash``: the tool-surface hash ``sha384:<hex>`` produced by
    :func:`tool_surface_hash` (canonical JSON over the sorted allowed_tools).
  - ``0x00`` separator: domain separation — removes concatenation ambiguity
    between the two variable-length inputs.

Single source of truth: user_agents instantiate, the approve/mint path, the
audit event, and the Phase 2 OPA baseline push must all import from here.
"""
from __future__ import annotations

import hashlib
import json

from cryptography import x509

#: Provenance UUID for the Yashigani private arc (same as Phase 1a).
YASHIGANI_ARC_PROVENANCE_UUID = "b8e1b5af-95fa-4a3b-844d-12ef9bb1c320"

#: UUID-derived private arc — the provenance UUID split into eight 16-bit
#: arcs under Microsoft's public GUID-self-assignment arc (see module
#: docstring).  Phase 1b-i: every arc MUST stay <= 2^31-1 or Go crypto/x509
#: (Caddy require_and_verify, gateway mesh listeners) rejects the whole
#: certificate at parse time — test_oid_arcs_go_parseable guards this.
YASHIGANI_PRIVATE_ARC = (
    "1.2.840.113556.1.8000.2554."
    "47329.46511.38394.19003.33869.4847.39857.49952"
)

#: Change-prevention binding digest extension (NON-critical — see docstring).
BINDING_EXTENSION_OID = x509.ObjectIdentifier(YASHIGANI_PRIVATE_ARC + ".1")

#: Dotted-string form for consumers that match on strings (OPA input, openssl).
BINDING_EXTENSION_OID_DOTTED = YASHIGANI_PRIVATE_ARC + ".1"

_PREFIX = "sha384:"


def tool_surface_hash(allowed_tools: list[str]) -> str:
    """Canonical tool-surface hash (``scope_hash``) for an NHI instance.

    Byte-identical to the R3 instantiate-path computation (user_agents.py):
    ``"sha384:" + sha384(json({"allowed_tools": sorted(tools)}, sort_keys))``.
    """
    scope_obj = {"allowed_tools": sorted(allowed_tools)}
    return _PREFIX + hashlib.sha384(
        json.dumps(scope_obj, sort_keys=True).encode("utf-8")
    ).hexdigest()


def binding_digest(image_digest: str, scope_hash: str) -> str:
    """``sha384:<hex>`` binding of image digest + tool-surface hash.

    NUL-separated to remove concatenation ambiguity (see module docstring).
    """
    payload = image_digest.encode("utf-8") + b"\x00" + scope_hash.encode("utf-8")
    return _PREFIX + hashlib.sha384(payload).hexdigest()


def encode_binding_extension_value(image_digest: str, scope_hash: str) -> bytes:
    """Raw extnValue bytes for the binding extension (ASCII ``sha384:<hex>``)."""
    return binding_digest(image_digest, scope_hash).encode("ascii")


def parse_binding_extension(cert: x509.Certificate) -> str | None:
    """Return the binding digest string from a leaf, or None when absent.

    Raises ValueError on a malformed value — a present-but-garbled binding is
    tampering evidence, never silently ignored (fail-closed for callers).
    """
    try:
        ext = cert.extensions.get_extension_for_oid(BINDING_EXTENSION_OID)
    except x509.ExtensionNotFound:
        return None
    raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else b""
    text = raw.decode("ascii", errors="strict") if raw else ""
    if not text.startswith(_PREFIX) or len(text) != len(_PREFIX) + 96:
        raise ValueError(
            f"malformed change-prevention binding extension value: {text[:32]!r}..."
        )
    int(text[len(_PREFIX):], 16)  # hex-validate; raises ValueError if not hex
    return text
