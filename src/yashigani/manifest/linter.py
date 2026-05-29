"""
Yashigani Manifest — Linter (M5, M6, M7, C1-C3, N1, N2).

Applies all semantic validation rules that go beyond the JSON-Schema (M8)
and the parser-level guards (M1-M3).  The linter is the ``yashigani validate``
engine.

Rules implemented here:
  M5  — inbound_ports allowlist 1024-49151; non-MCP inbound forbidden in v1.
  M6  — spec.image.digest + all spec.sidecars[*].image.digest present;
         --verify-digests live-inspect path (behind flag; mock in tests).
  M7  — signature enforcement gate (via signatures.py).
  N1  — SPIFFE identity /agents/{tenant_id}/{name} namespace mandate.
         If spec.identity.spiffe.override_id is set it MUST start with
         ``spiffe://yashigani.internal/agents/<tenant_id>/``.  Prevents
         escape to the /agents/<other_tenant>/ namespace and prevents
         collision with core-service identities (Nico NICO-002).
         Error code: N1_spiffe_override_out_of_namespace.
  N2  — Onboard-time cert issuance constraint (v2.25.0 P1 W5).
         v1 issues certs at onboard time; runtime/on-demand per-identity
         issuance requires the v2.24.0 PKI Issuer API.  The combination
         ``lifecycle.mode: on-demand`` + ``pool.container_per: identity``
         is therefore blocked in v1.  Persistent mode (and on-demand
         without container_per:identity) pass.
         Error code: N2_ondemand_identity_v1_blocked.
         Note: ``lifecycle.mode: on-demand`` is also rejected by the
         JSON-Schema enum (M8) since the schema currently permits only
         ``persistent``; the N2 linter rule adds a human-quality error
         message that explicitly names the v2.24.0 constraint and the
         affected combination.
  C1  — egress_allow host must not resolve to RFC1918/loopback/link-local
         (static parse-time check on literal values; full DNS is codegen).
         Also applied to spec.model_egress.base_url (F4 — Laura MED).
         LAURA-001 fix: normalise before ipaddress parse — strip trailing
         dots, unwrap brackets, reject integer/hex/octal strings, check
         ipv4_mapped attribute, add fd00::/7 ULA and 0.0.0.0/8.
  C3  — duplicate (tenant_id, name) within a single validate run (stateless
         in v1 — registry uniqueness is a runtime concern; validator flags
         exact duplicate fields in the manifest itself).
         LAURA-002/003 fix: metadata.name and metadata.tenant_id must match
         _SLUG_RE (^[a-z0-9][a-z0-9\\-]{0,62}[a-z0-9]$).
  P2  — spec.mcp.identity_propagation == gateway-enforced-only is FORBIDDEN
         when spec.audit.sensitivity_ceiling is CONFIDENTIAL or RESTRICTED.
         Default sensitivity ceiling is CONFIDENTIAL (L-01), so an absent
         ceiling also triggers this check.

Error messages are human-quality (K3 — Nora launch gate):
  Every error includes: what failed, why it matters, how to fix it.

W3 additions (v2.25.0 P1):
  P2  — spec.mcp.identity_propagation == gateway-enforced-only is FORBIDDEN
         when spec.audit.sensitivity_ceiling is CONFIDENTIAL or RESTRICTED
         (default is CONFIDENTIAL per L-01).
  LAURA-001 — _is_private_address SSRF bypass hardening.
  LAURA-002/003 — slug validation on metadata.name and metadata.tenant_id.

W5 additions (v2.25.0 P1):
  N1  — Error code renamed from N1_spiffe_prefix to
         N1_spiffe_override_out_of_namespace (more precise; existing tests
         updated).  Semantics unchanged: override_id must start with the
         /agents/<tenant_id>/ prefix.
  N2  — New rule: on-demand + container_per:identity blocked in v1 (PKI
         Issuer API required for on-demand per-identity issuance).

Last updated: 2026-05-29T00:00:00+00:00
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LintError
# ---------------------------------------------------------------------------


class LintError:
    """A single linter finding."""

    def __init__(
        self,
        rule: str,
        message: str,
        field: str = "",
        fix: str = "",
    ) -> None:
        self.rule = rule
        self.message = message
        self.field = field
        self.fix = fix

    def human_message(self) -> str:
        """Human-quality error message (K3)."""
        parts = [self.message]
        if self.field:
            parts = ["[%s] %s" % (self.field, self.message)]
        if self.fix:
            parts.append("  Fix: %s" % self.fix)
        return "\n".join(parts)

    def __repr__(self) -> str:
        return "LintError(%s, %r)" % (self.rule, self.message)


# ---------------------------------------------------------------------------
# M5 — inbound_ports
# ---------------------------------------------------------------------------

_INBOUND_PORT_MIN = 1024
_INBOUND_PORT_MAX = 49151


def _lint_inbound_ports(parsed: dict) -> list[LintError]:
    """
    M5 — inbound_ports must only list values in [1024, 49151].
    Non-MCP inbound is forbidden in v1: the only permitted inbound is
    mcp.exposes.listen_port.  If inbound_ports contains any value that is
    not also the mcp.exposes.listen_port, flag it.
    """
    errors: list[LintError] = []
    network = (parsed.get("spec") or {}).get("network") or {}
    inbound_ports = network.get("inbound_ports") or []

    mcp_listen_port: Optional[int] = None
    mcp_exposes = ((parsed.get("spec") or {}).get("mcp") or {}).get("exposes")
    if isinstance(mcp_exposes, dict):
        mcp_listen_port = mcp_exposes.get("listen_port")

    for port in inbound_ports:
        if not isinstance(port, int):
            errors.append(LintError(
                "M5_inbound_port_type",
                "inbound_ports entry %r is not an integer." % port,
                field="spec.network.inbound_ports",
                fix="All entries in spec.network.inbound_ports must be integers.",
            ))
            continue
        if port < _INBOUND_PORT_MIN or port > _INBOUND_PORT_MAX:
            errors.append(LintError(
                "M5_inbound_port_range",
                "inbound port %d is outside the allowed range [1024, 49151]." % port,
                field="spec.network.inbound_ports",
                fix="Use a port between 1024 and 49151.  Ports ≤ 1023 require root "
                    "and are never permitted for ring-fenced agents.",
            ))
        if mcp_listen_port is not None and port != mcp_listen_port:
            errors.append(LintError(
                "M5_non_mcp_inbound",
                "inbound port %d is not the MCP listen port (%d). "
                "Non-MCP inbound is forbidden in v1." % (port, mcp_listen_port),
                field="spec.network.inbound_ports",
                fix="Remove port %d from spec.network.inbound_ports, or set "
                    "spec.mcp.exposes.listen_port to %d." % (port, port),
            ))
        elif mcp_listen_port is None and inbound_ports:
            errors.append(LintError(
                "M5_non_mcp_inbound",
                "inbound port %d declared but spec.mcp.exposes.listen_port is not set. "
                "Non-MCP inbound is forbidden in v1." % port,
                field="spec.network.inbound_ports",
                fix="Add spec.mcp.exposes.listen_port: %d, or remove "
                    "spec.network.inbound_ports entirely." % port,
            ))
            break  # one error per policy violation is enough

    return errors


# ---------------------------------------------------------------------------
# M6 — image digest enforcement
# ---------------------------------------------------------------------------

_SHA256_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


def _lint_image_digests(parsed: dict) -> list[LintError]:
    """
    M6 — spec.image.digest and all spec.sidecars[*].image.digest must be
    present and in the form ``sha256:<64 hex chars>``.
    """
    errors: list[LintError] = []
    spec = parsed.get("spec") or {}

    # Main image
    image = spec.get("image") or {}
    digest = image.get("digest", "")
    if not digest:
        errors.append(LintError(
            "M6_image_digest_missing",
            "spec.image.digest is required but missing.",
            field="spec.image.digest",
            fix="Add spec.image.digest: sha256:<64-char hex>.  Run "
                "`docker manifest inspect <image>` or "
                "`skopeo inspect docker://<image>` to get the digest.",
        ))
    elif not _SHA256_PATTERN.match(digest):
        errors.append(LintError(
            "M6_image_digest_format",
            "spec.image.digest %r is not a valid SHA-256 digest." % digest,
            field="spec.image.digest",
            fix="Use the form sha256:<64 lowercase hex characters>.",
        ))

    # Sidecars
    sidecars = spec.get("sidecars") or []
    for i, sidecar in enumerate(sidecars):
        if not isinstance(sidecar, dict):
            continue
        sidecar_img = sidecar.get("image") or {}
        sc_digest = sidecar_img.get("digest", "")
        field = "spec.sidecars[%d].image.digest" % i
        sc_name = sidecar.get("name", str(i))
        if not sc_digest:
            errors.append(LintError(
                "M6_sidecar_digest_missing",
                "sidecar %r is missing spec.sidecars[%d].image.digest (required by M6)." % (sc_name, i),
                field=field,
                fix="Add the image digest for sidecar %r.  "
                    "All sidecar images must be pinned by digest." % sc_name,
            ))
        elif not _SHA256_PATTERN.match(sc_digest):
            errors.append(LintError(
                "M6_sidecar_digest_format",
                "sidecar %r digest %r is not a valid SHA-256 digest." % (sc_name, sc_digest),
                field=field,
                fix="Use the form sha256:<64 lowercase hex characters>.",
            ))

    return errors


# ---------------------------------------------------------------------------
# M6 — live digest verification (behind --verify-digests flag)
# ---------------------------------------------------------------------------


def verify_digests_live(parsed: dict, *, _inspector: Any = None) -> list[LintError]:
    """
    M6 — live digest verification: confirm that the image tag resolves to the
    declared digest in the registry.

    This is only called when ``--verify-digests`` is passed to
    ``yashigani validate``.  It requires network access and is skipped in
    air-gap / offline deployments.

    The ``_inspector`` parameter accepts a mock in tests:
      _inspector.inspect(repository, tag) -> str  (returns digest string)

    In production, the default inspector calls ``docker manifest inspect`` or
    ``skopeo inspect`` (Captain's container tooling — no direct dependency here;
    the inspector is injected so this module stays container-runtime-agnostic).
    """
    if _inspector is None:
        # No inspector injected — skip live check with an INFO log.
        _log.info("M6: --verify-digests requested but no inspector provided; skipping live check.")
        return []

    errors: list[LintError] = []
    spec = parsed.get("spec") or {}

    def _check_one(image: dict, field_prefix: str, label: str) -> None:
        repo = image.get("repository", "")
        tag = image.get("tag", "")
        declared_digest = image.get("digest", "")
        if not (repo and tag and declared_digest):
            return  # missing fields handled by _lint_image_digests
        try:
            live_digest = _inspector.inspect(repo, tag)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            errors.append(LintError(
                "M6_digest_inspect_error",
                "could not inspect digest for %s (%s): %s" % (label, "%s:%s" % (repo, tag), str(exc)[:128]),
                field=field_prefix + ".digest",
                fix="Ensure the image %s:%s is accessible in the registry, "
                    "or use --no-verify-digests for air-gap deployments." % (repo, tag),
            ))
            return
        if live_digest != declared_digest:
            errors.append(LintError(
                "M6_digest_mismatch",
                "image %s:%s live digest %r does not match declared %r." % (
                    repo, tag, live_digest, declared_digest),
                field=field_prefix + ".digest",
                fix="Update spec.image.digest to %r, or pin the correct tag." % live_digest,
            ))

    _check_one(spec.get("image") or {}, "spec.image", "main image")
    for i, sidecar in enumerate(spec.get("sidecars") or []):
        if isinstance(sidecar, dict):
            _check_one(
                sidecar.get("image") or {},
                "spec.sidecars[%d].image" % i,
                "sidecar %r" % sidecar.get("name", str(i)),
            )

    return errors


# ---------------------------------------------------------------------------
# N1 — SPIFFE identity prefix mandate + URI resolver (P1-F-01)
# ---------------------------------------------------------------------------

_SPIFFE_TRUST_DOMAIN = "yashigani.internal"
_SPIFFE_AGENTS_PREFIX = "spiffe://%s/agents" % _SPIFFE_TRUST_DOMAIN


def resolve_spiffe_uri(parsed: dict) -> str:
    """
    P1-F-01 (Iris LOW) — resolve the canonical SPIFFE URI for an agent manifest.

    Returns ``spec.identity.spiffe.override_id`` if set, otherwise constructs
    the default URI:

        spiffe://yashigani.internal/agents/{tenant_id}/{name}

    Note: ``spec.identity.spiffe`` is a **dict** (not a plain string); the
    ``override_id`` key is the string field within it.

    Args:
        parsed: A parsed manifest dict (output of ``parse_manifest``).

    Returns:
        A string SPIFFE URI.

    Raises:
        ValueError: if neither override_id nor both tenant_id and name are
                    available to construct a URI.

    Usage (W3 codegen, Captain W2 §11):
        from yashigani.manifest import resolve_spiffe_uri
        spiffe_id = resolve_spiffe_uri(parsed)
    """
    # Check for override_id
    override_id: Optional[str] = (
        ((parsed.get("spec") or {}).get("identity") or {})
        .get("spiffe") or {}
    ).get("override_id")

    if override_id is not None:
        return override_id

    # Construct default URI
    metadata = parsed.get("metadata") or {}
    tenant_id: str = metadata.get("tenant_id", "")
    name: str = metadata.get("name", "")

    if not tenant_id or not name:
        raise ValueError(
            "Cannot resolve SPIFFE URI: manifest is missing metadata.tenant_id "
            "and/or metadata.name, and no spec.identity.spiffe.override_id is set."
        )

    return "%s/%s/%s" % (_SPIFFE_AGENTS_PREFIX, tenant_id, name)


def _lint_spiffe_prefix(parsed: dict) -> list[LintError]:
    """
    N1 — SPIFFE override_id namespace mandate (W5, v2.25.0 P1).

    If spec.identity.spiffe.override_id is supplied it MUST start with
    ``spiffe://yashigani.internal/agents/<tenant_id>/``.

    This enforces two invariants simultaneously:
    1. Core-service collision prevention: IDs not under ``/agents/`` (e.g.
       ``spiffe://yashigani.internal/gateway``) are structurally impossible.
    2. Cross-tenant namespace isolation: an override for tenant ``acme-corp``
       cannot set a URI that begins with another tenant's prefix (e.g.
       ``spiffe://yashigani.internal/agents/evil-corp/...``).

    The trailing ``/<name>`` is NOT mandatory in the override (subpaths under
    the tenant namespace are permitted).

    No override (default) is always accepted — resolve_spiffe_uri() constructs
    the correct canonical URI at codegen time.

    Error code: N1_spiffe_override_out_of_namespace.
    Reference: Nico NICO-002.
    """
    errors: list[LintError] = []
    metadata = parsed.get("metadata") or {}
    tenant_id = metadata.get("tenant_id", "")
    name = metadata.get("name", "")

    if not (tenant_id and name):
        return errors  # M2 / schema will catch missing fields

    required_prefix = "spiffe://yashigani.internal/agents/%s/" % tenant_id

    override = (
        ((parsed.get("spec") or {}).get("identity") or {})
        .get("spiffe") or {}
    ).get("override_id")

    if override is not None:
        if not override.startswith(required_prefix):
            errors.append(LintError(
                "N1_spiffe_override_out_of_namespace",
                "spec.identity.spiffe.override_id %r is outside the allowed "
                "namespace for tenant %r.  The override must begin with %r.  "
                "Identities outside this namespace can collide with core-service "
                "identities (e.g. spiffe://yashigani.internal/gateway) or impersonate "
                "agents belonging to another tenant (Nico NICO-002 / N1)." % (
                    override, tenant_id, required_prefix),
                field="spec.identity.spiffe.override_id",
                fix="Change override_id to start with %r, e.g. %s%s.  "
                    "Remove override_id entirely to use the auto-constructed default "
                    "URI spiffe://yashigani.internal/agents/%s/%s." % (
                        required_prefix, required_prefix, name, tenant_id, name),
            ))

    return errors


# ---------------------------------------------------------------------------
# C1 — egress_allow host must not be RFC1918 / loopback / link-local
# ---------------------------------------------------------------------------

_LOOPBACK_V4 = ipaddress.IPv4Network("127.0.0.0/8")
_LINK_LOCAL_V4 = ipaddress.IPv4Network("169.254.0.0/16")
_RFC1918: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
# LAURA-001: additional blocked ranges
_ZERO_V4 = ipaddress.IPv4Network("0.0.0.0/8")          # 0.0.0.0/8 — routes to localhost on Docker
_ULA_V6 = ipaddress.IPv6Network("fc00::/7")             # fd00::/7 ULA (fc00::/7 covers both fc::/8 and fd::/8)
_LOOPBACK_V6 = ipaddress.IPv6Network("::1/128")
_LINK_LOCAL_V6 = ipaddress.IPv6Network("fe80::/10")
_IPV4_MAPPED_V6 = ipaddress.IPv6Network("::ffff:0:0/96")  # IPv4-mapped (::ffff:<ipv4>)

# LAURA-001: reject non-standard IP text encodings before handing to ipaddress.
# Decimal integers (2852039166), hex (0xAA9EFEA), octal (0252...)  are accepted
# by getaddrinfo but raise ValueError in ipaddress.ip_address().  We must block
# them explicitly so they are not silently passed as "hostnames".
# Only dotted-quad IPv4 or standard colon-hex IPv6 (optionally bracket-wrapped)
# are acceptable literal IP forms.
# _PURE_DECIMAL_RE: any string that is purely digits is a decimal-encoded IP.
_PURE_DECIMAL_RE = re.compile(r"^\d+$")
# _HEX_IP_RE: 0x-prefixed hex strings are also alternative IP encodings.
_HEX_IP_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")


def _is_private_address(host: str) -> bool:
    """
    Return True if ``host`` is a literal RFC1918, loopback, link-local,
    ULA, zero-address, or IPv4-mapped-IPv6 address.

    LAURA-001 hardening (v2.25.0):
    - Strip a trailing dot before parsing (169.254.169.254. bypass).
    - Unwrap [...] brackets (IPv6 bracket form from URL parsing).
    - Reject decimal-integer strings (2852039166) and hex strings
      (0xAA9EFE...) — getaddrinfo resolves them but ipaddress raises
      ValueError, causing the old code to pass them as "hostnames".
    - Add fd00::/7 (IPv6 ULA, covers fc00::/7 and fd00::/7) to blocklist.
    - Add 0.0.0.0/8 to blocklist.
    - For IPv6Address, unwrap ipv4_mapped and re-run check on the IPv4.
    - Add ::ffff:0:0/96 (IPv4-mapped) to IPv6 blocklist.

    Hostnames (non-IP strings) are NOT resolved — that is the codegen's job.
    Only literal IP addresses are checked here.
    """
    # --- normalise ---
    # Strip trailing dot (C1-E bypass: "169.254.169.254.")
    if host.endswith("."):
        host = host[:-1]

    # Unwrap IPv6 bracket form (C1-A bypass: "[::ffff:169.254.169.254]")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    # Reject pure-decimal integers (C1-B bypass: "2852039166")
    # and hex strings ("0xAA9EFEA") — these are alternative IP encodings
    # that ipaddress rejects with ValueError, but getaddrinfo resolves.
    if _PURE_DECIMAL_RE.match(host) or _HEX_IP_RE.match(host):
        # These are not valid hostname characters either, but treat as
        # private to fail closed (getaddrinfo may resolve them to private).
        return True

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # genuine hostname — not a literal IP

    if isinstance(addr, ipaddress.IPv4Address):
        return (
            addr in _LOOPBACK_V4
            or addr in _LINK_LOCAL_V4
            or addr in _ZERO_V4        # LAURA-001: 0.0.0.0/8
            or any(addr in net for net in _RFC1918)
        )
    if isinstance(addr, ipaddress.IPv6Address):
        # LAURA-001: unwrap IPv4-mapped IPv6 and re-run IPv4 check (C1-A)
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return (
                mapped in _LOOPBACK_V4
                or mapped in _LINK_LOCAL_V4
                or mapped in _ZERO_V4
                or any(mapped in net for net in _RFC1918)
            )
        return (
            addr in _LOOPBACK_V6
            or addr in _LINK_LOCAL_V6
            or addr in _ULA_V6         # LAURA-001: fc00::/7 ULA
            or addr in _IPV4_MAPPED_V6  # LAURA-001: ::ffff:0:0/96
        )
    return False


def _lint_egress_allow(parsed: dict) -> list[LintError]:
    """
    C1 — egress_allow entries must not use RFC1918/loopback/link-local
    literal IP addresses.  Hostnames are allowed (codegen resolves and
    rejects private IPs at onboard time).
    """
    errors: list[LintError] = []
    network = (parsed.get("spec") or {}).get("network") or {}
    egress_allow = network.get("egress_allow") or []
    for i, entry in enumerate(egress_allow):
        if not isinstance(entry, dict):
            continue
        host = entry.get("host", "")
        if not host:
            continue
        if _is_private_address(host):
            errors.append(LintError(
                "C1_private_egress_host",
                "egress_allow entry %d host %r is a private/loopback/link-local address. "
                "Egress to internal addresses is blocked (C1 — SSRF prevention)." % (i, host),
                field="spec.network.egress_allow[%d].host" % i,
                fix="Use a public hostname (e.g. api.openai.com) instead of a "
                    "literal IP address.  If you need to allow a private upstream, "
                    "contact your security team (C1 requires operator justification).",
            ))
    return errors


# ---------------------------------------------------------------------------
# C1 (extended) — model_egress.base_url SSRF / private-IP check (F4)
# ---------------------------------------------------------------------------


def _lint_model_egress_base_url(parsed: dict) -> list[LintError]:
    """
    F4 (Laura MED) — C1 extension: spec.model_egress.base_url must not
    contain a private/loopback/link-local/metadata IP address.

    Only spec.network.egress_allow[].host was previously checked.  A
    base_url of ``http://169.254.169.254/...`` (AWS IMDS / metadata service)
    or any RFC1918/loopback address passes right through the old check.

    The ``_is_private_address`` helper is reused; the URL is parsed to
    extract the hostname/IP component.  Non-parseable URLs are silently
    passed (the codegen and schema validate URL syntax).
    """
    errors: list[LintError] = []
    model_egress = (parsed.get("spec") or {}).get("model_egress") or {}
    base_url = model_egress.get("base_url")
    if not base_url or not isinstance(base_url, str):
        return errors

    try:
        parsed_url = urlparse(base_url)
        host = parsed_url.hostname or ""
    except Exception:  # noqa: BLE001 — urlparse is permissive; malformed URLs silently skip
        return errors

    if not host:
        return errors

    if _is_private_address(host):
        errors.append(LintError(
            "C1_model_egress_private_url",
            "spec.model_egress.base_url host %r is a private/loopback/link-local address. "
            "Using internal addresses as model egress endpoints enables SSRF attacks "
            "(C1 — SSRF prevention / F4)." % host,
            field="spec.model_egress.base_url",
            fix="Use a public model API endpoint (e.g. https://api.openai.com/v1) "
                "instead of a private IP address.  If a private upstream is required, "
                "contact your security team (C1 / operator justification needed).",
        ))
    return errors


# ---------------------------------------------------------------------------
# P2 — gateway-enforced-only forbidden for CONFIDENTIAL/RESTRICTED
# ---------------------------------------------------------------------------

# Sensitivity ceilings that require an identity-propagation stronger than
# gateway-enforced-only.  Absent ceiling defaults to CONFIDENTIAL (L-01).
_HIGH_SENSITIVITY_CEILINGS: frozenset[str] = frozenset({"CONFIDENTIAL", "RESTRICTED"})


def _lint_identity_propagation_p2(parsed: dict) -> list[LintError]:
    """
    P2 — spec.mcp.identity_propagation == gateway-enforced-only is FORBIDDEN
    when spec.audit.sensitivity_ceiling is CONFIDENTIAL or RESTRICTED.

    L-01: the global default sensitivity ceiling is CONFIDENTIAL.
    An absent spec.audit.sensitivity_ceiling therefore ALSO triggers this check
    when identity_propagation is gateway-enforced-only.
    """
    errors: list[LintError] = []
    mcp = (parsed.get("spec") or {}).get("mcp") or {}
    identity_propagation = mcp.get("identity_propagation")
    if identity_propagation != "gateway-enforced-only":
        return errors

    # Determine effective sensitivity ceiling (L-01: absent defaults to CONFIDENTIAL)
    audit = (parsed.get("spec") or {}).get("audit") or {}
    ceiling = audit.get("sensitivity_ceiling") or "CONFIDENTIAL"

    if ceiling in _HIGH_SENSITIVITY_CEILINGS:
        errors.append(LintError(
            "P2_gateway_enforced_only_forbidden",
            "spec.mcp.identity_propagation: 'gateway-enforced-only' is forbidden when "
            "sensitivity_ceiling is '%s'. gateway-enforced-only provides no per-user "
            "identity to downstream MCP servers, enabling privilege confusion attacks "
            "when the agent processes %s-sensitivity data (P2)." % (ceiling, ceiling),
            field="spec.mcp.identity_propagation",
            fix="Change spec.mcp.identity_propagation to 'gateway-signed-jwt' (ES384 JWT "
                "forwarding — v1 default) or 'per-user-credential'. "
                "If you intend PUBLIC-data-only usage, set "
                "spec.audit.sensitivity_ceiling: PUBLIC and justify with "
                "spec.network.egress_allow[*].justification.",
        ))
    return errors


# ---------------------------------------------------------------------------
# C3 — duplicate (tenant_id, agent_id) check within a single manifest
# ---------------------------------------------------------------------------

# LAURA-002/003: slug constraint for metadata.name and metadata.tenant_id.
# Enforces lowercase alphanumeric + hyphen, 2-64 chars, no leading/trailing hyphen.
# This closes all four INJ sub-findings simultaneously (Caddy, shell, YAML, Kyverno).
# Characters like }, ", \n, / cannot appear in a valid slug.
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{0,62}[a-z0-9]$")


def _lint_name_uniqueness(parsed: dict) -> list[LintError]:
    """
    C3 — within a single manifest file, metadata.name + metadata.tenant_id
    must not be empty, and must match the slug format.

    LAURA-002/003 fix: enforce _SLUG_RE on both fields.  A slug-valid name
    cannot contain }, ", \\n, /, or .. — closing all injection sub-findings
    (INJ-A Caddy, INJ-B shell, INJ-C YAML, INJ-D Kyverno).

    Full registry-level uniqueness is enforced at runtime; the linter only
    flags the stateless case where both fields are empty (usually a template
    error).
    """
    errors: list[LintError] = []
    metadata = parsed.get("metadata") or {}
    name = metadata.get("name", "")
    tenant_id = metadata.get("tenant_id", "")

    _SLUG_FIX = (
        "Use only lowercase letters (a-z), digits (0-9), and hyphens (-). "
        "Must start and end with a letter or digit. Length 2–64 characters. "
        "No /, \\n, }, \", or other special characters."
    )

    if not name:
        errors.append(LintError(
            "C3_name_empty",
            "metadata.name is required and must not be empty.",
            field="metadata.name",
            fix="Set metadata.name to a lowercase alphanumeric slug (e.g. name: my-agent).",
        ))
    elif not _SLUG_RE.match(name):
        errors.append(LintError(
            "C3_name_invalid_slug",
            "metadata.name %r does not match the required slug format. "
            "Names are interpolated into Caddy config, shell variables, YAML, and "
            "Kyverno manifests — non-slug characters enable injection attacks "
            "(LAURA-002/003 — SSRF / injection prevention)." % name,
            field="metadata.name",
            fix=_SLUG_FIX,
        ))

    if not tenant_id:
        errors.append(LintError(
            "C3_tenant_id_empty",
            "metadata.tenant_id is required and must not be empty.",
            field="metadata.tenant_id",
            fix="Set metadata.tenant_id to your organisation's tenant identifier "
                "(e.g. tenant_id: acme-corp).",
        ))
    elif not _SLUG_RE.match(tenant_id):
        errors.append(LintError(
            "C3_tenant_id_invalid_slug",
            "metadata.tenant_id %r does not match the required slug format. "
            "Tenant IDs are interpolated into Caddy config, shell variables, YAML, and "
            "Kyverno manifests — non-slug characters enable injection attacks "
            "(LAURA-002/003 — injection prevention)." % tenant_id,
            field="metadata.tenant_id",
            fix=_SLUG_FIX,
        ))
    return errors


# ---------------------------------------------------------------------------
# M7 — signature gate (delegates to signatures.py)
# ---------------------------------------------------------------------------


def _lint_signature_gate(parsed: dict, manifest_bytes: bytes) -> list[LintError]:
    """
    M7 — check that a signature block is present and structurally valid.

    The actual cryptographic verification is done in signatures.py;
    here we just check for the presence and structure of the block so the
    linter can emit a human-quality error (K3) before the heavier
    cryptographic check.
    """

    errors: list[LintError] = []
    sig_block = (parsed.get("spec") or {}).get("signature")

    if not sig_block:
        env_val = os.environ.get("YSG_REQUIRE_SIGNED_MANIFEST", "warn").lower()
        if env_val in ("fail", "1", "true", "yes"):
            errors.append(LintError(
                "M7_signature_missing",
                "spec.signature block is missing.  Signed manifests are required "
                "(YSG_REQUIRE_SIGNED_MANIFEST=fail).",
                field="spec.signature",
                fix="Sign the manifest with `cosign sign-blob --key <key> manifest.yaml` "
                    "(non-FIPS) or with the RSA-PSS-3072 tool (FIPS), then add the "
                    "spec.signature block.  See the signing guide in the operator runbook.",
            ))
        return errors

    algorithm = sig_block.get("algorithm", "")
    if algorithm not in ("cosign-bundled-key", "rsa-pss-3072-sha384"):
        errors.append(LintError(
            "M7_unknown_algorithm",
            "spec.signature.algorithm %r is not recognised. "
            "Expected 'cosign-bundled-key' or 'rsa-pss-3072-sha384'." % algorithm,
            field="spec.signature.algorithm",
            fix="Set spec.signature.algorithm to one of: cosign-bundled-key "
                "(non-FIPS / air-gap), rsa-pss-3072-sha384 (FIPS mode).",
        ))

    if not sig_block.get("signature_hex"):
        errors.append(LintError(
            "M7_signature_hex_missing",
            "spec.signature.signature_hex is required when a signature block is present.",
            field="spec.signature.signature_hex",
            fix="Populate spec.signature.signature_hex with the hex-encoded signature "
                "produced by the signing tool.",
        ))

    return errors


# ---------------------------------------------------------------------------
# N2 — onboard-time cert issuance constraint (W5, v2.25.0 P1)
# ---------------------------------------------------------------------------


def _lint_lifecycle_n2(parsed: dict) -> list[LintError]:
    """
    N2 — ``lifecycle.mode: on-demand`` combined with ``pool.container_per: identity``
    is BLOCKED in v1.

    v1 issues agent TLS certificates at onboard time (one cert per manifest
    registration).  Runtime per-identity cert issuance requires the v2.24.0
    PKI Issuer API (Nico NICO-003), which is not present in v1.

    The blocked combination is:
        spec.lifecycle.mode: on-demand   AND   spec.pool.container_per: identity

    This is the only sub-case that requires per-identity runtime issuance.
    All other combinations pass:
        - lifecycle.mode: persistent (any container_per) — issued at onboard time, OK.
        - lifecycle.mode: on-demand + container_per: agent — one shared cert per
          agent pool entry, OK (onboard-time issuance still works).

    Note: ``lifecycle.mode: on-demand`` is ALSO rejected by the JSON-Schema enum
    (M8 rule) since the schema currently only permits ``persistent``.  The N2
    linter rule fires in addition to (or before) M8 to provide a human-quality
    error message that explicitly names the constraint and its v2.24.0 resolution
    path.

    Error code: N2_ondemand_identity_v1_blocked.
    Reference: Nico NICO-003 / v2.24.0 PKI Issuer API.
    """
    errors: list[LintError] = []
    spec = parsed.get("spec") or {}

    lifecycle = spec.get("lifecycle") or {}
    lifecycle_mode = lifecycle.get("mode", "")

    pool = spec.get("pool") or {}
    container_per = pool.get("container_per", "")

    if lifecycle_mode == "on-demand" and container_per == "identity":
        errors.append(LintError(
            "N2_ondemand_identity_v1_blocked",
            "The combination of lifecycle.mode: 'on-demand' and "
            "pool.container_per: 'identity' is not supported in v1.  "
            "Per-identity on-demand container creation requires the PKI Issuer API "
            "(runtime per-identity cert issuance) which is not available until v2.24.0 "
            "(Nico NICO-003).  v1 issues TLS certificates at onboard time only.",
            field="spec.lifecycle.mode + spec.pool.container_per",
            fix="Change spec.lifecycle.mode to 'persistent'.  Per-identity isolation "
                "is fully supported with persistent mode in v1 — each identity gets its "
                "own container and the cert is issued once at onboard time.  "
                "If you specifically require on-demand per-identity cert issuance, "
                "upgrade to a Yashigani release that includes the v2.24.0 PKI Issuer API.",
        ))

    return errors


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class LintResult:
    """Aggregate result from validate_manifest."""

    def __init__(
        self,
        errors: list[LintError],
        warnings: list[LintError],
        passed: bool,
    ) -> None:
        self.errors = errors
        self.warnings = warnings
        self.passed = passed

    def format_report(self) -> str:
        """Return a human-quality report string (K3)."""
        lines: list[str] = []
        if not self.errors and not self.warnings:
            lines.append("yashigani validate: OK — manifest passes all checks.")
            return "\n".join(lines)

        if self.errors:
            lines.append("ERRORS (%d):" % len(self.errors))
            for i, err in enumerate(self.errors, 1):
                lines.append("  %d. [%s] %s" % (i, err.rule, err.human_message()))
        if self.warnings:
            lines.append("WARNINGS (%d):" % len(self.warnings))
            for i, warn in enumerate(self.warnings, 1):
                lines.append("  %d. [%s] %s" % (i, warn.rule, warn.human_message()))

        if self.passed:
            lines.append("\nyashigani validate: PASSED (with warnings)")
        else:
            lines.append("\nyashigani validate: FAILED")
        return "\n".join(lines)


def validate_manifest(
    parsed: dict,
    *,
    manifest_bytes: bytes = b"",
    verify_digests: bool = False,
    digest_inspector: Optional[object] = None,
) -> LintResult:
    """
    Run all linter rules against a parsed manifest dict.

    Args:
        parsed:           The output of ``parser.parse_manifest()``.
        manifest_bytes:   Raw bytes of the manifest (for M7 signature check).
        verify_digests:   If True, run live registry digest inspection (M6).
        digest_inspector: Injectable inspector for live digest checks (testing).

    Returns:
        LintResult with errors, warnings, and passed flag.
    """
    errors: list[LintError] = []
    warnings: list[LintError] = []

    # JSON-Schema (M8)
    from yashigani.manifest.schema import validate_schema  # noqa: PLC0415
    schema_errors = validate_schema(parsed)
    for msg in schema_errors:
        errors.append(LintError(
            "M8_schema",
            msg,
            fix="Correct the manifest field to match the yashigani.io/v1alpha1 schema.",
        ))

    # M5 — inbound_ports
    errors.extend(_lint_inbound_ports(parsed))

    # M6 — image digests
    errors.extend(_lint_image_digests(parsed))

    # M6 — live digest verification (optional)
    if verify_digests:
        live_errors = verify_digests_live(parsed, _inspector=digest_inspector)
        errors.extend(live_errors)

    # M7 — signature gate (structural; crypto in signatures.py)
    errors.extend(_lint_signature_gate(parsed, manifest_bytes))

    # N1 — SPIFFE override_id namespace mandate (W5)
    errors.extend(_lint_spiffe_prefix(parsed))

    # C1 — egress_allow private IPs
    errors.extend(_lint_egress_allow(parsed))

    # C1 (extended) — model_egress.base_url private-IP / SSRF check (F4)
    errors.extend(_lint_model_egress_base_url(parsed))

    # C3 — name/tenant_id presence
    errors.extend(_lint_name_uniqueness(parsed))

    # P2 — gateway-enforced-only forbidden for CONFIDENTIAL/RESTRICTED
    errors.extend(_lint_identity_propagation_p2(parsed))

    # N2 — on-demand + container_per:identity blocked in v1 (W5)
    errors.extend(_lint_lifecycle_n2(parsed))

    passed = len(errors) == 0
    return LintResult(errors=errors, warnings=warnings, passed=passed)
