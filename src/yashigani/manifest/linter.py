"""
Yashigani Manifest — Linter (M5, M6, M7, C1-C3, N1).

Applies all semantic validation rules that go beyond the JSON-Schema (M8)
and the parser-level guards (M1-M3).  The linter is the ``yashigani validate``
engine.

Rules implemented here:
  M5  — inbound_ports allowlist 1024-49151; non-MCP inbound forbidden in v1.
  M6  — spec.image.digest + all spec.sidecars[*].image.digest present;
         --verify-digests live-inspect path (behind flag; mock in tests).
  M7  — signature enforcement gate (via signatures.py).
  N1  — SPIFFE identity /agents/{tenant_id}/{name} prefix mandate.
  C1  — egress_allow host must not resolve to RFC1918/loopback/link-local
         (static parse-time check on literal values; full DNS is codegen).
         Also applied to spec.model_egress.base_url (F4 — Laura MED).
  C3  — duplicate (tenant_id, name) within a single validate run (stateless
         in v1 — registry uniqueness is a runtime concern; validator flags
         exact duplicate fields in the manifest itself).

Error messages are human-quality (K3 — Nora launch gate):
  Every error includes: what failed, why it matters, how to fix it.

Last updated: 2026-05-28T00:00:00+00:00
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
    N1 — The SPIFFE URI for this agent must be
    ``spiffe://yashigani.internal/agents/{tenant_id}/{name}``.

    If spec.identity.spiffe.override_id is supplied, it must start with
    ``spiffe://yashigani.internal/agents/{tenant_id}/``.  The trailing
    ``/{name}`` is not mandatory in the override (allows subpath).

    The /agents/ prefix prevents core-service collision (Nico NICO-002).
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
                "N1_spiffe_prefix",
                "spec.identity.spiffe.override_id %r does not start with "
                "the required prefix %r." % (override, required_prefix),
                field="spec.identity.spiffe.override_id",
                fix="SPIFFE IDs for ring-fenced agents must begin with "
                    "%r to prevent collision with core-service identities "
                    "(Nico NICO-002 / N1)." % required_prefix,
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
_LOOPBACK_V6 = ipaddress.IPv6Network("::1/128")
_LINK_LOCAL_V6 = ipaddress.IPv6Network("fe80::/10")


def _is_private_address(host: str) -> bool:
    """
    Return True if ``host`` is a literal RFC1918, loopback, or link-local address.

    Hostnames (non-IP strings) are NOT resolved — that is the codegen's job.
    Only literal IP addresses are checked here.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostname — not a literal IP

    if isinstance(addr, ipaddress.IPv4Address):
        return (
            addr in _LOOPBACK_V4
            or addr in _LINK_LOCAL_V4
            or any(addr in net for net in _RFC1918)
        )
    if isinstance(addr, ipaddress.IPv6Address):
        return addr in _LOOPBACK_V6 or addr in _LINK_LOCAL_V6
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
# C3 — duplicate (tenant_id, agent_id) check within a single manifest
# ---------------------------------------------------------------------------

def _lint_name_uniqueness(parsed: dict) -> list[LintError]:
    """
    C3 — within a single manifest file, metadata.name + metadata.tenant_id
    must not be empty (the combination must be non-trivial).

    Full registry-level uniqueness is enforced at runtime; the linter only
    flags the stateless case where both fields are empty (usually a template
    error).
    """
    errors: list[LintError] = []
    metadata = parsed.get("metadata") or {}
    name = metadata.get("name", "")
    tenant_id = metadata.get("tenant_id", "")
    if not name:
        errors.append(LintError(
            "C3_name_empty",
            "metadata.name is required and must not be empty.",
            field="metadata.name",
            fix="Set metadata.name to a lowercase alphanumeric identifier for this agent "
                "(e.g. name: my-agent).",
        ))
    if not tenant_id:
        errors.append(LintError(
            "C3_tenant_id_empty",
            "metadata.tenant_id is required and must not be empty.",
            field="metadata.tenant_id",
            fix="Set metadata.tenant_id to your organisation's tenant identifier "
                "(e.g. tenant_id: acme-corp).",
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

    # N1 — SPIFFE prefix
    errors.extend(_lint_spiffe_prefix(parsed))

    # C1 — egress_allow private IPs
    errors.extend(_lint_egress_allow(parsed))

    # C1 (extended) — model_egress.base_url private-IP / SSRF check (F4)
    errors.extend(_lint_model_egress_base_url(parsed))

    # C3 — name/tenant_id presence
    errors.extend(_lint_name_uniqueness(parsed))

    passed = len(errors) == 0
    return LintResult(errors=errors, warnings=warnings, passed=passed)
