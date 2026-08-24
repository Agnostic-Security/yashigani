"""
Service identity + manifest loader for Yashigani internal PKI.

Last updated: 2026-04-28T20:30:00+00:00

This module is import-safe from any service entrypoint. It does no network
I/O, no cryptographic operations beyond SHA-256 (stdlib hashlib), and does
not depend on the heavier ``cryptography`` package. The cryptography package
is only required by :mod:`yashigani.pki.issuer` which runs inside install.sh
and admin-API rotation endpoints.

Refined PKI trust pattern (2026-04-28, post gate #58a evidence):
  * Python ssl consumers      → trust anchor = ca_root.crt (Pattern A).
                                  Python 3.12 / OpenSSL 3.0 / Ubuntu 24.04 does
                                  not auto-set X509_V_FLAG_PARTIAL_CHAIN, so an
                                  intermediate-only anchor fails strict chain
                                  validation. The PUBLIC ca_root.crt is loaded
                                  into the workload container; the PRIVATE
                                  ca_root.key never leaves the host (0400).
  * postgres / libpq          → sslrootcert = ca_intermediate.crt (Pattern B,
                                  partial-chain capable).
  * Caddy / Go crypto/tls     → ca_intermediate.crt (Pattern B).
  * pgbouncer / Redis libssl  → ca_root.crt (Pattern A; libssl-direct strict).

Environment inputs at runtime:
    YASHIGANI_SERVICE_NAME          — e.g. "gateway", "backoffice" (required)
    YASHIGANI_INTERNAL_CA_DIR       — where ca_root.crt + ca_intermediate.crt +
                                       <svc>_client.{crt,key} + <svc>_bootstrap_token live.
                                       Default: /run/secrets
    YASHIGANI_SERVICE_MANIFEST_PATH — path to service_identities.yaml.
                                       Default: /etc/yashigani/service_identities.yaml
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

try:
    import yaml  # type: ignore[import-untyped]  # PyYAML — present in base install (pydantic stack pulls it)
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "PyYAML is required for the service manifest. Install with: pip install pyyaml"
    ) from exc

logger = logging.getLogger(__name__)

_DEFAULT_SECRETS_DIR = "/run/secrets"
_DEFAULT_MANIFEST_PATH = "/etc/yashigani/service_identities.yaml"

_VALID_CA_MODES = {"yashigani_generated", "byo_intermediate", "byo_root", "remote_acme"}

# TB-07 (Lu, 4.1.2): this list was missing "igniter" and "professional_plus"
# entirely — added to LicenseTier by 8073620a (retro #42, 2026-05-06), which
# swept licensing/model.py's TIER_DEFAULTS but never touched this manifest
# validator/ordering list (same root cause as the sibling defects in
# auth/broker.py's _TIER_IDP_LIMITS and pool/manager.py's _TIER_LIMITS).
# Two distinct live consequences of the gap:
#   1. _parse_ca_source() (below) rejects any service_identities.yaml that
#      sets min_license_tier to "igniter" or "professional_plus" with a
#      ManifestError at manifest-LOAD time (blocks every service in the
#      manifest, not just the affected ca_source entry).
#   2. tier_at_least() — see below — silently returned False (deny) for any
#      *actual* deployed tier of "igniter" or "professional_plus" against
#      even the lowest bar ("community"), because ValueError from
#      .index("igniter") was caught by the existing fail-closed try/except.
#      An Igniter customer was denied "yashigani_generated" (the
#      free/default CA mode) despite Community-tier deployments passing.
#
# "academic_nonprofit" is intentionally listed but handled via the
# short-circuit in tier_at_least() below, not via list position — it is a
# PARALLEL unlimited tier (same as enterprise), not a linear step above
# enterprise, mirroring the identical "Enterprise and academic_nonprofit
# always qualify" special-case already established in
# backoffice/routes/license.py::_tier_gte(). It still needs list membership
# here because _parse_ca_source() also uses this list to validate that a
# manifest's min_license_tier VALUE names a real tier.
#
# LicenseTier.CANARY ("never issued to customers" per model.py) is
# deliberately NOT in this list — the existing `except ValueError: return
# False` in tier_at_least() already denies it, and canary must never
# satisfy any minimum-tier gate. Fail-closed convention kept unchanged.
_TIER_ORDER = [
    "community",
    "igniter",
    "starter",
    "professional",
    "professional_plus",
    "enterprise",
    "academic_nonprofit",
]


class ManifestError(ValueError):
    """Raised when service_identities.yaml is missing, malformed, or the
    requested service is not in the allowlist."""


class TamperError(RuntimeError):
    """Raised when the on-disk bootstrap token does not hash to the manifest
    entry — indicates the secrets dir was tampered with after install."""


# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ServiceIdentity:
    """One entry from service_identities.yaml."""

    name: str
    dns_sans: tuple[str, ...]
    purpose: str
    mtls_capable: bool
    bootstrap_token_sha256: str
    revoked: bool
    # SPIFFE URI embedded as URI SAN on the leaf cert (v2.23.1 — EX-231-08).
    # Empty string means "no SPIFFE identity" — treated as a soft default when
    # the manifest is mid-migration. Fresh manifests populate this for every
    # service. The issuer always emits a URI SAN when this is non-empty.
    spiffe_id: str = ""

    # Runtime-only fields resolved from the filesystem
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None
    ca_root_path: Optional[Path] = None

    def expect_cert_files(self) -> tuple[Path, Path, Path]:
        """Return (cert_path, key_path, ca_root_path) or raise."""
        if not (self.cert_path and self.key_path and self.ca_root_path):
            raise ManifestError(
                f"Service {self.name!r} has no cert paths resolved — "
                "is YASHIGANI_INTERNAL_CA_DIR populated by install.sh?"
            )
        for p in (self.cert_path, self.key_path, self.ca_root_path):
            if not p.exists():
                raise ManifestError(
                    f"Service {self.name!r}: expected cert file missing: {p}"
                )
        return self.cert_path, self.key_path, self.ca_root_path


@dataclass(frozen=True)
class CertPolicy:
    """Hard bounds from service_identities.yaml cert_policy block."""

    root_lifetime_years_min: int
    root_lifetime_years_max: int
    root_lifetime_years_default: int
    root_rotation_requires_manual_confirmation: bool

    intermediate_lifetime_days_min: int
    intermediate_lifetime_days_max: int
    intermediate_lifetime_days_default: int

    leaf_lifetime_days_min: int
    leaf_lifetime_days_max: int
    leaf_lifetime_days_default: int

    renewal_threshold: float

    def clamp_leaf(self, days: int) -> int:
        return max(self.leaf_lifetime_days_min, min(self.leaf_lifetime_days_max, days))

    def clamp_intermediate(self, days: int) -> int:
        return max(
            self.intermediate_lifetime_days_min,
            min(self.intermediate_lifetime_days_max, days),
        )

    def clamp_root(self, years: int) -> int:
        return max(
            self.root_lifetime_years_min,
            min(self.root_lifetime_years_max, years),
        )


@dataclass(frozen=True)
class CASource:
    mode: str  # one of _VALID_CA_MODES
    byo_root_cert_path: str = ""
    byo_intermediate_cert_path: str = ""
    byo_intermediate_key_path: str = ""
    remote_acme_driver: str = ""
    remote_acme_directory_url: str = ""
    remote_acme_eab_kid: str = ""
    remote_acme_eab_hmac_key_secret_ref: str = ""
    min_license_tier: dict[str, str] = field(default_factory=dict)

    def requires_license_tier(self) -> str:
        return self.min_license_tier.get(self.mode, "community")


@dataclass(frozen=True)
class EndpointAcl:
    """One parsed ``endpoint_acls`` rule (v4.1 Phase 1 — cert/rotate gate).

    ``allowed_spiffe_ids``
        Exact-match allowlist (the only field parsed before v4.1 Phase 1).
    ``allowed_spiffe_prefix``
        Optional prefix grant for agent self-service endpoints (e.g.
        ``spiffe://<td>/agents/`` lets every live agent identity call its OWN
        rotation endpoint without listing per-instance URIs in IaC).  Empty
        string disables prefix matching.
    ``verify_spiffe_matches_agent_id``
        When True, a prefix-matched caller is accepted ONLY if its SPIFFE
        ``agent_name`` or ``instance_id`` segment equals the route's
        ``{agent_id}`` path parameter — one agent can never rotate/poll
        another agent's identity.  Requires ``allowed_spiffe_prefix``.
    """
    allowed_spiffe_ids: frozenset[str]
    allowed_spiffe_prefix: str = ""
    verify_spiffe_matches_agent_id: bool = False


@dataclass(frozen=True)
class Manifest:
    schema_version: int
    services: tuple[ServiceIdentity, ...]
    cert_policy: CertPolicy
    ca_source: CASource
    # Top-level endpoint_acls: path -> EndpointAcl rule (exact allowlist +
    # optional agent-prefix grant). Empty dict means "no ACLs declared" —
    # yashigani.auth.spiffe defaults to deny on any gated endpoint.
    endpoint_acls: dict[str, EndpointAcl] = field(default_factory=dict)

    def get(self, name: str) -> ServiceIdentity:
        for s in self.services:
            if s.name == name:
                return s
        raise ManifestError(
            f"Service {name!r} is not in service_identities.yaml — "
            "rogue service, refusing to operate in the mesh."
        )

    def live_services(self) -> tuple[ServiceIdentity, ...]:
        """Services eligible for cert issuance (not revoked)."""
        return tuple(s for s in self.services if not s.revoked)


# ─────────────────────────────────────────────────────────────────────────────
# Loader
# ─────────────────────────────────────────────────────────────────────────────

def load_manifest(path: Optional[str] = None) -> Manifest:
    """Parse and validate the service_identities.yaml manifest.

    Raises :class:`ManifestError` on missing file, unknown schema version,
    or violated invariants.
    """
    resolved_path = cast(str, path or os.getenv("YASHIGANI_SERVICE_MANIFEST_PATH", _DEFAULT_MANIFEST_PATH))
    try:
        with open(resolved_path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise ManifestError(f"Service manifest not found at {path}") from exc
    except yaml.YAMLError as exc:
        raise ManifestError(f"Service manifest is not valid YAML: {exc}") from exc

    if not isinstance(doc, dict):
        raise ManifestError("Service manifest root must be a mapping")

    schema_version = doc.get("schema_version")
    if schema_version != 1:
        raise ManifestError(
            f"Unsupported schema_version {schema_version!r}; expected 1"
        )

    services_raw = doc.get("services", [])
    if not isinstance(services_raw, list) or not services_raw:
        raise ManifestError("service_identities.yaml has no services")

    services: list[ServiceIdentity] = []
    seen_names: set[str] = set()
    for idx, entry in enumerate(services_raw):
        if not isinstance(entry, dict):
            raise ManifestError(f"services[{idx}] is not a mapping")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise ManifestError(f"services[{idx}].name is missing or non-string")
        if name in seen_names:
            raise ManifestError(f"duplicate service name {name!r}")
        seen_names.add(name)

        sans = entry.get("dns_sans", [])
        if not isinstance(sans, list) or not all(isinstance(s, str) for s in sans):
            raise ManifestError(f"{name}: dns_sans must be a list of strings")

        purpose = entry.get("purpose", "")
        if not isinstance(purpose, str):
            raise ManifestError(f"{name}: purpose must be a string")

        mtls_capable = bool(entry.get("mtls_capable", True))
        bootstrap_token_sha256 = entry.get("bootstrap_token_sha256", "")
        if not isinstance(bootstrap_token_sha256, str):
            raise ManifestError(f"{name}: bootstrap_token_sha256 must be a string")
        revoked = bool(entry.get("revoked", False))

        spiffe_id = entry.get("spiffe_id", "") or ""
        if not isinstance(spiffe_id, str):
            raise ManifestError(f"{name}: spiffe_id must be a string")
        if spiffe_id and not spiffe_id.startswith("spiffe://"):
            raise ManifestError(
                f"{name}: spiffe_id {spiffe_id!r} must start with spiffe://"
            )

        services.append(
            ServiceIdentity(
                name=name,
                dns_sans=tuple(sans),
                purpose=purpose,
                mtls_capable=mtls_capable,
                bootstrap_token_sha256=bootstrap_token_sha256,
                revoked=revoked,
                spiffe_id=spiffe_id,
            )
        )

    policy = _parse_cert_policy(doc.get("cert_policy", {}))
    ca_source = _parse_ca_source(doc.get("ca_source", {}))
    endpoint_acls = _parse_endpoint_acls(doc.get("endpoint_acls", {}))

    return Manifest(
        schema_version=schema_version,
        services=tuple(services),
        cert_policy=policy,
        ca_source=ca_source,
        endpoint_acls=endpoint_acls,
    )


def _parse_endpoint_acls(raw: Any) -> dict[str, EndpointAcl]:
    """Parse the top-level endpoint_acls block into {path: EndpointAcl}.

    v4.1 Phase 1 (Nico Q1 — cert/rotate): ``allowed_spiffe_prefix`` and
    ``verify_spiffe_matches_agent_id`` were declared in service_identities.yaml
    since 4.0 Phase 0 but silently DROPPED by this parser — the ACL gate could
    therefore never honour the sidecar self-rotation grant. Now parsed and
    enforced by yashigani.auth.spiffe.require_spiffe_id.
    """
    if raw is None or raw == {}:
        return {}
    if not isinstance(raw, dict):
        raise ManifestError("endpoint_acls must be a mapping of path -> rule")
    out: dict[str, EndpointAcl] = {}
    for path, rule in raw.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise ManifestError(
                f"endpoint_acls key {path!r} must be a string path starting with '/'"
            )
        if not isinstance(rule, dict):
            raise ManifestError(f"endpoint_acls[{path!r}] must be a mapping")
        allowed = rule.get("allowed_spiffe_ids", [])
        if not isinstance(allowed, list) or not all(isinstance(s, str) for s in allowed):
            raise ManifestError(
                f"endpoint_acls[{path!r}].allowed_spiffe_ids must be a list of strings"
            )
        for sid in allowed:
            if not sid.startswith("spiffe://"):
                raise ManifestError(
                    f"endpoint_acls[{path!r}] contains non-SPIFFE id {sid!r}"
                )
        prefix = rule.get("allowed_spiffe_prefix", "") or ""
        if not isinstance(prefix, str):
            raise ManifestError(
                f"endpoint_acls[{path!r}].allowed_spiffe_prefix must be a string"
            )
        if prefix and not prefix.startswith("spiffe://"):
            raise ManifestError(
                f"endpoint_acls[{path!r}].allowed_spiffe_prefix {prefix!r} "
                "must start with spiffe://"
            )
        verify_match = bool(rule.get("verify_spiffe_matches_agent_id", False))
        if verify_match and not prefix:
            raise ManifestError(
                f"endpoint_acls[{path!r}]: verify_spiffe_matches_agent_id "
                "requires allowed_spiffe_prefix (exact-id callers carry no "
                "agent segment to match)"
            )
        out[path] = EndpointAcl(
            allowed_spiffe_ids=frozenset(allowed),
            allowed_spiffe_prefix=prefix,
            verify_spiffe_matches_agent_id=verify_match,
        )
    return out


def _parse_cert_policy(raw: Any) -> CertPolicy:
    if not isinstance(raw, dict):
        raise ManifestError("cert_policy must be a mapping")

    def _int(key: str, default: int) -> int:
        v = raw.get(key, default)
        if not isinstance(v, int) or isinstance(v, bool):
            raise ManifestError(f"cert_policy.{key} must be an integer")
        return v

    def _float(key: str, default: float) -> float:
        v = raw.get(key, default)
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise ManifestError(f"cert_policy.{key} must be numeric")
        return float(v)

    policy = CertPolicy(
        root_lifetime_years_min=_int("root_lifetime_years_min", 5),
        root_lifetime_years_max=_int("root_lifetime_years_max", 20),
        root_lifetime_years_default=_int("root_lifetime_years_default", 10),
        root_rotation_requires_manual_confirmation=bool(
            raw.get("root_rotation_requires_manual_confirmation", True)
        ),
        intermediate_lifetime_days_min=_int("intermediate_lifetime_days_min", 90),
        intermediate_lifetime_days_max=_int("intermediate_lifetime_days_max", 365),
        intermediate_lifetime_days_default=_int("intermediate_lifetime_days_default", 180),
        leaf_lifetime_days_min=_int("leaf_lifetime_days_min", 30),
        leaf_lifetime_days_max=_int("leaf_lifetime_days_max", 90),
        leaf_lifetime_days_default=_int("leaf_lifetime_days_default", 90),
        renewal_threshold=_float("renewal_threshold", 0.33),
    )
    _validate_policy(policy)
    return policy


def _validate_policy(policy: CertPolicy) -> None:
    if not (
        policy.root_lifetime_years_min
        <= policy.root_lifetime_years_default
        <= policy.root_lifetime_years_max
    ):
        raise ManifestError("cert_policy root default outside min/max bounds")
    if not (
        policy.intermediate_lifetime_days_min
        <= policy.intermediate_lifetime_days_default
        <= policy.intermediate_lifetime_days_max
    ):
        raise ManifestError("cert_policy intermediate default outside min/max bounds")
    if not (
        policy.leaf_lifetime_days_min
        <= policy.leaf_lifetime_days_default
        <= policy.leaf_lifetime_days_max
    ):
        raise ManifestError("cert_policy leaf default outside min/max bounds")
    if not (0.05 <= policy.renewal_threshold <= 0.9):
        raise ManifestError("cert_policy renewal_threshold must be between 0.05 and 0.9")


def _parse_ca_source(raw: Any) -> CASource:
    if not isinstance(raw, dict):
        raise ManifestError("ca_source must be a mapping")

    mode = raw.get("mode", "yashigani_generated")
    if mode not in _VALID_CA_MODES:
        raise ManifestError(
            f"ca_source.mode {mode!r} not in {sorted(_VALID_CA_MODES)}"
        )
    byo = raw.get("byo", {}) or {}
    rem = raw.get("remote_acme", {}) or {}
    min_tier_raw = raw.get("min_license_tier", {}) or {}
    if not isinstance(min_tier_raw, dict):
        raise ManifestError("ca_source.min_license_tier must be a mapping")
    for k, v in min_tier_raw.items():
        if v not in _TIER_ORDER:
            raise ManifestError(
                f"ca_source.min_license_tier[{k!r}]={v!r} not a known tier"
            )

    return CASource(
        mode=mode,
        byo_root_cert_path=str(byo.get("root_cert_path", "")),
        byo_intermediate_cert_path=str(byo.get("intermediate_cert_path", "")),
        byo_intermediate_key_path=str(byo.get("intermediate_key_path", "")),
        remote_acme_driver=str(rem.get("driver", "")),
        remote_acme_directory_url=str(rem.get("directory_url", "")),
        remote_acme_eab_kid=str(rem.get("eab_kid", "")),
        remote_acme_eab_hmac_key_secret_ref=str(rem.get("eab_hmac_key_secret_ref", "")),
        min_license_tier=dict(min_tier_raw),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Runtime self-resolution
# ─────────────────────────────────────────────────────────────────────────────

def current_service(
    *,
    verify_token: bool = True,
    secrets_dir: Optional[str] = None,
    manifest_path: Optional[str] = None,
) -> ServiceIdentity:
    """Resolve the ServiceIdentity for this container, populated with cert paths.

    Steps:
      1. Read YASHIGANI_SERVICE_NAME (required).
      2. Load manifest — if name not present -> ManifestError (rogue).
      3. If verify_token: read bootstrap token file, SHA-256 it, compare
         to manifest entry in constant time. Mismatch -> TamperError.
      4. Resolve cert file paths inside secrets_dir.
      5. Return ServiceIdentity with paths populated.
    """
    name = os.environ.get("YASHIGANI_SERVICE_NAME", "").strip()
    if not name:
        raise ManifestError(
            "YASHIGANI_SERVICE_NAME is not set — the container does not know "
            "its own identity. Add it to the service environment in compose."
        )

    manifest = load_manifest(manifest_path)
    identity = manifest.get(name)

    if identity.revoked:
        raise ManifestError(
            f"Service {name!r} is marked revoked: true in the manifest — "
            "refusing to start. Operator must un-revoke and rotate certs."
        )

    _resolved_secrets_dir = cast(str, secrets_dir or os.getenv("YASHIGANI_INTERNAL_CA_DIR", _DEFAULT_SECRETS_DIR))
    secrets_dir_path = Path(_resolved_secrets_dir)
    cert_path = secrets_dir_path / f"{name}_client.crt"
    key_path = secrets_dir_path / f"{name}_client.key"
    # Pattern A for Python ssl: trust anchor is the public root cert (NOT the
    # private root key). Python 3.12 / OpenSSL 3.0 on Ubuntu 24.04 does not
    # auto-set X509_V_FLAG_PARTIAL_CHAIN on SSLContext.load_verify_locations(),
    # so an intermediate-only anchor fails with "unable to get issuer
    # certificate" (gate #58a evidence, 2026-04-28). Caddy/Go/postgres remain
    # on Pattern B (partial-chain capable). Root PRIVATE key never enters a
    # workload container — only the public ca_root.crt does.
    ca_root = secrets_dir_path / "ca_root.crt"
    bootstrap_token_path = secrets_dir_path / f"{name}_bootstrap_token"

    if verify_token:
        _verify_bootstrap_token(identity, bootstrap_token_path)

    return ServiceIdentity(
        name=identity.name,
        dns_sans=identity.dns_sans,
        purpose=identity.purpose,
        mtls_capable=identity.mtls_capable,
        bootstrap_token_sha256=identity.bootstrap_token_sha256,
        revoked=identity.revoked,
        spiffe_id=identity.spiffe_id,
        cert_path=cert_path,
        key_path=key_path,
        ca_root_path=ca_root,
    )


def _verify_bootstrap_token(identity: ServiceIdentity, path: Path) -> None:
    """Read token from disk, hash it, compare constant-time to manifest."""
    if not identity.bootstrap_token_sha256:
        # First install path — install.sh will populate on rotation.
        # Refuse to start if the manifest declares the service at all
        # but the install step didn't complete.
        raise TamperError(
            f"Service {identity.name!r} has no bootstrap_token_sha256 in the "
            "manifest — install.sh bootstrap_internal_pki() did not run, or "
            "the manifest was not committed after install."
        )
    if not path.exists():
        raise TamperError(
            f"Bootstrap token for {identity.name!r} not found at {path} — "
            "secrets directory may have been tampered with."
        )
    try:
        token_bytes = path.read_bytes().strip()
    except OSError as exc:
        raise TamperError(f"Cannot read bootstrap token at {path}: {exc}") from exc
    actual_sha = hashlib.sha256(token_bytes).hexdigest()
    if not hmac.compare_digest(actual_sha, identity.bootstrap_token_sha256):
        raise TamperError(
            f"Bootstrap token SHA-256 mismatch for {identity.name!r}. "
            "The on-disk secret does not match the manifest. Refusing to start."
        )


def tier_at_least(actual: str, required: str) -> bool:
    """Return True if licensed tier *actual* meets *required* or higher.

    "enterprise" and "academic_nonprofit" are parallel unlimited tiers, not
    a linear order (mirrors backoffice/routes/license.py::_tier_gte's
    "Enterprise and academic_nonprofit always qualify" special-case) — both
    always satisfy any *required* tier. Everything else is resolved via
    _TIER_ORDER position; an unrecognised *actual* string (including the
    internal-only "canary" sentinel, deliberately excluded from
    _TIER_ORDER) fails closed to False via the ValueError catch below.
    """
    if actual in ("enterprise", "academic_nonprofit"):
        return True
    try:
        return _TIER_ORDER.index(actual) >= _TIER_ORDER.index(required)
    except ValueError:
        return False
