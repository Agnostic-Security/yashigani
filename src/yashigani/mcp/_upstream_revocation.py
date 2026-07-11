"""
MCP Broker — external-upstream certificate REVOCATION watch (YSG-RISK-058).

Residual closed by this module
------------------------------
``_upstream_pin._get_cert_fingerprint_sha256`` pins the upstream leaf by
SHA-256 fingerprint EQUALITY.  A fingerprint pin proves *identity continuity*
(the cert is the one we onboarded) but says nothing about *validity*: a
**revoked-but-not-yet-rotated** leaf still matches the pinned fingerprint and
would be accepted.  External MCP upstreams are issued by public CAs, not our
internal CA, so the internal CRL/OCSP machinery (``pki/``) does not cover them.

Per Laura's threat model (PR #35) + Tiago's "only approved MCPs added" posture:
the approved set is curated, but a revoked cert *inside* the approved set must
still be caught.  This module is the revocation channel.

Layers (Laura L1 / L2)
----------------------
* **L1 — revocation-watch + short pin-TTL.**  From the live leaf we extract the
  AIA OCSP responder URL and the CRL distribution points.  We actively query
  OCSP and BLOCK on a ``REVOKED`` verdict.  A CRL distribution point, if present,
  only satisfies the strict *has-a-revocation-channel* check — no CRL is fetched
  or parsed in 3.1 (active CRL fetch is a 3.2 item).  A pin older than
  ``max_pin_age`` is treated as stale and must be re-validated before use.
* **L2 — OCSP freshness (synchronous, highest leverage).**  An OCSP verdict is
  only honoured if it is *fresh*: ``this_update`` is in the past and
  ``next_update`` is in the future, within ``ocsp_max_age``.  A stale OCSP
  response (replayed "good" past its validity) is rejected.

  stdlib note (ground-truthed 2026-06-10): Python's ``ssl`` module exposes NO
  API to read a *stapled* OCSP response from the live handshake, and pyOpenSSL
  is not a dependency (and the ``cryptography`` aarch64 pin is fragile — see
  pyproject).  So L2 is implemented as an **active OCSP fetch** with the SAME
  freshness contract a stapled check would enforce.  ``_get_stapled_ocsp`` is a
  pluggable hook: if a stapled response is ever made available (pyOpenSSL or a
  sidecar), it is preferred over an active fetch with NO change to this contract.

strict_mode (buyer-facing hard option) — strict by default since v3.1
-----------------------------------------------------------------------
``strict_mode`` defaults to **True** (changed from False in v3.1-fix; controlled
via ``YASHIGANI_MCP_REVOCATION_STRICT``).

When a cert presents NO revocation channel (NO_CHANNEL) the response is
**environment-gated**:

* In ``production`` or ``staging`` (``YASHIGANI_ENV`` in the enforcing set
  ``_ENFORCE_ENVS``): strict_mode=True **REFUSES** the upstream — there is no
  channel to prove the cert is unrevoked.  The operator may override by setting
  ``YASHIGANI_MCP_REVOCATION_STRICT=false``; the residual is then bounded by
  ``max_pin_age``.
* In dev/test (``YASHIGANI_ENV`` unset or not an enforcing env): strict_mode=True
  is **warn-only** on NO_CHANNEL.  Fingerprint-pinned self-signed MCP upstreams
  (no OCSP/CRL) are usable in dev without config changes.  The refusal kicks in
  automatically when the env is promoted to production.

``strict_mode=False`` disables the NO_CHANNEL block in **all** envs.

REVOKED and STALE are **never** env-gated — they always block, in all
environments and regardless of strict_mode.

Residual (documented)
----------------------
Where the external CA offers neither stapling nor OCSP nor CRL AND the operator
sets ``YASHIGANI_MCP_REVOCATION_STRICT=false`` (or is running in a dev env), a
revoked-but-unrotated leaf is only caught when the pin ages past ``max_pin_age``
and is re-onboarded.  The exposure is therefore **bounded by ``max_pin_age``**.
In production with the default strict posture, such an upstream is simply refused.

YSG-RISK-051 (risk-register) / code-label YSG-RISK-058 /
Laura external-upstream-revocation threat model (PR #35) / release 3.0.
Strict-by-default + env-gate added in 3.1-fix.

Last updated: 2026-07-02T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import time
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtensionOID,
)
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_response,
)

logger = logging.getLogger(__name__)

# Environments where a strict NO_CHANNEL verdict REFUSES the upstream.
# Dev/test is warn-only even when strict_mode=True (self-signed MCP compatibility).
# Single source of truth: McpBroker._ENFORCE_PIN_ENVS imports this constant so
# both layers share the same definition without duplication.
_ENFORCE_ENVS: frozenset[str] = frozenset({"production", "staging"})

# Audit labels (consumed by broker._emit_upstream_pin_event-style writers).
REVOKED_LABEL = "MCP_UPSTREAM_CERT_REVOKED"
REVOCATION_STALE_LABEL = "MCP_UPSTREAM_REVOCATION_STALE"
REVOCATION_NO_CHANNEL_LABEL = "MCP_UPSTREAM_NO_REVOCATION_CHANNEL"
REVOCATION_PIN_EXPIRED_LABEL = "MCP_UPSTREAM_PIN_AGE_EXPIRED"


class RevocationStatus(str, Enum):
    """Outcome of a revocation check for one upstream leaf."""
    GOOD = "good"                 # explicitly not-revoked, fresh evidence
    REVOKED = "revoked"           # CA says revoked — BLOCK, always
    UNKNOWN = "unknown"           # responder reachable but no definite answer
    STALE = "stale"              # evidence too old to trust (L2 freshness fail)
    NO_CHANNEL = "no_channel"    # cert exposes no OCSP and no CRL
    ERROR = "error"              # network / parse error fetching evidence
    PIN_EXPIRED = "pin_expired"  # pin older than max_pin_age — must re-validate


@dataclass
class RevocationConfig:
    """
    Revocation-watch configuration for external MCP upstreams.

    Attributes
    ----------
    strict_mode:
        When True (default since v3.1), an upstream that presents NO revocation
        channel (NO_CHANNEL) is REFUSED in production/staging enforcing envs
        (``YASHIGANI_ENV in _ENFORCE_ENVS``).  In dev/test environments the
        block is warn-only so self-signed MCP upstreams remain usable during
        development.  Set ``YASHIGANI_MCP_REVOCATION_STRICT=false`` to disable
        in production, accepting the residual bounded by ``max_pin_age``.
    max_pin_age_seconds:
        A fingerprint pin older than this MUST be re-validated against a live
        revocation channel before the upstream is used.  Bounds the residual
        when no live channel is reachable.  Default 24h.
    ocsp_max_age_seconds:
        L2 freshness window: an OCSP response whose ``this_update`` is older
        than this is treated as STALE even if ``next_update`` has not passed.
        Default 1h.
    http_timeout_seconds:
        Timeout for OCSP/CRL fetches.  Default 5s.
    """
    strict_mode: bool = True
    max_pin_age_seconds: int = 24 * 3600
    ocsp_max_age_seconds: int = 3600
    http_timeout_seconds: float = 5.0


def _config_from_env() -> RevocationConfig:
    """Build a RevocationConfig from YASHIGANI_MCP_REVOCATION_* env vars."""
    def _b(name: str, default: bool) -> bool:
        v = os.environ.get(name)
        if v is None:
            return default
        return v.strip().lower() in ("1", "true", "yes", "on")

    def _i(name: str, default: int) -> int:
        v = os.environ.get(name)
        try:
            return int(v) if v is not None else default
        except ValueError:
            return default

    return RevocationConfig(
        strict_mode=_b("YASHIGANI_MCP_REVOCATION_STRICT", True),
        max_pin_age_seconds=_i("YASHIGANI_MCP_PIN_MAX_AGE_SECONDS", 24 * 3600),
        ocsp_max_age_seconds=_i("YASHIGANI_MCP_OCSP_MAX_AGE_SECONDS", 3600),
        http_timeout_seconds=float(_i("YASHIGANI_MCP_REVOCATION_TIMEOUT", 5)),
    )


@dataclass
class RevocationResult:
    """Result of a revocation check."""
    status: RevocationStatus
    reason: str                          # stable machine label
    blocks: bool                         # True => caller MUST refuse the upstream
    ocsp_this_update: Optional[str] = None
    ocsp_next_update: Optional[str] = None


# ---------------------------------------------------------------------------
# Cert extraction helpers
# ---------------------------------------------------------------------------


def _extract_ocsp_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.OCSP
    ]


def _extract_ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return []
    return [
        d.access_location.value
        for d in aia
        if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]


def _extract_crl_urls(cert: x509.Certificate) -> list[str]:
    try:
        crldp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []
    urls: list[str] = []
    for dp in crldp:
        if dp.full_name:
            for name in dp.full_name:
                val = getattr(name, "value", None)
                if isinstance(val, str) and val.startswith("http"):
                    urls.append(val)
    return urls


def _has_revocation_channel(cert: x509.Certificate) -> bool:
    return bool(_extract_ocsp_urls(cert) or _extract_crl_urls(cert))


# ---------------------------------------------------------------------------
# OCSP fetch + freshness (L1 + L2)
# ---------------------------------------------------------------------------


def _http_post_der(url: str, body: bytes, timeout: float) -> bytes:
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/ocsp-request"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (URL is from cert AIA)
        return resp.read()


def _http_get(url: str, timeout: float) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def _default_ocsp_fetch(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    ocsp_url: str,
    timeout: float,
) -> bytes:
    """Build + send an OCSP request, return the raw DER response bytes."""
    builder = OCSPRequestBuilder().add_certificate(leaf, issuer, hashes.SHA1())
    req = builder.build()
    return _http_post_der(ocsp_url, req.public_bytes(_der_encoding()), timeout)


def _der_encoding():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def _aware(dt: datetime) -> datetime:
    """Normalise a (possibly naive, UTC) x509 datetime to aware-UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _evaluate_ocsp_response(
    der: bytes,
    config: RevocationConfig,
    now: Optional[float] = None,
) -> RevocationResult:
    """
    Parse + evaluate an OCSP response DER.  Enforces L2 freshness.

    GOOD only when: responder SUCCESSFUL, cert_status GOOD, this_update <= now,
    next_update (if present) > now, and this_update within ocsp_max_age.
    """
    now_ts = time.time() if now is None else now
    try:
        resp = load_der_ocsp_response(der)
    except Exception as exc:  # noqa: BLE001
        return RevocationResult(
            RevocationStatus.ERROR, f"ocsp_parse_error:{type(exc).__name__}", blocks=False
        )

    if resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        return RevocationResult(
            RevocationStatus.UNKNOWN,
            f"ocsp_status:{resp.response_status.name}",
            blocks=False,
        )

    # cert_status: REVOKED always blocks.
    if resp.certificate_status == OCSPCertStatus.REVOKED:
        return RevocationResult(RevocationStatus.REVOKED, REVOKED_LABEL, blocks=True)

    if resp.certificate_status == OCSPCertStatus.UNKNOWN:
        return RevocationResult(RevocationStatus.UNKNOWN, "ocsp_cert_unknown", blocks=False)

    # cert_status == GOOD — now enforce L2 freshness.
    this_update = getattr(resp, "this_update_utc", None) or resp.this_update
    next_update = getattr(resp, "next_update_utc", None) or resp.next_update
    tu = _aware(this_update) if this_update else None
    nu = _aware(next_update) if next_update else None
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)

    if tu is None:
        return RevocationResult(
            RevocationStatus.STALE, "ocsp_no_this_update", blocks=True,
        )
    if tu > now_dt:
        # this_update in the future — tampered / clock skew, reject conservatively.
        return RevocationResult(
            RevocationStatus.STALE, "ocsp_this_update_future", blocks=True,
            ocsp_this_update=tu.isoformat(),
        )
    if nu is not None and nu <= now_dt:
        return RevocationResult(
            RevocationStatus.STALE, REVOCATION_STALE_LABEL, blocks=True,
            ocsp_this_update=tu.isoformat(), ocsp_next_update=nu.isoformat(),
        )
    if (now_dt - tu).total_seconds() > config.ocsp_max_age_seconds:
        return RevocationResult(
            RevocationStatus.STALE, REVOCATION_STALE_LABEL, blocks=True,
            ocsp_this_update=tu.isoformat(),
        )

    return RevocationResult(
        RevocationStatus.GOOD, "ok", blocks=False,
        ocsp_this_update=tu.isoformat(),
        ocsp_next_update=nu.isoformat() if nu else None,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def check_revocation(
    leaf_der: bytes,
    *,
    issuer_der: Optional[bytes] = None,
    pin_age_seconds: Optional[float] = None,
    config: Optional[RevocationConfig] = None,
    now: Optional[float] = None,
    # Injection hooks for testing (override live network).
    _get_stapled_ocsp: Optional[Callable[[], Optional[bytes]]] = None,
    _ocsp_fetch: Optional[Callable[..., bytes]] = None,
    _fetch_issuer: Optional[Callable[[str, float], bytes]] = None,
) -> RevocationResult:
    """
    Check an external upstream leaf for revocation (YSG-RISK-058).

    Parameters
    ----------
    leaf_der:
        DER bytes of the upstream leaf cert (same bytes the fingerprint pin hashes).
    issuer_der:
        DER bytes of the issuer cert (needed to build the OCSP request).  When
        absent it is fetched from the AIA CA-issuers URL.
    pin_age_seconds:
        Age of the fingerprint pin.  When older than ``max_pin_age_seconds`` and
        no live GOOD verdict is obtained, the result blocks (PIN_EXPIRED) so a
        stale pin cannot mask a revocation that happened after onboard.
    config:
        RevocationConfig (defaults from env / RevocationConfig()).

    Returns
    -------
    RevocationResult — ``blocks=True`` means the caller MUST refuse the upstream.

    Fail-closed semantics:
      * REVOKED    -> blocks (always, every env).
      * STALE      -> blocks (L2: evidence too old to trust; every env).
      * NO_CHANNEL -> blocks in strict_mode (default True) ONLY when
                      YASHIGANI_ENV is in the enforcing set (production/staging).
                      In dev/test envs strict_mode is warn-only on NO_CHANNEL so
                      self-signed MCP upstreams remain usable.
      * PIN_EXPIRED -> blocks (pin too old, no fresh GOOD verdict).
      * ERROR / UNKNOWN -> does NOT block on its own (fingerprint pin still holds),
        UNLESS the pin is also expired.
    """
    cfg = config if config is not None else _config_from_env()
    now_ts = time.time() if now is None else now

    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as exc:  # noqa: BLE001
        return RevocationResult(
            RevocationStatus.ERROR, f"leaf_parse_error:{type(exc).__name__}", blocks=True
        )

    has_channel = _has_revocation_channel(leaf)

    # --- strict-mode: refuse an upstream with no revocation channel in enforcing envs. ---
    if not has_channel:
        if cfg.strict_mode:
            _env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
            if _env in _ENFORCE_ENVS:
                # Production/staging: NO revocation channel is a hard block.
                # A self-signed upstream with no OCSP/CRL must be explicitly allowed
                # via YASHIGANI_MCP_REVOCATION_STRICT=false; exposure then bounded by
                # max_pin_age.  REVOKED/STALE always block regardless of this gate.
                logger.warning(
                    "revocation-watch: %s leaf has NO OCSP and NO CRL — strict_mode "
                    "REFUSES upstream (env=%s). To allow a self-signed upstream set "
                    "YASHIGANI_MCP_REVOCATION_STRICT=false (residual bounded by "
                    "max_pin_age=%ds).",
                    REVOCATION_NO_CHANNEL_LABEL, _env, cfg.max_pin_age_seconds,
                )
                return RevocationResult(
                    RevocationStatus.NO_CHANNEL, REVOCATION_NO_CHANNEL_LABEL, blocks=True
                )
            # Dev/test: strict_mode=True on NO_CHANNEL is warn-only so self-signed MCP
            # upstreams (no OCSP/CRL) remain usable during development.  This enforcement
            # activates automatically when YASHIGANI_ENV is set to production/staging.
            logger.warning(
                "revocation-watch: %s leaf has NO OCSP and NO CRL — strict_mode=True but "
                "env=%r is not an enforcing environment; warn-only. "
                "In production/staging this upstream would be REFUSED.",
                REVOCATION_NO_CHANNEL_LABEL, _env,
            )
        else:
            logger.warning(
                "revocation-watch: %s leaf has NO OCSP and NO CRL — fingerprint pin is "
                "the only control (residual bounded by max_pin_age=%ds; "
                "YASHIGANI_MCP_REVOCATION_STRICT=false override intentional).",
                REVOCATION_NO_CHANNEL_LABEL, cfg.max_pin_age_seconds,
            )
        # Pin-age still applies even without a channel (both strict warn-only and non-strict):
        # an over-age pin with no way to re-validate must be refused so the residual
        # stays bounded.
        if pin_age_seconds is not None and pin_age_seconds > cfg.max_pin_age_seconds:
            return RevocationResult(
                RevocationStatus.PIN_EXPIRED, REVOCATION_PIN_EXPIRED_LABEL, blocks=True
            )
        return RevocationResult(
            RevocationStatus.NO_CHANNEL, REVOCATION_NO_CHANNEL_LABEL, blocks=False
        )

    # Default verdict if no evidence is obtained (channel exists but unreachable).
    result = RevocationResult(RevocationStatus.UNKNOWN, "no_ocsp_evidence", blocks=False)

    # --- L2 first: a stapled OCSP response (preferred when available). ---
    der: Optional[bytes] = None
    if _get_stapled_ocsp is not None:
        try:
            der = _get_stapled_ocsp()
        except Exception as exc:  # noqa: BLE001
            logger.info("revocation-watch: stapled OCSP unavailable: %s", exc)
            der = None

    # --- L1: active OCSP fetch via AIA when no staple. ---
    if der is None:
        ocsp_urls = _extract_ocsp_urls(leaf)
        if ocsp_urls:
            issuer = _resolve_issuer(leaf, issuer_der, cfg, _fetch_issuer)
            if issuer is None:
                result = RevocationResult(
                    RevocationStatus.ERROR, "ocsp_issuer_unavailable", blocks=False
                )
            else:
                fetch = _ocsp_fetch if _ocsp_fetch is not None else _default_ocsp_fetch
                try:
                    der = fetch(leaf, issuer, ocsp_urls[0], cfg.http_timeout_seconds)
                except Exception as exc:  # noqa: BLE001
                    logger.info(
                        "revocation-watch: OCSP fetch failed url=%s: %s", ocsp_urls[0], exc
                    )
                    der = None
                    result = RevocationResult(
                        RevocationStatus.ERROR,
                        f"ocsp_fetch_error:{type(exc).__name__}",
                        blocks=False,
                    )

    if der is not None:
        result = _evaluate_ocsp_response(der, cfg, now=now_ts)

    # REVOKED / STALE block unconditionally.
    if result.status in (RevocationStatus.REVOKED, RevocationStatus.STALE):
        return result

    # Pin-age fail-closed: no fresh GOOD verdict + over-age pin => block.
    if result.status != RevocationStatus.GOOD:
        if pin_age_seconds is not None and pin_age_seconds > cfg.max_pin_age_seconds:
            logger.warning(
                "revocation-watch: %s pin_age=%.0fs > max=%ds and no fresh GOOD verdict "
                "(status=%s) — refusing upstream",
                REVOCATION_PIN_EXPIRED_LABEL, pin_age_seconds, cfg.max_pin_age_seconds,
                result.status.value,
            )
            return RevocationResult(
                RevocationStatus.PIN_EXPIRED, REVOCATION_PIN_EXPIRED_LABEL, blocks=True
            )

    return result


def _resolve_issuer(
    leaf: x509.Certificate,
    issuer_der: Optional[bytes],
    cfg: RevocationConfig,
    fetch_issuer: Optional[Callable[[str, float], bytes]],
) -> Optional[x509.Certificate]:
    """Return the issuer cert: provided DER, else fetched from AIA CA-issuers."""
    if issuer_der is not None:
        try:
            return x509.load_der_x509_certificate(issuer_der)
        except Exception:  # noqa: BLE001
            return None
    urls = _extract_ca_issuer_urls(leaf)
    if not urls:
        return None
    fetch = fetch_issuer if fetch_issuer is not None else _http_get
    try:
        data = fetch(urls[0], cfg.http_timeout_seconds)
    except Exception:  # noqa: BLE001
        return None
    # CA-issuers data is usually a single DER cert (sometimes PEM).
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:  # noqa: BLE001
        try:
            return x509.load_pem_x509_certificate(data)
        except Exception:  # noqa: BLE001
            return None
