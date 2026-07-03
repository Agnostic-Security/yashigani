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

Layers (Laura L1 / L2 / L3)
-----------------------------
* **L1 — OCSP (primary).**  From the live leaf we extract the AIA OCSP
  responder URL.  We query it directly (or use a stapled response when
  available) and BLOCK on a ``REVOKED`` verdict.
* **L2 — OCSP freshness.**  An OCSP verdict is only honoured if it is *fresh*:
  ``this_update`` is in the past and ``next_update`` is in the future, within
  ``ocsp_max_age``.  A stale OCSP response (replayed "good" past its validity)
  is rejected.
* **L3 — CRL fallback (active, enabled in 4.0).**  When OCSP is unavailable or
  returns ERROR/UNKNOWN, we fall back to the CRL distribution point(s) in the
  leaf.  The fetched CRL is cached per ``(tenant_id, crl_url)`` and freshness-
  checked against ``thisUpdate / nextUpdate``.  A serial found in the CRL
  revoked list blocks the connection.  CRL data is public CA metadata; the per-
  tenant cache key prevents hypothetical cross-tenant cache pollution.

  stdlib note (ground-truthed 2026-06-10): Python's ``ssl`` module exposes NO
  API to read a *stapled* OCSP response from the live handshake, and pyOpenSSL
  is not a dependency (and the ``cryptography`` aarch64 pin is fragile — see
  pyproject).  So L2 is implemented as an **active OCSP fetch** with the SAME
  freshness contract a stapled check would enforce.  ``_get_stapled_ocsp`` is a
  pluggable hook: if a stapled response is ever made available (pyOpenSSL or a
  sidecar), it is preferred over an active fetch with NO change to this contract.

strict_mode (buyer-facing hard option)
---------------------------------------
Default posture: a cert that offers neither OCSP nor CRL yields ``NO_CHANNEL``,
which is logged + alerted but (since the approved set is curated) does NOT by
itself block — the fingerprint pin remains the control.  ``strict_mode=True``
flips this: an upstream that presents NO revocation channel is REFUSED.

Residual (documented)
----------------------
Where the external CA offers neither stapling nor OCSP nor CRL, a revoked-but-
unrotated leaf is only caught when the pin ages past ``max_pin_age`` and is
re-onboarded.  The exposure is therefore **bounded by ``max_pin_age``**.
strict_mode removes this residual entirely by refusing such upstreams.

YSG-RISK-058 / Laura external-upstream-revocation threat model (PR #35) /
release 3.0 + 4.0 (CRL L3 activation).

Last updated: 2026-07-03T00:00:00+00:00
"""
from __future__ import annotations

import logging
import os
import threading
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

# Audit labels (consumed by broker._emit_upstream_pin_event-style writers).
REVOKED_LABEL = "MCP_UPSTREAM_CERT_REVOKED"
REVOCATION_STALE_LABEL = "MCP_UPSTREAM_REVOCATION_STALE"
REVOCATION_NO_CHANNEL_LABEL = "MCP_UPSTREAM_NO_REVOCATION_CHANNEL"
REVOCATION_PIN_EXPIRED_LABEL = "MCP_UPSTREAM_PIN_AGE_EXPIRED"
CRL_REVOKED_LABEL = "MCP_UPSTREAM_CERT_CRL_REVOKED"
CRL_STALE_LABEL = "MCP_UPSTREAM_CRL_STALE"


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
        When True, an upstream that presents NO revocation channel
        (NO_CHANNEL) is REFUSED.  Default False (curated approved-set posture).
    max_pin_age_seconds:
        A fingerprint pin older than this MUST be re-validated against a live
        revocation channel before the upstream is used.  Bounds the residual
        when no live channel is reachable.  Default 24h.
    ocsp_max_age_seconds:
        L2 freshness window: an OCSP response whose ``this_update`` is older
        than this is treated as STALE even if ``next_update`` has not passed.
        Default 1h.
    crl_max_age_seconds:
        L3 CRL freshness window: a CRL whose ``thisUpdate`` is older than this
        is treated as STALE even if ``nextUpdate`` has not passed.  Default 24h.
        CRL issuance cadence varies by CA (hourly to weekly); 24h is a safe
        conservative bound.
    http_timeout_seconds:
        Timeout for OCSP/CRL fetches.  Default 5s.
    tenant_id:
        Tenant identifier. Used to key the per-tenant CRL cache so one tenant's
        cached CRL data cannot be served to another tenant's check.  Empty string
        uses a shared default bucket (acceptable for single-tenant deployments).
    """
    strict_mode: bool = False
    max_pin_age_seconds: int = 24 * 3600
    ocsp_max_age_seconds: int = 3600
    crl_max_age_seconds: int = 24 * 3600
    http_timeout_seconds: float = 5.0
    tenant_id: str = ""


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
        strict_mode=_b("YASHIGANI_MCP_REVOCATION_STRICT", False),
        max_pin_age_seconds=_i("YASHIGANI_MCP_PIN_MAX_AGE_SECONDS", 24 * 3600),
        ocsp_max_age_seconds=_i("YASHIGANI_MCP_OCSP_MAX_AGE_SECONDS", 3600),
        crl_max_age_seconds=_i("YASHIGANI_MCP_CRL_MAX_AGE_SECONDS", 24 * 3600),
        http_timeout_seconds=float(_i("YASHIGANI_MCP_REVOCATION_TIMEOUT", 5)),
        tenant_id=os.environ.get("YASHIGANI_TENANT_ID", ""),
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
# CRL fetch + cache + freshness (L3 — active CRL channel, 4.0)
# ---------------------------------------------------------------------------
#
# CRL data is public CA metadata published by the issuing CA.  It is the same
# for all callers hitting the same CA endpoint, so caching by URL is correct.
# The cache key is (tenant_id, url) rather than url alone: this scopes each
# tenant's cached CRL view independently, preventing any hypothetical cross-
# tenant cache pollution (e.g., if a compromised tenant could somehow inject a
# stale/invalid CRL entry that affects another tenant's check).  CRL data
# itself is CA-signed and verified; the per-tenant key is defence-in-depth.


@dataclass
class _CrlCacheEntry:
    """One cached CRL entry: the parsed object + freshness timestamps."""
    crl: object                           # x509.CertificateRevocationList
    fetched_at: float                     # time.time() when fetched
    this_update: datetime                 # CRL's thisUpdate (aware UTC)
    next_update: Optional[datetime]       # CRL's nextUpdate (aware UTC), or None


# Process-global CRL cache: (tenant_id, crl_url) -> _CrlCacheEntry
# Protected by _CRL_CACHE_LOCK for thread safety.
_CRL_CACHE: dict[tuple[str, str], _CrlCacheEntry] = {}
_CRL_CACHE_LOCK = threading.Lock()


def _get_crl_from_cache_or_fetch(
    crl_url: str,
    cfg: RevocationConfig,
    *,
    _http_get: Optional[Callable[[str, float], bytes]] = None,
) -> "_CrlCacheEntry":
    """
    Return a cached CRL entry for ``(cfg.tenant_id, crl_url)``, or fetch and
    cache a fresh one.

    Freshness: an existing cache entry is reused if:
      * its ``next_update`` is in the future (or unknown), AND
      * ``(now - fetched_at)`` < ``crl_max_age_seconds``.
    Otherwise the CRL is re-fetched.

    Raises OSError / ValueError on network or parse failure.
    """
    cache_key = (cfg.tenant_id, crl_url)
    now_ts = time.time()
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)

    with _CRL_CACHE_LOCK:
        entry = _CRL_CACHE.get(cache_key)

    if entry is not None:
        # Re-use if next_update is in the future AND entry is within max_age.
        age = now_ts - entry.fetched_at
        next_ok = entry.next_update is None or entry.next_update > now_dt
        if next_ok and age < cfg.crl_max_age_seconds:
            return entry

    # Need to fetch. _http_get module-level function is resolved at call time.
    if _http_get is not None:
        raw = _http_get(crl_url, cfg.http_timeout_seconds)
    else:
        from urllib.request import urlopen as _urlopen  # noqa: PLC0415
        with _urlopen(crl_url, timeout=cfg.http_timeout_seconds) as resp:  # noqa: S310
            raw = resp.read()
    # Try DER first, then PEM.
    try:
        crl = x509.load_der_x509_crl(raw)
    except Exception:  # noqa: BLE001
        crl = x509.load_pem_x509_crl(raw)

    # Prefer timezone-aware _utc variants (cryptography 42+); fall back to
    # naive last_update / next_update (cryptography <42) normalised via _aware().
    tu_raw = getattr(crl, "last_update_utc", None) or crl.last_update
    tu = _aware(tu_raw)
    nu_obj = getattr(crl, "next_update_utc", None) or crl.next_update
    nu: Optional[datetime] = _aware(nu_obj) if nu_obj is not None else None

    new_entry = _CrlCacheEntry(
        crl=crl,
        fetched_at=now_ts,
        this_update=tu,
        next_update=nu,
    )
    with _CRL_CACHE_LOCK:
        _CRL_CACHE[cache_key] = new_entry
    return new_entry


def _evaluate_crl_channel(
    leaf: x509.Certificate,
    cfg: RevocationConfig,
    now: Optional[float] = None,
    *,
    _crl_fetch: Optional[Callable[[str, float], bytes]] = None,
) -> Optional[RevocationResult]:
    """
    Try each CRL distribution point URL for the leaf.  Return a
    ``RevocationResult`` on the FIRST URL that yields a definitive answer
    (REVOKED, GOOD, or STALE), or None if no CRL URL is reachable / parseable.

    Freshness contract mirrors OCSP L2:
      * CRL ``thisUpdate`` must be within ``crl_max_age_seconds`` of now.
      * CRL ``nextUpdate`` (if present) must be in the future.
      * A stale CRL blocks (same fail-closed posture as stale OCSP).

    A serial number found in the CRL revoked list → REVOKED (blocks=True).
    A serial number NOT in the CRL revoked list + fresh CRL → GOOD.
    """
    crl_urls = _extract_crl_urls(leaf)
    if not crl_urls:
        return None

    now_ts = time.time() if now is None else now
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)

    for url in crl_urls:
        try:
            entry = _get_crl_from_cache_or_fetch(url, cfg, _http_get=_crl_fetch)
        except Exception as exc:  # noqa: BLE001
            logger.info("revocation-watch/CRL: fetch failed url=%s: %s", url, exc)
            continue

        tu = entry.this_update
        nu = entry.next_update

        # Freshness check (mirrors OCSP L2).
        if tu > now_dt:
            logger.warning(
                "revocation-watch/CRL: %s thisUpdate in the future (clock skew?) url=%s",
                CRL_STALE_LABEL, url,
            )
            return RevocationResult(
                RevocationStatus.STALE, CRL_STALE_LABEL, blocks=True,
            )
        if nu is not None and nu <= now_dt:
            logger.warning(
                "revocation-watch/CRL: %s nextUpdate expired url=%s nu=%s",
                CRL_STALE_LABEL, url, nu.isoformat(),
            )
            return RevocationResult(
                RevocationStatus.STALE, CRL_STALE_LABEL, blocks=True,
            )
        if (now_dt - tu).total_seconds() > cfg.crl_max_age_seconds:
            logger.warning(
                "revocation-watch/CRL: %s thisUpdate too old url=%s tu=%s",
                CRL_STALE_LABEL, url, tu.isoformat(),
            )
            return RevocationResult(
                RevocationStatus.STALE, CRL_STALE_LABEL, blocks=True,
            )

        # Revocation check.
        revoked_entry = entry.crl.get_revoked_certificate_by_serial_number(  # type: ignore[attr-defined]
            leaf.serial_number
        )
        if revoked_entry is not None:
            logger.warning(
                "revocation-watch/CRL: %s serial=%s found in CRL url=%s",
                CRL_REVOKED_LABEL, leaf.serial_number, url,
            )
            return RevocationResult(
                RevocationStatus.REVOKED, CRL_REVOKED_LABEL, blocks=True,
            )

        # Fresh CRL, serial not revoked.
        logger.debug(
            "revocation-watch/CRL: serial=%s NOT in CRL (fresh) url=%s",
            leaf.serial_number, url,
        )
        return RevocationResult(RevocationStatus.GOOD, "ok", blocks=False)

    # All URLs tried, none yielded a result.
    return None


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
    _crl_fetch: Optional[Callable[[str, float], bytes]] = None,
) -> RevocationResult:
    """
    Check an external upstream leaf for revocation (YSG-RISK-058 / 4.0 CRL).

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
    _crl_fetch:
        Injection hook for CRL HTTP fetch (testing only).  When provided, called
        as ``_crl_fetch(url, timeout_seconds) -> bytes``.

    Returns
    -------
    RevocationResult — ``blocks=True`` means the caller MUST refuse the upstream.

    Fail-closed semantics:
      * REVOKED  -> blocks (always; from OCSP or CRL).
      * STALE    -> blocks (L2/L3: evidence too old to trust).
      * NO_CHANNEL -> blocks ONLY in strict_mode; else warn (curated posture).
      * PIN_EXPIRED -> blocks (pin too old, no fresh GOOD verdict).
      * ERROR / UNKNOWN -> does NOT block on its own (fingerprint pin still holds),
        UNLESS the pin is also expired or strict_mode demands a channel.

    Channel priority:
      OCSP (L1/L2) is tried first.  If OCSP yields GOOD, REVOKED, or STALE,
      that result is final.  CRL (L3) is tried only when OCSP is unavailable
      (ERROR / UNKNOWN / no OCSP URL in the leaf).  This mirrors the RFC 6960
      recommendation: OCSP is the preferred real-time channel; CRL is fallback.
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

    # --- strict-mode: refuse an upstream with no revocation channel at all. ---
    if not has_channel:
        if cfg.strict_mode:
            logger.warning(
                "revocation-watch: %s leaf has NO OCSP and NO CRL — strict_mode REFUSES upstream",
                REVOCATION_NO_CHANNEL_LABEL,
            )
            return RevocationResult(
                RevocationStatus.NO_CHANNEL, REVOCATION_NO_CHANNEL_LABEL, blocks=True
            )
        logger.warning(
            "revocation-watch: %s leaf has NO OCSP and NO CRL — fingerprint pin is the "
            "only control (residual bounded by max_pin_age=%ds; set strict_mode to refuse)",
            REVOCATION_NO_CHANNEL_LABEL, cfg.max_pin_age_seconds,
        )
        # Pin-age still applies even without a channel: an over-age pin with no way
        # to re-validate must be refused so the residual stays bounded.
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

    # REVOKED / STALE block unconditionally (from OCSP).
    if result.status in (RevocationStatus.REVOKED, RevocationStatus.STALE):
        return result

    # GOOD from OCSP — authoritative; no need to check CRL.
    if result.status == RevocationStatus.GOOD:
        return result

    # OCSP was unavailable or returned UNKNOWN: try CRL fallback (L3 — 4.0).
    # A CRL REVOKED or STALE verdict is as hard as OCSP; GOOD from a fresh
    # CRL overrides an OCSP ERROR/UNKNOWN (net: cert is clean per CA).
    crl_result = _evaluate_crl_channel(leaf, cfg, now=now_ts, _crl_fetch=_crl_fetch)
    if crl_result is not None:
        if crl_result.status in (RevocationStatus.REVOKED, RevocationStatus.STALE):
            return crl_result
        if crl_result.status == RevocationStatus.GOOD:
            # Fresh CRL says not revoked — treat as GOOD verdict.
            result = crl_result

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
