"""
Yashigani Alerts — Webhook URL guard against SSRF (V232-CSCAN-01b).

# Last updated: 2026-07-20T00:00:00+00:00

Provides assert_webhook_url() which must be called:
  1. At admin PUT /admin/alerts/config — fail 400 before persisting the URL.
  2. At send-time in each sink's post_to_webhook() — last-line-of-defence even
     if the config-write path is somehow bypassed.

Threat model: malicious/compromised admin sets slack_webhook_url to an internal
endpoint (AWS IMDS 169.254.169.254, in-cluster Prometheus, RFC1918 host, loopback)
and triggers /admin/alerts/test/slack to exfiltrate IMDS credentials or probe
internal services.

Guards applied (in order):
  - Scheme must be https.
  - netloc must not contain userinfo (user:pass@ prefix).
  - Hostname must not parse as an IP literal (rejects 169.254.169.254, ::1, etc.).
  - All IPs that the hostname resolves to must be non-private, non-loopback,
    non-link-local, non-multicast, non-reserved (ALL resolved IPs checked — not
    just the first — to block DNS-rebinding round-1).
  - Hostname must match or be a subdomain of one of allowed_hosts.

Raises WebhookUrlForbidden (ValueError subclass) on any violation.

Also provides assert_no_imds_or_loopback_url() (codescan #1 / mustui triage
2026-07-20, backoffice/routes/mcp_servers.py:464) — a narrower variant for
operator-supplied MCP-server upstream_url values. Unlike assert_webhook_url(),
it has NO vendor-domain allowlist and does NOT reject general RFC-1918/private
addresses: MCP upstreams are legitimately operator-chosen internal-mesh
endpoints (e.g. compose-DNS hostnames resolving to bridge-network IPs) by
design. It blocks only cloud-metadata (IMDS) and loopback/link-local/
unspecified/multicast targets — the same class of payload proven exploitable
against the pre-fix Slack/Teams sinks, applied here without breaking
legitimate internal MCP deployments.
"""
from __future__ import annotations

import ipaddress
import socket
import logging
from collections.abc import Set as AbstractSet
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WebhookUrlForbidden(ValueError):
    """Raised when a webhook URL fails the allowlist or IP-safety checks."""

    def __init__(self, reason: str, url: str) -> None:
        self.reason = reason
        self.url = url
        super().__init__(f"Webhook URL blocked [{reason}]: {url!r}")


def _is_unsafe_address(addr: str) -> bool:
    """Return True if the resolved address falls in a prohibited range."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        # Unparseable — treat as unsafe
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_webhook_url(url: str, *, allowed_hosts: AbstractSet[str]) -> None:
    """Assert that *url* is safe to use as a webhook destination.

    Parameters
    ----------
    url:
        The full webhook URL to validate.
    allowed_hosts:
        Set of exact hostnames that are permitted (e.g. ``{"hooks.slack.com"}``).
        Subdomain matching is also applied: a host ``foo.hooks.slack.com``
        passes if ``"hooks.slack.com"`` is in *allowed_hosts*.

    Raises
    ------
    WebhookUrlForbidden
        On any violation.
    """
    if not url:
        raise WebhookUrlForbidden("empty_url", url)

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise WebhookUrlForbidden("parse_error", url) from exc

    # 1. Scheme must be https only.
    scheme = (parsed.scheme or "").lower()
    if scheme != "https":
        raise WebhookUrlForbidden(f"scheme_not_https:{scheme!r}", url)

    # 2. Reject embedded userinfo (user:pass@host or user@host).
    netloc = parsed.netloc or ""
    if "@" in netloc:
        raise WebhookUrlForbidden("userinfo_in_netloc", url)

    # 3. Extract and normalise the hostname.
    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        raise WebhookUrlForbidden("empty_hostname", url)

    # 4. Reject IP literals directly (covers IPv4, IPv6, and link-local).
    try:
        ipaddress.ip_address(hostname)
        raise WebhookUrlForbidden("ip_literal_hostname", url)
    except WebhookUrlForbidden:
        raise
    except ValueError:
        pass  # Not an IP literal — hostname continues checks below.

    # 5. Resolve DNS and reject if any resolved address is in a prohibited range.
    #    We check ALL returned addresses to block DNS-rebinding round-1 pivots.
    try:
        addrinfos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        # Resolution failure — reject rather than allow unresolvable hosts through.
        raise WebhookUrlForbidden(f"dns_resolution_failed:{exc}", url) from exc

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        # sockaddr[0] is typed as `str | int` in typeshed (covers IPv4/IPv6 union);
        # in practice always a string IP literal — coerce explicitly for the type checker.
        addr = str(sockaddr[0])
        if _is_unsafe_address(addr):
            raise WebhookUrlForbidden(f"resolves_to_private_or_reserved:{addr}", url)

    # 6. Host must be in allowed_hosts (exact) or be a subdomain of an entry.
    def _host_allowed(h: str, allowed: AbstractSet[str]) -> bool:
        if h in allowed:
            return True
        for ah in allowed:
            if h.endswith("." + ah):
                return True
        return False

    if not _host_allowed(hostname, {ah.lower() for ah in allowed_hosts}):
        raise WebhookUrlForbidden(f"host_not_in_allowlist:{hostname!r}", url)

    logger.debug("assert_webhook_url: accepted %r (hostname=%r)", url, hostname)


# ---------------------------------------------------------------------------
# IMDS/loopback-only guard — for operator-supplied internal-mesh endpoints
# (mcp_servers.py upstream_url) where a vendor-domain allowlist and blanket
# RFC-1918 block are NOT appropriate (codescan #1, mustui triage 2026-07-20).
# ---------------------------------------------------------------------------

# AWS EC2/ECS IMDSv6 uses a fixed address in the RFC4193 ULA range
# (fd00:ec2::254). Unlike the IPv4 IMDS endpoint (169.254.169.254, already
# covered by ip.is_link_local), this address is NOT link-local, so it needs
# an explicit entry — blocking it does not block ULA/private space generally.
_EXPLICIT_METADATA_ADDRESSES: frozenset[str] = frozenset({"fd00:ec2::254"})

# Cloud-metadata hostnames that must be blocked by name, regardless of what
# they resolve to in this environment (defence-in-depth: GCP's metadata
# server is reachable via these magic hostnames only from inside GCP, but an
# operator or attacker-forged request should never be allowed to reference
# them here).
_EXPLICIT_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {"metadata.google.internal", "metadata"}
)


def _is_imds_or_loopback_address(addr: str) -> bool:
    """Return True for loopback/link-local/unspecified/multicast addresses or
    a known cloud-metadata ULA address. Deliberately does NOT flag general
    RFC-1918/private addresses — see module docstring."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True  # unparseable — treat as unsafe
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return True
    return addr in _EXPLICIT_METADATA_ADDRESSES


def assert_no_imds_or_loopback_url(url: str) -> None:
    """Assert *url* is not an IMDS/loopback SSRF target.

    Narrower than assert_webhook_url(): no host allowlist, and no blanket
    RFC-1918/private-range block — callers (the MCP-server import ceremony)
    are expected to reach operator-chosen internal-mesh hosts by design.

    Blocks:
      - non-http(s) schemes
      - userinfo-in-netloc (user:pass@host)
      - IP literals / DNS-resolved addresses that are loopback, link-local
        (covers 169.254.0.0/16 — AWS/Azure/GCP IMDS — and fe80::/10),
        unspecified, multicast, or the known AWS IMDSv6 ULA address
        (fd00:ec2::254)
      - the literal hostnames 'metadata.google.internal' / 'metadata'
        (GCP magic metadata hostname), regardless of DNS resolution result

    Does NOT block RFC-1918/private/ULA addresses in general, or reserved
    ranges beyond the above — an internal MCP server on the compose/mesh
    network (e.g. 172.x bridge-network IP) is an accepted, by-design target.

    Raises
    ------
    WebhookUrlForbidden
        On any violation.
    """
    if not url:
        raise WebhookUrlForbidden("empty_url", url)

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise WebhookUrlForbidden("parse_error", url) from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise WebhookUrlForbidden(f"scheme_not_http_or_https:{scheme!r}", url)

    netloc = parsed.netloc or ""
    if "@" in netloc:
        raise WebhookUrlForbidden("userinfo_in_netloc", url)

    hostname = (parsed.hostname or "").lower().strip(".")
    if not hostname:
        raise WebhookUrlForbidden("empty_hostname", url)

    if hostname in _EXPLICIT_METADATA_HOSTNAMES:
        raise WebhookUrlForbidden(f"cloud_metadata_hostname:{hostname!r}", url)

    # IP-literal hostname — check directly (covers 127.0.0.1, 169.254.169.254,
    # [::1], [fd00:ec2::254], etc.). A non-IMDS/loopback IP literal (e.g. a
    # private-mesh IP entered directly) is accepted for this guard variant.
    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        if _is_imds_or_loopback_address(hostname):
            raise WebhookUrlForbidden(f"imds_or_loopback_ip_literal:{hostname}", url)
        return

    # Resolve DNS and reject if ANY resolved address is IMDS/loopback (blocks
    # DNS-rebinding round-1 pivots the same way assert_webhook_url() does).
    # Unresolvable hostnames are rejected — a name that fails DNS at
    # registration time must not be accepted, since the checks above operate
    # on resolved IPs (mirrors assert_webhook_url() and
    # backoffice/_ssrf.assert_safe_outbound_url()).
    try:
        addrinfos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookUrlForbidden(f"dns_resolution_failed:{exc}", url) from exc

    for _family, _type, _proto, _canonname, sockaddr in addrinfos:
        addr = str(sockaddr[0])
        if _is_imds_or_loopback_address(addr):
            raise WebhookUrlForbidden(f"resolves_to_imds_or_loopback:{addr}", url)

    logger.debug(
        "assert_no_imds_or_loopback_url: accepted %r (hostname=%r)", url, hostname
    )
