"""
Shared SSRF guard for admin-configurable outbound URLs.

Extracted from backoffice/routes/agents.py (TM-V231-004 / CWE-918) so that the
same validation applies to every endpoint that stores an admin-supplied URL:

  - Agent upstream_url  (agents.py)
  - SIEM backend endpoint (audit_sinks.py)

FIND-3.0-001: audit_sinks.py update_siem_config() stored body.endpoint with no
URL validation, allowing loopback / link-local / RFC-1918 / cloud-metadata SSRF.
This module closes that gap by providing a single, tested guard that both callers
import.

Rejected: loopback (127.x/::1), link-local / IMDS (169.254.x.x), RFC-1918
private (10.x / 172.16-31.x / 192.168.x), multicast, reserved, non-http(s)
scheme (file, gopher, ftp, dict, ldap, ws, …).

Allowed: any public-routable http(s) host, OR any host explicitly listed in the
caller-supplied env var (operator opt-in for internal Docker-mesh services).

Every caller passes the name of its env-var allowlist (e.g.
``YASHIGANI_AGENT_UPSTREAM_HOSTNAMES`` for agents,
``YASHIGANI_SIEM_HOSTNAMES`` for SIEM endpoints).

Returns the URL unchanged on PASS.  Raises ``ValueError`` on any violation
(Pydantic v2 turns this into HTTP 422; callers outside Pydantic convert it to
HTTPException 422 manually).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


def assert_safe_outbound_url(
    url: str,
    *,
    allowlist_env: str,
    label: str = "url",
) -> str:
    """Assert that ``url`` is safe to store as an admin-configured outbound endpoint.

    Parameters
    ----------
    url:
        The URL to validate.
    allowlist_env:
        Name of the environment variable that holds a comma-separated allowlist
        of hostnames whose RFC-1918 / loopback resolution is operator-permitted
        (e.g. ``"YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"``).  If the host is in the
        allowlist the IP-category check is skipped.
    label:
        Human-readable field name for error messages (e.g. ``"upstream_url"``,
        ``"siem_endpoint"``).

    Returns
    -------
    str
        The URL unchanged if it passes all checks.

    Raises
    ------
    ValueError
        On any policy violation.  The message describes the specific failure so
        Pydantic / the caller can surface a useful 422 body.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            f"{label} scheme {scheme!r} not allowed — only http and https are accepted "
            f"(CWE-918 / FIND-3.0-001)"
        )

    if not host:
        raise ValueError(
            f"{label} has no hostname (parsed from {url!r}) — must be an addressable HTTP(S) endpoint"
        )

    # Operator-explicit internal allowlist: bypass IP-category checks for
    # known Docker-mesh hostnames (e.g. "wazuh-indexer", "splunk-hec").
    raw_allowlist = os.getenv(allowlist_env, "")
    internal_allowed = {h.strip().lower() for h in raw_allowlist.split(",") if h.strip()}
    if host in internal_allowed:
        return url  # operator has explicitly permitted this internal host

    # Resolve hostname → IP(s).  Unknown hosts that don't resolve are REJECTED:
    # a name that fails DNS at registration time must not be stored, because the
    # SSRF category checks below operate on resolved IPs — falling through on a
    # resolution failure would silently accept attacker-controlled names such as
    # "metadata.google.internal" that resolve only inside the target's network
    # (LAURA-300-001 / CWE-918). Matches audit/writer.validate_siem_url().
    try:
        addrinfo = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs = {info[4][0] for info in addrinfo}
    except (socket.gaierror, socket.herror) as exc:
        raise ValueError(
            f"{label} host {host!r} does not resolve — refusing to store a URL "
            "for an unresolvable host; if this is an internal mesh service, add "
            f"the hostname to {allowlist_env} (CWE-918 / LAURA-300-001)"
        ) from exc

    for addr_str in addrs:
        try:
            ip = ipaddress.ip_address(addr_str)
        except ValueError:
            continue  # not an IP literal — skip category check for this entry

        if ip.is_loopback:
            raise ValueError(
                f"{label} host {host!r} resolves to loopback {addr_str} — "
                "loopback addresses are SSRF targets; add the hostname to "
                f"{allowlist_env} if intentional (CWE-918 / FIND-3.0-001)"
            )
        if ip.is_link_local:
            # 169.254.169.254 is the AWS/GCP/Azure IMDS endpoint — primary SSRF target.
            raise ValueError(
                f"{label} host {host!r} resolves to link-local {addr_str} — "
                "link-local addresses (incl. cloud IMDS 169.254.169.254) "
                f"are SSRF targets (CWE-918 / FIND-3.0-001)"
            )
        if ip.is_multicast:
            raise ValueError(
                f"{label} host {host!r} resolves to multicast {addr_str} — "
                "multicast addresses are not valid HTTP(S) endpoints"
            )
        if ip.is_private:
            raise ValueError(
                f"{label} host {host!r} resolves to RFC-1918 private {addr_str} — "
                f"private addresses are SSRF-prone; add the hostname to "
                f"{allowlist_env} if intentional (CWE-918 / FIND-3.0-001)"
            )
        if ip.is_reserved:
            raise ValueError(
                f"{label} host {host!r} resolves to reserved {addr_str} (CWE-918 / FIND-3.0-001)"
            )

    return url
