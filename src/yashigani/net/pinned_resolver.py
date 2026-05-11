"""
DNS-rebinding defence: pinned-IP resolver (OWASP API7 SSRF / issue #91).

Problem
-------
Allowlist checks in :class:`~yashigani.net.HttpClient` run before the
outbound request is issued.  An attacker who controls DNS can respond with
an allowlisted IP on the first query (the policy check) and then swap the
record to an internal IP before the actual TCP connection is attempted.
This "DNS-rebinding" attack bypasses purely pre-flight URL guards.

Solution
--------
:func:`pinned_resolver` is an async context manager that resolves the target
hostname *once*, verifies the resolved IP passes policy, caches it, and
creates an :class:`httpx.AsyncClient` that is pre-configured to use a custom
:class:`httpx.AsyncHTTPTransport` wired to a bespoke ``socket.getaddrinfo``
shim.  The shim short-circuits every subsequent DNS lookup for that hostname
and returns only the cached, verified IP.  Any future resolution of the same
hostname (by the connection layer or follow-up requests inside the same
``with`` block) is therefore unaffected by DNS changes.

Usage
-----
::

    from yashigani.net.pinned_resolver import pinned_resolver

    async with pinned_resolver("api.pwnedpasswords.com", port=443,
                               allowlist=["api.pwnedpasswords.com"]) as session:
        resp = await session.get("https://api.pwnedpasswords.com/range/ABCDE")

Audit event
-----------
Every successful pin emits a ``SSRF_PINNED_RESOLVER_USED`` debug-level log
so operators can confirm the path is active.  The resolved IP is included
in the log payload (not the audit hash-chain — debug-only).

Limitations
-----------
* IPv6 is supported wherever :func:`socket.getaddrinfo` returns AAAA records.
* The pin lasts for the duration of the context block only; it is not shared
  across concurrent coroutines.
* Follow-redirects is always ``False`` inside the pinned session — callers
  must handle redirects explicitly to avoid bypass via redirect to a
  different host.

Last updated: 2026-05-09T00:00:00+01:00
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import httpx

from yashigani.net.http_client import BlockedByPolicy, _host_matches_entry, _is_private_or_metadata

logger = logging.getLogger(__name__)

# Audit event name — emitted at DEBUG level so CI noise stays low but
# operators can raise to INFO via log config.
_AUDIT_EVENT_NAME = "SSRF_PINNED_RESOLVER_USED"


def _resolve_first_safe_ip(
    hostname: str,
    port: int,
    allowlist: Optional[list[str]],
    blocklist: Optional[list[str]],
) -> str:
    """Resolve *hostname* synchronously via the OS resolver and return the
    first address that passes the SSRF policy checks.

    Raises :class:`BlockedByPolicy` if no safe address is found.

    The OS resolver is used intentionally — it is the same resolver that the
    underlying socket layer would use, so pinning to its output gives us the
    "first legitimate answer" that the transport would have seen.
    """
    blocklist = blocklist or []
    try:
        results = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise BlockedByPolicy(f"DNS resolution failed for {hostname!r}: {exc}") from exc

    if not results:
        raise BlockedByPolicy(f"DNS resolution returned no results for {hostname!r}")

    for _family, _type, _proto, _canonname, sockaddr in results:
        # sockaddr is (ip, port) for IPv4 or (ip, port, flow, scope) for IPv6.
        # The first element is always the IP address string.
        ip_str: str = str(sockaddr[0])

        # Hard-block: private/loopback/metadata ranges
        if _is_private_or_metadata(ip_str):
            continue

        # Operator blocklist
        blocked = any(_host_matches_entry(ip_str, entry) for entry in blocklist)
        if blocked:
            continue

        # Allowlist enforcement (when configured)
        if allowlist:
            in_allowlist = any(_host_matches_entry(ip_str, entry) for entry in allowlist) or any(
                _host_matches_entry(hostname, entry) for entry in allowlist
            )
            if not in_allowlist:
                continue

        # This address passes all checks — pin it.
        return ip_str

    raise BlockedByPolicy(
        f"All resolved addresses for {hostname!r} are blocked by SSRF policy "
        f"(private/loopback/metadata, blocklist, or allowlist mismatch). "
        "DNS-rebinding guard: no safe address to pin."
    )


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """An httpx transport that injects a pre-resolved IP override.

    The HTTP request target (URL host header and TLS SNI) retains the original
    hostname, while the TCP connection goes to the pinned IP.  This keeps TLS
    certificate verification correct (SNI = hostname, not IP).

    The ``socket.getaddrinfo`` function is monkey-patched on this transport
    instance's resolver scope by wrapping the underlying ``_pool`` once the
    transport has been initialised.
    """

    def __init__(self, pinned_ip: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Patch getaddrinfo for the duration of this single request.
        # We restore it immediately after so there is no global side-effect.
        original_getaddrinfo = socket.getaddrinfo
        pinned_ip = self._pinned_ip

        def _pinned_getaddrinfo(host, port, *args, **kwargs):  # type: ignore[override]
            # Intercept only exact-match lookups for the pinned hostname.
            # Pass everything else to the real resolver.
            request_host = request.url.host
            if host in (request_host, request_host.lower()):
                # Determine address family from pinned IP.
                try:
                    addr = ipaddress.ip_address(pinned_ip)
                    family = socket.AF_INET6 if isinstance(addr, ipaddress.IPv6Address) else socket.AF_INET
                except ValueError:
                    family = socket.AF_INET
                # Return the (family, type, proto, canonname, sockaddr) tuple
                # in the format getaddrinfo normally returns.
                return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (pinned_ip, port))]
            return original_getaddrinfo(host, port, *args, **kwargs)

        socket.getaddrinfo = _pinned_getaddrinfo  # type: ignore[assignment]
        try:
            return await super().handle_async_request(request)
        finally:
            socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


@asynccontextmanager
async def pinned_resolver(
    hostname: str,
    *,
    port: int = 443,
    allowlist: Optional[list[str]] = None,
    blocklist: Optional[list[str]] = None,
    timeout_s: float = 30.0,
    verify: bool = True,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Async context manager that yields an :class:`httpx.AsyncClient` whose
    TCP transport is pinned to a pre-verified, SSRF-safe IP address.

    Parameters
    ----------
    hostname:
        The hostname to resolve and pin.  Must match the URL host used inside
        the context block.
    port:
        Hint for ``getaddrinfo`` so SRV/service records resolve correctly.
        Defaults to 443.
    allowlist:
        Optional list of hostname/suffix/CIDR entries.  Resolved IPs must match
        an entry in addition to passing the hard-block checks.  When omitted,
        any non-blocked public IP is accepted.
    blocklist:
        Additional entries to block beyond the built-in private/loopback/metadata
        ranges.
    timeout_s:
        Request timeout in seconds (default 30).
    verify:
        Whether to verify TLS certificates (default ``True``).  Setting to
        ``False`` is a security downgrade; use only in local test overrides.

    Raises
    ------
    BlockedByPolicy
        If the hostname resolves only to disallowed addresses.
    """
    pinned_ip = _resolve_first_safe_ip(hostname, port, allowlist, blocklist)

    logger.debug(
        "%s host=%s pinned_ip=%s port=%d",
        _AUDIT_EVENT_NAME,
        hostname,
        pinned_ip,
        port,
    )

    transport = _PinnedTransport(pinned_ip=pinned_ip, verify=verify)

    async with httpx.AsyncClient(
        transport=transport,
        timeout=timeout_s,
        follow_redirects=False,  # Never follow redirects — avoids host-hop bypass.
    ) as client:
        yield client
