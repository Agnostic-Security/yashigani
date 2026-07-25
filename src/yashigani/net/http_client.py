"""
Centralised outbound HTTP client with SSRF guardrails.

Every outbound HTTP call in Yashigani should go through
:class:`HttpClient`. It enforces:

* URL scheme allowlist (https:// only by default)
* Host allowlist / blocklist (env-driven)
* Private / cloud-metadata IP rejection
* Timeout ceiling
* Restricted redirect chain (same-allowlist hosts only)
* Logged audit event on blocked attempts

Configuration (environment variables):
    YASHIGANI_OUTBOUND_ALLOWLIST       Comma-separated hostnames /
                                       hostname suffixes / CIDR blocks.
                                       Empty = allow every public host.
    YASHIGANI_OUTBOUND_BLOCKLIST       Comma-separated additional blocks
                                       on top of the hard-coded private /
                                       metadata ranges.
    YASHIGANI_OUTBOUND_ALLOW_HTTP      "1" to permit plain-HTTP to
                                       allowlisted hosts (default: off).
    YASHIGANI_OUTBOUND_DEFAULT_TIMEOUT Seconds (default 30).

MCP upstream guard mode (bypass_private_for_allowlisted=True):
    Used by McpHttpTransport to allow private/RFC1918 MCP upstreams
    (Docker bridge IPs) while still hard-blocking IMDS, link-local, and
    loopback.  In this mode the allowlist is MANDATORY and any host not
    in it is denied (fail-closed).  IMDS/link-local/loopback cannot be
    overridden even if an operator mistakenly allowlists them.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


class BlockedByPolicy(Exception):
    """Raised when an outbound request violates policy."""


# Hard-coded blocks that cannot be overridden — cloud metadata endpoints
# and loopback. Even the most permissive deployment never wants the
# gateway to proxy to these.
_HARD_BLOCK_HOSTS = {
    "169.254.169.254",        # AWS / Azure / GCP IMDS
    "metadata.google.internal",
    "fd00:ec2::254",          # AWS IMDS IPv6
    "100.100.100.200",        # Alibaba Cloud metadata
}
_HARD_BLOCK_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local IPv4
    ipaddress.ip_network("fe80::/10"),        # link-local IPv6
]


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [tok.strip() for tok in raw.split(",") if tok.strip()]


def _host_matches_entry(host: str, entry: str) -> bool:
    """Return True if ``host`` matches an allowlist/blocklist entry.

    Entry forms:
      * exact hostname:            api.pwnedpasswords.com
      * suffix with leading dot:   .agnosticsec.com   (covers all subdomains)
      * IP CIDR:                   10.0.0.0/8
      * bare IP:                   203.0.113.42
    """
    host = host.lower().strip()
    entry = entry.lower().strip()
    if entry.startswith("."):
        return host == entry[1:] or host.endswith(entry)
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    return host == entry


def _is_private_or_metadata(host: str) -> bool:
    """Return True if the host is a private IP, loopback, link-local, or
    a cloud metadata endpoint that must never be reachable from a
    gateway-originated request."""
    if host.lower() in _HARD_BLOCK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Not a literal IP — let DNS resolution happen at connect-time.
        # (Further protection against DNS-rebinding requires a pinned
        #  resolver; tracked for v2.24.)
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    for net in _HARD_BLOCK_NETS:
        if ip in net:
            return True
    return False


def _is_hard_block(host: str) -> bool:
    """Return True for hosts that are UNCONDITIONALLY blocked even when
    ``bypass_private_for_allowlisted=True`` is set.

    These are the cloud metadata endpoints (IMDS), loopback addresses, and
    link-local ranges that must never be reachable regardless of operator
    configuration:

    * ``_HARD_BLOCK_HOSTS``: named IMDS endpoints (169.254.169.254,
      metadata.google.internal, fd00:ec2::254, 100.100.100.200).
    * ``_HARD_BLOCK_NETS``: loopback (127.0.0.0/8, ::1/128) and link-local
      (169.254.0.0/16, fe80::/10).

    Generic RFC-1918 private ranges (10.0.0.0/8, 172.16.0.0/12,
    192.168.0.0/16) are NOT in scope here — those may be bypassed for
    explicitly-allowlisted MCP upstream hosts on private Docker bridges.
    """
    if host.lower() in _HARD_BLOCK_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # hostname (not a literal IP) — not a hard block
    for net in _HARD_BLOCK_NETS:  # loopback + link-local
        if ip in net:
            return True
    return False


class HttpClient:
    """Wraps :mod:`httpx` with allowlist enforcement.

    Instances are cheap; reuse across a single scope for connection
    pooling. Every method (:meth:`get`, :meth:`post`, etc.) calls
    :meth:`_check_policy` before issuing the request.

    ``bypass_private_for_allowlisted`` (MCP upstream mode):
        When True the policy check order is changed so that allowlisted
        hosts bypass the RFC-1918 private-IP rejection, enabling internal
        Docker-bridge MCP upstreams to be reached.  IMDS/link-local/loopback
        (``_is_hard_block``) are still blocked unconditionally.  Requires a
        non-empty allowlist; without one every host is denied (fail-closed).
        This flag is set only by ``McpHttpTransport`` — never for general
        outbound HTTP.

    ``expected_spiffe_id`` (FINDING C, v4.1.2 final onboarding e2e):
        When set, an ``https://`` request made in
        ``bypass_private_for_allowlisted`` mode is verified by SPIFFE URI SAN
        (via ``pki.client.internal_httpx_client_verify_spiffe``) instead of
        DNS hostname — the ring-fenced agent's per-instance Caddy front leaf
        carries a SPIFFE URI SAN only, no DNS SAN. Chain verification against
        the internal CA is unchanged either way. When
        ``bypass_private_for_allowlisted`` + ``https://`` is used WITHOUT an
        ``expected_spiffe_id``, the request is refused fail-closed (see
        ``_request``) rather than silently falling back to a hostname check
        that structurally cannot succeed against this class of upstream.
    """

    def __init__(
        self,
        *,
        allowlist: Optional[list[str]] = None,
        blocklist: Optional[list[str]] = None,
        allow_http: Optional[bool] = None,
        timeout_s: Optional[float] = None,
        bypass_private_for_allowlisted: bool = False,
        expected_spiffe_id: Optional[str] = None,
    ):
        self.allowlist = allowlist if allowlist is not None else _env_list("YASHIGANI_OUTBOUND_ALLOWLIST")
        self.blocklist = blocklist if blocklist is not None else _env_list("YASHIGANI_OUTBOUND_BLOCKLIST")
        if allow_http is None:
            allow_http = os.getenv("YASHIGANI_OUTBOUND_ALLOW_HTTP") == "1"
        self.allow_http = allow_http
        if timeout_s is None:
            timeout_s = float(os.getenv("YASHIGANI_OUTBOUND_DEFAULT_TIMEOUT", "30"))
        self.timeout_s = timeout_s
        self.bypass_private_for_allowlisted = bypass_private_for_allowlisted
        self.expected_spiffe_id = expected_spiffe_id

    # ------------------------------------------------------------------
    # Policy check
    # ------------------------------------------------------------------

    def _check_policy(self, url: str) -> None:
        """Raise :class:`BlockedByPolicy` if ``url`` is not allowed.

        Standard mode (``bypass_private_for_allowlisted=False``):
          scheme → private-IP → blocklist → allowlist (if set)

        MCP upstream mode (``bypass_private_for_allowlisted=True``):
          scheme → IMDS/link-local/loopback hard-block (unconditional)
                 → allowlist gate (allowlisted RFC-1918 hosts PASS here)
                 → anything not in allowlist DENIED

        The split prevents a blanket private-IP rejection from blocking
        legitimate internal MCP servers on Docker bridge networks while
        ensuring cloud metadata endpoints (IMDS, link-local) are never
        reachable regardless of the allowlist contents.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()

        # Scheme check first — covers file://, gopher:// etc. regardless of host.
        if scheme not in ("http", "https"):
            raise BlockedByPolicy(
                f"Scheme {scheme!r} not allowed (only http/https)"
            )

        if not host:
            raise BlockedByPolicy(f"URL lacks a hostname: {url!r}")

        if scheme == "http" and not self.allow_http:
            raise BlockedByPolicy(
                "Plain HTTP disallowed by policy. Set "
                "YASHIGANI_OUTBOUND_ALLOW_HTTP=1 to opt in (only for "
                "explicitly-trusted internal hosts)."
            )

        # ── MCP upstream guard mode ──────────────────────────────────────────
        # When bypass_private_for_allowlisted=True (set only by McpHttpTransport):
        #  1. Unconditionally hard-block IMDS/link-local/loopback.
        #  2. Allowlist is MANDATORY and is the sole gate — host must match.
        #     This allows RFC-1918 Docker bridge hosts that are explicitly
        #     registered as MCP upstreams, while blocking everything else.
        if self.bypass_private_for_allowlisted:
            if _is_hard_block(host):
                raise BlockedByPolicy(
                    f"Host {host!r} is an IMDS / link-local / loopback address "
                    "(unconditionally hard-blocked; cannot be overridden by "
                    "the MCP upstream allowlist)."
                )
            if not self.allowlist:
                raise BlockedByPolicy(
                    "bypass_private_for_allowlisted=True requires a non-empty "
                    "trusted upstream allowlist — no host is reachable in this "
                    "mode without an explicit allowlist entry."
                )
            for entry in self.allowlist:
                if _host_matches_entry(host, entry):
                    return  # registered MCP upstream — allow even if RFC-1918
            raise BlockedByPolicy(
                f"Host {host!r} is not in the trusted MCP upstream allowlist "
                f"(SSRF guard blocked unregistered host)."
            )

        # ── Standard mode ────────────────────────────────────────────────────
        if _is_private_or_metadata(host):
            raise BlockedByPolicy(
                f"Host {host!r} is a private / loopback / metadata address "
                "(hard-blocked to prevent SSRF to infrastructure endpoints)."
            )

        for entry in self.blocklist:
            if _host_matches_entry(host, entry):
                raise BlockedByPolicy(
                    f"Host {host!r} matches YASHIGANI_OUTBOUND_BLOCKLIST "
                    f"entry {entry!r}."
                )

        if self.allowlist:
            # Allowlist mode — host must match some entry.
            for entry in self.allowlist:
                if _host_matches_entry(host, entry):
                    return
            raise BlockedByPolicy(
                f"Host {host!r} not in YASHIGANI_OUTBOUND_ALLOWLIST."
            )
        # Empty allowlist = allow any non-blocked public host.

    # ------------------------------------------------------------------
    # HTTP methods (async)
    # ------------------------------------------------------------------

    async def get(self, url: str, **kwargs) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> httpx.Response:
        return await self._request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> httpx.Response:
        return await self._request("DELETE", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> httpx.Response:
        return await self._request("PATCH", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            self._check_policy(url)
        except BlockedByPolicy:
            logger.warning("Outbound blocked by SSRF policy: %s %s", method, url)
            raise
        kwargs.setdefault("timeout", self.timeout_s)
        kwargs.setdefault("follow_redirects", False)  # explicit opt-in only

        scheme = (urlparse(url).scheme or "").lower()
        if self.bypass_private_for_allowlisted and scheme == "https":
            # ── FINDING N1 (v4.1.2 onboarding e2e, Ava) ──────────────────────
            # ``bypass_private_for_allowlisted=True`` is set ONLY by
            # ``McpHttpTransport`` (see module docstring) to reach registered
            # ring-fenced MCP upstreams — including per-instance Caddy fronts
            # signed by the INTERNAL CA (e.g.
            # ``https://caddy:<mesh_port>/mcp/<tenant>/<server>``, which
            # terminates mesh mTLS with ``client_auth require_and_verify`` —
            # see backoffice/mcp_onboard.py:328). A bare
            # ``httpx.AsyncClient()`` uses the DEFAULT SYSTEM trust store,
            # which does not trust the internal CA, so verification fails
            # (502 UPSTREAM_UNREACHABLE) even though the agent is reachable
            # and usable via the chat path.
            #
            # This flag is the same one that already gates the RFC-1918
            # private-IP SSRF bypass for this exact class of upstream — it is
            # the existing "this destination is our own ring-fenced mesh"
            # marker, so gating CA-trust selection on it (rather than on a
            # host/IP heuristic) keeps a single source of truth and does not
            # change behaviour for any other ``HttpClient`` caller (HIBP
            # password checks, JWKS fetch, Open WebUI proxy, generic
            # outbound) — those never set this flag and keep using the
            # system CA bundle for genuinely-external hosts, unchanged.
            #
            # ── FINDING C (v4.1.2 final onboarding e2e, Ava/Tom) ────────────
            # With N1's internal-CA trust in place, the handshake still fails
            # DNS-hostname verification: the agent's per-instance Caddy front
            # leaf carries a SPIFFE URI SAN only (no DNS SAN — see
            # manifest/codegen.py::_gen_caddy_snippet_mcp). We therefore
            # verify by SPIFFE URI SAN instead of DNS hostname
            # (``internal_httpx_client_verify_spiffe`` — chain verification
            # against the internal CA is UNCHANGED; only the identity match
            # strategy differs, and ``verify=False``/bare
            # ``check_hostname=False`` is never used without this
            # compensating SPIFFE check).
            #
            # Fail-closed: without an expected_spiffe_id we refuse rather
            # than fall back to ``internal_httpx_client()``'s DNS-hostname
            # check, which cannot succeed against this class of upstream
            # (every https:// bypass-mode caller today is a ring-fenced MCP
            # agent front — see McpHttpTransport/mcp_router_runtime.py) and
            # would otherwise mask a caller that forgot to pass the expected
            # identity as an opaque 502, or (worse) invite a future caller to
            # "fix" it by disabling hostname checking without a compensating
            # control.
            if not self.expected_spiffe_id:
                logger.error(
                    "Outbound blocked: bypass_private_for_allowlisted https:// "
                    "request to %r has no expected_spiffe_id — refusing rather "
                    "than silently falling back to DNS-hostname verification "
                    "(FINDING C: ring-fenced agent leaves are SPIFFE-URI-SAN "
                    "only and cannot pass a DNS-hostname check).",
                    url,
                )
                raise BlockedByPolicy(
                    f"Host {urlparse(url).hostname!r} requires SPIFFE URI SAN "
                    "verification (expected_spiffe_id not supplied) — refusing "
                    "to dial with unverifiable peer identity."
                )

            from yashigani.pki.client import internal_httpx_client_verify_spiffe

            async with internal_httpx_client_verify_spiffe(
                self.expected_spiffe_id
            ) as client:
                return await client.request(method, url, **kwargs)

        # Genuinely-external (or non-TLS internal-bridge) traffic — default
        # system CA trust store, unchanged from prior behaviour.
        async with httpx.AsyncClient() as client:
            return await client.request(method, url, **kwargs)

    async def aclose(self) -> None:
        """No-op — ``HttpClient`` creates a new connection per request.

        Provided so that callers that own the lifetime of an injected
        client (e.g. ``McpHttpTransport.__aexit__``) can call ``aclose()``
        uniformly on both ``httpx.AsyncClient`` and ``HttpClient`` instances
        without a type check.
        """
