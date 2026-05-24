# X-Forwarded-For Trust Boundary

**Control:** CWE-345 (Insufficient Verification of Data Authenticity)
**Finding:** V232-NEG03 / LAURA-2026-04-29-006
**Code path:** `src/yashigani/gateway/proxy.py:987–1080` (`_parse_trusted_proxy_cidrs`, `_get_client_ip`)

---

## What the CHANGELOG v2.23.2 says vs. what is implemented

The CHANGELOG entry for v2.23.2 reads:

> "Caddy strips and re-sets `X-Forwarded-For` at the edge; rate limiting and audit
> logging now bind to the Caddy-observed address, not caller-supplied headers."

**This is inaccurate.** No XFF-stripping directive exists in any Caddyfile variant
(`docker/Caddyfile.selfsigned`, `docker/Caddyfile.acme`, `docker/Caddyfile.ca`,
`helm/yashigani/templates/configmaps.yaml`).

The actual XFF spoofing defence is implemented in application code:

- **Function:** `_get_client_ip()` in `src/yashigani/gateway/proxy.py:1034–1080`
- **Algorithm:** Right-to-left walk of the XFF header chain. Each IP is checked
  against `TRUSTED_PROXY_CIDRS`. The first IP that is NOT in a trusted CIDR is
  treated as the real client address.
- **Env var:** `TRUSTED_PROXY_CIDRS` (gateway service) — comma-separated CIDR list.

## Why this matters for operators

If you are deploying Yashigani behind Caddy (the standard deployment), or behind an
external load-balancer, you MUST set `TRUSTED_PROXY_CIDRS` to include the address
range of your proxy infrastructure. Without this:

- The default trust boundary is loopback only (`127.0.0.1/32`, `::1/128`).
- All XFF hops arrive from non-loopback addresses (the Caddy container IP is on the
  Docker bridge, e.g. `172.20.0.x`) and are treated as the real client IP.
- Rate limiting and audit events bind to the proxy address, not the originating
  client. Every request appears to come from the same IP — per-IP rate limiting
  is effectively disabled.

## Standard Compose deployment configuration

In `docker/.env` (or as an env override):

```dotenv
# Trust the Docker internal bridge range (Caddy container → gateway)
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8
```

The gateway reads this once at module import time (`proxy.py:1029`). A container
restart is required after changing this value.

## Kubernetes deployment configuration

The Helm chart exposes this as a gateway environment variable. In your override values:

```yaml
gateway:
  env:
    TRUSTED_PROXY_CIDRS: "127.0.0.1/32,::1/128,10.0.0.0/8"
```

Set the CIDR to match your cluster's pod CIDR range.

## Spoofing attack pattern (mitigated)

An attacker can prepend arbitrary IPs to the XFF header:

```
X-Forwarded-For: <spoofed-ip>, <real-client>, <proxy>
```

A naïve left-to-right trust model takes `<spoofed-ip>` as the client. The
right-to-left walk in `_get_client_ip()` skips trusted proxy hops from the right
and stops at the first non-trusted hop — returning `<real-client>`, not
`<spoofed-ip>`.

**Malformed entries** (non-IP strings in the XFF chain) are treated as untrusted
and returned directly — this is a fail-closed behaviour (the malformed entry acts
as a stop-the-walk signal).

## Code reference

```
src/yashigani/gateway/proxy.py
  987  def _parse_trusted_proxy_cidrs() -> list[...]
 1002    raw = os.environ.get("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128")
 1034  def _get_client_ip(request: Request) -> str:
 1066    for hop in reversed(hops):          # right-to-left walk
 1075      if not any(addr in cidr for cidr in trusted_cidrs):
 1076        return hop                       # first non-trusted = real client
 1078    # All hops trusted → return leftmost (best approximation)
 1080    return hops[0]
```

---

*Security doc — Yashigani. Maintained by Agnostic Security.*
