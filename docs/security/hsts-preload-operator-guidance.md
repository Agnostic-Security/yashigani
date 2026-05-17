<!-- last-updated: 2026-05-17T18:30:00+01:00 (v2.23.4: SEC-240-5 / ACS-RISK-015 close — HSTS preload operator-side guidance) -->

# HSTS Preload — Operator Guidance

**Audience:** Yashigani administrators running an internet-facing deployment with a CA-signed certificate.

**Scope:** This document covers HSTS preload submission for hosts using `docker/Caddyfile.ca` (CA-signed enterprise / on-prem deployments) and `docker/Caddyfile.acme` (Let's Encrypt / public ACME deployments). Self-signed deployments (`docker/Caddyfile.selfsigned`) intentionally do not emit HSTS — the certificate is not trusted by browsers, so HSTS-pinning a self-signed cert would prevent operators from later swapping to a real certificate.

---

## What Yashigani ships by default

The Caddy TLS edge emits the following header on every HTTPS response for both `Caddyfile.ca` and `Caddyfile.acme` modes:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

- `max-age=63072000` — 2 years (`63072000 s = 730 days`). Matches the minimum the [hstspreload.org](https://hstspreload.org/) submission gate requires.
- `includeSubDomains` — extends HSTS to every subdomain. Confirm you actually want every subdomain of `${YASHIGANI_TLS_DOMAIN}` covered before submitting (see below).
- `preload` — the *signal* token. Setting this header does **not** preload your domain; it only declares that your domain is **eligible** for preload-list submission.

---

## Operator responsibility — preload submission is opt-in

The `preload` token in the response header is necessary but not sufficient. Browsers do **not** read this header and automatically add your domain. The actual preload list is a hardcoded list inside the Chromium source tree (and inherited by Firefox / Safari / Edge). To get your domain onto that list:

1. Verify your deployment satisfies every [hstspreload.org submission requirement](https://hstspreload.org/#submission-requirements):
   - Valid certificate chain.
   - Redirect all HTTP traffic to HTTPS on the same hostname (Yashigani's Caddyfile.ca + Caddyfile.acme do this by default).
   - `Strict-Transport-Security` header on the base domain — Yashigani ships this.
   - `max-age` ≥ 31536000 (1 year) — Yashigani ships 2 years.
   - `includeSubDomains` directive — Yashigani ships this.
   - `preload` directive — Yashigani ships this.
   - All subdomains served over HTTPS (this is **your** responsibility — Yashigani only serves the hostnames you configured).
2. Submit your domain at [https://hstspreload.org/](https://hstspreload.org/).
3. Wait for the next Chromium release to roll out (typically 6–12 weeks after acceptance).

---

## Irreversibility — removal window is ~45 days from request

Once your domain is added to the preload list:

- Browsers that have shipped with the list update will refuse any plaintext-HTTP connection to your domain or any subdomain, forever, even if you later remove the HSTS header.
- The only way to remove a domain is to submit a [removal request](https://hstspreload.org/removal/) — and removal takes effect only after the next Chromium release rolls out, typically 6–12 weeks later.
- Older browsers that already cached the preload list will continue to refuse plaintext until they update.

**In practice this is irreversible for the deployment lifetime.**

Before submitting, confirm:

- You will continue to operate this hostname on HTTPS indefinitely.
- Every subdomain (`*.${YASHIGANI_TLS_DOMAIN}`) will continue to serve HTTPS indefinitely. A development subdomain you spin up on plaintext will be unreachable from any browser that has the preload entry.
- You have full administrative control of the domain — preload submission for a domain you don't own (e.g. a shared corporate domain you don't fully control) is contrary to the preload-list policy and may break unrelated services on sibling subdomains.

---

## What to do if you are NOT ready to preload

The shipped header is harmless if you don't submit your domain. Browsers will honour the `Strict-Transport-Security` header for the visiting client only (a session-scoped HSTS, with the same 2-year `max-age` cached in that browser's local store). This is the standard HSTS posture for any production HTTPS site.

If you want to disable HSTS entirely (uncommon — usually only during pre-production rollout), remove or comment out the `Strict-Transport-Security` header line in `docker/Caddyfile.ca` or `docker/Caddyfile.acme` before installing.

---

## Risk register cross-reference

- **YSG-RISK-015** (LOW) — `Internal/Risk-Register/yashigani-risks.md` — Caddyfile.ca HSTS preload directive.
- **SEC-240-5** — `Internal/v2.24.0/backlog-security.md` — was originally scoped as v2.24.0 P1; closed in v2.23.4 per the "everything ships in v2.23.4" rule (Tiago directive 2026-05-15).
- **ASVS reference:** V3.7.4 (HSTS preload eligibility).
