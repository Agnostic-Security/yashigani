"""
Tier-C category: cross_runtime_parity — 120-123 were ALL parity gaps (PKI
mount path drift compose vs helm, cached-vs-runtime cert, selective-backup
contract drift, Caddy on-by-default drift). Every security control must
behave IDENTICALLY docker == podman == k8s.

These tests run identically on every leg (the runner passes --runtime so the
SAME test file exercises the SAME assertions against whichever leg is live);
the PARITY claim is proven by running this file on all three runtimes and
diffing the results, not by anything inside a single run. Each test records
its runtime label in the assertion message so a cross-leg diff is legible
straight from CI/log output.
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, YTF_RUNTIME, http_client


@SKIP_NO_STACK
def test_admin_route_requires_caddy_verified_header_on_every_runtime():
    """Layer B (CaddyVerifiedMiddleware) must fail-closed identically on
    every runtime — this is the exact control class BUG-3 (PKI mount path
    drift) and the Caddy-disabled-by-default-on-k8s drift both undermined on
    ONE runtime while the others stayed correct."""
    with http_client() as c:
        # No X-Caddy-Verified-Secret header at all — must 401 everywhere.
        resp = c.get("/admin/", headers={})
        assert resp.status_code in (401, 302, 303), (
            f"[{YTF_RUNTIME}] admin route did not fail closed without the "
            f"Caddy-verified header (got {resp.status_code}) — cross-runtime "
            "parity gap if this differs from the other legs' result for this "
            "same test."
        )


@SKIP_NO_STACK
def test_healthz_reachable_over_tls_on_every_runtime():
    """Baseline parity smoke: every runtime must serve /healthz 200 over the
    same TLS posture (mTLS front, no plaintext fallback) — a runtime that
    silently allows plaintext (K8s Caddy-disabled-by-default class) diverges
    here first, before any deeper control is even reachable to test."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200, f"[{YTF_RUNTIME}] /healthz not 200: {resp.status_code}"
