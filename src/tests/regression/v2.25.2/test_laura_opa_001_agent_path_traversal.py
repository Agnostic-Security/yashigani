"""
LAURA-OPA-001 (2.25.2) regression — agent path-traversal confused-deputy.

agent_router.py forwarded remainder_path verbatim into the httpx URL; httpx
collapses "/do/../admin" -> "/admin" on the wire (RFC-3986), while the OPA gate
matched the un-collapsed path with literal startswith — so an agent scoped to
"/do/**" could reach "/admin" on the target. The router now rejects any
remainder_path containing a traversal sequence (raw or percent-encoded, single-
or double-encoded) BEFORE building the OPA input and before forwarding, so the
path OPA evaluates is byte-identical to what httpx would forward.

These tests pin the _is_path_traversal predicate. The rego-layer guard
(_agent_path_safe) is covered by policy/agents_test.rego.

OWASP WSTG-ATHZ-01 / API1:2023 (BOLA) / ASVS V12.3.1.
PoC: testing_runs/yashigani/opa-bypass-audit-20260604/inputs/proof_004_agent_path_traversal.json
"""
from __future__ import annotations

import pytest

from yashigani.gateway.agent_router import _is_path_traversal


@pytest.mark.parametrize("path", [
    "/do/../admin",          # the PoC
    "/do/../../etc/passwd",
    "/../admin",
    "/do/..",                # trailing dot-segment
    "..",                    # bare
    "/do/%2e%2e/admin",      # encoded dots
    "/do%2f..%2fadmin",      # encoded slashes
    "/do/%2E%2E/admin",      # encoded dots, upper-case
    "/do/%252e%252e/admin",  # double-encoded dots
    "/do/%252f/admin",       # double-encoded slash
    "/do/..\\admin",         # backslash variant
    "/do/%5c..%5cadmin",     # encoded backslash
])
def test_traversal_paths_rejected(path):
    assert _is_path_traversal(path) is True, f"{path!r} must be flagged as traversal"


@pytest.mark.parametrize("path", [
    "/",
    "/do/run",
    "/do/a/b/c",
    "/status",
    "/do/report..final.pdf",   # embedded dots in a filename, not a segment
    "/do/v2.0/run",            # dotted version segment, not traversal
    "/files/my.config.json",
])
def test_legit_paths_allowed(path):
    assert _is_path_traversal(path) is False, f"{path!r} must NOT be flagged as traversal"
