"""
Unit tests for _assert_safe_upstream_url — YSG-RISK-007.A (CWE-918).

Verifies that the agent upstream-URL SSRF guard blocks dangerous URLs and
permits only safe or explicitly allowlisted hostnames.

Updated in fix/v233-base-regressions to reference the current function name
(_assert_safe_upstream_url, introduced in d76dddb) instead of the removed
_assert_safe_owui_url helper. The hand-rolled helper was replaced by
centralised HttpClient._check_policy() for OWUI calls; the agent
upstream_url path now goes through _assert_safe_upstream_url.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load the agents module in isolation — the full import chain pulls in bcrypt/
# asyncpg which are not available in the macOS unit-test environment.
# ---------------------------------------------------------------------------
_AGENTS_PATH = Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "agents.py"


def _load_agents_module():
    """Load agents.py without triggering the full backoffice import chain."""
    # Stub the heavy transitive dependencies before importing
    _stubs = {
        "yashigani.backoffice.middleware": type(sys)("stub"),
        "yashigani.backoffice.state": type(sys)("stub"),
        "yashigani.licensing.enforcer": type(sys)("stub"),
        "pydantic": importlib.import_module("pydantic"),
        "fastapi": importlib.import_module("fastapi"),
    }
    # Add minimal attributes needed by the module-level imports
    _stubs["yashigani.backoffice.middleware"].require_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].AdminSession = object
    _stubs["yashigani.backoffice.middleware"].require_stepup_admin_session = lambda *a, **kw: None
    _stubs["yashigani.backoffice.middleware"].StepUpAdminSession = object
    _stubs["yashigani.backoffice.state"].backoffice_state = None
    _stubs["yashigani.licensing.enforcer"].require_feature = lambda *a, **kw: None

    old = {}
    for k, v in _stubs.items():
        old[k] = sys.modules.get(k)
        sys.modules[k] = v

    spec = importlib.util.spec_from_file_location("agents_isolated", _AGENTS_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    finally:
        for k, v in old.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return mod


_agents = _load_agents_module()
# d76dddb renamed _assert_safe_owui_url → _assert_safe_upstream_url.
# All OWUI outbound calls now go through _owui_http_client()._check_policy().
# Agent upstream_url registration still validates through this function.
_assert_safe_upstream_url = _agents._assert_safe_upstream_url


def _fn(url: str, hostnames_env: str = ""):
    """Call _assert_safe_upstream_url with optional YASHIGANI_AGENT_UPSTREAM_HOSTNAMES override."""
    if hostnames_env:
        old = os.environ.get("YASHIGANI_AGENT_UPSTREAM_HOSTNAMES")
        os.environ["YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"] = hostnames_env
        try:
            return _assert_safe_upstream_url(url)
        finally:
            if old is None:
                os.environ.pop("YASHIGANI_AGENT_UPSTREAM_HOSTNAMES", None)
            else:
                os.environ["YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"] = old
    else:
        # Remove any override so default (empty allowlist) is used
        old = os.environ.pop("YASHIGANI_AGENT_UPSTREAM_HOSTNAMES", None)
        try:
            return _assert_safe_upstream_url(url)
        finally:
            if old is not None:
                os.environ["YASHIGANI_AGENT_UPSTREAM_HOSTNAMES"] = old


class TestAssertSafeUpstreamUrl:
    def test_unresolvable_host_passes(self):
        """Hostname that doesn't resolve (e.g. internal mesh name) passes scheme check.

        open-webui won't resolve outside a Docker network; DNS failure falls
        through to the literal-IP check which skips non-IP tokens — URL passes.
        """
        result = _fn("http://open-webui:8080")
        assert result == "http://open-webui:8080"

    def test_explicit_allowlist_permits_localhost(self):
        """localhost is permitted when explicitly added to YASHIGANI_AGENT_UPSTREAM_HOSTNAMES."""
        result = _fn("http://localhost:8080", hostnames_env="localhost")
        assert result == "http://localhost:8080"

    def test_explicit_allowlist_permits_loopback_ip(self):
        """127.0.0.1 is permitted when explicitly allowlisted."""
        result = _fn("http://127.0.0.1:8080", hostnames_env="127.0.0.1")
        assert result == "http://127.0.0.1:8080"

    def test_https_allowed(self):
        """https:// scheme is allowed for a non-resolving hostname."""
        result = _fn("https://open-webui:8080/api")
        assert result.startswith("https://")

    def test_metadata_endpoint_blocked(self):
        """AWS IMDS link-local endpoint must be blocked (CWE-918)."""
        with pytest.raises(ValueError, match="CWE-918"):
            _fn("http://169.254.169.254/latest/meta-data/")

    def test_custom_allowlist_permits_custom_host(self):
        """A custom YASHIGANI_AGENT_UPSTREAM_HOSTNAMES value allows the specified host."""
        result = _fn("http://my-agent.internal:8080", hostnames_env="my-agent.internal")
        assert result == "http://my-agent.internal:8080"

    def test_custom_allowlist_does_not_permit_unlisted(self):
        """A host not in the custom allowlist must be blocked if it resolves to private/loopback."""
        # evil.example.com won't resolve; falls through to non-IP literal check → passes
        # Use an IP that is definitely blocked: loopback 127.0.0.2 not in allowlist.
        with pytest.raises(ValueError, match="CWE-918"):
            _fn("http://127.0.0.2:8080", hostnames_env="my-agent.internal")

    def test_file_scheme_blocked(self):
        """file:// scheme must be blocked."""
        with pytest.raises(ValueError, match="CWE-918"):
            _fn("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        """ftp:// scheme must be blocked."""
        with pytest.raises(ValueError, match="CWE-918"):
            _fn("ftp://open-webui:21/")

    def test_private_ip_via_explicit_allowlist_passes(self):
        """A private RFC1918 IP explicitly allowlisted is permitted."""
        result = _fn("http://10.0.0.5:8080", hostnames_env="10.0.0.5")
        assert result == "http://10.0.0.5:8080"

    def test_loopback_without_allowlist_blocked(self):
        """localhost resolves to 127.0.0.1 (loopback) — blocked without allowlist."""
        with pytest.raises(ValueError, match="CWE-918"):
            _fn("http://127.0.0.1:8080")
