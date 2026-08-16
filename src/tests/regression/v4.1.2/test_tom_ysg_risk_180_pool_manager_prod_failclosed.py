"""
Regression test -- v4.1.2 YSG-RISK-180: pool-manager (container-per-identity
CIAA isolation) silently degraded to stub mode on production Linux when the
Docker/Podman/Kubernetes container backend was unreachable.

Current state found: gateway/entrypoint.py's Pool Manager block called
create_backend() (pool/backend.py) -- which itself already WARNS and
returns None (stub mode) when no container backend is reachable -- and
unconditionally continued: PoolManager(backend=None, ...) constructs
successfully in stub mode, no exception raised at all. The wrapping
`except Exception as exc: logger.warning(...)` around the whole block would
ALSO have swallowed a deliberate RuntimeError if one had been raised there
naively, since it has no re-raise. On macOS Docker-Desktop this degrade is
an accepted, documented dev-only limitation (socket passthrough is
unreliable there). On a real production Linux deployment it shipped a
gateway that reports healthy but has never actually container-isolated a
single pool-managed request -- CIAA silently OFF.

Fix:
  - New `_pool_manager_prod_fail_closed(container_backend, *, ysg_env=None,
    os_name=None)` helper in gateway/entrypoint.py -- True iff backend is
    None AND platform.system() == "Linux" AND YASHIGANI_ENV == "production"
    (mirrors the existing zero-trust OPA-mandatory-in-production guard's
    YASHIGANI_ENV signal; ANDed with a Linux-only platform check so a
    genuine macOS dev/test box is never caught even though install.sh /
    docker-compose.yml default YASHIGANI_ENV=production for every non-demo
    install).
  - The Pool Manager try-block now raises RuntimeError when this helper
    returns True, BEFORE constructing PoolManager.
  - `except RuntimeError: raise` inserted ahead of the pre-existing
    `except Exception as exc: logger.warning(...)` so the deliberate
    fail-closed RuntimeError propagates to module-import time (uvicorn
    exits non-zero) instead of being swallowed by the broad handler.
  - macOS-dev (any non-Linux platform) and non-production YASHIGANI_ENV
    keep the existing warn+stub behaviour, unchanged.

Live Linux verification (docker socket missing on a real Linux prod stack
-> gateway refuses to start) is x8x's remit -- this test proves the
decision function and the exception-propagation wiring in isolation.

YASHIGANI_ENV=1 test env note: importing yashigani.gateway.entrypoint
directly triggers `_build_app()` as a module-level side effect (creates
audit log dirs, DB pools, etc.) -- there is no existing test in this repo
that imports it directly (grep confirms every other reference is a
docstring/comment). YASHIGANI_IS_MESH_PROCESS=1 is the ONE documented guard
that skips the `_build_app()` call at import time (see entrypoint.py's
own "Guard: when imported by mesh_entrypoint.py" comment) -- setting it
lets us import the module cleanly and test the REAL
`_pool_manager_prod_fail_closed` function directly, zero logic-duplication
drift risk.
"""
from __future__ import annotations

import importlib
import os
import sys

import pytest


@pytest.fixture
def entrypoint_mod(monkeypatch):
    """Import gateway.entrypoint without triggering _build_app()'s heavy
    side effects (see module docstring above)."""
    monkeypatch.setenv("YASHIGANI_IS_MESH_PROCESS", "1")
    monkeypatch.setenv("YASHIGANI_ENV", os.environ.get("YASHIGANI_ENV", "dev"))
    monkeypatch.setenv("YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-unit-tests")
    sys.modules.pop("yashigani.gateway.entrypoint", None)
    mod = importlib.import_module("yashigani.gateway.entrypoint")
    assert mod.app is None, "sanity: mesh-process guard must have skipped _build_app()"
    yield mod
    sys.modules.pop("yashigani.gateway.entrypoint", None)


class TestPoolManagerProdFailClosedDecision:
    def test_linux_production_no_backend_fails_closed(self, entrypoint_mod):
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Linux"
        ) is True

    def test_linux_production_with_backend_does_not_fail_closed(self, entrypoint_mod):
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            object(), ysg_env="production", os_name="Linux"
        ) is False

    def test_linux_dev_no_backend_warns_not_fails(self, entrypoint_mod):
        """A Linux dev/test box (YASHIGANI_ENV=dev) must NOT fail closed."""
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="dev", os_name="Linux"
        ) is False

    def test_linux_unset_env_does_not_fail_closed(self, entrypoint_mod):
        """No YASHIGANI_ENV set at all -- must not fail closed (fail-open for
        the settings-detection layer itself; the guard only fires on an
        EXPLICIT YASHIGANI_ENV=production)."""
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="", os_name="Linux"
        ) is False

    def test_macos_production_no_backend_exempt(self, entrypoint_mod):
        """macOS Docker-Desktop is the documented accepted dev-only
        limitation -- must stay warn+stub EVEN if YASHIGANI_ENV=production
        (its default per docker-compose.yml/install.sh for any non-demo
        install)."""
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Darwin"
        ) is False

    def test_macos_dev_no_backend_exempt(self, entrypoint_mod):
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="dev", os_name="Darwin"
        ) is False

    def test_env_case_and_whitespace_insensitive(self, entrypoint_mod):
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="  PRODUCTION  ", os_name="Linux"
        ) is True

    def test_live_env_read_when_kwargs_omitted(self, entrypoint_mod, monkeypatch):
        """When ysg_env/os_name are omitted, the function reads live
        os.environ / platform.system() -- confirms the default-arg wiring
        is correct, not just the injectable test seam."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setattr(entrypoint_mod.platform, "system", lambda: "Linux")
        assert entrypoint_mod._pool_manager_prod_fail_closed(None) is True
        monkeypatch.setattr(entrypoint_mod.platform, "system", lambda: "Darwin")
        assert entrypoint_mod._pool_manager_prod_fail_closed(None) is False


class TestExceptionPropagationWiring:
    """Source-level checks that the RuntimeError from the guard cannot be
    swallowed by the pre-existing broad `except Exception` handler around
    the Pool Manager block -- this is the actual fail-closed guarantee;
    the decision function alone is not sufficient without correct
    exception-handler ordering (SOP 1 / lifespan fail-closed discipline)."""

    def _pool_manager_block_source(self):
        import inspect
        from yashigani.gateway import entrypoint as mod
        src = inspect.getsource(mod._build_app)
        start = src.index("# ── v2.4.1: Pool Manager")
        end = src.index("# DDoS protector")
        return src[start:end]

    def test_runtime_error_raised_before_pool_manager_construction(self):
        # Asserts the PROPERTY (guard precedes construction), not one call
        # spelling. Previously matched the literal
        # "if _pool_manager_prod_fail_closed(_container_backend):" — which broke
        # the moment the call became multi-line to pass pool_agents_configured
        # (Tiago 2026-08-16: agents are optional). A guard that only recognises
        # one formatting of itself is a spelling test, not a safety test —
        # cf. FIND-0813-012.
        import re as _re
        block = self._pool_manager_block_source()
        m = _re.search(r"if\s+_pool_manager_prod_fail_closed\s*\(", block)
        assert m, "no `if _pool_manager_prod_fail_closed(...)` guard in the pool-manager block"
        guard_idx = m.start()
        construct_idx = block.index("pool_manager = _PoolManager(")
        assert guard_idx < construct_idx, (
            "the fail-closed guard MUST be evaluated before PoolManager is "
            "constructed, or a production Linux deployment would build a "
            "stub-mode manager before refusing to start"
        )

    def test_except_runtime_error_reraises_before_broad_except(self):
        block = self._pool_manager_block_source()
        runtime_except_idx = block.index("except RuntimeError:")
        broad_except_idx = block.index("except Exception as exc:")
        assert runtime_except_idx < broad_except_idx, (
            "except RuntimeError: raise MUST come before except Exception: "
            "in try/except ordering, or the broad handler would catch it first"
        )
        # The RuntimeError handler must re-raise, not swallow.
        reraise_segment = block[runtime_except_idx:broad_except_idx]
        assert "raise" in reraise_segment

    def test_guard_message_references_ciaa_and_remediation(self):
        block = self._pool_manager_block_source()
        assert "CIAA" in block
        assert "docker.sock" in block or "docker/podman socket" in block
        assert "rbac-pool-manager.yaml" in block


class TestAgentsAreOptional:
    """Tiago directive 2026-08-16: "that should be a choice not mandatory to
    install any agents" / "the client might want to deploy their own with the
    wrapper".

    CIAA only means anything for POOL-MANAGED agents (upstream_url=pool://...).
    Before this change the predicate keyed only on (no backend, Linux,
    production), so a deployment with ZERO agents refused to boot demanding
    isolation for agents that do not exist — including install.sh's own
    documented lean path (--no-agents / --agent-bundles none) and a client
    wrapping their own agents.
    """

    def test_no_pool_agents_does_not_fail_closed(self, entrypoint_mod):
        # The lean/BYO-agent case: production Linux, no backend, but nothing
        # that could ever need container-per-identity isolation.
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Linux",
            pool_agents_configured=False,
        ) is False

    def test_pool_agents_present_still_fails_closed(self, entrypoint_mod):
        # The guard's whole point: a deployment RELYING on isolation must not
        # silently degrade to stub mode.
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Linux",
            pool_agents_configured=True,
        ) is True

    def test_unknown_pool_agents_preserves_conservative_behaviour(self, entrypoint_mod):
        # None = registry unavailable/unreadable. Must NOT silently disable the
        # control on an error path.
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Linux",
            pool_agents_configured=None,
        ) is True

    def test_explicit_socket_opt_out_honoured(self, entrypoint_mod):
        # docker-compose.yml has documented this escape since 4.x
        # ("set CONTAINER_SOCKET_ENABLED=false") while it existed NOWHERE in
        # src/ — an operator following the docs had no way out.
        assert entrypoint_mod._pool_manager_prod_fail_closed(
            None, ysg_env="production", os_name="Linux",
            pool_agents_configured=True, socket_enabled=False,
        ) is False

    def test_socket_enabled_env_var_is_read(self, entrypoint_mod, monkeypatch):
        monkeypatch.setenv("CONTAINER_SOCKET_ENABLED", "false")
        assert entrypoint_mod._socket_enabled() is False
        for truthy in ("true", "TRUE", "1", "yes", ""):
            monkeypatch.setenv("CONTAINER_SOCKET_ENABLED", truthy)
            assert entrypoint_mod._socket_enabled() is True, truthy
        monkeypatch.delenv("CONTAINER_SOCKET_ENABLED", raising=False)
        assert entrypoint_mod._socket_enabled() is True  # default = enabled

    def test_pool_agents_configured_detects_pool_scheme(self, entrypoint_mod):
        class _Reg:
            def __init__(self, agents): self._a = agents
            def list_all(self): return self._a
        assert entrypoint_mod._pool_agents_configured(
            _Reg([{"name": "a", "upstream_url": "https://x"}])) is False
        assert entrypoint_mod._pool_agents_configured(
            _Reg([{"name": "a", "upstream_url": "https://x"},
                  {"name": "b", "upstream_url": "pool://img:1"}])) is True
        assert entrypoint_mod._pool_agents_configured(_Reg([])) is False
        assert entrypoint_mod._pool_agents_configured(None) is None

    def test_registry_error_returns_none_not_false(self, entrypoint_mod):
        # An exception must NOT be read as "no agents" — that would silently
        # disable the guard on an error path.
        class _Boom:
            def list_all(self): raise RuntimeError("redis down")
        assert entrypoint_mod._pool_agents_configured(_Boom()) is None
