"""
yashigani.net — centralised outbound HTTP client with SSRF guardrails.

QA Wave 2 finding #5 (API7): 17 outbound `httpx` / `requests` call
sites across the code base lacked a uniform allowlist wrapper. The gateway
upstream is admin-configured (fine), but alert sinks, backoffice routes
for agents/models, and a handful of other callers made raw outbound HTTP
with no centralised safety.

This module provides a single entry point that every outbound caller
should use. It enforces:

  * URL scheme allowlist (only https:// by default; http:// opt-in per
    call AND only for explicitly-trusted hosts)
  * Host allowlist / blocklist resolved against env-driven config
  * Timeout default (no more than 30 s, unless overridden)
  * No auto-follow of redirects to hosts outside the allowlist
  * Optional mTLS client-cert loading (integrates with task #29)
  * Logged audit event on blocked attempts

v2.23.3 — DNS-rebinding defence (OWASP API7, issue #91):
  :func:`pinned_resolver` is an async context manager that resolves the
  target hostname once, pins the resulting IP, and monkey-patches
  ``socket.getaddrinfo`` for the underlying transport so that subsequent
  DNS changes cannot redirect the connection to a different (internal) host.

Usage:

    from yashigani.net import HttpClient, BlockedByPolicy
    client = HttpClient()
    try:
        r = await client.get("https://api.pwnedpasswords.com/range/ABCDE")
    except BlockedByPolicy as exc:
        logger.warning("Outbound blocked: %s", exc)

    from yashigani.net import pinned_resolver
    async with pinned_resolver("api.pwnedpasswords.com",
                               allowlist=["api.pwnedpasswords.com"]) as session:
        r = await session.get("https://api.pwnedpasswords.com/range/ABCDE")

Migration of the existing 17 call sites happens as task #32b (tracked
separately) — this module lands first so callers can opt in incrementally.

Implementation note — lazy ``pinned_resolver`` export
-----------------------------------------------------
``pinned_resolver`` is NOT eagerly imported at package-init time.  It is
exposed via a custom module class (``_NetModule``) that overrides
``__getattribute__`` to intercept the name ``pinned_resolver`` and always
return the *function* from ``yashigani.net.pinned_resolver``, regardless of
whether the submodule object has been installed as a package attribute by
Python's import machinery.

Rationale: ``pinned_resolver.py`` imports ``socket`` and ``httpx`` at module
level.  Under rootful Podman (GitHub Actions CI, GH runner ubuntu-latest,
podman-compose), the backoffice container runs with ``--read-only``,
``--cap-drop ALL``, and a custom seccomp profile.  Importing
``pinned_resolver.py`` eagerly at package-init time caused a silent startup
crash on that platform (zero stdout/stderr — process killed before uvicorn
emitted a single log line).  The identical image passes on Docker Engine,
which handles the network-namespace / seccomp / read-only filesystem
interaction differently.

Deferring the import until ``pinned_resolver`` is first accessed means that
importing this package for ``HttpClient`` or ``BlockedByPolicy`` (the hot-path
startup imports) never touches ``pinned_resolver.py``.

Why ``__getattribute__`` and not ``__getattr__``?
  ``__getattr__`` fires only when the attribute is *not found* via normal
  lookup.  Python's import system, after loading the ``pinned_resolver``
  submodule, sets ``sys.modules['yashigani.net'].pinned_resolver = <module>``
  as a side effect.  Once that attribute exists, ``__getattr__`` is bypassed
  entirely, and ``from yashigani.net import pinned_resolver`` silently returns
  the *module*, which is not callable.  Overriding ``__getattribute__`` on a
  custom module class intercepts every attribute access unconditionally,
  letting us redirect ``pinned_resolver`` to the function even after the
  submodule has been registered.

Fix-reference: fix/v233-backoffice-startup-podman (P0, Su pre-flight
2026-05-09T09:47).
"""

from __future__ import annotations

import sys
import types
from typing import TYPE_CHECKING

from .http_client import HttpClient, BlockedByPolicy

if TYPE_CHECKING:
    # Type-check-time only: gives mypy the correct callable type for
    # `pinned_resolver` when imported via `from yashigani.net import
    # pinned_resolver`.  At runtime the lazy _NetModule.__getattribute__ trick
    # handles the redirect; this block is never executed.
    from .pinned_resolver import pinned_resolver as pinned_resolver  # noqa: F401

__all__ = ["HttpClient", "BlockedByPolicy", "pinned_resolver"]

# Sentinel used in _NetModule.__getattribute__ to distinguish "key absent"
# from a value of None.  Must be defined at module level so it is captured
# in the dict-copy when we replace this module in sys.modules.
_SENTINEL = object()


class _NetModule(types.ModuleType):
    """Wrapper module class that intercepts ``pinned_resolver`` attribute access.

    Python's import machinery sets ``yashigani.net.pinned_resolver`` to the
    *submodule object* whenever ``yashigani.net.pinned_resolver`` is imported.
    This class overrides ``__getattribute__`` so that accessing
    ``yashigani.net.pinned_resolver`` always returns the *function*, not the
    submodule.  The submodule is loaded lazily on first access.

    All other attribute lookups delegate to the standard module ``__dict__``.
    """

    def __getattribute__(self, name: str):  # type: ignore[override]
        if name == "pinned_resolver":
            # 1. Check module __dict__ first — allows test monkeypatching via
            #    patch.object(yashigani.net, 'pinned_resolver', fake).
            #    When a test patches the attribute, the patched value is a callable
            #    (the fake), not the submodule.  We honour the patch.
            d = object.__getattribute__(self, "__dict__")
            val = d.get("pinned_resolver", _SENTINEL)
            if val is not _SENTINEL and callable(val):
                # Either a patched fake or the real function set previously.
                return val

            # 2. val is missing or is the submodule (module, not callable):
            #    load/re-fetch the function from the submodule.
            import importlib

            submod = importlib.import_module("yashigani.net.pinned_resolver")
            # Return the *function* from the submodule, not the submodule itself.
            fn = object.__getattribute__(submod, "pinned_resolver")
            # Cache the function in __dict__ so the next access is fast and avoids
            # importlib.import_module overhead.  The submodule is already in
            # sys.modules so this doesn't trigger a re-import.  If the submodule
            # attribute write later sets __dict__['pinned_resolver'] to the module
            # object again, the callable check above will catch it and re-fetch.
            d["pinned_resolver"] = fn
            return fn
        return super().__getattribute__(name)


# ---------------------------------------------------------------------------
# Replace this module in sys.modules with the custom wrapper so that any
# code that imports yashigani.net — directly or via the package cache —
# goes through _NetModule.__getattribute__.
# ---------------------------------------------------------------------------
_current_module = sys.modules[__name__]
_replacement = _NetModule(__name__, _current_module.__doc__)
# Copy all existing module attributes into the replacement.
_replacement.__dict__.update(
    {
        k: v
        for k, v in _current_module.__dict__.items()
        if k
        not in (
            # Exclude items we're re-defining or that are only needed during init.
            "_current_module",
            "_replacement",
            "_NetModule",
        )
    }
)
# Swap the module in sys.modules.  From this point on, 'import yashigani.net'
# and all attribute lookups go through _NetModule.
sys.modules[__name__] = _replacement
