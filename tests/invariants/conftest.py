"""
Invariant-suite test bootstrap.

These three env vars MUST be set before any ``yashigani.gateway`` module is
imported — ``gateway/proxy.py`` and ``gateway/openai_router.py`` run their
fail-closed startup guards at MODULE LOAD time (no OPA URL / no internal bearer →
RuntimeError on import). This mirrors ``src/tests/conftest.py`` exactly; the
invariant suite lives in a separate test tree so it needs its own bootstrap.

``setdefault`` preserves any explicit override (e.g. CI with a real rotated
secret), so this never weakens a configured run.

NOTE: these are TEST-ONLY shims for importability. The invariants that PROVE the
fail-closed startup behaviour (test_i1) assert the guard exists in source text —
they do not rely on these defaults; the defaults only let the modules import so the
other code-level contracts can be exercised.
"""
from __future__ import annotations

import os

os.environ.setdefault("YASHIGANI_ENV", "dev")
os.environ.setdefault(
    "YASHIGANI_INTERNAL_BEARER", "test-internal-bearer-token-for-invariant-suite"
)
os.environ.setdefault("YASHIGANI_OPA_OPTIONAL", "true")
