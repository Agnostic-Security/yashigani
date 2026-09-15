# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Concurrency and per-user context move as one unit — YSG-RISK-317.

Tiago 2026-09-15: "max_concurrent_requests, default 4 seems very low" /
"should be different for every yashigani license type".

Both true, and the same change. llama-server DIVIDES total context across
slots — measured on the pinned Metal build, same binary, same `-c`:

    -c 4096 -np 1                 n_slots = 1, n_ctx_slot = 4096
    -c 4096 -np 4                 n_slots = 4, n_ctx_slot = 1024
    -c 4096 -np 4 --kv-unified    n_slots = 4, n_ctx_slot = 4096

We shipped `--parallel 4` and no `--ctx-size`, so llama-server applied its own
4096 default and quartered it: every user got 1024 tokens. Nobody chose that;
it fell out of the Red-Council C1 coupling of the admission ceiling to the slot
count.

So a tier that raises concurrency alone does not add capacity — it divides
everyone's context by the new slot count. These tests make that shape
impossible to reintroduce.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kuroshio.entrypoint import (
    LICENCE_TIERS,
    EntrypointConfigError,
    LicenceTier,
    resolve_licence_tier,
)
from kuroshio.models import Provenance, ProvenanceKind, ResolvedModel
from kuroshio.supervisor.supervisor import LoadConfig, ResourceLimits, Supervisor


class _NullRunner:
    def spawn(self, *, binary: str, args: list[str], env: dict[str, str]) -> object:
        raise AssertionError("not spawned in these tests")


def _args(*, limits: ResourceLimits | None = None, **kw: object) -> list[str]:
    sha = "a" * 64
    model = ResolvedModel(
        sha256=sha,
        blob_path=Path(f"/blobs/{sha}.gguf"),
        metadata={"name": "m"},
        provenance=Provenance(kind=ProvenanceKind.LOCAL_FILE, origin="x", sha256=sha),
    )
    sup = Supervisor(
        process_runner=_NullRunner(),
        llama_server_binary="llama-server",
        resource_limits=limits,
    )
    return sup.build_args(model, LoadConfig(**kw), 39000)  # type: ignore[arg-type]


def _flag(args: list[str], name: str) -> str | None:
    return args[args.index(name) + 1] if name in args else None


# --- the derivation: total context is per-user * slots -----------------------


@pytest.mark.parametrize("slots", [1, 2, 4, 32, 128])
def test_total_context_scales_with_slots_so_per_user_context_is_constant(slots: int) -> None:
    """The property that matters. Whatever the slot count, one user still gets
    `per_user_context` — which is the thing an operator actually reasons about."""
    args = _args(per_user_context=8192, parallel_slots=slots)
    assert _flag(args, "--parallel") == str(slots)
    assert _flag(args, "--ctx-size") == str(8192 * slots)


def test_raising_concurrency_alone_no_longer_shrinks_context() -> None:
    """The exact YSG-RISK-317 defect, pinned. Going 4 -> 32 slots must not
    leave each user with an eighth of the context."""
    small = _args(per_user_context=8192, parallel_slots=4)
    large = _args(per_user_context=8192, parallel_slots=32)
    per_user = lambda a: int(_flag(a, "--ctx-size")) // int(_flag(a, "--parallel"))  # noqa: E731
    assert per_user(small) == per_user(large) == 8192


def test_explicit_total_context_still_wins() -> None:
    """Deploys that already set a total keep their exact behaviour — this must
    not be a behaviour change smuggled in under a new feature."""
    args = _args(context_length=4096, per_user_context=8192, parallel_slots=4)
    assert _flag(args, "--ctx-size") == "4096"


def test_ctx_size_omitted_when_neither_is_configured() -> None:
    """Unchanged from before: no opinion means no flag."""
    assert "--ctx-size" not in _args(parallel_slots=4)


def test_ctx_size_is_emitted_after_parallel_is_known() -> None:
    """Ordering is load-bearing, not cosmetic: the total cannot be computed
    before the slot count is resolved."""
    args = _args(per_user_context=2048, parallel_slots=3)
    assert args.index("--parallel") < args.index("--ctx-size")


def test_slots_default_to_the_admission_ceiling_and_context_follows() -> None:
    """The C1 coupling of --parallel to max_concurrent_requests is preserved;
    context now follows it instead of being silently divided by it."""
    args = _args(per_user_context=8192, limits=ResourceLimits(max_concurrent_requests=8))
    assert _flag(args, "--parallel") == "8"
    assert _flag(args, "--ctx-size") == str(8192 * 8)


# --- tiers -------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(LICENCE_TIERS))
def test_every_tier_sets_both_knobs(name: str) -> None:
    """A tier that set only one would reintroduce the bug it exists to prevent."""
    tier = resolve_licence_tier(name)
    assert isinstance(tier, LicenceTier)
    assert tier.max_concurrent_requests > 0
    assert tier.per_user_context > 0


def test_tiers_increase_monotonically_in_concurrency() -> None:
    order = ["community", "smb", "enterprise", "datacenter"]
    seats = [LICENCE_TIERS[n].max_concurrent_requests for n in order]
    assert seats == sorted(seats), f"tiers must not decrease in capacity: {seats}"


def test_no_tier_is_worse_than_the_old_broken_default() -> None:
    """1024 tokens/user is what the old defaults produced. No tier may ship
    that, including the smallest — a floor, not a target."""
    for tier in LICENCE_TIERS.values():
        assert tier.per_user_context > 1024, f"{tier.name} is no better than the defect"


def test_unknown_tier_is_refused_not_defaulted() -> None:
    """Silently defaulting would serve a tier nobody purchased, in either
    direction. A typo in a manifest must stop the deploy."""
    with pytest.raises(EntrypointConfigError, match="unknown licence tier"):
        resolve_licence_tier("entrprise")


@pytest.mark.parametrize("blank", [None, "", "   "])
def test_absent_tier_is_not_an_error(blank: str | None) -> None:
    """Tiering is opt-in; not naming one is legitimate, unlike naming a wrong one."""
    assert resolve_licence_tier(blank) is None


def test_tier_lookup_is_case_insensitive() -> None:
    assert resolve_licence_tier("Enterprise") is LICENCE_TIERS["enterprise"]
