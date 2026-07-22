# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""ASGI wiring entrypoint — env-var-driven construction of the yashigani-infer app.

This module is the coordination-gap fix Captain flagged in
`infer/deploy/docker/entrypoint/infer-entrypoint.sh` and `infer/deploy/README.md`: every
container `ENTRYPOINT` execs::

    uvicorn yashigani_infer.entrypoint:create_asgi_app --factory --host 0.0.0.0 --port 8000

`create_asgi_app` is that `--factory` target. `yashigani_infer.app.create_app` takes
constructor keyword arguments (`blob_store`, `supervisor`, `upstream`, `pull_resolver`,
`output_inspection_hook`) — it is not itself a bare factory. This module parses the
documented env-var contract, builds the real (non-fake) collaborators, and wires them
into `create_app`.

Fail-closed discipline: any missing/invalid REQUIRED env var raises
`EntrypointConfigError` (a `RuntimeError` subclass), uncaught, so the uvicorn process
exits non-zero at startup rather than serving with a half-built or wrongly-guessed
dependency graph. This is the Python-side half of the shell entrypoint's exit-78
(EX_CONFIG) fail-closed contract — the shell script already fails closed today because
this module did not exist; now that it exists, THIS module must keep failing closed on
bad input rather than silently guessing.

Env-var contract (source of truth: the inline comment block in
``infer/deploy/docker/entrypoint/infer-entrypoint.sh``, mirrored in
``infer/deploy/README.md``)::

    YSG_INFER_ROLE                     REQUIRED. classifier | chat | puller.
    YSG_INFER_BLOB_STORE_ROOT          optional (already exists — config.py); defaults
                                        under the operator's home directory.
    YSG_INFER_LLAMA_SERVER_BINARY      optional, default "llama-server"; ABSENT in the
                                        puller image (the puller never spawns it — the
                                        puller image ships no llama-server binary at
                                        all, and the puller role never has a blob to
                                        auto-load in practice; if it ever did, spawn
                                        would fail closed on the missing binary, which
                                        is the deploy-layer's write-path-isolation
                                        control, not a bug in this module).
    YSG_INFER_MAX_CTX                  optional int -> ResourceLimits.max_context_length
                                        (hard n_ctx ceiling; CLAMPED, never rejected).
    YSG_INFER_MAX_CONCURRENCY          optional int -> ResourceLimits.max_concurrent_requests.
    YSG_INFER_MAX_TOKENS_PER_REQUEST   optional int -> ResourceLimits.max_tokens_per_request.
    YSG_INFER_IDLE_UNLOAD_SECONDS      optional int -> Supervisor idle-unload timeout.
    YSG_INFER_MAX_RESIDENT_MODELS      optional int -> Supervisor LRU ceiling.
    YSG_INFER_KEEP_ALIVE_PIN            optional bool -> LoadConfig.keep_alive_pin ("true"
                                        for the classifier role, WARMUP-001 analog).
    YSG_INFER_EXPECT_GPU               optional bool -> LoadConfig.expect_gpu (healthz
                                        hard-fail gate on a GPU-tagged deployment).
    YSG_INFER_N_GPU_LAYERS             optional int -> LoadConfig.n_gpu_layers.
    YSG_INFER_OVERRIDE_TENSOR          optional, comma-separated MoE `--override-tensor`
                                        regex rules -> LoadConfig.override_tensor.

Every var above except ``YSG_INFER_ROLE`` is optional — absence means "use the existing
dataclass default" (never "crash"), matching the supervisor/app foundation's own
clamp-don't-reject philosophy. An explicitly-set-but-malformed value (not blank, not a
valid int/bool) DOES fail closed, since a silently-ignored typo in an explicit override is
worse than refusing to start (e.g. a typo'd "YSG_INFER_EXPECT_GPU=treu" silently defaulting
to `False` would quietly disable the GPU-engaged healthz hard-fail gate).

Pull-resolver wiring (Captain's decision — see ``infer/deploy/README.md``'s "Classifier /
chat / puller container split" section): this v1 wiring always constructs the app with
``pull_resolver=None`` regardless of role. No source-adapter env vars (Hugging Face
repo/token allowlist, catalog path, licence-acceptance policy) exist in the documented
contract yet — none of the compose/Helm manifests set any such var even for the puller
role — so inventing an adapter wiring here would be guessing, not following the contract.
``/api/pull`` therefore returns 501 in every role until a follow-up increment adds real
source-adapter env-var wiring. This is not a regression on finding #4(b) (write-path
isolation): that vector is already closed at the deploy layer today, because only the
puller container/pod's compose service / Helm Deployment is granted blob-store WRITE
access in the first place (`infer-classifier` / `infer-chat` mount the blob volume
read-only) — a `pull_resolver=None` app cannot write regardless of which container it
runs in, so this is belt-and-braces, not the primary control.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from fastapi import FastAPI

from yashigani_infer.app import create_app
from yashigani_infer.blobstore.store import BlobStore
from yashigani_infer.config import EngineConfig
from yashigani_infer.supervisor.process import SubprocessProcessRunner
from yashigani_infer.supervisor.supervisor import LoadConfig, ResourceLimits, Supervisor
from yashigani_infer.upstream import HttpxUpstreamClient

#: The three container roles the deploy layer builds (see infer/deploy/README.md's
#: "Classifier / chat / puller container split" section). Anything else is refused.
VALID_ROLES = ("classifier", "chat", "puller")

_TRUE_VALUES = frozenset({"true", "1", "yes"})
_FALSE_VALUES = frozenset({"false", "0", "no"})

_ROLE_ENV = "YSG_INFER_ROLE"
_BLOB_STORE_ROOT_ENV = "YSG_INFER_BLOB_STORE_ROOT"
_LLAMA_SERVER_BINARY_ENV = "YSG_INFER_LLAMA_SERVER_BINARY"
_MAX_CTX_ENV = "YSG_INFER_MAX_CTX"
_MAX_CONCURRENCY_ENV = "YSG_INFER_MAX_CONCURRENCY"
_MAX_TOKENS_PER_REQUEST_ENV = "YSG_INFER_MAX_TOKENS_PER_REQUEST"
_IDLE_UNLOAD_SECONDS_ENV = "YSG_INFER_IDLE_UNLOAD_SECONDS"
_MAX_RESIDENT_MODELS_ENV = "YSG_INFER_MAX_RESIDENT_MODELS"
_KEEP_ALIVE_PIN_ENV = "YSG_INFER_KEEP_ALIVE_PIN"
_EXPECT_GPU_ENV = "YSG_INFER_EXPECT_GPU"
_N_GPU_LAYERS_ENV = "YSG_INFER_N_GPU_LAYERS"
_OVERRIDE_TENSOR_ENV = "YSG_INFER_OVERRIDE_TENSOR"


class EntrypointConfigError(RuntimeError):
    """The env-var contract this module honours is missing or invalid.

    Deliberately left uncaught by `create_asgi_app` — see the module docstring's
    fail-closed discipline. An uncaught exception raised from a `uvicorn --factory`
    target aborts server startup with a non-zero process exit, which is the Python-side
    analogue of the shell entrypoint's `exit 78` (EX_CONFIG).
    """


@dataclass(frozen=True)
class RoleConfig:
    """Everything `create_asgi_app` needs, parsed once from the environment.

    Split out from `create_asgi_app` so the env-parsing half (pure, no filesystem/process
    I/O) is independently unit-testable from the wiring half (which constructs a real
    `BlobStore` — a `mkdir` side effect — and a real `Supervisor`/`HttpxUpstreamClient`).
    """

    role: str
    engine_config: EngineConfig
    resource_limits: ResourceLimits
    default_load_config: LoadConfig


def _require_role(env: Mapping[str, str]) -> str:
    role = (env.get(_ROLE_ENV) or "").strip()
    if not role:
        raise EntrypointConfigError(
            f"{_ROLE_ENV} is required and was not set (must be one of: {', '.join(VALID_ROLES)})"
        )
    if role not in VALID_ROLES:
        raise EntrypointConfigError(
            f"{_ROLE_ENV}={role!r} is not a recognised role (must be one of: {', '.join(VALID_ROLES)})"
        )
    return role


def _parse_optional_int(env: Mapping[str, str], name: str) -> int | None:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return None
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise EntrypointConfigError(f"{name}={raw!r} is not a valid integer") from exc


def _parse_optional_bool(env: Mapping[str, str], name: str, *, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise EntrypointConfigError(f"{name}={raw!r} is not a valid boolean (expected one of true/false/1/0/yes/no)")


def _parse_override_tensor(env: Mapping[str, str]) -> tuple[str, ...]:
    raw = env.get(_OVERRIDE_TENSOR_ENV, "")
    if not raw.strip():
        return ()
    return tuple(rule.strip() for rule in raw.split(",") if rule.strip())


def _resolve_blob_store_root(env: Mapping[str, str]) -> Path:
    """Mirror `config._default_blob_store_root`'s override-or-home-default logic, but
    against the injected `env` mapping rather than `os.environ` directly — so tests can
    fully control this via a fake mapping without touching the real process environment
    or the real home directory."""
    override = env.get(_BLOB_STORE_ROOT_ENV)
    if override:
        return Path(override)
    return Path.home() / ".yashigani" / "infer" / "blobs"


def load_role_config(env: Mapping[str, str]) -> RoleConfig:
    """Parse the full env-var contract into a `RoleConfig`.

    Pure function — reads only from `env`, does no filesystem/process I/O, so it is
    trivially unit-testable with a plain `dict`. Raises `EntrypointConfigError` on any
    missing/invalid value (see module docstring).
    """
    role = _require_role(env)

    llama_server_binary = (env.get(_LLAMA_SERVER_BINARY_ENV) or "").strip() or EngineConfig().llama_server_binary
    blob_store_root = _resolve_blob_store_root(env)
    idle_unload_seconds = _parse_optional_int(env, _IDLE_UNLOAD_SECONDS_ENV)
    max_resident_models = _parse_optional_int(env, _MAX_RESIDENT_MODELS_ENV)

    engine_kwargs: dict[str, Any] = {
        "blob_store_root": blob_store_root,
        "llama_server_binary": llama_server_binary,
    }
    if idle_unload_seconds is not None:
        engine_kwargs["idle_unload_seconds"] = idle_unload_seconds
    if max_resident_models is not None:
        engine_kwargs["max_resident_models"] = max_resident_models
    engine_config = EngineConfig(**engine_kwargs)

    max_context_length = _parse_optional_int(env, _MAX_CTX_ENV)
    max_concurrent_requests = _parse_optional_int(env, _MAX_CONCURRENCY_ENV)
    max_tokens_per_request = _parse_optional_int(env, _MAX_TOKENS_PER_REQUEST_ENV)
    resource_limits_kwargs: dict[str, Any] = {
        "max_context_length": max_context_length,
        "max_tokens_per_request": max_tokens_per_request,
    }
    if max_concurrent_requests is not None:
        resource_limits_kwargs["max_concurrent_requests"] = max_concurrent_requests
    resource_limits = ResourceLimits(**resource_limits_kwargs)

    keep_alive_pin = _parse_optional_bool(env, _KEEP_ALIVE_PIN_ENV, default=False)
    expect_gpu = _parse_optional_bool(env, _EXPECT_GPU_ENV, default=False)
    n_gpu_layers = _parse_optional_int(env, _N_GPU_LAYERS_ENV)
    override_tensor = _parse_override_tensor(env)
    default_load_config = LoadConfig(
        n_gpu_layers=n_gpu_layers,
        override_tensor=override_tensor,
        keep_alive_pin=keep_alive_pin,
        expect_gpu=expect_gpu,
    )

    return RoleConfig(
        role=role,
        engine_config=engine_config,
        resource_limits=resource_limits,
        default_load_config=default_load_config,
    )


def create_asgi_app(env: Mapping[str, str] | None = None) -> FastAPI:
    """ASGI app factory — the `uvicorn ... --factory` target every container image execs.

    Builds the full dependency graph (a real `BlobStore` rooted at the configured/default
    path, a `Supervisor` over a real `SubprocessProcessRunner`, a real
    `HttpxUpstreamClient`) from the env-var contract and wires it into
    `yashigani_infer.app.create_app`. Fails closed (raises `EntrypointConfigError`,
    uncaught) on any missing/invalid required env var — see module docstring.

    Args:
        env: defaults to `os.environ` (the real container environment). Tests pass a
            fake mapping instead; production/`uvicorn --factory` calls this with no
            arguments.
    """
    active_env: Mapping[str, str] = os.environ if env is None else env
    role_config = load_role_config(active_env)

    blob_store = BlobStore(role_config.engine_config.blob_store_root)
    supervisor = Supervisor(
        process_runner=SubprocessProcessRunner(),
        llama_server_binary=role_config.engine_config.llama_server_binary,
        idle_unload_seconds=role_config.engine_config.idle_unload_seconds,
        max_resident_models=role_config.engine_config.max_resident_models,
        resource_limits=role_config.resource_limits,
    )
    upstream = HttpxUpstreamClient()

    return create_app(
        blob_store=blob_store,
        supervisor=supervisor,
        upstream=upstream,
        default_load_config=role_config.default_load_config,
        pull_resolver=None,
    )


__all__ = [
    "VALID_ROLES",
    "EntrypointConfigError",
    "RoleConfig",
    "load_role_config",
    "create_asgi_app",
]
