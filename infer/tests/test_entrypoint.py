# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the ASGI wiring entrypoint (`yashigani_infer.entrypoint`).

Hard constraint (same as the rest of this suite): no real `llama-server` binary, no
network, no live process spawn. `create_asgi_app` builds a real `SubprocessProcessRunner`
and `HttpxUpstreamClient`, but neither is ever exercised at construction time — the
supervisor only touches the process runner when a model is actually loaded, and nothing
in these tests loads one. `BlobStore` construction does real (but harmless) local
filesystem `mkdir`s, always rooted at a `tmp_path`-derived directory, never the real
process home directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from yashigani_infer.config import EngineConfig
from yashigani_infer.entrypoint import (
    VALID_ROLES,
    EntrypointConfigError,
    RoleConfig,
    create_asgi_app,
    load_role_config,
)
from yashigani_infer.supervisor.supervisor import LoadConfig, ResourceLimits


def _classifier_env(blob_root: Path) -> dict[str, str]:
    """Mirrors the actual `infer-classifier` service block in
    `infer/deploy/docker/docker-compose.infer.yml`, plus an explicit blob-store root
    (the compose file itself does not set one today — see final report)."""
    return {
        "YSG_INFER_ROLE": "classifier",
        "YSG_INFER_BLOB_STORE_ROOT": str(blob_root),
        "YSG_INFER_KEEP_ALIVE_PIN": "true",
        "YSG_INFER_MAX_CTX": "2048",
        "YSG_INFER_MAX_CONCURRENCY": "8",
        "YSG_INFER_MAX_TOKENS_PER_REQUEST": "512",
        "YSG_INFER_IDLE_UNLOAD_SECONDS": "0",
        "YSG_INFER_MAX_RESIDENT_MODELS": "1",
        "YSG_INFER_EXPECT_GPU": "true",
    }


def _chat_env(blob_root: Path) -> dict[str, str]:
    """Mirrors the actual `infer-chat` service block."""
    return {
        "YSG_INFER_ROLE": "chat",
        "YSG_INFER_BLOB_STORE_ROOT": str(blob_root),
        "YSG_INFER_KEEP_ALIVE_PIN": "false",
        "YSG_INFER_MAX_CTX": "8192",
        "YSG_INFER_MAX_CONCURRENCY": "4",
        "YSG_INFER_MAX_TOKENS_PER_REQUEST": "4096",
        "YSG_INFER_IDLE_UNLOAD_SECONDS": "600",
        "YSG_INFER_MAX_RESIDENT_MODELS": "3",
        "YSG_INFER_EXPECT_GPU": "true",
    }


def _puller_env(blob_root: Path) -> dict[str, str]:
    """Mirrors the actual `infer-puller` service block: YSG_INFER_ROLE is the ONLY
    contract var it sets — no llama_server_binary, no ceilings, no keep-alive/GPU flags."""
    return {"YSG_INFER_ROLE": "puller", "YSG_INFER_BLOB_STORE_ROOT": str(blob_root)}


# ── YSG_INFER_ROLE — required, fail-closed ──────────────────────────────────────────


def test_missing_role_fails_closed() -> None:
    with pytest.raises(EntrypointConfigError, match="YSG_INFER_ROLE"):
        load_role_config({})


def test_blank_role_fails_closed() -> None:
    with pytest.raises(EntrypointConfigError, match="YSG_INFER_ROLE"):
        load_role_config({"YSG_INFER_ROLE": "   "})


def test_unrecognised_role_fails_closed() -> None:
    with pytest.raises(EntrypointConfigError, match="not a recognised role"):
        load_role_config({"YSG_INFER_ROLE": "admin"})


def test_valid_roles_constant_matches_documented_contract() -> None:
    assert VALID_ROLES == ("classifier", "chat", "puller")


@pytest.mark.parametrize("role", ["classifier", "chat", "puller"])
def test_each_documented_role_parses_successfully(role: str, tmp_path: Path) -> None:
    config = load_role_config({"YSG_INFER_ROLE": role, "YSG_INFER_BLOB_STORE_ROOT": str(tmp_path)})
    assert isinstance(config, RoleConfig)
    assert config.role == role


# ── Role-specific env blocks (grounded in the actual compose service definitions) ───


def test_classifier_env_maps_to_expected_engine_and_load_config(tmp_path: Path) -> None:
    config = load_role_config(_classifier_env(tmp_path))

    assert config.engine_config.blob_store_root == tmp_path
    assert config.engine_config.idle_unload_seconds == 0
    assert config.engine_config.max_resident_models == 1
    assert config.engine_config.llama_server_binary == "llama-server"

    assert config.resource_limits == ResourceLimits(
        max_context_length=2048, max_concurrent_requests=8, max_tokens_per_request=512
    )
    assert config.default_load_config.keep_alive_pin is True
    assert config.default_load_config.expect_gpu is True
    assert config.default_load_config.n_gpu_layers is None
    assert config.default_load_config.override_tensor == ()


def test_chat_env_maps_to_expected_engine_and_load_config(tmp_path: Path) -> None:
    config = load_role_config(_chat_env(tmp_path))

    assert config.engine_config.idle_unload_seconds == 600
    assert config.engine_config.max_resident_models == 3
    assert config.resource_limits == ResourceLimits(
        max_context_length=8192, max_concurrent_requests=4, max_tokens_per_request=4096
    )
    assert config.default_load_config.keep_alive_pin is False
    assert config.default_load_config.expect_gpu is True


def test_puller_env_uses_documented_defaults_for_everything_else(tmp_path: Path) -> None:
    """The puller compose service sets ONLY YSG_INFER_ROLE — every other contract var
    must fall back to the dataclass defaults, never crash on absence."""
    default_engine = EngineConfig()
    default_limits = ResourceLimits()
    default_load = LoadConfig()

    config = load_role_config(_puller_env(tmp_path))

    assert config.role == "puller"
    assert config.engine_config.llama_server_binary == default_engine.llama_server_binary == "llama-server"
    assert config.engine_config.idle_unload_seconds == default_engine.idle_unload_seconds
    assert config.engine_config.max_resident_models == default_engine.max_resident_models
    assert config.resource_limits == default_limits
    assert config.default_load_config.keep_alive_pin == default_load.keep_alive_pin is False
    assert config.default_load_config.expect_gpu == default_load.expect_gpu is False
    assert config.default_load_config.n_gpu_layers is None


def test_llama_server_binary_absent_defaults_rather_than_crashes(tmp_path: Path) -> None:
    """Contract explicitly documents YSG_INFER_LLAMA_SERVER_BINARY as ABSENT in the
    puller image — absence must never be a fail-closed condition for this var."""
    env = {"YSG_INFER_ROLE": "puller", "YSG_INFER_BLOB_STORE_ROOT": str(tmp_path)}
    assert "YSG_INFER_LLAMA_SERVER_BINARY" not in env
    config = load_role_config(env)
    assert config.engine_config.llama_server_binary == "llama-server"


# ── Blob-store root resolution ──────────────────────────────────────────────────────


def test_blob_store_root_override_is_honoured(tmp_path: Path) -> None:
    custom_root = tmp_path / "custom-blobs"
    config = load_role_config({"YSG_INFER_ROLE": "chat", "YSG_INFER_BLOB_STORE_ROOT": str(custom_root)})
    assert config.engine_config.blob_store_root == custom_root


def test_blob_store_root_defaults_under_home_when_unset() -> None:
    config = load_role_config({"YSG_INFER_ROLE": "chat"})
    assert config.engine_config.blob_store_root == Path.home() / ".yashigani" / "infer" / "blobs"


# ── Numeric / boolean / list parsing — invalid explicit values fail closed ─────────


@pytest.mark.parametrize(
    "env_var", ["YSG_INFER_MAX_CTX", "YSG_INFER_MAX_CONCURRENCY", "YSG_INFER_MAX_TOKENS_PER_REQUEST"]
)
def test_invalid_integer_env_fails_closed(env_var: str, tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env[env_var] = "not-a-number"
    with pytest.raises(EntrypointConfigError, match=env_var):
        load_role_config(env)


@pytest.mark.parametrize("env_var", ["YSG_INFER_KEEP_ALIVE_PIN", "YSG_INFER_EXPECT_GPU"])
def test_invalid_boolean_env_fails_closed(env_var: str, tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env[env_var] = "maybe"
    with pytest.raises(EntrypointConfigError, match=env_var):
        load_role_config(env)


@pytest.mark.parametrize("truthy", ["true", "1", "yes", "TRUE", "Yes"])
def test_boolean_env_accepts_documented_truthy_values(truthy: str, tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_EXPECT_GPU"] = truthy
    config = load_role_config(env)
    assert config.default_load_config.expect_gpu is True


@pytest.mark.parametrize("falsy", ["false", "0", "no", "FALSE"])
def test_boolean_env_accepts_documented_falsy_values(falsy: str, tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_EXPECT_GPU"] = falsy
    config = load_role_config(env)
    assert config.default_load_config.expect_gpu is False


def test_n_gpu_layers_parses_when_set(tmp_path: Path) -> None:
    env = _classifier_env(tmp_path)
    env["YSG_INFER_N_GPU_LAYERS"] = "999"
    config = load_role_config(env)
    assert config.default_load_config.n_gpu_layers == 999


def test_n_gpu_layers_invalid_fails_closed(tmp_path: Path) -> None:
    env = _classifier_env(tmp_path)
    env["YSG_INFER_N_GPU_LAYERS"] = "all-of-them"
    with pytest.raises(EntrypointConfigError, match="YSG_INFER_N_GPU_LAYERS"):
        load_role_config(env)


def test_override_tensor_splits_and_trims_comma_separated_rules(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_OVERRIDE_TENSOR"] = r"\.ffn_.*_exps\.weight=CPU ,  \.attn_.*=GPU ,,"
    config = load_role_config(env)
    assert config.default_load_config.override_tensor == (r"\.ffn_.*_exps\.weight=CPU", r"\.attn_.*=GPU")


def test_override_tensor_absent_is_empty_tuple(tmp_path: Path) -> None:
    config = load_role_config(_puller_env(tmp_path))
    assert config.default_load_config.override_tensor == ()


# --- Red-Council C1 (2026-07-29): cache_prompt / parallel_slots env wiring ---


def test_cache_prompt_absent_defaults_to_false(tmp_path: Path) -> None:
    config = load_role_config(_chat_env(tmp_path))
    assert config.default_load_config.cache_prompt is False


def test_cache_prompt_true_parses(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_CACHE_PROMPT"] = "true"
    config = load_role_config(env)
    assert config.default_load_config.cache_prompt is True


def test_cache_prompt_invalid_fails_closed(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_CACHE_PROMPT"] = "maybe"
    with pytest.raises(EntrypointConfigError, match="YSG_INFER_CACHE_PROMPT"):
        load_role_config(env)


def test_parallel_slots_absent_defaults_to_none(tmp_path: Path) -> None:
    config = load_role_config(_chat_env(tmp_path))
    assert config.default_load_config.parallel_slots is None


def test_parallel_slots_parses_when_set(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_PARALLEL_SLOTS"] = "4"
    config = load_role_config(env)
    assert config.default_load_config.parallel_slots == 4


def test_parallel_slots_invalid_fails_closed(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    env["YSG_INFER_PARALLEL_SLOTS"] = "not-an-int"
    with pytest.raises(EntrypointConfigError, match="YSG_INFER_PARALLEL_SLOTS"):
        load_role_config(env)


# ── create_asgi_app — full wiring, offline (no live process/network) ──────────────


def test_create_asgi_app_builds_a_working_fastapi_app(tmp_path: Path) -> None:
    env = _chat_env(tmp_path)
    app = create_asgi_app(env)

    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "resident_models": []}

    # blob store really was created on disk, rooted where the env said
    assert (tmp_path / "blobs").is_dir()
    assert (tmp_path / "meta").is_dir()


def test_create_asgi_app_wires_pull_resolver_none_for_every_role(tmp_path: Path) -> None:
    """Captain's decision: v1 always passes pull_resolver=None (see module docstring) —
    /api/pull must 501 in every role until source-adapter env wiring lands."""
    for env_builder in (_classifier_env, _chat_env, _puller_env):
        app = create_asgi_app(env_builder(tmp_path))
        client = TestClient(app)
        resp = client.post("/api/pull", json={"repo_id": "acme/x"})
        assert resp.status_code == 501


def test_create_asgi_app_fails_closed_on_missing_role(tmp_path: Path) -> None:
    with pytest.raises(EntrypointConfigError):
        create_asgi_app({"YSG_INFER_BLOB_STORE_ROOT": str(tmp_path)})


def test_create_asgi_app_fails_closed_before_touching_the_filesystem(tmp_path: Path) -> None:
    """Role validation must happen before any BlobStore mkdir side effect — a
    misconfigured container should not scribble a blob-store skeleton on disk before
    refusing to start."""
    unused_root = tmp_path / "should-never-be-created"
    with pytest.raises(EntrypointConfigError):
        create_asgi_app({"YSG_INFER_BLOB_STORE_ROOT": str(unused_root)})
    assert not unused_root.exists()


def test_create_asgi_app_defaults_to_os_environ(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("YSG_INFER_ROLE", "chat")
    monkeypatch.setenv("YSG_INFER_BLOB_STORE_ROOT", str(tmp_path))
    app = create_asgi_app()  # no explicit env -> os.environ
    client = TestClient(app)
    assert client.get("/healthz").status_code == 200
