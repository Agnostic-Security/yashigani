# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for `config.py` (Iris integration-seam audit F4: the blob-store-root
override-or-home-default logic used to be duplicated independently in
`entrypoint._resolve_blob_store_root` — this now delegates to `config._default_blob_store_root`,
the single source of truth)."""

from __future__ import annotations

from pathlib import Path

from yashigani_infer import config, entrypoint
from yashigani_infer.config import BLOB_STORE_ROOT_ENV, EngineConfig, _default_blob_store_root


def test_default_blob_store_root_honours_override_from_injected_env(tmp_path: Path) -> None:
    custom = tmp_path / "custom-blobs"
    assert _default_blob_store_root({BLOB_STORE_ROOT_ENV: str(custom)}) == custom


def test_default_blob_store_root_defaults_under_home_when_env_lacks_override() -> None:
    assert _default_blob_store_root({}) == Path.home() / ".yashigani" / "infer" / "blobs"


def test_default_blob_store_root_reads_real_os_environ_when_no_env_passed(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "os-environ-blobs"
    monkeypatch.setenv(BLOB_STORE_ROOT_ENV, str(custom))
    assert _default_blob_store_root() == custom


def test_engine_config_default_factory_uses_the_same_function(monkeypatch, tmp_path: Path) -> None:
    custom = tmp_path / "engine-config-blobs"
    monkeypatch.setenv(BLOB_STORE_ROOT_ENV, str(custom))
    assert EngineConfig().blob_store_root == custom


def test_entrypoint_resolve_blob_store_root_delegates_to_config(monkeypatch, tmp_path: Path) -> None:
    """The single-source-of-truth assertion for F4: `entrypoint._resolve_blob_store_root`
    must call `config._default_blob_store_root` rather than re-implement the
    override-or-home-default logic itself."""
    calls: list[dict[str, str]] = []
    sentinel = tmp_path / "sentinel"

    def _fake_default(env):
        calls.append(dict(env))
        return sentinel

    monkeypatch.setattr(config, "_default_blob_store_root", _fake_default)
    monkeypatch.setattr(entrypoint, "_default_blob_store_root", _fake_default)

    result = entrypoint._resolve_blob_store_root({"YSG_INFER_BLOB_STORE_ROOT": "/whatever"})

    assert result == sentinel
    assert calls == [{"YSG_INFER_BLOB_STORE_ROOT": "/whatever"}]


def test_entrypoint_and_config_agree_on_the_default_root_when_unset() -> None:
    assert entrypoint._resolve_blob_store_root({}) == _default_blob_store_root({})
