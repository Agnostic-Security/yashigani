# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Unit tests for the two independent path-containment gates + O_NOFOLLOW open."""

from __future__ import annotations

import os

import pytest

from yashigani_infer.pathsafety import (
    PathTraversalError,
    SymlinkEscapeError,
    canonicalize_and_contain,
    open_no_follow_symlink,
    reject_dotdot_segments,
)


def test_reject_dotdot_segments_allows_normal_relative_path() -> None:
    reject_dotdot_segments("a/b/c.gguf")  # must not raise


def test_reject_dotdot_segments_blocks_parent_traversal() -> None:
    with pytest.raises(PathTraversalError):
        reject_dotdot_segments("a/../../etc/passwd")


def test_reject_dotdot_segments_blocks_bare_dot() -> None:
    with pytest.raises(PathTraversalError):
        reject_dotdot_segments("./secret")


def test_reject_dotdot_segments_blocks_leading_slash() -> None:
    with pytest.raises(PathTraversalError):
        reject_dotdot_segments("/etc/passwd")


def test_reject_dotdot_segments_blocks_backslash_traversal() -> None:
    with pytest.raises(PathTraversalError):
        reject_dotdot_segments("a\\..\\..\\windows")


def test_canonicalize_and_contain_allows_nested_path(tmp_path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    (root / "a" / "b").mkdir(parents=True)
    result = canonicalize_and_contain(root, "a/b/c.gguf")
    assert result == (root / "a" / "b" / "c.gguf").resolve()


def test_canonicalize_and_contain_blocks_traversal_even_if_gate_one_skipped(tmp_path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    with pytest.raises(PathTraversalError):
        canonicalize_and_contain(root, "../outside.gguf")


def test_canonicalize_and_contain_blocks_symlink_escape(tmp_path) -> None:
    root = tmp_path / "store"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.gguf").write_bytes(b"secret")
    (root / "escape").symlink_to(outside)

    with pytest.raises(PathTraversalError):
        canonicalize_and_contain(root, "escape/secret.gguf")


def test_canonicalize_and_contain_blocks_leaf_symlink_even_if_target_is_inside_root(tmp_path) -> None:
    """A resolve()-based containment check alone would PASS here (the
    symlink's target legitimately lives inside root) — the leaf-symlink
    check must catch it independently of where the target resolves."""
    root = tmp_path / "store"
    root.mkdir()
    real_file = root / "real.gguf"
    real_file.write_bytes(b"data")
    link = root / "link.gguf"
    link.symlink_to(real_file)

    with pytest.raises(PathTraversalError, match="symlink"):
        canonicalize_and_contain(root, "link.gguf")


def test_open_no_follow_symlink_reads_a_real_file(tmp_path) -> None:
    path = tmp_path / "real.gguf"
    path.write_bytes(b"hello")
    fd = open_no_follow_symlink(path)
    try:
        assert os.read(fd, 5) == b"hello"
    finally:
        os.close(fd)


def test_open_no_follow_symlink_refuses_a_symlink_leaf(tmp_path) -> None:
    target = tmp_path / "target.gguf"
    target.write_bytes(b"data")
    link = tmp_path / "link.gguf"
    link.symlink_to(target)

    with pytest.raises(SymlinkEscapeError):
        open_no_follow_symlink(link)
