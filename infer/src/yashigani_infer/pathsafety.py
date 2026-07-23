# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Agnostic Security Ltd
"""Path-containment primitives shared by every filesystem-touching adapter.

Red-council hardening pass (Laura/Nico/Captain/Su, GO-WITH-FIXES) Critical
findings #1/#2: every externally-derived path fragment (Hugging Face
repo/revision/filename, local-store index entries, model names) must pass
TWO INDEPENDENT gates before touching the filesystem:

  1. `reject_dotdot_segments` — a fast, allocation-free segment-level check
     that refuses any `..`/`.` path component *before* any join/resolve is
     attempted. Regex allowlists alone do NOT reliably block traversal
     (a regex can be subtly wrong; a dedicated segment check cannot).
  2. `canonicalize_and_contain` — resolves symlinks and joins onto the
     store root, then hard-requires the result stays inside that root. This
     independently catches absolute-path overrides and symlink-based
     escapes that don't literally contain a `..` segment.

Both gates run on every local-store indexing path (Ollama/LM Studio
adapters). `open_no_follow_symlink` closes the remaining TOCTOU window: even
after both gates pass, the leaf file could theoretically be swapped for a
symlink between the check and the open — `O_NOFOLLOW` makes that swap fail
instead of silently following the attacker's symlink.
"""

from __future__ import annotations

import os
from pathlib import Path


class PathTraversalError(ValueError):
    """Raised when a path fragment fails either containment gate."""


class SymlinkEscapeError(OSError):
    """Raised when the final open() would follow a symlink (TOCTOU guard)."""


_MAX_REFLECTED_COMPONENT_LEN = 64


def _bounded_component(component: str, limit: int = _MAX_REFLECTED_COMPONENT_LEN) -> str:
    """Bound an attacker-controlled path fragment before it reaches an exception message.

    Laura's adversarial re-attack (2026-07-22, probe A1f) found that an
    overlong single path component causes the OSError raised by
    `Path.is_symlink()`/`Path.resolve()` (`ENAMETOOLONG` / "File name too
    long") to reflect the FULL attacker-controlled string verbatim —
    confirmed O(1)/linear, not itself a resource-exhaustion vector, but
    worth truncating before it can inflate structured logs once this path
    becomes network-reachable (Info-only, non-blocking). Fixed length, not a
    ratio, so behaviour doesn't vary by input size.
    """
    if len(component) <= limit:
        return component
    return f"{component[:limit]}…[truncated, {len(component)} chars total]"


def reject_dotdot_segments(relative: str) -> None:
    """Gate 1: reject any `..`/`.` path segment before any join/resolve.

    Operates on the raw, un-joined string — this is deliberately independent
    of `canonicalize_and_contain` (gate 2), which only runs after a `Path`
    join. A caller that (by mistake) skips gate 2 still gets this check.
    """
    normalized = relative.replace("\\", "/")
    for segment in normalized.split("/"):
        if segment in ("..", "."):
            raise PathTraversalError(f"path segment {segment!r} is not allowed in {relative!r}")
        if segment == "":
            # Empty segments (leading '/', '//', trailing '/') are refused
            # too — an absolute-path override or a malformed relative path
            # should never silently collapse into something else.
            raise PathTraversalError(f"empty path segment is not allowed in {relative!r}")


def canonicalize_and_contain(root: Path, relative: str) -> Path:
    """Gate 2: join `relative` onto `root`, resolve symlinks, hard-require containment.

    Independent of `reject_dotdot_segments` (gate 1) — this also catches
    absolute-path overrides (`Path(root) / "/etc/passwd"` behaves like
    `PosixPath("/etc/passwd")` in pathlib's `/` join) and symlink escapes
    that resolve outside `root` without ever containing a literal `..`.

    Additionally refuses if the FINAL (leaf) component is itself a symlink,
    even when that symlink's target happens to resolve back inside `root` —
    "do not follow escaping symlinks" (red-council item #2) is enforced as
    "do not follow ANY symlink at the leaf," which is both simpler and
    strictly stronger than only rejecting symlinks whose target lies
    outside root (a resolve()-based containment check alone cannot
    distinguish a symlink from a real file once it has already resolved
    through it, so this check must run on the UN-resolved candidate).

    Returns the resolved, contained, real path. Uses `strict=False` so a
    not-yet-existing path can still be validated (the caller is expected to
    `is_file()`/open it next); existence is never assumed here.
    """
    root_real = root.resolve(strict=False)
    candidate = root / relative

    # `is_symlink()`/`resolve()` below do real lstat/realpath syscalls — an
    # overlong `relative` component (or overlong resulting path) surfaces a
    # native OSError (ENAMETOOLONG) whose message embeds the full path
    # verbatim. Catch and re-raise the SAME exception type (still fails
    # closed, no control-flow change) with the reflected component bounded
    # (Laura A1f, log-hygiene hardening).
    try:
        candidate_is_symlink = candidate.is_symlink()
    except OSError as exc:
        raise OSError(
            exc.errno, f"cannot stat path component {_bounded_component(relative)!r}: {exc.strerror or exc}"
        ) from None
    if candidate_is_symlink:
        raise PathTraversalError(f"{relative!r} is a symlink — refusing to follow it (leaf must be a regular file)")
    try:
        candidate_real = candidate.resolve(strict=False)
    except OSError as exc:
        raise OSError(
            exc.errno, f"cannot resolve path component {_bounded_component(relative)!r}: {exc.strerror or exc}"
        ) from None
    try:
        candidate_real.relative_to(root_real)
    except ValueError:
        raise PathTraversalError(f"{relative!r} resolves outside {root_real}: got {candidate_real}") from None
    return candidate_real


def open_no_follow_symlink(path: Path, *, flags: int = os.O_RDONLY) -> int:
    """Open `path`'s FINAL component with O_NOFOLLOW.

    Refuses if the leaf itself is a symlink — closing the residual TOCTOU
    window between `canonicalize_and_contain` resolving the path and this
    call actually opening it (the leaf cannot be swapped to a symlink in
    between without this raising). Returns a raw fd; caller is responsible
    for closing it (or wrapping in `os.fdopen`, which will close on `close()`).
    """
    try:
        return os.open(path, flags | os.O_NOFOLLOW)
    except OSError as exc:
        raise SymlinkEscapeError(f"refusing to open {path} (possible symlink swap): {exc}") from exc


__all__ = [
    "PathTraversalError",
    "SymlinkEscapeError",
    "reject_dotdot_segments",
    "canonicalize_and_contain",
    "open_no_follow_symlink",
]
