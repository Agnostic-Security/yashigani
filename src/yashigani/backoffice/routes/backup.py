"""
Yashigani Backoffice — Backup status + integrity verification.

GET  /admin/backup/status   — list all backups with MANIFEST state
POST /admin/backup/verify   — re-hash a named backup, compare checksums

ASVS: 4.3.1 (body limit enforced in app.py), 7.1.2 (audit log on verify),
      9.2.1 (path traversal guard), ASVS 11.4 (no absolute FS path in response)
CWE-200: backup_path in response is relative only (never absolute fs path)
API-SP-3: never expose internal directory structure via error messages

Last updated: 2026-05-06
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession, require_admin_session

router = APIRouter(prefix="/admin/backup", tags=["backup"])
_log = logging.getLogger("yashigani.backup")

# Configurable via env; default is the container-side mount point.
_BACKUPS_DIR = Path(os.getenv("YASHIGANI_BACKUPS_DIR", "/data/backups"))

_MANIFEST_FILE = "MANIFEST.sha256"
_MANIFEST_SIG_FILE = "MANIFEST.sha256.sig"

# CWE-200 sentinel: always return this string, never str(_BACKUPS_DIR).
_BACKUPS_DIR_RELATIVE = "backups"

# Path traversal guard: must start with alphanumeric (prevents "." and ".." names).
# Subsequent chars may include underscores, hyphens, and dots.
_BACKUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-\.]*$")


def _manifest_state(backup_dir: Path) -> str:
    """Return 'signed', 'unsigned', or 'corrupt' based on MANIFEST file presence."""
    has_manifest = (backup_dir / _MANIFEST_FILE).exists()
    has_sig = (backup_dir / _MANIFEST_SIG_FILE).exists()
    if has_manifest and has_sig:
        return "signed"
    if not has_manifest and not has_sig:
        return "unsigned"
    # Exactly one present — corrupt (retro RETRO-R4-3 three-state model)
    return "corrupt"


def _backup_type(name: str) -> str:
    """Classify backup as 'install' or 'update_preflight' by dir name convention."""
    return "update_preflight" if name.startswith("pre-update-") else "install"


def _dir_size(path: Path) -> int:
    """Total bytes for all files in a directory (non-recursive for shallowness)."""
    total = 0
    try:
        for entry in path.iterdir():
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
            elif entry.is_dir():
                for sub in entry.rglob("*"):
                    if sub.is_file():
                        try:
                            total += sub.stat().st_size
                        except OSError:
                            pass
    except OSError:
        pass
    return total


def _dir_mtime_iso(path: Path) -> str | None:
    """Return ISO-8601 UTC mtime of a directory, or None on error."""
    try:
        ts = path.stat().st_mtime
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except OSError:
        return None


def _list_files(path: Path) -> list[str]:
    """Return relative filenames (not absolute paths) for all files in backup dir."""
    files = []
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    files.append(str(entry.relative_to(path)))
                except ValueError:
                    pass
    except OSError:
        pass
    return sorted(files)


def _compute_checksums(backup_dir: Path) -> dict[str, str]:
    """
    SHA-256 every file in backup_dir, return {relative_path: sha256hex}.
    Excludes MANIFEST.sha256 and MANIFEST.sha256.sig (they ARE the manifest).
    """
    results: dict[str, str] = {}
    exclude = {_MANIFEST_FILE, _MANIFEST_SIG_FILE}
    try:
        for entry in backup_dir.rglob("*"):
            if not entry.is_file():
                continue
            rel = str(entry.relative_to(backup_dir))
            if rel in exclude:
                continue
            try:
                h = hashlib.sha256()
                with open(entry, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                results[rel] = h.hexdigest()
            except OSError:
                pass
    except OSError:
        pass
    return results


def _parse_manifest(backup_dir: Path) -> dict[str, str]:
    """
    Parse MANIFEST.sha256 (sha256sum format: '<hash>  <relpath>' per line).
    Returns {relpath: sha256hex}. Skips blank lines and comments.
    """
    manifest_path = backup_dir / _MANIFEST_FILE
    result: dict[str, str] = {}
    try:
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("  ", 1)
            if len(parts) == 2:
                result[parts[1].strip()] = parts[0].strip()
    except (OSError, UnicodeDecodeError):
        pass
    return result


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class VerifyRequest(BaseModel):
    backup_name: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/status")
async def backup_status(session: AdminSession):
    """
    List all backups with MANIFEST integrity state.

    Returns empty state (backups=[], latest=null) if no backup directory exists
    or directory is empty — never 500.

    CWE-200: backups_dir is always "backups" (relative), never an absolute path.
    """
    if not _BACKUPS_DIR.exists() or not _BACKUPS_DIR.is_dir():
        return {
            "backups": [],
            "latest": None,
            "backups_dir": _BACKUPS_DIR_RELATIVE,
        }

    entries = []
    try:
        subdirs = sorted(
            [d for d in _BACKUPS_DIR.iterdir() if d.is_dir()],
            key=lambda d: d.name,
            reverse=True,  # newest first
        )
    except OSError:
        subdirs = []

    for d in subdirs:
        entry = {
            "name": d.name,
            "type": _backup_type(d.name),
            "created_at": _dir_mtime_iso(d),
            "manifest_state": _manifest_state(d),
            "size_bytes": _dir_size(d),
            "files": _list_files(d),
        }
        entries.append(entry)

    return {
        "backups": entries,
        "latest": entries[0] if entries else None,
        "backups_dir": _BACKUPS_DIR_RELATIVE,
    }


@router.post("/verify")
async def backup_verify(body: VerifyRequest, session: AdminSession):
    """
    Re-hash a named backup and compare against MANIFEST.sha256.

    Path traversal guard: backup_name must match [A-Za-z0-9_\\-.]+
    and resolved path must be a direct child of BACKUPS_DIR.

    MANIFEST states:
    - unsigned: ok=True, no comparison (warn: no integrity record)
    - signed:   ok=(mismatches == [])
    - corrupt:  ok=False, error=manifest_corrupt

    ASVS 7.1.2: audit log on every verify invocation.
    CWE-200: no absolute paths in response.
    """
    backup_name = body.backup_name

    # --- Path traversal guard (ASVS 9.2.1) ---
    if not _BACKUP_NAME_RE.fullmatch(backup_name):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_backup_name",
                    "message": "backup_name may only contain alphanumerics, underscores, hyphens, and dots"},
        )

    target = _BACKUPS_DIR / backup_name
    try:
        resolved = target.resolve()
        backups_resolved = _BACKUPS_DIR.resolve()
    except OSError as exc:
        raise HTTPException(status_code=500, detail={"error": "path_resolution_failed"}) from exc

    # Resolved path must be a DIRECT child of BACKUPS_DIR (no symlink escape)
    if resolved.parent != backups_resolved:
        raise HTTPException(
            status_code=422,
            detail={"error": "path_traversal_rejected"},
        )

    if not resolved.exists() or not resolved.is_dir():
        raise HTTPException(
            status_code=404,
            detail={"error": "backup_not_found"},
        )

    # --- Compute checksums ---
    computed = _compute_checksums(resolved)
    state = _manifest_state(resolved)
    verified_at = datetime.now(tz=timezone.utc).isoformat()

    if state == "corrupt":
        _log.warning(
            "Admin %s verified backup: %s — CORRUPT manifest (one of pair missing)",
            session.account_id, backup_name,
        )
        return {
            "ok": False,
            "backup_name": backup_name,
            "manifest_state": "corrupt",
            "computed_checksums": computed,
            "recorded_checksums": None,
            "mismatches": [],
            "verified_at": verified_at,
            "concurrent_write_risk": (
                "Backup directory is not write-locked during verification. "
                "If a backup is in progress, checksums may not match."
            ),
        }

    if state == "unsigned":
        _log.info(
            "Admin %s verified backup: %s ok=True manifest_state=unsigned (no integrity record)",
            session.account_id, backup_name,
        )
        return {
            "ok": True,
            "backup_name": backup_name,
            "manifest_state": "unsigned",
            "computed_checksums": computed,
            "recorded_checksums": None,
            "mismatches": [],
            "verified_at": verified_at,
            "concurrent_write_risk": (
                "Backup directory is not write-locked during verification. "
                "If a backup is in progress, checksums may not match."
            ),
        }

    # state == "signed" — parse and compare
    recorded = _parse_manifest(resolved)
    mismatches = []

    # Check every file we can read against the manifest
    for relpath, computed_hash in computed.items():
        recorded_hash = recorded.get(relpath)
        if recorded_hash is None:
            mismatches.append({"file": relpath, "recorded": None, "computed": computed_hash,
                                "issue": "file_not_in_manifest"})
        elif recorded_hash != computed_hash:
            mismatches.append({"file": relpath, "recorded": recorded_hash, "computed": computed_hash,
                                "issue": "checksum_mismatch"})

    # Also flag files in manifest that are missing on disk
    for relpath, recorded_hash in recorded.items():
        if relpath not in computed:
            mismatches.append({"file": relpath, "recorded": recorded_hash, "computed": None,
                                "issue": "file_missing_on_disk"})

    ok = len(mismatches) == 0
    _log.info(
        "Admin %s verified backup: %s ok=%s manifest_state=signed mismatches=%d",
        session.account_id, backup_name, ok, len(mismatches),
    )

    return {
        "ok": ok,
        "backup_name": backup_name,
        "manifest_state": "signed",
        "computed_checksums": computed,
        "recorded_checksums": recorded,
        "mismatches": mismatches,
        "verified_at": verified_at,
        "concurrent_write_risk": (
            "Backup directory is not write-locked during verification. "
            "If a backup is in progress, checksums may not match."
        ),
    }


@router.post("/create")
async def backup_create(session: StepUpAdminSession):
    """
    On-demand database backup — the "push-button" create action.

    Snapshots the Postgres state (the crown jewels: admin/user accounts, RBAC,
    agents, policies, budgets, audit) via pg_dump to a timestamped dir under the
    backups volume, with a MANIFEST.sha256 the verify endpoint understands.

    High-value mutation -> StepUpAdminSession. NOTE: this is a DB snapshot the
    admin can take any time; full-system backups (volumes, secrets) and RESTORE
    remain installer/recovery operations (install.sh), per the deploy-time model.
    """
    import shutil
    import subprocess

    dsn = os.getenv("YASHIGANI_DB_DSN_DIRECT") or os.getenv("YASHIGANI_DB_DSN")
    if not dsn:
        raise HTTPException(status_code=503, detail={"error": "db_dsn_unavailable"})
    if shutil.which("pg_dump") is None:
        raise HTTPException(status_code=503, detail={"error": "pg_dump_unavailable"})
    try:
        _BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise HTTPException(status_code=500, detail={"error": "backups_dir_unavailable"})

    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    name = f"ondemand_{ts}"
    dest = _BACKUPS_DIR / name
    try:
        dest.mkdir(exist_ok=False)
    except OSError as exc:
        _log.warning("backup create: cannot create dir %s: %s", name, type(exc).__name__)
        raise HTTPException(status_code=500, detail={"error": "backup_dir_not_writable"})

    dump_path = dest / "database.dump"
    try:
        result = subprocess.run(
            ["pg_dump", "--format=custom", "--no-owner", "--no-privileges",
             "--file", str(dump_path), dsn],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(status_code=504, detail={"error": "backup_timeout"})
    if result.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        # CWE-200: never echo pg_dump stderr — it can contain the DSN/host.
        _log.error("backup create: pg_dump failed rc=%s", result.returncode)
        raise HTTPException(status_code=500, detail={"error": "pg_dump_failed"})

    # MANIFEST.sha256 — same format the verify endpoint reads (unsigned record).
    try:
        h = hashlib.sha256()
        with open(dump_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        (dest / _MANIFEST_FILE).write_text(f"{h.hexdigest()}  database.dump\n")
        size = dump_path.stat().st_size
    except OSError:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(status_code=500, detail={"error": "manifest_write_failed"})

    _log.info("Admin %s created on-demand DB backup: %s (%d bytes)", session.account_id, name, size)
    return {
        "status": "ok",
        "backup_name": name,
        "type": "ondemand",
        "size_bytes": size,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "message": "Database snapshot created. Full-system restore is an installer/recovery operation.",
    }
