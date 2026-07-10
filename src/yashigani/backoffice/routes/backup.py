"""
Yashigani Backoffice — Backup status + integrity verification + on-demand creation.

GET  /admin/backup/status   — list all backups with MANIFEST state
POST /admin/backup/verify   — re-hash a named backup, compare checksums
POST /admin/backup/create   — on-demand DB snapshot (signed + encrypted, B12)

ASVS: 4.3.1 (body limit enforced in app.py), 7.1.2 (audit log on verify),
      9.2.1 (path traversal guard), ASVS 11.4 (no absolute FS path in response)
CWE-200: backup_path in response is relative only (never absolute fs path)
API-SP-3: never expose internal directory structure via error messages

B12 (security): on-demand backups are now encrypted (AES-256-GCM, DEK wrapped
under YASHIGANI_DB_AES_KEY via HKDF-SHA384) and signed (HMAC-SHA384 over the
MANIFEST). Closes CWE-311 (plaintext backup) + CWE-345 (integrity bypass).

Last updated: 2026-06-12 (B12 — encryption + signing on-demand backup)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from yashigani.backoffice.middleware import AdminSession, StepUpAdminSession

router = APIRouter(prefix="/admin/backup", tags=["backup"])
_log = logging.getLogger("yashigani.backup")

# Configurable via env; default is the container-side mount point.
_BACKUPS_DIR = Path(os.getenv("YASHIGANI_BACKUPS_DIR", "/data/backups"))

_MANIFEST_FILE = "MANIFEST.sha256"
_MANIFEST_SIG_FILE = "MANIFEST.sha256.sig"
_BUNDLE_FILE = "bundle.enc"
_META_FILE = "backup-meta.json"

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
# B12: Encryption + signing helpers
# ---------------------------------------------------------------------------
# Key hierarchy for on-demand backups (CWE-311 / CWE-345 closure):
#
#   IKM      = YASHIGANI_DB_AES_KEY bytes (32 B, per-install CSPRNG key)
#   kek_salt = os.urandom(32)
#   KEK      = HKDF-SHA384(IKM, salt=kek_salt,
#                           info=b"yashigani-ondemand-backup-kek-v1", len=32)
#   DEK      = os.urandom(32)
#   MAC_KEY  = HKDF-SHA384(DEK, salt=b"", info=b"yashigani-backup-meta-mac-v1", len=48)
#   WDEK     = AES-256-GCM(KEK, kek_iv, aad=b"ondemand-v1", pt=DEK)
#   bundle   = AES-256-GCM(DEK, bundle_iv, aad=meta_aad_bytes, pt=dump_bytes)
#   hmac_hex = HMAC-SHA384(MAC_KEY, meta_aad_bytes)
#   MANIFEST = SHA-256 of bundle.enc
#   MANIFEST.sig = HMAC-SHA384(MAC_KEY, manifest_bytes) — establishes "signed" state
#
# Restoration: decrypt WDEK with KEK (re-derived from IKM+kek_salt), then decrypt
# bundle with DEK. All parameters are stored in backup-meta.json (non-secret).
# The IKM (YASHIGANI_DB_AES_KEY) must be preserved; losing it makes the backup
# unrecoverable (same constraint as the install.sh dual-wrap wrap#2 / community path).
#
# All crypto runs in-process (cryptography + argon2-cffi are backoffice deps).
# SHA-384 everywhere; no new SHA-256 in crypto primitives (CNSA-2.0 symmetric suite).

def _get_db_aes_key() -> bytes:
    """
    Read YASHIGANI_DB_AES_KEY from env, validate, return raw 32 bytes.
    Raises ValueError if missing or malformed (64-char hex required).
    CWE-321: key comes from install-time CSPRNG generation, never a static default.
    """
    raw = os.environ.get("YASHIGANI_DB_AES_KEY", "")
    if not raw or len(raw) != 64:
        raise ValueError(
            "YASHIGANI_DB_AES_KEY must be a 64-character hex string (32 bytes). "
            "Run install.sh to generate it."
        )
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("YASHIGANI_DB_AES_KEY is not valid hex.") from exc


def _hkdf_sha384(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA384 key derivation."""
    from cryptography.hazmat.primitives.hashes import SHA384
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=SHA384(),
        length=length,
        salt=salt if salt else None,
        info=info,
    ).derive(ikm)


def _aes_gcm_encrypt(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns ciphertext+tag (16-byte tag appended by AESGCM)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).encrypt(iv, plaintext, aad)


def _encrypt_and_sign_backup(dest: Path, dump_path: Path) -> dict:
    """
    B12: Encrypt database.dump with AES-256-GCM and sign the MANIFEST with
    HMAC-SHA384 so every on-demand backup is both confidential and tamper-evident.

    Writes into dest/:
      bundle.enc        — AES-256-GCM encrypted dump
      backup-meta.json  — key derivation params + wrapped DEK (non-secret params only)
      MANIFEST.sha256   — SHA-256 of bundle.enc
      MANIFEST.sha256.sig — HMAC-SHA384(MAC_KEY, manifest_bytes) — establishes "signed" state

    Returns dict with metadata suitable for including in the API response.

    Fail-closed: raises on any crypto error; partial files are cleaned up by the
    caller's existing shutil.rmtree(dest) error path.
    """
    ikm = _get_db_aes_key()

    # Key derivation salts + IVs — all CSPRNG
    kek_salt   = os.urandom(32)
    kek_iv     = os.urandom(12)
    bundle_iv  = os.urandom(12)

    # Derive KEK from per-install key
    kek = _hkdf_sha384(
        ikm=ikm,
        salt=kek_salt,
        info=b"yashigani-ondemand-backup-kek-v1",
        length=32,
    )

    # Generate per-backup DEK and MAC_KEY
    dek = os.urandom(32)
    mac_key = _hkdf_sha384(
        ikm=dek,
        salt=b"",
        info=b"yashigani-backup-meta-mac-v1",
        length=48,
    )

    # Wrap DEK under KEK (AES-256-GCM, aad="ondemand-v1")
    wdek_aad = b"ondemand-v1"
    wdek_ct  = _aes_gcm_encrypt(kek, kek_iv, wdek_aad, dek)

    # Build AAD for bundle encryption: deterministic bytes from meta fields.
    # Does NOT include hmac_hex (that is computed over this same bytes blob).
    aad_obj = {
        "version": "ondemand-v1",
        "kek_salt_hex": kek_salt.hex(),
        "kek_iv_hex": kek_iv.hex(),
        "bundle_iv_hex": bundle_iv.hex(),
        "wdek_hex": wdek_ct.hex(),
    }
    aad_bytes = json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode()

    # Encrypt the dump
    dump_bytes = dump_path.read_bytes()
    bundle_ct  = _aes_gcm_encrypt(dek, bundle_iv, aad_bytes, dump_bytes)

    # Write bundle.enc atomically (tmp → rename)
    bundle_tmp  = dest / f"bundle.enc.tmp.{os.getpid()}"
    bundle_path = dest / _BUNDLE_FILE
    bundle_tmp.write_bytes(bundle_ct)
    bundle_tmp.rename(bundle_path)
    bundle_path.chmod(0o600)

    # HMAC over aad_bytes (integrity cover for meta fields)
    hmac_hex = _hmac_mod.new(mac_key, aad_bytes, "sha384").hexdigest()

    # Write backup-meta.json (non-secret: salts, IVs, wrapped DEK, hmac)
    meta = {**aad_obj, "hmac_hex": hmac_hex}
    meta_path = dest / _META_FILE
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    meta_path.chmod(0o600)

    # Remove the plaintext dump — no plaintext survives in the backup dir
    dump_path.unlink()

    # MANIFEST.sha256: hash of bundle.enc + backup-meta.json (FIND-3.0-002).
    # Including backup-meta.json gives it integrity protection: the verify
    # endpoint will detect any tampering with the key-derivation parameters.
    h_bundle = hashlib.sha256()
    with open(bundle_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h_bundle.update(chunk)

    h_meta = hashlib.sha256()
    with open(meta_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h_meta.update(chunk)

    manifest_text = (
        f"{h_bundle.hexdigest()}  {_BUNDLE_FILE}\n"
        f"{h_meta.hexdigest()}  {_META_FILE}\n"
    )
    manifest_path = dest / _MANIFEST_FILE
    manifest_path.write_text(manifest_text, encoding="utf-8")
    manifest_path.chmod(0o400)

    # MANIFEST.sha256.sig: HMAC-SHA384(MAC_KEY, manifest_bytes)
    # This establishes _manifest_state() == "signed" (both files present).
    sig_hex = _hmac_mod.new(mac_key, manifest_text.encode(), "sha384").hexdigest()
    sig_path = dest / _MANIFEST_SIG_FILE
    sig_path.write_bytes(sig_hex.encode())
    sig_path.chmod(0o400)

    return {
        "encrypted": True,
        "signed": True,
        "bundle_bytes": bundle_path.stat().st_size,
    }


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

    # YSG-BUG-2255-001: pg_dump must run with full read privileges over every
    # object (incl. sequences like manifest_registrations_id_seq).  The app role
    # (DSN_DIRECT / DSN) is least-privilege post the 2.25.2 role split and trips
    # "permission denied for sequence ..." → pg_dump rc=1 → pg_dump_failed.  Use
    # the admin-direct DSN (yashigani_admin) for backups; fall back for older
    # installs that only wire the app DSN.
    dsn = (
        os.getenv("YASHIGANI_DB_DSN_ADMIN_DIRECT")
        or os.getenv("YASHIGANI_DB_DSN_DIRECT")
        or os.getenv("YASHIGANI_DB_DSN")
    )
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

    # B12: validate that the per-install encryption key is available before
    # running pg_dump — fail fast rather than producing a plaintext backup.
    try:
        _get_db_aes_key()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail={"error": "backup_key_unavailable",
                                                      "message": str(exc)})

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

    # B12: encrypt + sign — no plaintext dump survives in the backup dir.
    # _encrypt_and_sign_backup deletes database.dump after successful encryption.
    try:
        crypto_meta = _encrypt_and_sign_backup(dest, dump_path)
        size = crypto_meta["bundle_bytes"]
    except Exception as exc:  # pylint: disable=broad-except
        shutil.rmtree(dest, ignore_errors=True)
        _log.error("backup create: encryption/signing failed: %s", type(exc).__name__)
        raise HTTPException(status_code=500, detail={"error": "backup_crypto_failed"})

    _log.info(
        "Admin %s created on-demand DB backup: %s (%d bytes, encrypted=True, signed=True)",
        session.account_id, name, size,
    )
    return {
        "status": "ok",
        "backup_name": name,
        "type": "ondemand",
        "size_bytes": size,
        "encrypted": True,
        "signed": True,
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
        "message": (
            "Database snapshot created (encrypted + signed). "
            "Recovery requires YASHIGANI_DB_AES_KEY from your .env. "
            "Full-system restore is an installer/recovery operation."
        ),
    }
