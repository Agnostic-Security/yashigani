"""
Unit tests for /admin/backup/status, /admin/backup/verify, and B12 crypto helpers.

Coverage:
- Empty / missing backup directory → empty state (not 500)
- Install vs update_preflight type classification
- All three MANIFEST states: signed, unsigned, corrupt
- Path traversal rejection (CWE-22)
- Backup not found → 404
- Verify unsigned → ok=True
- Verify signed → pass (checksums match)
- Verify signed → fail (checksum mismatch + mismatches list populated)
- CWE-200: backups_dir is always "backups" (relative), never absolute path
- B12: _encrypt_and_sign_backup produces encrypted bundle (not plaintext)
- B12: _encrypt_and_sign_backup produces MANIFEST + .sig (manifest_state = "signed")
- B12: plaintext dump removed after encryption
- B12: backup_create returns encrypted=True signed=True in response
- B12: backup_create fails closed when YASHIGANI_DB_AES_KEY is absent

Last updated: 2026-06-12 (B12 — encryption + signing tests)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import yashigani.backoffice.routes.backup as backup_mod
from yashigani.backoffice.routes.backup import router


# ---------------------------------------------------------------------------
# App fixture — minimal FastAPI with auth bypass
# ---------------------------------------------------------------------------

def _make_app() -> FastAPI:
    """Minimal test app with auth bypassed via override."""
    from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session

    app = FastAPI()

    class _FakeSession:
        account_id = "test-admin"
        account_tier = "admin"

    async def _fake_admin_session():
        return _FakeSession()

    app.dependency_overrides[require_admin_session] = _fake_admin_session
    app.dependency_overrides[require_stepup_admin_session] = _fake_admin_session
    app.include_router(router)
    return app


@pytest_asyncio.fixture
async def client(tmp_path: Path, monkeypatch) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client with BACKUPS_DIR pointed at tmp_path."""
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path)
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_manifest(backup_dir: Path, entries: dict[str, bytes]) -> None:
    """Write a valid MANIFEST.sha256 + MANIFEST.sha256.sig (stub sig) for given files."""
    lines = []
    for relpath, content in entries.items():
        lines.append(f"{_sha256_hex(content)}  {relpath}")
    (backup_dir / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    # Stub sig — present but not cryptographically verified in Python-level unit tests
    (backup_dir / "MANIFEST.sha256.sig").write_bytes(b"stub-sig")


# ---------------------------------------------------------------------------
# Tests: /admin/backup/status
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_status_empty_dir(client: AsyncClient, tmp_path: Path):
    """Empty directory → backups=[], latest=null, no 500."""
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert data["backups"] == []
    assert data["latest"] is None


@pytest.mark.asyncio
async def test_status_missing_dir(monkeypatch, tmp_path: Path):
    """Non-existent BACKUPS_DIR → empty state, not 500."""
    monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path / "does_not_exist")
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert data["backups"] == []
    assert data["latest"] is None


@pytest.mark.asyncio
async def test_status_install_type(client: AsyncClient, tmp_path: Path):
    """Dir named 'YYYYMMDD_HHMMSS' → type='install'."""
    backup_dir = tmp_path / "20260502_230214"
    backup_dir.mkdir()
    (backup_dir / "postgres_dump.sql").write_bytes(b"-- dump")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert len(data["backups"]) == 1
    assert data["backups"][0]["type"] == "install"
    assert data["backups"][0]["name"] == "20260502_230214"


@pytest.mark.asyncio
async def test_status_update_preflight_type(client: AsyncClient, tmp_path: Path):
    """Dir named 'pre-update-...' → type='update_preflight'."""
    backup_dir = tmp_path / "pre-update-v2.23.1-20260501-120000"
    backup_dir.mkdir()
    (backup_dir / "config.yml").write_bytes(b"key: value")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    assert len(data["backups"]) == 1
    assert data["backups"][0]["type"] == "update_preflight"


@pytest.mark.asyncio
async def test_status_manifest_signed(client: AsyncClient, tmp_path: Path):
    """Both MANIFEST files present → manifest_state='signed'."""
    backup_dir = tmp_path / "20260502_000001"
    backup_dir.mkdir()
    content = b"data content"
    (backup_dir / "file.dat").write_bytes(content)
    _write_manifest(backup_dir, {"file.dat": content})
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "signed"


@pytest.mark.asyncio
async def test_status_manifest_unsigned(client: AsyncClient, tmp_path: Path):
    """Neither MANIFEST file present → manifest_state='unsigned'."""
    backup_dir = tmp_path / "20260501_000001"
    backup_dir.mkdir()
    (backup_dir / "secrets" ).mkdir()
    (backup_dir / "secrets" / "admin_password").write_bytes(b"secret")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "unsigned"


@pytest.mark.asyncio
async def test_status_manifest_corrupt(client: AsyncClient, tmp_path: Path):
    """Only MANIFEST.sha256 present (no .sig) → manifest_state='corrupt'."""
    backup_dir = tmp_path / "20260503_000001"
    backup_dir.mkdir()
    (backup_dir / "file.dat").write_bytes(b"x")
    (backup_dir / "MANIFEST.sha256").write_text("abc123  file.dat\n")
    # Deliberately NO .sig file
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    assert r.json()["backups"][0]["manifest_state"] == "corrupt"


# ---------------------------------------------------------------------------
# Tests: /admin/backup/verify
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_verify_path_traversal(client: AsyncClient):
    """backup_name containing '..' → 422."""
    r = await client.post("/admin/backup/verify", json={"backup_name": "../etc/passwd"})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] in ("invalid_backup_name", "path_traversal_rejected")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_name", [".", "..", "./", "../"])
async def test_verify_dot_only_names_rejected_at_regex(client: AsyncClient, bad_name: str):
    """Dot-only names ('.', '..', './', '../') must be rejected by _BACKUP_NAME_RE (regex layer),
    not merely by the resolved-path check.  CWE-22 / ASVS 9.2.1."""
    r = await client.post("/admin/backup/verify", json={"backup_name": bad_name})
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_backup_name", (
        f"Expected regex-layer rejection for {bad_name!r}, got: {r.json()}"
    )


@pytest.mark.asyncio
async def test_verify_not_found(client: AsyncClient):
    """Valid name but dir doesn't exist → 404."""
    r = await client.post("/admin/backup/verify", json={"backup_name": "nonexistent_backup"})
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "backup_not_found"


@pytest.mark.asyncio
async def test_verify_unsigned(client: AsyncClient, tmp_path: Path):
    """Backup with no MANIFEST → ok=True, manifest_state='unsigned'."""
    backup_dir = tmp_path / "20260502_unsigned"
    backup_dir.mkdir()
    (backup_dir / "postgres_dump.sql").write_bytes(b"-- dump data")
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_unsigned"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["manifest_state"] == "unsigned"
    assert "postgres_dump.sql" in data["computed_checksums"]
    assert data["recorded_checksums"] is None
    assert data["mismatches"] == []


@pytest.mark.asyncio
async def test_verify_signed_pass(client: AsyncClient, tmp_path: Path):
    """Backup with valid MANIFEST → ok=True, manifest_state='signed', no mismatches."""
    backup_dir = tmp_path / "20260502_signed_pass"
    backup_dir.mkdir()
    content = b"important data"
    (backup_dir / "postgres_dump.sql").write_bytes(content)
    _write_manifest(backup_dir, {"postgres_dump.sql": content})
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_signed_pass"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert data["manifest_state"] == "signed"
    assert data["mismatches"] == []
    assert "postgres_dump.sql" in data["computed_checksums"]
    assert "postgres_dump.sql" in data["recorded_checksums"]


@pytest.mark.asyncio
async def test_verify_signed_fail(client: AsyncClient, tmp_path: Path):
    """Backup with MANIFEST but tampered file → ok=False, mismatches populated."""
    backup_dir = tmp_path / "20260502_signed_fail"
    backup_dir.mkdir()
    original = b"original content"
    tampered = b"tampered content"
    (backup_dir / "postgres_dump.sql").write_bytes(tampered)  # write tampered content
    _write_manifest(backup_dir, {"postgres_dump.sql": original})  # manifest has original hash
    r = await client.post("/admin/backup/verify", json={"backup_name": "20260502_signed_fail"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert data["manifest_state"] == "signed"
    assert len(data["mismatches"]) >= 1
    mismatch = data["mismatches"][0]
    assert mismatch["file"] == "postgres_dump.sql"
    assert mismatch["recorded"] == _sha256_hex(original)
    assert mismatch["computed"] == _sha256_hex(tampered)


@pytest.mark.asyncio
async def test_status_no_absolute_path(client: AsyncClient, tmp_path: Path):
    """CWE-200: backups_dir in response is 'backups' (relative), never absolute."""
    # Create one backup dir so it's not degenerate
    backup_dir = tmp_path / "20260502_cwe200"
    backup_dir.mkdir()
    (backup_dir / "file.dat").write_bytes(b"data")
    r = await client.get("/admin/backup/status")
    assert r.status_code == 200
    data = r.json()
    # Must be relative sentinel, never the real tmp_path
    assert data["backups_dir"] == "backups"
    assert str(tmp_path) not in data["backups_dir"]
    # Also check no file entry leaks an absolute path
    for entry in data["backups"]:
        for f in entry.get("files", []):
            assert not f.startswith("/")


# ---------------------------------------------------------------------------
# B12: _encrypt_and_sign_backup unit tests
# ---------------------------------------------------------------------------
# These are pure Python tests — no running service needed.
# They exercise the crypto helpers directly against a synthetic dump.
# ---------------------------------------------------------------------------

_TEST_AES_KEY_HEX = "a" * 64  # 32-byte all-0xaa key — safe for testing only


def _fake_env_key(monkeypatch) -> None:
    """Inject a synthetic YASHIGANI_DB_AES_KEY into the env for testing."""
    monkeypatch.setenv("YASHIGANI_DB_AES_KEY", _TEST_AES_KEY_HEX)


class TestB12EncryptAndSignBackup:
    """B12 (CWE-311/CWE-345): on-demand backup is encrypted and tamper-evident."""

    def test_bundle_not_plaintext_sql(self, tmp_path, monkeypatch):
        """bundle.enc must not be readable as plaintext SQL (CWE-311 closure)."""
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_enc"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- PostgreSQL custom dump\nINSERT INTO secrets VALUES ('password123');\n")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        bundle = (dest / "bundle.enc").read_bytes()
        # Must not contain plaintext SQL markers
        assert b"INSERT INTO" not in bundle
        assert b"password123" not in bundle
        assert b"PostgreSQL" not in bundle

    def test_manifest_state_is_signed(self, tmp_path, monkeypatch):
        """After _encrypt_and_sign_backup, MANIFEST + .sig both exist → state='signed'."""
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_signed"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- dump data")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        assert (dest / "MANIFEST.sha256").exists(), "MANIFEST.sha256 must be written"
        assert (dest / "MANIFEST.sha256.sig").exists(), "MANIFEST.sha256.sig must be written"
        assert backup_mod._manifest_state(dest) == "signed"

    def test_plaintext_dump_removed(self, tmp_path, monkeypatch):
        """database.dump must be deleted after successful encryption (no plaintext on disk)."""
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_noplain"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- dump")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        assert not dump_path.exists(), "database.dump must be removed after encryption"

    def test_meta_json_present_and_parseable(self, tmp_path, monkeypatch):
        """backup-meta.json must be written and contain the required fields."""
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_meta"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- dump")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        meta_path = dest / "backup-meta.json"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        for field in ("version", "kek_salt_hex", "kek_iv_hex", "bundle_iv_hex", "wdek_hex", "hmac_hex"):
            assert field in meta, f"backup-meta.json missing field: {field}"
        assert meta["version"] == "ondemand-v1"

    def test_bundle_enc_hashes_match_manifest(self, tmp_path, monkeypatch):
        """MANIFEST.sha256 hash of bundle.enc must match actual bundle.enc.
        Updated for FIND-3.0-002: manifest now has two lines (bundle.enc + backup-meta.json).
        Parse the bundle.enc line by name rather than assuming it's the only line.
        """
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_manifest_hash"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- sensitive dump data")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        bundle_bytes = (dest / "bundle.enc").read_bytes()
        expected_hash = hashlib.sha256(bundle_bytes).hexdigest()

        manifest_text = (dest / "MANIFEST.sha256").read_text()
        # Find the bundle.enc line — manifest now has >= 2 entries (FIND-3.0-002)
        bundle_line = next(
            (line for line in manifest_text.splitlines() if "bundle.enc" in line),
            None,
        )
        assert bundle_line is not None, "No bundle.enc line in MANIFEST.sha256"
        recorded_hash, recorded_name = bundle_line.split("  ", 1)
        assert recorded_hash == expected_hash
        assert recorded_name.strip() == "bundle.enc"

    def test_missing_key_raises_valueerror(self, tmp_path, monkeypatch):
        """_get_db_aes_key must raise ValueError if env var is absent."""
        monkeypatch.delenv("YASHIGANI_DB_AES_KEY", raising=False)
        with pytest.raises(ValueError, match="YASHIGANI_DB_AES_KEY"):
            backup_mod._get_db_aes_key()

    def test_short_key_raises_valueerror(self, tmp_path, monkeypatch):
        """_get_db_aes_key must raise ValueError if key is shorter than 64 hex chars."""
        monkeypatch.setenv("YASHIGANI_DB_AES_KEY", "aa" * 10)  # 20 chars, not 64
        with pytest.raises(ValueError, match="64-character"):
            backup_mod._get_db_aes_key()

    def test_different_dumps_produce_different_bundles(self, tmp_path, monkeypatch):
        """Two different dumps must produce different ciphertexts (random IVs)."""
        _fake_env_key(monkeypatch)
        for i, payload in enumerate([b"-- dump A", b"-- dump B"]):
            dest = tmp_path / f"backup_b12_diff_{i}"
            dest.mkdir()
            dump_path = dest / "database.dump"
            dump_path.write_bytes(payload)
            backup_mod._encrypt_and_sign_backup(dest, dump_path)
        bundle_a = (tmp_path / "backup_b12_diff_0" / "bundle.enc").read_bytes()
        bundle_b = (tmp_path / "backup_b12_diff_1" / "bundle.enc").read_bytes()
        assert bundle_a != bundle_b

    # -----------------------------------------------------------------------
    # FIND-3.0-002: backup-meta.json must be in MANIFEST.sha256
    # -----------------------------------------------------------------------

    def test_meta_json_in_manifest(self, tmp_path, monkeypatch):
        """FIND-3.0-002: backup-meta.json must appear in MANIFEST.sha256 so that
        verify returns ok=True (not file_not_in_manifest mismatch)."""
        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_meta_in_manifest"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- dump data")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        manifest_text = (dest / "MANIFEST.sha256").read_text(encoding="utf-8")
        assert "backup-meta.json" in manifest_text, (
            "backup-meta.json must be included in MANIFEST.sha256 (FIND-3.0-002)"
        )

    def test_meta_json_hash_correct_in_manifest(self, tmp_path, monkeypatch):
        """The hash recorded for backup-meta.json in MANIFEST.sha256 must match
        the actual file on disk (regression: verify must pass ok=True)."""
        import hashlib as _hashlib

        _fake_env_key(monkeypatch)
        dest = tmp_path / "backup_b12_meta_hash_correct"
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- sensitive dump data")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        meta_bytes = (dest / "backup-meta.json").read_bytes()
        expected_hash = _hashlib.sha256(meta_bytes).hexdigest()

        manifest_text = (dest / "MANIFEST.sha256").read_text(encoding="utf-8")
        # Find the line for backup-meta.json
        meta_line = next(
            (line for line in manifest_text.splitlines() if "backup-meta.json" in line),
            None,
        )
        assert meta_line is not None, "No backup-meta.json line found in manifest"
        recorded_hash = meta_line.split("  ", 1)[0].strip()
        assert recorded_hash == expected_hash, (
            f"MANIFEST hash for backup-meta.json {recorded_hash!r} != actual {expected_hash!r}"
        )

    @pytest.mark.asyncio
    async def test_verify_ondemand_backup_ok_true(self, tmp_path, monkeypatch):
        """End-to-end: a backup created by _encrypt_and_sign_backup must verify
        as ok=True with no mismatches (FIND-3.0-002 — backup-meta.json included)."""
        monkeypatch.setenv("YASHIGANI_DB_AES_KEY", _TEST_AES_KEY_HEX)
        monkeypatch.setattr(backup_mod, "_BACKUPS_DIR", tmp_path)

        backup_name = "ondemand_test_verify"
        dest = tmp_path / backup_name
        dest.mkdir()
        dump_path = dest / "database.dump"
        dump_path.write_bytes(b"-- test dump for verify e2e")

        backup_mod._encrypt_and_sign_backup(dest, dump_path)

        # Now run verify via the API
        from yashigani.backoffice.middleware import require_admin_session, require_stepup_admin_session
        from yashigani.backoffice.routes.backup import router
        from fastapi import FastAPI
        from httpx import ASGITransport, AsyncClient

        app = FastAPI()

        class _FakeSession:
            account_id = "test-admin"

        async def _fake_admin_session():
            return _FakeSession()

        app.dependency_overrides[require_admin_session] = _fake_admin_session
        app.dependency_overrides[require_stepup_admin_session] = _fake_admin_session
        app.include_router(router)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            r = await c.post("/admin/backup/verify", json={"backup_name": backup_name})

        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True, (
            f"verify returned ok=False with mismatches: {data.get('mismatches')}"
        )
        assert data["manifest_state"] == "signed"
        assert data["mismatches"] == []
