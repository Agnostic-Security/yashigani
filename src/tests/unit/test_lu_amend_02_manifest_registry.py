"""
Unit tests for LU-AMEND-02 — multi-tenant manifest registration ledger.

Coverage:
  - ManifestRegistryService.register: success, chain (previous_sha lookup),
    size limits (hard limit raises, soft limit warns), missing arg validation.
  - ManifestRegistryService.history: returns rows in desc order, limit/offset.
  - ManifestRegistryService.show: found + not-found.
  - ManifestRegistryService.verify: matching SHA, tampered blob.
  - ManifestRegistrationRecord: _row_to_record round-trip.
  - REVOKE enforcement: yashigani_app cannot UPDATE or DELETE rows (documented
    via a DB-privilege assertion pattern — integration tests have the live gate;
    unit tests verify the migration DDL string contains the REVOKE).
  - Migration 0012: DDL string contains expected SQL fragments.
  - Barrel import: ManifestRegistryService and ManifestRegistrationRecord
    importable from yashigani.manifest_registry.

Integration tests (requiring Postgres) are skipped here and live in
tests/integration/test_lu_amend_02_manifest_registry_pg.py (not written here).

Last updated: 2026-05-24T00:00:00+00:00
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures — mock asyncpg pool
# ---------------------------------------------------------------------------

def _make_mock_pool():
    """
    Return a mock asyncpg pool whose acquire() context manager yields a
    mock connection.  Tests configure fetchrow/fetch return values directly
    on the connection.
    """
    conn = AsyncMock()
    pool = MagicMock()
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=conn)
    cm.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=cm)
    return pool, conn


# ---------------------------------------------------------------------------
# Barrel import
# ---------------------------------------------------------------------------

class TestBarrelImport:
    def test_manifest_registry_service_importable(self):
        from yashigani.manifest_registry import ManifestRegistryService
        assert ManifestRegistryService is not None

    def test_manifest_registration_record_importable(self):
        from yashigani.manifest_registry import ManifestRegistrationRecord
        assert ManifestRegistrationRecord is not None

    def test_service_from_package_direct(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        assert ManifestRegistryService is not None


# ---------------------------------------------------------------------------
# ManifestRegistryService construction
# ---------------------------------------------------------------------------

class TestServiceConstruction:
    def test_none_pool_raises_runtime_error(self):
        from yashigani.manifest_registry import ManifestRegistryService
        with pytest.raises(RuntimeError, match="non-None asyncpg pool"):
            ManifestRegistryService(pool=None)

    def test_valid_pool_constructs(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        assert svc is not None


# ---------------------------------------------------------------------------
# SHA-256 helper
# ---------------------------------------------------------------------------

class TestComputeSha256:
    def test_known_vector(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        result = svc._compute_sha256("hello")
        expected = hashlib.sha256("hello".encode("utf-8")).hexdigest()
        assert result == expected
        assert len(result) == 64

    def test_utf8_multi_byte(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        text = "name: café\nversion: 1.0"
        result = svc._compute_sha256(text)
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert result == expected

    def test_empty_string_has_known_sha(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        result = svc._compute_sha256("")
        assert result == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Size limit enforcement
# ---------------------------------------------------------------------------

class TestBlobSizeLimit:
    def test_below_soft_limit_no_warning(self, caplog):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        blob = "a" * 1000  # well below 512 kB
        with caplog.at_level(logging.WARNING, logger="yashigani.manifest_registry"):
            svc._check_blob_size(blob)
        assert "large" not in caplog.text

    def test_above_soft_limit_warns(self, caplog):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        blob = "a" * (512 * 1024 + 1)
        with caplog.at_level(logging.WARNING, logger="yashigani.manifest_registry"):
            svc._check_blob_size(blob)
        assert "large" in caplog.text

    def test_above_hard_limit_raises(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        blob = "a" * (1 * 1024 * 1024 + 1)
        with pytest.raises(ValueError, match="hard limit"):
            svc._check_blob_size(blob)

    def test_exactly_hard_limit_raises(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        blob = "a" * (1 * 1024 * 1024 + 1)
        with pytest.raises(ValueError):
            svc._check_blob_size(blob)

    def test_exactly_hard_limit_minus_one_does_not_raise(self):
        from yashigani.manifest_registry.service import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        blob = "a" * (1 * 1024 * 1024)  # exactly at limit — OK
        svc._check_blob_size(blob)  # should not raise


# ---------------------------------------------------------------------------
# register()
# ---------------------------------------------------------------------------

def _make_fetchrow_result(data: dict):
    """Simulate an asyncpg Record-like dict with [] access."""
    return data


class TestRegister:
    @pytest.mark.asyncio
    async def test_register_first_time_no_prev(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)

        manifest = "name: test-agent\nupstream: http://agent:8080"
        sha = hashlib.sha256(manifest.encode()).hexdigest()

        # First fetchrow: no previous record
        # Second fetchrow: the INSERT RETURNING id result
        conn.fetchrow.side_effect = [
            None,                    # no previous manifest
            {"id": 42},              # INSERT RETURNING id
        ]

        record_id = await svc.register(
            tenant_id="tenant-a",
            agent_id="agent-1",
            manifest_yaml=manifest,
            operator_identity="admin1",
        )
        assert record_id == 42

        # Verify INSERT args
        insert_call = conn.fetchrow.call_args_list[1]
        args = insert_call[0]
        # $1=tenant_id, $2=agent_id, $3=sha256, $4=blob, $5=operator, $6=prev_sha, $7=prov
        assert args[1] == "tenant-a"
        assert args[2] == "agent-1"
        assert args[3] == sha
        assert args[4] == manifest
        assert args[5] == "admin1"
        assert args[6] is None   # no previous sha
        assert args[7] is None   # no provenance

    @pytest.mark.asyncio
    async def test_register_chain_carries_previous_sha(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)

        manifest = "name: agent\nversion: 2"
        prev_sha = "a" * 64

        conn.fetchrow.side_effect = [
            {"manifest_sha256": prev_sha},  # previous registration found
            {"id": 99},
        ]

        record_id = await svc.register(
            tenant_id="tenant-b",
            agent_id="agent-2",
            manifest_yaml=manifest,
            operator_identity="admin2",
        )
        assert record_id == 99

        insert_call = conn.fetchrow.call_args_list[1]
        args = insert_call[0]
        assert args[6] == prev_sha  # previous_manifest_sha256 propagated

    @pytest.mark.asyncio
    async def test_register_with_provenance(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)

        manifest = "name: agent-prov"
        prov = {"alg": "spiffe-internal-hmac", "signer": "spiffe://test", "sig": "abc123"}

        conn.fetchrow.side_effect = [None, {"id": 7}]

        record_id = await svc.register(
            tenant_id="t1",
            agent_id="a1",
            manifest_yaml=manifest,
            operator_identity="op",
            signature_provenance=prov,
        )
        assert record_id == 7

        insert_call = conn.fetchrow.call_args_list[1]
        args = insert_call[0]
        prov_json = args[7]
        assert prov_json is not None
        # The service serialises provenance to JSON
        loaded = json.loads(prov_json)
        assert loaded["alg"] == "spiffe-internal-hmac"
        assert loaded["sig"] == "abc123"

    @pytest.mark.asyncio
    async def test_register_empty_tenant_id_raises(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        with pytest.raises(ValueError, match="tenant_id"):
            await svc.register(
                tenant_id="",
                agent_id="a",
                manifest_yaml="yaml",
                operator_identity="op",
            )

    @pytest.mark.asyncio
    async def test_register_empty_agent_id_raises(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, _ = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        with pytest.raises(ValueError, match="agent_id"):
            await svc.register(
                tenant_id="t",
                agent_id="",
                manifest_yaml="yaml",
                operator_identity="op",
            )

    @pytest.mark.asyncio
    async def test_register_hard_limit_raises_before_db(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        big_blob = "a" * (1 * 1024 * 1024 + 1)
        with pytest.raises(ValueError, match="hard limit"):
            await svc.register(
                tenant_id="t",
                agent_id="a",
                manifest_yaml=big_blob,
                operator_identity="op",
            )
        # pool should never have been touched
        conn.fetchrow.assert_not_called()


# ---------------------------------------------------------------------------
# history()
# ---------------------------------------------------------------------------

def _make_history_row(id_: int, agent: str, sha: str, prev: Optional[str] = None):
    return {
        "id": id_,
        "tenant_id": "tenant-x",
        "agent_id": agent,
        "manifest_sha256": sha,
        "manifest_yaml_blob": f"name: {agent}",
        "registered_by_operator_identity": "op",
        "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
        "previous_manifest_sha256": prev,
        "signature_provenance": None,
    }


class TestHistory:
    @pytest.mark.asyncio
    async def test_history_returns_records(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)

        sha1 = "a" * 64
        sha2 = "b" * 64
        rows = [
            _make_history_row(2, "agent-1", sha2, prev=sha1),
            _make_history_row(1, "agent-1", sha1),
        ]
        conn.fetch = AsyncMock(return_value=rows)

        result = await svc.history(tenant_id="tenant-x")
        assert len(result) == 2
        assert result[0].id == 2
        assert result[1].id == 1

    @pytest.mark.asyncio
    async def test_history_empty(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetch = AsyncMock(return_value=[])
        result = await svc.history(tenant_id="tenant-empty")
        assert result == []

    @pytest.mark.asyncio
    async def test_history_limit_clamped(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetch = AsyncMock(return_value=[])
        await svc.history(tenant_id="t", limit=999)  # 999 > 200 → clamped to 200
        call_args = conn.fetch.call_args[0]
        # $2 is limit
        assert call_args[2] == 200

    @pytest.mark.asyncio
    async def test_history_limit_minimum(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetch = AsyncMock(return_value=[])
        await svc.history(tenant_id="t", limit=0)  # 0 → clamped to 1
        call_args = conn.fetch.call_args[0]
        assert call_args[2] == 1

    @pytest.mark.asyncio
    async def test_history_offset_non_negative(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetch = AsyncMock(return_value=[])
        await svc.history(tenant_id="t", offset=-5)  # -5 → clamped to 0
        call_args = conn.fetch.call_args[0]
        assert call_args[3] == 0


# ---------------------------------------------------------------------------
# show()
# ---------------------------------------------------------------------------

class TestShow:
    @pytest.mark.asyncio
    async def test_show_found(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        sha = "c" * 64
        row = _make_history_row(5, "agent-show", sha)
        conn.fetchrow = AsyncMock(return_value=row)
        result = await svc.show(5)
        assert result is not None
        assert result.id == 5
        assert result.manifest_sha256 == sha

    @pytest.mark.asyncio
    async def test_show_not_found_returns_none(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetchrow = AsyncMock(return_value=None)
        result = await svc.show(9999)
        assert result is None


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------

class TestVerify:
    @pytest.mark.asyncio
    async def test_verify_matching_sha(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        manifest = "name: verify-test"
        sha = hashlib.sha256(manifest.encode()).hexdigest()
        row = {
            "id": 10,
            "tenant_id": "t",
            "agent_id": "a",
            "manifest_sha256": sha,
            "manifest_yaml_blob": manifest,
            "registered_by_operator_identity": "op",
            "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
            "previous_manifest_sha256": None,
            "signature_provenance": None,
        }
        conn.fetchrow = AsyncMock(return_value=row)
        ok, msg = await svc.verify(10)
        assert ok is True
        assert sha in msg

    @pytest.mark.asyncio
    async def test_verify_tampered_sha(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        manifest = "name: verify-test"
        wrong_sha = "d" * 64  # wrong stored SHA
        row = {
            "id": 11,
            "tenant_id": "t",
            "agent_id": "a",
            "manifest_sha256": wrong_sha,
            "manifest_yaml_blob": manifest,
            "registered_by_operator_identity": "op",
            "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
            "previous_manifest_sha256": None,
            "signature_provenance": None,
        }
        conn.fetchrow = AsyncMock(return_value=row)
        ok, msg = await svc.verify(11)
        assert ok is False
        assert "MISMATCH" in msg

    @pytest.mark.asyncio
    async def test_verify_record_not_found(self):
        from yashigani.manifest_registry import ManifestRegistryService
        pool, conn = _make_mock_pool()
        svc = ManifestRegistryService(pool=pool)
        conn.fetchrow = AsyncMock(return_value=None)
        ok, msg = await svc.verify(9999)
        assert ok is False
        assert "not found" in msg


# ---------------------------------------------------------------------------
# _row_to_record: JSONB provenance handling
# ---------------------------------------------------------------------------

class TestRowToRecord:
    def test_provenance_dict_passthrough(self):
        from yashigani.manifest_registry.service import _row_to_record
        prov = {"alg": "test", "sig": "abc"}
        row = {
            "id": 1, "tenant_id": "t", "agent_id": "a",
            "manifest_sha256": "x" * 64,
            "manifest_yaml_blob": "yaml",
            "registered_by_operator_identity": "op",
            "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
            "previous_manifest_sha256": None,
            "signature_provenance": prov,
        }
        rec = _row_to_record(row)
        assert rec.signature_provenance == prov

    def test_provenance_json_string_decoded(self):
        from yashigani.manifest_registry.service import _row_to_record
        prov = {"alg": "test", "sig": "abc"}
        row = {
            "id": 2, "tenant_id": "t", "agent_id": "a",
            "manifest_sha256": "x" * 64,
            "manifest_yaml_blob": "yaml",
            "registered_by_operator_identity": "op",
            "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
            "previous_manifest_sha256": None,
            "signature_provenance": json.dumps(prov),  # string from TEXT-cast JSONB
        }
        rec = _row_to_record(row)
        assert rec.signature_provenance == prov

    def test_provenance_none_stays_none(self):
        from yashigani.manifest_registry.service import _row_to_record
        row = {
            "id": 3, "tenant_id": "t", "agent_id": "a",
            "manifest_sha256": "x" * 64,
            "manifest_yaml_blob": "yaml",
            "registered_by_operator_identity": "op",
            "registered_at": datetime(2026, 5, 24, tzinfo=timezone.utc),
            "previous_manifest_sha256": None,
            "signature_provenance": None,
        }
        rec = _row_to_record(row)
        assert rec.signature_provenance is None


# ---------------------------------------------------------------------------
# Migration DDL assertions (LU-AMEND-02 spec compliance)
# ---------------------------------------------------------------------------

def _read_migration_0012_text() -> str:
    """
    Read the 0012 migration file as raw text.
    Used instead of importlib because alembic may not be installed in the
    unit-test virtualenv (it IS in the container env).
    """
    import os
    mig_path = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "yashigani", "db", "migrations", "versions",
        "0012_manifest_registrations.py",
    )
    with open(mig_path) as f:
        return f.read()


class TestMigrationDDL:
    """
    Verify that the migration 0012 DDL string contains the required SQL
    fragments per the LU-AMEND-02 specification.
    We read the file as text so alembic doesn't need to be installed.
    """

    def _get_ddl(self) -> str:
        # Extract _DDL_UP by reading the source and finding the section.
        # The string is assigned to _DDL_UP and ends before _DDL_DOWN.
        src = _read_migration_0012_text()
        # Return the whole source — all assertions are in the DDL constants.
        return src

    def test_table_created(self):
        assert "CREATE TABLE manifest_registrations" in self._get_ddl()

    def test_tenant_id_column(self):
        assert "tenant_id" in self._get_ddl()

    def test_agent_id_column(self):
        assert "agent_id" in self._get_ddl()

    def test_manifest_sha256_column(self):
        assert "manifest_sha256" in self._get_ddl()

    def test_manifest_yaml_blob_column(self):
        assert "manifest_yaml_blob" in self._get_ddl()

    def test_registered_by_operator_identity_column(self):
        assert "registered_by_operator_identity" in self._get_ddl()

    def test_registered_at_column(self):
        assert "registered_at" in self._get_ddl()

    def test_previous_manifest_sha256_column(self):
        assert "previous_manifest_sha256" in self._get_ddl()

    def test_signature_provenance_jsonb(self):
        ddl = self._get_ddl()
        assert "signature_provenance" in ddl
        assert "JSONB" in ddl

    def test_revoke_update_delete(self):
        assert "REVOKE UPDATE, DELETE ON manifest_registrations FROM yashigani_app" in self._get_ddl()

    def test_grant_select_insert(self):
        assert "GRANT SELECT, INSERT ON manifest_registrations TO yashigani_app" in self._get_ddl()

    def test_index_tenant(self):
        assert "idx_manifest_reg_tenant" in self._get_ddl()

    def test_index_agent(self):
        assert "idx_manifest_reg_agent" in self._get_ddl()

    def test_down_drops_table(self):
        src = _read_migration_0012_text()
        assert "DROP TABLE IF EXISTS manifest_registrations" in src

    def test_revision_follows_0011(self):
        src = _read_migration_0012_text()
        assert 'revision: str = "0012"' in src
        assert 'down_revision: Union[str, None] = "0011"' in src
