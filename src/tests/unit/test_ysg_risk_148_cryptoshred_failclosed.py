"""
YSG-RISK-148 (Tier-0 SECURITY, GDPR) — crypto-shred fail-closed regression tests.

Prior behaviour: Shredder.seal() wrapped each per-field seal in try/except
that logged-and-continued, leaving the field CLEARTEXT in the event that was
then written to the immutable/append-only audit chain — while
erase_subject() unconditionally returned {"shredded": True}, a false
GDPR Art 17 erasure certificate for data that was never actually sealed
under key material it could destroy.

This test proves, at the AuditLogWriter.write() level (not just the
Shredder unit level covered in tests/invariants/test_crypto_shred.py):
  1. A seal() failure aborts the write — AuditWriteError is raised and
     NOTHING is appended to the audit volume file (no partial/cleartext
     record on disk).
  2. A normal (non-failing) seal still writes successfully and the sealed
     field on disk is ciphertext, never cleartext.

See also tests/invariants/test_crypto_shred.py for the Shredder-level
erase_subject() honesty tests.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from yashigani.audit.config import AuditConfig
from yashigani.audit.writer import AuditLogWriter, AuditWriteError
from yashigani.audit.schema import AuditEvent


@dataclasses.dataclass
class _PiiEvent(AuditEvent):
    admin_account: str = "alice@corp.com"


class _FailingShredder:
    """Stand-in for crypto_shred.Shredder whose seal() always raises,
    exactly as the real Shredder now does on a KMS/seal error
    (YSG-RISK-148 fix)."""

    def seal(self, event, tenant_id=None):
        raise RuntimeError("KMS unavailable — simulated seal failure")


class _WorkingShredder:
    """Stand-in that 'seals' by uppercasing the field — enough to prove the
    on-disk record carries the sealed value, not the raw plaintext."""

    def seal(self, event, tenant_id=None):
        object.__setattr__(event, "admin_account", "SEALED:" + event.admin_account)
        return event


def _make_writer(tmp_path: Path) -> AuditLogWriter:
    config = AuditConfig(
        log_path=str(tmp_path / "audit.log"),
        max_file_size_mb=100,
        retention_days=90,
    )
    return AuditLogWriter(config=config)


def test_seal_failure_aborts_write_no_cleartext_on_disk(tmp_path):
    """A seal() failure must raise AuditWriteError and leave the audit
    volume file untouched — no cleartext PII record must land on disk."""
    writer = _make_writer(tmp_path)
    writer.attach_crypto_shred(_FailingShredder())

    event = _PiiEvent(
        event_type="ADMIN_LOGIN",
        account_tier="admin",
        admin_account="alice@corp.com",
    )
    with pytest.raises(AuditWriteError):
        writer.write(event)
    writer.close()

    log_file = tmp_path / "audit.log"
    if log_file.exists():
        content = log_file.read_text(encoding="utf-8")
        assert content.strip() == "", (
            "seal() failure must not result in ANY record (cleartext or "
            "otherwise) being appended to the audit chain"
        )
        assert "alice@corp.com" not in content, (
            "cleartext PII must never reach the audit volume file"
        )


def test_seal_success_writes_sealed_value_not_cleartext(tmp_path):
    """Sanity counterpart: a successful seal still writes, and what lands on
    disk is the sealed value, never the raw plaintext untouched."""
    writer = _make_writer(tmp_path)
    writer.attach_crypto_shred(_WorkingShredder())

    event = _PiiEvent(
        event_type="ADMIN_LOGIN",
        account_tier="admin",
        admin_account="alice@corp.com",
    )
    writer.write(event)
    writer.close()

    log_file = tmp_path / "audit.log"
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["admin_account"] == "SEALED:alice@corp.com"


def test_no_shredder_attached_writes_normally(tmp_path):
    """Regression guard: when no shredder is attached (self._shredder is
    None), write() must behave exactly as before — this fix must not
    require crypto-shred to be wired to write audit events at all."""
    writer = _make_writer(tmp_path)
    event = _PiiEvent(
        event_type="ADMIN_LOGIN",
        account_tier="admin",
        admin_account="alice@corp.com",
    )
    writer.write(event)
    writer.close()
    log_file = tmp_path / "audit.log"
    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
