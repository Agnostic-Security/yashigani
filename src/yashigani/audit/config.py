"""
Yashigani Audit — Configuration loaded from environment variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditConfig:
    log_path: str
    max_file_size_mb: int
    retention_days: int
    # v2.25.2 — DB audit sink (PostgresSink) wiring.
    #   db_sink_enabled: when True, audit events are ALSO mirrored to the
    #     audit_events Postgres table via PostgresSink (fire-and-forget,
    #     never blocks or fails the request — the file sink remains the
    #     canonical durability anchor). Default ON per Tiago decision
    #     2026-06-04 (WIRE in 2.25.2), but safely disableable via
    #     YASHIGANI_AUDIT_DB_SINK=false for community / file-only deploys.
    db_sink_enabled: bool = True

    @classmethod
    def from_env(cls) -> "AuditConfig":
        return cls(
            log_path=os.environ.get(
                "YASHIGANI_AUDIT_LOG_PATH",
                "/var/log/yashigani/audit.log",
            ),
            max_file_size_mb=int(
                os.environ.get("YASHIGANI_AUDIT_MAX_FILE_SIZE_MB", "100")
            ),
            retention_days=int(
                os.environ.get("YASHIGANI_AUDIT_RETENTION_DAYS", "90")
            ),
            db_sink_enabled=os.environ.get(
                "YASHIGANI_AUDIT_DB_SINK", "true"
            ).strip().lower()
            not in ("false", "0", "no", "off"),
        )
