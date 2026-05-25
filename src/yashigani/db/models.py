"""
Table column definitions and typed row helpers.
Not an ORM. asyncpg returns asyncpg.Record objects; these dataclasses
provide typed wrappers for frequently accessed rows.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class TenantRow:
    id: uuid.UUID
    name: str
    is_active: bool
    created_at: datetime


@dataclass(frozen=True)
class AgentRegistryRow:
    id: uuid.UUID
    tenant_id: uuid.UUID
    agent_name: str
    upstream_url: str
    token_hash: str
    rate_limit_rps: int
    rate_limit_burst: int
    is_active: bool


@dataclass(frozen=True)
class InferenceEventRow:
    tenant_id: uuid.UUID
    session_id: str
    agent_id: str
    payload_hash: str
    payload_length: int
    response_length: Optional[int]
    classification_label: str
    classification_confidence: float
    backend_used: str
    latency_ms: int


@dataclass(frozen=True)
class AuditEventRow:
    tenant_id: uuid.UUID
    event_type: str
    request_id: Optional[uuid.UUID]
    session_id: Optional[str]
    agent_id: Optional[str]
    action: str
    reason: Optional[str]
    upstream_status: Optional[int]
    elapsed_ms: Optional[int]
    confidence_score: Optional[float]
    client_ip_hash: Optional[str]


# ---------------------------------------------------------------------------
# Query helpers — all use $N parameterization, no string interpolation
# ---------------------------------------------------------------------------

INSERT_INFERENCE_EVENT = """
INSERT INTO inference_events (
    tenant_id, session_id, agent_id, payload_hash, payload_length,
    response_length, payload_content, response_content,
    classification_label, classification_confidence,
    backend_used, latency_ms
) VALUES (
    $1, $2, $3, $4, $5, $6,
    pgp_sym_encrypt($7, current_setting('app.aes_key')),
    pgp_sym_encrypt($8, current_setting('app.aes_key')),
    $9, $10, $11, $12
)
"""

INSERT_AUDIT_EVENT = """
INSERT INTO audit_events (
    tenant_id, event_type, request_id, session_id, agent_id,
    action, reason, upstream_status, elapsed_ms,
    confidence_score, client_ip_hash,
    prev_hash, event_hash
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
"""

SELECT_AGENT_BY_TOKEN_HASH = """
SELECT id, tenant_id, agent_name, upstream_url, token_hash,
       rate_limit_rps, rate_limit_burst, is_active
FROM   agent_registry
WHERE  tenant_id = $1
AND    token_hash = $2
AND    is_active = true
"""

SELECT_TENANT_BY_ID = """
SELECT id, name, is_active, created_at
FROM   tenants
WHERE  id = $1
AND    is_active = true
"""

SELECT_JWT_CONFIG = """
SELECT jwks_url, issuer, audience, fail_closed, scope
FROM   jwt_config
WHERE  tenant_id = $1
ORDER BY scope DESC
LIMIT 1
"""

SELECT_PLATFORM_JWT_CONFIG = """
SELECT jwks_url, issuer, audience, fail_closed, scope
FROM   jwt_config
WHERE  tenant_id = '00000000-0000-0000-0000-000000000000'::uuid
AND    scope = 'platform'
LIMIT 1
"""

SELECT_CACHE_CONFIG = """
SELECT enabled, ttl_seconds, max_size_mb
FROM   cache_config
WHERE  tenant_id = $1
"""

SELECT_ANOMALY_THRESHOLDS = """
SELECT window_seconds, call_count_n, payload_threshold_bytes
FROM   anomaly_thresholds
WHERE  tenant_id = $1
"""

UPSERT_ANOMALY_THRESHOLDS = """
INSERT INTO anomaly_thresholds (tenant_id, window_seconds, call_count_n, payload_threshold_bytes)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id) DO UPDATE
SET window_seconds = EXCLUDED.window_seconds,
    call_count_n = EXCLUDED.call_count_n,
    payload_threshold_bytes = EXCLUDED.payload_threshold_bytes,
    updated_at = now()
"""
