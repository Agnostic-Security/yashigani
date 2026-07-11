"""Yashigani DB — typed model sub-package."""
from yashigani.db.models.webauthn_credential import WebAuthnCredentialRow
from yashigani.db.postgres import PGP_SYM_OPTS  # Issue #144: AES-256 cipher pin

# SQL query constants re-exported here so that
# `from yashigani.db.models import INSERT_INFERENCE_EVENT` etc. work
# regardless of whether models.py (shadowed by this package) is accessible.
# f-string embeds PGP_SYM_OPTS at module load time (Python constant, not user input).
INSERT_INFERENCE_EVENT = f"""
INSERT INTO inference_events (
    tenant_id, session_id, agent_id, payload_hash, payload_length,
    response_length, payload_content, response_content,
    classification_label, classification_confidence,
    backend_used, latency_ms
) VALUES (
    $1, $2, $3, $4, $5, $6,
    pgp_sym_encrypt($7, current_setting('app.aes_key'), '{PGP_SYM_OPTS}'),
    pgp_sym_encrypt($8, current_setting('app.aes_key'), '{PGP_SYM_OPTS}'),
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
RETURNING seq
"""

__all__ = ["WebAuthnCredentialRow", "INSERT_INFERENCE_EVENT", "INSERT_AUDIT_EVENT"]
