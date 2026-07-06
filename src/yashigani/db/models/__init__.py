"""Yashigani DB — typed model sub-package."""
from yashigani.db.models.webauthn_credential import WebAuthnCredentialRow
from yashigani.db.pgcrypto import PGP_SYM_ENCRYPT_OPTIONS

# SQL query constants re-exported here so that
# `from yashigani.db.models import INSERT_INFERENCE_EVENT` etc. work
# regardless of whether models.py (shadowed by this package) is accessible.
# v4.1 (#144): payload/response content is AES-256 encrypted at rest
# (pgp_sym_encrypt defaults to AES-128 without the options argument).
INSERT_INFERENCE_EVENT = f"""
INSERT INTO inference_events (
    tenant_id, session_id, agent_id, payload_hash, payload_length,
    response_length, payload_content, response_content,
    classification_label, classification_confidence,
    backend_used, latency_ms
) VALUES (
    $1, $2, $3, $4, $5, $6,
    pgp_sym_encrypt($7, current_setting('app.aes_key'), '{PGP_SYM_ENCRYPT_OPTIONS}'),
    pgp_sym_encrypt($8, current_setting('app.aes_key'), '{PGP_SYM_ENCRYPT_OPTIONS}'),
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
