"""
Yashigani Permissions — Unified permission store and resolver.

Implements the Phase 2 (3.1) core model: a single Redis-backed grant store
covering all resource_types, with deterministic org-ceiling resolution.

Grant primitive: (subject, resource_type, resource_id, value)

Public API:
    from yashigani.permissions import (
        ResourceType, BLAST_RADIUS_TYPES,
        SubjectKind, Subject, GATEWAY_ORCHESTRATOR,
        BooleanGrantValue,
        GrantValidationError, validate_boolean_grant,
        PermissionStore,
        resolve_boolean_grant, resolve_browser_capability_set,
        DEFAULT_ORG_ID,
    )

Last updated: 2026-06-28T00:00:00+00:00
"""

from yashigani.permissions.model import (
    ResourceType,
    BLAST_RADIUS_TYPES,
    RESOURCE_TYPE_VALUES,
    SubjectKind,
    Subject,
    GATEWAY_ORCHESTRATOR,
    BooleanGrantValue,
    GrantValidationError,
    validate_boolean_grant,
    validate_resource_type,
    validate_subject,
)
from yashigani.permissions.store import PermissionStore
from yashigani.permissions.resolver import (
    resolve_boolean_grant,
    resolve_browser_capability_set,
    DEFAULT_ORG_ID,
)
from yashigani.permissions.seeder import seed_mcp_grants, seed_agent_grants

__all__ = [
    # Model
    "ResourceType",
    "BLAST_RADIUS_TYPES",
    "RESOURCE_TYPE_VALUES",
    "SubjectKind",
    "Subject",
    "GATEWAY_ORCHESTRATOR",
    "BooleanGrantValue",
    "GrantValidationError",
    "validate_boolean_grant",
    "validate_resource_type",
    "validate_subject",
    # Store
    "PermissionStore",
    # Resolver
    "resolve_boolean_grant",
    "resolve_browser_capability_set",
    "DEFAULT_ORG_ID",
    # Seeder
    "seed_mcp_grants",
    "seed_agent_grants",
]
