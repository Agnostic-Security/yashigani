"""
Yashigani Unified Identity Registry.

Every entity (human or service) is an identity. One registry, one governance
model, one budget system, one audit trail.

Modules:
  identity.registry      -- CRUD operations, lookup, lifecycle management
  identity.durable_store -- Postgres durable mirror + startup reconciler (B1 follow-on)
  identity.api_key       -- API key generation, rotation, validation
"""

from yashigani.identity.registry import IdentityRegistry, IdentityKind
from yashigani.identity.durable_store import (
    IdentityDurableStore,
    reconcile_identities_from_durable,
)
from yashigani.identity.api_key import generate_api_key, hash_api_key, verify_api_key
from yashigani.identity.slug import email_to_slug

__all__ = [
    "IdentityRegistry",
    "IdentityKind",
    "IdentityDurableStore",
    "reconcile_identities_from_durable",
    "generate_api_key",
    "hash_api_key",
    "verify_api_key",
    "email_to_slug",
]
