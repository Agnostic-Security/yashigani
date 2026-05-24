"""
Yashigani Manifest Registry — LU-AMEND-02 / v2.24.1.

Append-only ledger of every agent manifest registration.

Exports:
  ManifestRegistryService   — async service for register + history + verify
  ManifestRegistrationRecord — typed record returned from queries
"""
from yashigani.manifest_registry.service import (
    ManifestRegistryService,
    ManifestRegistrationRecord,
)

__all__ = ["ManifestRegistryService", "ManifestRegistrationRecord"]
