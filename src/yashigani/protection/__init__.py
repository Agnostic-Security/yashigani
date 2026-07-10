"""
Yashigani data-protection control management.

Exports the DpWeakenPendingStore used by the dual-admin maker-checker flow
for the three weakening directions (pii_config, pii_cloud_bypass,
doc_enforcement).
"""
from .weaken_pending_store import DpWeakenPendingStore

__all__ = ["DpWeakenPendingStore"]
