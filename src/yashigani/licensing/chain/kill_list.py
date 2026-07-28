"""
Yashigani licence-hardening v2 — leaf-serial kill-list.

Ref: design doc §6 (Revocation — leaf-serial kill-list, offline,
ships-with-updates) + §6.1 (Namespaces + per-namespace verifier semantics).

    "Mandatory ... Shipped/updated with releases, checked locally — never a
    live CRL/callback (no-phone-home invariant holds for revocation too)."

Namespaces (§6.1):
    master-anchor:<anchor_id>              IMMEDIATE   4a, 4b, 4c
    leaf:<serial>                          IMMEDIATE   4a, 4b, 4c
    licence:<licence_serial>               IMMEDIATE   4b
    client:<client_id>  (licence-leaf)     IMMEDIATE   4b
    client:<client_id>  (audit-leaf)       FORWARD-ONLY  4c  [Phase C — NOT wired this phase]

This module builds the full revoked_at-aware entry structure (so Phase C's
forward-only audit-scope drops in without a schema change) but Phase B-CORE
only WIRES the IMMEDIATE namespaces (leaf/licence/client-licence-scope/
master-anchor) into 4a and 4b — see verifier.py and build_integrity.py.
There is no `scope` distinguishing "licence-leaf client" vs "audit-leaf
client" `client:<client_id>` entries yet, because role=audit leaves and
audit-checkpoint verification (§4c) are explicitly out of scope for this
phase (Phase C). When §4c lands, KillListEntry.semantics="forward_only"
plus an explicit audit-scope marker is the drop-in point — flagged here so
Phase C does not have to touch this module's core shape.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class KillListSemantics(str, Enum):
    IMMEDIATE = "immediate"
    FORWARD_ONLY = "forward_only"


@dataclass(frozen=True)
class KillListEntry:
    """One kill-list entry.

    `revoked_at` is a forensic/audit-trail timestamp for IMMEDIATE entries
    (§6.1: "For the four IMMEDIATE rows it is a forensic/audit-trail field
    ... for the client:<client_id> audit-leaf-scope row it is LOAD-BEARING").
    Phase B-CORE only constructs/consumes IMMEDIATE entries; FORWARD_ONLY is
    defined here for Phase C's audit-checkpoint revocation (§4c step 4) and
    is not exercised by any Phase B-CORE call site.
    """

    namespace: str  # "master-anchor" | "leaf" | "licence" | "client"
    identifier: str
    revoked_at: datetime
    semantics: KillListSemantics = KillListSemantics.IMMEDIATE
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.revoked_at.tzinfo is None:
            raise ValueError("revoked_at must be timezone-aware (UTC)")

    def to_canonical_dict(self) -> dict:
        return {
            "namespace": self.namespace,
            "identifier": self.identifier,
            "revoked_at": self.revoked_at.astimezone(timezone.utc).isoformat(),
            "semantics": self.semantics.value,
            "reason": self.reason,
        }

    @classmethod
    def from_canonical_dict(cls, d: dict) -> "KillListEntry":
        return cls(
            namespace=d["namespace"],
            identifier=d["identifier"],
            revoked_at=datetime.fromisoformat(d["revoked_at"]),
            semantics=KillListSemantics(d.get("semantics", KillListSemantics.IMMEDIATE.value)),
            reason=d.get("reason"),
        )


class KillList:
    """An embedded, ships-with-releases kill-list.

    Checked entirely locally/offline — never a live CRL/callback (no-phone-
    home invariant, §"NO PHONE-HOME" in the design's LOCKED DECISIONS).
    """

    def __init__(self, entries: list[KillListEntry]) -> None:
        self._entries = list(entries)

    def __len__(self) -> int:
        return len(self._entries)

    def all_entries(self) -> list[KillListEntry]:
        return list(self._entries)

    def is_revoked_immediate(self, namespace: str, identifier: str) -> bool:
        """True if ANY entry matches (namespace, identifier) — semantics is
        ignored here (an IMMEDIATE-namespace lookup treats any match as
        revoked regardless of the entry's own semantics tag; a
        forward_only-tagged client:<id> audit-scope entry is looked up via
        is_revoked_forward_only() instead, never via this method, so there
        is no cross-contamination between the licence-leaf and audit-leaf
        `client:<client_id>` rows per §6.1's "two leaves it kills do NOT get
        the same treatment")."""
        for entry in self._entries:
            if (
                entry.namespace == namespace
                and entry.identifier == identifier
                and entry.semantics == KillListSemantics.IMMEDIATE
            ):
                return True
        return False

    def is_revoked_forward_only(
        self, namespace: str, identifier: str, event_date: datetime
    ) -> bool:
        """Phase C hook (§4c step 4, audit-checkpoint revocation): True only
        if a FORWARD_ONLY entry exists AND event_date > entry.revoked_at — a
        checkpoint dated at-or-before revoked_at still verifies (Laura
        R5-F3). Not called by any Phase B-CORE code path."""
        for entry in self._entries:
            if (
                entry.namespace == namespace
                and entry.identifier == identifier
                and entry.semantics == KillListSemantics.FORWARD_ONLY
                and event_date > entry.revoked_at
            ):
                return True
        return False

    def to_canonical_list(self) -> list[dict]:
        return [e.to_canonical_dict() for e in self._entries]

    @classmethod
    def from_canonical_list(cls, raw: list[dict]) -> "KillList":
        return cls([KillListEntry.from_canonical_dict(d) for d in raw])

    @classmethod
    def empty(cls) -> "KillList":
        return cls([])
