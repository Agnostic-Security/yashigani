"""
Yashigani licence-hardening v2 — key registry (Su / Phase B-CORE).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     "Key-management & KMS-migration abstraction" item 2 (Key registry) +
     §2.2 (Master trust-anchor SET) + "MASTER-ROTATION READINESS" (LOCKED
     DECISIONS historical block — add/mark-retiring/mark-retired/emit-
     current-anchor-set tooling).

    "Key registry (the "management" layer) — a durable record of every key:
    id, role (master / build-leaf / licence-leaf), client_id (licence
    leaves) / release (build leaves), public_key, master-signed cert,
    not_before/not_after, serial, backend_ref (piv-slot / pem-path /
    kms-key-id), status (active / retired / revoked). licgen reads the
    registry and dispatches to the right Signer. Migrating a key to KMS =
    generate-in-KMS + update its backend_ref (+ re-issue if the key itself
    changes)."

This module is the durable-storage half of that abstraction — a JSON-file
registry (sole issuer = Tiago, manual, per LOCKED DECISIONS' "Operational
assumption" — a human-scale JSON ledger is the right fit, not a database).
`licgen`/`keygen.py` write to it; `inject_hashes.sh` (via
`emit_current_anchor_set_json()`) reads from it to embed the trust-anchor
SET into a build.

Two record kinds, matching the two different rotation lifecycles in the
design:
  MasterAnchorRecord  — mirrors chain.anchors.TrustAnchor's 3-state
                        (active/retiring/retired) rotation lifecycle (§2.2).
  KeyRecord           — one per code/licence/audit LEAF (simpler
                        active/retired/revoked lifecycle — leaves don't
                        have a "retiring" grace state; they are either
                        usable or not, per LOCKED DECISIONS' "leaf-serial
                        kill-list ONLY" revocation model).

Storage: NOT under docker/secrets/ and NEVER holds private key material —
only public keys, master-signed certs (also public), and backend_ref
pointers (a PEM *path* or a PIV slot label, never key bytes). Still written
with owner-only permissions (0600) by default: the registry is operational/
business data (client roster, active-key roster) that has no reason to be
group/world readable.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from yashigani.licensing.chain.algorithms import Alg
from yashigani.licensing.chain.anchors import AnchorSet, AnchorStatus, TrustAnchor
from yashigani.licensing.chain.leaf_cert import LeafCert, Role


class KeyStatus(str, Enum):
    """Lifecycle for a LEAF key record (code/licence/audit) — simpler than
    the master anchor's 3-state rotation (see AnchorStatus): a leaf is
    either usable or not. Revocation itself is via the kill-list
    (chain.kill_list); `status` here is the registry's own bookkeeping of
    intent (has this key been superseded / deliberately retired) so
    `licgen` doesn't offer a retired/revoked key for new signing."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


@dataclass
class MasterAnchorRecord:
    """Durable record backing one chain.anchors.TrustAnchor.

    `backend_ref` is the KMS-migration-abstraction pointer (LOCKED
    DECISIONS: "Registry: the master's backend_ref is ALWAYS the YubiKey/
    PIV (never changes)") — e.g. "piv:slot9c" for a real YubiKey master, or
    "pem:<path>" for the interim/demo throwaway master (§7: "Demo channel:
    throwaway master (local file)").
    """

    anchor_id: str
    pubkey_pem: str
    alg: Alg
    status: AnchorStatus
    added: datetime
    backend_ref: str
    audit_retention: str = "kept"  # "kept" | "dropped" — §2.2, independent of `status`.
    note: Optional[str] = None

    def __post_init__(self) -> None:
        if self.added.tzinfo is None:
            raise ValueError("added must be timezone-aware (UTC)")
        if self.audit_retention not in ("kept", "dropped"):
            raise ValueError(f"audit_retention must be 'kept' or 'dropped', got {self.audit_retention!r}")

    def to_trust_anchor(self) -> TrustAnchor:
        return TrustAnchor(
            anchor_id=self.anchor_id,
            pubkey_pem=self.pubkey_pem,
            alg=self.alg,
            status=self.status,
            added=self.added,
        )

    def to_dict(self) -> dict:
        return {
            "anchor_id": self.anchor_id,
            "pubkey_pem": self.pubkey_pem,
            "alg": self.alg.value,
            "status": self.status.value,
            "added": self.added.astimezone(timezone.utc).isoformat(),
            "backend_ref": self.backend_ref,
            "audit_retention": self.audit_retention,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MasterAnchorRecord":
        return cls(
            anchor_id=d["anchor_id"],
            pubkey_pem=d["pubkey_pem"],
            alg=Alg.from_wire(d["alg"]),
            status=AnchorStatus(d["status"]),
            added=datetime.fromisoformat(d["added"]),
            backend_ref=d["backend_ref"],
            audit_retention=d.get("audit_retention", "kept"),
            note=d.get("note"),
        )

    def anchor_set_entry_dict(self) -> dict:
        """The exact shape chain.build_integrity.anchor_set_from_json() expects
        (TrustAnchor field names) — used by emit_current_anchor_set_json()."""
        return {
            "anchor_id": self.anchor_id,
            "pubkey_pem": self.pubkey_pem,
            "alg": self.alg.value,
            "status": self.status.value,
            "added": self.added.astimezone(timezone.utc).isoformat(),
        }


@dataclass
class KeyRecord:
    """Durable record backing one LEAF key (role=code|licence|audit).

    `leaf_cert`/`leaf_cert_sig_b64` are the master-certified artefacts
    (public — safe to store here). `private_key_backend_ref` is a PEM path
    or KMS key-id — a *pointer*, never key bytes (never the passphrase).
    `org_domain` is populated for LICENCE leaves at client onboarding, and
    is what feeds emit_client_domain_registry_json() (the seam
    chain/licence_v5.py's verify_licence_v5() SEAM note calls out as
    "Su/licgen registry work is the intended writer").
    """

    key_id: str
    role: Role
    client_id: str
    release: Optional[str]
    public_key_pem: str
    leaf_cert: LeafCert
    leaf_cert_sig_b64: str
    not_before: datetime
    not_after: datetime
    serial: str
    private_key_backend_ref: str
    status: KeyStatus = KeyStatus.ACTIVE
    org_domain: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    note: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "role": self.role.value,
            "client_id": self.client_id,
            "release": self.release,
            "public_key_pem": self.public_key_pem,
            "leaf_cert": self.leaf_cert.to_canonical_dict(),
            "leaf_cert_sig_b64": self.leaf_cert_sig_b64,
            "not_before": self.not_before.astimezone(timezone.utc).isoformat(),
            "not_after": self.not_after.astimezone(timezone.utc).isoformat(),
            "serial": self.serial,
            "private_key_backend_ref": self.private_key_backend_ref,
            "status": self.status.value,
            "org_domain": self.org_domain,
            "created_at": self.created_at.astimezone(timezone.utc).isoformat(),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyRecord":
        return cls(
            key_id=d["key_id"],
            role=Role(d["role"]),
            client_id=d["client_id"],
            release=d.get("release"),
            public_key_pem=d["public_key_pem"],
            leaf_cert=LeafCert.from_canonical_dict(d["leaf_cert"]),
            leaf_cert_sig_b64=d["leaf_cert_sig_b64"],
            not_before=datetime.fromisoformat(d["not_before"]),
            not_after=datetime.fromisoformat(d["not_after"]),
            serial=d["serial"],
            private_key_backend_ref=d["private_key_backend_ref"],
            status=KeyStatus(d.get("status", KeyStatus.ACTIVE.value)),
            org_domain=d.get("org_domain"),
            created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else datetime.now(timezone.utc),
            note=d.get("note"),
        )


class RegistryError(RuntimeError):
    """Raised on registry consistency errors (duplicate id, not found, etc.)."""


class KeyRegistry:
    """JSON-file-backed durable registry of master anchors + leaf keys.

    NOT a database — matches the design's "Operational assumption... sole
    issuer = Tiago, manual" scale. Every mutating call re-writes the whole
    file atomically (temp file + os.replace, 0600) — safe for a single
    human operator's cadence (a handful of writes per release/onboarding),
    not designed for concurrent writers (no file locking) — see
    keygen.py/licgen's own docs for the "one issuer at a time" assumption
    this mirrors from the design.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._anchors: dict[str, MasterAnchorRecord] = {}
        self._keys: dict[str, KeyRecord] = {}
        if self.path.exists():
            self._load()

    # -- persistence ---------------------------------------------------

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._anchors = {
            a["anchor_id"]: MasterAnchorRecord.from_dict(a) for a in raw.get("anchors", [])
        }
        self._keys = {k["key_id"]: KeyRecord.from_dict(k) for k in raw.get("keys", [])}

    def save(self) -> None:
        """Atomic write (TOCTOU-hardened: write to a sibling temp file, then
        os.replace — never a partial/corrupt registry file even if the
        process is killed mid-write). 0600 — owner-only (S1 discipline
        applied by default even though this file holds no private key
        material)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "anchors": [a.to_dict() for a in self._sorted_anchors()],
            "keys": [k.to_dict() for k in self._sorted_keys()],
        }
        tmp_path = self.path.with_suffix(self.path.suffix + f".tmp.{os.getpid()}")
        fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.write("\n")
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise
        os.replace(str(tmp_path), str(self.path))
        os.chmod(self.path, 0o600)

    def _sorted_anchors(self) -> list[MasterAnchorRecord]:
        return [self._anchors[k] for k in sorted(self._anchors)]

    def _sorted_keys(self) -> list[KeyRecord]:
        return [self._keys[k] for k in sorted(self._keys)]

    # -- master anchors --------------------------------------------------

    def add_anchor(self, anchor: MasterAnchorRecord) -> None:
        if anchor.anchor_id in self._anchors:
            raise RegistryError(f"anchor_id {anchor.anchor_id!r} already exists")
        self._anchors[anchor.anchor_id] = anchor
        self.save()

    def get_anchor(self, anchor_id: str) -> MasterAnchorRecord:
        try:
            return self._anchors[anchor_id]
        except KeyError:
            raise RegistryError(f"anchor_id {anchor_id!r} not found") from None

    def mark_anchor_retiring(self, anchor_id: str) -> None:
        """LOCKED DECISIONS lifecycle: 'mark M1 retiring' step — still
        trusted for verification (chain.anchors.AnchorSet.trusted_anchors())
        but no longer used for NEW issuance."""
        a = self.get_anchor(anchor_id)
        a.status = AnchorStatus.RETIRING
        self.save()

    def mark_anchor_retired(self, anchor_id: str) -> None:
        """'once all migrated, retired' — dropped from new builds.
        audit_retention is intentionally left untouched (§2.2: retention is
        INDEPENDENT of status — never flip it as a side-effect of routine
        licence-anchor retirement)."""
        a = self.get_anchor(anchor_id)
        a.status = AnchorStatus.RETIRED
        self.save()

    def list_anchors(self) -> list[MasterAnchorRecord]:
        return self._sorted_anchors()

    def emit_current_anchor_set(self) -> AnchorSet:
        """The verification-time trust set: active + retiring (retired
        anchors are dropped — 'Dropped from new builds', §2.2)."""
        anchors = [
            a.to_trust_anchor()
            for a in self._sorted_anchors()
            if a.status in (AnchorStatus.ACTIVE, AnchorStatus.RETIRING)
        ]
        return AnchorSet(anchors)

    def emit_current_anchor_set_json(self) -> str:
        """The exact string to embed as _integrity.MASTER_ANCHOR_SET_JSON —
        matches chain.build_integrity.anchor_set_from_json()'s expected
        schema field-for-field."""
        entries = [
            a.anchor_set_entry_dict()
            for a in self._sorted_anchors()
            if a.status in (AnchorStatus.ACTIVE, AnchorStatus.RETIRING)
        ]
        return json.dumps(entries, sort_keys=True, separators=(",", ":"))

    # -- leaf keys ---------------------------------------------------------

    def add_key(self, record: KeyRecord) -> None:
        if record.key_id in self._keys:
            raise RegistryError(f"key_id {record.key_id!r} already exists")
        self._keys[record.key_id] = record
        self.save()

    def get_key(self, key_id: str) -> KeyRecord:
        try:
            return self._keys[key_id]
        except KeyError:
            raise RegistryError(f"key_id {key_id!r} not found") from None

    def mark_key_retired(self, key_id: str) -> None:
        k = self.get_key(key_id)
        k.status = KeyStatus.RETIRED
        self.save()

    def mark_key_revoked(self, key_id: str, reason: Optional[str] = None) -> None:
        """Registry-side bookkeeping only — does NOT itself write a
        kill-list entry (that is chain.kill_list / licgen revoke's job,
        driven by leaf serial, independently of this registry). Keeping the
        two concerns separate mirrors the design's own split between 'the
        registry tracks key lifecycle' and 'the kill-list is what builds
        embed and verifiers check' (§6)."""
        k = self.get_key(key_id)
        k.status = KeyStatus.REVOKED
        if reason:
            k.note = reason
        self.save()

    def list_keys(
        self, role: Optional[Role] = None, client_id: Optional[str] = None
    ) -> list[KeyRecord]:
        keys = self._sorted_keys()
        if role is not None:
            keys = [k for k in keys if k.role == role]
        if client_id is not None:
            keys = [k for k in keys if k.client_id == client_id]
        return keys

    def active_code_leaf_for_release(self, release: str) -> Optional[KeyRecord]:
        for k in self._sorted_keys():
            if k.role == Role.CODE and k.release == release and k.status == KeyStatus.ACTIVE:
                return k
        return None

    def active_licence_leaf_for_client(self, client_id: str) -> Optional[KeyRecord]:
        for k in self._sorted_keys():
            if k.role == Role.LICENCE and k.client_id == client_id and k.status == KeyStatus.ACTIVE:
                return k
        return None

    def emit_client_domain_registry_json(self) -> str:
        """The exact string to embed as _integrity.CLIENT_DOMAIN_REGISTRY_JSON
        — {client_id: org_domain} built from every LICENCE-role key that has
        a registered org_domain. Populates the seam
        chain/licence_v5.py's verify_licence_v5() SEAM note flagged as
        unpopulated in Phase B-CORE."""
        mapping: dict[str, str] = {}
        for k in self._sorted_keys():
            if k.role == Role.LICENCE and k.org_domain and k.status != KeyStatus.REVOKED:
                mapping[k.client_id] = k.org_domain
        return json.dumps(mapping, sort_keys=True, separators=(",", ":"))
