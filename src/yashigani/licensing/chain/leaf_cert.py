"""
Yashigani licence-hardening v2 — leaf_cert schema.

Ref: design doc ROUND-3 fix 4 ("Update §3 format spec to match ALL locked
fields") + ROUND-4 fix ("Three leaf roles ... audit").

A leaf_cert binds a leaf public key to the master, for exactly one of three
roles:
    code    — per release, shared across all clients, signs the build bundle
    licence — per client, held on OUR signer, signs that client's licences
    audit   — per client/deployment, held on the CUSTOMER's box, signs their
              audit-chain checkpoints ONLY (role separation is a hard
              boundary — a customer-held audit leaf must never be accepted
              for a licence or code signature; see verify_leaf_cert_role()).

Phase A builds the SCHEMA + the master-signs / anchor-verifies primitives.
Full chain wiring (verifier.py rewrite, v5 licence format, keygen/licgen) is
Phase B — see the dispatch brief.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from yashigani.licensing.chain.algorithms import Alg
from yashigani.licensing.chain.canonical import leaf_cert_signing_digest


class Role(str, Enum):
    """Closed enum — the `role` field is defense-in-depth against cert-substitution
    bugs (LOCKED DECISIONS) and, per ROUND-4, the hard boundary that stops a
    customer-held audit leaf forging a licence or code signature."""

    CODE = "code"
    LICENCE = "licence"
    AUDIT = "audit"


# Sentinel client_id for the shared, per-release CODE leaf — it is not bound
# to any single client (build artefacts are identical across all customers).
SHARED_CLIENT_ID = "*"


@dataclass(frozen=True)
class LeafCert:
    """A master-certified leaf public key.

    Field notes (design doc locked field-set, ROUND-3 fix 1 + fix 4 + ROUND-4):
      role              closed enum: code | licence | audit
      client_id         binds isolation (Laura R3-F1). SHARED_CLIENT_ID ("*") for
                         the shared per-release code leaf; a real client identifier
                         (e.g. "acme-corp", "Demo") for licence/audit leaves.
                         ROUND-4 extended client_id binding to audit leaves too
                         (r3-F1 was licence-only) — a leaked customer-held audit
                         key must not be able to impersonate another client's
                         audit chain to an auditor.
      release           the release this leaf serves, e.g. "4.1.1" — set for
                         CODE leaves ONLY. None for LICENCE/AUDIT leaves, which
                         are per-client and persist across releases via
                         chain-to-master (LOCKED DECISIONS: "Persists across
                         releases via chain-to-master").
      leaf_pubkey_pem   the per-leaf public key, PEM-encoded.
      not_before        SIGNING-SIDE ONLY window start. NEVER checked at
                         verify time — see verify_leaf_cert_signature()'s
                         docstring. Governs when a KMS/PIV backend will agree
                         to sign with this leaf.
      not_after         SIGNING-SIDE ONLY window end. Same caveat.
      serial            monotonic leaf serial — the kill-list revocation unit
                         (per-release for code leaves, per-client for
                         licence/audit leaves; LOCKED DECISIONS: "leaf-serial
                         kill-list ONLY").
      signed_at         forensic signing timestamp (LOCKED DECISIONS: "Signing
                         timestamp (signed_at) in the licence — forensic trail").
      alg               closed Alg enum member. Lives INSIDE this dataclass
                         (and therefore inside the canonicalised, signed
                         digest) — never as an unsigned wrapper.
      csr_pop           Optional self-signed CSR / proof-of-possession the
                         requester submitted at provisioning time (Phase B /
                         Su addition — LOCKED DECISIONS bullet 9 + §3.1: "the
                         master only signs a pubkey that proves it holds the
                         private key"). Shape:
                         {"leaf_pubkey_pem", "client_id", "role", "csr_self_sig"}.
                         The MASTER verifies csr_self_sig against
                         leaf_pubkey_pem BEFORE certifying (keygen.py mint
                         flow) — this field is carried on the cert purely as
                         a provenance record; it is NOT re-verified at
                         runtime (§4a/§4b/§4c never re-check csr_pop, only
                         the mint-time master does). None for leaves minted
                         before this field existed / where PoP is out of
                         scope (kept Optional for backward compatibility with
                         Phase A round-trip tests).
    """

    role: Role
    client_id: str
    leaf_pubkey_pem: str
    not_before: datetime
    not_after: datetime
    serial: str
    signed_at: datetime
    alg: Alg
    release: Optional[str] = None
    csr_pop: Optional[dict] = None

    def __post_init__(self) -> None:
        if self.role == Role.CODE and self.client_id != SHARED_CLIENT_ID:
            raise ValueError(
                f"CODE leaf_cert must use client_id={SHARED_CLIENT_ID!r} (shared across "
                f"all clients); got {self.client_id!r}"
            )
        if self.role in (Role.LICENCE, Role.AUDIT) and self.client_id == SHARED_CLIENT_ID:
            raise ValueError(
                f"{self.role.value} leaf_cert must be bound to a real client_id, "
                f"not the shared sentinel {SHARED_CLIENT_ID!r} (Laura R3-F1 / ROUND-4 audit binding)"
            )
        if self.role == Role.CODE and self.release is None:
            raise ValueError("CODE leaf_cert must set `release` (e.g. \"4.1.1\")")
        if self.role != Role.CODE and self.release is not None:
            raise ValueError(
                f"{self.role.value} leaf_cert must not set `release` — licence/audit "
                f"leaves persist across releases via chain-to-master"
            )
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be strictly after not_before")
        for dt_name, dt_val in (
            ("not_before", self.not_before),
            ("not_after", self.not_after),
            ("signed_at", self.signed_at),
        ):
            if dt_val.tzinfo is None:
                raise ValueError(f"{dt_name} must be timezone-aware (UTC)")

    def to_canonical_dict(self) -> dict:
        """Deterministic dict for canonical() — every field explicit (no
        implicit omission of None fields, so the signed shape is stable)."""
        return {
            "role": self.role.value,
            "client_id": self.client_id,
            "release": self.release,
            "leaf_pubkey_pem": self.leaf_pubkey_pem,
            "not_before": self.not_before.astimezone(timezone.utc).isoformat(),
            "not_after": self.not_after.astimezone(timezone.utc).isoformat(),
            "serial": self.serial,
            "licence_serial": self.licence_serial,
            "signed_at": self.signed_at.astimezone(timezone.utc).isoformat(),
            "alg": self.alg.value,
            "csr_pop": self.csr_pop,
        }

    @classmethod
    def from_canonical_dict(cls, d: dict) -> "LeafCert":
        """Inverse of to_canonical_dict() — for round-trip tests and for a
        verifier reconstructing a LeafCert from parsed licence/build JSON."""
        return cls(
            role=Role(d["role"]),
            client_id=d["client_id"],
            release=d.get("release"),
            leaf_pubkey_pem=d["leaf_pubkey_pem"],
            not_before=datetime.fromisoformat(d["not_before"]),
            not_after=datetime.fromisoformat(d["not_after"]),
            serial=d["serial"],
            licence_serial=d.get("licence_serial"),
            signed_at=datetime.fromisoformat(d["signed_at"]),
            alg=Alg.from_wire(d["alg"]),
            csr_pop=d.get("csr_pop"),
        )

    def signing_digest(self) -> bytes:
        """The digest the MASTER signs to produce leaf_cert_sig."""
        return leaf_cert_signing_digest(self.to_canonical_dict())
