"""
Yashigani licence-hardening v2 — Signer backend interface.

Ref: design doc "Key-management & KMS-migration abstraction" section.

    "Signer backend interface — sign(role, context_tag, message) -> signature
    (+ public_key(), cert()). ... The verifier never sees the backend — it
    validates signatures + chain against public keys only. Migration = swap
    the signer, not the format."

Three concrete backends, per the design's PKCS#11-first recommendation:
    PemSigner  — local software key (interim LEAVES: build + per-client
                 licence). Functional today.
    PivSigner  — YubiKey/PIV on-device via PKCS#11 (interim MASTER). Wires
                 the PKCS#11-first shape; sign() is a stub (NotImplementedError)
                 until real hardware is present in an environment — the shape
                 (constructor, slot/label/PIN params, raw r||s -> DER
                 reconciliation) is real and load-bearing for Su/Captain.
    KmsSigner  — AWS/GCP/Azure/Vault asymmetric-sign (future MASTER and
                 LEAVES). Stub; handles the DER-vs-raw-r||s reconciliation
                 internally per provider quirk (Azure returns raw r||s; AWS/
                 GCP/Vault return DER already).

The verifier (Phase B) never imports this module — it only ever sees public
keys + signatures + the Alg enum. That is what "backend-agnostic verifier"
means and is enforced simply by module boundary (nothing in
chain/algorithms.py, chain/leaf_cert.py or chain/anchors.py imports Signer).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.chain.algorithms import (
    Alg,
    RoleMismatchError,
    raw_rs_to_der,
    sign_message,
)
from yashigani.licensing.chain.leaf_cert import LeafCert, Role


class Signer(ABC):
    """Backend-agnostic signing interface.

    `role` is passed into every sign() call (not just fixed at construction)
    so a backend can defense-in-depth reject a request for a role it was not
    provisioned for — this is the same "role separation is a hard boundary"
    property the design applies to leaf_cert.role, enforced again at the
    signer layer (belt + braces: even if a caller somehow constructed a
    LeafCert with the wrong role, the signer itself refuses to produce a
    signature under a mismatched role).
    """

    def __init__(self, role: Role) -> None:
        self._role = role

    @property
    def role(self) -> Role:
        return self._role

    @abstractmethod
    def sign(self, role: Role, context_tag: str, message: bytes) -> bytes:
        """Sign `message` (a pre-computed domain-separated digest — see
        canonical.py's *_signing_digest() helpers) for `role` under
        `context_tag`. Returns a DER-encoded ECDSA signature (or, for future
        PQC/hybrid algs, that algorithm's canonical wire encoding).

        Implementations MUST raise RoleMismatchError if role != self.role.
        `context_tag` is accepted for audit/logging purposes (LOCKED
        DECISIONS: "Audit-log every licgen issue") — it is not re-hashed
        here, because the caller already folded it into `message` via
        canonical.py's digest helpers. A backend MAY use it to enrich its
        own audit trail (e.g. PivSigner logging which context tag a rare
        master-unlock was used for).
        """
        raise NotImplementedError

    @abstractmethod
    def public_key(self) -> str:
        """Return this signer's public key, PEM-encoded."""
        raise NotImplementedError

    @abstractmethod
    def cert(self) -> Optional[LeafCert]:
        """Return this signer's own leaf_cert, if it is a leaf (master
        signers return None — the master has no cert of its own; it IS the
        trust anchor)."""
        raise NotImplementedError

    @property
    @abstractmethod
    def alg(self) -> Alg:
        """The Alg this signer produces signatures under."""
        raise NotImplementedError

    def _check_role(self, role: Role) -> None:
        if role != self._role:
            raise RoleMismatchError(
                f"{type(self).__name__} is provisioned for role={self._role.value}; "
                f"refused sign() request for role={role.value}"
            )


class PemSigner(Signer):
    """Local software key signer — interim backend for LEAVES (build-leaf,
    per-client licence-leaf). Functional today: cryptography's EC sign()
    already emits DER, so no raw-r||s reconciliation is needed here (that is
    a PKCS#11/KMS-specific quirk — see PivSigner/KmsSigner).
    """

    def __init__(
        self,
        role: Role,
        private_key: ec.EllipticCurvePrivateKey,
        alg: Alg = Alg.ECDSA_P384_SHA384,
        leaf_cert: Optional[LeafCert] = None,
    ) -> None:
        super().__init__(role)
        if alg != Alg.ECDSA_P384_SHA384:
            raise ValueError(
                f"PemSigner only supports ecdsa-p384-sha384 today; got {alg.value} "
                f"(no live backend for PQC/hybrid algs yet — see algorithms.py)"
            )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
            private_key.curve, ec.SECP384R1
        ):
            raise ValueError("PemSigner requires a P-384 ECDSA private key")
        self._private_key = private_key
        self._alg = alg
        self._leaf_cert = leaf_cert

    @classmethod
    def from_pem_bytes(
        cls,
        role: Role,
        pem_bytes: bytes,
        password: Optional[bytes] = None,
        leaf_cert: Optional[LeafCert] = None,
    ) -> "PemSigner":
        private_key = serialization.load_pem_private_key(pem_bytes, password=password)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError(f"PEM does not contain an EC private key: {type(private_key).__name__}")
        return cls(role=role, private_key=private_key, leaf_cert=leaf_cert)

    def sign(self, role: Role, context_tag: str, message: bytes) -> bytes:
        self._check_role(role)
        return sign_message(self._alg, self._private_key, message)

    def public_key(self) -> str:
        return (
            self._private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

    def cert(self) -> Optional[LeafCert]:
        return self._leaf_cert

    @property
    def alg(self) -> Alg:
        return self._alg


class PivSigner(Signer):
    """YubiKey/PIV master signer via PKCS#11 — interim MASTER backend.

    Design rationale (KMS-migration section): "Standardize the signer
    interface on PKCS#11. YubiKey (now) and a VPC HSM/Vault (later) both
    speak PKCS#11 — so YubiKey->VPC is a provider/config swap, not new
    code." This class wires that shape now.

    STUB in Phase A: sign() raises NotImplementedError. No YubiKey hardware
    is present in this dev/CI/worktree environment, and pulling in a real
    PKCS#11 binding (python-pkcs11 + ykcs11 module) is Phase B/Captain scope
    (KMS plumbing). What IS real here and load-bearing for Phase B:
      - the constructor shape (module path / slot / key label / PIN — the
        parameters any PKCS#11 session needs, for YubiKey today and a VPC
        HSM/Vault tomorrow with the same shape),
      - public_key() reading the certificate/public object off the token
        (stubbed the same way — needs a live session),
      - the raw r||s -> DER reconciliation via raw_rs_to_der(), which is a
        pure function and IS unit-tested here without hardware.
    """

    def __init__(
        self,
        pkcs11_module_path: str,
        key_label: str,
        slot_id: Optional[int] = None,
        pin: Optional[bytes] = None,
        role: Role = Role.CODE,
        alg: Alg = Alg.ECDSA_P384_SHA384,
    ) -> None:
        super().__init__(role)
        self._pkcs11_module_path = pkcs11_module_path
        self._key_label = key_label
        self._slot_id = slot_id
        self._pin = pin
        self._alg = alg

    def sign(self, role: Role, context_tag: str, message: bytes) -> bytes:
        self._check_role(role)
        raise NotImplementedError(
            "PivSigner requires live PKCS#11 hardware (YubiKey/PIV) — not wired in "
            "this environment. See class docstring: the shape is real, the hardware "
            "session is Phase B/Captain scope."
        )

    def public_key(self) -> str:
        raise NotImplementedError(
            "PivSigner.public_key() requires a live PKCS#11 session to read the "
            "token's public key object — not wired in this environment."
        )

    def cert(self) -> Optional[LeafCert]:
        # The master has no leaf_cert of its own — it IS the trust anchor.
        return None

    @property
    def alg(self) -> Alg:
        return self._alg

    @staticmethod
    def raw_signature_to_der(raw_signature: bytes, curve_size_bytes: int = 48) -> bytes:
        """PKCS#11 C_Sign for an EC key returns raw r||s — convert to DER
        before this signature leaves the PivSigner (ROUND-3 fix 3, "live
        TODAY"). Exposed as a staticmethod so it is testable independent of
        a live PKCS#11 session."""
        return raw_rs_to_der(raw_signature, curve_size_bytes=curve_size_bytes)


class KmsSigner(Signer):
    """Cloud/self-hosted KMS asymmetric-sign backend — future MASTER *and*
    LEAVES (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault Transit).

    STUB in Phase A: no live KMS is wired. What is real: the single sign()
    contract (always returns DER regardless of provider quirk) via the
    `raw_signature_format` constructor flag, matching the design's KMS-
    abstraction requirement: "Handles the DER-vs-raw-r||s reconciliation
    internally." AWS KMS / GCP KMS / HashiCorp Vault Transit already return
    DER; Azure Key Vault returns raw r||s — reconcile() normalises both to
    this codebase's canonical DER wire format.
    """

    def __init__(
        self,
        kms_key_id: str,
        provider: str,
        raw_signature_format: str,  # "der" | "raw_rs"
        role: Role,
        alg: Alg = Alg.ECDSA_P384_SHA384,
        curve_size_bytes: int = 48,
    ) -> None:
        super().__init__(role)
        if raw_signature_format not in ("der", "raw_rs"):
            raise ValueError(
                f"raw_signature_format must be 'der' or 'raw_rs', got {raw_signature_format!r}"
            )
        self._kms_key_id = kms_key_id
        self._provider = provider
        self._raw_signature_format = raw_signature_format
        self._alg = alg
        self._curve_size_bytes = curve_size_bytes

    def sign(self, role: Role, context_tag: str, message: bytes) -> bytes:
        self._check_role(role)
        raise NotImplementedError(
            f"KmsSigner requires a live {self._provider} KMS connection — not wired "
            f"in Phase A. See design doc 'Key-management & KMS-migration abstraction': "
            f"this is future MASTER+LEAVES scope, gated on 'which KMS' (design §10 open "
            f"decision 1)."
        )

    def public_key(self) -> str:
        raise NotImplementedError(
            f"KmsSigner.public_key() requires a live {self._provider} connection — "
            f"not wired in Phase A."
        )

    def cert(self) -> Optional[LeafCert]:
        return None

    @property
    def alg(self) -> Alg:
        return self._alg

    def reconcile(self, raw_kms_signature: bytes) -> bytes:
        """Normalise a raw signature returned by the KMS provider into this
        codebase's canonical DER wire format, per this signer's configured
        `raw_signature_format`. Pure function — testable without a live KMS
        connection by feeding it a captured provider response."""
        if self._raw_signature_format == "der":
            return raw_kms_signature
        return raw_rs_to_der(raw_kms_signature, curve_size_bytes=self._curve_size_bytes)
