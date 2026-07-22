"""
Yashigani Inspection — model-integrity pinning + dual-control (A5, 5.0).

Threat (design `model-integrity-pinning-design-5.0-20260714.md`, council
4x GO-WITH-FIXES): detect/block a swapped or trojaned Ollama model delivered via
DNS hijack, registry poisoning, a MITM'd pull, or silent operator drift.

Trust root (Nico, decisive): pin the WEIGHTS-BLOB sha256 computed by us from
disk (`~/.ollama/models/blobs/sha256-<weights>`), verified at process start —
NOT ollama's self-reported manifest digest, which ollama does not re-hash at
serve time (an in-place blob swap would still "match"). The manifest digest via
`/api/tags` is the cheap per-request fast-path that catches network-delivery
substitution. Both values are pinned; dual-control covers both.

Dual-control (Lu/Iris) implements the corrected pattern the design mandates —
these are the SOD-1/SOD-2 fixes the base cloud_override.py still lacks:
  - SOD-1: the approver RE-SUPPLIES the confirming digest; the server
    byte-compares it against the immutable pending record (keyed by
    proposal_id). A second propose() while one is PENDING is rejected, so a
    digest cannot be swapped between review and activation.
  - SOD-2: write-ahead DURABLE audit — the mutation fails closed if the audit
    write fails (never a silent activation).
  - B != A by account; no new role/service-account (Tiago standing rule).

Fail-closed: an unreachable pin store blocks (stronger than the alias/alloc
stores — documented). Bootstrap (TOFU): first pin captured under single
installer authority, audited; dual-control governs CHANGES thereafter. With one
admin the change path deadlocks fail-closed (existing pin stays enforced).
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_PIN_KEY_PREFIX = "yashigani:model:pin:"
_PENDING_KEY_PREFIX = "yashigani:model:pin:pending:"
_PROPOSAL_WINDOW_SECONDS = 300
_BLOB_READ_CHUNK = 1024 * 1024


class ModelIntegrityError(Exception):
    """Base error for model-integrity operations."""


class PinStoreUnavailableError(ModelIntegrityError):
    """The pin store could not be reached — callers MUST fail closed."""


class DualControlError(ModelIntegrityError):
    """Raised on an invalid propose/approve (self-approval, digest mismatch, …)."""


# ── Blob-hash anchor ────────────────────────────────────────────────────────

def compute_blob_sha256(path: str) -> str:
    """SHA-256 of a weights blob on disk. Streamed so a multi-GB blob does not
    load into memory. Raises OSError if the path is unreadable (caller decides
    fail-closed)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(_BLOB_READ_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class Pin:
    model: str
    weights_sha256: str
    manifest_digest: str


@dataclass
class VerifyResult:
    ok: bool
    model: str
    reason: str  # "match" | "no_pin" | "weights_mismatch" | "manifest_mismatch" | "store_unavailable"
    expected_weights: str = ""
    observed_weights: str = ""
    expected_manifest: str = ""
    observed_manifest: str = ""


# ── Pin store (Redis-backed; fail-closed) ───────────────────────────────────

class ModelPinStore:
    """Durable pin store. The gateway reads pins live; the admin API writes them
    through the dual-control manager. Any store error surfaces as
    PinStoreUnavailableError so the caller fails closed."""

    def __init__(self, redis_client) -> None:
        self._r = redis_client

    def get(self, model: str) -> Optional[Pin]:
        try:
            raw = self._r.get(_PIN_KEY_PREFIX + model)
        except Exception as exc:  # noqa: BLE001 — normalize to fail-closed
            raise PinStoreUnavailableError(str(exc)) from exc
        if not raw:
            return None
        d = json.loads(raw if isinstance(raw, str) else raw.decode())
        return Pin(
            model=d["model"],
            weights_sha256=d.get("weights_sha256", ""),
            manifest_digest=d.get("manifest_digest", ""),
        )

    def put(self, pin: Pin) -> None:
        try:
            self._r.set(
                _PIN_KEY_PREFIX + pin.model,
                json.dumps({
                    "model": pin.model,
                    "weights_sha256": pin.weights_sha256,
                    "manifest_digest": pin.manifest_digest,
                }),
            )
        except Exception as exc:  # noqa: BLE001
            raise PinStoreUnavailableError(str(exc)) from exc

    def has_any(self) -> bool:
        try:
            return bool(next(iter(self._r.scan_iter(_PIN_KEY_PREFIX + "*")), None))
        except Exception as exc:  # noqa: BLE001
            raise PinStoreUnavailableError(str(exc)) from exc


# ── Verifier ────────────────────────────────────────────────────────────────

class ModelIntegrityVerifier:
    """Verify an ollama model against its pin. weights are the primary anchor
    (checked when a blob hash is available); the manifest digest is the cheap
    fast-path checked on every call."""

    def __init__(self, store: ModelPinStore, audit_writer=None) -> None:
        self._store = store
        self._audit = audit_writer

    def verify(
        self,
        model: str,
        observed_manifest_digest: str = "",
        observed_weights_sha256: str = "",
        request_id: str = "",
    ) -> VerifyResult:
        """Fail-closed: a store error returns ok=False (store_unavailable)."""
        try:
            pin = self._store.get(model)
        except PinStoreUnavailableError:
            logger.error(
                "model-integrity: pin store unavailable — fail-closed block model=%s", model
            )
            return VerifyResult(ok=False, model=model, reason="store_unavailable")

        if pin is None:
            # No pin for this model — not a mismatch, but not verified either.
            # Policy decision (caller): unpinned models pass unless strict mode.
            return VerifyResult(ok=True, model=model, reason="no_pin")

        if (
            pin.weights_sha256
            and observed_weights_sha256
            and observed_weights_sha256 != pin.weights_sha256
        ):
            self._emit_mismatch(model, pin.weights_sha256, observed_weights_sha256,
                                pin.manifest_digest, observed_manifest_digest, request_id)
            return VerifyResult(
                ok=False, model=model, reason="weights_mismatch",
                expected_weights=pin.weights_sha256, observed_weights=observed_weights_sha256,
            )

        if (
            pin.manifest_digest
            and observed_manifest_digest
            and observed_manifest_digest != pin.manifest_digest
        ):
            self._emit_mismatch(model, pin.weights_sha256, observed_weights_sha256,
                                pin.manifest_digest, observed_manifest_digest, request_id)
            return VerifyResult(
                ok=False, model=model, reason="manifest_mismatch",
                expected_manifest=pin.manifest_digest, observed_manifest=observed_manifest_digest,
            )

        return VerifyResult(ok=True, model=model, reason="match")

    def _emit_mismatch(self, model, exp_w, obs_w, exp_m, obs_m, request_id) -> None:
        logger.error(
            "MODEL_INTEGRITY_MISMATCH model=%s expected_weights=%s observed_weights=%s "
            "expected_manifest=%s observed_manifest=%s — BLOCK",
            model, exp_w, obs_w, exp_m, obs_m,
        )
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import ModelPinEvent, EventType
            self._audit.write(ModelPinEvent(
                event_type=EventType.MODEL_INTEGRITY_MISMATCH,
                request_id=request_id, model=model,
                old_weights_sha256=exp_w, new_weights_sha256=obs_w,
                old_manifest_digest=exp_m, new_manifest_digest=obs_m,
                action_taken="block",
            ))
        except Exception:  # pragma: no cover
            logger.exception("model-integrity: mismatch audit emit failed")


# ── Dual-control pin changes (corrected SOD-1/SOD-2 pattern) ────────────────

class ModelPinDualControl:
    """Two-admin pin changes. propose() by admin A with justification; approve()
    by a DIFFERENT admin B who re-supplies the confirming digest. The pending
    record is immutable while PENDING (a second propose is rejected)."""

    def __init__(self, store: ModelPinStore, redis_client, audit_writer=None) -> None:
        self._store = store
        self._r = redis_client
        self._audit = audit_writer

    def bootstrap(self, model: str, weights_sha256: str, manifest_digest: str,
                  actor_id: str) -> Pin:
        """TOFU: capture the first pin for a model under single installer
        authority. Write-ahead audit — fails closed if the audit write fails."""
        pin = Pin(model=model, weights_sha256=weights_sha256, manifest_digest=manifest_digest)
        self._audit_or_raise(
            "MODEL_PIN_BOOTSTRAPPED", model,
            new_w=weights_sha256, new_m=manifest_digest,
            initiated_by=actor_id, approver="", action="bootstrapped",
        )
        self._store.put(pin)
        logger.warning("MODEL_PIN_BOOTSTRAPPED model=%s by=%s", model, actor_id)
        return pin

    def propose(self, model: str, new_weights_sha256: str, new_manifest_digest: str,
                justification: str, initiator_id: str) -> str:
        just = (justification or "").strip()
        if len(just) < 4:
            raise DualControlError("A justification is required for a pin change.")
        if not new_weights_sha256 and not new_manifest_digest:
            raise DualControlError("At least one of weights/manifest digest is required.")

        key = _PENDING_KEY_PREFIX + model
        # Immutable while PENDING: reject a second proposal for the same model.
        try:
            if self._r.get(key):
                raise DualControlError(
                    "A pin change is already pending for this model; approve or let it expire.")
        except DualControlError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise PinStoreUnavailableError(str(exc)) from exc

        proposal_id = uuid.uuid4().hex
        record = {
            "proposal_id": proposal_id,
            "model": model,
            "new_weights_sha256": new_weights_sha256,
            "new_manifest_digest": new_manifest_digest,
            "justification": just,
            "initiated_by": initiator_id,
        }
        self._audit_or_raise(
            "MODEL_PIN_PROPOSED", model,
            new_w=new_weights_sha256, new_m=new_manifest_digest,
            initiated_by=initiator_id, approver="", action="proposed",
        )
        # NX + short TTL: the record cannot be overwritten while pending.
        self._r.set(key, json.dumps(record), ex=_PROPOSAL_WINDOW_SECONDS, nx=True)
        logger.warning("MODEL_PIN_PROPOSED model=%s by=%s proposal=%s — awaiting 2nd admin",
                       model, initiator_id, proposal_id)
        return proposal_id

    def approve(self, model: str, approver_id: str,
                confirming_weights_sha256: str, confirming_manifest_digest: str) -> Pin:
        key = _PENDING_KEY_PREFIX + model
        raw = self._r.get(key)
        if not raw:
            raise DualControlError("No pending pin change (the 5-minute window may have expired).")
        rec = json.loads(raw if isinstance(raw, str) else raw.decode())

        if rec["initiated_by"] == approver_id:
            raise DualControlError("The approver must be a DIFFERENT admin from the initiator.")

        # SOD-1: byte-compare the approver's confirming digest against the
        # IMMUTABLE pending record — not "whatever is currently pending".
        if confirming_weights_sha256 != rec["new_weights_sha256"]:
            self._audit_or_raise(
                "MODEL_PIN_REJECTED", model,
                new_w=confirming_weights_sha256, new_m=confirming_manifest_digest,
                initiated_by=rec["initiated_by"], approver=approver_id, action="rejected",
            )
            raise DualControlError("Confirming weights digest does not match the proposed pin.")
        if confirming_manifest_digest != rec["new_manifest_digest"]:
            self._audit_or_raise(
                "MODEL_PIN_REJECTED", model,
                new_w=confirming_weights_sha256, new_m=confirming_manifest_digest,
                initiated_by=rec["initiated_by"], approver=approver_id, action="rejected",
            )
            raise DualControlError("Confirming manifest digest does not match the proposed pin.")

        pin = Pin(
            model=model,
            weights_sha256=rec["new_weights_sha256"],
            manifest_digest=rec["new_manifest_digest"],
        )
        # SOD-2: write-ahead durable audit BEFORE the mutation.
        self._audit_or_raise(
            "MODEL_PIN_APPROVED", model,
            new_w=pin.weights_sha256, new_m=pin.manifest_digest,
            initiated_by=rec["initiated_by"], approver=approver_id, action="approved",
        )
        self._store.put(pin)
        self._r.delete(key)
        logger.warning("MODEL_PIN_APPROVED model=%s by=%s (proposed by %s)",
                       model, approver_id, rec["initiated_by"])
        return pin

    def _audit_or_raise(self, event_type: str, model: str, new_w: str, new_m: str,
                        initiated_by: str, approver: str, action: str) -> None:
        """Write-ahead durable audit (SOD-2): if the audit write fails, the
        caller's mutation must NOT proceed — raise, do not swallow."""
        if self._audit is None:
            return
        from yashigani.audit.schema import ModelPinEvent, EventType
        self._audit.write(ModelPinEvent(
            event_type=getattr(EventType, event_type),
            model=model,
            new_weights_sha256=new_w, new_manifest_digest=new_m,
            initiated_by=initiated_by, approver=approver, action_taken=action,
        ))
