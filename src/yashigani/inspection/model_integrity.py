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
from typing import Callable, Optional

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
    # "match" | "no_pin" | "weights_mismatch" | "manifest_mismatch"
    # | "store_unavailable" | "pin_unverifiable"
    #
    # "pin_unverifiable" (LAURA-V50-004): a pin EXISTS but nothing was actually
    # compared on either axis — pin.weights_sha256/manifest_digest were empty,
    # or the observed side was empty, on BOTH axes. This must never be reported
    # as "match" (a vacuous pin is not a verified pin). ok reflects the caller's
    # strict-mode choice (see ModelIntegrityVerifier.verify).
    reason: str
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
        strict: bool = False,
    ) -> VerifyResult:
        """Fail-closed: a store error returns ok=False (store_unavailable).

        LAURA-V50-004: a pin that COMPARES NOTHING must never report "match".
        Each axis (weights, manifest) is only "comparable" when BOTH the pin
        field and the observed field are non-empty. If a pin exists but NEITHER
        axis is comparable (empty pin fields, or the observed side is
        unavailable on both axes — e.g. weights unprobeable on this host
        topology AND an empty manifest_digest), the pin is vacuous: the dual-
        control ceremony may show "approved" but it enforces nothing. That
        state is reported as reason="pin_unverifiable", never "match".

        `strict` (caller passes YASHIGANI_MODEL_PIN_STRICT): when True, an
        unverifiable pin BLOCKS (ok=False) — the fail-safe default is to trust
        the operator's explicit opt-in over uptime. When False (default), it
        does not block (ok=True) so a legitimately-unprobeable platform (Mac
        host-native ollama; see model_probe.py) does not cause an outage — but
        it is never silent: a WARNING is logged and an audit event is written
        either way, so the vacuous state is always operator-visible.
        """
        try:
            pin = self._store.get(model)
        except PinStoreUnavailableError:
            logger.error(
                "model-integrity: pin store unavailable — fail-closed block model=%s", model
            )
            self._emit_store_unavailable(model, request_id)
            return VerifyResult(ok=False, model=model, reason="store_unavailable")

        if pin is None:
            # No pin for this model — not a mismatch, but not verified either.
            # Policy decision (caller): unpinned models pass unless strict mode.
            return VerifyResult(ok=True, model=model, reason="no_pin")

        weights_comparable = bool(pin.weights_sha256 and observed_weights_sha256)
        manifest_comparable = bool(pin.manifest_digest and observed_manifest_digest)

        if weights_comparable and observed_weights_sha256 != pin.weights_sha256:
            self._emit_mismatch(model, pin.weights_sha256, observed_weights_sha256,
                                pin.manifest_digest, observed_manifest_digest, request_id)
            return VerifyResult(
                ok=False, model=model, reason="weights_mismatch",
                expected_weights=pin.weights_sha256, observed_weights=observed_weights_sha256,
            )

        if manifest_comparable and observed_manifest_digest != pin.manifest_digest:
            self._emit_mismatch(model, pin.weights_sha256, observed_weights_sha256,
                                pin.manifest_digest, observed_manifest_digest, request_id)
            return VerifyResult(
                ok=False, model=model, reason="manifest_mismatch",
                expected_manifest=pin.manifest_digest, observed_manifest=observed_manifest_digest,
            )

        if not weights_comparable and not manifest_comparable:
            self._emit_unverifiable(model, pin, observed_weights_sha256,
                                    observed_manifest_digest, request_id, strict)
            return VerifyResult(
                ok=not strict, model=model, reason="pin_unverifiable",
                expected_weights=pin.weights_sha256, observed_weights=observed_weights_sha256,
                expected_manifest=pin.manifest_digest, observed_manifest=observed_manifest_digest,
            )

        return VerifyResult(ok=True, model=model, reason="match")

    def _emit_store_unavailable(self, model: str, request_id: str) -> None:
        """NDC follow-up (2026-07-31): the pin-store-unreachable branch fails
        closed (BLOCK) just like a genuine mismatch, but previously had NO
        audit trail — only the weights/manifest-mismatch and pin_unverifiable
        outcomes emitted an event. Best-effort; never blocks the deny."""
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import ModelPinEvent, EventType
            self._audit.write(ModelPinEvent(
                event_type=EventType.MODEL_PIN_STORE_UNAVAILABLE,
                request_id=request_id, model=model,
                action_taken="block",
            ))
        except Exception:  # pragma: no cover
            logger.exception("model-integrity: store-unavailable audit emit failed")

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

    def _emit_unverifiable(self, model: str, pin: Pin, obs_w: str, obs_m: str,
                           request_id: str, strict: bool) -> None:
        """LAURA-V50-004: a pin exists but compared nothing on either axis.
        Always loud (WARNING + audit) — this state must never be silent,
        strict or not."""
        logger.warning(
            "MODEL_PIN_UNVERIFIABLE model=%s pin_weights=%r pin_manifest=%r "
            "observed_weights=%r observed_manifest=%r strict=%s action=%s — "
            "the pin exists but enforces nothing: it was not compared on "
            "either axis (empty pin field, or the observed side is "
            "unavailable, on BOTH axes)",
            model, pin.weights_sha256, pin.manifest_digest, obs_w, obs_m,
            strict, "block" if strict else "warn",
        )
        if self._audit is None:
            return
        try:
            from yashigani.audit.schema import ModelPinEvent, EventType
            self._audit.write(ModelPinEvent(
                event_type=EventType.MODEL_PIN_UNVERIFIABLE,
                request_id=request_id, model=model,
                old_weights_sha256=pin.weights_sha256, new_weights_sha256=obs_w,
                old_manifest_digest=pin.manifest_digest, new_manifest_digest=obs_m,
                action_taken="block" if strict else "warn",
            ))
        except Exception:  # pragma: no cover
            logger.exception("model-integrity: unverifiable audit emit failed")


# ── Dual-control pin changes (corrected SOD-1/SOD-2 pattern) ────────────────

class ModelPinDualControl:
    """Two-admin pin changes. propose() by admin A with justification; approve()
    by a DIFFERENT admin B who re-supplies the confirming digest. The pending
    record is immutable while PENDING (a second propose is rejected)."""

    def __init__(self, store: ModelPinStore, redis_client, audit_writer=None,
                probe_manifest_digest_fn: Optional[Callable[[str], str]] = None) -> None:
        self._store = store
        self._r = redis_client
        self._audit = audit_writer
        # LAURA-V50-004 rec #2: best-effort live-probe callback the caller can
        # wire (backoffice: model_probe.probe_manifest_digests against ollama)
        # to auto-populate manifest_digest when the admin didn't supply one —
        # so the dual-control ceremony records a REAL, comparable anchor
        # instead of silently accepting an empty one. Optional/DI so this
        # module stays network-free and unit-testable.
        self._probe_manifest_digest_fn = probe_manifest_digest_fn

    def _autofill_manifest_digest(self, model: str, weights_sha256: str,
                                  manifest_digest: str) -> str:
        """If manifest_digest was not supplied and a probe callback is wired,
        best-effort fetch the model's CURRENT observed manifest digest so the
        pin commits to a real anchor. Never raises — probe failure just leaves
        manifest_digest as supplied (empty), and the caller's own
        both-empty check then rejects the vacuous pin."""
        if manifest_digest or self._probe_manifest_digest_fn is None:
            return manifest_digest
        try:
            observed = self._probe_manifest_digest_fn(model)
        except Exception as exc:  # noqa: BLE001 — best-effort, never block on probe errors
            logger.warning(
                "model-integrity: live manifest-digest probe failed for model=%s (%s) — "
                "pin will proceed with the digest as supplied", model, exc,
            )
            return manifest_digest
        if observed:
            logger.info(
                "model-integrity: auto-populated manifest_digest for model=%s from live probe "
                "(admin did not supply one)", model,
            )
            return observed
        return manifest_digest

    def bootstrap(self, model: str, weights_sha256: str, manifest_digest: str,
                  actor_id: str) -> Pin:
        """TOFU: capture the first pin for a model under single installer
        authority. Write-ahead audit — fails closed if the audit write fails.

        LAURA-V50-004: reject a pin with NO usable anchor (both digests empty
        after best-effort live-probe autofill) — a pin must commit to at
        least one real, comparable anchor. This is what let the live
        qwen2.5:3b pin ship with an empty manifest_digest and an unprobeable
        weights anchor, enforcing nothing while showing "approved"."""
        manifest_digest = self._autofill_manifest_digest(model, weights_sha256, manifest_digest)
        if not weights_sha256 and not manifest_digest:
            raise DualControlError(
                "A pin requires at least one non-empty anchor (weights_sha256 or "
                "manifest_digest); none was supplied and none could be observed "
                "from a live probe for this model."
            )
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
        new_manifest_digest = self._autofill_manifest_digest(
            model, new_weights_sha256, new_manifest_digest)
        if not new_weights_sha256 and not new_manifest_digest:
            raise DualControlError(
                "At least one of weights/manifest digest is required (none was "
                "supplied and none could be observed from a live probe)."
            )

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
