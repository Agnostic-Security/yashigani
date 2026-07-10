"""
Yashigani policy-bindings startup reconciler — LAURA-4.0-S1-001 (MEDIUM).

Problem
-------
Policy bindings for ``scope_kind="human"`` are evaluated by OPA against
``human:{identity_id}`` where ``identity_id`` is the ``idnt_`` PK issued by
the IdentityRegistry.  Bindings created before the endpoint was hardened
(or via the direct Redis path) may carry an email address or slug as their
``scope_id``.  Those never match the OPA key → silently ineffective.

Fix (startup reconcile)
-----------------------
``reconcile_binding_scope_ids()`` enumerates every PolicyBinding in the store
and for each ``scope_kind="human"`` binding whose ``scope_id`` does NOT begin
with ``idnt_``:

  * Email (``@`` present): derive canonical slug via ``email_to_slug``, look up
    via ``registry.get_by_slug``.
  * Slug (no ``@``): look up via ``registry.get_by_slug`` directly.

If the registry returns an identity, the binding is rewritten in-place to the
``idnt_`` PK.  The binding retains its original ``id`` and ``created_at`` so
audit-trail references remain valid.

Bindings whose ``scope_id`` cannot be resolved are left untouched but a
WARNING is logged and an audit event is emitted so operators can investigate.

After rewriting, if any bindings were updated and ``opa_url`` is provided, the
full binding document is re-pushed to OPA so the corrected bindings enforce
immediately (without waiting for the next mutation).

Idempotent: already-``idnt_``-prefixed bindings are skipped in O(1).

Standalone use
--------------
The function is importable and callable from scripts or the admin CLI without
running the full backoffice stack (it needs only a ``BindingStore`` and an
``IdentityRegistry`` instance).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from yashigani.policy_bindings.store import BindingStore
    from yashigani.identity.registry import IdentityRegistry

_log = logging.getLogger("yashigani.policy_bindings.reconcile")


def reconcile_binding_scope_ids(
    binding_store: "BindingStore",
    identity_registry: "IdentityRegistry",
    opa_url: Optional[str] = None,
    audit_writer=None,
) -> dict:
    """Normalise stale email/slug scope_ids in all human-scoped policy bindings.

    Parameters
    ----------
    binding_store:
        The live BindingStore backed by Redis db/3.
    identity_registry:
        The live IdentityRegistry backed by Redis db/3.
    opa_url:
        If provided and bindings were rewritten, push the corrected binding
        document to OPA at this URL so enforcement is immediate.
    audit_writer:
        If provided, emits a ``BindingScopeIdReconcileEvent`` summarising the
        run to the tamper-evident audit chain.

    Returns
    -------
    dict with keys:
        checked       — int, total human-scoped bindings examined.
        rewritten     — int, bindings rewritten to idnt_ PK.
        already_pk    — int, bindings already carrying an idnt_ PK (skipped).
        unresolvable  — int, bindings that could not be resolved (left in place).
        opa_re_pushed — bool, True if OPA was successfully re-synced.
    """
    from yashigani.identity.slug import email_to_slug

    checked = 0
    rewritten = 0
    already_pk = 0
    unresolvable = 0
    opa_re_pushed = False

    bindings = binding_store.list()
    for binding in bindings:
        if binding.scope_kind != "human":
            continue
        if not binding.scope_id:
            # Wildcard (all humans) — no scope_id to normalise.
            continue
        checked += 1

        if binding.scope_id.startswith("idnt_"):
            already_pk += 1
            continue

        # --- Attempt resolution ---
        resolved_id: Optional[str] = None
        try:
            if "@" in binding.scope_id:
                slug = email_to_slug(binding.scope_id)
                identity = identity_registry.get_by_slug(slug)
            else:
                identity = identity_registry.get_by_slug(binding.scope_id)
            if identity:
                candidate = identity.get("identity_id", "")
                if candidate.startswith("idnt_"):
                    resolved_id = candidate
        except Exception as exc:
            _log.warning(
                "BINDING-RECONCILE: resolution error for binding %s scope_id=%r: %s",
                binding.id, binding.scope_id, exc,
            )

        if resolved_id:
            old_scope_id = binding.scope_id
            updated = binding_store.rewrite_scope_id(binding.id, resolved_id)
            if updated:
                rewritten += 1
                _log.info(
                    "BINDING-RECONCILE: binding %s (policy=%s) scope_id %r -> %r "
                    "(LAURA-4.0-S1-001)",
                    binding.id, binding.policy_name, old_scope_id, resolved_id,
                )
        else:
            unresolvable += 1
            _log.warning(
                "BINDING-RECONCILE: UNRESOLVABLE binding %s (policy=%s scope_id=%r) — "
                "no matching identity in registry; binding left in place but WILL NOT "
                "ENFORCE until scope_id is corrected (LAURA-4.0-S1-001)",
                binding.id, binding.policy_name, binding.scope_id,
            )
            # Emit an individual warning audit event per unresolvable binding so
            # operators get a per-binding trace in the audit log, not just the summary.
            _emit_audit_unresolvable(audit_writer, binding)

    # --- OPA re-push if any bindings were rewritten ---
    if rewritten > 0 and opa_url:
        try:
            from yashigani.policy_bindings.opa_push import push_bindings_data
            push_bindings_data(binding_store, opa_url)
            opa_re_pushed = True
            _log.info(
                "BINDING-RECONCILE: OPA re-pushed after rewriting %d binding(s)", rewritten
            )
        except Exception as exc:
            _log.warning(
                "BINDING-RECONCILE: OPA re-push failed after rewriting %d binding(s): %s — "
                "bindings are correct in Redis and will enforce on next OPA restart/mutation",
                rewritten, exc,
            )

    summary = {
        "checked": checked,
        "rewritten": rewritten,
        "already_pk": already_pk,
        "unresolvable": unresolvable,
        "opa_re_pushed": opa_re_pushed,
    }
    _log.info(
        "BINDING-RECONCILE: complete — checked=%d rewritten=%d already_pk=%d "
        "unresolvable=%d opa_re_pushed=%s",
        checked, rewritten, already_pk, unresolvable, opa_re_pushed,
    )

    # --- Summary audit event ---
    if audit_writer is not None:
        try:
            from yashigani.audit.schema import BindingScopeIdReconcileEvent
            audit_writer.write(BindingScopeIdReconcileEvent(
                checked=checked,
                rewritten=rewritten,
                already_pk=already_pk,
                unresolvable=unresolvable,
                opa_re_pushed=opa_re_pushed,
            ))
        except Exception as exc:
            _log.error("BINDING-RECONCILE: audit write failed: %s", exc)

    return summary


def _emit_audit_unresolvable(audit_writer, binding) -> None:
    """Emit a PolicyBoundEvent-shaped warning for an unresolvable stale binding.

    We re-use PolicyBoundEvent (existing event type) rather than inventing a new
    one, flagging it via binding_id prefix so log-search identifies it:
        binding_id = "UNRESOLVABLE:<original_id>"

    This ensures the tamper-evident chain records every stale binding that was
    NOT corrected during reconcile.
    """
    if audit_writer is None:
        return
    try:
        from yashigani.audit.schema import PolicyBoundEvent
        audit_writer.write(PolicyBoundEvent(
            admin_account="SYSTEM:binding-reconcile",
            policy_name=binding.policy_name,
            scope_kind=binding.scope_kind,
            scope_id=binding.scope_id,
            direction=binding.direction,
            binding_id=f"UNRESOLVABLE:{binding.id}",
        ))
    except Exception as exc:
        _log.error("BINDING-RECONCILE: unresolvable audit write failed: %s", exc)
