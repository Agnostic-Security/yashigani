"""
Yashigani Document Enforcement — audit-obligation execution bridge (RESTART-013 gap #5).

Before this module existed, EVERY consumer of ``DocumentInspectionPipeline``
wired ``on_audit`` to a bare ``logger.info(...)`` (backoffice
``documents.py`` / ``user_ui.py``) or to nothing at all (the gateway's own
mode-B pipeline construction, ``gateway/entrypoint.py``, passed no callback —
the pipeline's default is a silent no-op).  ``policy/document.rego`` ALWAYS
returns ``"audit_document_decision"`` in its ``obligations`` list, but nothing
in the codebase ever dispatched that obligation into the tamper-evident audit
chain (``AuditLogWriter`` / ``backoffice_state.audit_writer`` /
``state["audit_writer"]``).  This closes that gap: every call site builds its
``on_audit`` callback via :func:`make_document_audit_callback`, which writes a
:class:`yashigani.audit.schema.DocumentEnforcementDecisionEvent` for every
pipeline decision (LOG/REDACT/PSEUDONYMIZE/BLOCK/ROUTE_LOCAL).

Design note — the two-pass call pattern:
    Every call site enumerates FIRST (``requested_action=LOG``, before the OPA
    decision is known) and only re-invokes ``pipeline.inspect()`` a SECOND time
    (with the OPA-decided action) when that action is not LOG.  The audit
    ``obligations`` list is only known AFTER the first pass returns (it comes
    from ``evaluate_document_decision()``).  Rather than rebuild the whole
    pipeline (re-constructing the extractor registry, etc.) once the decision
    is known, the caller passes a small MUTABLE context dict that it updates
    in place (``context["obligations"] = decision.get("obligations", [])``)
    between the two passes — the SAME callback closure reads the live values
    at write time.  This means the first (enumeration) pass's own audit event
    is written with the obligations still empty (the OPA decision has not run
    yet) — acceptable: that pass either duplicates as the final LOG event
    (whose own execution of THIS audit write IS the "audit_document_decision"
    obligation) or is superseded by the second pass's own richer event.

Fail-safe (audit is a side channel, never a gate): a missing ``audit_writer``
or a write failure is logged at WARNING/ERROR and NEVER blocks or alters the
pipeline's own decision — the pipeline's disposition (including any BLOCK) is
computed and returned regardless of whether the audit write succeeds.
"""
from __future__ import annotations

import contextlib
import contextvars
import logging
from typing import Any, Callable, Iterator, Optional

logger = logging.getLogger(__name__)


def make_document_audit_callback(
    audit_writer: Optional[Any],
    *,
    surface: str,
    context: Optional[dict] = None,
) -> Callable[[str, dict], None]:
    """Build a ``DocumentInspectionPipeline(on_audit=...)`` callback.

    Parameters
    ----------
    audit_writer:
        The wired ``AuditLogWriter`` (``backoffice_state.audit_writer`` /
        ``state["audit_writer"]``).  ``None`` is tolerated (dev/test without
        the chain wired) — the event is still logged at INFO, just not
        persisted to the tamper-evident chain.
    surface:
        Where this pipeline is invoked from (``"admin-inspect"`` |
        ``"user-upload"`` | ``"proxy-egress"`` | ``"mcp-tool-call"`` | ...) —
        carried on every event so the audit trail distinguishes the channel.
    context:
        Optional MUTABLE dict the caller updates between the enumeration pass
        and the apply pass (keys: ``identity_id``, ``tenant``,
        ``obligations``).  When omitted, every event carries the defaults
        (``identity_id=""``, ``tenant=""``, ``obligations=[]``).
    """
    ctx: dict = context if context is not None else {}

    def _audit(event_name: str, fields: dict) -> None:
        request_id = str(fields.get("request_id", ""))
        logger.info(
            "document audit event: %s surface=%s request_id=%s disposition=%s",
            event_name, surface, request_id, fields.get("disposition", ""),
        )
        if audit_writer is None:
            return
        try:
            from yashigani.audit.schema import DocumentEnforcementDecisionEvent

            audit_writer.write(
                DocumentEnforcementDecisionEvent(
                    request_id=request_id,
                    surface=surface,
                    disposition=str(fields.get("disposition", "")),
                    detected_format=str(fields.get("detected_format", "")),
                    match_count=int(fields.get("match_count", 0) or 0),
                    identity_id=str(ctx.get("identity_id", "") or ""),
                    tenant=str(ctx.get("tenant", "") or ""),
                    obligations=list(ctx.get("obligations") or []),
                    pipeline_event_type=str(event_name),
                    pipeline_audit_fields=fields,
                )
            )
        except Exception as exc:  # noqa: BLE001 — audit write must never break the pipeline call
            logger.error(
                "document audit write failed (surface=%s event=%s request_id=%s): %s",
                surface, event_name, request_id, exc,
            )

    return _audit


# ---------------------------------------------------------------------------
# Shared/singleton pipeline variant (gateway).
#
# The gateway's document_pipeline (gateway/entrypoint.py) is built ONCE at
# process startup and reused for every concurrent request (state["document_pipeline"]).
# A plain closure-captured mutable dict (the ``context=`` parameter above) is
# UNSAFE there: two concurrent requests interleaving across an ``await`` (e.g.
# the OPA round-trip in ``documents/proxy_modeb.egress_decide`` /
# ``documents/mcp_document_bridge.py`` between the enumeration pass and the
# apply pass) could race and cross-write each other's identity_id/obligations
# into the WRONG request's audit event.
#
# ``contextvars.ContextVar`` is the standard, asyncio-task-safe answer: each
# concurrently-running task gets its OWN value, with no cross-task leakage,
# even across ``await`` points — exactly the isolation a per-request context
# needs from a callback built once and shared by every request.
# ---------------------------------------------------------------------------

_shared_audit_context: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "yashigani_document_audit_context", default={}
)


@contextlib.contextmanager
def document_audit_scope(
    *,
    identity_id: str = "",
    tenant: str = "",
    obligations: Optional[list] = None,
    surface: Optional[str] = None,
) -> Iterator[None]:
    """Task-scoped context for :func:`make_shared_document_audit_callback`.

    Usage (per request, around the pipeline call(s) for THAT request only)::

        with document_audit_scope(identity_id=caller_identity_id, tenant=tenant):
            enum_result = pipeline.inspect(..., requested_action=LOG)
            decision = await evaluate_document_decision(...)
            update_document_audit_obligations(decision.get("obligations", []))
            result = pipeline.inspect(..., requested_action=opa_action)

    Reset on exit (even on exception) so nothing leaks into a sibling task that
    happens to reuse the same OS thread / event loop iteration.
    """
    token = _shared_audit_context.set(
        {
            "identity_id": identity_id,
            "tenant": tenant,
            "obligations": list(obligations or []),
            "surface": surface,
        }
    )
    try:
        yield
    finally:
        _shared_audit_context.reset(token)


def set_document_audit_context(
    *,
    identity_id: str = "",
    tenant: str = "",
    obligations: Optional[list] = None,
    surface: Optional[str] = None,
) -> None:
    """Set the CURRENT asyncio task's audit context directly (no ``with``
    block — for call sites where wrapping the whole function body in a
    context-manager ``with`` would require re-indenting a large amount of
    pre-existing code, e.g. ``documents/proxy_modeb.egress_decide``).

    ``surface`` optionally OVERRIDES the surface baked into
    :func:`make_shared_document_audit_callback` at construction time — this
    is what lets ONE shared pipeline instance (the gateway's singleton
    ``document_pipeline``) distinguish "generic proxy egress" from
    "MCP tool-call" in the audit trail without constructing a second pipeline.
    ``None`` (default) keeps whatever surface the callback was built with.

    Safe under concurrency WITHOUT an explicit reset: asyncio copies the
    context at Task creation (each inbound HTTP request is its own Task), so
    a ``.set()`` here mutates only the calling Task's own context — it can
    never leak into a sibling request's concurrently-running Task. The only
    residual risk is a SAME task reusing stale values from a PRIOR document
    on a LATER, unrelated call — call sites avoid this by calling
    :func:`set_document_audit_context` again at the start of every new
    document decision, which unconditionally overwrites the prior value."""
    _shared_audit_context.set(
        {
            "identity_id": identity_id,
            "tenant": tenant,
            "obligations": list(obligations or []),
            "surface": surface,
        }
    )


def update_document_audit_obligations(obligations: list) -> None:
    """Update the CURRENT task's obligations list mid-scope (after the OPA
    decision is known, before the second ``pipeline.inspect()`` apply-pass
    call) — mirrors the mutable-dict pattern's
    ``context["obligations"] = decision.get("obligations", [])`` update, but
    task-safe. No-op if called outside a :func:`document_audit_scope` block."""
    current = dict(_shared_audit_context.get())
    current["obligations"] = list(obligations or [])
    _shared_audit_context.set(current)


def make_shared_document_audit_callback(
    audit_writer: Optional[Any], *, surface: str,
) -> Callable[[str, dict], None]:
    """Build an ``on_audit`` callback for a SHARED/singleton pipeline instance
    (the gateway's single ``document_pipeline``, reused by every request).
    Reads the per-task context set by :func:`document_audit_scope` instead of
    a closure-captured dict — safe under concurrent requests."""

    def _audit(event_name: str, fields: dict) -> None:
        ctx = _shared_audit_context.get()
        effective_surface = str(ctx.get("surface") or surface)
        request_id = str(fields.get("request_id", ""))
        logger.info(
            "document audit event: %s surface=%s request_id=%s disposition=%s",
            event_name, effective_surface, request_id, fields.get("disposition", ""),
        )
        if audit_writer is None:
            return
        try:
            from yashigani.audit.schema import DocumentEnforcementDecisionEvent

            audit_writer.write(
                DocumentEnforcementDecisionEvent(
                    request_id=request_id,
                    surface=effective_surface,
                    disposition=str(fields.get("disposition", "")),
                    detected_format=str(fields.get("detected_format", "")),
                    match_count=int(fields.get("match_count", 0) or 0),
                    identity_id=str(ctx.get("identity_id", "") or ""),
                    tenant=str(ctx.get("tenant", "") or ""),
                    obligations=list(ctx.get("obligations") or []),
                    pipeline_event_type=str(event_name),
                    pipeline_audit_fields=fields,
                )
            )
        except Exception as exc:  # noqa: BLE001 — audit write must never break the pipeline call
            logger.error(
                "document audit write failed (surface=%s event=%s request_id=%s): %s",
                effective_surface, event_name, request_id, exc,
            )

    return _audit
