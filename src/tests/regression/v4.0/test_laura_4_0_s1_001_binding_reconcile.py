"""
Regression tests — LAURA-4.0-S1-001 residuals (policy-binding scope_id normalisation).

MEDIUM residual — scope_id backfill / startup reconcile:
  Existing policy bindings stored with an email or slug as scope_id are NOT
  evaluated by OPA (it keys on ``human:idnt_...``).  A startup reconciler
  must detect and rewrite those bindings to the canonical idnt_ PK so they
  enforce after upgrade.  Idempotent: already-PK bindings must not be mutated.

LOW residual — phantom idnt_ rejection at bind endpoint:
  POST /admin/policies/bind with scope_kind=human and a scope_id that begins
  with ``idnt_`` but has NO matching identity in the registry must return HTTP
  400 (not silently accept a no-op binding).

Each test would fail on pre-fix code:
  - MEDIUM: reconcile_binding_scope_ids did not exist; stale email bindings
    were never rewritten; they persisted in Redis with the original email and
    never matched OPA's ``human:idnt_...`` key.
  - LOW: bind_policy accepted any idnt_-prefixed scope_id without registry
    validation, silently storing an ineffective binding.

Refs: LAURA-4.0-S1-001, PENTEST-4.0-round3.md re-verify section.
Retro rule T4: regression test per Python-level fix.
"""

from __future__ import annotations

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_binding(
    policy_name: str = "test_policy",
    scope_kind: str = "human",
    scope_id: str = "ana@agnosticsec.com",
    direction: str = "both",
) -> MagicMock:
    """Create a mock PolicyBinding matching the dataclass API."""
    b = MagicMock()
    b.policy_name = policy_name
    b.scope_kind = scope_kind
    b.scope_id = scope_id
    b.direction = direction
    b.enabled = True
    b.id = uuid.uuid4().hex
    return b


def _make_identity(identity_id: str, slug: str, kind: str = "human") -> dict:
    return {
        "identity_id": identity_id,
        "kind": kind,
        "name": "Test User",
        "slug": slug,
        "status": "active",
    }


# ---------------------------------------------------------------------------
# MEDIUM — startup reconcile: email/slug → idnt_ rewrite
# ---------------------------------------------------------------------------

class TestBindingScopeIdReconcile:
    """reconcile_binding_scope_ids() rewrites stale email/slug bindings."""

    def _make_binding_store(self, bindings: list) -> MagicMock:
        store = MagicMock()
        store.list.return_value = bindings
        store.rewrite_scope_id.side_effect = lambda bid, new_id: (
            next((b for b in bindings if b.id == bid), None)
        )
        return store

    def _make_registry(self, slug_map: dict[str, dict]) -> MagicMock:
        """slug_map: {slug: identity_dict}.  Also supports get(identity_id)."""
        registry = MagicMock()
        registry.get_by_slug.side_effect = lambda slug: slug_map.get(slug)
        # get(identity_id) returns None by default (we don't need it here)
        registry.get.return_value = None
        return registry

    def test_email_binding_rewritten_to_idnt_pk(self):
        """An email-scoped binding is rewritten to the idnt_ PK."""
        identity_id = "idnt_abc123"
        slug = "ana-agnosticsec-com"
        binding = _make_binding(scope_id="ana@agnosticsec.com")
        store = self._make_binding_store([binding])
        registry = self._make_registry({slug: _make_identity(identity_id, slug)})

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["rewritten"] == 1
        assert result["unresolvable"] == 0
        assert result["already_pk"] == 0
        assert result["checked"] == 1
        store.rewrite_scope_id.assert_called_once_with(binding.id, identity_id)

    def test_slug_binding_rewritten_to_idnt_pk(self):
        """A slug-scoped binding (no '@') is rewritten to the idnt_ PK."""
        identity_id = "idnt_def456"
        slug = "spark"
        binding = _make_binding(scope_id="spark")
        store = self._make_binding_store([binding])
        registry = self._make_registry({slug: _make_identity(identity_id, slug)})

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["rewritten"] == 1
        store.rewrite_scope_id.assert_called_once_with(binding.id, identity_id)

    def test_already_pk_binding_is_skipped(self):
        """A binding already carrying an idnt_ PK is counted as already_pk and NOT mutated."""
        binding = _make_binding(scope_id="idnt_already000")
        store = self._make_binding_store([binding])
        registry = MagicMock()

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["already_pk"] == 1
        assert result["rewritten"] == 0
        assert result["checked"] == 1
        store.rewrite_scope_id.assert_not_called()

    def test_non_human_scope_binding_is_not_checked(self):
        """Bindings with scope_kind != 'human' are not subject to normalisation."""
        binding = _make_binding(scope_kind="agent", scope_id="some-agent")
        store = self._make_binding_store([binding])
        registry = MagicMock()

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["checked"] == 0
        assert result["rewritten"] == 0
        store.rewrite_scope_id.assert_not_called()

    def test_unresolvable_binding_left_in_place_with_warning(self):
        """An unresolvable scope_id is left in Redis but counted as unresolvable."""
        binding = _make_binding(scope_id="nobody@nowhere.example")
        store = self._make_binding_store([binding])
        # slug_map empty → registry returns None for all slugs
        registry = self._make_registry({})

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["unresolvable"] == 1
        assert result["rewritten"] == 0
        # Binding not mutated
        store.rewrite_scope_id.assert_not_called()

    def test_idempotent_on_second_run(self):
        """Running the reconcile twice on the same store is safe (already_pk path)."""
        # Simulate that after the first run the binding now has an idnt_ scope_id
        binding = _make_binding(scope_id="idnt_already000")
        store = self._make_binding_store([binding])
        registry = MagicMock()

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        r1 = reconcile_binding_scope_ids(store, registry)
        r2 = reconcile_binding_scope_ids(store, registry)

        assert r1["rewritten"] == 0
        assert r2["rewritten"] == 0
        store.rewrite_scope_id.assert_not_called()

    def test_opa_repush_called_on_rewrite(self):
        """OPA is re-pushed when at least one binding is rewritten."""
        identity_id = "idnt_abc999"
        slug = "ana-agnosticsec-com"
        binding = _make_binding(scope_id="ana@agnosticsec.com")
        store = self._make_binding_store([binding])
        registry = self._make_registry({slug: _make_identity(identity_id, slug)})

        # push_bindings_data is imported lazily inside reconcile(); patch at its
        # source module so the import inside the function resolves to the mock.
        with patch("yashigani.policy_bindings.opa_push.push_bindings_data") as mock_push:
            from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
            result = reconcile_binding_scope_ids(
                store, registry, opa_url="https://policy:8181"
            )
            mock_push.assert_called_once()
            assert result["opa_re_pushed"] is True

    def test_opa_not_repushed_when_nothing_rewritten(self):
        """OPA push is NOT called when all bindings are already correct."""
        binding = _make_binding(scope_id="idnt_already000")
        store = self._make_binding_store([binding])
        registry = MagicMock()

        with patch("yashigani.policy_bindings.opa_push.push_bindings_data") as mock_push:
            from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
            result = reconcile_binding_scope_ids(
                store, registry, opa_url="https://policy:8181"
            )
            mock_push.assert_not_called()
            assert result["opa_re_pushed"] is False

    def test_audit_event_emitted_on_completion(self):
        """A BindingScopeIdReconcileEvent is written to the audit chain."""
        binding = _make_binding(scope_id="idnt_already000")
        store = self._make_binding_store([binding])
        registry = MagicMock()
        audit_writer = MagicMock()

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        from yashigani.audit.schema import BindingScopeIdReconcileEvent
        reconcile_binding_scope_ids(store, registry, audit_writer=audit_writer)

        audit_writer.write.assert_called_once()
        event = audit_writer.write.call_args[0][0]
        assert isinstance(event, BindingScopeIdReconcileEvent)
        assert event.already_pk == 1

    def test_mixed_bindings_correct_counts(self):
        """Mixed set: 1 email, 1 slug, 1 already-PK, 1 service, 1 unresolvable."""
        identity_id_a = "idnt_aaa111"
        identity_id_b = "idnt_bbb222"

        b_email = _make_binding(scope_kind="human", scope_id="ana@agnosticsec.com")
        b_slug = _make_binding(scope_kind="human", scope_id="spark")
        b_pk = _make_binding(scope_kind="human", scope_id="idnt_already000")
        b_service = _make_binding(scope_kind="service", scope_id="svc-gateway")
        b_unresolvable = _make_binding(scope_kind="human", scope_id="ghost@nowhere.invalid")

        store = self._make_binding_store([b_email, b_slug, b_pk, b_service, b_unresolvable])
        registry = self._make_registry({
            "ana-agnosticsec-com": _make_identity(identity_id_a, "ana-agnosticsec-com"),
            "spark": _make_identity(identity_id_b, "spark"),
        })

        from yashigani.policy_bindings.reconcile import reconcile_binding_scope_ids
        result = reconcile_binding_scope_ids(store, registry)

        assert result["checked"] == 4          # 3 human non-wildcard (email+slug+unresolvable) + 1 already_pk
        assert result["rewritten"] == 2         # email + slug
        assert result["already_pk"] == 1        # b_pk
        assert result["unresolvable"] == 1      # ghost@nowhere.invalid
        assert result["opa_re_pushed"] is False  # opa_url not supplied


# ---------------------------------------------------------------------------
# LOW — bind endpoint: phantom idnt_ → HTTP 400
# ---------------------------------------------------------------------------

class TestBindEndpointPhantomIdnt:
    """POST /admin/policies/bind with a phantom idnt_ rejects with 400."""

    def _setup_backoffice_state(self, identity_id_map: dict):
        """
        identity_id_map: {idnt_xxx: identity_dict} or {} for phantom.
        Returns a context manager that patches backoffice_state.
        """
        registry = MagicMock()
        # registry.get(identity_id) → look up by PK
        registry.get.side_effect = lambda iid: identity_id_map.get(iid)
        # registry.get_by_slug not called for idnt_ inputs
        registry.get_by_slug.return_value = None

        binding_store = MagicMock()
        binding_store.list.return_value = []

        state = MagicMock()
        state.identity_registry = registry
        state.binding_store = binding_store
        state.opa_url = "https://policy:8181"
        state.audit_writer = MagicMock()
        return state

    @pytest.mark.asyncio
    async def test_phantom_idnt_scope_id_returns_400(self):
        """POST /bind with scope_kind=human and idnt_FAKE that doesn't exist → 400."""
        from fastapi import HTTPException
        from yashigani.backoffice.routes.policies import bind_policy, BindRequest

        state = self._setup_backoffice_state({})  # empty registry → phantom

        body = BindRequest(
            policy_name="test_policy",
            scope_kind="human",
            scope_id="idnt_FAKEFAKEFAKE",
            direction="both",
        )
        session = MagicMock()
        session.account_id = "admin-uuid"

        with patch("yashigani.backoffice.routes.policies.backoffice_state", state), \
             patch("yashigani.backoffice.routes.policies._client_policy_loaded", AsyncMock(return_value=True)):
            with pytest.raises(HTTPException) as exc_info:
                await bind_policy(body, session)

            assert exc_info.value.status_code == 400
            detail = exc_info.value.detail
            assert detail["error"] == "invalid_scope_id"
            assert "idnt_FAKEFAKEFAKE" in detail["message"]
            assert "not found" in detail["message"].lower() or "registry" in detail["message"].lower()

    @pytest.mark.asyncio
    async def test_valid_idnt_scope_id_accepted(self):
        """POST /bind with a real idnt_ PK that exists in registry succeeds."""
        from yashigani.backoffice.routes.policies import bind_policy, BindRequest
        from yashigani.policy_bindings.store import PolicyBinding

        real_id = "idnt_real123"
        state = self._setup_backoffice_state({
            real_id: _make_identity(real_id, "real-user"),
        })

        # Wire a minimal binding add
        added_binding = PolicyBinding(
            policy_name="test_policy",
            scope_kind="human",
            scope_id=real_id,
            direction="both",
        )
        state.binding_store.add.return_value = added_binding

        body = BindRequest(
            policy_name="test_policy",
            scope_kind="human",
            scope_id=real_id,
            direction="both",
        )
        session = MagicMock()
        session.account_id = "admin-uuid"

        with patch("yashigani.backoffice.routes.policies.backoffice_state", state), \
             patch("yashigani.backoffice.routes.policies._client_policy_loaded", AsyncMock(return_value=True)), \
             patch("yashigani.backoffice.routes.policies._push_bindings", AsyncMock()):
            result = await bind_policy(body, session)

        assert result["status"] == "ok"
        assert result["binding"]["scope_id"] == real_id

    @pytest.mark.asyncio
    async def test_email_scope_id_still_normalised_to_idnt(self):
        """POST /bind with an email scope_id is still normalised to idnt_ PK."""
        from yashigani.backoffice.routes.policies import bind_policy, BindRequest
        from yashigani.policy_bindings.store import PolicyBinding

        real_id = "idnt_email123"
        slug = "ana-agnosticsec-com"
        state = self._setup_backoffice_state({})
        state.identity_registry.get_by_slug.side_effect = lambda s: (
            _make_identity(real_id, slug) if s == slug else None
        )

        added_binding = PolicyBinding(
            policy_name="test_policy",
            scope_kind="human",
            scope_id=real_id,
            direction="ingress",
        )
        state.binding_store.add.return_value = added_binding

        body = BindRequest(
            policy_name="test_policy",
            scope_kind="human",
            scope_id="ana@agnosticsec.com",
            direction="ingress",
        )
        session = MagicMock()
        session.account_id = "admin-uuid"

        with patch("yashigani.backoffice.routes.policies.backoffice_state", state), \
             patch("yashigani.backoffice.routes.policies._client_policy_loaded", AsyncMock(return_value=True)), \
             patch("yashigani.backoffice.routes.policies._push_bindings", AsyncMock()):
            result = await bind_policy(body, session)

        # The binding stored in OPA should carry the idnt_ PK, not the email.
        assert result["binding"]["scope_id"] == real_id

    @pytest.mark.asyncio
    async def test_nonhuman_scope_id_bypasses_registry_check(self):
        """Non-human scope_kinds (service, agent, etc.) skip registry validation."""
        from yashigani.backoffice.routes.policies import bind_policy, BindRequest
        from yashigani.policy_bindings.store import PolicyBinding

        state = self._setup_backoffice_state({})  # empty registry

        added_binding = PolicyBinding(
            policy_name="test_policy",
            scope_kind="agent",
            scope_id="my-agent-slug",
            direction="egress",
        )
        state.binding_store.add.return_value = added_binding

        body = BindRequest(
            policy_name="test_policy",
            scope_kind="agent",
            scope_id="my-agent-slug",
            direction="egress",
        )
        session = MagicMock()
        session.account_id = "admin-uuid"

        with patch("yashigani.backoffice.routes.policies.backoffice_state", state), \
             patch("yashigani.backoffice.routes.policies._client_policy_loaded", AsyncMock(return_value=True)), \
             patch("yashigani.backoffice.routes.policies._push_bindings", AsyncMock()):
            result = await bind_policy(body, session)

        assert result["status"] == "ok"
        # registry.get must NOT have been called for a non-human scope
        state.identity_registry.get.assert_not_called()
        state.identity_registry.get_by_slug.assert_not_called()
