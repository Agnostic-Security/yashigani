"""
Regression tests for LAURA-412-001 (HIGH) — cloud-model DENY bypassable via
model-string variants.

Proven live bypasses (restricted_user, explicit allow=false on openai:gpt-4o):
  • openai:gpt-4o.      (trailing dot)
  • openai::gpt-4o      (double colon)
  • openai://gpt-4o     (URL-proto with known provider prefix)

Root cause:
  normalize_model_for_deny() only lowercased + converted single-slash to colon
  when no colon was present.  Trailing punctuation, consecutive separators, and
  ://  forms were NOT collapsed → the DENY lookup key-missed the stored grant
  key "openai:gpt-4o" → silent local fallback served content (200).

Fix:
  1. _validate_model_string(): reject any "://" form → 422 url_not_allowed.
  2. normalize_model_for_deny(): after existing step:
       a) re.sub(r"[:/]+", ":", norm)  — collapse consecutive separators
       b) norm.strip(" .:;,/")         — strip leading/trailing punctuation
  3. _is_known_model(): use normalize_model_for_deny so known-check and
     DENY-check operate on the same canonical form.

All DENY-variant inputs for restricted_user must return 403 or 422 — NEVER 200.
power_user (allowed) variants must not 403.
Local installed model must not 422.

Last updated: 2026-07-15T00:00:00+00:00
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ===========================================================================
# Unit: normalize_model_for_deny — LAURA-412-001 new canonicalization steps
# ===========================================================================

class TestNormalizeModelForDenyL412:
    """Comprehensive coverage of all separator/punctuation bypass variants."""

    def _norm(self, s: str) -> str:
        from yashigani.models.effective import normalize_model_for_deny
        return normalize_model_for_deny(s)

    # ── trailing punctuation ─────────────────────────────────────────────

    def test_trailing_dot(self):
        """openai:gpt-4o. must canonicalize to openai:gpt-4o."""
        assert self._norm("openai:gpt-4o.") == "openai:gpt-4o"

    def test_trailing_double_dot(self):
        assert self._norm("openai:gpt-4o..") == "openai:gpt-4o"

    def test_trailing_semicolon(self):
        assert self._norm("openai:gpt-4o;") == "openai:gpt-4o"

    def test_trailing_comma(self):
        assert self._norm("openai:gpt-4o,") == "openai:gpt-4o"

    # ── consecutive separators ───────────────────────────────────────────

    def test_double_colon(self):
        """openai::gpt-4o must canonicalize to openai:gpt-4o."""
        assert self._norm("openai::gpt-4o") == "openai:gpt-4o"

    def test_triple_colon(self):
        assert self._norm("openai:::gpt-4o") == "openai:gpt-4o"

    def test_double_slash_no_colon(self):
        """openai//gpt-4o (no colon) must canonicalize to openai:gpt-4o."""
        assert self._norm("openai//gpt-4o") == "openai:gpt-4o"

    def test_colon_slash(self):
        """openai:/gpt-4o must canonicalize to openai:gpt-4o."""
        assert self._norm("openai:/gpt-4o") == "openai:gpt-4o"

    def test_double_colon_double_slash(self):
        """openai:://gpt-4o collapses to openai:gpt-4o."""
        assert self._norm("openai:://gpt-4o") == "openai:gpt-4o"

    # ── URL-proto variant (should be caught upstream, normalize handles it too) ─

    def test_url_proto_variant(self):
        """openai://gpt-4o → openai:gpt-4o via consecutive-separator collapse.
        NOTE: _validate_model_string now rejects :// → 422; this tests that
        normalize also handles it defensively (belt-and-braces)."""
        assert self._norm("openai://gpt-4o") == "openai:gpt-4o"

    # ── case + separator combo ───────────────────────────────────────────

    def test_uppercase_url_proto(self):
        """OPENAI://GPT-4O → openai:gpt-4o."""
        assert self._norm("OPENAI://GPT-4O") == "openai:gpt-4o"

    # ── leading punctuation ──────────────────────────────────────────────

    def test_leading_colon(self):
        """Leading colon stripped: :openai:gpt-4o → openai:gpt-4o."""
        assert self._norm(":openai:gpt-4o") == "openai:gpt-4o"

    # ── surrounding spaces (already handled by strip(), guard stays) ─────

    def test_surrounding_spaces(self):
        assert self._norm(" openai:gpt-4o ") == "openai:gpt-4o"

    # ── canonical form unchanged ─────────────────────────────────────────

    def test_canonical_unchanged(self):
        """openai:gpt-4o (already canonical) must remain openai:gpt-4o."""
        assert self._norm("openai:gpt-4o") == "openai:gpt-4o"

    def test_local_model_unchanged(self):
        """qwen2.5:3b must remain qwen2.5:3b (dot in model tag is expected)."""
        assert self._norm("qwen2.5:3b") == "qwen2.5:3b"

    def test_slash_separator_still_normalizes(self):
        """openai/gpt-4o → openai:gpt-4o (existing LAURA-411-002 behaviour)."""
        assert self._norm("openai/gpt-4o") == "openai:gpt-4o"

    def test_empty_returns_empty(self):
        from yashigani.models.effective import normalize_model_for_deny
        assert normalize_model_for_deny("") == ""
        assert normalize_model_for_deny(None) == ""  # type: ignore[arg-type]


# ===========================================================================
# Unit: is_model_denied — all 13+ variant forms for restricted_user
# ===========================================================================

class TestIsModelDeniedL412:
    """is_model_denied must return True for EVERY variant of a denied model."""

    def _restricted(self):
        from yashigani.models.effective import EffectiveModels
        return EffectiveModels(
            allowed={"qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases=set(),
            gated={"openai:gpt-4o"},
        )

    def _power(self):
        from yashigani.models.effective import EffectiveModels
        return EffectiveModels(
            allowed={"openai:gpt-4o", "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={"openai:gpt-4o"},
            gated={"openai:gpt-4o"},
        )

    @pytest.mark.parametrize("model_variant", [
        "openai:gpt-4o.",          # trailing dot — proven bypass
        "openai::gpt-4o",          # double colon — proven bypass
        "openai://gpt-4o",         # URL-proto — proven bypass (also 422 upstream)
        "openai:::gpt-4o",         # triple colon
        "openai:/gpt-4o",          # colon-slash
        "openai//gpt-4o",          # double slash
        "OPENAI://GPT-4O",         # upper + URL-proto
        "openai:gpt-4o..",         # double trailing dot
        "openai:gpt-4o;",          # trailing semicolon
        "openai:gpt-4o,",          # trailing comma
        " openai:gpt-4o ",         # surrounding spaces
        "openai/gpt-4o",           # slash separator (LAURA-411 existing)
        "openai:gpt-4o",           # canonical (regression guard)
    ])
    def test_restricted_user_denied_all_variants(self, model_variant):
        """All variant forms of a denied model must be denied for restricted_user."""
        eff = self._restricted()
        assert eff.is_model_denied(model_variant) is True, (
            f"is_model_denied({model_variant!r}) must be True for restricted_user; "
            "this variant bypasses the DENY check"
        )

    @pytest.mark.parametrize("model_variant", [
        "openai:gpt-4o.",
        "openai::gpt-4o",
        "openai://gpt-4o",
        "openai///gpt-4o",
        "openai:gpt-4o..",
        "OPENAI:GPT-4O",
        "openai/gpt-4o",
        "openai:gpt-4o",
    ])
    def test_power_user_not_denied_variants(self, model_variant):
        """power_user (openai:gpt-4o allocated) must NOT be denied any variant."""
        eff = self._power()
        assert eff.is_model_denied(model_variant) is False, (
            f"is_model_denied({model_variant!r}) must be False for power_user; "
            "allocated user is being incorrectly denied"
        )

    def test_allowed_local_not_denied(self):
        """qwen2.5:3b (allocated to restricted_user) must NOT be denied."""
        eff = self._restricted()
        assert eff.is_model_denied("qwen2.5:3b") is False

    def test_unknown_model_denied_when_restricted(self):
        """A model not in allowed and not in gated is denied when has_restriction=True."""
        eff = self._restricted()
        assert eff.is_model_denied("anthropic:claude-3-5-sonnet") is True


# ===========================================================================
# Unit: _validate_model_string — LAURA-412-001 :// rejection
# ===========================================================================

class TestValidateModelStringL412:
    """_validate_model_string must reject any ://  scheme form."""

    def _validate(self, s: str):
        from yashigani.gateway.openai_router import _validate_model_string
        return _validate_model_string(s)

    def test_openai_url_proto_rejected(self):
        err = self._validate("openai://gpt-4o")
        assert err == "url_not_allowed", (
            f"openai://gpt-4o must return url_not_allowed, got {err!r}"
        )

    def test_anthropic_url_proto_rejected(self):
        assert self._validate("anthropic://claude-3") == "url_not_allowed"

    def test_arbitrary_scheme_rejected(self):
        assert self._validate("unknown://model") == "url_not_allowed"

    def test_uppercase_proto_rejected(self):
        assert self._validate("OPENAI://GPT-4O") == "url_not_allowed"

    def test_existing_http_still_rejected(self):
        assert self._validate("http://openai.com/gpt-4o") == "url_not_allowed"

    def test_existing_https_still_rejected(self):
        assert self._validate("https://openai.com/gpt-4o") == "url_not_allowed"

    def test_canonical_not_rejected(self):
        assert self._validate("openai:gpt-4o") is None

    def test_double_colon_not_rejected_by_validate(self):
        """openai::gpt-4o has :: but NOT ://; should NOT be 422 from validate
        (it will be handled by normalize_model_for_deny → denied at RBAC)."""
        assert self._validate("openai::gpt-4o") is None

    def test_trailing_dot_not_rejected_by_validate(self):
        """openai:gpt-4o. has trailing dot; should NOT be 422 from validate
        (normalize_model_for_deny strips it; RBAC fires)."""
        assert self._validate("openai:gpt-4o.") is None


# ===========================================================================
# Unit: _is_known_model — canonicalization consistency (LAURA-412-001)
# ===========================================================================

class TestIsKnownModelL412:
    """_is_known_model must use normalize_model_for_deny for canonical form
    so known-check and DENY-check both operate on the same canonical value."""

    def _known(self, model, alias_store=None, available_models=None):
        from yashigani.gateway.openai_router import _is_known_model
        return _is_known_model(model, alias_store, available_models or [])

    def _alias_store_for(self, *known_keys):
        store = MagicMock()
        store.get.side_effect = lambda k: (MagicMock() if k in known_keys else None)
        return store

    def test_double_colon_variant_known_as_cloud(self):
        """openai::gpt-4o must be known as a cloud model (canonicalizes to openai:gpt-4o)."""
        assert self._known("openai::gpt-4o") is True

    def test_trailing_dot_variant_known_as_cloud(self):
        """openai:gpt-4o. must be known as a cloud model."""
        assert self._known("openai:gpt-4o.") is True

    def test_colon_slash_variant_known_as_cloud(self):
        """openai:/gpt-4o must be known as a cloud model."""
        assert self._known("openai:/gpt-4o") is True

    def test_url_proto_caught_upstream_but_canonicalizes_correctly(self):
        """openai://gpt-4o canonicalizes to openai:gpt-4o via normalize;
        _is_known_model would return True BUT it never reaches this function
        in practice because _validate_model_string returns url_not_allowed first."""
        # Defensive test: even if somehow it reaches _is_known_model, canonical form
        # must be used (not the raw :// form).
        result = self._known("openai://gpt-4o")
        assert result is True, (
            "openai://gpt-4o canonicalizes to openai:gpt-4o → cloud-known=True. "
            "In practice this is caught upstream by _validate_model_string → 422."
        )

    def test_local_model_still_known_via_available(self):
        """qwen2.5:3b in available_models (id-keyed, production shape) must be known."""
        store = MagicMock()
        store.get.return_value = None
        available = [{"id": "qwen2.5:3b"}]
        assert self._known("qwen2.5:3b", alias_store=store, available_models=available) is True

    def test_unknown_model_not_known(self):
        store = MagicMock()
        store.get.return_value = None
        available = [{"id": "qwen2.5:3b"}]
        assert self._known("nobody:unknown-model", alias_store=store, available_models=available) is False


# ===========================================================================
# E2E: drive chat_completions for ALL variant forms — restricted_user
# Must return 403 or 422 — NEVER 200 with qwen2.5:3b content
# ===========================================================================

class TestDenyVariantsE2EL412:
    """End-to-end route-level test: ALL separator/punctuation variant forms of
    a denied cloud model must be 403 (DENY at RBAC) or 422 (invalid input)."""

    def _make_state(self):
        alias_store = MagicMock()
        alias_store.get.side_effect = lambda k: (
            MagicMock() if k.lower().strip(".:;,/ ").replace("::", ":") in
            ("gpt-4o", "openai:gpt-4o") else None
        )
        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "qwen2.5:3b"
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.permission_store = None
        state.permission_strict = False
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = alias_store
        state.available_models = [{"name": "qwen2.5:3b"}]
        state.model_allocation_store = None
        state.audit_writer = None
        state.identity_registry = None
        state.agent_registry = None
        state.pool_manager = None
        state.pii_detector = None
        state.streaming_enabled = False
        state.streaming_inspect_interval = 200
        state.response_inspection_pipeline = None
        state.low_confidence_stepup_threshold = 0.7
        return state

    def _restricted_effective(self):
        from yashigani.models.effective import EffectiveModels
        return EffectiveModels(
            allowed={"qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases=set(),
            gated={"openai:gpt-4o"},
        )

    def _make_request(self):
        from fastapi import Request
        req = MagicMock(spec=Request)
        req.method = "POST"
        req.headers = MagicMock()
        req.headers.__iter__ = MagicMock(return_value=iter([]))
        req.headers.items = MagicMock(return_value=[])
        req.headers.get = MagicMock(return_value=None)
        req.state = MagicMock()
        req.state.ysg_principal = None
        return req

    @pytest.mark.asyncio
    @pytest.mark.parametrize("model_input,expected_status", [
        # Proven live bypasses (must now be 403)
        ("openai:gpt-4o.",   403),  # trailing dot — LAURA-412-001 proven bypass
        ("openai::gpt-4o",   403),  # double colon — LAURA-412-001 proven bypass
        ("openai://gpt-4o",  422),  # URL-proto — caught by _validate → 422
        # Additional variants that must not escape to 200
        ("openai:::gpt-4o",  403),  # triple colon
        ("openai:/gpt-4o",   403),  # colon-slash
        ("openai//gpt-4o",   403),  # double slash
        ("OPENAI://GPT-4O",  422),  # upper + URL-proto → 422
        ("openai:gpt-4o..",  403),  # double trailing dot
        ("openai:gpt-4o;",   403),  # trailing semicolon
        ("openai:gpt-4o,",   403),  # trailing comma
        (" openai:gpt-4o ",  403),  # surrounding spaces
        ("openai/gpt-4o",    403),  # slash separator (LAURA-411 existing)
        ("openai:gpt-4o",    403),  # canonical (regression guard)
    ])
    async def test_variant_never_200(self, model_input, expected_status):
        """LAURA-412-001: every variant of denied cloud model returns 403 or 422,
        NEVER 200 with the silent qwen2.5:3b fallback."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model=model_input,
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        patches = [
            patch("yashigani.gateway.openai_router._state", self._make_state()),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_restricted_412",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ),
            patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=self._restricted_effective()),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
        ]

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, self._make_request())

        assert isinstance(result, JSONResponse), (
            f"model={model_input!r}: expected JSONResponse, got {type(result)}"
        )
        assert result.status_code == expected_status, (
            f"LAURA-412-001 model={model_input!r}: expected HTTP {expected_status}, "
            f"got {result.status_code}. Body: {result.body}"
        )
        # Critical invariant: NEVER a 200 (silent local fallback)
        assert result.status_code != 200, (
            f"LAURA-412-001 model={model_input!r}: got 200 — silent fallback to "
            "qwen2.5:3b. DENY bypass NOT fixed."
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("model_variant", [
        "openai:gpt-4o.",
        "openai::gpt-4o",
        "openai:gpt-4o..",
        "openai:gpt-4o;",
        "openai:gpt-4o,",
        " openai:gpt-4o ",
        "openai/gpt-4o",
        "openai:gpt-4o",
        "OPENAI:GPT-4O",
    ])
    async def test_power_user_variants_not_403(self, model_variant):
        """power_user (openai:gpt-4o allocated) must not get 403 for any variant."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        power_eff = EffectiveModels(
            allowed={"openai:gpt-4o", "qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases={"openai:gpt-4o"},
            gated={"openai:gpt-4o"},
        )

        body = ChatCompletionRequest(
            model=model_variant,
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        patches = [
            patch("yashigani.gateway.openai_router._state", self._make_state()),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_power_412",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ),
            patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=power_eff),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
        ]

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            try:
                result = await chat_completions(body, self._make_request())
                if isinstance(result, JSONResponse):
                    body_json = json.loads(result.body)
                    code = body_json.get("error", {}).get("code", "")
                    assert code != "model_not_allocated", (
                        f"power_user model={model_variant!r} must NOT get "
                        f"model_not_allocated; got {result.status_code} code={code!r}"
                    )
            except FastHTTPException as exc:
                if exc.status_code == 403:
                    detail = exc.detail or {}
                    code = detail.get("code", "") if isinstance(detail, dict) else ""
                    assert code != "model_not_allocated", (
                        f"power_user model={model_variant!r} must NOT get 403 "
                        f"model_not_allocated; got {exc.detail!r}"
                    )
                # 503 = backend unreachable in unit test — passes RBAC

    @pytest.mark.asyncio
    async def test_local_model_still_200_for_allowed_user(self):
        """qwen2.5:3b (installed, allocated to restricted_user) must NOT be denied.
        503 (no Ollama in unit test) is acceptable; 403 or 422 is not."""
        import contextlib
        from fastapi import HTTPException as FastHTTPException
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        local_eff = EffectiveModels(
            allowed={"qwen2.5:3b"},
            has_restriction=True,
            allocated_aliases=set(),
            gated=set(),
        )

        body = ChatCompletionRequest(
            model="qwen2.5:3b",
            messages=[ChatMessage(role="user", content="hello")],
            stream=False,
        )

        patches = [
            patch("yashigani.gateway.openai_router._state", self._make_state()),
            patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_localonly_412",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ),
            patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=local_eff),
            ),
            patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ),
            patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ),
        ]

        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            from yashigani.gateway.openai_router import chat_completions
            try:
                result = await chat_completions(body, self._make_request())
                if isinstance(result, JSONResponse):
                    assert result.status_code != 403, (
                        "qwen2.5:3b (allocated) must not 403 for an allocated local user"
                    )
                    assert result.status_code != 422, (
                        "qwen2.5:3b (installed) must not 422 model_not_found"
                    )
            except FastHTTPException as exc:
                assert exc.status_code not in (403, 422), (
                    f"qwen2.5:3b for local-only user: expected no 403/422, "
                    f"got {exc.status_code}: {exc.detail!r}"
                )
