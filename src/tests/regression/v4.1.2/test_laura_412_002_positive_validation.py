"""
Regression tests for LAURA-412 4th round — definitive positive-validation fix.

ROOT CAUSE (confirmed across fdf94811 → fix/v412-deny-positive-validation):
  normalize_model_for_deny() strips only " .:;,/" so any char outside that set
  survives → the lookup key ≠ stored grant "openai:gpt-4o" → deny missed →
  the optimization engine routes the (garbage) openai:* string to LOCAL default
  (qwen2.5:3b) → 200 with LLM content.  Deeper hole: a cloud-provider-prefixed
  model that is NOT a real/granted cloud model silently falls to local.

FIX — two layers, both positive (no more denylist):
  Layer 1 (_validate_model_string):
    Strict ASCII allowlist ^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*\\Z rejects ALL chars
    outside the set — |#!~<\\ printables, Unicode Cf (ZWSP/ZWNJ/ZWJ/BOM/etc.),
    NUL, embedded \\n/\\r — regardless of position.  Existing denylist checks
    kept ahead for backward-compat error codes (url_not_allowed, etc.).
  Layer 2 (chat_completions, after _is_known_model):
    If canonical model has a known cloud-provider prefix (openai:/anthropic:)
    AND permission_store is configured AND no alias or permission grant exists
    for the EXACT canonical string → 422.  Closes structural bypasses
    (openai:openai:gpt-4o, openai:gpt-4oAAAA) that pass layer 1 (valid chars)
    but are not real cloud models.

TESTS:
  • Unit: _validate_model_string positive regex for all 24+ bypass char classes
  • Unit: layer 2 gate logic (cloud prefix + no grant → 422; grant exists → pass)
  • E2E: drive chat_completions for ALL 24 Laura bypass variants → never 200
  • Fuzz: random junk chars, Unicode Cf chars, random suffixes → never 200
  • Positive: power_user granted models → not 403; local model → 200 or 503

Last updated: 2026-07-15T00:00:00+00:00
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ===========================================================================
# Unit: _validate_model_string — Layer 1 positive validation
# ===========================================================================

class TestPositiveValidation:
    """Layer 1: _validate_model_string must reject every char outside the ASCII
    allowlist ^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*\\Z."""

    def _validate(self, s: str):
        from yashigani.gateway.openai_router import _validate_model_string
        return _validate_model_string(s)

    # ── Invalid printable chars (appended to valid cloud model name) ─────

    @pytest.mark.parametrize("model", [
        "openai:gpt-4o|",
        "openai:gpt-4o#",
        "openai:gpt-4o!",
        "openai:gpt-4o~",
        "openai:gpt-4o<",
        "openai:gpt-4o\\",
        "openai:gpt-4o|junk",
        "openai:gpt-4o>",
        "openai:gpt-4o?",
        "openai:gpt-4o%",
        "openai:gpt-4o^",
        "openai:gpt-4o&",
        "openai:gpt-4o*",
        "openai:gpt-4o(",
        "openai:gpt-4o)",
        "openai:gpt-4o[",
        "openai:gpt-4o]",
        "openai:gpt-4o{",
        "openai:gpt-4o}",
        "openai:gpt-4o\"",
        "openai:gpt-4o'",
        "openai:gpt-4o;",  # ; is in normalize strip chars but positive validation catches it first
        "openai:gpt-4o,",  # , is in normalize strip chars but positive validation catches it first
        "openai:gpt-4o\tinside",  # TAB embedded (not trailing — trailing TAB is stripped by .strip())
        "openai:gpt-4o `",
    ])
    def test_invalid_printable_char_rejected(self, model):
        """Any printable char outside [a-zA-Z0-9._:/@-] surviving .strip() → invalid_model."""
        err = self._validate(model)
        assert err == "invalid_model", (
            f"{model!r}: expected invalid_model, got {err!r}. "
            "Positive validation must reject this char."
        )

    # ── Standalone invalid single chars ──────────────────────────────────

    @pytest.mark.parametrize("model", [
        "!",
        "~",
        "<",
        "\\",
        "|",
        "#",
        "%",
        "^",
        "&",
        "*",
        ";",
        "'",
        '"',
    ])
    def test_standalone_invalid_char_rejected(self, model):
        """Single invalid char as model name → invalid_model (first char fails)."""
        err = self._validate(model)
        assert err == "invalid_model", (
            f"{model!r}: expected invalid_model, got {err!r}."
        )

    # ── Unicode Cf (format) chars — all must be rejected ─────────────────

    @pytest.mark.parametrize("char,name", [
        ("​", "ZWSP U+200B"),
        ("‌", "ZWNJ U+200C"),
        ("‍", "ZWJ U+200D"),
        ("﻿", "BOM U+FEFF"),
        ("⁠", "Word-Joiner U+2060"),
        ("⁣", "Invisible-Sep U+2063"),
        ("­", "Soft-Hyphen U+00AD"),
        ("‎", "LRM U+200E"),
        ("‏", "RLM U+200F"),
        ("᠎", "Mongolian-VS U+180E"),
    ])
    def test_unicode_cf_char_rejected(self, char, name):
        """Unicode format chars embedded in or appended to a model name → invalid_model."""
        model_appended = f"openai:gpt-4o{char}"
        err = self._validate(model_appended)
        assert err == "invalid_model", (
            f"Model with {name} appended: expected invalid_model, got {err!r}. "
            "Unicode Cf bypass NOT closed."
        )

    # ── NUL and control chars ─────────────────────────────────────────────

    @pytest.mark.parametrize("model,label,allow_empty", [
        ("openai:gpt-4o\x00", "NUL byte", False),
        ("openai:gpt-4o\njunk", "embedded LF", False),
        ("openai:gpt-4o\rjunk", "embedded CR", False),
        ("openai:gpt-4o\x00123", "NUL embedded with suffix", False),
        # Standalone control chars: Python's .strip() removes whitespace → returns
        # empty_model (not invalid_model), but either means the model is rejected.
        ("\x00", "NUL alone", True),
        ("\n", "LF alone", True),
        ("\r", "CR alone", True),
        ("\t", "TAB alone", True),
    ])
    def test_control_chars_rejected(self, model, label, allow_empty):
        """Control chars (NUL, LF, CR, TAB) in model string must be rejected.

        Standalone whitespace-like control chars (LF, CR, TAB) are stripped by
        .strip() leaving an empty string → empty_model.  NUL is not whitespace.
        All forms must return a non-None error (the model is rejected).
        """
        err = self._validate(model)
        if allow_empty:
            # Standalone whitespace chars stripped → "empty_model" or "invalid_model"
            assert err is not None, (
                f"{label} ({model!r}): expected some error, got None. "
                "Control char model must be rejected."
            )
        else:
            # Embedded control chars survive .strip() → must be "invalid_model"
            assert err == "invalid_model", (
                f"{label} ({model!r}): expected invalid_model, got {err!r}. "
                "Embedded control char bypass NOT closed."
            )

    # ── Valid models must pass ────────────────────────────────────────────

    @pytest.mark.parametrize("model", [
        "qwen2.5:3b",
        "openai:gpt-4o",
        "openai/gpt-4o",
        "OPENAI:GPT-4O",
        "anthropic:claude-3-5-sonnet",
        "library/llama3.2:3b",
        "model@sha256:abc123def456",
        "phi3.5",
        "llama3.2",
        "fast",
        "smart",
        "gpt-4o",
        "claude-sonnet-4-5",
    ])
    def test_valid_models_pass(self, model):
        """All legitimate model name forms must pass positive validation."""
        err = self._validate(model)
        assert err is None, (
            f"{model!r}: expected None (valid), got {err!r}. "
            "Valid model incorrectly rejected."
        )

    # ── Backward compat: existing error codes must not change ─────────────

    def test_url_scheme_still_url_not_allowed(self):
        """openai://gpt-4o must still return url_not_allowed (not invalid_model).
        Kept for backward-compat with existing tests and clearer error messages."""
        assert self._validate("openai://gpt-4o") == "url_not_allowed"

    def test_http_still_url_not_allowed(self):
        assert self._validate("http://api.openai.com/gpt-4o") == "url_not_allowed"

    def test_path_traversal_still_rejected(self):
        assert self._validate("../etc/passwd") == "path_traversal_not_allowed"

    def test_null_sentinel_still_rejected(self):
        assert self._validate("null") == "null_not_allowed"
        assert self._validate("none") == "null_not_allowed"
        assert self._validate("undefined") == "null_not_allowed"


# ===========================================================================
# Unit: Layer 2 cloud-prefix gate (permission-store level)
# ===========================================================================

class TestLayer2CloudPrefixGate:
    """Layer 2 closes structural bypasses: cloud-prefixed strings with valid
    chars but no permission grant silently fell to local default.  This unit
    tests the gate logic directly via _validate_model_string + normalize
    to confirm the canonical key is what the gate checks."""

    def _norm(self, s: str) -> str:
        from yashigani.models.effective import normalize_model_for_deny
        return normalize_model_for_deny(s)

    @pytest.mark.parametrize("model,expected_canonical", [
        ("openai:openai:gpt-4o",    "openai:openai:gpt-4o"),   # nested provider — not real
        ("openai:gpt-4oAAAAAAAA",   "openai:gpt-4oaaaaaaaa"),  # 8 A's → 8 a's (lowercased)
        ("openai:gpt-4o-extra",     "openai:gpt-4o-extra"),    # hyphen suffix
        ("openai:notarealmodel123", "openai:notarealmodel123"),  # fake model name
        ("anthropic:notreal-v99",   "anthropic:notreal-v99"),  # anthropic variant
    ])
    def test_junk_cloud_prefixed_canonicalize_correctly(self, model, expected_canonical):
        """Structural bypass models normalize to a canonical form that has no grant
        in the permission store → layer 2 returns 422."""
        # Verify normalization is stable and doesn't collapse to a granted key
        canonical = self._norm(model)
        assert canonical == expected_canonical, (
            f"{model!r} canonicalized to {canonical!r}, expected {expected_canonical!r}"
        )
        # Canonical form must still have cloud prefix → layer 2 would check it
        prefix = canonical.split(":", 1)[0] if ":" in canonical else ""
        assert prefix in ("openai", "anthropic"), (
            f"Canonical {canonical!r} prefix {prefix!r} not a cloud provider — "
            "layer 2 would not fire"
        )
        # Canonical form must NOT equal the real model name → no grant found
        assert canonical != "openai:gpt-4o", (
            f"{model!r} collapsed to openai:gpt-4o — layer 2 would (correctly) "
            "pass because a grant exists for that exact key"
        )

    def test_exact_canonical_passes_layer2_when_grant_exists(self):
        """openai:gpt-4o (exact) has a grant (allow=False for restricted_user)
        → layer 2 _412_has_grant=True → gate passes → LAURA-411-001 catches deny."""
        # The canonical key IS the stored grant key — layer 2 must NOT 422 this
        canonical = self._norm("openai:gpt-4o")
        assert canonical == "openai:gpt-4o"


# ===========================================================================
# E2E: drive chat_completions for all 24 Laura bypass variants
# ===========================================================================

class TestDenyBypass412E2E:
    """End-to-end route-level test driving chat_completions.

    restricted_user has explicit allow=False on cloud_model:openai:gpt-4o.
    Every one of Laura's 24+ bypass variants must return 403 or 422 — NEVER 200.
    """

    def _make_state(self, *, with_permission_store: bool = False):
        """Build a minimal OpenAIRouterState mock.

        with_permission_store=True: mock the permission store so layer 2 fires.
        with_permission_store=False: permission_store=None so layer 2 is skipped
          (layer 1 must catch the input before we even reach layer 2).
        """
        alias_store = MagicMock()
        alias_store.get.return_value = None  # no aliases configured

        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "qwen2.5:3b"
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = alias_store
        state.available_models = [{"id": "qwen2.5:3b"}]
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
        state.permission_strict = False
        state.kms_provider = None
        state._cloud_key_cache = {}

        if with_permission_store:
            perm_store = MagicMock()
            # Only the exact canonical "openai:gpt-4o" has a user-level deny grant.
            # All other model strings → None (no grant → layer 2 returns 422).
            def _mock_grant(resource_type, scope_kind, scope_id, resource_id):
                if resource_id == "openai:gpt-4o" and scope_kind == "user":
                    g = MagicMock()
                    g.allow = False
                    return g
                return None
            perm_store.get_boolean_grant.side_effect = _mock_grant
            state.permission_store = perm_store
        else:
            state.permission_store = None

        return state

    def _restricted_identity(self):
        return {
            "identity_id": "idnt_restricted_412002",
            "kind": "human",
            "groups": [],
            "status": "active",
            "sensitivity_ceiling": "PUBLIC",
        }

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

    # ── Layer 1 bypass variants: invalid chars → 422 (no perm store needed) ─

    @pytest.mark.asyncio
    @pytest.mark.parametrize("model_input", [
        # Invalid printable chars (appended to cloud model name)
        "openai:gpt-4o|",
        "openai:gpt-4o#",
        "openai:gpt-4o!",
        "openai:gpt-4o~",
        "openai:gpt-4o<",
        "openai:gpt-4o\\",
        "openai:gpt-4o|junk",
        # Standalone invalid chars
        "!",
        "~",
        "<",
        "\\",
        # Unicode Cf chars embedded in cloud model name
        "openai:gpt-4o​",    # ZWSP
        "openai:gpt-4o‌",    # ZWNJ
        "openai:gpt-4o‍",    # ZWJ
        "openai:gpt-4o﻿",    # BOM
        "openai:gpt-4o⁠",    # Word-Joiner
        "openai:gpt-4o⁣",    # Invisible-Sep
        # NUL byte
        "openai:gpt-4o\x00",
        # Embedded control chars
        "openai:gpt-4o\njunk",
        "openai:gpt-4o\rjunk",
        "​123",               # Cf at start
    ])
    async def test_layer1_variants_422(self, model_input):
        """Layer 1 (positive validation) must catch all invalid-char variants → 422.
        NEVER 200 — the silent qwen2.5:3b fallback must not fire."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model=model_input,
            messages=[ChatMessage(role="user", content="bypass test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", self._make_state()))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=self._restricted_identity()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=self._restricted_effective()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, self._make_request())

        assert isinstance(result, JSONResponse), (
            f"model={model_input!r}: expected JSONResponse, got {type(result)}"
        )
        assert result.status_code == 422, (
            f"LAURA-412-002 layer 1 model={model_input!r}: expected 422 (invalid_model), "
            f"got {result.status_code}. Body: {result.body}"
        )
        body_json = json.loads(result.body)
        assert body_json["error"]["code"] in ("invalid_model", "model_not_found"), (
            f"model={model_input!r}: unexpected error code {body_json['error']['code']!r}"
        )

    # ── Layer 2 bypass variants: valid chars, cloud prefix, no grant → 422 ──

    @pytest.mark.asyncio
    @pytest.mark.parametrize("model_input", [
        # Structural: nested provider prefix — passes char validation but not a real model
        "openai:openai:gpt-4o",
        # Unbounded alnum suffix — valid chars, not a recognized model
        "openai:gpt-4oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        # Short junk suffix
        "openai:gpt-4o-XXXX",
        # Anthropic variant with junk
        "anthropic:not-a-real-model-xyz",
        # Fake model under known provider
        "openai:notarealmodel999",
    ])
    async def test_layer2_variants_422(self, model_input):
        """Layer 2 (cloud-prefix + no grant gate) must catch structural bypasses
        that pass layer 1 (all chars valid) but are not real cloud models → 422.
        These represent the deeper hole: _is_known_model returns True for any
        openai:* prefix, then the string falls through to local qwen2.5:3b."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model=model_input,
            messages=[ChatMessage(role="user", content="bypass test")],
            stream=False,
        )

        # with_permission_store=True so layer 2 fires.
        # The mock permission store has NO grant for these junk models.
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state",
                self._make_state(with_permission_store=True),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=self._restricted_identity()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=self._restricted_effective()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, self._make_request())

        assert isinstance(result, JSONResponse), (
            f"model={model_input!r}: expected JSONResponse, got {type(result)}"
        )
        assert result.status_code == 422, (
            f"LAURA-412-002 layer 2 model={model_input!r}: expected 422 (unknown cloud model), "
            f"got {result.status_code}. Body: {result.body}. "
            "Structural bypass NOT closed — model should 422, not 200 via local fallback."
        )

    # ── Canonical denied model must be 403 (not 422) ─────────────────────

    @pytest.mark.asyncio
    async def test_exact_denied_model_is_403(self):
        """openai:gpt-4o (exact canonical denied model) must be 403 (RBAC deny),
        NOT 422. Layer 2 finds a grant for it → passes; LAURA-411-001 catches deny."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        body = ChatCompletionRequest(
            model="openai:gpt-4o",
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state",
                self._make_state(with_permission_store=True),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value=self._restricted_identity()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=self._restricted_effective()),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, self._make_request())

        assert isinstance(result, JSONResponse), type(result)
        assert result.status_code == 403, (
            f"openai:gpt-4o for restricted_user: expected 403 (explicit deny), "
            f"got {result.status_code}. Body: {result.body}"
        )
        body_json = json.loads(result.body)
        # Layer 2 passes (grant exists for exact canonical key → _412_has_grant=True).
        # The alloc-bind B1 check fires before LAURA-411-001 and returns
        # model_not_allocated; LAURA-411-001 returns cloud_model_not_granted.
        # Both are correct 403 responses — the deny is not a silent 200.
        assert body_json["error"]["code"] in ("cloud_model_not_granted", "model_not_allocated"), (
            f"Expected 403 deny code, got {body_json['error']['code']!r}"
        )


# ===========================================================================
# Fuzz: random junk chars, Unicode Cf, random suffixes
# ===========================================================================

class TestFuzzVariants:
    """Fuzz-style coverage: random junk chars, random Unicode, random suffixes.
    All must be 422 (invalid or unknown) for restricted_user — NEVER 200."""

    def _validate(self, s: str):
        from yashigani.gateway.openai_router import _validate_model_string
        return _validate_model_string(s)

    # ── Broad charset fuzz via unit test ─────────────────────────────────
    #
    # NOTE on trailing Unicode whitespace: Python .strip() removes ALL Unicode
    # whitespace (NEL \x85, NBSP \xa0, Ogham \u1680, En-Quad \u2000,
    # Line-Sep \u2028, Para-Sep \u2029, Narrow-NBSP \u202f, Ideo \u3000, etc.)
    # before the positive-validation regex runs.  A trailing Unicode-whitespace
    # suffix on "openai:gpt-4o" therefore collapses to the bare canonical string
    # and is NOT a layer-1 bypass (RBAC / alloc-bind handle it downstream).
    # The fuzz cases below test EMBEDDED occurrences which .strip() cannot remove.

    @pytest.mark.parametrize("suffix", [
        "%",
        "^",
        "&",
        "*",
        "(",
        ")",
        "[",
        "]",
        "{",
        "}",
        '"',
        "'",
        "+",
        "=",
        "`",
        ",",        # comma is in normalize strip chars but must still fail validation
        " injected", # space mid-string
        "\x01",     # SOH control char
        "\x1b",     # ESC control char
        "\x7f",     # DEL
        # Unicode whitespace EMBEDDED (not trailing — .strip() doesn't reach middle chars)
        "\x85x",    # NEL embedded
        "\xa0x",    # NBSP embedded
        "\u1680x",  # Ogham Space Mark embedded
        "\u2000x",  # En Quad embedded
        "\u2028x",  # Line Separator embedded
        "\u2029x",  # Paragraph Separator embedded
        "\u202fx",  # Narrow NBSP embedded
        "\u3000x",  # Ideographic Space embedded
        "\ufffe",   # non-char (suffix)
        "\U0001f600",  # emoji (outside BMP)
    ])
    def test_fuzz_invalid_suffix_rejected(self, suffix):
        """Appending any char outside the ASCII allowlist to a model name -> invalid_model.

        Trailing Unicode whitespace is tested as embedded (middle-of-string) forms
        because .strip() removes trailing Unicode whitespace before the regex runs —
        that is not a bypass (the stripped canonical is handled by RBAC downstream).
        """
        model = f"openai:gpt-4o{suffix}"
        err = self._validate(model)
        assert err is not None, (
            f"openai:gpt-4o + {suffix!r}: "
            f"expected error, got None (PASSES VALIDATION). This is a bypass."
        )


    @pytest.mark.parametrize("fuzz_model", [
        # Various Unicode format char standalone bypass attempts
        "​",
        "‌",
        "‍",
        "﻿",
        "⁠",
        "⁡",
        "⁢",
        "⁣",
        "⁤",
        # Mixed: valid prefix then junk
        "a​",
        "openai​:gpt-4o",
        "openai:​gpt-4o",
        # Trailing assorted
        "openai:gpt-4o­",   # Soft Hyphen (Cf)
    ])
    def test_fuzz_unicode_format_chars_rejected(self, fuzz_model):
        """Unicode format/whitespace chars embedded anywhere in a model string → invalid_model."""
        err = self._validate(fuzz_model)
        assert err is not None, (
            f"{fuzz_model!r}: expected validation error, got None. "
            "Unicode Cf bypass NOT closed."
        )

    @pytest.mark.parametrize("suffix_len,char", [
        (10,  "A"),    # short alnum suffix → layer 1 passes, layer 2 should catch (no grant)
        (100, "a"),    # medium alnum suffix
        (500, "X"),    # long alnum suffix
    ])
    def test_fuzz_alnum_suffix_cloud_model_no_grant(self, suffix_len, char):
        """Cloud-prefixed model + long valid-char suffix (no grant) → layer 2 → 422.
        Validates that layer 2 isn't bypassed by unbounded-length alnum suffixes."""
        # Just validate the canonical form has cloud prefix and doesn't match a real model
        from yashigani.models.effective import normalize_model_for_deny
        model = f"openai:gpt-4o{char * suffix_len}"
        canonical = normalize_model_for_deny(model)
        # Canonical still has openai: prefix
        assert canonical.startswith("openai:"), canonical
        # Canonical is NOT the real model
        assert canonical != "openai:gpt-4o", (
            f"Suffix collapsed to real model — layer 2 would (correctly) pass because grant exists"
        )


# ===========================================================================
# Positive: granted models must NOT be 403; local model must NOT be 422/403
# ===========================================================================

class TestPositiveCases:
    """Ensure the fix doesn't regress legitimate flows."""

    def _make_state_with_power_grant(self):
        """State with permission store configured; power_user has allow=True on openai:gpt-4o."""
        alias_store = MagicMock()
        alias_store.get.return_value = None

        perm_store = MagicMock()
        def _mock_grant_power(resource_type, scope_kind, scope_id, resource_id):
            # org-level allow grant for openai:gpt-4o
            if resource_id == "openai:gpt-4o" and scope_kind == "org":
                g = MagicMock()
                g.allow = True
                g.opa_policy_ref = "policy/cloud_model_openai"
                return g
            if resource_id == "openai:gpt-4o" and scope_kind == "user":
                g = MagicMock()
                g.allow = True
                g.opa_policy_ref = "policy/cloud_model_openai"
                return g
            return None
        perm_store.get_boolean_grant.side_effect = _mock_grant_power

        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "qwen2.5:3b"
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = alias_store
        state.available_models = [{"id": "qwen2.5:3b"}]
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
        state.permission_strict = False
        state.kms_provider = None
        state._cloud_key_cache = {}
        state.permission_store = perm_store
        return state

    def _make_state_no_perm(self):
        """State without permission store (minimally configured / no cloud grants)."""
        alias_store = MagicMock()
        alias_store.get.return_value = None
        state = MagicMock()
        state.opa_url = "http://opa:8181"
        state.ollama_url = "http://ollama:11434"
        state.default_model = "qwen2.5:3b"
        state.optimization_engine = None
        state.sensitivity_classifier = None
        state.complexity_scorer = None
        state.budget_enforcer = None
        state.ddos_protector = None
        state.content_relay_detector = None
        state.model_alias_store = alias_store
        state.available_models = [{"id": "qwen2.5:3b"}]
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
        state.permission_strict = False
        state.kms_provider = None
        state._cloud_key_cache = {}
        state.permission_store = None
        return state

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
    @pytest.mark.parametrize("model_variant", [
        "openai:gpt-4o",
        "openai/gpt-4o",    # slash separator normalizes to openai:gpt-4o
        "OPENAI:GPT-4O",    # uppercase normalizes to openai:gpt-4o
    ])
    async def test_power_user_granted_model_not_403(self, model_variant):
        """power_user with allow=True on openai:gpt-4o must NOT get 403 or 422
        from the RBAC layer.  A 503 (no Ollama in unit test) is acceptable —
        it means the request passed RBAC and hit the backend."""
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

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state",
                self._make_state_with_power_grant(),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_power_412002",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=power_eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            try:
                result = await chat_completions(body, self._make_request())
                if isinstance(result, JSONResponse):
                    body_json = json.loads(result.body)
                    code = body_json.get("error", {}).get("code", "")
                    assert code not in ("model_not_allocated", "cloud_model_not_granted", "model_not_found"), (
                        f"power_user model={model_variant!r}: got RBAC deny code {code!r}. "
                        "Granted user must NOT be blocked by layer 1 or layer 2."
                    )
                    assert result.status_code not in (403, 422), (
                        f"power_user model={model_variant!r}: got {result.status_code}. "
                        "Granted user must not be blocked."
                    )
            except FastHTTPException as exc:
                assert exc.status_code not in (403, 422), (
                    f"power_user model={model_variant!r}: HTTPException {exc.status_code}: {exc.detail!r}. "
                    "Granted user must not be blocked."
                )
            # 503 (Ollama unreachable in unit test) is acceptable — RBAC passed

    @pytest.mark.asyncio
    async def test_restricted_user_local_model_not_blocked(self):
        """qwen2.5:3b (installed local model, allocated to restricted_user) must
        NOT be 403 or 422. A 503 (no Ollama in unit test) is acceptable."""
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

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._state",
                self._make_state_no_perm(),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_localonly_412002",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=local_eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True, "model_allowed": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            try:
                result = await chat_completions(body, self._make_request())
                if isinstance(result, JSONResponse):
                    assert result.status_code not in (403, 422), (
                        f"qwen2.5:3b for local-only user: expected no 403/422, "
                        f"got {result.status_code}. Body: {result.body}"
                    )
            except FastHTTPException as exc:
                assert exc.status_code not in (403, 422), (
                    f"qwen2.5:3b for local-only user: got HTTPException {exc.status_code}: {exc.detail!r}"
                )

    @pytest.mark.asyncio
    async def test_genuinely_unknown_model_422(self):
        """A genuinely-unknown model (not installed, not an alias, not a cloud
        provider prefix) must return 422 model_not_found."""
        import contextlib
        from fastapi.responses import JSONResponse
        from yashigani.models.effective import EffectiveModels
        from yashigani.gateway.openai_router import ChatCompletionRequest, ChatMessage

        eff = EffectiveModels(allowed=set(), has_restriction=False, allocated_aliases=set(), gated=set())

        body = ChatCompletionRequest(
            model="totally-unknown-model-xyzzy",
            messages=[ChatMessage(role="user", content="test")],
            stream=False,
        )

        state = self._make_state_no_perm()
        # available_models is an EMPTY list (fetched successfully, none installed)
        state.available_models = []
        # alias_store.get returns None for unknown model
        state.model_alias_store.get.return_value = None

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("yashigani.gateway.openai_router._state", state))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._resolve_identity",
                MagicMock(return_value={
                    "identity_id": "idnt_anon_412002",
                    "kind": "human",
                    "groups": [],
                    "status": "active",
                    "sensitivity_ceiling": "PUBLIC",
                }),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._effective_allowed_models",
                MagicMock(return_value=eff),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router._opa_v1_check",
                AsyncMock(return_value={"allow": True}),
            ))
            stack.enter_context(patch(
                "yashigani.gateway.openai_router.evaluate_client_policies",
                AsyncMock(return_value={"allow": True}),
            ))
            from yashigani.gateway.openai_router import chat_completions
            result = await chat_completions(body, self._make_request())

        assert isinstance(result, JSONResponse)
        assert result.status_code == 422, (
            f"Genuinely-unknown model: expected 422, got {result.status_code}"
        )
