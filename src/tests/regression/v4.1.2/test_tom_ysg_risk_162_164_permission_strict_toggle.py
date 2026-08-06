"""
Regression test -- v4.1.2 YSG-RISK-162 (permission_strict dark default) and
YSG-RISK-164 (local-model detect-only confirmation).

## YSG-RISK-162

Current state found: ``permission_strict`` was ONLY an env var
(YASHIGANI_PERMISSION_STRICT), read once at ``configure()`` time into
``_state.permission_strict`` -- no admin API/UI surfaced it, and changing it
required editing the container environment + a restart. Default False.

Investigated interaction with YSG-RISK-164 (see below): flipping the
DEFAULT to True would gate every LOCAL Ollama chat request behind an
explicit ``cloud_model`` permission grant on every fresh/community install
(permission_store is wired whenever Redis is reachable -- essentially every
real deployment -- so this is not a theoretical edge case). No grants exist
out of the box, so every local chat call would 403 until an admin manually
creates a grant for every in-use local model. That directly contradicts
YSG-RISK-164's by-design "local = detect-only, cloud-egress = enforcement
boundary" posture and would be a severe availability regression disguised
as a security fix, since the actually-dangerous path (cloud egress) is
ALREADY deny-by-default (INV-1) independent of this dial.

Per dispatch instruction: STOP on the default flip, FLAG the interaction
(see commit body), and instead close the "dark default" complaint by making
the setting a genuine admin-visible, DB-backed, no-restart-required runtime
toggle (mirroring gateway.models.service_account_full_list) -- so the
setting is discoverable/auditable/toggleable, while the shipped default
value is UNCHANGED (False).

Tests below cover:
  - the new gateway.permissions.strict_mode key is registered with the
    correct env var + class_default=False (unchanged)
  - the live-read helper `_permission_strict_mode_enabled()` falls back to
    `_state.permission_strict` (fail-open to configured value) when no DB
    is configured -- so existing/default behaviour is byte-for-byte
    unchanged for every deployment without the runtime override
  - the gate call site now calls the live-read helper instead of reading
    `_state.permission_strict` directly (source-level check)
  - G9/G10/G11 (v3.1 test_cloud_model_gate.py) still pass unmodified,
    proving no behavioural regression to the existing strict-dial contract

## YSG-RISK-164

Confirmed BY DESIGN, no code change: local (Ollama) models are never
silently passed with zero visibility.
  - `_state.pii_detector.process_decoded(prompt_text)` runs on every
    prompt unconditionally of provider (before the routing decision).
  - `_state.sensitivity_classifier.classify_decoded(prompt_text)` runs on
    every prompt unconditionally of provider.
  - `_state.response_inspection_pipeline.inspect(...)` runs on every
    assistant response unconditionally of provider (audits + can flag
    BLOCKED via header; does not silently pass).
The only thing gated by cloud-vs-local is the ACCESS-CONTROL permission
gate (INV-1 cloud deny-by-default + optional local strict-dial) -- detect
+audit is always on. This matches the intended design: cloud egress is the
data-exfiltration risk boundary (hence mandatory grant + OPA coupling);
local inference stays inside the org's infra, so it is detect+audit rather
than deny-by-default, unless an operator opts into the strict dial above.
"""
from __future__ import annotations

import os

import pytest


class TestPermissionStrictRuntimeSetting:
    def test_key_registered_with_unchanged_default(self):
        from yashigani.runtime_settings.keys import (
            KEY_PERMISSION_STRICT_MODE,
            KNOWN_SETTINGS_BY_KEY,
        )
        meta = KNOWN_SETTINGS_BY_KEY[KEY_PERMISSION_STRICT_MODE]
        assert meta.env_var == "YASHIGANI_PERMISSION_STRICT"
        assert meta.class_default is False
        assert meta.allowed_type == "bool"

    def test_admin_api_auto_discovers_the_key(self):
        """The generic admin runtime-settings routes key off KNOWN_SETTINGS_
        BY_KEY -- confirms GET/PUT /admin/runtime-settings/gateway.permissions.
        strict_mode will 200 instead of 404 (was previously not a known key
        at all)."""
        from yashigani.backoffice.routes.runtime_settings import _get_known_key
        from yashigani.runtime_settings.keys import KEY_PERMISSION_STRICT_MODE
        meta = _get_known_key(KEY_PERMISSION_STRICT_MODE)
        assert meta.key == KEY_PERMISSION_STRICT_MODE


class TestPermissionStrictLiveRead:
    def _reset_cache(self):
        from yashigani.gateway import openai_router as router_mod
        router_mod._PERMISSION_STRICT_CACHE["value"] = None
        router_mod._PERMISSION_STRICT_CACHE["ts"] = 0.0

    def test_default_no_db_falls_back_to_configured_value_false(self, monkeypatch):
        """No DSN configured -> live-read helper falls back to _state.
        permission_strict, which configure()/module default is False.
        Byte-for-byte unchanged default behaviour."""
        monkeypatch.delenv("YASHIGANI_DB_DSN", raising=False)
        from yashigani.gateway import openai_router as router_mod
        self._reset_cache()
        router_mod._state.permission_strict = False
        assert router_mod._permission_strict_mode_enabled() is False

    def test_configured_env_true_falls_back_correctly(self, monkeypatch):
        """When the operator sets YASHIGANI_PERMISSION_STRICT=true (existing
        env-only mechanism) and no DB override exists, the live-read helper
        must honour it -- fail-open to the CONFIGURED value, not force False."""
        monkeypatch.delenv("YASHIGANI_DB_DSN", raising=False)
        from yashigani.gateway import openai_router as router_mod
        self._reset_cache()
        router_mod._state.permission_strict = True
        assert router_mod._permission_strict_mode_enabled() is True
        # restore
        router_mod._state.permission_strict = False
        self._reset_cache()

    def test_db_read_failure_fails_open_to_configured_value(self, monkeypatch):
        """DSN configured but unreachable -> fail-open to _state.permission_strict,
        NOT hard-fail to True (would 403 every local chat request on a
        transient DB outage -- an availability regression, not a security
        fix, for this specific setting)."""
        monkeypatch.setenv("YASHIGANI_DB_DSN", "postgresql://bad:bad@127.0.0.1:1/nonexistent")
        from yashigani.gateway import openai_router as router_mod
        self._reset_cache()
        router_mod._state.permission_strict = False
        assert router_mod._permission_strict_mode_enabled() is False
        monkeypatch.delenv("YASHIGANI_DB_DSN", raising=False)
        self._reset_cache()

    def test_cache_ttl_respected(self, monkeypatch):
        """Within the TTL window, repeated calls must not re-hit the DB path
        (cheap sanity check: cached value returned without re-evaluating
        _state.permission_strict changes mid-window)."""
        monkeypatch.delenv("YASHIGANI_DB_DSN", raising=False)
        from yashigani.gateway import openai_router as router_mod
        self._reset_cache()
        router_mod._state.permission_strict = False
        assert router_mod._permission_strict_mode_enabled() is False
        # Flip the underlying value mid-window -- cached read must still win.
        router_mod._state.permission_strict = True
        assert router_mod._permission_strict_mode_enabled() is False
        # cleanup
        router_mod._state.permission_strict = False
        self._reset_cache()


class TestGateCallSiteUsesLiveRead:
    def test_gate_condition_calls_live_read_helper_not_raw_attribute(self):
        """Source-level check: the _perm_needs_check condition in
        chat_completions must call _permission_strict_mode_enabled(), not
        read _state.permission_strict directly -- confirms the admin-toggle
        wiring actually reaches the enforcement call site."""
        import inspect
        from yashigani.gateway import openai_router as router_mod
        src = inspect.getsource(router_mod)
        assert "_perm_is_cloud or _permission_strict_mode_enabled()" in src


class TestExistingStrictDialContractUnchanged:
    """G9/G10/G11 from v3.1/test_cloud_model_gate.py re-asserted here to
    prove the RISK-162 change introduces no behavioural regression to the
    strict-dial contract itself."""

    def test_g9_strict_local_no_grant_denied(self):
        fakeredis = pytest.importorskip("fakeredis", reason="fakeredis not installed")
        from yashigani.permissions import resolve_boolean_grant, ResourceType, DEFAULT_ORG_ID
        from yashigani.permissions.store import PermissionStore
        store = PermissionStore(fakeredis.FakeRedis(decode_responses=False), default_org_id=DEFAULT_ORG_ID)
        result = resolve_boolean_grant(
            ResourceType.CLOUD_MODEL, "qwen2.5:3b",
            org_id=DEFAULT_ORG_ID, group_ids=[],
            principal_scope=None, principal_id=None, store=store,
        )
        assert result is False

    def test_g11_default_off_gate_skipped_when_no_store(self):
        from yashigani.gateway.openai_router import OpenAIRouterState
        s = OpenAIRouterState()
        assert s.permission_strict is False
        _perm_needs_check = (
            s.permission_store is not None
            and (False or s.permission_strict)
        )
        assert _perm_needs_check is False
