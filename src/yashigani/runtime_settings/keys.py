"""
Canonical setting key constants and their metadata.

Every entry in KNOWN_SETTINGS drives:
  - DB seed on first boot (default_value comes from env or class default)
  - Admin API validation (allowed_type determines Pydantic field type)
  - Admin UI rendering (description shown in the settings panel)

Adding a new setting: append an entry here; the service seeds it automatically.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ── Per-user rate limit (gateway.ratelimit) ──────────────────────────────────
KEY_RATE_LIMIT_PER_USER_RPS = "gateway.ratelimit.per_user_rps"

# ── DDoS protector (gateway.ddos) ────────────────────────────────────────────
KEY_DDOS_PER_IP_LIMIT = "gateway.ddos.per_ip_limit"
KEY_DDOS_WINDOW_SECONDS = "gateway.ddos.window_seconds"

# ── Model-list visibility for service accounts (gateway.models) ──────────────
KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST = "gateway.models.service_account_full_list"

# ── Cloud-model permission strict dial (gateway.permissions) ─────────────────
KEY_PERMISSION_STRICT_MODE = "gateway.permissions.strict_mode"


@dataclass(frozen=True)
class SettingMeta:
    """Metadata for a single runtime setting."""
    key: str
    description: str
    allowed_type: str          # 'int' | 'float' | 'bool' | 'string'
    env_var: str               # env var that seeds this on first boot
    class_default: Any         # value used when env var is absent
    # YSG-RISK-155: numeric settings previously had NO bounds — an admin
    # could set gateway.ddos.window_seconds=0 (division-by-zero in the
    # windowed counter) or gateway.ratelimit.per_user_rps=-1 (negative token
    # bucket refill) or an absurdly large value, with only a type coercion
    # in between. min_value/max_value are enforced by
    # RuntimeSettingsService.set() (service.py _validate_bounds) — None means
    # "no bound on that side" (used for bool/string settings and any
    # numeric setting that genuinely has no natural limit).
    min_value: float | None = None
    max_value: float | None = None


#: All settings managed by RuntimeSettingsService.
#: Order controls display order in the admin UI.
KNOWN_SETTINGS: list[SettingMeta] = [
    SettingMeta(
        key=KEY_RATE_LIMIT_PER_USER_RPS,
        description=(
            "Per-authenticated-user token bucket refill rate (requests/second). "
            "Burst = 2x this value. Lower to throttle heavy users; raise for "
            "high-volume API consumers. YSG-RISK-222."
        ),
        allowed_type="float",
        env_var="YASHIGANI_RATE_LIMIT_PER_USER_RPS",
        class_default=100.0,
        # Must be strictly positive (0 or negative would stall/invert the
        # token-bucket refill); upper bound is a generous sanity ceiling.
        min_value=0.01,
        max_value=1_000_000.0,
    ),
    SettingMeta(
        key=KEY_DDOS_PER_IP_LIMIT,
        description=(
            "Maximum requests from a single IP within the DDoS window before the "
            "IP is throttled (HTTP 429). Raise for large NAT deployments; lower "
            "for stricter DDoS posture. YSG-RISK-220."
        ),
        allowed_type="int",
        env_var="YASHIGANI_DDOS_PER_IP_LIMIT",
        class_default=5000,
        min_value=1,
        max_value=10_000_000,
    ),
    SettingMeta(
        key=KEY_DDOS_WINDOW_SECONDS,
        description=(
            "Fixed-window duration (seconds) for DDoS per-IP counter. "
            "Shorter = tighter burst window; longer = rolling average. "
            "YSG-RISK-220."
        ),
        allowed_type="int",
        env_var="YASHIGANI_DDOS_WINDOW_SECONDS",
        class_default=60,
        # A 0-or-negative window would divide-by-zero / invert the fixed-window
        # counter; upper bound caps it at one day.
        min_value=1,
        max_value=86_400,
    ),
    SettingMeta(
        key=KEY_MODELS_SERVICE_ACCOUNT_FULL_LIST,
        description=(
            "When ON, service-account identities (notably the Open WebUI chat "
            "surface, which authenticates with the shared internal bearer) receive "
            "the FULL GET /v1/models list — local models + registered agents + "
            "service identities — instead of the restricted default. Enable this "
            "for Open WebUI deployments so the model picker populates with the "
            "models and agents. Default OFF (restricted) per OPA GAP-001/002 / "
            "FINDING-59-01 (internal-topology disclosure hardening)."
        ),
        allowed_type="bool",
        env_var="YASHIGANI_MODELS_SERVICE_ACCOUNT_FULL_LIST",
        class_default=False,
    ),
    SettingMeta(
        key=KEY_PERMISSION_STRICT_MODE,
        description=(
            "YSG-RISK-162: cloud LLM providers (openai/anthropic) are ALWAYS "
            "deny-by-default and require an explicit cloud_model grant, "
            "regardless of this setting (INV-1, not affected by this toggle). "
            "When OFF (default), LOCAL Ollama models are permissive-by-default "
            "-- no grant required -- so out-of-the-box local-LLM usage works "
            "without any grant configuration (matches YSG-RISK-164: local "
            "models are always detect+audit via the PII/sensitivity/response-"
            "inspection pipelines regardless of this setting -- the egress "
            "boundary, not local access, is the enforcement point). When ON, "
            "LOCAL models ALSO require an explicit cloud_model grant "
            "(deny-unless-permitted for every model). Turning this ON with no "
            "grants configured will 403 every local chat request -- create "
            "grants for every in-use local model FIRST. Intentionally left "
            "OFF by default; flip only for orgs that require an allowlist for "
            "local models too."
        ),
        allowed_type="bool",
        env_var="YASHIGANI_PERMISSION_STRICT",
        class_default=False,
    ),
]

# Indexed by key for O(1) lookup
KNOWN_SETTINGS_BY_KEY: dict[str, SettingMeta] = {s.key: s for s in KNOWN_SETTINGS}
