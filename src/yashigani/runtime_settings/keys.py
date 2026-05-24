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


@dataclass(frozen=True)
class SettingMeta:
    """Metadata for a single runtime setting."""
    key: str
    description: str
    allowed_type: str          # 'int' | 'float' | 'bool' | 'string'
    env_var: str               # env var that seeds this on first boot
    class_default: Any         # value used when env var is absent


#: All settings managed by RuntimeSettingsService.
#: Order controls display order in the admin UI.
KNOWN_SETTINGS: list[SettingMeta] = [
    SettingMeta(
        key=KEY_RATE_LIMIT_PER_USER_RPS,
        description=(
            "Per-authenticated-user token bucket refill rate (requests/second). "
            "Burst = 2x this value. Lower to throttle heavy users; raise for "
            "high-volume API consumers. YSG-RISK-058."
        ),
        allowed_type="float",
        env_var="YASHIGANI_RATE_LIMIT_PER_USER_RPS",
        class_default=100.0,
    ),
    SettingMeta(
        key=KEY_DDOS_PER_IP_LIMIT,
        description=(
            "Maximum requests from a single IP within the DDoS window before the "
            "IP is throttled (HTTP 429). Raise for large NAT deployments; lower "
            "for stricter DDoS posture. YSG-RISK-056."
        ),
        allowed_type="int",
        env_var="YASHIGANI_DDOS_PER_IP_LIMIT",
        class_default=5000,
    ),
    SettingMeta(
        key=KEY_DDOS_WINDOW_SECONDS,
        description=(
            "Fixed-window duration (seconds) for DDoS per-IP counter. "
            "Shorter = tighter burst window; longer = rolling average. "
            "YSG-RISK-056."
        ),
        allowed_type="int",
        env_var="YASHIGANI_DDOS_WINDOW_SECONDS",
        class_default=60,
    ),
]

# Indexed by key for O(1) lookup
KNOWN_SETTINGS_BY_KEY: dict[str, SettingMeta] = {s.key: s for s in KNOWN_SETTINGS}
