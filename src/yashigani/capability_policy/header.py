"""
Yashigani Capability Policy — Permissions-Policy header rendering.

Renders a resolved CapabilityPolicySet into the Permissions-Policy HTTP
header string format as defined by the W3C Permissions Policy specification.

Format:
    camera=()                                      → off
    camera=(self)                                  → self
    camera=(self "https://a.com" "https://b.com")  → allow_list

Last updated: 2026-06-27T00:00:00+00:00
"""
from __future__ import annotations

from yashigani.capability_policy.model import CapabilitySetting, CapabilityPolicySet

# Emit capabilities in a consistent, deterministic order.
# Alphabetical so the header value is stable across deployments.
_CAP_ORDER: tuple[str, ...] = (
    "camera",
    "display-capture",
    "fullscreen",
    "geolocation",
    "microphone",
)


def render_permissions_policy(policy: CapabilityPolicySet) -> str:
    """
    Render *policy* as a Permissions-Policy header string.

    All 5 capabilities are emitted in alphabetical order regardless of which
    capabilities are present in *policy* (missing capabilities fall back to
    "self" — the non-breaking default).

    Examples:
        {"camera": CapabilitySetting("off"), ...}
            → "camera=(), display-capture=(self), ..."

        {"microphone": CapabilitySetting("allow_list", ["https://voice.example.com"])}
            → "..., microphone=(self \"https://voice.example.com\")"
    """
    parts: list[str] = []

    for cap in _CAP_ORDER:
        setting: CapabilitySetting = policy.get(cap, CapabilitySetting(value="self"))

        if setting.value == "off":
            parts.append(f"{cap}=()")

        elif setting.value == "self":
            parts.append(f"{cap}=(self)")

        else:  # allow_list
            if setting.allow_list:
                quoted = " ".join(f'"{o}"' for o in setting.allow_list)
                parts.append(f"{cap}=(self {quoted})")
            else:
                # Degenerate allow_list with zero entries — treat as self.
                parts.append(f"{cap}=(self)")

    return ", ".join(parts)
