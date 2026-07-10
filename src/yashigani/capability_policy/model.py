"""
Yashigani Capability Policy — Data model.

Supports exactly 5 browser capabilities: camera, microphone, geolocation,
display-capture, fullscreen.  Each capability may be configured as:

    off        — renders as  camera=()
    self       — renders as  camera=(self)
    allow_list — renders as  camera=(self "https://origin" ...)

Last updated: 2026-06-27T00:00:00+00:00

Scope precedence (highest → lowest):
    user override  >  most-restrictive group override  >  org policy  >  BASELINE

The BASELINE (default_policy()) is the hardcoded, immutable system fallback —
self×5 for all 5 capabilities.  It is NOT stored in Redis and NOT operator-editable.
The org policy is the lowest operator-configurable level (see store.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Valid capability names and values
# ---------------------------------------------------------------------------

CAPABILITY_NAMES: frozenset[str] = frozenset({
    "camera",
    "microphone",
    "geolocation",
    "display-capture",
    "fullscreen",
})

CAPABILITY_VALUES: frozenset[str] = frozenset({"off", "self", "allow_list"})

# Restrictiveness ordering used by the group-merge resolver:
# off (0) is most restrictive; allow_list (2) is least.
_RESTRICTIVENESS: dict[str, int] = {"off": 0, "self": 1, "allow_list": 2}

# Maximum origins in a single allow_list entry (per capability).
MAX_ALLOW_LIST_ENTRIES: int = 10

# Validates an HTTPS origin: https://hostname  or  https://hostname:port
# No paths, no fragment, no wildcard hostnames.
_HTTPS_ORIGIN_RE = re.compile(
    r'^https://[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*(:[0-9]{1,5})?$'
)


# ---------------------------------------------------------------------------
# Core dataclass
# ---------------------------------------------------------------------------

@dataclass
class CapabilitySetting:
    """
    Policy setting for one browser capability.

    value:      "off" | "self" | "allow_list"
    allow_list: list of https:// origins — only meaningful when value="allow_list"
    """
    value: str
    allow_list: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"value": self.value, "allow_list": list(self.allow_list)}

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilitySetting":
        return cls(value=d["value"], allow_list=list(d.get("allow_list", [])))

    def restrictiveness(self) -> int:
        """Lower value = more restrictive. off=0 < self=1 < allow_list=2."""
        return _RESTRICTIVENESS.get(self.value, 2)


# Full resolved policy: all 5 capabilities guaranteed.
CapabilityPolicySet = dict[str, CapabilitySetting]


# ---------------------------------------------------------------------------
# Default policy (non-breaking: all "self")
# ---------------------------------------------------------------------------

def default_policy() -> CapabilityPolicySet:
    """
    Return the immutable system BASELINE policy.

    All 5 capabilities are set to "self" — a non-breaking default that keeps
    OpenWebUI mic/voice and client-side geofencing/impossible-travel working.

    This is the hardcoded, operator-immutable floor.  It is used only when no
    org policy exists for the principal's org (i.e. as the final resolver
    fallback).  Operators configure the org tier instead (cap_policy:org:{id}).

    Called fresh each time to prevent accidental shared mutation.
    """
    return {cap: CapabilitySetting(value="self") for cap in CAPABILITY_NAMES}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when a policy entry fails validation."""


def validate_capability_name(name: str) -> None:
    """Raise ValidationError if *name* is not one of the 5 valid capabilities."""
    if name not in CAPABILITY_NAMES:
        raise ValidationError(
            f"Unknown capability {name!r}. Valid names: {sorted(CAPABILITY_NAMES)}"
        )


def validate_capability_setting(name: str, setting: CapabilitySetting) -> None:
    """Raise ValidationError if *setting* is invalid for *name*."""
    validate_capability_name(name)
    if setting.value not in CAPABILITY_VALUES:
        raise ValidationError(
            f"Capability {name!r}: value must be one of {sorted(CAPABILITY_VALUES)}"
        )
    if setting.value == "allow_list":
        if len(setting.allow_list) > MAX_ALLOW_LIST_ENTRIES:
            raise ValidationError(
                f"Capability {name!r}: allow_list may contain at most "
                f"{MAX_ALLOW_LIST_ENTRIES} entries (got {len(setting.allow_list)})"
            )
        for origin in setting.allow_list:
            if not _HTTPS_ORIGIN_RE.fullmatch(origin):
                raise ValidationError(
                    f"Capability {name!r}: invalid origin {origin!r}. "
                    "Must be a valid https:// origin (scheme + host, no path, "
                    "no wildcard hostnames)"
                )


def validate_policy_set(
    policy: dict,
    *,
    require_all: bool = False,
) -> None:
    """
    Validate a dict of capability_name → CapabilitySetting.

    require_all=True  → all 5 capabilities must be present (used for global PUT).
    require_all=False → partial dict is acceptable (per-group / per-user PUT).
    """
    for name in policy:
        validate_capability_name(name)
    if require_all:
        missing = CAPABILITY_NAMES - set(policy)
        if missing:
            raise ValidationError(
                f"Org policy must define all 5 capabilities. "
                f"Missing: {sorted(missing)}"
            )
    for name, setting in policy.items():
        validate_capability_setting(name, setting)
