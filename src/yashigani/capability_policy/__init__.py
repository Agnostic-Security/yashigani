"""
Yashigani Capability Policy — browser Permissions-Policy, admin-configurable.

Capabilities: camera, microphone, geolocation, display-capture, fullscreen.
Per-capability value: off | self | allow_list (with optional https:// origins).

Scope and precedence (Redis-backed, db/3):
    user override  >  most-restrictive group override  >  org policy  >  BASELINE

BASELINE = default_policy() = hardcoded self×5, immutable, not in Redis.
Org policy = cap_policy:org:{org_id}, operator-configurable.
Group/user = partial overrides.

Public API used by header middlewares:
    from yashigani.capability_policy.resolver import resolve_policy, DEFAULT_ORG_ID
    from yashigani.capability_policy.header import render_permissions_policy
    from yashigani.capability_policy.store import CapabilityPolicyStore
"""

from yashigani.capability_policy.model import (
    CAPABILITY_NAMES,
    CAPABILITY_VALUES,
    MAX_ALLOW_LIST_ENTRIES,
    CapabilitySetting,
    CapabilityPolicySet,
    default_policy,
    validate_capability_name,
    validate_capability_setting,
    validate_policy_set,
    ValidationError,
)
from yashigani.capability_policy.store import CapabilityPolicyStore
from yashigani.capability_policy.resolver import resolve_policy, DEFAULT_ORG_ID
from yashigani.capability_policy.header import render_permissions_policy

__all__ = [
    "CAPABILITY_NAMES",
    "CAPABILITY_VALUES",
    "MAX_ALLOW_LIST_ENTRIES",
    "CapabilitySetting",
    "CapabilityPolicySet",
    "CapabilityPolicyStore",
    "DEFAULT_ORG_ID",
    "default_policy",
    "resolve_policy",
    "render_permissions_policy",
    "validate_capability_name",
    "validate_capability_setting",
    "validate_policy_set",
    "ValidationError",
]
