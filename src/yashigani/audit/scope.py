"""
Yashigani Audit — Masking scope configuration.
Controls which log sources have credential masking applied.
Default: all sources masked. Admin can narrow the scope.
Immutable floor events are always masked regardless of config.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from yashigani.audit.masking import AUDIT_INTEGRITY_EVENTS, IMMUTABLE_FLOOR_EVENTS
from yashigani.audit.schema import AuditEvent


@dataclass
class MaskingScopeConfig:
    """
    Masking scope settings as configured by the admin.

    Override semantics: masking wins.
    If any applicable rule says masked=True, the event is masked.
    An event is un-masked ONLY IF it is explicitly overridden to False
    AND it is not an immutable floor event type.
    """
    mask_all_by_default: bool = True
    # agent_id → masking enabled (True=mask, False=don't mask)
    agent_overrides: dict[str, bool] = field(default_factory=dict)
    # user_handle → masking enabled
    user_overrides: dict[str, bool] = field(default_factory=dict)
    # component name → masking enabled
    component_overrides: dict[str, bool] = field(default_factory=dict)

    def should_mask(
        self,
        event: AuditEvent,
        agent_id: Optional[str] = None,
        user_handle: Optional[str] = None,
        component: Optional[str] = None,
    ) -> bool:
        """
        Determine whether masking should be applied for this event.

        Immutable floor always returns True regardless of overrides.
        Otherwise: masking wins — any True override causes masking.
        """
        # Immutable floor — cannot be overridden
        if event.event_type in IMMUTABLE_FLOOR_EVENTS:
            return True

        # Audit-integrity events — never masked regardless of config.
        # These carry SHA-256 / SHA-384 anchors that auditors must read.
        if event.event_type in AUDIT_INTEGRITY_EVENTS:
            return False

        # Collect override values that apply to this event
        overrides: list[bool] = []

        if agent_id is not None and agent_id in self.agent_overrides:
            overrides.append(self.agent_overrides[agent_id])

        if user_handle is not None and user_handle in self.user_overrides:
            overrides.append(self.user_overrides[user_handle])

        if component is not None and component in self.component_overrides:
            overrides.append(self.component_overrides[component])

        # If any applicable override explicitly enables masking → mask
        if any(overrides):
            return True

        # If all applicable overrides explicitly disable masking → don't mask
        if overrides and not any(overrides):
            return False

        # No applicable overrides — fall back to global default
        return self.mask_all_by_default
