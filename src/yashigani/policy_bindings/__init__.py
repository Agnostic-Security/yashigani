"""Yashigani policy-bindings (#16, OPA Phase 2).

Maps activated client policies (OPA modules under data.clients.<name>) to a
subject scope (kind + optional id) and a direction (ingress|egress), so the
gateway can enforce per-client policies on the right callers in the right
direction. The binding set is pushed to OPA under the SEPARATE
/v1/data/client_bindings namespace (never /v1/data/yashigani, which
push_rbac_data now sub-path-PUTs at /v1/data/yashigani/rbac and
/v1/data/yashigani/agents only — YSG-RISK-176).
"""
from yashigani.policy_bindings.store import BindingStore, PolicyBinding

__all__ = ["BindingStore", "PolicyBinding"]
