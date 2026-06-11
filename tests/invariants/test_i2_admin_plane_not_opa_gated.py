"""
I2 — The admin plane is NOT OPA-gated, BY DESIGN. Lock the boundary.

INVARIANT (must ALWAYS hold): `/admin/*` backoffice routes authorise via
AdminSession / StepUpAdminSession (+ SPIFFE on writes), NOT via an OPA
authorisation query. The backoffice may PUSH data TO OPA (RBAC bindings, document
policy data, agent registry) — that is the data plane feeding the policy engine —
but it must NEVER consult OPA to decide whether to admit an admin request.

Why an invariant (the deliberate boundary, per Lu §2.1 / Iris S7 design-call):
OPA is the DATA-plane policy engine. The admin plane is intentionally gated by
admin-session + step-up, because routing admin authz through OPA would force admin
identities / PII into OPA input and re-create the PII-paradox the team explicitly
avoided. This test LOCKS that decision so no future change can silently OPA-gate
admin (which would look like "more security" but break the design and leak admin
context into the policy plane).

Asserted here: (1) backoffice route modules import AdminSession/StepUp and use
them as the auth dependency; (2) no route module issues an OPA *authorisation
decision query* (``/v1/data/yashigani/<decision>``). Pushes to OPA
(``push_*`` / data writes) are explicitly permitted.

LIVE-PROOF (#44): a live walk of /admin/* confirming admit/deny is session-driven
(not OPA-driven) is the VM item; here we lock the code boundary.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ROUTES_DIR = REPO_ROOT / "src" / "yashigani" / "backoffice" / "routes"

# Modules that are NOT admin-request route handlers and are allowed to talk to OPA
# freely: the policy-authoring admin tool + the OPA assistant tool. These EDIT
# policy; they are not "is this admin request allowed?" gates.
_POLICY_TOOLING = {"policies.py", "opa_assistant.py"}

# An OPA *authorisation decision* query — the thing the admin plane must NOT do.
# We forbid querying a yashigani decision rule. (push endpoints are /v1/data/<pkg>
# with a PUT/POST body, surfaced through push_* helpers — allowed.)
_OPA_DECISION_QUERY = re.compile(
    r"/v1/data/yashigani/(?:v1/)?(?:decision|response_decision|allow\b|"
    r"agent_call_allowed|agent_response_decision|proxy_response_decision)"
)


def _route_modules() -> list[Path]:
    return sorted(
        p
        for p in ROUTES_DIR.glob("*.py")
        if p.name not in {"__init__.py"} and not p.name.startswith("_")
    )


def test_routes_dir_exists() -> None:
    assert ROUTES_DIR.is_dir(), f"backoffice routes dir missing: {ROUTES_DIR}"


def test_admin_routes_use_admin_session_dependency() -> None:
    """At least the admin-authz primitives exist and are imported by the route
    layer — AdminSession / StepUpAdminSession are the admin-plane gate."""
    imports_admin_session = False
    for p in _route_modules():
        text = p.read_text(encoding="utf-8")
        if "AdminSession" in text or "StepUpAdminSession" in text:
            imports_admin_session = True
            break
    assert imports_admin_session, (
        "no backoffice route imports AdminSession/StepUpAdminSession — the admin "
        "plane must be session-gated."
    )


@pytest.mark.parametrize("path", _route_modules(), ids=lambda p: p.name)
def test_no_admin_route_queries_opa_for_authz(path: Path) -> None:
    """No admin route module issues an OPA authorisation *decision* query.

    Pushing data TO OPA (push_rbac_data / push_document_data / push_bindings_data /
    push_opa) is allowed and expected — that is the data plane feeding the engine.
    Querying an OPA *decision rule* to admit an admin request is the forbidden
    pattern that would silently OPA-gate the admin plane.
    """
    if path.name in _POLICY_TOOLING:
        pytest.skip(f"{path.name} is OPA policy-authoring tooling, not an authz gate")
    text = path.read_text(encoding="utf-8")
    hits = [m.group(0) for m in _OPA_DECISION_QUERY.finditer(text)]
    assert not hits, (
        f"{path.name} issues an OPA authorisation decision query {hits} — the admin "
        f"plane must NOT be OPA-gated (deliberate boundary, Lu §2.1). If admin authz "
        f"is intentionally moving to OPA, that is a design change requiring Tiago "
        f"sign-off and an update to this invariant — not a silent edit."
    )


def test_opa_decision_queries_live_only_in_data_plane() -> None:
    """Positive control: the OPA decision queries DO exist on the data plane
    (gateway), proving the regex matches real queries and the admin-plane absence
    above is meaningful (not a regex that never matches anything)."""
    gateway_dir = REPO_ROOT / "src" / "yashigani" / "gateway"
    found = False
    for p in gateway_dir.glob("*.py"):
        if _OPA_DECISION_QUERY.search(p.read_text(encoding="utf-8")):
            found = True
            break
    assert found, (
        "expected OPA decision queries on the gateway data plane — the I2 regex "
        "matches nothing, so the admin-plane assertion would be vacuous."
    )
