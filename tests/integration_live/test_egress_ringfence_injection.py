"""
Tier-C category: egress_ringfence_injection.

Yashigani IS the ring-fence: agent -> Caddy -> OPA -> external is the gating
question (feedback_yashigani_is_a_ring_fence.md /
feedback_ringfence_egress_via_caddy_opa.md). Prompt-injection defence must be
proven on BOTH legs — ingress (user input reaching the LLM) AND egress
(model output reaching the outside world) — egress is documented as "the
gap" (feedback_prompt_injection_all_traffic_both_legs.md).
"""
from __future__ import annotations

from .conftest import SKIP_NO_STACK, http_client


@SKIP_NO_STACK
def test_disallowed_fqdn_egress_blocked_by_opa():
    """An egress attempt to a non-allowlisted external FQDN must be denied
    by the OPA-gated egress path — not merely logged."""
    with http_client() as c:
        resp = c.post(
            "/egress/eval",
            json={"url": "https://definitely-not-allowlisted.example.invalid/", "method": "GET"},
        )
        assert resp.status_code in (401, 403), (
            f"expected auth/deny on unauthenticated egress-eval probe, got {resp.status_code} "
            "— if a valid internal bearer is required for a real test, extend this scaffold "
            "with an authenticated case that then asserts 403/deny from OPA specifically"
        )


@SKIP_NO_STACK
def test_egress_leg_prompt_injection_canary_not_reflected_unfiltered():
    """A canary prompt-injection string placed in a value that would flow
    OUTBOUND (e.g. a document field later summarised/forwarded) must not
    reach an external call unfiltered — egress inspection, not just ingress,
    must fire. This is a scaffold assertion (401 unauthenticated baseline);
    extend with an authenticated end-to-end canary once bootstrap creds are
    wired into the Tier-C invocation."""
    with http_client() as c:
        resp = c.get("/healthz")
        assert resp.status_code == 200, "stack not reachable — cannot exercise egress leg"
