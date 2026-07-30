"""
Regression tests — YSG-RISK-170 (chat-path repair, 2026-07-30).

Root cause: gateway/egress_proxy.py::egress_eval() hardcoded a single
sensitivity ceiling ("PUBLIC") for EVERY egress prefix. PUBLIC is correct for
the genuinely external notification prefixes (slack / slack-hooks / telegram
-- real 3rd-party destinations) but was ALSO applied, unmodified, to the
"llm" prefix -- the agent's own reasoning self-call to the fully-internal
"gateway-inference" destination (bundles/{langflow,letta,openclaw}-egress.yaml
all mark "llm" as a "Reserved internal class", never internet-facing).

Live-confirmed via `docker logs openclaw` (embedded agent framework log):

    embedded run agent end: ... error=403 "result_sensitivity_exceeds_caller_ceiling"

on a one-sentence greeting -- a false-positive on the M4 injection-pattern
heuristic elevated `result_sensitivity` to RESTRICTED, which exceeds the
PUBLIC ceiling meant for Slack/Telegram, denying the agent's own internal
LLM self-call. openclaw's embedded agent then surfaced this to the gateway
as a masked HTTP 500 (compounding YSG-RISK-167).

Confirmed NOT a PII-detector false positive: the observed deny_reason was
`result_sensitivity_exceeds_caller_ceiling`, not `pii_detected_in_result` --
`pii_detected=False`. The separate hard PII/secrets gate
(`policy/mcp.rego`'s `not input.result.pii_detected == true` check) is
UNTOUCHED by this fix and remains fully enforced regardless of ceiling.

Fix: per-prefix ceiling. "llm" gets a ceiling that does not artificially cap
the reserved-internal class; every other prefix (slack, slack-hooks,
telegram, and any future prefix) keeps the unchanged PUBLIC ceiling correct
for real external egress. Does NOT weaken external-egress enforcement.
"""
from __future__ import annotations


class TestRisk170PerPrefixCeiling:
    """egress_proxy.py must NOT apply the external-notification PUBLIC
    ceiling to the internal 'llm' self-call class, and MUST keep it for
    every genuinely external prefix."""

    def test_llm_prefix_does_not_get_public_ceiling(self):
        from yashigani.gateway.egress_proxy import _egress_ceiling_for_prefix

        ceiling = _egress_ceiling_for_prefix("llm")
        assert ceiling != "PUBLIC", (
            "YSG-RISK-170 regression: the 'llm' (reserved-internal, agent "
            "self-call) prefix must not be capped at the external-egress "
            f"PUBLIC ceiling — got {ceiling!r}"
        )

    def test_external_prefixes_keep_public_ceiling(self):
        from yashigani.gateway.egress_proxy import _egress_ceiling_for_prefix

        for prefix in ("slack", "slack-hooks", "telegram", "some-future-prefix"):
            ceiling = _egress_ceiling_for_prefix(prefix)
            assert ceiling == "PUBLIC", (
                f"External-notification prefix {prefix!r} must keep the "
                f"PUBLIC ceiling (do not weaken genuine external-egress "
                f"enforcement) — got {ceiling!r}"
            )

    def test_llm_ceiling_permits_injection_pattern_false_positive(self):
        """The exact live-observed failure mode: result_sensitivity elevated
        to RESTRICTED by injection_detected=True (pii_detected=False) must
        NOT exceed the llm-prefix ceiling."""
        from yashigani.gateway import egress_proxy

        result_rank = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
        llm_ceiling = egress_proxy._egress_ceiling_for_prefix("llm")
        # result_sensitivity="RESTRICTED" is what egress_eval() computes when
        # pii_detected or injection_detected is True (see module source).
        assert result_rank[llm_ceiling] >= result_rank["RESTRICTED"], (
            f"llm-prefix ceiling {llm_ceiling!r} (rank "
            f"{result_rank.get(llm_ceiling)}) must be >= RESTRICTED's rank "
            f"(3) so an injection-pattern false positive on the agent's own "
            f"self-call does not false-DENY it"
        )

    def test_pii_hard_gate_is_independent_of_ceiling(self):
        """This fix must not touch the separate hard-PII gate in
        policy/mcp.rego — confirm the source still carries the independent
        `not input.result.pii_detected == true` check untouched by any
        ceiling value."""
        import os

        repo_root = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
        )
        rego_path = os.path.join(repo_root, "policy", "mcp.rego")
        with open(rego_path, "r", encoding="utf-8") as fh:
            rego_src = fh.read()
        assert "not input.result.pii_detected == true" in rego_src, (
            "The independent hard PII/secrets gate in mcp.rego must remain "
            "present and unconditional on ceiling — YSG-RISK-170 fix must "
            "not weaken it"
        )
