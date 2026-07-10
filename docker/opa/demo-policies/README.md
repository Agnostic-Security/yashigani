# Demo client OPA policies (POL-001 … POL-008)

The eight self-describing client OPA policies seeded by `scripts/populate-demo.py`
(step 9 saves them via `POST /admin/policies`, step 10 binds them via
`/admin/policies/bindings`). They follow the Yashigani decision contract — each
carries `policy_id`, `user_message`, and `code` so the gateway can surface a
layman security alert at every enforcement point.

| Policy | Purpose |
|---|---|
| POL-001 data_access_control     | Baseline client data-access control |
| POL-002 finance_read_only       | Finance group: read-only |
| POL-003 compliance_audit_log    | Compliance/legal actions must emit to the audit chain |
| POL-004 pii_redaction_policy    | PII redaction on data-plane responses |
| POL-005 model_routing_control   | Restrict which models a caller may route to |
| POL-006 rate_limit_enforcement  | Per-client rate limiting |
| POL-007 agent_tool_restriction  | Restrict which tools an agent may call |
| POL-008 eu_ai_act_human_review  | EU AI Act Art.14 — human-in-the-loop on consequential decisions |

These `.rego` files are the codified source of truth (previously only embedded in
the populate script). `scripts/populate-demo.py` still embeds the same rego inline
for its API calls; keep the two in sync, or refactor the script to read these files.
