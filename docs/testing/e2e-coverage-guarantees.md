# E2E Coverage Guarantees

**Last updated:** 2026-05-24
**Owner:** Ava (QA)
**Linked risk:** YSG-RISK-059

---

## The gap this document addresses

Prior to v2.24.1, Yashigani E2E test sweeps (Tier 1 MAX) verified:

- Container health (`docker inspect` healthcheck status)
- Agent registration (Redis `agent:index:active` set)
- Service reachability (`GET /healthz` from inside the gateway container)
- `/v1/models` returning a model list

These checks all **passed** across five platforms even when BUG-V241-LANGFLOW-LETTA-BASE-URL
was present. The bug caused every langflow and letta inference dispatch to fail at runtime,
but none of the above checks exercised the actual dispatch data path.

This document records the **A1 amendment principle** applied to agent dispatch testing
and the rules for extending coverage when new agent bundles are added.

---

## Container-healthy vs dispatch-working

These are two distinct properties:

| Property | What it proves | Test mechanism |
|---|---|---|
| **Container-healthy** | The process started; the health endpoint responds; no crash at startup | `docker inspect .State.Health.Status` or `GET /healthz` |
| **Dispatch-working** | A real LLM inference request travels the full data path and returns a non-empty response | `POST /v1/chat/completions` with `model: @<agent>` and assertion on `choices[0].message.content` |

Container-healthy does NOT imply dispatch-working. The specific failure mode for
BUG-V241-LANGFLOW-LETTA-BASE-URL was:

1. Langflow container starts successfully (healthcheck PASS).
2. Agent registers in Redis with `upstream_url: http://langflow:7860` (registration PASS).
3. Gateway receives `POST /v1/chat/completions` with `model: @langflow`.
4. Gateway calls langflow at `http://langflow:7860`.
5. Langflow attempts to call back to gateway at `OPENAI_API_BASE: http://gateway:8080/v1`.
6. Gateway port 8080 requires mutual TLS (`ssl.CERT_REQUIRED`) — langflow has no client cert.
7. TLS handshake fails → langflow returns an error → gateway returns HTTP 502.

Steps 1-4 all pass standard health/registration checks. Step 5-7 is the silent failure.
No prior E2E test asserted the outcome of step 7.

---

## The A1 amendment principle

**Rule (from `feedback_admin_bootstrap_both_admins.md` §A1):**

> Absence of a test artefact = SKIP, not PASS. PASS requires positive evidence
> that each step of the test ran AND its expected artefact materialised.

Applied to agent dispatch: a test that verifies container health, agent registration,
and `/healthz` reachability does NOT PASS the "dispatch works" requirement. The
specific artefact required is:

```
choices[0].message.content != "" AND HTTP 200 from POST /v1/chat/completions
```

Any E2E sweep that asserts only health/registration/reachability must be recorded as
**SKIP for dispatch-working**, not PASS.

---

## Test layers for agent dispatch

### Layer A — Static contract tests (no stack needed)

Location: `tests/contracts/test_agent_base_url_port.py`

These tests run on every PR and push. They check that config values in
`docker/docker-compose.yml` and `helm/yashigani/values.yaml` use the correct
gateway port (8081, plain-HTTP mesh) rather than the mTLS port (8080).

These are the REGRESSION GATE for the config-class of this bug. They:
- Run in seconds (no stack, no Docker, no network).
- Block merges if a compose/Helm change introduces the wrong port.
- Are part of the `agent-dispatch-e2e.yml` workflow AND the main `ci.yml` contract suite.

### Layer B — Live dispatch tests (stack required)

Location: `src/tests/e2e/test_agent_dispatch_e2e.py`

These tests require a running Yashigani stack with the relevant agent profiles active
(`--agent-bundles langflow,letta,openclaw`). They:
- Send real `POST /v1/chat/completions` requests with `model: @langflow`, `@letta`, `@openclaw`.
- Assert `HTTP 200` AND `choices[0].message.content` is non-empty.
- Verify the callback leg: from inside the langflow/letta containers, confirm the
  configured `OPENAI_API_BASE` URL is reachable (200 or 401, not a connection error).
- SKIP when the stack is not running (not a blocking failure for CI without a stack).
- Run nightly via the `agent-dispatch-e2e.yml` workflow scheduled trigger on a
  self-hosted runner with a live stack.

---

## Adding a new agent bundle

When a new agent bundle is added to Yashigani:

1. **Add to Layer A contract tests.** If the new agent calls back to the gateway
   (i.e., it has an `OPENAI_API_BASE` or similar env var pointing at the gateway),
   add a test in `tests/contracts/test_agent_base_url_port.py` asserting it uses
   port 8081. Copy the `test_langflow_openai_api_base_uses_mesh_port` pattern.

2. **Add to Layer B live tests.** Add a test in
   `src/tests/e2e/test_agent_dispatch_e2e.py::TestAgentDispatchLive` that:
   - Skips if the agent container is not running.
   - Sends `POST /v1/chat/completions` with `model: @<agent_name>`.
   - Asserts HTTP 200 + non-empty `choices[0].message.content`.

3. **Register the upstream URL check.** If the agent calls back to the gateway
   (pull-through inference), add a round-trip test (see
   `test_langflow_gateway_round_trip_from_inside_langflow` as pattern) that:
   - Executes inside the new agent's container.
   - Reads `OPENAI_API_BASE` from the container environment.
   - Confirms the URL is reachable at the application layer (200 or 401).

4. **Update the Helm contract test** if the agent has a Helm values.yaml entry.
   Add it to `TestHelmAgentBaseUrlPort.test_helm_langflow_openai_api_base_uses_mesh_port`.

5. **Add to the CI workflow path filter.** Add the new agent's
   `helm/yashigani/templates/<agent>.yaml` to the `paths:` list in
   `.github/workflows/agent-dispatch-e2e.yml`.

---

## What the existing tests DO NOT cover

The Layer B tests cover the **happy path** (agent registered, dispatch succeeds).
They do NOT cover:

- Agent authentication failure (wrong bearer → should return 401/403 — covered by
  the existing auth E2E suite).
- TOTP replay on agent registration (covered by `tests/install/test_agent_reg_totp_window.sh`).
- Budget exhaustion during dispatch (covered by `src/tests/e2e/test_budget_e2e.py`).
- Sensitivity classification of agent responses (covered by
  `src/tests/e2e/test_ollama_sensitivity.py`).
- Agent-to-agent RBAC (covered by `src/tests/unit/test_gateway_auth.py`).

If dispatch is broken for all agents simultaneously, the contract tests (Layer A) will
catch the config-class cause. If dispatch is broken for a specific agent due to a runtime
issue (container OOM, misconfigured model name, Postgres unavailable for letta), Layer B
will surface it in the nightly run.

---

## Historical context

| Version | Event |
|---|---|
| v2.23.4 | BUG-2: `open-webui` was using `gateway:8080` (mTLS). Fixed to `gateway:8081`. |
| v2.24.0 | Langflow and letta added. Both inherited the pre-BUG-2 pattern: `gateway:8080`. No dispatch test added at inclusion time. |
| v2.24.1 | BUG-V241-LANGFLOW-LETTA-BASE-URL confirmed. Fix: `8080 → 8081`. This document and `tests/contracts/test_agent_base_url_port.py` added as regression gate. |

The lesson: new agent bundles added after BUG-2 needed a Laura threat model review
(per `feedback_laura_review_new_third_party_components.md`) AND a dispatch-working
test at inclusion time. Both were absent for langflow and letta.
