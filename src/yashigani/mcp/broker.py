"""
MCP Broker — core enforcement pipeline.

Per-call flow:
  1. Receive McpCallContext (posture already derived from channel by transport layer).
  2. Validate chain (mcp-c only: verify upstream JWT against JWKS).
  3. Check chain depth (gateway pre-validates before signing — belt-and-suspenders).
  4. Query OPA: /v1/data/yashigani/mcp/mcp_decision (500ms timeout, fail-closed).
  5. On OPA allow: issue ES384 gateway-signed JWT with extended chain.
  6. On OPA deny or error: return deny, do NOT issue JWT.
  7. Emit audit events: MCP_CALL + OPA_DECISION_ON_MCP (on EVERY call).
     A clean allowed call MUST leave a witness record (AU-2/12/CC7.1).
     Full-record variant (args) when audit_capture=True from OPA.

OPA healthcheck: McpBroker.opa_health() queries OPA /health.

Phase-2 hardening (implemented):
  [M4] MCP tool-description / prompts.get prompt-injection content filter.
       fetch_and_filter_tools() / fetch_and_filter_prompt() apply the filter
       and emit McpToolDescriptionFetchedEvent on every catalogue fetch.
  [P8] Upstream MCP-server cert/SPIFFE pinning enforcement.
       enforce() calls verify_upstream() as Step 2f (after all OPA/envelope
       gates, before JWT issuance). The MCP runtime also calls it before
       non-gated forwards (session/notification/passthrough).
       Mismatch or missing pin in prod/staging raises ConnectionError → deny;
       logs/audits MCP_UPSTREAM_CERT_PIN_MISMATCH / pin_not_configured.
  [P1-pool] Per-tenant provider-key cache + per-tenant connection pools.
       McpBroker.pool_manager exposes a TenantPoolManager keyed by
       (tenant_id, provider_host) — never shared across tenant_ids.

v2.25.0 / P1 W3 Phase 2b-ii + Phase 2 hardening /
  YSG-RISK-054 (audit) + YSG-RISK-055 (posture) + YSG-RISK-056 (upstream pin)
  + YSG-RISK-057 (cross-tenant isolation).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import types as _types
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

import httpx

from yashigani.mcp._types import (
    BrokerDecision,
    EgressDecision,
    McpCallContext,
    McpPosture,
    OpaDecision,
)
from yashigani.identity.trust_domain import agent_spiffe_uri
from yashigani.mcp._jwt import ChainDepthExceeded, McpJwtIssuer, McpJwtVerifier
from yashigani.mcp._nonce import NonceStore, InMemoryNonceStore
from yashigani.mcp._opa import (
    query_mcp_decision,
    query_mcp_response_decision,
    query_filesystem_tool_allowed,
    query_git_tool_allowed,
    OpaResponseDecisionResult,
    _normalize_tool_args,
)
from yashigani.mcp._content_filter import (
    FilterResult,
    ToolCatalogueStore,
    build_catalogue,
    TenantCatalogue,
)
from yashigani.mcp._upstream_pin import (
    UpstreamPinConfig,
    PinVerificationResult,
    verify_upstream_pin,
)
from yashigani.mcp._upstream_revocation import _ENFORCE_ENVS as _MCP_ENFORCE_ENVS
from yashigani.mcp._pool import TenantPoolManager

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class McpBrokerConfig:
    """
    Configuration for McpBroker.

    opa_url:
        Base URL of the OPA server (e.g. "http://policy:8181").
        Required. Broker fails-closed (denies everything) if OPA is unreachable.

    tenant_id:
        Tenant identifier. Embedded in JWT iss + identity.spiffe.

    issuer:
        Pre-constructed McpJwtIssuer. If None, one is created at broker init
        with an ephemeral key (dev/test mode only).

    nonce_store:
        Nonce store for jti replay prevention. If None, InMemoryNonceStore
        is used (dev mode — not crash-safe; Redis required for production).

    chain_max_depth:
        Maximum allowed chain depth. Default 9, kept in sync with the pinned OPA policy
        constant `mcp_chain_max_depth` (YSG-RISK-056 — no longer runtime-overridable via OPA
        data; changing it is a reviewed policy edit, pending a governed admin-UI setting).
        Gateway pre-validates before signing; OPA is the authoritative gate.

    audit_writer:
        AuditLogWriter instance for emitting MCP_CALL + OPA_DECISION_ON_MCP events.
        If None, audit events are logged at WARNING level only (test mode).

    # Phase-2 hardening fields ---

    catalogue_store:
        [M4] ToolCatalogueStore for per-tenant tool-description catalogues.
        If None, a new store is created at broker init.  Callers can pass a
        shared store so multiple broker instances for the same tenant share
        catalogue state.

    upstream_pin_configs:
        [P8] List of UpstreamPinConfig entries for upstream MCP server pinning.
        If None or empty, no pinning is enforced (warn-only in dev, reject in prod).

    pool_manager:
        [P1-pool] TenantPoolManager for per-tenant HTTP connection pools.
        If None, a new manager is created at broker init.

    semantic_intent_sidecar:
        [v2.26 / YSG-RISK-057] Optional content-filter v2 sidecar.  When
        supplied AND the YASHIGANI_SEMANTIC_INTENT_SIDECAR flag is ON, each
        clean-heuristic tool description / prompt gets a second, encoding-aware
        look (decode-before-classify) that catches the encoded-injection
        residual the v1 heuristic cannot.  When None or the flag is OFF, the
        broker's filter path is byte-identical to v1.  Escalate-only,
        fail-closed — see ``inspection.semantic_intent``.
    """

    opa_url: str
    tenant_id: str
    issuer: Optional[McpJwtIssuer] = None
    verifier: Optional[McpJwtVerifier] = None
    nonce_store: Optional[NonceStore] = None
    chain_max_depth: int = 9
    audit_writer: Optional[Any] = None   # AuditLogWriter, typed as Any to avoid circular import

    # Phase-2 hardening
    catalogue_store: Optional[ToolCatalogueStore] = None
    upstream_pin_configs: Optional[list] = None  # list[UpstreamPinConfig]
    pool_manager: Optional[TenantPoolManager] = None

    # v2.26 / YSG-RISK-057 — content-filter v2 semantic-intent sidecar.
    semantic_intent_sidecar: Optional[Any] = None  # SemanticIntentSidecar

    # 3.0 / YSG-RISK-060 — imported-MCP capability-envelope service.
    #
    # When supplied, broker.enforce() runs the INVOCATION HARD GATE (Laura
    # R3-3 / Iris §3.1.2): a tools/call whose (provenance_id, tool_name) is not
    # inside an ACTIVE approved envelope — or whose envelope is blocked / whose
    # surface mutated away from the materialised byte-hash — fails closed.  This
    # is the load-bearing security boundary; the refresh-time triage is
    # defence-in-depth on top.
    #
    # When None, the gate is a NO-OP in dev/test (no envelopes provisioned);
    # in production/staging it is REQUIRED for any pinned imported MCP — the
    # broker fail-closes a call against a server that has pin material but no
    # envelope service to consult.
    envelope_service: Optional[Any] = None  # CapabilityEnvelopeService

    # 3.0 — whether the capability-envelope invocation gate is enforced for
    # this broker's imported MCP servers.  Defaults to True when an
    # envelope_service is wired; an operator may not silently disable it in
    # prod (the gate fail-closes a pinned server regardless).
    enforce_capability_envelope: bool = True

    # 3.0 / YSG-RISK-060 (Ava — re-approval SPA wiring) — optional callback the
    # broker invokes when it LATCHES a block on a refresh, handing the
    # operator-facing layer the CANDIDATE (refreshed) surface so the re-approval
    # admin SPA can show the diff vs the ORIGINAL baseline and mint it on a
    # step-up approve.  Signature:
    #     sink(provenance_id, tenant_id, server_id, candidate_env,
    #          triage_class, new_surface_hash, findings) -> None
    # None ⇒ no operator queue wired (dev/test, or gateway-only deploy); the
    # block is still latched in the DB regardless (the queue is purely the
    # operator-visible mirror).  The callback is best-effort: a sink fault never
    # affects the fail-closed block.
    pending_block_sink: Optional[Any] = None

    # FIX-P3-ENFORCE (Iris F2): Shape-C filesystem MCP-server flag.
    # When True, broker runs a SECOND OPA gate (filesystem_tool_allowed)
    # after the global mcp_decision allow, enforcing per-tool + path-arg
    # constraints from policy/mcp.rego §P3.
    # Set to True for any agent whose manifest declares category=mcp_server.
    is_filesystem_agent: bool = False

    # P3-GIT: Shape-C git MCP-server flag.
    # When True, broker runs a second OPA gate (git_tool_allowed) after the
    # global mcp_decision allow, enforcing per-tool + repo_path constraints
    # and git_log timestamp injection guard (GIT-TM-001, GIT-TM-004).
    # Set to True for the git bundle (metadata.name == "git").
    is_git_agent: bool = False

    # 3.1 Phase 4 — connection allow-list: PermissionStore for org-level MCP
    # server access control.  When provided, ``broker.enforce()`` calls
    # ``resolve_boolean_grant(MCP_SERVER, ctx.server_id, org_id, ...)`` before
    # the OPA query to verify the caller's org has permission to reach this
    # server.  Deny-by-default: servers with no org grant are denied.
    # When None, the check is a no-op (backwards-compatible dev/test mode).
    permission_store: Optional[Any] = None  # PermissionStore

    # 3.1 Phase 4 — org ID used for the connection allow-list check.
    # Should match YASHIGANI_ORG_ID.  Defaults to "default" when unset.
    org_id: str = "default"


class McpBroker:
    """
    MCP enforcement pipeline.

    Orchestrates posture validation, OPA enforcement, JWT issuance, and
    Merkle-chained audit emission on every MCP call.

    Usage::

        broker = McpBroker(config)
        decision = await broker.enforce(call_context)
        if decision.allow:
            # forward call with decision.issued_jwt as Authorization header
            ...
    """

    def __init__(self, config: McpBrokerConfig) -> None:
        self._config = config
        self._opa_url = config.opa_url

        # JWT issuer
        if config.issuer is not None:
            self._issuer = config.issuer
        else:
            logger.warning(
                "mcp-broker: no McpJwtIssuer provided — generating ephemeral key "
                "(DEV/TEST MODE). Production requires KMS-backed issuer."
            )
            self._issuer = McpJwtIssuer(
                tenant_id=config.tenant_id,
                chain_max_depth=config.chain_max_depth,
            )

        # JWT verifier (for upstream relay JWT validation in mcp-c)
        if config.verifier is not None:
            self._verifier = config.verifier
        else:
            # Default: same-installation verifier (verifies JWTs issued by this broker)
            self._verifier = McpJwtVerifier.from_issuer(self._issuer)

        # Nonce store
        if config.nonce_store is not None:
            self._nonce_store = config.nonce_store
        else:
            self._nonce_store = InMemoryNonceStore()

        self._audit_writer = config.audit_writer

        # FIX-D (Nico + Lu): production must have a real audit_writer.
        # A ring-fence with no witness is not acceptable in production.
        # YASHIGANI_ENV=production or YASHIGANI_ENV=staging → fail loudly.
        # dev/test/local pass None freely (mock writers acceptable).
        _env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
        _prod_envs = {"production", "staging"}
        if self._audit_writer is None and _env in _prod_envs:
            raise RuntimeError(
                "McpBroker: audit_writer is None in a production/staging environment "
                f"(YASHIGANI_ENV={_env!r}). A ring-fence with no audit witness is not "
                "acceptable. Provide a real AuditLogWriter instance. "
                "YSG-RISK-054 / AU-2 / AU-12 / CC7.1."
            )

        # [M4] Tool-description catalogue store (per-tenant isolation).
        if config.catalogue_store is not None:
            self._catalogue_store = config.catalogue_store
        else:
            self._catalogue_store = ToolCatalogueStore()

        # [P8] Upstream cert/SPIFFE pin configs, indexed by server_id.
        self._upstream_pin_map: dict[str, UpstreamPinConfig] = {}
        for pin_cfg in (config.upstream_pin_configs or []):
            self._upstream_pin_map[pin_cfg.server_id] = pin_cfg

        # [P1-pool] Per-tenant connection pool manager.
        if config.pool_manager is not None:
            self._pool_manager = config.pool_manager
        else:
            self._pool_manager = TenantPoolManager()

        # [v2.26 / YSG-RISK-057] Content-filter v2 semantic-intent sidecar.
        # None by default → the filter path is byte-identical to v1.  When a
        # sidecar is supplied, it only escalates when its own feature flag is ON
        # (the flag check lives inside the sidecar / filter_description_v2), so
        # wiring a sidecar here without setting the flag is still v1 behaviour.
        self._semantic_intent_sidecar = config.semantic_intent_sidecar

        # [3.0 / YSG-RISK-060] Capability-envelope invocation gate.
        self._envelope_service = config.envelope_service
        self._enforce_capability_envelope = bool(config.enforce_capability_envelope)
        # 3.0 — operator re-approval queue sink (best-effort; see config doc).
        self._pending_block_sink = config.pending_block_sink

    async def enforce(self, ctx: McpCallContext) -> BrokerDecision:
        """
        Run the full enforcement pipeline for one MCP call.

        Always emits audit events (MCP_CALL + OPA_DECISION_ON_MCP).
        Returns BrokerDecision with allow=True + issued_jwt on success,
        or allow=False + deny_reason on failure.

        Security invariants:
        - posture in ctx MUST have been derived from the physical channel
          (YSG-RISK-055). The broker does NOT re-derive posture here.
        - On any error (OPA timeout, chain error, JWT issue error), the call
          is DENIED and the error is captured in the audit event.
        """
        t0 = time.monotonic()
        call_id = ctx.call_id

        # Step 1: mcp-c upstream JWT verification
        upstream_chain: list[str] = list(ctx.upstream_chain)
        if ctx.posture == McpPosture.MCP_C:
            verification_error = await self._verify_upstream_jwt(ctx)
            if verification_error is not None:
                elapsed = int((time.monotonic() - t0) * 1000)
                decision = BrokerDecision(
                    call_id=call_id,
                    allow=False,
                    deny_reason="upstream_jwt_verification_failed",
                    opa_decision=OpaDecision(
                        allow=False,
                        deny_reason="upstream_jwt_verification_failed",
                        redact_args=set(),
                        audit_capture=True,
                        rate_limit_key=None,
                    ),
                    chain_depth=len(upstream_chain),
                    elapsed_ms=elapsed,
                    error=verification_error,
                )
                await self._emit_audit(ctx, decision)
                return decision

        # Step 1a: Phase 4 — connection allow-list (3.1).
        #
        # Before querying OPA, verify that the caller's org is permitted to
        # reach this MCP server at all.  Deny-by-default: only servers seeded
        # with an org-level grant (via seed_mcp_grants at startup) are allowed.
        # Unregistered / mis-configured servers are denied here.
        #
        # Org ceiling check; group/user narrowing from _check_connection_permit
        # applies when the caller is identified (human: scope="user"/ctx.user_id;
        # agent: scope="agent"/caller_agent_id).  gateway:orchestrator is allowed
        # when the org grant exists (no per-principal narrowing for the orchestrator).
        conn_deny = self._check_connection_permit(ctx)
        if conn_deny is not None:
            conn_elapsed = int((time.monotonic() - t0) * 1000)
            conn_decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason=conn_deny,
                opa_decision=OpaDecision(
                    allow=False, deny_reason=conn_deny, redact_args=set(),
                    audit_capture=True, rate_limit_key=None,
                ),
                chain_depth=len(upstream_chain),
                elapsed_ms=conn_elapsed,
                error=None,
            )
            logger.info(
                "mcp-broker: [P4] connection not permitted call_id=%s server=%s "
                "caller=%s reason=%s",
                call_id, ctx.server_id or ctx.agent_name,
                ctx.caller_agent_id, conn_deny,
            )
            await self._emit_audit(ctx, conn_decision)
            return conn_decision

        # Step 1b: Phase 3 — tool allow-list (3.1).
        #
        # If the caller has a non-empty allowed_tools list in their identity
        # record (McpCallContext.caller_allowed_tools, populated by the runtime
        # from the identity registry), enforce it: only tools in the list may be
        # invoked.  "gateway:orchestrator" is exempt (unrestricted access).
        # When caller_allowed_tools is None/empty, no per-caller restriction.
        tool_deny = self._check_tool_permit(ctx)
        if tool_deny is not None:
            tool_elapsed = int((time.monotonic() - t0) * 1000)
            tool_decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason=tool_deny,
                opa_decision=OpaDecision(
                    allow=False, deny_reason=tool_deny, redact_args=set(),
                    audit_capture=True, rate_limit_key=None,
                ),
                chain_depth=len(upstream_chain),
                elapsed_ms=tool_elapsed,
                error=None,
            )
            logger.info(
                "mcp-broker: [P3] tool not permitted call_id=%s tool=%s "
                "caller=%s allowed=%s reason=%s",
                call_id, ctx.tool_name, ctx.caller_agent_id,
                ctx.caller_allowed_tools, tool_deny,
            )
            await self._emit_audit(ctx, tool_decision)
            return tool_decision

        # Step 2: query OPA (fail-closed).  MI-6 (YSG-RISK-061): build the agent
        # SPIFFE URI in THIS instance's trust domain so OPA adjudicates the
        # instance's own identity (matches the per-instance cert SAN).
        spiffe_uri = agent_spiffe_uri(ctx.tenant_id, ctx.agent_name)
        chain_for_opa = list(upstream_chain)

        # FIX-C (Iris FIND-001): pass sensitivity fields so OPA audit_capture
        # escalation for CONFIDENTIAL/RESTRICTED resources/prompts is reachable.
        # FIX-P3-001: pass tool_args (full args) for path normalisation; also
        # pass agent_name so per-agent rego packages can inspect it.
        opa_result = await query_mcp_decision(
            opa_url=self._opa_url,
            posture=ctx.posture.value,
            action=ctx.action,
            spiffe_uri=spiffe_uri,
            chain=chain_for_opa,
            tool_name=ctx.tool_name,
            tool_args_redacted=ctx.tool_args_redacted,
            tool_args=ctx.tool_args_redacted,   # normalisation applied inside _opa.py
            prompt_name=ctx.prompt_name,
            resource_uri=ctx.resource_uri,
            resource_sensitivity=ctx.resource_sensitivity,
            prompt_sensitivity=ctx.prompt_sensitivity,
            agent_name=ctx.agent_name,
            # 3.1 Phase 1 — caller identity: additive, no-op for unbound policies.
            # Mirrors the agent_router.py:326 caller+target pattern for MCP.
            caller={"agent_id": ctx.caller_agent_id or "", "user_id": ctx.user_id or ""},
        )

        elapsed = int((time.monotonic() - t0) * 1000)

        opa_decision = OpaDecision(
            allow=opa_result.allow,
            deny_reason=opa_result.deny_reason,
            redact_args=opa_result.redact_args,
            audit_capture=opa_result.audit_capture,
            rate_limit_key=opa_result.rate_limit_key,
            elapsed_ms=opa_result.elapsed_ms,
        )

        if not opa_result.allow:
            decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason=opa_result.deny_reason,
                opa_decision=opa_decision,
                chain_depth=len(chain_for_opa),
                elapsed_ms=elapsed,
                error=opa_result.error,
            )
            await self._emit_audit(ctx, decision)
            return decision

        # Step 2b (FIX-P3-ENFORCE / Iris F2): Shape-C filesystem tool-gating.
        #
        # For agents declared as category=mcp_server (is_filesystem_agent=True),
        # the global mcp_decision allow is NECESSARY but NOT SUFFICIENT.
        # A second OPA gate enforces the filesystem-specific per-tool allowlist,
        # path-traversal checks, directory_tree depth cap, and search_files
        # ReDoS cap defined in policy/mcp.rego §P3 (filesystem_tool_allowed rule).
        #
        # Without this second gate, the filesystem rules exist only in OPA policy
        # source but are NEVER queried at runtime — making them dead code.
        # This closes the Iris F2 finding: "gating MAY BE inert".
        #
        # Path normalisation (FIX-P3-001): _normalize_tool_args() was already
        # applied inside _build_opa_input() for the mcp_decision query above.
        # We re-apply here to ensure the filesystem gate receives normalised args
        # even if called standalone in tests or future refactors.
        if self._config.is_filesystem_agent and ctx.tool_name is not None:
            fs_args = _normalize_tool_args(ctx.tool_args_redacted)
            fs_result = await query_filesystem_tool_allowed(
                opa_url=self._opa_url,
                tool_name=ctx.tool_name,
                tool_args=fs_args,
            )
            if not fs_result.allowed:
                fs_elapsed = int((time.monotonic() - t0) * 1000)
                fs_decision = BrokerDecision(
                    call_id=call_id,
                    allow=False,
                    deny_reason=fs_result.deny_reason,
                    opa_decision=OpaDecision(
                        allow=False,
                        deny_reason=fs_result.deny_reason,
                        redact_args=set(),
                        audit_capture=True,
                        rate_limit_key=None,
                    ),
                    chain_depth=len(chain_for_opa),
                    elapsed_ms=fs_elapsed,
                    error=fs_result.error,
                )
                logger.info(
                    "mcp-broker: [P3] filesystem tool denied call_id=%s tool=%s reason=%s",
                    call_id, ctx.tool_name, fs_result.deny_reason,
                )
                await self._emit_audit(ctx, fs_decision)
                return fs_decision

        # Step 2c (P3-GIT): git tool-gating — parallel to step 2b for filesystem.
        #
        # For git agents (is_git_agent=True), enforce GIT-TM-001 repo_path
        # boundary check and GIT-TM-004 timestamp option injection guard via the
        # git_tool_allowed OPA rule.  Same fail-closed pattern as filesystem gate.
        if self._config.is_git_agent and ctx.tool_name is not None:
            git_args = _normalize_tool_args(ctx.tool_args_redacted)
            git_result = await query_git_tool_allowed(
                opa_url=self._opa_url,
                tool_name=ctx.tool_name,
                tool_args=git_args,
            )
            if not git_result.allowed:
                git_elapsed = int((time.monotonic() - t0) * 1000)
                git_decision = BrokerDecision(
                    call_id=call_id,
                    allow=False,
                    deny_reason=git_result.deny_reason,
                    opa_decision=OpaDecision(
                        allow=False,
                        deny_reason=git_result.deny_reason,
                        redact_args=set(),
                        audit_capture=True,
                        rate_limit_key=None,
                    ),
                    chain_depth=len(chain_for_opa),
                    elapsed_ms=git_elapsed,
                    error=git_result.error,
                )
                logger.info(
                    "mcp-broker: [P3-GIT] git tool denied call_id=%s tool=%s reason=%s",
                    call_id, ctx.tool_name, git_result.deny_reason,
                )
                await self._emit_audit(ctx, git_decision)
                return git_decision

        # Step 2d (#16): client-policy enforcement — mcp_server scope, INGRESS.
        # Runs AFTER the global mcp_decision + per-tool gates; deny-only, fail-closed;
        # no-op when this MCP server has no bound client policies. scope_id = the
        # MCP server's agent_name.
        from yashigani.gateway._client_enforce import evaluate_client_policies
        _ce = await evaluate_client_policies(
            _types.SimpleNamespace(opa_url=self._opa_url), "mcp_server", ctx.agent_name, "ingress",
            {"identity": {"agent": ctx.agent_name},
             "request": {"action": ctx.action, "tool": ctx.tool_name or ""},
             # 3.1 Phase 1 — caller identity: additive, mirrors agent_router.py:326.
             "caller": {"agent_id": ctx.caller_agent_id or "", "user_id": ctx.user_id or ""}},
        )
        if not _ce.get("allow", False):
            _ce_reason = ("client_policy:" + ",".join(_ce.get("deny", []) or ["denied"])).encode("ascii", "replace").decode("ascii")
            _ce_elapsed = int((time.monotonic() - t0) * 1000)
            ce_decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason=_ce_reason,
                opa_decision=OpaDecision(
                    allow=False, deny_reason=_ce_reason, redact_args=set(),
                    audit_capture=True, rate_limit_key=None,
                ),
                chain_depth=len(chain_for_opa),
                elapsed_ms=_ce_elapsed,
                error=None,
            )
            logger.info("mcp-broker: [#16] client-policy denied call_id=%s server=%s reason=%s",
                        call_id, ctx.agent_name, _ce_reason)
            await self._emit_audit(ctx, ce_decision)
            return ce_decision

        # Step 2e (3.0 / YSG-RISK-060): capability-envelope INVOCATION HARD GATE.
        #
        # The load-bearing security boundary (Laura R3-3 / Iris §3.1.2).  A
        # tools/call whose (provenance_id, tool_name) is not inside an ACTIVE
        # approved envelope — or whose envelope is blocked / whose live surface
        # has mutated away from the materialised byte-hash — fails CLOSED here,
        # at the call, regardless of whether the refresh-time triage raced or
        # was skipped.  The pin/triage is defence-in-depth on top of this.
        env_deny = await self._check_capability_envelope(ctx)
        if env_deny is not None:
            env_elapsed = int((time.monotonic() - t0) * 1000)
            env_decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason=env_deny,
                opa_decision=OpaDecision(
                    allow=False, deny_reason=env_deny, redact_args=set(),
                    audit_capture=True, rate_limit_key=None,
                ),
                chain_depth=len(chain_for_opa),
                elapsed_ms=env_elapsed,
                error=None,
            )
            logger.warning(
                "mcp-broker: [YSG-RISK-060] capability-envelope gate DENIED "
                "call_id=%s server=%s tool=%s reason=%s",
                call_id, ctx.server_id, ctx.tool_name, env_deny,
            )
            await self._emit_audit(ctx, env_decision)
            self._emit_envelope_blocked_at_invocation(ctx, env_deny)
            return env_decision

        # Step 2f [P8/YSG-RISK-056]: upstream cert/SPIFFE pin verification.
        #
        # verify_upstream() does a synchronous TLS handshake to check the
        # upstream server's cert fingerprint or SPIFFE ID against the pinned
        # config.  It is offloaded to a thread so the event loop is not blocked.
        # In production/staging: ConnectionError is raised by verify_upstream()
        # on mismatch or missing pin config — we convert that to a deny
        # BrokerDecision (upstream_pin_mismatch) so the runtime returns 403,
        # not 502.  In dev/test: matched=False is logged, call proceeds.
        #
        # verify_upstream() already emits the structured pin audit event
        # (MCP_UPSTREAM_PIN_OK / MCP_UPSTREAM_CERT_PIN_MISMATCH /
        # pin_not_configured) via _emit_upstream_pin_event() before raising.
        # We also emit the standard MCP_CALL + OPA_DECISION_ON_MCP witness via
        # _emit_audit() so Lu has a complete call record.  YSG-RISK-056.
        if ctx.server_id:
            try:
                await asyncio.to_thread(self.verify_upstream, ctx.server_id)
            except ConnectionError as _pin_exc:
                _pin_elapsed = int((time.monotonic() - t0) * 1000)
                _pin_reason = "upstream_pin_mismatch"
                pin_decision = BrokerDecision(
                    call_id=call_id,
                    allow=False,
                    deny_reason=_pin_reason,
                    opa_decision=OpaDecision(
                        allow=False,
                        deny_reason=_pin_reason,
                        redact_args=set(),
                        audit_capture=True,
                        rate_limit_key=None,
                    ),
                    chain_depth=len(chain_for_opa),
                    elapsed_ms=_pin_elapsed,
                    error=str(_pin_exc),
                )
                logger.warning(
                    "mcp-broker: [P8] upstream pin DENIED call_id=%s server_id=%s: %s",
                    call_id, ctx.server_id, _pin_exc,
                )
                await self._emit_audit(ctx, pin_decision)
                return pin_decision

        # Step 3: issue gateway-signed JWT (only on OPA allow)
        #
        # FIX-B (Lu FIX-1): ChainDepthExceeded must be caught and emitted with
        # an accurate deny_reason label ("chain_depth_exceeded"), not the generic
        # "jwt_issuance_failed".  Split the except so the two failure modes have
        # distinct deny_reason labels in the audit record.
        issued_jwt: Optional[str] = None
        jwt_error: Optional[str] = None
        try:
            issued_jwt = self._issuer.issue(
                user_id=ctx.user_id,
                agent_name=ctx.agent_name,
                posture=ctx.posture.value,
                posture_binding=ctx.posture_binding.to_dict(),
                action=ctx.action,
                call_id=call_id,
                upstream_chain=upstream_chain if upstream_chain else None,
            )
        except ChainDepthExceeded as exc:
            jwt_error = str(exc)
            logger.warning(
                "mcp-broker: chain_depth_exceeded call_id=%s chain_len=%d max=%d: %s",
                call_id, len(chain_for_opa), self._config.chain_max_depth, exc,
            )
            # FIX-B: emit witness with accurate label so audit trail is clear
            decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason="chain_depth_exceeded",
                opa_decision=opa_decision,
                chain_depth=len(chain_for_opa),
                elapsed_ms=int((time.monotonic() - t0) * 1000),
                error=jwt_error,
            )
            await self._emit_audit(ctx, decision)
            return decision
        except Exception as exc:
            jwt_error = str(exc)
            logger.error(
                "mcp-broker: JWT issuance failed call_id=%s: %s", call_id, exc
            )
            # JWT issuance failure → deny (cannot issue a token, call fails-closed)
            decision = BrokerDecision(
                call_id=call_id,
                allow=False,
                deny_reason="jwt_issuance_failed",
                opa_decision=opa_decision,
                chain_depth=len(chain_for_opa),
                elapsed_ms=int((time.monotonic() - t0) * 1000),
                error=jwt_error,
            )
            await self._emit_audit(ctx, decision)
            return decision

        # Step 4: compute final chain depth for audit
        # The issued JWT's chain = upstream_chain + [this hop's SPIFFE URI]
        outgoing_chain_depth = len(chain_for_opa) + 1

        decision = BrokerDecision(
            call_id=call_id,
            allow=True,
            deny_reason="ok",
            opa_decision=opa_decision,
            issued_jwt=issued_jwt,
            chain_depth=outgoing_chain_depth,
            elapsed_ms=int((time.monotonic() - t0) * 1000),
        )

        # Step 5: emit audit (EVERY call — clean allowed calls leave a witness)
        await self._emit_audit(ctx, decision)
        return decision

    async def enforce_result(
        self,
        ctx: McpCallContext,
        result_sensitivity: str,
        pii_detected: bool,
    ) -> EgressDecision:
        """
        G-ORCH-OPA-1 — MCP egress decision for a tool result.

        Called by the transport layer AFTER the upstream tool result is
        obtained and AFTER the content-filter + inspection step has produced
        a sensitivity label and PII flag.  Queries OPA
        /v1/data/yashigani/mcp/mcp_response_decision to decide whether the
        result may be returned to the calling agent.

        This is an ADDITIONAL, INDEPENDENT OPA decision layer — it does not
        replace the existing content-filter or inspection pipeline.  Both must
        run.  The call order MUST be:

          1. Get upstream result (transport layer).
          2. Run content-filter / inspection → result_sensitivity, pii_detected.
          3. Call enforce_result(ctx, result_sensitivity, pii_detected).
          4. If EgressDecision.allow is False → WITHHOLD result; return error.
             If True → return result to caller.

        Fail-closed: any OPA error (timeout, unreachable, HTTP error, undefined
        rule) results in EgressDecision.allow=False.  The result is WITHHELD
        and the error is logged.  This implements zero-trust: OPA outage = no
        result delivery (intentional, same posture as _opa_response_check in
        the gateway LLM path).

        Parameters
        ----------
        ctx :
            The McpCallContext for the call.  ctx.caller_sensitivity_ceiling
            MUST be populated by the transport layer from the authenticated
            caller identity BEFORE calling enforce_result.  If it is None,
            OPA's _result_ceiling_rank will be undefined and the decision
            will be fail-closed deny with reason="invalid_or_missing_caller_ceiling".
        result_sensitivity :
            Sensitivity label produced by the inspection/classifier pipeline
            ("PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "RESTRICTED").
            The broker's caller is responsible for providing this — reuse the
            ResponseInspectionResult.response_sensitivity value from the
            inspection pipeline; do not run a second classifier.
        pii_detected :
            True when the inspection pipeline detected PII in the result body.

        Returns EgressDecision.  Never raises.
        """
        t0 = time.monotonic()
        spiffe_uri = agent_spiffe_uri(ctx.tenant_id, ctx.agent_name)

        opa_result = await query_mcp_response_decision(
            opa_url=self._opa_url,
            caller_spiffe=spiffe_uri,
            caller_sensitivity_ceiling=ctx.caller_sensitivity_ceiling,
            caller_groups=[],   # populated from identity when available; empty is safe (not used for allow/deny currently)
            result_sensitivity=result_sensitivity,
            pii_detected=pii_detected,
            tool_name=ctx.tool_name,
            agent_name=ctx.agent_name,
        )

        elapsed = int((time.monotonic() - t0) * 1000)

        if not opa_result.allow:
            logger.info(
                "mcp-broker: [G-ORCH-OPA-1] egress DENIED call_id=%s tool=%s "
                "reason=%s result_sensitivity=%s pii=%s elapsed_ms=%d",
                ctx.call_id, ctx.tool_name, opa_result.deny_reason,
                result_sensitivity, pii_detected, elapsed,
            )
            # Emit audit for the egress denial.
            await self._emit_egress_audit(ctx, opa_result, result_sensitivity, pii_detected)
        else:
            logger.debug(
                "mcp-broker: [G-ORCH-OPA-1] egress ALLOWED call_id=%s tool=%s elapsed_ms=%d",
                ctx.call_id, ctx.tool_name, elapsed,
            )

        return EgressDecision(
            allow=opa_result.allow,
            deny_reason=opa_result.deny_reason,
            policy_id=opa_result.policy_id,
            code=opa_result.code,
            user_message=opa_result.user_message,
            elapsed_ms=elapsed,
            error=opa_result.error,
        )

    async def _emit_egress_audit(
        self,
        ctx: McpCallContext,
        opa_result: OpaResponseDecisionResult,
        result_sensitivity: str,
        pii_detected: bool,
    ) -> None:
        """
        Emit an OPA_DECISION_ON_MCP audit event for an egress denial.

        Egress allows do not emit an additional audit event beyond what
        enforce() already emitted (the ingress allow is the witness record).
        Egress denials require an explicit audit record so the operator can
        see that a result was withheld after an allowed ingress call.
        """
        try:
            from yashigani.audit.schema import (
                AccountTier,
                OpaDecisionOnMcpEvent,
            )
        except Exception as exc:
            logger.error("mcp-broker: egress audit import failed: %s", exc)
            return

        event = OpaDecisionOnMcpEvent(
            account_tier=AccountTier.SYSTEM,
            tenant_id=ctx.tenant_id,
            agent_name=ctx.agent_name,
            tool_name=ctx.tool_name or ctx.prompt_name or ctx.resource_uri or "",
            server_id=ctx.server_id,
            request_id=ctx.request_id,
            decision="deny",
            deny_reason=f"egress:{opa_result.deny_reason}",
            identity_chain=list(ctx.upstream_chain),
            chain_depth=len(ctx.upstream_chain),
            elapsed_ms=opa_result.elapsed_ms,
            # FIND-A-AUD (3.1.2): caller identity → audit_events.agent_id DB column.
            agent_id=ctx.caller_agent_id or None,
            # 3.1 UID unification: resolved identity_id from boundary resolver.
            # ctx.user_id carries idnt_{12hex} after mcp_router_runtime resolution.
            caller_identity_id=ctx.user_id or "",
        )

        if self._audit_writer is not None:
            try:
                self._audit_writer.write(event)
            except Exception as exc:
                logger.error(
                    "mcp-broker: egress audit write failed call_id=%s: %s",
                    ctx.call_id, exc,
                )
        else:
            logger.warning(
                "mcp-broker: no audit_writer — egress OPA_DECISION_ON_MCP NOT written "
                "call_id=%s reason=%s",
                ctx.call_id, opa_result.deny_reason,
            )

    def _provenance_id_for(self, server_id: str) -> Optional[str]:
        """
        Derive provenance_id = H(server_id ‖ P8-pin-material) for an upstream
        server, using the P8 pin config.  Returns None when no pin config is
        registered for the server (the envelope is bound to the transport
        identity — without a pin there is no provenance to bind to).
        """
        if not server_id:
            return None
        pin_cfg = self._upstream_pin_map.get(server_id)
        if pin_cfg is None:
            return None
        # Pin material = the cert fingerprint OR the SPIFFE id, whichever the
        # P8 pin established for this server.
        pin_material = pin_cfg.cert_fingerprint_sha256 or pin_cfg.spiffe_id
        if not pin_material:
            return None
        from yashigani.mcp._envelope import compute_provenance_id
        return compute_provenance_id(server_id, pin_material)

    async def _check_capability_envelope(
        self, ctx: McpCallContext
    ) -> Optional[str]:
        """
        Capability-envelope invocation hard gate (YSG-RISK-060 / Laura R3-3).

        Returns a deny_reason string when the call must be BLOCKED, or None when
        the call may proceed.  Fail-closed semantics:

          * Only applies to tool calls (a resolvable tool_name).  Non-tool
            actions (resource/prompt) are out of scope for the tool-surface pin.
          * No envelope_service wired:
              - dev/test  → no-op (None): envelopes not provisioned.
              - prod/stag → if the server has pin material (is a pinned imported
                MCP) → DENY (a pinned server with no envelope service to consult
                must fail closed).
          * Server has no provenance_id (no P8 pin) → not an envelope-governed
            imported MCP → no-op (None).  (Local stdio / first-party tools are
            not imported MCPs.)
          * Active envelope missing / blocked → DENY (unpinned / suspended).
          * Tool not in the active envelope's tool_set → DENY (the tool the
            caller named is not an approved capability).
          * Live catalogue surface hash != envelope current_surface_hash → DENY
            (the surface mutated between fetch and call — caught at the call).
        """
        if not self._enforce_capability_envelope:
            return None
        # Only tool calls carry a tool surface to pin.
        if ctx.tool_name is None:
            return None

        provenance_id = self._provenance_id_for(ctx.server_id)

        if self._envelope_service is None:
            # No service wired.  In prod/staging, a PINNED imported MCP must not
            # be invoked without an envelope to consult — fail closed.
            _env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
            if provenance_id is not None and _env in {"production", "staging"}:
                return "capability_envelope_service_unavailable"
            return None

        if provenance_id is None:
            # Not a pinned imported MCP (no P8 pin material) → out of scope.
            return None

        try:
            record = await self._envelope_service.get_active_envelope(provenance_id)
        except Exception as exc:  # fail-closed on any service/DB error
            logger.error(
                "mcp-broker: [YSG-RISK-060] envelope lookup failed server=%s: %s — "
                "fail-closed deny", ctx.server_id, exc,
            )
            return "capability_envelope_lookup_error"

        if record is None:
            # No active envelope: never approved, or latched-blocked, or
            # superseded-without-active (re-approval pending).  Fail closed.
            return "capability_envelope_not_active"

        from yashigani.mcp._envelope import namespaced_tool_key
        tool_key = namespaced_tool_key(provenance_id, ctx.tool_name)
        if tool_key not in record.envelope.tools:
            return "capability_envelope_tool_not_approved"

        # Surface-mutation-between-fetch-and-call: compare the live catalogue's
        # byte-hash to the envelope's materialised current_surface_hash.  A
        # mismatch means the surface changed and the refresh triage has not
        # (yet) re-pinned/blocked it — fail closed at the call.
        live = self._catalogue_store.get(ctx.tenant_id, ctx.server_id)
        if live is not None:
            from yashigani.mcp._envelope import surface_set_hash
            # Reconstruct the live surface hash from the stored catalogue's raw
            # descriptors is not possible (we only keep safe text), so we rely on
            # the catalogue carrying the last-fetched surface hash when present.
            live_hash = getattr(live, "surface_set_hash", None)
            if live_hash and live_hash != record.current_surface_hash:
                return "capability_envelope_surface_stale"

        return None

    def _emit_envelope_blocked_at_invocation(
        self, ctx: McpCallContext, block_reason: str
    ) -> None:
        """Emit McpEnvelopeBlockedEvent for an invocation-gate denial (audit)."""
        try:
            from yashigani.audit.schema import McpEnvelopeBlockedEvent
        except Exception as exc:  # noqa: BLE001
            logger.error("mcp-broker: envelope-blocked audit import failed: %s", exc)
            return
        provenance_id = self._provenance_id_for(ctx.server_id) or ""
        event = McpEnvelopeBlockedEvent(
            tenant_id=ctx.tenant_id,
            server_id=ctx.server_id,
            provenance_id=provenance_id,
            block_reason=f"invocation:{block_reason}",
            tool_name=ctx.tool_name or "",
        )
        if self._audit_writer is not None:
            try:
                self._audit_writer.write(event)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "mcp-broker: envelope-blocked audit write failed server=%s: %s",
                    ctx.server_id, exc,
                )

    def _check_connection_permit(self, ctx: McpCallContext) -> Optional[str]:
        """
        3.1 Phase 4 — connection allow-list.

        Returns None (permitted) or a deny_reason string.

        Logic:
          - No permission_store configured:
              • ENFORCING env (production/staging) → DENY
                "permission_store_unavailable" (FIX-005: fail-closed mandate).
                Redis MUST be available in production/staging.  A missing store
                is a misconfiguration, not a silent allow.
              • Non-enforcing env → no-op (None), backwards-compatible (dev/test).
          - Determines principal_scope + principal_id via 3-way dispatch:
              Human caller (caller_user_email set) → scope="user", id=ctx.user_id (identity_id, not PII).
              Agent caller (caller_agent_id set, not orchestrator) → scope="agent", id=agent_id.
              Orchestrator or unauthenticated → scope=None (org+group ceiling only).
          - Calls resolve_boolean_grant(MCP_SERVER, server_id, org_id,
              group_ids=ctx.caller_group_ids, principal_scope=..., principal_id=...).
          - Returns "mcp_server_not_permitted" when no org grant or org denies.

        Fail-closed: any exception from the resolver is already caught inside
        resolve_boolean_grant (it returns False on any error).
        """
        if self._config.permission_store is None:
            # FIX-005: deny-by-default mandate — permission store must be available
            # in enforcing envs.  Dev/test get a no-op (warn) for usability.
            _env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
            if _env in self._ENFORCE_PIN_ENVS:
                logger.error(
                    "mcp-broker: [FIX-005] permission_store is None in %r env — "
                    "DENYING call fail-closed (deny-by-default mandate). "
                    "Restore Redis/permission-store to re-enable MCP access. "
                    "server=%s caller=%s",
                    _env,
                    ctx.server_id or ctx.agent_name,
                    ctx.caller_agent_id,
                )
                return "permission_store_unavailable"
            # Dev/test: no permission store → no-op (backwards-compatible).
            return None

        from yashigani.permissions import ResourceType, resolve_boolean_grant

        server_key = ctx.server_id or ctx.agent_name
        if not server_key:
            # No server identifier — deny (fail-closed on missing context).
            return "mcp_server_not_permitted"

        org_id = self._config.org_id or "default"

        # Determine principal scope+id for per-principal narrowing:
        # - Human caller (caller_user_email set → kind=human/user confirmed)
        #   → user scope; principal_id = ctx.user_id (identity_id idnt_{12hex} from the
        #     identity registry after 3.1 UID unification, NOT the email — email is
        #     presentation-only).  Falls through to org+group
        #     ceiling only when ctx.user_id is "unknown" or empty (unresolved identity).
        # - Agent caller (caller_agent_id set, not the reserved orchestrator id)
        #   → agent scope; principal_id = the caller agent_id (stable registry key)
        # - Orchestrator or unauthenticated
        #   → no per-principal narrowing (org+group ceiling only)
        if ctx.caller_user_email:
            _uid = ctx.user_id if ctx.user_id not in ("unknown", "", None) else None
            _principal_scope: Optional[str] = "user" if _uid else None
            _principal_id: Optional[str] = _uid
        elif ctx.caller_agent_id and ctx.caller_agent_id != "gateway:orchestrator":
            _principal_scope = "agent"
            _principal_id = ctx.caller_agent_id
        else:
            _principal_scope = None
            _principal_id = None

        allowed = resolve_boolean_grant(
            ResourceType.MCP_SERVER,
            server_key,
            org_id=org_id,
            group_ids=ctx.caller_group_ids,
            principal_scope=_principal_scope,
            principal_id=_principal_id,
            store=self._config.permission_store,  # type: ignore[arg-type]
        )
        return None if allowed else "mcp_server_not_permitted"

    def _check_tool_permit(self, ctx: McpCallContext) -> Optional[str]:
        """
        3.1 Phase 3 — per-caller tool allow-list.

        Returns None (permitted) or a deny_reason string.

        Skip conditions (all result in None / no restriction):
          - caller is "gateway:orchestrator" (unrestricted).
          - caller_agent_id is None (unauthenticated / unidentified path).
          - tool_name is None (not a tools/call action).
          - caller_allowed_tools is None or empty (no restriction configured).

        When caller_allowed_tools is set and tool_name is NOT in the list,
        returns "tool_not_permitted".
        """
        if ctx.caller_agent_id == "gateway:orchestrator":
            return None
        if ctx.caller_agent_id is None:
            return None
        if ctx.tool_name is None:
            return None
        if not ctx.caller_allowed_tools:
            return None  # Empty / None list → no per-caller restriction

        if ctx.tool_name not in ctx.caller_allowed_tools:
            return "tool_not_permitted"
        return None

    async def _verify_upstream_jwt(self, ctx: McpCallContext) -> Optional[str]:
        """
        Verify the upstream relay JWT for mcp-c calls.

        Returns None on success (verification passed).
        Returns error string on failure.
        """
        if not ctx.upstream_jwt:
            return "mcp-c requires upstream JWT (upstream_jwt is empty)"

        try:
            payload = self._verifier.verify(ctx.upstream_jwt)
        except Exception as exc:
            return f"Upstream JWT verification failed: {exc}"

        # Extract and validate chain from upstream JWT
        upstream_identity = payload.get("identity", {})
        upstream_chain = upstream_identity.get("chain", [])

        if not isinstance(upstream_chain, list):
            return (
                f"Upstream JWT identity.chain is not a list: {type(upstream_chain).__name__}"
            )
        for element in upstream_chain:
            if not isinstance(element, str):
                return f"Upstream JWT identity.chain contains non-string element: {element!r}"

        # Check jti replay
        jti = payload.get("jti")
        if not jti:
            return "Upstream JWT missing jti claim"

        exp = payload.get("exp", 0)
        try:
            is_new = self._nonce_store.check_and_record(
                jti=str(jti),
                exp_epoch=float(exp),
                tenant_id=ctx.tenant_id,
            )
        except Exception as exc:
            logger.error("mcp-broker: nonce store error: %s", exc)
            return f"Nonce store error: {exc}"

        if not is_new:
            return f"Upstream JWT jti_replayed: {jti!r}"

        # Populate upstream chain into ctx (mutate in place — broker owns ctx)
        ctx.upstream_chain[:] = upstream_chain
        return None

    async def _emit_audit(
        self, ctx: McpCallContext, decision: BrokerDecision
    ) -> None:
        """
        Emit MCP_CALL + OPA_DECISION_ON_MCP audit events.

        EVERY call emits both events — clean allowed calls MUST leave a
        witness record (AU-2/12/CC7.1 gap closure).

        audit_capture=True (from OPA) escalates to the full-record variant
        with args captured. In v1, we always log the tool_name but never
        log raw args values (only keys with redact_args applied by OPA).
        """
        from yashigani.audit.schema import (
            AccountTier,
            McpCallEvent,
            OpaDecisionOnMcpEvent,
        )

        opa_decision_label = "allow" if decision.allow else "deny"

        mcp_call_event = McpCallEvent(
            account_tier=AccountTier.SYSTEM,
            tenant_id=ctx.tenant_id,
            agent_name=ctx.agent_name,
            identity_id=agent_spiffe_uri(ctx.tenant_id, ctx.agent_name),
            request_id=ctx.request_id,
            tool_name=ctx.tool_name or ctx.prompt_name or ctx.resource_uri or "",
            server_id=ctx.server_id,
            opa_decision=opa_decision_label,
            args_redacted=bool(decision.opa_decision.redact_args),
            elapsed_ms=decision.elapsed_ms,
            # FIND-A-AUD (3.1.2): caller identity → audit_events.agent_id DB column.
            # Previously NULL; now carries McpCallContext.caller_agent_id so the
            # acting identity is in the tamper-evident audit chain.
            agent_id=ctx.caller_agent_id or None,
            # 3.1 UID unification: resolved identity_id from boundary resolver.
            caller_identity_id=ctx.user_id or "",
        )

        opa_event = OpaDecisionOnMcpEvent(
            account_tier=AccountTier.SYSTEM,
            tenant_id=ctx.tenant_id,
            agent_name=ctx.agent_name,
            tool_name=ctx.tool_name or ctx.prompt_name or ctx.resource_uri or "",
            server_id=ctx.server_id,
            request_id=ctx.request_id,
            decision=opa_decision_label,
            deny_reason=decision.deny_reason,
            # FIX-E (Lu FIX-3): persist full SPIFFE chain (ordered list) so
            # auditor sees WHICH identities were in the chain, not just how many.
            identity_chain=list(ctx.upstream_chain),
            chain_depth=decision.chain_depth,
            elapsed_ms=decision.opa_decision.elapsed_ms,
            # FIND-A-AUD (3.1.2): mirrors McpCallEvent.agent_id.
            agent_id=ctx.caller_agent_id or None,
            # 3.1 UID unification: mirrors McpCallEvent.caller_identity_id.
            caller_identity_id=ctx.user_id or "",
        )

        if self._audit_writer is not None:
            try:
                self._audit_writer.write(mcp_call_event)
                self._audit_writer.write(opa_event)
            except Exception as exc:
                # Audit write failure MUST be logged but MUST NOT suppress the
                # broker decision (audit failures are separately alerted via
                # SIEM_DELIVERY_FAILED events). The decision has already been made.
                logger.error(
                    "mcp-broker: audit write failed call_id=%s: %s",
                    ctx.call_id, exc,
                )
        else:
            # No writer configured (test/dev mode) — log at WARNING
            logger.warning(
                "mcp-broker: no audit_writer configured — MCP_CALL + OPA_DECISION "
                "events NOT written. call_id=%s decision=%s",
                ctx.call_id, opa_decision_label,
            )

    # -----------------------------------------------------------------------
    # [M4] Tool-description / prompt content filter + audit
    # -----------------------------------------------------------------------

    def fetch_and_filter_tools(
        self,
        server_id: str,
        raw_tools: list[dict],
        raw_prompts: Optional[list[dict]] = None,
    ) -> TenantCatalogue:
        """
        Run the M4 content filter over a raw tools/list (and optionally
        prompts/list) response.

        - NFKC-normalises all descriptions.
        - Rejects descriptions that exceed 2048 chars, contain control chars,
          or match injection-marker patterns.
        - Stores the filtered catalogue in the per-tenant store (keyed by
          (self._config.tenant_id, server_id) — never shared across tenants).
        - Emits McpToolDescriptionFetchedEvent for audit (Lu FIX-2 / M4).

        Returns the TenantCatalogue with safe_description / safe_content
        populated.  Callers MUST use ``safe_description`` / ``safe_content``
        when forwarding tool/prompt text to downstream agents.
        """
        catalogue = build_catalogue(
            tenant_id=self._config.tenant_id,
            server_id=server_id,
            raw_tools=raw_tools,
            raw_prompts=raw_prompts or [],
            sidecar=self._semantic_intent_sidecar,
        )
        self._catalogue_store.store(catalogue)
        self._emit_tool_description_fetched_event(catalogue, fetch_type="tools_list")
        # v2.26 / YSG-RISK-057 — emit a dedicated, self-describing audit event
        # for every descriptor the sidecar ESCALATED (caught what the heuristic
        # missed).  No-op when the sidecar is off (no escalations).
        self._emit_semantic_intent_escalations(catalogue, fetch_type="tools_list")
        return catalogue

    async def refresh_and_triage_tools(
        self,
        server_id: str,
        raw_tools: list[dict],
        raw_prompts: Optional[list[dict]] = None,
    ) -> "Any":
        """
        3.0 / YSG-RISK-060 — the M4 refresh hook with capability-envelope triage.

        Filters the surface (as fetch_and_filter_tools does) AND, when an
        envelope_service is wired and an active envelope exists, triages the
        refreshed surface against the ORIGINAL approved baseline:

          * byte-hash unchanged           → no-op (identical surface).
          * structurally within envelope  → run escalate-only sidecar:
              - sidecar clean   → BENIGN: auto-allow + re-pin byte-hash + log.
              - sidecar flag/err→ UNCERTAIN: latch block + log (fail-closed).
          * structurally expanding        → EXPANDING: latch block + log
                                            (operator step-up re-approval needed).

        Returns the TriageOutcome (or None when no envelope governs this server
        — e.g. no P8 pin / no active envelope yet at first import).

        The drift is measured against the ORIGINAL baseline (envelope_version 1),
        never the last auto-allowed state (Laura must-have #1 / Δ1).
        """
        # Always run the M4 filter first (catalogue stored, audit emitted).
        catalogue = self.fetch_and_filter_tools(server_id, raw_tools, raw_prompts)

        provenance_id = self._provenance_id_for(server_id)
        if self._envelope_service is None or provenance_id is None:
            # No envelope governance for this server (dev/test, or not a pinned
            # imported MCP).  The invocation gate still fail-closes in prod.
            return None

        from yashigani.mcp._envelope import project_surface, surface_set_hash
        from yashigani.mcp._envelope_triage import triage_refresh, TriageClass

        # The ORIGINAL approved baseline (Δ1).  None ⇒ never imported ⇒ nothing
        # to triage against (the import ceremony mints v1 separately).
        baseline = await self._envelope_service.get_baseline_envelope(provenance_id)
        active = await self._envelope_service.get_active_envelope(provenance_id)
        if baseline is None or active is None:
            return None

        new_hash = surface_set_hash(raw_tools, raw_prompts or [])
        # byte-hash unchanged vs the active materialisation → identical surface.
        if new_hash == active.current_surface_hash:
            return None

        current_env = project_surface(
            provenance_id,
            self._config.tenant_id,
            raw_tools,
            egress_posture=baseline.egress_posture,
        )

        outcome = triage_refresh(
            approved_baseline=baseline.envelope,
            current_envelope=current_env,
            current_raw_tools=raw_tools,
            new_surface_hash=new_hash,
            sidecar=self._semantic_intent_sidecar,
            topology=active.topology,
        )

        if outcome.triage_class is TriageClass.BENIGN:
            await self._envelope_service.record_benign_repin(provenance_id, new_hash)
            self._emit_envelope_benign_update(
                server_id, provenance_id, active.envelope_version, new_hash
            )
        else:
            # EXPANDING or UNCERTAIN — latch the block on the provenance.  The
            # block PERSISTS until a step-up re-approval; reversion does not
            # clear it (Laura §3 bypass B).
            await self._envelope_service.latch_block(provenance_id)
            self._emit_envelope_blocked_at_refresh(
                server_id, provenance_id, outcome
            )
            # 3.0 / YSG-RISK-060 — hand the CANDIDATE surface to the operator
            # re-approval queue so the admin SPA can show the diff vs the
            # ORIGINAL baseline and mint it on a step-up approve.  Best-effort:
            # a sink fault never affects the fail-closed block above.
            if self._pending_block_sink is not None:
                try:
                    findings = [
                        {"dimension": f.dimension, "tool_key": f.tool_key,
                         "detail": f.detail}
                        for f in outcome.findings
                    ]
                    self._pending_block_sink(
                        provenance_id=provenance_id,
                        tenant_id=self._config.tenant_id,
                        server_id=server_id,
                        candidate=current_env,
                        triage_class=outcome.triage_class.value,
                        new_surface_hash=outcome.new_surface_hash,
                        findings=findings,
                    )
                except Exception as exc:  # noqa: BLE001 — queue is best-effort
                    logger.error(
                        "mcp-broker: pending_block_sink failed for provenance=%.12s "
                        "(block still latched): %s", provenance_id, exc,
                    )
        return outcome

    def _emit_envelope_benign_update(
        self, server_id: str, provenance_id: str,
        envelope_version: int, new_hash: str,
    ) -> None:
        """Emit McpEnvelopeBenignUpdateEvent for an auto-allowed benign refresh."""
        try:
            from yashigani.audit.schema import McpEnvelopeBenignUpdateEvent
        except Exception as exc:  # noqa: BLE001
            logger.error("mcp-broker: envelope-benign audit import failed: %s", exc)
            return
        event = McpEnvelopeBenignUpdateEvent(
            tenant_id=self._config.tenant_id,
            server_id=server_id,
            provenance_id=provenance_id,
            envelope_version=envelope_version,
            new_surface_hash=new_hash,
        )
        if self._audit_writer is not None:
            try:
                self._audit_writer.write(event)
            except Exception as exc:  # noqa: BLE001
                logger.error("mcp-broker: envelope-benign audit write failed: %s", exc)

    def _emit_envelope_blocked_at_refresh(
        self, server_id: str, provenance_id: str, outcome: "Any"
    ) -> None:
        """Emit McpEnvelopeBlockedEvent for an expanding/uncertain refresh block."""
        try:
            from yashigani.audit.schema import McpEnvelopeBlockedEvent
            from yashigani.mcp._envelope_triage import TriageClass
        except Exception as exc:  # noqa: BLE001
            logger.error("mcp-broker: envelope-blocked audit import failed: %s", exc)
            return
        block_reason = (
            "refresh_expanding"
            if outcome.triage_class is TriageClass.EXPANDING
            else "refresh_uncertain"
        )
        dims = sorted({f.dimension for f in outcome.findings})
        event = McpEnvelopeBlockedEvent(
            tenant_id=self._config.tenant_id,
            server_id=server_id,
            provenance_id=provenance_id,
            block_reason=block_reason,
            expansion_dimensions=dims,
            finding_count=len(outcome.findings),
        )
        if self._audit_writer is not None:
            try:
                self._audit_writer.write(event)
            except Exception as exc:  # noqa: BLE001
                logger.error("mcp-broker: envelope-blocked audit write failed: %s", exc)

    def fetch_and_filter_prompt(
        self,
        server_id: str,
        prompt_name: str,
        prompt_content: str,
    ) -> FilterResult:
        """
        Run the M4 content filter over a single prompts/get response.

        The prompts/get path is the SECOND injection vector (separate from
        tools/list) — both MUST be filtered.  This method handles the single-
        prompt case.

        Emits McpToolDescriptionFetchedEvent with fetch_type="prompts_get"
        for audit (Lu FIX-2 / M4).

        Returns the FilterResult.  Use ``result.safe_text`` downstream.
        """
        from yashigani.mcp._content_filter import filter_description_v2
        result = filter_description_v2(
            prompt_content, sidecar=self._semantic_intent_sidecar
        )

        # Build a minimal catalogue entry for audit emission
        from yashigani.mcp._content_filter import (
            PromptDescriptor,
            TenantCatalogue,
        )
        mini_catalogue = TenantCatalogue(
            tenant_id=self._config.tenant_id,
            server_id=server_id,
            tools=[],
            prompts=[PromptDescriptor(
                prompt_name=prompt_name,
                safe_content=result.safe_text,
                filter_result=result,
            )],
        )
        self._emit_tool_description_fetched_event(
            mini_catalogue, fetch_type="prompts_get"
        )
        self._emit_semantic_intent_escalations(
            mini_catalogue, fetch_type="prompts_get"
        )
        return result

    def _emit_tool_description_fetched_event(
        self,
        catalogue: TenantCatalogue,
        fetch_type: str,
    ) -> None:
        """
        Emit McpToolDescriptionFetchedEvent for audit (Lu FIX-2 / M4 close).

        Records tool_count, filtered_count (NFKC-altered), rejected_count,
        and whether any prompt was rejected.  The raw text is NEVER stored.
        """
        from yashigani.audit.schema import McpToolDescriptionFetchedEvent, AccountTier

        rejected_count = catalogue.rejected_tool_count + catalogue.rejected_prompt_count

        event = McpToolDescriptionFetchedEvent(
            account_tier=AccountTier.SYSTEM,
            tenant_id=catalogue.tenant_id,
            agent_name="",   # catalogue fetch is broker-level, not agent-specific
            server_id=catalogue.server_id,
            tool_count=catalogue.tool_count + catalogue.prompt_count,
            filtered_count=catalogue.filtered_tool_count,
            rejected_count=rejected_count,
            fetch_type=fetch_type,
        )

        if self._audit_writer is not None:
            try:
                self._audit_writer.write(event)
            except Exception as exc:
                logger.error(
                    "mcp-broker: audit write failed for McpToolDescriptionFetchedEvent "
                    "server_id=%s: %s", catalogue.server_id, exc,
                )
        else:
            logger.warning(
                "mcp-broker: no audit_writer — McpToolDescriptionFetchedEvent NOT written "
                "server_id=%s tenant=%s rejected=%d",
                catalogue.server_id, catalogue.tenant_id, rejected_count,
            )

    def _emit_semantic_intent_escalations(
        self,
        catalogue: TenantCatalogue,
        fetch_type: str,
    ) -> None:
        """
        v2.26 / YSG-RISK-057 — emit a dedicated SemanticIntentEscalatedEvent for
        every descriptor the content-filter v2 sidecar ESCALATED (caught what
        the v1 heuristic missed: an encoded/obfuscated injection).

        An escalation is identified by ``filter_result.reject_reason ==
        "semantic_intent"`` — set only by ``filter_description_v2`` when the
        sidecar flagged a clean-heuristic verdict.  When the sidecar is off, no
        descriptor carries that reason and this is a no-op.

        The event is self-describing (rule_id + layman user_message + code) and
        carries ONLY masked / audit-safe verdict detail (flagged_view codec name,
        masked encoded segment, aggregate score) — never the raw content.
        """
        from yashigani.audit.schema import SemanticIntentEscalatedEvent

        # Gather (item_name, filter_result) pairs for tools + prompts.
        items: list[tuple[str, Any]] = [
            (t.tool_name, t.filter_result) for t in catalogue.tools
        ] + [
            (p.prompt_name, p.filter_result) for p in catalogue.prompts
        ]

        for item_name, fr in items:
            if fr is None or fr.reject_reason != "semantic_intent":
                continue

            event = SemanticIntentEscalatedEvent(
                tenant_id=catalogue.tenant_id,
                server_id=catalogue.server_id,
                fetch_type=fetch_type,
                item_name=item_name,
                flagged_view=fr.semantic_intent_view or "",
                # Masked encoded token of the decoded view that triggered the
                # verdict (pii.decode._mask_token: first4…last4 + length).
                # Never the raw content.
                flagged_segment=fr.semantic_intent_segment or "",
                intent_score=float(fr.semantic_intent_score or 0.0),
            )

            if self._audit_writer is not None:
                try:
                    self._audit_writer.write(event)
                except Exception as exc:
                    logger.error(
                        "mcp-broker: audit write failed for SemanticIntentEscalatedEvent "
                        "server_id=%s item=%s: %s",
                        catalogue.server_id, item_name, exc,
                    )
            else:
                logger.warning(
                    "mcp-broker: no audit_writer — SemanticIntentEscalatedEvent NOT written "
                    "server_id=%s item=%s view=%s score=%.2f",
                    catalogue.server_id, item_name,
                    event.flagged_view, event.intent_score,
                )

    # -----------------------------------------------------------------------
    # [P8] Upstream MCP-server cert/SPIFFE pinning  (FIX-P8-002)
    # -----------------------------------------------------------------------

    #: Environments where a pin failure causes an immediate ConnectionError.
    #: Dev/test environments receive a warning only.
    #: Single source: _upstream_revocation._ENFORCE_ENVS — imported as _MCP_ENFORCE_ENVS
    #: so revocation + pin enforcement share the same definition without duplication.
    _ENFORCE_PIN_ENVS: frozenset[str] = _MCP_ENFORCE_ENVS

    def verify_upstream(
        self,
        server_id: str,
        timeout: float = 5.0,
        _get_fp: Optional[Any] = None,
        _get_spiffe: Optional[Any] = None,
        # YSG-RISK-058 revocation-watch injection hooks (testing).
        pin_age_seconds: Optional[float] = None,
        _check_revocation: Optional[Any] = None,
        _get_der: Optional[Any] = None,
    ) -> PinVerificationResult:
        """
        Verify the upstream MCP server identified by server_id against the
        pinned cert fingerprint or SPIFFE ID.

        FIX-P8-002 — inline enforcement:
        ──────────────────────────────────
        In ``production`` and ``staging`` environments
        (YASHIGANI_ENV=production|staging):

        • If no pin config is registered for server_id, the connection is
          REFUSED immediately (ConnectionError raised).  A structured audit
          event ``MCP_UPSTREAM_PIN_NOT_CONFIGURED`` is emitted.

        • If a pin is configured but the live cert/SPIFFE ID does NOT match,
          the connection is REFUSED immediately (ConnectionError raised).  A
          structured audit event ``MCP_UPSTREAM_CERT_PIN_MISMATCH`` is emitted.

        In dev/test environments the same result object is returned but no
        ConnectionError is raised — callers observe matched=False and can log.

        The docstring previously claimed "reject in prod" without the code
        actually raising.  This fix closes that gap.  YSG-RISK-056.
        """
        _env = os.environ.get("YASHIGANI_ENV", "").lower().strip()
        _enforcing = _env in self._ENFORCE_PIN_ENVS

        pin_cfg = self._upstream_pin_map.get(server_id)
        if pin_cfg is None:
            result = PinVerificationResult(
                server_id=server_id,
                matched=False,
                reason="pin_not_configured",
            )
            self._emit_upstream_pin_event(server_id, result, env=_env)
            if _enforcing:
                raise ConnectionError(
                    f"mcp-broker: [P8] upstream server {server_id!r} has no pin "
                    f"config in {_env!r} environment — connection REFUSED. "
                    "YSG-RISK-056. Configure pin_mode in consumes.servers[]."
                )
            logger.warning(
                "mcp-broker: [P8] no pin config for server_id=%r (env=%r) — "
                "returned pin_not_configured (non-enforcing env).",
                server_id, _env,
            )
            return result

        result = verify_upstream_pin(
            config=pin_cfg,
            timeout=timeout,
            _get_fp=_get_fp,
            _get_spiffe=_get_spiffe,
            # YSG-RISK-058: revocation-watch runs on a matched pin. A revoked /
            # stale / (strict) no-channel / over-age leaf overrides the match.
            pin_age_seconds=pin_age_seconds,
            _get_der=_get_der,
            _check_revocation=_check_revocation,
        )
        self._emit_upstream_pin_event(server_id, result, env=_env)

        if not result.matched and _enforcing:
            raise ConnectionError(
                f"mcp-broker: [P8] upstream pin verification FAILED for "
                f"server_id={server_id!r} reason={result.reason!r} "
                f"(env={_env!r}) — connection REFUSED. YSG-RISK-056/058."
            )

        return result

    def _emit_upstream_pin_event(
        self,
        server_id: str,
        result: PinVerificationResult,
        env: str,
    ) -> None:
        """
        Emit a structured audit event for upstream pin verification outcome.

        Emits on BOTH success (reason='ok') and failure so Lu has a complete
        witness trail.  The event carries server_id, matched, reason, and env.
        """
        # Use the existing audit writer if available; fall back to WARNING log.
        # We use a plain dict payload rather than a bespoke audit schema class
        # so this method doesn't need a new schema migration in v2.25.0.
        event_label = (
            result.reason if not result.matched
            else "MCP_UPSTREAM_PIN_OK"
        )
        if self._audit_writer is not None:
            try:
                # Structured emit: wrap in a lightweight object the writer
                # accepts.  Writers accept any object with .event_type.
                class _PinEvent:
                    event_type = event_label
                    def __init__(self, sid: str, matched: bool, reason: str, environment: str) -> None:
                        self.server_id = sid
                        self.matched = matched
                        self.reason = reason
                        self.env = environment

                self._audit_writer.write(
                    _PinEvent(server_id, result.matched, result.reason, env)
                )
            except Exception as exc:
                logger.error(
                    "mcp-broker: audit write failed for upstream-pin event "
                    "server_id=%r: %s", server_id, exc,
                )
        else:
            log_fn = logger.warning if not result.matched else logger.debug
            log_fn(
                "mcp-broker: [P8] upstream pin event server_id=%r matched=%s "
                "reason=%r env=%r",
                server_id, result.matched, result.reason, env,
            )

    # -----------------------------------------------------------------------
    # [P1-pool] Per-tenant connection pool accessor
    # -----------------------------------------------------------------------

    @property
    def pool_manager(self) -> TenantPoolManager:
        """
        [P1-pool] Return the per-tenant connection pool manager.

        Use ``broker.pool_manager.get_or_create_client(tenant_id, host)``
        to get an httpx.AsyncClient scoped to the tenant.
        """
        return self._pool_manager

    async def opa_health(self) -> bool:
        """
        Query OPA /health endpoint.

        Returns True if OPA is healthy, False otherwise.
        Used by the gateway healthcheck endpoint (ASVS V11.1.1 / C9).
        """
        url = f"{self._opa_url.rstrip('/')}/health"
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(url)
                return resp.status_code == 200
        except Exception as exc:
            logger.warning("mcp-broker: OPA health check failed: %s", exc)
            return False
