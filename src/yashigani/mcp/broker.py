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
       verify_upstream_pin() is called before forwarding; mismatch aborts the
       connection and logs/audits MCP_UPSTREAM_CERT_PIN_MISMATCH.
  [P1-pool] Per-tenant provider-key cache + per-tenant connection pools.
       McpBroker.pool_manager exposes a TenantPoolManager keyed by
       (tenant_id, provider_host) — never shared across tenant_ids.

v2.25.0 / P1 W3 Phase 2b-ii + Phase 2 hardening /
  YSG-RISK-054 (audit) + YSG-RISK-055 (posture) + YSG-RISK-056 (upstream pin)
  + YSG-RISK-057 (cross-tenant isolation).
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

import httpx

from yashigani.mcp._types import (
    BrokerDecision,
    McpCallContext,
    McpPosture,
    OpaDecision,
)
from yashigani.mcp._jwt import ChainDepthExceeded, McpJwtIssuer, McpJwtVerifier
from yashigani.mcp._nonce import NonceStore, InMemoryNonceStore
from yashigani.mcp._opa import (
    query_mcp_decision,
    query_filesystem_tool_allowed,
    query_git_tool_allowed,
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
        Maximum allowed chain depth. Default 3. Reads from OPA data bundle
        at runtime (operator-tunable via data.yashigani.mcp.policy.chain_max_depth).
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
    """

    opa_url: str
    tenant_id: str
    issuer: Optional[McpJwtIssuer] = None
    verifier: Optional[McpJwtVerifier] = None
    nonce_store: Optional[NonceStore] = None
    chain_max_depth: int = 3
    audit_writer: Optional[Any] = None   # AuditLogWriter, typed as Any to avoid circular import

    # Phase-2 hardening
    catalogue_store: Optional[ToolCatalogueStore] = None
    upstream_pin_configs: Optional[list] = None  # list[UpstreamPinConfig]
    pool_manager: Optional[TenantPoolManager] = None

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

        # Step 2: query OPA (fail-closed)
        spiffe_uri = (
            f"spiffe://yashigani.internal/agents/{ctx.tenant_id}/{ctx.agent_name}"
        )
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
            identity_id=f"spiffe://yashigani.internal/agents/{ctx.tenant_id}/{ctx.agent_name}",
            request_id=ctx.request_id,
            tool_name=ctx.tool_name or ctx.prompt_name or ctx.resource_uri or "",
            server_id=ctx.server_id,
            opa_decision=opa_decision_label,
            args_redacted=bool(decision.opa_decision.redact_args),
            elapsed_ms=decision.elapsed_ms,
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
        )
        self._catalogue_store.store(catalogue)
        self._emit_tool_description_fetched_event(catalogue, fetch_type="tools_list")
        return catalogue

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
        from yashigani.mcp._content_filter import filter_description
        result = filter_description(prompt_content)

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

    # -----------------------------------------------------------------------
    # [P8] Upstream MCP-server cert/SPIFFE pinning  (FIX-P8-002)
    # -----------------------------------------------------------------------

    #: Environments where a pin failure causes an immediate ConnectionError.
    #: Dev/test environments receive a warning only.
    _ENFORCE_PIN_ENVS: frozenset[str] = frozenset({"production", "staging"})

    def verify_upstream(
        self,
        server_id: str,
        timeout: float = 5.0,
        _get_fp: Optional[Any] = None,
        _get_spiffe: Optional[Any] = None,
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
        )
        self._emit_upstream_pin_event(server_id, result, env=_env)

        if not result.matched and _enforcing:
            raise ConnectionError(
                f"mcp-broker: [P8] upstream pin verification FAILED for "
                f"server_id={server_id!r} reason={result.reason!r} "
                f"(env={_env!r}) — connection REFUSED. YSG-RISK-056."
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
