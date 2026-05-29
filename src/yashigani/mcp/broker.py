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

Deferred to phase-2:
  - TODO[M4]: MCP tool-description / prompts.get prompt-injection content filter.
  - TODO[P8]: Upstream MCP-server cert/SPIFFE pinning enforcement.
  - TODO[P1-pool]: Per-tenant provider-key cache + per-tenant connection pools.

v2.25.0 / P1 W3 Phase 2b-ii / YSG-RISK-054 (audit) + YSG-RISK-055 (posture).
"""
from __future__ import annotations

import logging
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
from yashigani.mcp._jwt import McpJwtIssuer, McpJwtVerifier
from yashigani.mcp._nonce import NonceStore, InMemoryNonceStore
from yashigani.mcp._opa import query_mcp_decision

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
    """

    opa_url: str
    tenant_id: str
    issuer: Optional[McpJwtIssuer] = None
    verifier: Optional[McpJwtVerifier] = None
    nonce_store: Optional[NonceStore] = None
    chain_max_depth: int = 3
    audit_writer: Optional[Any] = None   # AuditLogWriter, typed as Any to avoid circular import


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

        opa_result = await query_mcp_decision(
            opa_url=self._opa_url,
            posture=ctx.posture.value,
            action=ctx.action,
            spiffe_uri=spiffe_uri,
            chain=chain_for_opa,
            tool_name=ctx.tool_name,
            tool_args_redacted=ctx.tool_args_redacted,
            prompt_name=ctx.prompt_name,
            resource_uri=ctx.resource_uri,
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

        # Step 3: issue gateway-signed JWT (only on OPA allow)
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
