"""
Yashigani Gateway — Agent PSK authentication middleware.

Intercepts requests on /agents/* and validates the caller's Bearer token
against the AgentRegistry. On success, attaches:
  request.state.agent_id       — caller's agent_id
  request.state.caller_type    — "agent"
  request.state.target_agent_id — parsed target from path

On failure, returns HTTP 401 and writes an AGENT_AUTH_FAILED audit event.
All other paths are passed through untouched.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


def _get_client_ip(request: Request) -> str:
    """
    Delegate to the canonical trusted-proxy-boundary resolver in proxy.py.

    CWE-345 mitigation (V232-NEG03 / LAURA-2026-04-29-006): the old
    local copy trusted the first (leftmost) XFF hop, which is attacker-
    controlled.  Importing from proxy ensures a single implementation.
    """
    from yashigani.gateway.proxy import _get_client_ip as _canonical_get_client_ip
    return _canonical_get_client_ip(request)


def _ip_in_cidrs(ip_str: str, cidrs: list[str]) -> bool:
    """Return True if ip_str falls within any CIDR in cidrs. Handles IPv4 and IPv6."""
    try:
        client_ip = ipaddress.ip_address(ip_str)
    except ValueError:
        logger.warning("_ip_in_cidrs: cannot parse IP %r — denying", ip_str)
        return False
    for cidr in cidrs:
        try:
            if client_ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            logger.warning("_ip_in_cidrs: invalid CIDR %r — skipping", cidr)
    return False


class AgentAuthMiddleware(BaseHTTPMiddleware):
    """
    Validates agent PSK tokens on /agents/* requests.

    Token validation uses bcrypt.checkpw (via AgentRegistry.verify_token).
    The raw token is never logged. Source IP is hashed before audit emission.

    Caller identity is conveyed via:
      Authorization: Bearer <plaintext_token>
      X-Yashigani-Caller-Agent-Id: <caller_agent_id>

    The target agent_id is parsed from the URL path segment immediately
    following the prefix: /agents/{target_agent_id}/...
    """

    def __init__(
        self,
        app,
        agent_registry=None,
        audit_writer=None,
        agent_path_prefix: str = "/agents",
    ) -> None:
        super().__init__(app)
        self._registry = agent_registry
        self._audit = audit_writer
        self._prefix = agent_path_prefix.rstrip("/")

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Only intercept /agents/* — let everything else pass through
        if not path.startswith(self._prefix + "/"):
            return await call_next(request)

        # Parse target_agent_id from path: /agents/{target_agent_id}/...
        remainder = path[len(self._prefix):].lstrip("/")
        parts = remainder.split("/", 1)
        target_agent_id = parts[0] if parts and parts[0] else ""

        # Require Bearer token
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return await self._reject(
                request,
                caller_agent_id="",
                path=path,
                reason="missing_or_malformed_bearer",
                status=401,
            )

        plaintext_token = auth_header[7:]

        # Require caller agent ID header
        caller_agent_id = request.headers.get("x-yashigani-caller-agent-id", "").strip()
        if not caller_agent_id:
            return await self._reject(
                request,
                caller_agent_id="",
                path=path,
                reason="missing_caller_agent_id_header",
                status=401,
            )

        # Registry must be available.
        # YSG-RISK-131: self._registry is snapshotted BY VALUE at __init__
        # time (gateway-app build). If the cold-boot RBAC/Agent Redis init
        # raced a k8s DNS-not-ready window and failed, this stays None for
        # the process lifetime unless something else keeps trying — fall
        # back to gateway_fallback_state.agent_registry, which
        # redis_selfheal.py keeps updated independently after a successful
        # lazy reconnect (see gateway/state.py docstring).
        registry = self._registry
        if registry is None:
            from yashigani.gateway.state import gateway_fallback_state
            registry = gateway_fallback_state.agent_registry
        if registry is None:
            logger.error("AgentAuthMiddleware: no agent_registry configured")
            return await self._reject(
                request,
                caller_agent_id=caller_agent_id,
                path=path,
                reason="registry_unavailable",
                status=503,
            )

        # Verify PSK token
        if not registry.verify_token(caller_agent_id, plaintext_token):
            return await self._reject(
                request,
                caller_agent_id=caller_agent_id,
                path=path,
                reason="invalid_token",
                status=401,
            )

        # IP allowlist check — only if the agent has CIDRs configured
        agent = registry.get(caller_agent_id)
        if agent is not None:
            allowed_cidrs = agent.get("allowed_cidrs") or []
            if allowed_cidrs:
                source_ip = _get_client_ip(request)
                if not _ip_in_cidrs(source_ip, allowed_cidrs):
                    return await self._reject_ip(
                        request,
                        caller_agent_id=caller_agent_id,
                        path=path,
                        source_ip=source_ip,
                        allowed_cidrs=allowed_cidrs,
                    )

        # Authentication successful — attach state and proceed
        request.state.agent_id = caller_agent_id
        request.state.caller_type = "agent"
        request.state.target_agent_id = target_agent_id

        return await call_next(request)

    async def _reject_ip(
        self,
        request: Request,
        caller_agent_id: str,
        path: str,
        source_ip: str,
        allowed_cidrs: list,
    ):
        ip_hash = hashlib.sha256(source_ip.encode()).hexdigest()[:16]
        try:
            from yashigani.metrics.registry import agent_auth_failures_total
            agent_auth_failures_total.labels(reason="ip_allowlist_violation").inc()
        except Exception:
            logger.debug("agent_auth: metric increment failed for agent_auth_failures_total (ip_allowlist_violation)", exc_info=True)
        if self._audit is not None:
            try:
                from yashigani.audit.schema import IPAllowlistViolationEvent
                self._audit.write(IPAllowlistViolationEvent(
                    agent_id=caller_agent_id,
                    client_ip_hash=ip_hash,
                    allowed_cidrs=allowed_cidrs,
                ))
            except Exception as exc:
                logger.error("AgentAuthMiddleware: failed to write IPAllowlistViolationEvent: %s", exc)
        logger.warning(
            "AgentAuthMiddleware: IP allowlist violation agent=%s ip_hash=%s path=%s",
            caller_agent_id, ip_hash, path,
        )
        return JSONResponse(
            status_code=403,
            content={"error": "IP_ALLOWLIST_VIOLATION", "reason": "ip_not_in_allowlist"},
        )

    async def _reject(
        self,
        request: Request,
        caller_agent_id: str,
        path: str,
        reason: str,
        status: int = 401,
    ):
        source_ip = _get_client_ip(request)
        # Increment metric
        try:
            from yashigani.metrics.registry import agent_auth_failures_total
            agent_auth_failures_total.labels(reason=reason).inc()
        except Exception:
            logger.debug("agent_auth: metric increment failed for agent_auth_failures_total reason=%s", reason, exc_info=True)

        # Write audit event
        if self._audit is not None:
            try:
                from yashigani.audit.schema import AgentAuthFailedEvent
                self._audit.write(AgentAuthFailedEvent(
                    agent_id_claimed=caller_agent_id,
                    source_ip=hashlib.sha256(source_ip.encode()).hexdigest()[:16],
                    path=path,
                    failure_reason=reason,
                ))
            except Exception as exc:
                logger.error("AgentAuthMiddleware: failed to write audit event: %s", exc)

        logger.warning(
            "AgentAuthMiddleware: auth rejected path=%s caller=%r reason=%s",
            path, caller_agent_id, reason,
        )

        body = {"error": "AGENT_AUTH_FAILED", "reason": reason}
        if status == 503:
            body = {"error": "AGENT_REGISTRY_UNAVAILABLE"}

        return JSONResponse(status_code=status, content=body)
