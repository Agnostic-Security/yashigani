"""
MCP Broker — per-server broker registry.

Holds one McpBroker + McpBrokerServerConfig per onboarded MCP server.
Populated at gateway startup from YASHIGANI_MCP_SERVERS env var (JSON array).
Thread-safe for reads (dict reads are atomic in CPython; writes only at startup).

v2.25.0 / P3 gateway integration.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class McpBrokerServerConfig:
    """
    Per-server configuration held in the registry alongside the broker instance.

    upstream_url:
        URL of the stdio↔HTTP bridge inside the server container
        (e.g. "http://filesystem-mcp:8000" or "http://git-mcp:8000").

    is_filesystem_agent:
        When True, broker.enforce() runs the second OPA gate
        (filesystem_tool_allowed) after the global mcp_decision allow.
        Set True for agents whose manifest declares category=mcp_server
        and metadata.name == "filesystem" (or equivalent filesystem bundles).

    is_git_agent:
        When True, broker.enforce() runs the git OPA gate (git_tool_allowed)
        after the global mcp_decision allow.  Enforces GIT-TM-001 repo_path
        boundary and GIT-TM-004 timestamp option injection guard.
        Set True for the git bundle (metadata.name == "git").

    YASHIGANI_MCP_SERVERS JSON example:
        [
          {"agent_name": "filesystem-mcp", "upstream_url": "http://filesystem-mcp:8000",
           "tenant_id": "acme", "is_filesystem_agent": true},
          {"agent_name": "git", "upstream_url": "http://git-mcp:8000",
           "tenant_id": "acme", "is_git_agent": true}
        ]

    tenant_id:
        Tenant identifier — matches the broker's McpBrokerConfig.tenant_id.
        Stored here so the runtime route can build McpCallContext without
        calling back into the broker's private state.

    agent_name:
        Human-readable agent name (path param == registry key).
    """

    upstream_url: str
    is_filesystem_agent: bool
    tenant_id: str
    agent_name: str
    is_git_agent: bool = False


class McpBrokerRegistry:
    """
    Maps agent_name → (McpBroker, McpBrokerServerConfig).

    One McpBroker instance per registered MCP server.
    Registry is built once at startup; no runtime mutations.
    """

    def __init__(self) -> None:
        self._registry: dict[str, tuple[object, McpBrokerServerConfig]] = {}

    def register(
        self,
        agent_name: str,
        broker: object,  # McpBroker — typed as object to avoid circular import
        config: McpBrokerServerConfig,
    ) -> None:
        """Register a broker + config for agent_name. Overwrites if already set."""
        if agent_name in self._registry:
            logger.warning(
                "mcp-registry: re-registering agent_name=%r (existing entry replaced)",
                agent_name,
            )
        self._registry[agent_name] = (broker, config)
        logger.info(
            "mcp-registry: registered agent_name=%r upstream=%r is_filesystem=%s",
            agent_name, config.upstream_url, config.is_filesystem_agent,
        )

    def get(
        self, agent_name: str
    ) -> Optional[tuple[object, McpBrokerServerConfig]]:
        """
        Return (broker, server_config) for agent_name, or None if not registered.
        """
        return self._registry.get(agent_name)

    def all_brokers(self) -> list[object]:
        """Return all registered broker instances (useful for health probes)."""
        return [broker for broker, _ in self._registry.values()]

    def __len__(self) -> int:
        return len(self._registry)

    def __repr__(self) -> str:
        return f"McpBrokerRegistry(agents={list(self._registry.keys())})"


def build_registry_from_env(
    opa_url: str,
    audit_writer: Optional[object] = None,
    semantic_intent_sidecar: Optional[object] = None,
    envelope_service: Optional[object] = None,
    permission_store: Optional[object] = None,  # PermissionStore — 3.1 Phase 4
    org_id: str = "default",                    # 3.1 Phase 4 — org ceiling
    pending_store: Optional[object] = None,     # EnvelopePendingStore — 3.1 drift sink
) -> tuple[McpBrokerRegistry, object]:  # (registry, jwks_store | None)
    """
    Parse YASHIGANI_MCP_SERVERS and build a McpBrokerRegistry.

    ``semantic_intent_sidecar`` / ``envelope_service`` (3.0 / YSG-RISK-060):
    when supplied, every broker built here is wired with the escalate-only
    semantic-intent sidecar AND the capability-envelope service, so the
    tool-surface refresh/import path (``McpBroker.refresh_and_triage_tools``)
    can run the envelope triage at refresh — the structural diff vs the
    ORIGINAL baseline plus the escalate-only sidecar over the network-reachable
    inference backend (mesh-mTLS gateway→ollama edge; see
    helm/.../networkpolicy.yaml allow-gateway-egress + allow-ollama-ingress,
    and compose OLLAMA_BASE_URL/YASHIGANI_INSPECTION_DEFAULT_BACKEND).  When
    None (dev / feature OFF / pre-pool), the broker triage no-ops and the
    invocation gate still fail-closes in prod.

    ``pending_store`` (3.1 / YSG-RISK-060 full-close):
    when supplied (``EnvelopePendingStore`` over Redis db/3), every broker
    is wired with a ``pending_block_sink`` closure that calls
    ``pending_store.record_block(...)`` on drift — populating the operator-
    visible ``/admin/mcp/envelopes/pending`` queue.  None ⇒ drift is still
    latched + blocked in the DB, but the re-approval queue stays empty
    (backward-compatible dev/test mode).

    YASHIGANI_MCP_SERVERS is a JSON array of objects:
    [
      {
        "agent_name": "filesystem-mcp",
        "upstream_url": "http://filesystem-mcp:8000",
        "tenant_id": "acme",
        "is_filesystem_agent": true
      },
      ...
    ]

    Returns (registry, jwks_store).  If YASHIGANI_MCP_SERVERS is unset or empty,
    returns an empty registry and None — callers guard on len(registry) == 0.

    Fail-closed: JSON parse errors or missing required fields raise RuntimeError
    at startup so the gateway surfaces misconfiguration immediately.
    """
    from yashigani.mcp._jwt import McpJwtIssuer
    from yashigani.mcp._jwks import JwksStore
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig

    raw = os.environ.get("YASHIGANI_MCP_SERVERS", "").strip()
    if not raw:
        logger.info("mcp-registry: YASHIGANI_MCP_SERVERS not set — no MCP servers registered")
        return McpBrokerRegistry(), None

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"YASHIGANI_MCP_SERVERS is not valid JSON: {exc}"
        ) from exc

    if not isinstance(entries, list):
        raise RuntimeError(
            "YASHIGANI_MCP_SERVERS must be a JSON array of server descriptors"
        )

    if len(entries) == 0:
        logger.info("mcp-registry: YASHIGANI_MCP_SERVERS is an empty array — no MCP servers")
        return McpBrokerRegistry(), None

    # Fix-4 (HA-correctness): wire RedisNonceStore when REDIS_URL is configured,
    # fall back to InMemoryNonceStore for dev.
    #
    # Multi-replica implication: InMemoryNonceStore is PER-PROCESS.  If the
    # gateway runs with N>1 replicas, each replica has its own nonce store.
    # A jti that was admitted by replica A can be replayed to replica B — the
    # replay dedup window is only intra-process.
    #
    # RedisNonceStore uses a single shared Redis sorted set per tenant_id
    # (mcp:jti:seen:{tenant_id}).  Redis ZADD NX provides atomic replay dedup
    # across ALL gateway replicas.  REQUIRED for multi-replica deployments.
    #
    # When REDIS_URL is unset (dev/test), InMemoryNonceStore is used.  This is
    # intentional: the InMemoryNonceStore constructor logs a WARNING that it is
    # dev-mode only.  Operators must set REDIS_URL in production.
    _nonce_store: Optional[object] = None
    redis_url = os.environ.get("REDIS_URL", "").strip()
    if redis_url:
        try:
            import redis  # type: ignore[import-untyped]
            redis_client = redis.from_url(redis_url, decode_responses=False)
            from yashigani.mcp._nonce import RedisNonceStore
            _nonce_store = RedisNonceStore(redis_client)
            logger.info(
                "mcp-registry: RedisNonceStore wired for replay prevention "
                "(REDIS_URL=%s) — safe for multi-replica deployments",
                redis_url.split("@")[-1] if "@" in redis_url else redis_url,
            )
        except ImportError:
            raise RuntimeError(
                "REDIS_URL is set but the 'redis' package is not installed. "
                "Install redis>=5.0 (already in pyproject.toml). "
                "Cannot start without RedisNonceStore when REDIS_URL is configured."
            )
        except Exception as exc:
            raise RuntimeError(
                f"Failed to construct RedisNonceStore from REDIS_URL: {exc}. "
                "Check REDIS_URL and Redis connectivity."
            ) from exc
    else:
        # Dev/test: InMemoryNonceStore — logs a warning automatically in its __init__.
        # NOTE: InMemoryNonceStore is NOT safe for multi-replica deployments.
        # Set REDIS_URL in production/staging to use RedisNonceStore.
        from yashigani.mcp._nonce import InMemoryNonceStore
        _nonce_store = InMemoryNonceStore()

    # Build one shared issuer + JWKS store (one key per installation).
    #
    # Iris F-1 fix: "one key per installation, not per server" (design §3.4).
    # All brokers share a single McpJwtIssuer — per-broker instantiation caused
    # each broker to load (or generate) its OWN key in dev mode, resulting in
    # JWTs from broker B being rejected against shared_issuer's JWKS (broker A's
    # key).  The tenant_id in JWT claims identifies the tenant; it does NOT
    # determine the signing key.  The shared issuer signs for all tenants.
    #
    # The first entry's tenant_id is used to label the shared issuer (JWKS kid
    # and iss prefix).  This is a cosmetic choice — the key itself is shared.
    first_tenant = entries[0].get("tenant_id", "default")
    shared_issuer = McpJwtIssuer(tenant_id=first_tenant)
    jwks_store = JwksStore(primary_issuer=shared_issuer)

    registry = McpBrokerRegistry()

    for i, entry in enumerate(entries):
        _required = {"agent_name", "upstream_url", "tenant_id"}
        missing = _required - set(entry.keys())
        if missing:
            raise RuntimeError(
                f"YASHIGANI_MCP_SERVERS[{i}] is missing required fields: {missing}"
            )

        agent_name = str(entry["agent_name"])
        upstream_url = str(entry["upstream_url"])
        tenant_id = str(entry["tenant_id"])
        is_filesystem_agent = bool(entry.get("is_filesystem_agent", False))
        is_git_agent = bool(entry.get("is_git_agent", False))

        # Broker companion (FIX-003-companion) — wire P8 upstream pin config.
        #
        # If the YASHIGANI_MCP_SERVERS entry carries cert/SPIFFE pin material
        # (cert_fingerprint_sha256 or spiffe_id), build an UpstreamPinConfig and
        # pass it to McpBrokerConfig.upstream_pin_configs.  This activates:
        #   • broker.verify_upstream() Step 2f in enforce() (cert-fingerprint / SPIFFE check)
        #   • broker._provenance_id_for() → non-None → capability-envelope gate LIVE
        #
        # Without this wiring _upstream_pin_map is always empty → _provenance_id_for
        # returns None for ALL servers → envelope enforcement is inert for every
        # server regardless of whether an envelope v1 has been minted (FIX-003).
        #
        # Security note: the provenance_id is H(server_id ‖ pin_material).  A bare
        # server_id name-fallback (no pin material) is NOT used — a name can be
        # spoofed.  No pin material → no envelope binding → gate stays inert for
        # that server (correct fail-open only in dev; in prod P8 also raises on the
        # missing pin, so the call is denied at Step 2f before the envelope gate).
        _upstream_pin_configs = None
        _cert_fp = (entry.get("cert_fingerprint_sha256") or "").strip()
        _spiffe_id_val = (entry.get("spiffe_id") or "").strip()
        if _cert_fp or _spiffe_id_val:
            from urllib.parse import urlparse as _urlparse
            from yashigani.mcp._upstream_pin import UpstreamPinConfig, PinMode
            _parsed_url = _urlparse(upstream_url)
            _pin_host = (entry.get("pin_host") or "").strip() or (_parsed_url.hostname or "")
            # Port: explicit pin_port > URL port > 443 (TLS default for external)
            _raw_pin_port = entry.get("pin_port") or _parsed_url.port or 443
            try:
                _pin_port = int(_raw_pin_port)
            except (TypeError, ValueError):
                _pin_port = 443
            _pin_mode_raw = (entry.get("pin_mode") or "cert_fingerprint").strip()
            try:
                _pin_mode = PinMode(_pin_mode_raw)
            except ValueError:
                logger.warning(
                    "mcp-registry: [P8] unknown pin_mode=%r for agent=%r — "
                    "defaulting to cert_fingerprint",
                    _pin_mode_raw, agent_name,
                )
                _pin_mode = PinMode.CERT_FINGERPRINT
            _upstream_pin_configs = [UpstreamPinConfig(
                server_id=agent_name,
                host=_pin_host,
                port=_pin_port,
                pin_mode=_pin_mode,
                cert_fingerprint_sha256=_cert_fp or None,
                spiffe_id=_spiffe_id_val or None,
            )]
            logger.info(
                "mcp-registry: [P8] pin config wired for agent=%r "
                "mode=%r host=%r port=%d — provenance_id + envelope gate ACTIVE",
                agent_name, _pin_mode.value, _pin_host, _pin_port,
            )

        # 3.1 / YSG-RISK-060 full-close — build a pending-block sink so that
        # drift detected by refresh_and_triage_tools() is handed to the
        # operator re-approval queue (Redis db/3).  The closure captures a
        # reference to the shared pending_store (constructed once in the gateway
        # lifespan); a new closure per server is correct here because each
        # broker instance is per-server, but they all write to the SAME store.
        # Decoupling: the broker imports nothing from backoffice or Redis.
        _pending_block_sink = None
        if pending_store is not None:
            def _make_sink(_store: object) -> object:
                def _sink(
                    *,
                    provenance_id: str,
                    tenant_id: str,
                    server_id: str,
                    candidate: object,
                    triage_class: str,
                    new_surface_hash: str,
                    findings: list,
                ) -> None:
                    _store.record_block(  # type: ignore[attr-defined]
                        provenance_id=provenance_id,
                        tenant_id=tenant_id,
                        server_id=server_id,
                        candidate=candidate,
                        triage_class=triage_class,
                        new_surface_hash=new_surface_hash,
                        findings=findings,
                    )
                return _sink
            _pending_block_sink = _make_sink(pending_store)
            logger.info(
                "mcp-registry: pending_block_sink wired for agent=%r — drift "
                "writes to operator re-approval queue (YSG-RISK-060)",
                agent_name,
            )

        broker_cfg = McpBrokerConfig(
            opa_url=opa_url,
            tenant_id=tenant_id,
            issuer=shared_issuer,  # Iris F-1: shared issuer, not per-broker instance
            audit_writer=audit_writer,
            is_filesystem_agent=is_filesystem_agent,
            is_git_agent=is_git_agent,
            nonce_store=_nonce_store,
            # 3.0 / YSG-RISK-060 — wire the refresh-path envelope triage:
            # escalate-only sidecar (over the mesh-mTLS gateway→ollama edge) +
            # the capability-envelope durable store.  None ⇒ triage no-ops.
            semantic_intent_sidecar=semantic_intent_sidecar,
            envelope_service=envelope_service,
            # 3.1 / YSG-RISK-060 full-close — operator re-approval queue sink.
            # None ⇒ drift is blocked in DB but queue stays empty (dev/test).
            pending_block_sink=_pending_block_sink,
            # 3.1 Phase 4 — connection allow-list enforcement.
            # When permission_store is None (dev/test), the check is a no-op.
            permission_store=permission_store,
            org_id=org_id,
            # FIX-003-companion: P8 pin configs extracted from YASHIGANI_MCP_SERVERS entry.
            # None when no pin material configured (local/stdio agents, no envelope binding).
            upstream_pin_configs=_upstream_pin_configs,
        )
        broker = McpBroker(config=broker_cfg)

        server_cfg = McpBrokerServerConfig(
            upstream_url=upstream_url,
            is_filesystem_agent=is_filesystem_agent,
            is_git_agent=is_git_agent,
            tenant_id=tenant_id,
            agent_name=agent_name,
        )

        registry.register(agent_name, broker, server_cfg)
        logger.info(
            "mcp-registry: registered agent=%r upstream=%r "
            "is_filesystem=%s is_git=%s tenant=%r",
            agent_name, upstream_url,
            is_filesystem_agent, is_git_agent, tenant_id,
        )

    logger.info(
        "mcp-registry: built registry with %d server(s): %s",
        len(registry),
        [e.get("agent_name") for e in entries],
    )
    return registry, jwks_store
