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
    # v4.0 Item B — stable UUID minted once at first registration.
    # Keyed in: perm:grant:mcp_server:org:{org_id}:{mcp_id}
    # When present, McpBroker._check_connection_permit() uses mcp_id as the
    # grant key instead of agent_name so renaming a server does NOT orphan grants.
    # Populated by build_registry_from_env() via McpIdStore.get_or_mint().
    mcp_id: str = ""
    # v4.1 Phase 2a (LU-MCP-A2) — SHA-256 fingerprint of this instance's leaf
    # certificate ("sha256:<hex>").  Populated from the durable registry
    # descriptor written by the approve transaction (the minted per-instance
    # leaf), or left empty for boot-env entries without one.  Threaded into
    # McpCallContext.target_cert_fingerprint by the runtime router so the OPA
    # input target carries the cert binding.
    cert_fingerprint: str = ""


class McpBrokerRegistry:
    """
    Maps agent_name → (McpBroker, McpBrokerServerConfig).

    One McpBroker instance per registered MCP server.

    Population sources:
      1. Boot: YASHIGANI_MCP_SERVERS env var (build_registry_from_env).
      2. Runtime (v4.1 Phase 2a / SEAM-1d-07): the durable registry store —
         on a lookup MISS, ``get()`` consults the attached
         DurableMcpRegistryStore and lazily builds + registers the broker
         from the persisted descriptor.  This is how an MCP onboarded by the
         approve transaction becomes routable WITHOUT a gateway reboot.

    Thread-safety: dict reads are atomic in CPython; the lazy-register path
    is idempotent (rebuilding the same descriptor twice registers an
    equivalent broker — last write wins, both are valid).
    """

    def __init__(self) -> None:
        self._registry: dict[str, tuple[object, McpBrokerServerConfig]] = {}
        # v4.1 Phase 2a — lazy durable-store fallback (SEAM-1d-07).
        self._durable_store: Optional[object] = None   # DurableMcpRegistryStore
        self._broker_factory: Optional[object] = None  # Callable[[dict], tuple]

    def attach_durable_source(
        self,
        durable_store: object,
        broker_factory: object,
    ) -> None:
        """Attach the durable store + descriptor→broker factory for lazy load.

        ``broker_factory(descriptor: dict) -> (broker, McpBrokerServerConfig)``
        must build a broker with the SAME shared issuer / nonce store /
        permission wiring the boot path uses (build_registry_from_env wires
        its own per-entry builder here).
        """
        self._durable_store = durable_store
        self._broker_factory = broker_factory
        logger.info(
            "mcp-registry: durable registry source attached (SEAM-1d-07 — "
            "onboarded MCPs route without a gateway reboot)"
        )

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

        v4.1 Phase 2a (SEAM-1d-07): on a miss, consult the attached durable
        registry store; when the approve transaction has registered this
        server, lazily build + cache the broker so ``/mcp/<agent_name>``
        routes without a gateway reboot.  Every failure in the lazy path
        degrades to None (the pre-existing 404 behaviour — fail-closed).
        """
        hit = self._registry.get(agent_name)
        if hit is not None:
            return hit
        if self._durable_store is None or self._broker_factory is None:
            return None
        try:
            descriptor = self._durable_store.get_by_agent_name(  # type: ignore[attr-defined]
                agent_name
            )
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-registry: durable-store lookup failed for %r: %s",
                agent_name, exc,
            )
            return None
        if descriptor is None:
            return None
        try:
            broker, server_cfg = self._broker_factory(descriptor)  # type: ignore[operator]
        except Exception as exc:  # noqa: BLE001 — bad descriptor degrades to miss
            logger.error(
                "mcp-registry: lazy broker build failed for %r "
                "(descriptor rejected — 404): %s",
                agent_name, exc,
            )
            return None
        self.register(agent_name, broker, server_cfg)
        logger.info(
            "mcp-registry: lazily registered onboarded MCP %r from the "
            "durable registry (SEAM-1d-07 — no reboot required)",
            agent_name,
        )
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
    mcp_id_store: Optional[object] = None,      # McpIdStore — 4.0 Item B
    durable_store: Optional[object] = None,     # DurableMcpRegistryStore — 4.1 Ph2a
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

    Returns (registry, jwks_store).  If YASHIGANI_MCP_SERVERS is unset or empty
    AND no durable_store is supplied, returns an empty registry and None —
    callers guard on len(registry) == 0.

    ``durable_store`` (v4.1 Phase 2a / SEAM-1d-07): when supplied, the
    registry is wired with a lazy fallback — a lookup miss consults the
    durable registry store (written by the backoffice approve transaction)
    and builds the broker on first use, so an onboarded MCP routes WITHOUT a
    gateway reboot.  The shared issuer/nonce/jwks machinery is built even when
    the boot env is empty so lazily-built brokers can sign.

    Fail-closed: JSON parse errors or missing required fields raise RuntimeError
    at startup so the gateway surfaces misconfiguration immediately.
    """
    from yashigani.mcp._jwt import McpJwtIssuer
    from yashigani.mcp._jwks import JwksStore
    from yashigani.mcp.broker import McpBroker, McpBrokerConfig

    raw = os.environ.get("YASHIGANI_MCP_SERVERS", "").strip()
    entries: list = []
    if raw:
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

    if len(entries) == 0 and durable_store is None:
        logger.info(
            "mcp-registry: YASHIGANI_MCP_SERVERS unset/empty and no durable "
            "store — no MCP servers registered"
        )
        return McpBrokerRegistry(), None
    if len(entries) == 0:
        logger.info(
            "mcp-registry: YASHIGANI_MCP_SERVERS unset/empty — registry starts "
            "empty; durable-store lazy load active (SEAM-1d-07)"
        )

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
    first_tenant = entries[0].get("tenant_id", "default") if entries else "default"
    shared_issuer = McpJwtIssuer(tenant_id=first_tenant)
    jwks_store = JwksStore(primary_issuer=shared_issuer)

    registry = McpBrokerRegistry()

    def _build_broker_and_config(
        entry: dict,
    ) -> tuple[object, McpBrokerServerConfig]:
        """Build one (McpBroker, McpBrokerServerConfig) from a descriptor.

        Shared by the boot loop (YASHIGANI_MCP_SERVERS entries) AND the
        durable-registry lazy-load path (v4.1 Phase 2a / SEAM-1d-07) so both
        populations use the SAME shared issuer, nonce store and permission
        wiring.  Raises RuntimeError on missing required fields.
        """
        _required = {"agent_name", "upstream_url", "tenant_id"}
        missing = _required - set(entry.keys())
        if missing:
            raise RuntimeError(
                f"MCP server descriptor is missing required fields: {missing}"
            )

        agent_name = str(entry["agent_name"])
        upstream_url = str(entry["upstream_url"])
        tenant_id = str(entry["tenant_id"])
        is_filesystem_agent = bool(entry.get("is_filesystem_agent", False))
        is_git_agent = bool(entry.get("is_git_agent", False))

        # v4.0 Item B — mint (or restore) a stable mcp_id for this server.
        # Precedence:
        #   1. Explicit "mcp_id" field in the descriptor (operator-pinned).
        #   2. Existing entry in McpIdStore Redis (persisted from prior startup).
        #   3. Freshly minted UUID (first-time registration).
        # When no mcp_id_store is supplied (dev/test without Redis), fall back to
        # agent_name as the grant key (backward-compatible — grants work as before).
        _entry_mcp_id: str = str(entry.get("mcp_id", "")).strip()
        _resolved_mcp_id: str = ""
        if mcp_id_store is not None:
            try:
                _resolved_mcp_id = mcp_id_store.get_or_mint(  # type: ignore[union-attr, attr-defined]
                    agent_name,
                    override_mcp_id=_entry_mcp_id or None,
                )
            except Exception as _id_exc:
                logger.warning(
                    "mcp-registry: mcp_id mint/lookup failed for agent=%r: %s — "
                    "falling back to agent_name as grant key",
                    agent_name, _id_exc,
                )
        elif _entry_mcp_id:
            # No store but operator pinned an id — honour it.
            _resolved_mcp_id = _entry_mcp_id
        # Else: empty → broker falls back to agent_name (legacy path, no-op).

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
            # 3.1 Phase 4 — connection allow-list enforcement.
            # When permission_store is None (dev/test), the check is a no-op.
            permission_store=permission_store,
            org_id=org_id,
        )
        broker = McpBroker(config=broker_cfg)

        server_cfg = McpBrokerServerConfig(
            upstream_url=upstream_url,
            is_filesystem_agent=is_filesystem_agent,
            is_git_agent=is_git_agent,
            tenant_id=tenant_id,
            agent_name=agent_name,
            mcp_id=_resolved_mcp_id,   # v4.0 Item B — stable grant key
            # v4.1 Phase 2a (LU-MCP-A2) — per-instance leaf fingerprint from
            # the onboard transaction's durable descriptor (empty for
            # boot-env entries without one).
            cert_fingerprint=str(entry.get("cert_fingerprint", "") or ""),
        )
        return broker, server_cfg

    for i, entry in enumerate(entries):
        try:
            broker, server_cfg = _build_broker_and_config(entry)
        except RuntimeError as exc:
            raise RuntimeError(f"YASHIGANI_MCP_SERVERS[{i}]: {exc}") from exc

        registry.register(server_cfg.agent_name, broker, server_cfg)
        logger.info(
            "mcp-registry: registered agent=%r upstream=%r "
            "is_filesystem=%s is_git=%s tenant=%r",
            server_cfg.agent_name, server_cfg.upstream_url,
            server_cfg.is_filesystem_agent, server_cfg.is_git_agent,
            server_cfg.tenant_id,
        )

    # v4.1 Phase 2a (SEAM-1d-07) — wire the lazy durable-registry fallback so
    # MCPs onboarded by the approve transaction route without a gateway reboot.
    if durable_store is not None:
        registry.attach_durable_source(durable_store, _build_broker_and_config)

    logger.info(
        "mcp-registry: built registry with %d boot server(s): %s%s",
        len(registry),
        [e.get("agent_name") for e in entries],
        " (+durable lazy load)" if durable_store is not None else "",
    )
    return registry, jwks_store
