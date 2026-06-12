"""
Yashigani Pool Manager — Container lifecycle management.

Every identity gets a dedicated container for every service it invokes.
No shared instances. Container-per-identity is the ONLY isolation model.

Responsibilities:
  - Create container on first request
  - Route (identity_id, service_slug) -> container endpoint
  - Monitor health, replace unhealthy containers
  - Collect postmortem evidence before killing dead containers
  - Scale Ollama horizontally on load
  - Enforce license tier container limits
  - Tear down idle containers

Uses ContainerBackend abstraction (pool/backend.py) which supports
both Docker SDK and Podman SDK with automatic detection.

P1 W2 extension (v2.25.0):
  The ring-fence onboarding feature extends this module with:
    - ContainerInfo.networks / .mode / .spiffe_identity / .ringfence_init_ready
    - CertMount dataclass for SPIFFE TLS cert bind-mounts
    - get_or_create() + _create_container() keyword-only ring-fence params
    - _wait_for_ringfence_init() for PM / init-sidecar sequencing (plan L12)
    - RingfenceInitTimeout exception
  Full contract: src/yashigani/pool/POOL_MANAGER_CONTRACT.md
  TODO(tom): implement the P1 W2 extension against the contract in this file.
"""
from __future__ import annotations

import logging
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

# FIX-3 (Nico gate): SPIFFE identity prefix enforced at dataclass init time.
# Any non-empty spiffe_identity MUST start with this prefix — no caller can
# silently flow an arbitrary SPIFFE URI into ContainerInfo.
_SPIFFE_REQUIRED_PREFIX_RE = re.compile(
    r"^spiffe://yashigani\.internal/agents/"
)

logger = logging.getLogger(__name__)


@dataclass
class CertMount:
    """
    SPIFFE TLS certificate mount specification for a ring-fenced agent.

    P1 W2 (plan L11) — Captain owns contract; Tom owns implementation.
    Full spec: src/yashigani/pool/POOL_MANAGER_CONTRACT.md §2.

    host_cert_path / host_key_path / host_ca_path: absolute paths on the
    host (issued at onboard time by install.sh _pki_run_issuer).
    container_*_path: mount destinations inside the agent container.
    spiffe_identity: SPIFFE URI embedded in the cert — written to ContainerInfo.
    """
    host_cert_path: str
    host_key_path: str
    host_ca_path: str
    container_cert_path: str = "/run/secrets/client.crt"
    container_key_path: str = "/run/secrets/client.key"
    container_ca_path: str = "/run/secrets/ca.crt"
    spiffe_identity: str = ""

    def __post_init__(self) -> None:
        """
        FIX-3 (Nico gate — P1 W2): enforce SPIFFE identity prefix.

        A non-empty spiffe_identity MUST match
        ``spiffe://yashigani.internal/agents/``.  Empty string is allowed for
        non-agent pool containers (legacy behaviour, no cert issued).

        Raises:
            ValueError: if spiffe_identity is non-empty and does not start with
                        the required ``spiffe://yashigani.internal/agents/`` prefix.
        """
        if self.spiffe_identity and not _SPIFFE_REQUIRED_PREFIX_RE.match(
            self.spiffe_identity
        ):
            raise ValueError(
                f"CertMount.spiffe_identity {self.spiffe_identity!r} does not match the required prefix "
                "spiffe://yashigani.internal/agents/ — arbitrary SPIFFE identities "
                "must not flow silently into ContainerInfo. "
                "Use spiffe://yashigani.internal/agents/<tenant_id>/<agent_name> "
                "or leave spiffe_identity empty for non-agent containers. "
                "(FIX-3 / Nico gate, POOL_MANAGER_CONTRACT.md §2)"
            )


@dataclass
class ContainerInfo:
    """Tracking info for a managed container."""
    container_id: str
    container_name: str
    identity_id: str
    service_slug: str
    image: str
    endpoint: str           # host:port for routing
    status: str             # 'starting', 'healthy', 'unhealthy', 'stopped'
    created_at: float       # time.time()
    last_active: float      # time.time() — updated on every request
    health_failures: int = 0

    # P1 W2 extension (plan L11) — TODO(tom): implement usage in _create_container
    networks: list[str] = field(default_factory=list)
    """All network names the container is connected to.
    Ring-fenced agents: [ringfence_<agent>, caddy_internal].
    Legacy pool containers: [] (uses PoolManager._network)."""

    mode: str = "on-demand"
    """Container lifecycle mode.
    "on-demand"  — cleanup_idle() tears down after idle_timeout_seconds.
    "persistent" — cleanup_idle() skips; explicit teardown only.
    v1 ring-fenced agents MUST be "persistent" (Nico N2 constraint)."""

    spiffe_identity: str = ""
    """SPIFFE URI for this container instance.
    Format: spiffe://yashigani.internal/agents/{tenant_id}/{agent_name}
    Empty for non-agent pool containers."""

    ringfence_init_ready: bool = False
    """True after ringfence-init sidecar wrote /run/ringfence/ready
    and _wait_for_ringfence_init() confirmed it (plan L12)."""


@dataclass
class TierLimits:
    """Container limits per license tier."""
    per_service_per_identity: int = 1
    total_concurrent: int = 3

    @classmethod
    def from_tier(cls, tier: str) -> TierLimits:
        return _TIER_LIMITS.get(tier.lower(), cls())


_TIER_LIMITS = {
    "community": TierLimits(per_service_per_identity=1, total_concurrent=3),
    "academic": TierLimits(per_service_per_identity=1, total_concurrent=3),
    "starter": TierLimits(per_service_per_identity=1, total_concurrent=5),
    "professional": TierLimits(per_service_per_identity=3, total_concurrent=15),
    "professional_plus": TierLimits(per_service_per_identity=5, total_concurrent=50),
    "enterprise": TierLimits(per_service_per_identity=999, total_concurrent=9999),
}


class PoolManager:
    """
    Manages per-identity container lifecycle.

    Thread-safe. Container operations go through ContainerBackend
    (supports Docker SDK, Podman SDK, or stub mode).
    """

    def __init__(
        self,
        docker_client=None,
        backend=None,
        network_name: str = "docker_internal",
        idle_timeout_seconds: int = 1800,  # 30 minutes
        tier: str = "community",
        postmortem_dir: str = "/data/postmortem",
    ) -> None:
        # Prefer new backend param; fall back to legacy docker_client for test compat
        self._backend = backend
        self._docker = docker_client if not backend else None
        self._network = network_name
        self._idle_timeout = idle_timeout_seconds
        self._limits = TierLimits.from_tier(tier)
        self._postmortem_dir = postmortem_dir
        self._lock = threading.Lock()

        # Active containers: key = (identity_id, service_slug)
        self._containers: dict[tuple[str, str], ContainerInfo] = {}

        logger.info(
            "PoolManager: tier=%s, limits=%d/%d, idle_timeout=%ds",
            tier, self._limits.per_service_per_identity,
            self._limits.total_concurrent, idle_timeout_seconds,
        )

    def get_or_create(
        self,
        identity_id: str,
        service_slug: str,
        image: str,
        env: dict[str, str] | None = None,
        port: int = 8080,
        # P1 W2 ring-fence extension (keyword-only, backwards-compatible):
        *,
        networks: Optional[list[str]] = None,
        cert_mount: Optional["CertMount"] = None,
        mode: str = "on-demand",
        ringfence_init_network: Optional[str] = None,
    ) -> ContainerInfo:
        """
        Get an existing container or create a new one for (identity, service).

        Args:
            identity_id: The requesting identity
            service_slug: The service to invoke (e.g. 'goose')
            image: Docker image to run
            env: Environment variables for the container
            port: Internal port the service listens on

        P1 W2 keyword-only args (backwards-compatible — all default to existing behaviour):
            networks: Additional networks beyond self._network. Ring-fenced agents:
                      [ringfence_<agent>, caddy_internal]. None = use self._network only.
            cert_mount: SPIFFE TLS cert bind-mount spec. None = no cert mounts.
            mode: "on-demand" (cleanup_idle eligible) or "persistent" (explicit teardown only).
                  v1 ring-fenced agents MUST be "persistent" (Nico N2 constraint).
            ringfence_init_network: If set, _create_container waits for ringfence-init
                  sidecar to complete before returning. Raises RingfenceInitTimeout if
                  the sidecar does not finish within timeout. None = skip wait.

        Returns:
            ContainerInfo with the endpoint to route to

        Raises:
            PoolLimitExceeded: If tier limits would be exceeded
            RingfenceInitTimeout: If ringfence_init_network set and sidecar timed out
        """
        key = (identity_id, service_slug)

        with self._lock:
            # Check if container already exists and is healthy
            existing = self._containers.get(key)
            if existing and existing.status in ("healthy", "starting"):
                existing.last_active = time.time()
                return existing

            # Check tier limits
            self._check_limits(identity_id)

            # Create new container
            # TODO(tom, P1 W2): pass networks/cert_mount/mode/ringfence_init_network
            # to _create_container() when implementing the ring-fence PM extension.
            container_info = self._create_container(
                identity_id, service_slug, image, env or {}, port,
                networks=networks,
                cert_mount=cert_mount,
                mode=mode,
                ringfence_init_network=ringfence_init_network,
            )
            self._containers[key] = container_info
            try:
                from yashigani.metrics.registry import yashigani_pool_containers_created_total
                yashigani_pool_containers_created_total.inc()
            except Exception:
                pass
            return container_info

    def get(self, identity_id: str, service_slug: str) -> Optional[ContainerInfo]:
        """Get container info without creating. Returns None if not running."""
        return self._containers.get((identity_id, service_slug))

    def list_for_identity(self, identity_id: str) -> list[ContainerInfo]:
        """List all containers for an identity."""
        return [
            info for (iid, _), info in self._containers.items()
            if iid == identity_id
        ]

    def list_all(self) -> list[ContainerInfo]:
        """List all managed containers."""
        return list(self._containers.values())

    def mark_healthy(self, identity_id: str, service_slug: str) -> None:
        """Mark a container as healthy (called by health monitor)."""
        key = (identity_id, service_slug)
        if key in self._containers:
            self._containers[key].status = "healthy"
            self._containers[key].health_failures = 0

    def mark_unhealthy(self, identity_id: str, service_slug: str) -> None:
        """Mark a container as unhealthy. Triggers replacement after threshold."""
        key = (identity_id, service_slug)
        if key in self._containers:
            info = self._containers[key]
            info.health_failures += 1
            if info.health_failures >= 3:
                info.status = "unhealthy"
                logger.warning(
                    "Container %s unhealthy (%d failures) — scheduling replacement",
                    info.container_name, info.health_failures,
                )

    def replace(self, identity_id: str, service_slug: str, reason: str) -> Optional[ContainerInfo]:
        """
        Replace an unhealthy container: postmortem -> new container -> kill old.

        Returns the new ContainerInfo, or None if replacement failed.
        """
        key = (identity_id, service_slug)
        old = self._containers.get(key)
        if not old:
            return None

        logger.info("Replacing container %s: %s", old.container_name, reason)

        # Collect postmortem
        if self._backend or self._docker:
            try:
                from yashigani.pool.postmortem import collect_postmortem
                collect_postmortem(
                    self._docker, old.container_id, old.container_name,
                    reason, self._postmortem_dir,
                )
            except Exception as exc:
                logger.error("Postmortem failed for %s: %s", old.container_name, exc)

        # Create replacement — forward ring-fence params from old ContainerInfo (P1 W2)
        # TODO(tom, P1 W2): also reconstruct cert_mount from old.spiffe_identity via
        # a _resolve_cert_mount() helper (see POOL_MANAGER_CONTRACT.md §7).
        image = old.image if hasattr(old, "image") else ""
        try:
            new_info = self._create_container(
                identity_id, service_slug, image, {}, 8080,
                networks=old.networks if old.networks else None,
                mode=old.mode,
                # cert_mount: TODO(tom) — reconstruct from old.spiffe_identity
                ringfence_init_network=old.networks[0] if old.networks else None,
            )
            self._containers[key] = new_info
        except Exception as exc:
            logger.error("Failed to create replacement for %s: %s", old.container_name, exc)
            return None

        # Kill old container
        self._kill_container(old.container_id)

        try:
            from yashigani.metrics.registry import yashigani_pool_containers_replaced_total
            yashigani_pool_containers_replaced_total.inc()
        except Exception:
            pass

        return new_info

    def teardown(self, identity_id: str, service_slug: str, reason: str = "idle") -> None:
        """Tear down a container (idle timeout or identity deactivation)."""
        key = (identity_id, service_slug)
        info = self._containers.pop(key, None)
        if info:
            logger.info("Tearing down %s: %s", info.container_name, reason)
            if self._backend or self._docker:
                try:
                    from yashigani.pool.postmortem import collect_postmortem
                    collect_postmortem(
                        self._docker, info.container_id, info.container_name,
                        reason, self._postmortem_dir,
                    )
                except Exception:
                    pass
            self._kill_container(info.container_id)

    def teardown_all_for_identity(self, identity_id: str, reason: str = "deactivated") -> int:
        """Kill all containers for an identity. Returns count."""
        keys_to_remove = [
            k for k in self._containers if k[0] == identity_id
        ]
        for key in keys_to_remove:
            self.teardown(key[0], key[1], reason)
        return len(keys_to_remove)

    def cleanup_idle(self) -> int:
        """Tear down containers that have been idle longer than the timeout.

        P1 W2 modification: skips containers where info.mode == "persistent".
        Persistent containers are only torn down by explicit teardown() or
        teardown_all_for_identity() (e.g. yashigani offboard — Su S5/Lu G4).
        """
        now = time.time()
        idle_keys = [
            key for key, info in self._containers.items()
            if (now - info.last_active) > self._idle_timeout
            and info.mode != "persistent"  # P1 W2: skip persistent ring-fenced agents
        ]
        for key in idle_keys:
            self.teardown(key[0], key[1], f"idle>{self._idle_timeout}s")
        if idle_keys:
            try:
                from yashigani.metrics.registry import yashigani_pool_containers_idle_teardown_total
                yashigani_pool_containers_idle_teardown_total.inc(len(idle_keys))
            except Exception:
                pass
        return len(idle_keys)

    def count(self, identity_id: str | None = None) -> int:
        """Count active containers, optionally for a specific identity."""
        if identity_id:
            return sum(1 for k in self._containers if k[0] == identity_id)
        return len(self._containers)

    # ── Internal ─────────────────────────────────────────────────────

    def _check_limits(self, identity_id: str) -> None:
        """Check tier limits before creating a new container."""
        identity_count = self.count(identity_id)
        if identity_count >= self._limits.total_concurrent:
            try:
                from yashigani.metrics.registry import yashigani_pool_limit_exceeded_total
                yashigani_pool_limit_exceeded_total.inc()
            except Exception:
                pass
            raise PoolLimitExceeded(
                f"Identity {identity_id} has {identity_count} containers "
                f"(limit: {self._limits.total_concurrent})"
            )

        total = self.count()
        # No global limit enforcement here — tier limit is per identity

    def _create_container(
        self,
        identity_id: str,
        service_slug: str,
        image: str,
        env: dict,
        port: int,
        # P1 W2 extension (keyword-only) — TODO(tom): implement ring-fence body
        *,
        networks: Optional[list[str]] = None,
        cert_mount: Optional["CertMount"] = None,
        mode: str = "on-demand",
        ringfence_init_network: Optional[str] = None,
    ) -> ContainerInfo:
        """Create a new container via ContainerBackend (Docker or Podman).

        P1 W2 ring-fence parameters (keyword-only):
            networks: Additional networks beyond self._network. When provided,
                      the primary network is networks[0]; additional networks
                      are connected via network.connect() after creation.
                      TODO(tom): implement multi-network connect in each backend branch.
            cert_mount: SPIFFE TLS cert bind-mount. When provided, the container
                        gets the certs mounted at container_*_path (read-only).
                        TODO(tom): implement bind-mount injection per backend type.
            mode: "on-demand" | "persistent". Set on ContainerInfo for cleanup_idle().
            ringfence_init_network: If set, call _wait_for_ringfence_init() before
                                    returning. Raises RingfenceInitTimeout on timeout.
                                    TODO(tom): implement _wait_for_ringfence_init().
        """
        short_id = identity_id[-8:] if len(identity_id) > 8 else identity_id
        container_name = f"ysg-{service_slug}-{short_id}-{uuid.uuid4().hex[:6]}"

        # Determine effective primary network (P1 W2: ring-fenced agents pass networks[0])
        primary_network = networks[0] if networks else self._network
        additional_networks = networks[1:] if networks and len(networks) > 1 else []

        if self._backend:
            try:
                _labels = {
                    "yashigani.managed": "true",
                    "yashigani.identity": identity_id,
                    "yashigani.service": service_slug,
                }
                if ringfence_init_network:
                    _labels["yashigani.ringfence-network"] = ringfence_init_network
                if cert_mount and cert_mount.spiffe_identity:
                    _labels["yashigani.spiffe"] = cert_mount.spiffe_identity

                if self._backend.name == "kubernetes":
                    # KubernetesBackend.run() has no `network` param — pods use
                    # K8s in-namespace networking. The `port` param sets the
                    # container port declaration and the wait-for-Running path
                    # resolves the pod IP directly.
                    # TODO(tom, P1 W2): pass cert_mount to K8s projected-volume path.
                    handle = self._backend.run(
                        image=image,
                        name=container_name,
                        environment=env,
                        labels=_labels,
                        port=port,
                    )
                else:
                    # TODO(tom, P1 W2): pass cert_mount and additional_networks to
                    # ContainerBackend.run() once backend.run() is extended.
                    handle = self._backend.run(
                        image=image,
                        name=container_name,
                        environment=env,
                        network=primary_network,
                        labels=_labels,
                    )
                    # TODO(tom, P1 W2): connect additional_networks after run()
                    # if additional_networks:
                    #     for extra_net in additional_networks:
                    #         self._backend._client.networks.get(extra_net).connect(...)
                container_id = handle.id
                ip = handle.get_network_ip(primary_network)
                endpoint = f"{ip}:{port}"
            except Exception as exc:
                logger.error("Failed to create container %s: %s", container_name, exc)
                raise
        elif self._docker:
            # Legacy Docker client path (test compatibility)
            try:
                container = self._docker.containers.run(
                    image=image,
                    name=container_name,
                    environment=env,
                    network=primary_network,
                    detach=True,
                    remove=False,
                    labels={
                        "yashigani.managed": "true",
                        "yashigani.identity": identity_id,
                        "yashigani.service": service_slug,
                    },
                )
                container_id = container.id
                container.reload()
                container_networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                ip = "127.0.0.1"
                if primary_network in container_networks:
                    ip = container_networks[primary_network].get("IPAddress", "127.0.0.1")
                endpoint = f"{ip}:{port}"
                # TODO(tom, P1 W2): connect additional_networks for Docker legacy path
            except Exception as exc:
                logger.error("Failed to create container %s: %s", container_name, exc)
                raise
        else:
            # No backend — return a stub (for testing)
            container_id = f"stub-{uuid.uuid4().hex[:12]}"
            endpoint = f"127.0.0.1:{port}"

        # TODO(tom, P1 W2): call _wait_for_ringfence_init(ringfence_init_network)
        # here (before building ContainerInfo) if ringfence_init_network is set.
        # Example (to be implemented):
        #   if ringfence_init_network:
        #       self._wait_for_ringfence_init(ringfence_init_network)

        info = ContainerInfo(
            container_id=container_id,
            container_name=container_name,
            identity_id=identity_id,
            service_slug=service_slug,
            image=image,
            endpoint=endpoint,
            status="starting",
            created_at=time.time(),
            last_active=time.time(),
            # P1 W2 fields:
            networks=list(networks) if networks else [],
            mode=mode,
            spiffe_identity=cert_mount.spiffe_identity if cert_mount else "",
            ringfence_init_ready=(ringfence_init_network is None),  # True when no wait required
        )

        logger.info(
            "PoolManager: created %s for identity=%s service=%s endpoint=%s mode=%s",
            container_name, identity_id, service_slug, endpoint, mode,
        )
        return info

    def _wait_for_ringfence_init(
        self,
        ringfence_network: str,
        timeout_seconds: int = 30,
        poll_interval_seconds: float = 0.5,
    ) -> None:
        """
        Wait until the ringfence-init sidecar writes /run/ringfence/ready.

        P1 W2 (plan L12) — CONTRACT STUB. Tom implements this method.
        See POOL_MANAGER_CONTRACT.md §5 for full specification.

        Raises:
            RingfenceInitTimeout: if sidecar does not complete within timeout_seconds.
                                  Caller must NOT create the agent container.
        """
        # TODO(tom, P1 W2): implement polling for ringfence-init sidecar readiness.
        # Contract: fail-closed — raise RingfenceInitTimeout on timeout.
        # K8s backend: no-op (initContainer exit code is the sequencing gate).
        # Compose/direct-API: poll init container exit code + /run/ringfence/ready.
        raise NotImplementedError(
            "_wait_for_ringfence_init() is a P1 W2 contract stub. "
            "Tom implements this method. See POOL_MANAGER_CONTRACT.md §5."
        )

    def _kill_container(self, container_id: str) -> None:
        """Kill and remove a container."""
        if self._backend:
            try:
                handle = self._backend.get(container_id)
                handle.kill()
                handle.remove(force=True)
            except Exception as exc:
                logger.warning("Failed to kill container %s: %s", container_id[:12], exc)
        elif self._docker:
            try:
                container = self._docker.containers.get(container_id)
                container.kill()
                container.remove(force=True)
            except Exception as exc:
                logger.warning("Failed to kill container %s: %s", container_id[:12], exc)


class PoolLimitExceeded(Exception):
    """Raised when tier container limits would be exceeded."""
    pass


class RingfenceInitTimeout(Exception):
    """
    Raised when PoolManager._wait_for_ringfence_init() does not observe
    the ringfence-init sidecar completing within the timeout window.

    P1 W2 (plan L12) — Captain owns contract; Tom owns implementation.

    Callers MUST NOT create the agent container after this exception.
    Treat as a hard failure; emit 503 Service Unavailable.
    Fail-closed contract: an un-ring-fenced agent must never start.
    """
    pass
