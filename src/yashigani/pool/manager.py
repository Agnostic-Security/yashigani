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
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


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
    ) -> ContainerInfo:
        """
        Get an existing container or create a new one for (identity, service).

        Args:
            identity_id: The requesting identity
            service_slug: The service to invoke (e.g. 'goose')
            image: Docker image to run
            env: Environment variables for the container
            port: Internal port the service listens on

        Returns:
            ContainerInfo with the endpoint to route to

        Raises:
            PoolLimitExceeded: If tier limits would be exceeded
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
            container_info = self._create_container(
                identity_id, service_slug, image, env or {}, port,
            )
            self._containers[key] = container_info
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

        # Create replacement
        image = old.image if hasattr(old, "image") else ""
        try:
            new_info = self._create_container(
                identity_id, service_slug, image, {}, 8080,
            )
            self._containers[key] = new_info
        except Exception as exc:
            logger.error("Failed to create replacement for %s: %s", old.container_name, exc)
            return None

        # Kill old container
        self._kill_container(old.container_id)

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
        """Tear down containers that have been idle longer than the timeout."""
        now = time.time()
        idle_keys = [
            key for key, info in self._containers.items()
            if (now - info.last_active) > self._idle_timeout
        ]
        for key in idle_keys:
            self.teardown(key[0], key[1], f"idle>{self._idle_timeout}s")
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
    ) -> ContainerInfo:
        """Create a new container via ContainerBackend (Docker or Podman)."""
        short_id = identity_id[-8:] if len(identity_id) > 8 else identity_id
        container_name = f"ysg-{service_slug}-{short_id}-{uuid.uuid4().hex[:6]}"

        if self._backend:
            try:
                _labels = {
                    "yashigani.managed": "true",
                    "yashigani.identity": identity_id,
                    "yashigani.service": service_slug,
                }
                if self._backend.name == "kubernetes":
                    # KubernetesBackend.run() has no `network` param — pods use
                    # K8s in-namespace networking. The `port` param sets the
                    # container port declaration and the wait-for-Running path
                    # resolves the pod IP directly.
                    handle = self._backend.run(
                        image=image,
                        name=container_name,
                        environment=env,
                        labels=_labels,
                        port=port,
                    )
                else:
                    handle = self._backend.run(
                        image=image,
                        name=container_name,
                        environment=env,
                        network=self._network,
                        labels=_labels,
                    )
                container_id = handle.id
                ip = handle.get_network_ip(self._network)
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
                    network=self._network,
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
                networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                ip = "127.0.0.1"
                if self._network in networks:
                    ip = networks[self._network].get("IPAddress", "127.0.0.1")
                endpoint = f"{ip}:{port}"
            except Exception as exc:
                logger.error("Failed to create container %s: %s", container_name, exc)
                raise
        else:
            # No backend — return a stub (for testing)
            container_id = f"stub-{uuid.uuid4().hex[:12]}"
            endpoint = f"127.0.0.1:{port}"

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
        )

        logger.info(
            "PoolManager: created %s for identity=%s service=%s endpoint=%s",
            container_name, identity_id, service_slug, endpoint,
        )
        return info

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
