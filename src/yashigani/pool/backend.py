"""
Yashigani Pool Manager — Container backend abstraction.

Provides a unified interface for container lifecycle operations
across Docker SDK, Podman SDK, and Kubernetes API. Falls back gracefully:
  1. Kubernetes API backend — when running in-cluster (service account token present)
  2. Docker SDK (docker-py) — if Docker daemon is available
  3. Podman SDK (podman-py) — if Podman socket is available
  4. Stub mode — in-memory tracking only (no real isolation)

Security: container-per-identity isolation is a CIAA compliance
requirement. Stub mode should only be used in tests.

K8s backend notes (YSG-RISK-070):
  - Detects in-cluster via KUBERNETES_SERVICE_HOST env + service account token file.
  - Pod creation uses CoreV1Api.create_namespaced_pod().
  - Pod naming matches Docker/Podman pattern: ysg-<service>-<short_id>-<random>.
  - Labels: yashigani.managed=true, yashigani.identity=<id>, yashigani.service=<slug>.
  - Pod startup grace: K8s pods take seconds (vs Docker milliseconds). The backend
    waits up to POD_READY_TIMEOUT_S (default 120s) polling 2s intervals; if the pod
    is still Pending after the wait it raises PodStartupTimeout so the caller can
    emit 503 Retry-After rather than a silent 502.
  - RBAC: gateway ServiceAccount needs pods CRUD in its namespace (see
    helm/yashigani/templates/rbac-pool-manager.yaml). Least privilege — no
    cluster-wide permissions, no other resource types.
"""
# Last updated: 2026-05-25T00:00:00+00:00 (feat(pool): K8s API backend — YSG-RISK-070)
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Optional

logger = logging.getLogger(__name__)

# How long (seconds) to wait for a K8s pod to reach Running phase before raising.
# Kept intentionally generous — node image pulls can take tens of seconds.
_POD_READY_TIMEOUT_S = int(os.environ.get("YASHIGANI_POOL_K8S_POD_READY_TIMEOUT", "120"))
_POD_POLL_INTERVAL_S = 2


class PodStartupTimeout(Exception):
    """Raised when a K8s pod does not reach Running phase within the grace window."""
    pass


class ContainerHandle:
    """Wrapper around a container object from either Docker or Podman SDK."""

    def __init__(self, raw, backend_name: str):
        self._raw = raw
        self._backend = backend_name

    @property
    def id(self) -> str:
        return self._raw.id

    @property
    def attrs(self) -> dict:
        if self._backend == "podman":
            # podman-py uses inspect() to get full attrs
            try:
                return self._raw.inspect()
            except Exception:
                return getattr(self._raw, "attrs", {})
        return getattr(self._raw, "attrs", {})

    def reload(self) -> None:
        self._raw.reload()

    def logs(self, tail: int = 500) -> bytes:
        return self._raw.logs(tail=tail)

    def diff(self) -> list[dict]:
        try:
            return self._raw.diff()
        except Exception:
            return []

    def kill(self) -> None:
        self._raw.kill()

    def remove(self, force: bool = False) -> None:
        self._raw.remove(force=force)

    def get_network_ip(self, network_name: str) -> str:
        """Extract the container's IP on a given network."""
        self.reload()
        if self._backend == "podman":
            # Podman network info is in a different structure
            try:
                inspect = self._raw.inspect()
                networks = inspect.get("NetworkSettings", {}).get("Networks", {})
                if network_name in networks:
                    return networks[network_name].get("IPAddress", "127.0.0.1")
                # Podman may use different network naming
                for net_name, net_info in networks.items():
                    ip = net_info.get("IPAddress", "")
                    if ip:
                        return ip
            except Exception:
                pass
            return "127.0.0.1"
        else:
            networks = self.attrs.get("NetworkSettings", {}).get("Networks", {})
            if network_name in networks:
                return networks[network_name].get("IPAddress", "127.0.0.1")
            return "127.0.0.1"


class ContainerBackend:
    """Unified container backend for Docker and Podman."""

    def __init__(self, client, backend_name: str):
        self._client = client
        self.name = backend_name

    def run(
        self,
        image: str,
        name: str,
        environment: dict,
        network: str,
        labels: dict,
        detach: bool = True,
    ) -> ContainerHandle:
        """Create and start a container."""
        if self.name == "podman":
            container = self._client.containers.run(
                image=image,
                name=name,
                environment=environment,
                detach=detach,
                remove=False,
                labels=labels,
            )
            # Podman: connect to network after creation
            try:
                net = self._client.networks.get(network)
                net.connect(container)
            except Exception as exc:
                logger.warning("Podman: failed to connect %s to network %s: %s", name, network, exc)
            return ContainerHandle(container, self.name)
        else:
            container = self._client.containers.run(
                image=image,
                name=name,
                environment=environment,
                network=network,
                detach=detach,
                remove=False,
                labels=labels,
            )
            return ContainerHandle(container, self.name)

    def get(self, container_id: str) -> ContainerHandle:
        """Get an existing container by ID."""
        return ContainerHandle(
            self._client.containers.get(container_id),
            self.name,
        )

    def ping(self) -> bool:
        """Check if the backend is reachable."""
        try:
            self._client.ping()
            return True
        except Exception:
            return False


class KubernetesBackend:
    """
    Kubernetes API backend for PoolManager.

    Spawns per-identity pods via the K8s CoreV1Api when the gateway is running
    in-cluster. Requires namespace-scoped pods CRUD on the gateway ServiceAccount
    (see helm/yashigani/templates/rbac-pool-manager.yaml).

    Pod startup grace: K8s pods typically take 5-30s to reach Running (image
    pull + scheduler latency). This backend waits up to _POD_READY_TIMEOUT_S
    polling _POD_POLL_INTERVAL_S. If the pod is still Pending after the window,
    raises PodStartupTimeout — the caller should emit 503 with Retry-After
    rather than a silent 502.

    Teardown: delete_namespaced_pod() with grace_period_seconds=30 (graceful).
    """

    name = "kubernetes"

    def __init__(self, namespace: str) -> None:
        from kubernetes import client as k8s_client  # type: ignore[import-untyped]
        self._namespace = namespace
        self._core = k8s_client.CoreV1Api()

    def run(
        self,
        image: str,
        name: str,
        environment: dict,
        labels: dict,
        port: int = 8080,
    ) -> "KubernetesPodHandle":
        """Create and start a pod. Waits for Running phase."""
        from kubernetes import client as k8s_client  # type: ignore[import-untyped]

        env_vars = [
            k8s_client.V1EnvVar(name=k, value=str(v))
            for k, v in environment.items()
        ]

        pod_spec = k8s_client.V1Pod(
            metadata=k8s_client.V1ObjectMeta(
                name=name,
                namespace=self._namespace,
                labels=labels,
            ),
            spec=k8s_client.V1PodSpec(
                restart_policy="Never",
                automount_service_account_token=False,
                containers=[
                    k8s_client.V1Container(
                        name="agent",
                        image=image,
                        env=env_vars,
                        ports=[k8s_client.V1ContainerPort(container_port=port)],
                        # Security context: non-root, no privilege escalation.
                        # Pool-managed pods are USER identity containers — no
                        # elevated privileges ever (CIAA compliance).
                        security_context=k8s_client.V1SecurityContext(
                            allow_privilege_escalation=False,
                            run_as_non_root=True,
                            read_only_root_filesystem=False,  # Agents may need tmpfs writes
                            capabilities=k8s_client.V1Capabilities(drop=["ALL"]),
                        ),
                    ),
                ],
            ),
        )

        logger.info("K8s backend: creating pod %s in namespace %s", name, self._namespace)
        self._core.create_namespaced_pod(namespace=self._namespace, body=pod_spec)

        # Wait for pod to reach Running — emit informative warning if still Pending
        pod_ip = self._wait_for_running(name)
        return KubernetesPodHandle(name=name, pod_ip=pod_ip, port=port, core=self._core, namespace=self._namespace)

    def get(self, pod_name: str) -> "KubernetesPodHandle":
        """Get a handle to an existing pod by name (our pod names are the container_id)."""
        pod = self._core.read_namespaced_pod(name=pod_name, namespace=self._namespace)
        pod_ip = pod.status.pod_ip or "127.0.0.1"
        return KubernetesPodHandle(
            name=pod_name,
            pod_ip=pod_ip,
            port=8080,
            core=self._core,
            namespace=self._namespace,
        )

    def ping(self) -> bool:
        """Verify API server connectivity by listing pods (harmless)."""
        try:
            self._core.list_namespaced_pod(namespace=self._namespace, limit=1)
            return True
        except Exception:
            return False

    def _wait_for_running(self, pod_name: str) -> str:
        """
        Poll until pod phase == Running, then return its pod IP.

        Raises PodStartupTimeout if the pod is still not Running after
        _POD_READY_TIMEOUT_S seconds. The caller (PoolManager._create_container)
        lets this propagate — the dispatch layer catches it and emits 503
        Retry-After to the client.
        """
        deadline = time.monotonic() + _POD_READY_TIMEOUT_S
        phase: str | None = None
        while time.monotonic() < deadline:
            pod = self._core.read_namespaced_pod(name=pod_name, namespace=self._namespace)
            phase = pod.status.phase if pod.status else None
            if phase == "Running":
                pod_ip = pod.status.pod_ip or "127.0.0.1"
                logger.info("K8s backend: pod %s Running at %s", pod_name, pod_ip)
                return pod_ip
            if phase in ("Failed", "Succeeded", "Unknown"):
                raise RuntimeError(
                    "K8s pod %s reached unexpected phase %s during startup" % (pod_name, phase)
                )
            logger.debug("K8s backend: pod %s phase=%s, waiting...", pod_name, phase)
            time.sleep(_POD_POLL_INTERVAL_S)

        raise PodStartupTimeout(
            "Pod %s did not reach Running within %ds — phase still %s. "
            "Check namespace quota, image pull policy, and node scheduling. "
            "Caller should return 503 Retry-After." % (pod_name, _POD_READY_TIMEOUT_S, phase)
        )


class KubernetesPodHandle:
    """
    Handle to a K8s pod, implementing the interface expected by PoolManager.

    PoolManager calls: .id, .kill(), .remove(), .get_network_ip()
    """

    def __init__(
        self,
        name: str,
        pod_ip: str,
        port: int,
        core,  # kubernetes.client.CoreV1Api
        namespace: str,
    ) -> None:
        self._name = name
        self._pod_ip = pod_ip
        self._port = port
        self._core = core
        self._namespace = namespace

    @property
    def id(self) -> str:
        # In the K8s backend, the pod name IS the container_id.
        # It is unique within the namespace and follows the ysg-* pattern.
        return self._name

    @property
    def attrs(self) -> dict:
        return {"pod_name": self._name, "namespace": self._namespace}

    def reload(self) -> None:
        """Refresh pod IP from API (pod IP can change on reschedule, but that
        is rare for short-lived pool pods)."""
        try:
            pod = self._core.read_namespaced_pod(name=self._name, namespace=self._namespace)
            if pod.status and pod.status.pod_ip:
                self._pod_ip = pod.status.pod_ip
        except Exception as exc:
            logger.warning("K8s handle: reload failed for pod %s: %s", self._name, exc)

    def logs(self, tail: int = 500) -> bytes:
        try:
            log_str = self._core.read_namespaced_pod_log(
                name=self._name,
                namespace=self._namespace,
                tail_lines=tail,
            )
            return log_str.encode() if isinstance(log_str, str) else log_str
        except Exception as exc:
            logger.warning("K8s handle: log fetch failed for pod %s: %s", self._name, exc)
            return b""

    def diff(self) -> list:
        # K8s has no direct equivalent of `docker diff` — return empty list.
        return []

    def kill(self) -> None:
        """Delete the pod immediately (grace_period=0 for kill semantics)."""
        try:
            from kubernetes import client as k8s_client  # type: ignore[import-untyped]
            self._core.delete_namespaced_pod(
                name=self._name,
                namespace=self._namespace,
                body=k8s_client.V1DeleteOptions(grace_period_seconds=0),
            )
            logger.info("K8s backend: killed pod %s", self._name)
        except Exception as exc:
            logger.warning("K8s backend: kill failed for pod %s: %s", self._name, exc)

    def remove(self, force: bool = False) -> None:
        """Graceful delete (30s grace) — same semantic as docker rm."""
        try:
            from kubernetes import client as k8s_client  # type: ignore[import-untyped]
            grace = 0 if force else 30
            self._core.delete_namespaced_pod(
                name=self._name,
                namespace=self._namespace,
                body=k8s_client.V1DeleteOptions(grace_period_seconds=grace),
            )
            logger.info("K8s backend: removed pod %s (grace=%ds)", self._name, grace)
        except Exception as exc:
            # Pod may already be gone (teardown called twice) — log and continue.
            logger.warning("K8s backend: remove failed for pod %s: %s", self._name, exc)

    def get_network_ip(self, network_name: str) -> str:
        """
        Return the pod's cluster IP. In K8s, network_name is irrelevant —
        pods are reachable by pod IP within the same namespace.
        """
        return self._pod_ip


def create_backend() -> Optional["ContainerBackend | KubernetesBackend"]:
    """
    Auto-detect and create the best available container backend.

    Detection order:
      1. Kubernetes in-cluster (KUBERNETES_SERVICE_HOST env + service account token)
      2. Docker SDK (docker-py)
      3. Podman SDK (podman-py), then explicit Podman socket paths
      4. None — stub mode (CIAA compliance CANNOT be satisfied)

    Returns None if no backend is available (stub mode).
    """
    # Step 1: Kubernetes in-cluster detection.
    # Two conditions must both be true:
    #   a) Service account token file exists (we are running in a K8s pod)
    #   b) KUBERNETES_SERVICE_HOST is set (the API server address is injected)
    # Both must be present to avoid false-positives in dev environments where
    # the token file might exist but the API server is not reachable.
    _SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    if os.path.exists(_SA_TOKEN) and os.environ.get("KUBERNETES_SERVICE_HOST"):
        try:
            from kubernetes import config as k8s_config  # type: ignore[import-untyped]
            k8s_config.load_incluster_config()
            # Derive namespace from the projected service account namespace file
            _NS_FILE = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
            if os.path.exists(_NS_FILE):
                with open(_NS_FILE) as _f:
                    namespace = _f.read().strip()
            else:
                namespace = os.environ.get("POD_NAMESPACE", "default")
            backend = KubernetesBackend(namespace=namespace)
            if backend.ping():
                logger.info("Pool Manager: Kubernetes API backend connected (namespace=%s)", namespace)
                return backend  # type: ignore[return-value]
            logger.warning("Pool Manager: K8s backend ping failed — falling through to Docker/Podman")
        except Exception as exc:
            logger.warning("Pool Manager: K8s backend init failed: %s", exc)

    # Step 2: Docker SDK
    try:
        import docker  # type: ignore[import-untyped]
        client = docker.from_env()  # type: ignore[attr-defined]
        client.ping()
        logger.info("Pool Manager: Docker SDK connected")
        return ContainerBackend(client, "docker")
    except Exception:
        pass

    # Step 3: Podman SDK
    try:
        from podman import PodmanClient
        client = PodmanClient()
        client.ping()
        logger.info("Pool Manager: Podman SDK connected")
        return ContainerBackend(client, "podman")
    except Exception:
        pass

    # Try Podman via explicit socket paths (including mounted socket from compose)
    for sock in [
        "unix:///var/run/container.sock",  # Mounted by docker-compose.yml
        f"unix:///run/user/{_get_uid()}/podman/podman.sock",
        "unix:///run/podman/podman.sock",
        "unix:///var/run/podman/podman.sock",
        "unix:///var/run/docker.sock",  # Docker socket fallback
    ]:
        try:
            from podman import PodmanClient
            client = PodmanClient(base_url=sock)
            client.ping()
            logger.info("Pool Manager: Podman SDK connected via %s", sock)
            return ContainerBackend(client, "podman")
        except Exception:
            continue

    logger.warning(
        "Pool Manager: no Kubernetes, Docker, or Podman backend available — running in STUB MODE. "
        "Container-per-identity isolation is DISABLED and CIAA compliance cannot "
        "be satisfied. To fix on macOS with Podman: run "
        "`podman machine init --rootful && podman machine start`, then ensure "
        "docker-compose.podman-override.yml mounts /var/run/docker.sock into the "
        "gateway container. On Linux: `systemctl --user enable --now podman.socket`. "
        "In Kubernetes: ensure the gateway ServiceAccount has pods CRUD RBAC "
        "(helm/yashigani/templates/rbac-pool-manager.yaml)."
    )
    return None


def _get_uid() -> int:
    """Get current user ID for Podman rootless socket path."""
    return os.getuid()
