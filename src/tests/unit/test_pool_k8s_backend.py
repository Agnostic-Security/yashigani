"""
Unit tests — KubernetesBackend and create_backend() K8s detection path.

Coverage:
  1. KubernetesBackend.run() creates pod, waits for Running, returns handle.
  2. KubernetesBackend._wait_for_running() raises PodStartupTimeout when pod
     stays Pending beyond the timeout.
  3. KubernetesBackend._wait_for_running() raises RuntimeError when pod reaches
     Failed phase.
  4. KubernetesPodHandle.id returns pod name.
  5. KubernetesPodHandle.kill() calls delete_namespaced_pod with grace_period=0.
  6. KubernetesPodHandle.remove(force=False) calls delete with grace_period=30.
  7. KubernetesPodHandle.get_network_ip() returns pod_ip regardless of network_name.
  8. KubernetesPodHandle.logs() returns encoded bytes.
  9. create_backend() returns KubernetesBackend when in-cluster env + SA token present.
  10. create_backend() skips K8s and falls through to Docker when SA token absent.
  11. create_backend() falls through when K8s backend ping() fails.
  12. PoolManager._create_container() calls KubernetesBackend.run() without network param.
"""
from __future__ import annotations

import os
import sys
import time
import types
from dataclasses import dataclass
from unittest.mock import MagicMock, patch, mock_open

import pytest


# ---------------------------------------------------------------------------
# Helpers — minimal kubernetes.client stub so tests run without the real SDK
# ---------------------------------------------------------------------------


def _build_k8s_stub():
    """Return a minimal stub for the `kubernetes` package."""
    k8s = types.ModuleType("kubernetes")
    client_mod = types.ModuleType("kubernetes.client")
    config_mod = types.ModuleType("kubernetes.config")

    # Stub objects that match the real API surface used by KubernetesBackend
    class V1ObjectMeta:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1Pod:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1PodSpec:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1Container:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1ContainerPort:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1SecurityContext:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1Capabilities:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1DeleteOptions:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class V1EnvVar:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    for cls in [
        V1ObjectMeta, V1Pod, V1PodSpec, V1Container, V1ContainerPort,
        V1SecurityContext, V1Capabilities, V1DeleteOptions, V1EnvVar,
    ]:
        setattr(client_mod, cls.__name__, cls)

    # CoreV1Api stub — all methods are replaced per-test with MagicMock
    class CoreV1Api:
        def create_namespaced_pod(self, namespace, body):
            pass

        def read_namespaced_pod(self, name, namespace):
            pass

        def delete_namespaced_pod(self, name, namespace, body=None):
            pass

        def list_namespaced_pod(self, namespace, limit=None):
            pass

        def read_namespaced_pod_log(self, name, namespace, tail_lines=None):
            return ""

    client_mod.CoreV1Api = CoreV1Api

    def load_incluster_config():
        pass

    config_mod.load_incluster_config = load_incluster_config

    k8s.client = client_mod
    k8s.config = config_mod

    sys.modules.setdefault("kubernetes", k8s)
    sys.modules.setdefault("kubernetes.client", client_mod)
    sys.modules.setdefault("kubernetes.config", config_mod)
    return k8s, client_mod, config_mod


# Install stubs before importing pool.backend
_build_k8s_stub()


from yashigani.pool.backend import (  # noqa: E402
    KubernetesBackend,
    KubernetesPodHandle,
    PodStartupTimeout,
    create_backend,
)
from yashigani.pool.manager import PoolManager  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_pod_status(phase: str, pod_ip: str = "10.0.0.5"):
    """Build a minimal pod object matching the fields read by _wait_for_running."""
    pod = MagicMock()
    pod.status = MagicMock()
    pod.status.phase = phase
    pod.status.pod_ip = pod_ip
    return pod


def _make_core_api(phases: list, pod_ip: str = "10.0.0.5") -> MagicMock:
    """
    Return a MagicMock CoreV1Api whose read_namespaced_pod() cycles through
    the given phases on successive calls.
    """
    api = MagicMock()
    side_effects = [_make_pod_status(phase, pod_ip) for phase in phases]
    api.read_namespaced_pod.side_effect = side_effects
    return api


# ---------------------------------------------------------------------------
# Test 1: run() creates pod and returns handle on Running
# ---------------------------------------------------------------------------

class TestKubernetesBackendRun:
    def test_run_creates_pod_and_returns_handle(self):
        """run() calls create_namespaced_pod + waits for Running + returns handle."""
        api = _make_core_api(["Pending", "Running"])
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch.object(backend, "_wait_for_running", return_value="10.0.0.5") as mock_wait:
            handle = backend.run(
                image="ghcr.io/myco/goose:latest",
                name="ysg-goose-abcd12-001abc",
                environment={"FOO": "bar"},
                labels={"yashigani.managed": "true"},
                port=8080,
            )

        api.create_namespaced_pod.assert_called_once()
        mock_wait.assert_called_once_with("ysg-goose-abcd12-001abc")
        assert isinstance(handle, KubernetesPodHandle)
        assert handle.id == "ysg-goose-abcd12-001abc"
        assert handle._pod_ip == "10.0.0.5"

    def test_run_env_vars_are_passed(self):
        """Environment dict is converted to V1EnvVar objects."""
        api = MagicMock()
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch.object(backend, "_wait_for_running", return_value="10.0.0.1"):
            backend.run(
                image="img",
                name="pod-name",
                environment={"KEY": "val", "NUM": "42"},
                labels={},
                port=8080,
            )

        call_body = api.create_namespaced_pod.call_args.kwargs["body"]
        env_names = {e.name for e in call_body.spec.containers[0].env}
        assert "KEY" in env_names
        assert "NUM" in env_names


# ---------------------------------------------------------------------------
# Test 2: _wait_for_running raises PodStartupTimeout
# ---------------------------------------------------------------------------

class TestWaitForRunning:
    def test_timeout_raises_pod_startup_timeout(self):
        """Pod stuck in Pending past timeout window raises PodStartupTimeout."""
        api = MagicMock()
        api.read_namespaced_pod.return_value = _make_pod_status("Pending")
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch("yashigani.pool.backend._POD_READY_TIMEOUT_S", 0):
            with pytest.raises(PodStartupTimeout):
                backend._wait_for_running("ysg-test-pod")

    def test_running_returns_ip(self):
        """Running pod immediately returns pod IP."""
        api = _make_core_api(["Running"], pod_ip="192.168.1.50")
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch("yashigani.pool.backend._POD_POLL_INTERVAL_S", 0):
            ip = backend._wait_for_running("ysg-running-pod")

        assert ip == "192.168.1.50"

    def test_failed_phase_raises_runtime_error(self):
        """Pod reaching Failed phase raises RuntimeError (not PodStartupTimeout)."""
        api = _make_core_api(["Failed"])
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch("yashigani.pool.backend._POD_POLL_INTERVAL_S", 0):
            with pytest.raises(RuntimeError, match="unexpected phase"):
                backend._wait_for_running("ysg-failed-pod")

    def test_pending_then_running(self):
        """Backend waits through Pending then succeeds on Running."""
        api = _make_core_api(["Pending", "Pending", "Running"], pod_ip="10.1.2.3")
        backend = KubernetesBackend.__new__(KubernetesBackend)
        backend._namespace = "yashigani"
        backend._core = api

        with patch("yashigani.pool.backend._POD_READY_TIMEOUT_S", 60):
            with patch("yashigani.pool.backend._POD_POLL_INTERVAL_S", 0):
                ip = backend._wait_for_running("ysg-slow-pod")

        assert ip == "10.1.2.3"
        assert api.read_namespaced_pod.call_count == 3


# ---------------------------------------------------------------------------
# Test 4-8: KubernetesPodHandle interface
# ---------------------------------------------------------------------------

class TestKubernetesPodHandle:
    def _handle(self, pod_ip: str = "10.0.0.1") -> KubernetesPodHandle:
        return KubernetesPodHandle(
            name="ysg-goose-abc-001",
            pod_ip=pod_ip,
            port=8080,
            core=MagicMock(),
            namespace="yashigani",
        )

    def test_id_returns_pod_name(self):
        h = self._handle()
        assert h.id == "ysg-goose-abc-001"

    def test_kill_uses_grace_period_zero(self):
        h = self._handle()
        h.kill()
        call_kwargs = h._core.delete_namespaced_pod.call_args.kwargs
        assert call_kwargs["name"] == "ysg-goose-abc-001"
        assert call_kwargs["namespace"] == "yashigani"
        assert call_kwargs["body"].grace_period_seconds == 0

    def test_remove_force_false_uses_grace_30(self):
        h = self._handle()
        h.remove(force=False)
        call_kwargs = h._core.delete_namespaced_pod.call_args.kwargs
        assert call_kwargs["body"].grace_period_seconds == 30

    def test_remove_force_true_uses_grace_zero(self):
        h = self._handle()
        h.remove(force=True)
        call_kwargs = h._core.delete_namespaced_pod.call_args.kwargs
        assert call_kwargs["body"].grace_period_seconds == 0

    def test_get_network_ip_returns_pod_ip(self):
        h = self._handle(pod_ip="172.16.0.99")
        # network_name is irrelevant for K8s — always returns pod IP
        assert h.get_network_ip("docker_internal") == "172.16.0.99"
        assert h.get_network_ip("any_network") == "172.16.0.99"

    def test_logs_returns_bytes(self):
        h = self._handle()
        h._core.read_namespaced_pod_log.return_value = "line1\nline2\n"
        result = h.logs(tail=50)
        assert isinstance(result, bytes)
        assert b"line1" in result

    def test_logs_returns_empty_on_error(self):
        h = self._handle()
        h._core.read_namespaced_pod_log.side_effect = RuntimeError("API error")
        result = h.logs()
        assert result == b""

    def test_diff_returns_empty_list(self):
        h = self._handle()
        assert h.diff() == []

    def test_reload_updates_pod_ip(self):
        h = self._handle(pod_ip="10.0.0.1")
        refreshed_pod = MagicMock()
        refreshed_pod.status.pod_ip = "10.0.0.99"
        h._core.read_namespaced_pod.return_value = refreshed_pod
        h.reload()
        assert h._pod_ip == "10.0.0.99"


# ---------------------------------------------------------------------------
# Test 9: create_backend() K8s detection
# ---------------------------------------------------------------------------

class TestCreateBackendK8sDetection:
    def test_returns_k8s_backend_when_in_cluster(self, tmp_path):
        """create_backend() returns KubernetesBackend when SA token + K8s env present."""
        token_file = tmp_path / "token"
        token_file.write_text("fake-token")
        ns_file = tmp_path / "namespace"
        ns_file.write_text("yashigani")

        env = {
            "KUBERNETES_SERVICE_HOST": "10.96.0.1",
        }

        with patch.dict(os.environ, env, clear=False):
            with patch("os.path.exists", side_effect=lambda p: str(p) == str(token_file) or p == str(token_file)):
                # Patch the constant paths used in create_backend
                with patch("yashigani.pool.backend.os.path.exists", side_effect=lambda p: (
                    p == "/var/run/secrets/kubernetes.io/serviceaccount/token"
                )):
                    with patch("kubernetes.config.load_incluster_config"):
                        mock_backend = MagicMock(spec=KubernetesBackend)
                        mock_backend.name = "kubernetes"
                        mock_backend.ping.return_value = True
                        with patch("yashigani.pool.backend.KubernetesBackend", return_value=mock_backend):
                            with patch("builtins.open", mock_open(read_data="yashigani")):
                                result = create_backend()

        assert result is mock_backend

    def test_skips_k8s_when_no_sa_token(self):
        """create_backend() skips K8s when service account token file absent."""
        with patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.96.0.1"}, clear=False):
            with patch("yashigani.pool.backend.os.path.exists", return_value=False):
                # No Docker or Podman available either — should end up None
                with patch("yashigani.pool.backend.KubernetesBackend") as mock_k8s_cls:
                    # Docker and Podman imports fail → stub mode (None)
                    with patch.dict("sys.modules", {"docker": None, "podman": None}):
                        result = create_backend()

        mock_k8s_cls.assert_not_called()
        assert result is None

    def test_falls_through_on_k8s_ping_failure(self):
        """If K8s backend ping() fails, create_backend() tries Docker/Podman."""
        with patch.dict(os.environ, {"KUBERNETES_SERVICE_HOST": "10.96.0.1"}, clear=False):
            with patch("yashigani.pool.backend.os.path.exists", return_value=True):
                with patch("kubernetes.config.load_incluster_config"):
                    mock_backend = MagicMock(spec=KubernetesBackend)
                    mock_backend.name = "kubernetes"
                    mock_backend.ping.return_value = False  # ping fails
                    with patch("yashigani.pool.backend.KubernetesBackend", return_value=mock_backend):
                        with patch("builtins.open", mock_open(read_data="yashigani")):
                            # Docker available as fallback
                            mock_docker_client = MagicMock()
                            mock_docker_module = MagicMock()
                            mock_docker_module.from_env.return_value = mock_docker_client
                            with patch.dict("sys.modules", {"docker": mock_docker_module}):
                                result = create_backend()

        # Should have fallen through to Docker backend (or None)
        # The key assertion is that the K8s backend was NOT returned
        assert result is None or getattr(result, "name", None) != "kubernetes"


# ---------------------------------------------------------------------------
# Test 12: PoolManager uses KubernetesBackend correctly
# ---------------------------------------------------------------------------

class TestPoolManagerWithK8sBackend:
    def test_create_container_calls_k8s_run_without_network(self):
        """
        PoolManager._create_container() detects KubernetesBackend.name == 'kubernetes'
        and calls run() without the `network` parameter.
        """
        mock_handle = MagicMock()
        mock_handle.id = "ysg-goose-test-abc123"
        mock_handle.get_network_ip.return_value = "10.0.0.5"

        mock_backend = MagicMock(spec=KubernetesBackend)
        mock_backend.name = "kubernetes"
        mock_backend.run.return_value = mock_handle

        pool = PoolManager(
            backend=mock_backend,
            network_name="docker_internal",
            tier="community",
            idle_timeout_seconds=60,
        )

        info = pool.get_or_create("user1", "goose", "ghcr.io/myco/goose:latest")

        # run() must be called with image, name, environment, labels, port
        # but WITHOUT the network keyword
        call_kwargs = mock_backend.run.call_args.kwargs
        assert "network" not in call_kwargs
        assert "image" in call_kwargs
        assert "name" in call_kwargs
        assert "labels" in call_kwargs
        assert call_kwargs["labels"]["yashigani.managed"] == "true"
        assert call_kwargs["labels"]["yashigani.identity"] == "user1"
        assert call_kwargs["labels"]["yashigani.service"] == "goose"

        assert info.endpoint == "10.0.0.5:8080"
        assert info.identity_id == "user1"

    def test_create_container_docker_backend_still_gets_network(self):
        """
        PoolManager._create_container() passes `network` to Docker/Podman backends.
        Regression test: K8s path must NOT affect Docker/Podman path.
        """
        mock_handle = MagicMock()
        mock_handle.id = "docker-abc123"
        mock_handle.get_network_ip.return_value = "172.17.0.5"

        from yashigani.pool.backend import ContainerBackend
        mock_backend = MagicMock(spec=ContainerBackend)
        mock_backend.name = "docker"
        mock_backend.run.return_value = mock_handle

        pool = PoolManager(
            backend=mock_backend,
            network_name="docker_internal",
            tier="community",
            idle_timeout_seconds=60,
        )

        pool.get_or_create("user2", "goose", "img:latest")

        call_kwargs = mock_backend.run.call_args.kwargs
        assert "network" in call_kwargs
        assert call_kwargs["network"] == "docker_internal"
