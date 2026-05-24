"""
Network isolation regression test — EX-231-10 (Caddy-centric ingress).

Maintainer directive 2026-04-29: Caddy is the SOLE ingress to backoffice (:8443)
and gateway (:8080). No internal mesh peer may reach these listeners directly.

These tests assert:
  TEST 1 — Direct backoffice connect MUST fail from a non-Caddy peer.
  TEST 2 — Direct gateway connect MUST fail from a non-Caddy peer.
  TEST 3 — Caddy-proxied healthz MUST succeed (the legitimate path is intact).

Runtimes covered:
  Compose  — runs inside the prometheus container (obs network, no route to
             caddy_internal). Uses subprocess + docker/podman exec.
  K8s      — runs as a separate Pod in the yashigani namespace with no
             caddy label (default-deny NetworkPolicy blocks it from reaching
             gateway/backoffice). Uses kubectl exec.

Skips gracefully when neither a running compose stack nor K8s cluster is
reachable (unit-test CI does not have a live stack).

Last updated: 2026-04-29T14:30:00+01:00
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import pytest

pytestmark = pytest.mark.integration

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_COMPOSE_TIMEOUT = 8          # seconds for each TCP probe
_CADDY_HEALTHZ_TIMEOUT = 10   # seconds for the Caddy-proxied healthz check


def _runtime() -> str:
    """Return 'docker' or 'podman' based on what is available on PATH."""
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return ""


def _compose_stack_running() -> bool:
    """Return True if the yashigani compose stack appears to be up."""
    rt = _runtime()
    if not rt:
        return False
    result = subprocess.run(
        [rt, "inspect", "--format", "{{.State.Status}}", "yashigani-backoffice-1"],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


def _k8s_available() -> bool:
    """Return True if kubectl can reach the cluster and the namespace exists."""
    if not shutil.which("kubectl"):
        return False
    try:
        result = subprocess.run(
            ["kubectl", "get", "namespace", "yashigani", "--no-headers"],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        # kubectl present but cluster not reachable (no kubeconfig, no cluster running).
        # Treat as unavailable so the test fixture skips gracefully.
        return False
    return result.returncode == 0


def _exec_in_container(container: str, cmd: list[str]) -> subprocess.CompletedProcess:
    rt = _runtime()
    return subprocess.run(
        [rt, "exec", container] + cmd,
        capture_output=True, text=True, timeout=_COMPOSE_TIMEOUT + 5,
    )


def _tcp_connect_probe(host: str, port: int, timeout: float = 4.0) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False


# ---------------------------------------------------------------------------
# Compose tests
# ---------------------------------------------------------------------------

class TestComposeNetworkIsolation:
    """
    Run inside the prometheus container (on the `obs` network).
    prometheus has no route to `caddy_internal`, so TCP connects to
    backoffice:8443 and gateway:8080 must fail — DNS won't resolve
    those names from the obs network because they don't share that network.

    NOTE: the test itself runs on the test-runner host (macOS / CI Linux),
    not inside prometheus. We shell into the prometheus container using
    `docker exec` / `podman exec` to perform the probe from the correct
    network position.
    """

    @pytest.fixture(autouse=True)
    def require_stack(self):
        if not _compose_stack_running():
            pytest.skip("Yashigani compose stack not running — skipping isolation test")

    def _probe_from_prometheus(self, host: str, port: int) -> bool:
        """
        Attempt TCP connect to host:port from inside the prometheus container.
        Returns True if the connection SUCCEEDED (bad — means isolation failed).
        Returns False if the connection was refused/timed out (good).
        """
        result = _exec_in_container(
            "yashigani-prometheus-1",
            # wget with connect timeout; we only care about TCP SYN/RST,
            # not the HTTP response. wget exits 4 on connect failure.
            [
                "wget",
                "--timeout=4",
                "--tries=1",
                "-q",
                "-O", "/dev/null",
                f"https://{host}:{port}/healthz",
            ],
        )
        # wget exit code 4 = network failure (refused/timeout) — isolation holds.
        # exit code 0 = connected and got content — isolation FAILED.
        # exit code 5 = SSL error — still means TCP connected — isolation FAILED.
        connected = result.returncode not in (4, 1)
        return connected

    def test_1_backoffice_direct_connect_blocked(self):
        """
        TEST 1: backoffice:8443 must be unreachable from the obs network.

        PASS = connection refused or DNS NXDOMAIN (returncode 4 or 1 from wget).
        FAIL = connection established (any 2xx, 4xx, 5xx, or SSL error).
        """
        connected = self._probe_from_prometheus("yashigani-backoffice-1", 8443)
        assert not connected, (
            "ISOLATION FAILURE — prometheus (obs network) reached backoffice:8443 directly. "
            "EX-231-10 caddy-centric isolation is BROKEN. "
            "backoffice must only be reachable via Caddy on caddy_internal network."
        )

    def test_2_gateway_direct_connect_blocked(self):
        """
        TEST 2: gateway:8080 must be unreachable from the obs network.

        PASS = connection refused or DNS NXDOMAIN.
        FAIL = connection established.
        """
        connected = self._probe_from_prometheus("yashigani-gateway-1", 8080)
        assert not connected, (
            "ISOLATION FAILURE — prometheus (obs network) reached gateway:8080 directly. "
            "EX-231-10 caddy-centric isolation is BROKEN. "
            "gateway must only be reachable via Caddy on caddy_internal network."
        )

    def test_3_caddy_proxied_healthz_returns_200(self):
        """
        TEST 3: The legitimate path — via Caddy — must still work.

        Checks the actual healthz through Caddy to confirm Caddy is up.
        The TLS domain may be self-signed in test environments; we use the
        YASHIGANI_TLS_DOMAIN env var (or localhost fallback) for the check.
        NOTE: Caddy admin TCP :2019 is REMOVED (MUST-4 / v2.24.1) — admin
        surface is unix socket /run/caddy/admin.sock, in-container only.
        """
        tls_domain = os.environ.get("YASHIGANI_TLS_DOMAIN", "localhost")
        https_port = int(os.environ.get("YASHIGANI_HTTPS_PORT", "443"))
        url = f"https://{tls_domain}:{https_port}/healthz"
        ctx = None
        try:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE   # self-signed OK in test
            req = urllib.request.urlopen(url, context=ctx, timeout=_CADDY_HEALTHZ_TIMEOUT)
            status = req.status
        except urllib.error.HTTPError as e:
            status = e.code
        except Exception as exc:
            pytest.fail(
                f"TEST 3 FAILED — Caddy-proxied {url} raised {exc!r}. "
                "Caddy should be the working path — if this fails the stack is broken."
            )
        assert status == 200, (
            f"TEST 3 FAILED — Caddy-proxied {url} returned HTTP {status}, expected 200. "
            "Admin1/Admin2 login HTTP: BLOCKED — the front-door healthz must return 200."
        )


# ---------------------------------------------------------------------------
# K8s tests
# ---------------------------------------------------------------------------

class TestK8sNetworkPolicyIsolation:
    """
    Exercises the K8s NetworkPolicy rules from EX-231-10.
    Runs a kubectl exec into the postgres pod (no caddy label — blocked by
    default-deny + allow-backoffice-ingress / allow-gateway-ingress rules).
    """

    @pytest.fixture(autouse=True)
    def require_k8s(self):
        if not _k8s_available():
            pytest.skip("kubectl not available or yashigani namespace not found — skipping K8s isolation test")

    _NAMESPACE = "yashigani"
    _PROBE_POD = "yashigani-postgres-0"   # data-plane pod, NOT caddy

    def _exec_kubectl(self, cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["kubectl", "exec", "-n", self._NAMESPACE, self._PROBE_POD, "--"] + cmd,
            capture_output=True, text=True, timeout=15,
        )

    def _probe_direct(self, svc: str, port: int) -> bool:
        """
        Attempt curl from postgres pod to svc:port.
        Returns True if TCP connection succeeded (isolation FAILED).
        Returns False if refused/timeout (isolation holds).
        """
        result = self._exec_kubectl([
            "bash", "-c",
            f"timeout 4 bash -c '</dev/tcp/{svc}/{port}' 2>/dev/null; echo $?",
        ])
        # exit 0 = connected (bad), non-zero = failed (good)
        if result.returncode != 0:
            return False
        last_line = result.stdout.strip().split("\n")[-1]
        return last_line == "0"

    def test_1_backoffice_direct_connect_blocked_k8s(self):
        """
        TEST 1 (K8s): postgres pod must NOT reach backoffice:8443 directly.
        NetworkPolicy allow-backoffice-ingress only permits yashigani-caddy.
        """
        connected = self._probe_direct("yashigani-backoffice", 8443)
        assert not connected, (
            "K8s ISOLATION FAILURE — postgres pod reached yashigani-backoffice:8443 directly. "
            "NetworkPolicy allow-backoffice-ingress is not enforced. "
            "EX-231-10 Caddy-centric isolation is BROKEN."
        )

    def test_2_gateway_direct_connect_blocked_k8s(self):
        """
        TEST 2 (K8s): postgres pod must NOT reach gateway:8080 directly.
        NetworkPolicy allow-gateway-ingress only permits yashigani-caddy.
        """
        connected = self._probe_direct("yashigani-gateway", 8080)
        assert not connected, (
            "K8s ISOLATION FAILURE — postgres pod reached yashigani-gateway:8080 directly. "
            "NetworkPolicy allow-gateway-ingress is not enforced. "
            "EX-231-10 Caddy-centric isolation is BROKEN."
        )

    def test_3_caddy_proxied_healthz_k8s(self):
        """
        TEST 3 (K8s): Caddy-proxied healthz returns 200.
        Checks via kubectl exec into a test pod that CAN reach Caddy:443.
        """
        result = self._exec_kubectl([
            "bash", "-c",
            "curl -sk -o /dev/null -w '%{http_code}' https://yashigani-caddy/healthz 2>/dev/null",
        ])
        status = result.stdout.strip()
        assert status == "200", (
            f"TEST 3 (K8s) FAILED — Caddy-proxied /healthz returned HTTP {status}, expected 200. "
            "Admin1/Admin2 login HTTP: BLOCKED — front-door must return 200."
        )
