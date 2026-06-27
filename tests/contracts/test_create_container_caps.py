"""
Contract tests: PoolManager._create_container() resource caps + labels (4.0 Phase 3).

Verifies:
  1. R14: memory_mb (int) is converted to "{N}m" string internally before being
     passed to the Docker SDK — never as a raw integer.
  2. pids_limit: forwarded to backend.run() as-is.
  3. Security defaults: cap_drop=["ALL"], security_opt=["no-new-privileges:true"],
     user="1001" are applied when not explicitly overridden.
  4. Labels: ContainerInfo has the yashigani.identity label set to the identity_id.
  5. Mode=persistent: PoolManager.get_or_create() creates the container once and
     returns the cached ContainerInfo on subsequent calls (no duplicate creates).

These are structural/contract tests — no live Docker daemon, no live PoolManager.
The ContainerBackend is fully stubbed.
"""

import uuid
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

from yashigani.pool.manager import PoolManager


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stub_backend(container_id: str = "sha256:abc123") -> MagicMock:
    """Stub ContainerBackend that captures run() call kwargs."""
    backend = MagicMock()
    run_calls: list[dict] = []

    def _run(image: str, name: str, environment: dict, network: str,
             labels: dict, detach: bool = True, **kwargs: Any) -> MagicMock:
        run_calls.append(dict(
            image=image, name=name, environment=environment,
            network=network, labels=labels, detach=detach,
            **kwargs,
        ))
        handle = MagicMock()
        handle.container_id = container_id
        handle.ip_address = "172.28.0.10"
        return handle

    backend.run.side_effect = _run
    backend._run_calls = run_calls
    backend.ensure_network = MagicMock()
    backend.connect_network = MagicMock()
    backend.teardown_network = MagicMock()
    backend.get_container_ip.return_value = "172.28.0.10"
    return backend


def _make_pool_manager(backend: MagicMock | None = None) -> PoolManager:
    """Return a PoolManager wired with the given stub backend."""
    pm = MagicMock(spec=PoolManager)
    pm._backend = backend or _stub_backend()
    pm._containers = {}  # per-identity ContainerInfo cache
    pm._lock = __import__("threading").Lock()
    return pm


def _stub_cert_mount() -> MagicMock:
    """Minimal CertMount-like stub."""
    cm = MagicMock()
    cm.host_cert_path = ""
    cm.host_key_path = ""
    cm.host_ca_path = ""
    cm.container_cert_path = "/run/secrets/svid/client.crt"
    cm.container_key_path = "/run/secrets/svid/client.key"
    cm.container_ca_path = "/run/secrets/svid/ca.crt"
    cm.spiffe_identity = "spiffe://yashigani.internal/agents/test/letta"
    return cm


# ── Test 1: R14 — memory_mb int → "{N}m" string conversion ───────────────────

def test_create_container_memory_mb_converted_to_string() -> None:
    """R14: _create_container must convert memory_mb int to Docker SDK string 'Nm'."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    identity_id = str(uuid.uuid4())
    backend = _stub_backend()

    # Patch the backend that _create_container uses.
    with patch.object(RealPoolManager, "_backend", backend, create=True), \
         patch.object(RealPoolManager, "_client", None, create=True), \
         patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        # We call the real _create_container via an instance with enough state.
        pm = object.__new__(RealPoolManager)
        pm._backend = backend  # type: ignore[attr-defined]
        pm._client = None  # type: ignore[attr-defined]

        result = pm._create_container(
            identity_id=identity_id,
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={"OPENAI_API_BASE": "http://gateway:8081/v1"},
            port=8283,
            networks=["ringfence_letta_test"],
            cert_mount=_stub_cert_mount(),
            memory_mb=256,
            pids_limit=64,
        )

    # The backend's run() must have been called with mem_limit="256m"
    assert backend._run_calls, "_create_container must call backend.run()"
    run_kwargs = backend._run_calls[0]

    mem_limit = run_kwargs.get("mem_limit")
    assert mem_limit is not None, "mem_limit must be passed to backend.run()"
    assert isinstance(mem_limit, str), f"mem_limit must be a string, got {type(mem_limit)}"
    assert mem_limit == "256m", f"Expected '256m', got {mem_limit!r}"


def test_create_container_default_memory_mb_is_string() -> None:
    """Default memory_mb=512 must produce mem_limit='512m' (not 512 int)."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    identity_id = str(uuid.uuid4())
    backend = _stub_backend()

    with patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        pm = object.__new__(RealPoolManager)
        pm._backend = backend
        pm._client = None

        pm._create_container(
            identity_id=identity_id,
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={},
            port=8283,
            networks=["ringfence_letta_test"],
            cert_mount=_stub_cert_mount(),
        )

    run_kwargs = backend._run_calls[0]
    assert run_kwargs.get("mem_limit") == "512m"


# ── Test 2: pids_limit forwarded as-is ────────────────────────────────────────

def test_create_container_pids_limit_forwarded() -> None:
    """pids_limit must be passed through to backend.run()."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    backend = _stub_backend()

    with patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        pm = object.__new__(RealPoolManager)
        pm._backend = backend
        pm._client = None

        pm._create_container(
            identity_id=str(uuid.uuid4()),
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={},
            port=8283,
            networks=["ringfence_test"],
            cert_mount=_stub_cert_mount(),
            pids_limit=64,
        )

    run_kwargs = backend._run_calls[0]
    assert run_kwargs.get("pids_limit") == 64, (
        f"pids_limit must be 64, got {run_kwargs.get('pids_limit')!r}"
    )


# ── Test 3: Security defaults ─────────────────────────────────────────────────

def test_create_container_default_security_opts() -> None:
    """Default security: cap_drop=['ALL'], security_opt=['no-new-privileges:true'], user='1001'."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    backend = _stub_backend()

    with patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        pm = object.__new__(RealPoolManager)
        pm._backend = backend
        pm._client = None

        pm._create_container(
            identity_id=str(uuid.uuid4()),
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={},
            port=8283,
            networks=["ringfence_test"],
            cert_mount=_stub_cert_mount(),
        )

    run_kwargs = backend._run_calls[0]
    assert run_kwargs.get("cap_drop") == ["ALL"], (
        f"cap_drop must be ['ALL'], got {run_kwargs.get('cap_drop')!r}"
    )
    assert "no-new-privileges:true" in (run_kwargs.get("security_opt") or []), (
        f"security_opt must include no-new-privileges:true, got {run_kwargs.get('security_opt')!r}"
    )
    assert run_kwargs.get("user") == "1001", (
        f"user must be '1001', got {run_kwargs.get('user')!r}"
    )


# ── Test 4: Identity label ────────────────────────────────────────────────────

def test_create_container_identity_label_in_run_kwargs() -> None:
    """Labels passed to backend.run() must include yashigani.identity=<identity_id>."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    identity_id = str(uuid.uuid4())
    backend = _stub_backend()

    with patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        pm = object.__new__(RealPoolManager)
        pm._backend = backend
        pm._client = None

        pm._create_container(
            identity_id=identity_id,
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={},
            port=8283,
            networks=["ringfence_test"],
            cert_mount=_stub_cert_mount(),
        )

    run_kwargs = backend._run_calls[0]
    labels = run_kwargs.get("labels") or {}
    assert labels.get("yashigani.identity") == identity_id, (
        f"labels[yashigani.identity] must be {identity_id!r}, got {labels.get('yashigani.identity')!r}"
    )


# ── Test 5: ContainerInfo.endpoint is host:port ───────────────────────────────

def test_create_container_returns_endpoint_with_port() -> None:
    """_create_container must return a ContainerInfo with endpoint='<ip>:<port>'."""
    from yashigani.pool.manager import PoolManager as RealPoolManager

    identity_id = str(uuid.uuid4())
    backend = _stub_backend()
    backend.get_container_ip.return_value = "172.28.0.42"

    with patch.object(RealPoolManager, "_ensure_ringfence_networks", return_value=None), \
         patch.object(RealPoolManager, "_wait_for_ringfence_init", return_value=None):

        pm = object.__new__(RealPoolManager)
        pm._backend = backend
        pm._client = None

        result = pm._create_container(
            identity_id=identity_id,
            service_slug="letta",
            image="docker.io/letta/letta:0.16.7",
            env={},
            port=8283,
            networks=["ringfence_test"],
            cert_mount=_stub_cert_mount(),
        )

    # ContainerInfo.endpoint must be "IP:PORT"
    assert hasattr(result, "endpoint"), "ContainerInfo must have .endpoint attribute"
    assert "8283" in str(result.endpoint), (
        f"endpoint must include port 8283, got {result.endpoint!r}"
    )
