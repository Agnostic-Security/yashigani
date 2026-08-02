"""
YTF Tier-C — live, per-deployment integration/data-flow/chaos/parity suite.

Covers the 6 categories NOT already exercised by the pre-existing
src/tests/e2e/ suite (lifecycle self-heal chaos + real agent-dispatch/budget
data-path, which Tier-C ABSORBS rather than duplicates — see tests/MATRIX.yaml
tier_c.paths):
  cross_runtime_parity, egress_ringfence_injection,
  audit_observability_integrity, dataplane_byte_proof, multitenant_licensing,
  and the NAMED cache/store-divergence half of data_flow_seam (112/128/131
  class — a value written on one datastore, read back via a genuinely
  DIFFERENT read/verify path, not the same object handed back to itself).

Every test in this package MUST skip cleanly (not error) when no stack is
reachable — this package runs via `scripts/run-test-framework.sh --tier c
--target <url> ...` against a LIVE deployment; it is never part of Tier-A.

Status (2026-07-29, authored per Iris/YTF dispatch, "author now — no live
run — no stack"): this is a REAL, runnable scaffold, not placeholder text —
every test below issues real HTTP calls / real container introspection and
will PASS OR FAIL honestly the first time it is pointed at a live target. It
is a scaffold in the sense that per-category DEPTH (more scenarios per
category) is expected to grow as each leg is actually exercised live; it is
NOT a scaffold in the sense of "TODO: write test" stubs — there are none.
"""
import os as _ytf_os

# FIND-YTF412-009: container names were hardcoded to the compose project
# "docker" (e.g. f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1"), but install.sh DERIVES the project from
# --domain (documented multi-instance behaviour), and podman-compose separates
# with "_" where docker compose uses "-". A whole tier therefore reported
# per-test product failures while never finding a single container to act on --
# 23 failed / 11 passed in 2m00s with the stack untouched at 26/26 up.
_YTF_PROJ = _ytf_os.getenv("YTF_COMPOSE_PROJECT", "docker")
_YTF_SEP = _ytf_os.getenv("YTF_NAME_SEP", "-")
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import httpx
import pytest

REPO_ROOT = Path(__file__).parents[2]


def _resolve_ca_cert() -> Optional[str]:
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    for p in (REPO_ROOT / "docker" / "secrets" / "ca_root.crt", Path("/run/secrets/ca_root.crt")):
        if p.exists():
            return str(p)
    return None


_CA_CERT_PATH = _resolve_ca_cert()
BASE_URL = os.getenv("YASHIGANI_ADMIN_URL", "https://localhost:8443")
YTF_RUNTIME = os.getenv("YTF_RUNTIME", "unknown")
YTF_PLATFORM = os.getenv("YTF_PLATFORM", "unknown")
YTF_VERSION = os.getenv("YTF_VERSION", "unknown")


def _stack_running() -> bool:
    verify: bool | str = _CA_CERT_PATH if BASE_URL.startswith("https://") else False  # type: ignore[assignment]
    try:
        r = httpx.get(f"{BASE_URL}/healthz", verify=verify, timeout=3)
        return r.status_code == 200
    except Exception:
        return False


STACK_RUNNING = _stack_running()

SKIP_NO_STACK = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="No live Yashigani stack reachable at YASHIGANI_ADMIN_URL — Tier-C requires --target",
)


def http_client(**kw) -> httpx.Client:
    verify: bool | str = _CA_CERT_PATH if BASE_URL.startswith("https://") else False  # type: ignore[assignment]
    return httpx.Client(base_url=BASE_URL, verify=verify, timeout=10, **kw)


def _detect_runtime_binary() -> str:
    env = os.getenv("YASHIGANI_RUNTIME", "").lower()
    if env in ("podman", "docker"):
        return env
    if shutil.which("podman"):
        try:
            r = subprocess.run(["podman", "ps", "--format", "{{.Names}}"],
                                capture_output=True, text=True, timeout=5)
            if f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1" in r.stdout:
                return "podman"
        except Exception:
            pass
    return "docker"


def container_exec(container: str, cmd: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    """Run `cmd` inside `container` via the detected runtime binary (docker/
    podman) or `kubectl exec` when YTF_RUNTIME == k8s. Mirrors
    src/tests/e2e/conftest.py's runtime_run() helper pattern."""
    if YTF_RUNTIME == "k8s":
        full = ["kubectl", "exec", container, "--"] + cmd
    else:
        binary = _detect_runtime_binary()
        full = [binary, "exec", container] + cmd
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout)
