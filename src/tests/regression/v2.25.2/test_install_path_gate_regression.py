"""
Regression gate: v2.25.2 install-path fixes (found by the §4.5 clean-slate validation).

Each of these guarded a real install bug that had ZERO automated coverage — they would
silently regress without this gate. Static guards over install.sh / the wazuh overlay:
cheap, local, no infra. The behavioural counterpart is scripts/test_install_clean_slate.sh.

Fix references:
  - digest-strip drops overlays  (wazuh-security-init never created → SIEM chain stalls)
  - wazuh-mtls re-run idempotency (prior run chowns the dir to the container UID)
  - contaminated-volume check project-aware (COMPOSE_PROJECT_NAME; seeds 2.26 multi-instance)
  - convergence gate too tight    (full fresh install needs >180s to converge while healthy)
  - wazuh overlay is a clean DELTA (no duplicate security_opt → no merge break) + has the
    security-init sidecar + the indexer-cert SAN guard.

v2.25.2 / clean-slate validation — 2026-06-01.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[4]
INSTALL_SH = _ROOT / "install.sh"
WAZUH_OVERLAY = _ROOT / "docker" / "docker-compose.wazuh.yml"


@pytest.fixture(scope="module")
def install_sh() -> str:
    assert INSTALL_SH.is_file(), f"install.sh not found at {INSTALL_SH}"
    return INSTALL_SH.read_text()


@pytest.fixture(scope="module")
def overlay() -> str:
    assert WAZUH_OVERLAY.is_file(), f"wazuh overlay not found at {WAZUH_OVERLAY}"
    return WAZUH_OVERLAY.read_text()


def test_contaminated_volume_check_is_project_aware(install_sh: str) -> None:
    """The check must scope to COMPOSE_PROJECT_NAME, not a hardcoded 'docker' prefix —
    else a parallel/renamed-project install false-positives on another project's volumes."""
    assert '_project_prefix="${COMPOSE_PROJECT_NAME:-docker}"' in install_sh
    assert 'local _project_prefix="docker"' not in install_sh, "hardcoded 'docker' prefix regressed"


def test_digest_strip_preserves_overlay_files(install_sh: str) -> None:
    """In pre-seeded/cached-image mode the digest-strip must NOT drop override -f files
    (wazuh/podman/gpu overlays); otherwise overlay-only services (wazuh-security-init)
    are never created. Both up paths must re-append compose_files[2..]."""
    assert install_sh.count('compose_files[$_cf') >= 1
    assert '_compose_files_up+=("${compose_files[$_cf_i]}")' in install_sh
    assert '_compose_files_up2+=("${compose_files[$_cf2_i]}")' in install_sh


def test_wazuh_mtls_cleanup_is_root_capable(install_sh: str) -> None:
    """A prior successful run chowns docker/wazuh-mtls to the container UID; a non-root
    install user can't recurse it on re-run, so cleanup must fall back to a root container."""
    assert "rm -rf /d/wazuh-mtls" in install_sh, "root-container cleanup fallback regressed"


def test_convergence_gate_timeout_not_too_tight(install_sh: str) -> None:
    """A full fresh install (all services + migrations + SIEM) takes the gateway >180s to
    converge while healthy. The gate default must give enough headroom (>=300s) — but still
    be a finite, overridable, fail-closed ceiling."""
    m = re.search(r"YSG_HEALTHZ_TIMEOUT_S:-(\d+)", install_sh)
    assert m, "convergence-gate timeout default not found"
    default = int(m.group(1))
    assert default >= 300, f"convergence gate default {default}s is too tight (regressed)"


def test_provision_wazuh_mtls_verifies_indexer_san(install_sh: str) -> None:
    """full mTLS fail-closes if the indexer HTTP cert lacks SAN wazuh-indexer — the
    provisioning must verify it rather than ship a cert that breaks verification."""
    assert "grep -q 'DNS:wazuh-indexer'" in install_sh


def test_wazuh_indexer_http_tls13_floor(install_sh: str) -> None:
    """The SIEM link must match the internal-mesh 1.3-min (#156): _provision_wazuh_mtls must
    rewrite the indexer HTTP listener to TLSv1.3 (the Wazuh stock config pins TLSv1.2) and
    fail closed if the floor isn't applied. Validated end-to-end on the clean-slate stack:
    indexer serves 1.3-only, refuses 1.2; filebeat (Go) + dashboard (Node) negotiate 1.3."""
    # the rewrite that flips http.enabled_protocols to 1.3
    assert 'plugins\\.security\\.ssl\\.http\\.enabled_protocols' in install_sh
    assert '"TLSv1.3"' in install_sh
    assert "TLS_AES_256_GCM_SHA384" in install_sh, "TLS 1.3 ciphers not provisioned"
    # fail-closed guard: install aborts if the 1.3 floor didn't land
    assert "TLS 1.3 floor not applied to indexer HTTP listener" in install_sh


def test_pki_manifest_token_self_heal(install_sh: str) -> None:
    """ISSUE-009 / finding C: install/--upgrade must idempotently (re)populate the runtime
    manifest's bootstrap_token_sha256 fields from the persistent docker/secrets/*_bootstrap_token
    source, and fail closed if zero land (a write-back miss previously shipped empty tokens →
    broken internal mesh mTLS client). Self-heal must run for all runtimes, not just macOS."""
    assert "pki-token-ensure" in install_sh, "generic manifest token self-heal missing"
    assert "_bootstrap_token" in install_sh
    # the explicit fail-closed action-item gate
    assert "0 populated bootstrap_token_sha256 fields after issuance (ISSUE-009)" in install_sh


def test_convergence_gate_uses_insecure_for_loopback_edge(install_sh: str) -> None:
    """RECURRING REGRESSION (v2.23.x retros — Caddyfile/cert/probe drift): the convergence-gate
    healthz/login polls hit the Caddy EDGE on loopback. The edge cert is Caddy-local/selfsigned/
    acme/BYO — NEVER the internal ca_root — so `--cacert ca_root` always fails TLS verify (HTTP
    000) and the gate hangs, breaking every selfsigned/acme install. The loopback liveness poll
    must use --insecure. Do NOT re-harden to --cacert."""
    assert 'local _curl_tls_opt="--insecure"' in install_sh, \
        "convergence gate must use --insecure for the loopback edge poll"
    assert '_curl_tls_opt="--cacert ${_ca_cert_healthz}"' not in install_sh, \
        "convergence gate re-hardened to --cacert against the edge (regression — breaks selfsigned/acme)"


def test_gpu_overlay_wires_ollama_on_nvidia(install_sh: str) -> None:
    """ollama must get the GPU in Docker compose mode. The base ollama service's GPU reservation
    is commented out and the nvidia runtime is not the daemon default, so without an overlay
    ollama runs CPU-only. install.sh adds docker-compose.gpu.yml when an NVIDIA GPU is detected."""
    assert (_ROOT / "docker" / "docker-compose.gpu.yml").is_file(), "GPU overlay file missing"
    assert "docker-compose.gpu.yml" in install_sh, "install.sh does not wire the GPU overlay"
    assert '"${YSG_GPU_TYPE:-none}" == "nvidia"' in install_sh, "GPU overlay not gated on nvidia detection"


def test_wazuh_overlay_is_clean_delta(overlay: str) -> None:
    """The overlay must be a DELTA onto the main compose: it must NOT redeclare security_opt
    (that duplicated the list on merge and broke `docker compose config`), and it MUST add
    the security-init sidecar + minimal caps."""
    assert "wazuh-security-init" in overlay, "security-init sidecar missing from overlay"
    assert "security_opt:" not in overlay, "overlay redeclares security_opt (merge-dup regression)"
    assert "cap_add" in overlay, "overlay must add the minimal caps the s6 entrypoint needs"
