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


def test_wazuh_overlay_is_clean_delta(overlay: str) -> None:
    """The overlay must be a DELTA onto the main compose: it must NOT redeclare security_opt
    (that duplicated the list on merge and broke `docker compose config`), and it MUST add
    the security-init sidecar + minimal caps."""
    assert "wazuh-security-init" in overlay, "security-init sidecar missing from overlay"
    assert "security_opt:" not in overlay, "overlay redeclares security_opt (merge-dup regression)"
    assert "cap_add" in overlay, "overlay must add the minimal caps the s6 entrypoint needs"
