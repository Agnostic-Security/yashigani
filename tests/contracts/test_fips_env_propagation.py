# Last updated: 2026-05-27T00:00:00+01:00
"""
FIPS_MODE env propagation contract tests — Nico N-001 (v2.24.4).

Root cause: lib/yashigani-fips.sh defines FIPS_MODE and install.sh sources it for
host-side backup MANIFEST hashing + air-gap bundle integrity. NO container env block
(compose OR helm) passed FIPS_MODE to gateway / backoffice / caddy. The in-container
FIPS code path existed but never activated (Nico N-001).

Asserts:
  Helm:
    1. When fips.mode=true, gateway Deployment env contains FIPS_MODE=1.
    2. When fips.mode=true, backoffice Deployment env contains FIPS_MODE=1.
    3. When fips.mode=true, caddy Deployment env contains FIPS_MODE=1.
    4. When fips.mode=false (default), gateway env does NOT contain FIPS_MODE.
    5. When fips.mode=false (default), backoffice env does NOT contain FIPS_MODE.
    6. When fips.mode=false (default), caddy env does NOT contain FIPS_MODE.

  Compose:
    7. FIPS_MODE appears in x-common-env anchor (gateway + backoffice).
    8. FIPS_MODE appears in caddy service env block.
    9. Both reference YSG_FIPS_MODE with a default of 0.

  Doc language:
    10. yashigani_install_config.md contains the FIPS-capable vs FIPS-validated
        distinction (prevents customers from claiming FIPS compliance without
        a FIPS-configured base image).
    11. yashigani_install_config.md cites CMVP certificate #4985.

Test approach: helm template (subprocess) + file-parse for compose/docs.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"
COMPOSE_FILE = REPO_ROOT / "docker" / "docker-compose.yml"
INSTALL_CONFIG_DOC = REPO_ROOT / "docs" / "yashigani_install_config.md"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _helm_template(extra_set: list[str] | None = None) -> str:
    """Run `helm template` and return stdout; raise via pytest.fail on error."""
    cmd = [
        "helm",
        "template",
        "yashigani",
        str(HELM_CHART),
        "--set", "global.environment=ci",
        "--set", "mtls.enabled=true",
        "--set", "admissionPolicies.enabled=false",
    ]
    if extra_set:
        for s in extra_set:
            cmd += ["--set", s]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        pytest.fail(
            f"helm template failed (rc={result.returncode}):\n"
            f"STDOUT: {result.stdout[:2000]}\n"
            f"STDERR: {result.stderr[:2000]}"
        )
    return result.stdout


def _parse_all_docs(rendered: str) -> list[dict[str, Any]]:
    """Parse all non-None YAML documents from a helm template render."""
    return [doc for doc in yaml.safe_load_all(rendered) if doc is not None]


def _find_by_kind_name(docs: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any] | None:
    for doc in docs:
        if doc.get("kind") == kind and doc.get("metadata", {}).get("name") == name:
            return doc
    return None


def _get_container(deployment: dict[str, Any], name: str) -> dict[str, Any] | None:
    containers = (
        deployment.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )
    for c in containers:
        if c.get("name") == name:
            return c
    return None


def _get_env_value(container: dict[str, Any], env_name: str) -> str | None:
    for env in container.get("env", []):
        if env.get("name") == env_name:
            return env.get("value")
    return None


def _env_present(container: dict[str, Any], env_name: str) -> bool:
    return any(e.get("name") == env_name for e in container.get("env", []))


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def docs_fips_enabled() -> list[dict[str, Any]]:
    """Render with fips.mode=true."""
    rendered = _helm_template(["fips.mode=true"])
    return _parse_all_docs(rendered)


@pytest.fixture(scope="module")
def docs_fips_disabled() -> list[dict[str, Any]]:
    """Render with default (fips.mode=false)."""
    rendered = _helm_template()
    return _parse_all_docs(rendered)


# ──────────────────────────────────────────────────────────────────────────────
# Helm: FIPS_MODE=1 when fips.mode=true
# ──────────────────────────────────────────────────────────────────────────────

class TestHelmFipsModeEnabled:
    """When fips.mode=true, FIPS_MODE=1 must appear in gateway, backoffice, caddy."""

    def test_gateway_fips_mode_env(
        self, docs_fips_enabled: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_fips_enabled, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        container = _get_container(deployment, "gateway")
        assert container is not None
        val = _get_env_value(container, "FIPS_MODE")
        assert val == "1", (
            f"gateway: expected FIPS_MODE=1 when fips.mode=true, got: {val!r} "
            f"(Nico N-001)"
        )

    def test_backoffice_fips_mode_env(
        self, docs_fips_enabled: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_fips_enabled, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        container = _get_container(deployment, "backoffice")
        assert container is not None
        val = _get_env_value(container, "FIPS_MODE")
        assert val == "1", (
            f"backoffice: expected FIPS_MODE=1 when fips.mode=true, got: {val!r} "
            f"(Nico N-001)"
        )

    def test_caddy_fips_mode_env(
        self, docs_fips_enabled: list[dict[str, Any]]
    ) -> None:
        # Caddy deployment name
        deployment = _find_by_kind_name(
            docs_fips_enabled, "Deployment", "yashigani-caddy"
        )
        assert deployment is not None, "yashigani-caddy Deployment not found"
        container = _get_container(deployment, "caddy")
        assert container is not None
        val = _get_env_value(container, "FIPS_MODE")
        assert val == "1", (
            f"caddy: expected FIPS_MODE=1 when fips.mode=true, got: {val!r} "
            f"(Nico N-001)"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Helm: FIPS_MODE absent when fips.mode=false (default)
# ──────────────────────────────────────────────────────────────────────────────

class TestHelmFipsModeDisabled:
    """When fips.mode=false (default), FIPS_MODE must NOT appear in env blocks."""

    def test_gateway_no_fips_mode_env(
        self, docs_fips_disabled: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_fips_disabled, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        container = _get_container(deployment, "gateway")
        assert container is not None
        assert not _env_present(container, "FIPS_MODE"), (
            "gateway: FIPS_MODE env should NOT be present when fips.mode=false. "
            "Found unexpected FIPS_MODE entry."
        )

    def test_backoffice_no_fips_mode_env(
        self, docs_fips_disabled: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_fips_disabled, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        container = _get_container(deployment, "backoffice")
        assert container is not None
        assert not _env_present(container, "FIPS_MODE"), (
            "backoffice: FIPS_MODE env should NOT be present when fips.mode=false."
        )

    def test_caddy_no_fips_mode_env(
        self, docs_fips_disabled: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_fips_disabled, "Deployment", "yashigani-caddy"
        )
        assert deployment is not None
        container = _get_container(deployment, "caddy")
        assert container is not None
        assert not _env_present(container, "FIPS_MODE"), (
            "caddy: FIPS_MODE env should NOT be present when fips.mode=false."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Compose: FIPS_MODE present in x-common-env and caddy env
# ──────────────────────────────────────────────────────────────────────────────

class TestComposeFipsModePresence:
    """docker-compose.yml must carry FIPS_MODE in x-common-env and caddy env."""

    def test_compose_file_exists(self) -> None:
        assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"

    def test_fips_mode_in_common_env_anchor(self) -> None:
        """
        FIPS_MODE must appear in the x-common-env YAML anchor so that gateway
        and backoffice (which both use <<: *common-env) inherit it.
        The anchor block is at the top of the compose file before 'services:'.
        """
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        # Confirm FIPS_MODE appears in the x-common-env block (before 'services:')
        common_env_section = content.split("services:")[0]
        assert "FIPS_MODE:" in common_env_section, (
            "docker-compose.yml: FIPS_MODE not found in x-common-env anchor block "
            "(section before 'services:'). gateway and backoffice will not receive "
            "FIPS_MODE via <<: *common-env (Nico N-001)."
        )

    def test_fips_mode_uses_ysg_fips_mode_var(self) -> None:
        """FIPS_MODE must reference YSG_FIPS_MODE with default 0."""
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert "YSG_FIPS_MODE" in content, (
            "docker-compose.yml: YSG_FIPS_MODE variable reference not found. "
            "FIPS_MODE should be set from ${YSG_FIPS_MODE:-0}."
        )

    def test_fips_mode_in_caddy_service_env(self) -> None:
        """
        Caddy has its own env block (does not use <<: *common-env).
        FIPS_MODE must be explicitly set in the caddy service environment.
        """
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        # Parse the compose YAML to check caddy specifically
        compose = yaml.safe_load(content)
        caddy_env = compose.get("services", {}).get("caddy", {}).get("environment", {})
        assert "FIPS_MODE" in caddy_env, (
            "docker-compose.yml caddy service: FIPS_MODE not in environment block. "
            "Caddy does not use <<: *common-env — must be added explicitly (Nico N-001)."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Doc language: honest FIPS distinction
# ──────────────────────────────────────────────────────────────────────────────

class TestFipsDocLanguage:
    """
    yashigani_install_config.md must contain the honest FIPS-capable vs
    FIPS-validated distinction so customers cannot claim FIPS compliance
    without a FIPS-configured base image (Nico N-001 honest docs requirement).
    """

    def test_doc_exists(self) -> None:
        assert INSTALL_CONFIG_DOC.exists(), (
            f"yashigani_install_config.md not found at {INSTALL_CONFIG_DOC}"
        )

    def test_fips_capable_vs_validated_distinction(self) -> None:
        """
        Doc must contain the 'FIPS-capable' vs 'FIPS-validated' language.
        Prevents customers from claiming FIPS compliance without a
        FIPS-configured base image.
        """
        content = INSTALL_CONFIG_DOC.read_text(encoding="utf-8")
        assert "FIPS-capable" in content and "FIPS-validated" in content, (
            "yashigani_install_config.md is missing the 'FIPS-capable' vs "
            "'FIPS-validated' distinction. Customers must be clearly informed "
            "that FIPS_MODE=1 without a FIPS-configured base image does not "
            "produce FIPS-validated cryptography (Nico N-001)."
        )

    def test_cmvp_certificate_cited(self) -> None:
        """
        Doc must cite CMVP #4985 so operators can select a validated base image.
        """
        content = INSTALL_CONFIG_DOC.read_text(encoding="utf-8")
        assert "4985" in content, (
            "yashigani_install_config.md is missing a reference to CMVP certificate "
            "#4985. Operators selecting a FIPS-configured base image need the cert "
            "number to verify against the NIST CMVP database (Nico N-001)."
        )
