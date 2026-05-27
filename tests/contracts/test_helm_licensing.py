# Last updated: 2026-05-27T00:00:00+01:00
"""
Helm licensing contract tests — Petra P0-1.

Root cause: src/yashigani/licensing/loader.py resolves /run/secrets/license_key
as its second candidate. Docker/Podman compose provides it via bind-mount.
Helm had NO equivalent — every K8s install silently fell back to COMMUNITY tier
regardless of what the customer paid (Petra P0-1, v2.24.4).

Asserts:
  1. When licensing.licenseKey is non-empty, a Secret named yashigani-license
     is rendered with a `license_key` data field.
  2. When licensing.licenseKey is empty (default), NO yashigani-license Secret
     is rendered.
  3. When licensing.licenseKey is non-empty, gateway Deployment has a volumeMount
     at /run/secrets/license_key (subPath: license_key, readOnly: true).
  4. When licensing.licenseKey is non-empty, backoffice Deployment has the same
     volumeMount.
  5. When licensing.licenseKey is empty, neither gateway nor backoffice have a
     license volumeMount.
  6. When licensing.licenseKey is non-empty, a `license` volume backed by the
     yashigani-license Secret is present on gateway and backoffice.

Test approach: subprocess helm template render — no cluster required.
YAML parsed with PyYAML to avoid brittle string matching on rendered comments.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent
HELM_CHART = REPO_ROOT / "helm" / "yashigani"

_TEST_LICENSE_RAW = "test-license-key-for-contract-test"  # raw .ysg content (not base64)


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


def _get_volume_mount(container: dict[str, Any], mount_path: str) -> dict[str, Any] | None:
    for vm in container.get("volumeMounts", []):
        if vm.get("mountPath") == mount_path:
            return vm
    return None


def _get_volume(deployment: dict[str, Any], vol_name: str) -> dict[str, Any] | None:
    volumes = (
        deployment.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("volumes", [])
    )
    for v in volumes:
        if v.get("name") == vol_name:
            return v
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def docs_with_license() -> list[dict[str, Any]]:
    """Render with licensing.licenseKey set (raw .ysg content, not base64)."""
    rendered = _helm_template([f"licensing.licenseKey={_TEST_LICENSE_RAW}"])
    return _parse_all_docs(rendered)


@pytest.fixture(scope="module")
def docs_without_license() -> list[dict[str, Any]]:
    """Render with default (empty) licensing.licenseKey."""
    rendered = _helm_template()
    return _parse_all_docs(rendered)


# ──────────────────────────────────────────────────────────────────────────────
# Tests: with licenseKey set
# ──────────────────────────────────────────────────────────────────────────────

class TestLicenseSecretRendered:
    """When licenseKey is non-empty, yashigani-license Secret must be rendered."""

    def test_secret_exists(self, docs_with_license: list[dict[str, Any]]) -> None:
        secret = _find_by_kind_name(docs_with_license, "Secret", "yashigani-license")
        assert secret is not None, (
            "yashigani-license Secret not found in helm render with "
            "licensing.licenseKey set (Petra P0-1)"
        )

    def test_secret_uses_stringdata_not_data(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        """B3-D1 (Iris drift gate): Secret must use stringData, not data.
        K8s data: requires pre-encoded base64; stringData: accepts raw strings and
        K8s base64-encodes internally. Using data: with | quote (but no | b64enc)
        forces operators to pre-encode, causing silent garbage mounts on raw input.
        """
        secret = _find_by_kind_name(docs_with_license, "Secret", "yashigani-license")
        assert secret is not None
        assert secret.get("data") is None, (
            "yashigani-license Secret uses 'data:' — must use 'stringData:' instead "
            "(B3-D1 Iris drift gate). 'data:' requires pre-base64-encoded values; "
            "'stringData:' accepts raw content and K8s encodes internally."
        )
        assert secret.get("stringData") is not None, (
            "yashigani-license Secret is missing 'stringData:' block (B3-D1)."
        )

    def test_secret_has_license_key_field(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        secret = _find_by_kind_name(docs_with_license, "Secret", "yashigani-license")
        assert secret is not None
        assert "license_key" in (secret.get("stringData") or {}), (
            "yashigani-license Secret is missing the 'license_key' stringData field. "
            "loader.py resolves /run/secrets/license_key as candidate 2."
        )

    def test_secret_license_key_value_matches_input(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        secret = _find_by_kind_name(docs_with_license, "Secret", "yashigani-license")
        assert secret is not None
        actual = (secret.get("stringData") or {}).get("license_key")
        assert actual == _TEST_LICENSE_RAW, (
            f"yashigani-license.stringData.license_key mismatch. "
            f"Expected: {_TEST_LICENSE_RAW!r}, Got: {actual!r}"
        )


class TestGatewayLicenseMount:
    """When licenseKey is set, gateway must have the license volumeMount and volume."""

    def test_gateway_volumemount_present(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None, "yashigani-gateway Deployment not found"
        container = _get_container(deployment, "gateway")
        assert container is not None, "gateway container not found"
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None, (
            "gateway: volumeMount at /run/secrets/license_key not found. "
            "Petra P0-1: loader.py candidate 2 will not resolve."
        )

    def test_gateway_volumemount_subpath(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        container = _get_container(deployment, "gateway")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None
        assert vm.get("subPath") == "license_key", (
            f"gateway: license volumeMount subPath should be 'license_key', "
            f"got: {vm.get('subPath')!r}"
        )

    def test_gateway_volumemount_readonly(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        container = _get_container(deployment, "gateway")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None
        assert vm.get("readOnly") is True, (
            "gateway: license volumeMount must be readOnly: true"
        )

    def test_gateway_volume_backed_by_license_secret(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        vol = _get_volume(deployment, "license")
        assert vol is not None, "gateway: 'license' volume not found"
        secret_name = vol.get("secret", {}).get("secretName")
        assert secret_name == "yashigani-license", (
            f"gateway: 'license' volume secretName should be 'yashigani-license', "
            f"got: {secret_name!r}"
        )


class TestBackofficeLicenseMount:
    """When licenseKey is set, backoffice must have the license volumeMount and volume."""

    def test_backoffice_volumemount_present(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None, "yashigani-backoffice Deployment not found"
        container = _get_container(deployment, "backoffice")
        assert container is not None, "backoffice container not found"
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None, (
            "backoffice: volumeMount at /run/secrets/license_key not found. "
            "Petra P0-1: loader.py candidate 2 will not resolve."
        )

    def test_backoffice_volumemount_subpath(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        container = _get_container(deployment, "backoffice")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None
        assert vm.get("subPath") == "license_key", (
            f"backoffice: license volumeMount subPath should be 'license_key', "
            f"got: {vm.get('subPath')!r}"
        )

    def test_backoffice_volumemount_readonly(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        container = _get_container(deployment, "backoffice")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is not None
        assert vm.get("readOnly") is True, (
            "backoffice: license volumeMount must be readOnly: true"
        )

    def test_backoffice_volume_backed_by_license_secret(
        self, docs_with_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_with_license, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        vol = _get_volume(deployment, "license")
        assert vol is not None, "backoffice: 'license' volume not found"
        secret_name = vol.get("secret", {}).get("secretName")
        assert secret_name == "yashigani-license", (
            f"backoffice: 'license' volume secretName should be 'yashigani-license', "
            f"got: {secret_name!r}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Tests: without licenseKey (default / COMMUNITY tier)
# ──────────────────────────────────────────────────────────────────────────────

class TestNoLicenseSecretWhenKeyEmpty:
    """When licenseKey is empty, no yashigani-license Secret must be rendered."""

    def test_secret_absent(self, docs_without_license: list[dict[str, Any]]) -> None:
        secret = _find_by_kind_name(
            docs_without_license, "Secret", "yashigani-license"
        )
        assert secret is None, (
            "yashigani-license Secret should NOT be rendered when "
            "licensing.licenseKey is empty (default COMMUNITY tier). "
            "Found an unexpected Secret."
        )

    def test_gateway_has_no_license_volumemount(
        self, docs_without_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_without_license, "Deployment", "yashigani-gateway"
        )
        assert deployment is not None
        container = _get_container(deployment, "gateway")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is None, (
            "gateway: unexpected license volumeMount at /run/secrets/license_key "
            "when licensing.licenseKey is empty. Should only appear when key is set."
        )

    def test_backoffice_has_no_license_volumemount(
        self, docs_without_license: list[dict[str, Any]]
    ) -> None:
        deployment = _find_by_kind_name(
            docs_without_license, "Deployment", "yashigani-backoffice"
        )
        assert deployment is not None
        container = _get_container(deployment, "backoffice")
        assert container is not None
        vm = _get_volume_mount(container, "/run/secrets/license_key")
        assert vm is None, (
            "backoffice: unexpected license volumeMount at /run/secrets/license_key "
            "when licensing.licenseKey is empty. Should only appear when key is set."
        )
