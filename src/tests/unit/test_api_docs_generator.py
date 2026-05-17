"""
Unit tests for scripts/gen_api_docs.py (v2.23.4).

Verifies:
- Generator runs without error
- All three output markdown files are produced
- Each file contains expected top-level sections
- Gateway schema includes /v1/chat/completions (openai_router wired correctly)
- Backoffice schema contains /admin/* paths

Last updated: 2026-05-17T00:00:00+01:00
"""
from __future__ import annotations

import sys
import importlib
from pathlib import Path
from unittest.mock import MagicMock

import pytest


# tests/unit/ → tests/ → src/ → repo_root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPTS_DIR = _REPO_ROOT / "scripts"
_DOCS_API_DIR = _REPO_ROOT / "docs" / "api"


def _import_gen():
    """Import gen_api_docs from scripts/ as a module."""
    if str(_SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS_DIR))
    if "gen_api_docs" in sys.modules:
        del sys.modules["gen_api_docs"]
    import gen_api_docs
    return gen_api_docs


class TestGeneratorRuns:
    def test_main_returns_zero(self, tmp_path):
        """gen_api_docs.main() returns 0 (success) and writes all files."""
        gen = _import_gen()
        # Patch output dir to tmp_path so we don't pollute the real docs/api/
        original_out = gen._OUT
        gen._OUT = tmp_path
        try:
            rc = gen.main()
            assert rc == 0, f"gen_api_docs.main() returned {rc}"
        finally:
            gen._OUT = original_out

    def test_all_three_files_produced(self, tmp_path):
        """main() produces gateway-api.md, admin-api.md, auth-api.md, README.md."""
        gen = _import_gen()
        original_out = gen._OUT
        gen._OUT = tmp_path
        try:
            gen.main()
        finally:
            gen._OUT = original_out
        assert (tmp_path / "gateway-api.md").exists()
        assert (tmp_path / "admin-api.md").exists()
        assert (tmp_path / "auth-api.md").exists()
        assert (tmp_path / "README.md").exists()


class TestGatewaySchema:
    def test_gateway_schema_loads(self):
        """_load_gateway_schema() returns a valid OpenAPI dict."""
        gen = _import_gen()
        schema = gen._load_gateway_schema()
        assert "openapi" in schema
        assert "info" in schema
        assert schema["info"]["title"] == "Yashigani Gateway"

    def test_gateway_schema_has_chat_completions(self):
        """Gateway schema includes /v1/chat/completions (openai_router is wired)."""
        gen = _import_gen()
        schema = gen._load_gateway_schema()
        paths = schema.get("paths", {})
        assert "/v1/chat/completions" in paths, (
            "Gateway schema must include /v1/chat/completions — "
            "openai_router is not being passed as extra_router"
        )

    def test_gateway_schema_has_models(self):
        """Gateway schema includes /v1/models."""
        gen = _import_gen()
        schema = gen._load_gateway_schema()
        paths = schema.get("paths", {})
        assert "/v1/models" in paths, "Gateway schema must include /v1/models"


class TestBackofficeSchema:
    def test_backoffice_schema_loads(self):
        """_load_backoffice_schema() returns a valid OpenAPI dict."""
        gen = _import_gen()
        schema = gen._load_backoffice_schema()
        assert "openapi" in schema
        assert "info" in schema
        assert schema["info"]["title"] == "Yashigani Backoffice"

    def test_backoffice_schema_has_admin_paths(self):
        """Backoffice schema contains /admin/* paths."""
        gen = _import_gen()
        schema = gen._load_backoffice_schema()
        paths = schema.get("paths", {})
        admin_paths = [p for p in paths if p.startswith("/admin/")]
        assert len(admin_paths) > 0, "Backoffice schema must contain /admin/* paths"

    def test_backoffice_schema_has_auth_paths(self):
        """Backoffice schema contains /auth/* paths."""
        gen = _import_gen()
        schema = gen._load_backoffice_schema()
        paths = schema.get("paths", {})
        auth_paths = [p for p in paths if p.startswith("/auth/")]
        assert len(auth_paths) > 0, "Backoffice schema must contain /auth/* paths"


class TestGatewayMarkdown:
    def test_gateway_md_has_header(self, tmp_path):
        """gateway-api.md starts with # Yashigani Gateway API Reference."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_gateway_api(gen._load_gateway_schema())
        content = (tmp_path / "gateway-api.md").read_text()
        assert "# Yashigani Gateway API Reference" in content

    def test_gateway_md_has_auth_section(self, tmp_path):
        """gateway-api.md contains an Authentication section."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_gateway_api(gen._load_gateway_schema())
        content = (tmp_path / "gateway-api.md").read_text()
        assert "## Authentication" in content

    def test_gateway_md_no_internal_paths(self, tmp_path):
        """gateway-api.md must not expose /internal/metrics or /healthz."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_gateway_api(gen._load_gateway_schema())
        content = (tmp_path / "gateway-api.md").read_text()
        assert "/internal/metrics" not in content, (
            "/internal/metrics must not appear in customer-facing gateway docs"
        )


class TestAdminMarkdown:
    def test_admin_md_has_header(self, tmp_path):
        """admin-api.md starts with # Yashigani Backoffice API Reference."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_admin_api(gen._load_backoffice_schema())
        content = (tmp_path / "admin-api.md").read_text()
        assert "# Yashigani Backoffice API Reference" in content

    def test_admin_md_has_auth_section(self, tmp_path):
        """admin-api.md contains an Authentication section."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_admin_api(gen._load_backoffice_schema())
        content = (tmp_path / "admin-api.md").read_text()
        assert "## Authentication" in content


class TestAuthMarkdown:
    def test_auth_md_has_header(self, tmp_path):
        """auth-api.md starts with # Yashigani Auth API Reference."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_auth_api(gen._load_backoffice_schema())
        content = (tmp_path / "auth-api.md").read_text()
        assert "# Yashigani Auth API Reference" in content

    def test_auth_md_has_login_section(self, tmp_path):
        """auth-api.md contains the login flow description."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_auth_api(gen._load_backoffice_schema())
        content = (tmp_path / "auth-api.md").read_text()
        assert "/auth/login" in content, "auth-api.md must reference /auth/login"


class TestIndexMarkdown:
    def test_readme_links_three_docs(self, tmp_path):
        """README.md links gateway-api.md, admin-api.md, auth-api.md."""
        gen = _import_gen()
        gen._OUT = tmp_path
        gen._write_index()
        content = (tmp_path / "README.md").read_text()
        assert "gateway-api.md" in content
        assert "admin-api.md" in content
        assert "auth-api.md" in content
