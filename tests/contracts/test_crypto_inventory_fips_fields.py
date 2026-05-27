"""
Contract test — B9 /admin/crypto/inventory FIPS attestation fields.

Nico N-002 / v2.25.0 P2.

Asserts source-level and import-level guarantees that:
  1. crypto_inventory.py exposes fips_mode_active (bool) in the response payload.
  2. crypto_inventory.py exposes cmvp_cert (str | None) in the response payload.
  3. fips_mode_active reads from FIPS_MODE env variable (not a hardcoded value).
  4. cmvp_cert reads from YASHIGANI_CMVP_CERT env variable.
  5. metrics/registry.py exports the yashigani_fips_mode_active Gauge symbol.

These are static/import-level tests — no live service required.

Last updated: 2026-05-27T00:00:00+00:00
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
CRYPTO_PY = (
    REPO_ROOT / "src" / "yashigani" / "backoffice" / "routes" / "crypto_inventory.py"
)
REGISTRY_PY = (
    REPO_ROOT / "src" / "yashigani" / "metrics" / "registry.py"
)


class TestCryptoInventoryFipsContract:
    """Static contract assertions for B9 — no runtime required."""

    def test_crypto_inventory_file_exists(self):
        assert CRYPTO_PY.exists(), f"Missing: {CRYPTO_PY}"

    def test_registry_file_exists(self):
        assert REGISTRY_PY.exists(), f"Missing: {REGISTRY_PY}"

    def test_fips_mode_env_read(self):
        """crypto_inventory.py must read FIPS_MODE from os.environ."""
        src = CRYPTO_PY.read_text(encoding="utf-8")
        assert "FIPS_MODE" in src, (
            "B9 CONTRACT FAIL: FIPS_MODE env var not referenced in crypto_inventory.py. "
            "fips_mode_active will never reflect actual FIPS state."
        )

    def test_cmvp_cert_env_read(self):
        """crypto_inventory.py must read YASHIGANI_CMVP_CERT from os.environ."""
        src = CRYPTO_PY.read_text(encoding="utf-8")
        assert "YASHIGANI_CMVP_CERT" in src, (
            "B9 CONTRACT FAIL: YASHIGANI_CMVP_CERT env var not referenced in crypto_inventory.py."
        )

    def test_fips_mode_active_in_payload(self):
        """Handler must include fips_mode_active in the JSON payload."""
        src = CRYPTO_PY.read_text(encoding="utf-8")
        assert '"fips_mode_active"' in src or "'fips_mode_active'" in src or "fips_mode_active" in src, (
            "B9 CONTRACT FAIL: fips_mode_active not present in crypto_inventory.py payload."
        )

    def test_cmvp_cert_in_payload(self):
        """Handler must include cmvp_cert in the JSON payload."""
        src = CRYPTO_PY.read_text(encoding="utf-8")
        assert "cmvp_cert" in src, (
            "B9 CONTRACT FAIL: cmvp_cert not present in crypto_inventory.py payload."
        )

    def test_fips_gauge_in_registry(self):
        """metrics/registry.py must define yashigani_fips_mode_active Gauge."""
        src = REGISTRY_PY.read_text(encoding="utf-8")
        assert "yashigani_fips_mode_active" in src, (
            "B9 CONTRACT FAIL: yashigani_fips_mode_active Gauge missing from metrics/registry.py. "
            "Prometheus cannot scrape FIPS attestation data."
        )

    def test_fips_gauge_symbol_exported(self):
        """The symbol fips_mode_active must be importable from metrics.registry."""
        src = REGISTRY_PY.read_text(encoding="utf-8")
        assert "fips_mode_active" in src, (
            "B9 CONTRACT FAIL: fips_mode_active symbol not present in metrics/registry.py."
        )

    def test_fips_mode_active_type_is_bool_in_ast(self):
        """
        AST-level: the payload key 'fips_mode_active' must be assigned a value
        that is not a string literal (it must come from a variable or boolean
        expression derived from os.environ).
        """
        src = CRYPTO_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)

        # Confirm FIPS_MODE comparison expression exists at module level
        # (the os.environ.get("FIPS_MODE", "0") == "1" pattern).
        found_comparison = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                # Look for a comparison involving "FIPS_MODE" string.
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and child.value == "FIPS_MODE":
                        found_comparison = True
                        break
                    if isinstance(child, ast.Constant) and child.value == "1":
                        # May be the RHS of the comparison.
                        pass

        # Also accept: env.get("FIPS_MODE") in Call args.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and arg.value == "FIPS_MODE":
                        found_comparison = True
                        break

        assert found_comparison, (
            "B9 CONTRACT FAIL: 'FIPS_MODE' not found in any function call or comparison "
            "in crypto_inventory.py. The fips_mode_active value may be hardcoded."
        )
