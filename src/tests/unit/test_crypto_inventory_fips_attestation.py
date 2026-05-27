"""
Unit tests — B9 FIPS attestation surface on /admin/crypto/inventory.

Nico N-002 / v2.25.0 P2.

Asserts (source-level + functional):
  1. crypto_inventory.py reads FIPS_MODE env and exposes fips_mode_active (bool).
  2. crypto_inventory.py reads YASHIGANI_CMVP_CERT env and exposes cmvp_cert (str|None).
  3. fips_mode_active is True when FIPS_MODE=1, False otherwise.
  4. cmvp_cert carries the env value when set, None when absent.
  5. yashigani_fips_mode_active gauge is present in metrics/registry.py.
  6. Authenticated response includes both new keys with correct Python types.

Last updated: 2026-05-27T00:00:00+00:00
"""
from __future__ import annotations

import ast
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_CRYPTO_PY = (
    Path(__file__).parents[2] / "yashigani" / "backoffice" / "routes" / "crypto_inventory.py"
)
_REGISTRY_PY = (
    Path(__file__).parents[2] / "yashigani" / "metrics" / "registry.py"
)


# ---------------------------------------------------------------------------
# Source-level assertions
# ---------------------------------------------------------------------------

class TestCryptoInventoryFipsSource:
    """Source-level assertions — no runtime needed."""

    def test_crypto_inventory_py_exists(self):
        assert _CRYPTO_PY.exists(), f"Missing: {_CRYPTO_PY}"

    def test_fips_mode_env_read_present(self):
        """Module must read FIPS_MODE from os.environ."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "FIPS_MODE" in source, (
            "B9 REGRESSION: FIPS_MODE env var not referenced in crypto_inventory.py. "
            "fips_mode_active cannot reflect runtime state."
        )

    def test_cmvp_cert_env_read_present(self):
        """Module must read YASHIGANI_CMVP_CERT from os.environ."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "YASHIGANI_CMVP_CERT" in source, (
            "B9 REGRESSION: YASHIGANI_CMVP_CERT env var not referenced in crypto_inventory.py. "
            "cmvp_cert cannot be populated at runtime."
        )

    def test_fips_mode_active_key_in_payload(self):
        """Handler must add fips_mode_active to the response payload."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "fips_mode_active" in source, (
            "B9 REGRESSION: fips_mode_active not present in crypto_inventory.py. "
            "Auditors cannot verify FIPS mode was active at request time."
        )

    def test_cmvp_cert_key_in_payload(self):
        """Handler must add cmvp_cert to the response payload."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "cmvp_cert" in source, (
            "B9 REGRESSION: cmvp_cert not present in crypto_inventory.py."
        )

    def test_prometheus_gauge_import_present(self):
        """Module must import/reference fips_mode_active gauge from metrics registry."""
        source = _CRYPTO_PY.read_text(encoding="utf-8")
        assert "fips_mode_active" in source and "metrics" in source, (
            "B9 REGRESSION: Prometheus fips_mode_active gauge not wired from metrics.registry."
        )

    def test_registry_has_fips_mode_active_gauge(self):
        """metrics/registry.py must define yashigani_fips_mode_active gauge."""
        source = _REGISTRY_PY.read_text(encoding="utf-8")
        assert "yashigani_fips_mode_active" in source, (
            "B9 REGRESSION: yashigani_fips_mode_active gauge missing from metrics/registry.py. "
            "Prometheus cannot scrape FIPS mode status."
        )
        assert "fips_mode_active" in source, (
            "B9 REGRESSION: fips_mode_active symbol missing from metrics/registry.py."
        )


# ---------------------------------------------------------------------------
# Functional tests — env-controlled behaviour
# ---------------------------------------------------------------------------

def _import_fresh_crypto_inventory_module(env_overrides: dict) -> object:
    """
    Re-import crypto_inventory with a clean env so module-level constants
    (_FIPS_MODE_ACTIVE, _CMVP_CERT) are re-evaluated under test conditions.

    Returns the freshly imported module.
    """
    mod_name = "yashigani.backoffice.routes.crypto_inventory"
    # Remove cached module so importlib loads it fresh with patched env.
    sys.modules.pop(mod_name, None)
    with patch.dict(os.environ, env_overrides, clear=False):
        mod = importlib.import_module(mod_name)
    return mod


class TestCryptoInventoryFipsBehaviour:
    """Functional tests for FIPS env reading behaviour."""

    def test_fips_mode_active_true_when_env_is_1(self):
        """_FIPS_MODE_ACTIVE must be True when FIPS_MODE=1."""
        # Temporarily remove any existing FIPS_MODE so the override is clean.
        saved = os.environ.pop("FIPS_MODE", None)
        try:
            mod = _import_fresh_crypto_inventory_module({"FIPS_MODE": "1"})
            assert mod._FIPS_MODE_ACTIVE is True, (
                "B9: _FIPS_MODE_ACTIVE should be True when FIPS_MODE=1"
            )
        finally:
            if saved is not None:
                os.environ["FIPS_MODE"] = saved
            # Clean up module cache so other tests start fresh.
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)

    def test_fips_mode_active_false_when_env_is_0(self):
        """_FIPS_MODE_ACTIVE must be False when FIPS_MODE=0."""
        saved = os.environ.pop("FIPS_MODE", None)
        try:
            mod = _import_fresh_crypto_inventory_module({"FIPS_MODE": "0"})
            assert mod._FIPS_MODE_ACTIVE is False, (
                "B9: _FIPS_MODE_ACTIVE should be False when FIPS_MODE=0"
            )
        finally:
            if saved is not None:
                os.environ["FIPS_MODE"] = saved
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)

    def test_fips_mode_active_false_when_env_absent(self):
        """_FIPS_MODE_ACTIVE must be False when FIPS_MODE is not set."""
        saved = os.environ.pop("FIPS_MODE", None)
        try:
            # Ensure FIPS_MODE is absent from env.
            env = {k: v for k, v in os.environ.items() if k != "FIPS_MODE"}
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)
            with patch.dict(os.environ, {}, clear=True):
                os.environ.update(env)
                mod = importlib.import_module("yashigani.backoffice.routes.crypto_inventory")
            assert mod._FIPS_MODE_ACTIVE is False, (
                "B9: _FIPS_MODE_ACTIVE should be False when FIPS_MODE is absent"
            )
        finally:
            if saved is not None:
                os.environ["FIPS_MODE"] = saved
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)

    def test_cmvp_cert_populated_when_env_set(self):
        """_CMVP_CERT must reflect YASHIGANI_CMVP_CERT env var when set."""
        saved = os.environ.pop("YASHIGANI_CMVP_CERT", None)
        try:
            mod = _import_fresh_crypto_inventory_module(
                {"YASHIGANI_CMVP_CERT": "#4985"}
            )
            assert mod._CMVP_CERT == "#4985", (
                f"B9: _CMVP_CERT should be '#4985', got {mod._CMVP_CERT!r}"
            )
        finally:
            if saved is not None:
                os.environ["YASHIGANI_CMVP_CERT"] = saved
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)

    def test_cmvp_cert_none_when_env_absent(self):
        """_CMVP_CERT must be None when YASHIGANI_CMVP_CERT is not set."""
        saved = os.environ.pop("YASHIGANI_CMVP_CERT", None)
        try:
            env = {k: v for k, v in os.environ.items() if k != "YASHIGANI_CMVP_CERT"}
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)
            with patch.dict(os.environ, {}, clear=True):
                os.environ.update(env)
                mod = importlib.import_module("yashigani.backoffice.routes.crypto_inventory")
            assert mod._CMVP_CERT is None, (
                f"B9: _CMVP_CERT should be None when YASHIGANI_CMVP_CERT is absent, "
                f"got {mod._CMVP_CERT!r}"
            )
        finally:
            if saved is not None:
                os.environ["YASHIGANI_CMVP_CERT"] = saved
            sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)


# ---------------------------------------------------------------------------
# Functional — authenticated response includes fips_mode_active + cmvp_cert
# ---------------------------------------------------------------------------

def _make_fips_test_app(fips_mode: str, cmvp_cert: str | None):
    """
    Build a FastAPI test app mirroring the crypto_inventory route with
    the given FIPS env vars active at module load time.
    """
    try:
        from fastapi import FastAPI, Depends, HTTPException
        from fastapi import APIRouter as _AR
    except ImportError:
        return None, None

    def _sentinel():
        raise HTTPException(status_code=401, detail={"error": "authentication_required"})

    # Re-import with patched env.
    env: dict = {"FIPS_MODE": fips_mode}
    if cmvp_cert is not None:
        env["YASHIGANI_CMVP_CERT"] = cmvp_cert
    else:
        os.environ.pop("YASHIGANI_CMVP_CERT", None)

    sys.modules.pop("yashigani.backoffice.routes.crypto_inventory", None)
    with patch.dict(os.environ, env, clear=False):
        import yashigani.backoffice.routes.crypto_inventory as _ci_mod

    test_router = _AR()

    @test_router.get("/crypto/inventory")
    async def _handler(session=Depends(_sentinel)):
        payload = dict(_ci_mod._CRYPTO_INVENTORY)
        payload["fips_mode_active"] = _ci_mod._FIPS_MODE_ACTIVE
        payload["cmvp_cert"] = _ci_mod._CMVP_CERT
        from fastapi.responses import JSONResponse
        return JSONResponse(content=payload)

    app = FastAPI()
    app.include_router(test_router, prefix="/admin")
    return app, _sentinel


class TestCryptoInventoryFipsResponse:
    """Verify /admin/crypto/inventory response contains FIPS attestation fields."""

    def _get_authed_response(self, fips_mode: str, cmvp_cert: str | None):
        try:
            from fastapi.testclient import TestClient
            from fastapi import HTTPException
        except ImportError:
            pytest.skip("fastapi/httpx not available")

        app, sentinel = _make_fips_test_app(fips_mode, cmvp_cert)
        if app is None:
            pytest.skip("fastapi not available")

        mock_session = MagicMock()
        mock_session.account_tier = "admin"
        app.dependency_overrides[sentinel] = lambda: mock_session

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/admin/crypto/inventory")
        return resp

    def test_response_includes_fips_mode_active_key(self):
        """Authenticated response must include fips_mode_active key."""
        resp = self._get_authed_response("0", None)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = resp.json()
        assert "fips_mode_active" in data, (
            "B9 REGRESSION: fips_mode_active missing from /admin/crypto/inventory response"
        )

    def test_response_includes_cmvp_cert_key(self):
        """Authenticated response must include cmvp_cert key."""
        resp = self._get_authed_response("0", None)
        assert resp.status_code == 200
        data = resp.json()
        assert "cmvp_cert" in data, (
            "B9 REGRESSION: cmvp_cert missing from /admin/crypto/inventory response"
        )

    def test_fips_mode_active_false_when_fips_env_0(self):
        """fips_mode_active must be False when FIPS_MODE=0."""
        resp = self._get_authed_response("0", None)
        assert resp.status_code == 200
        data = resp.json()
        assert data["fips_mode_active"] is False, (
            f"B9: fips_mode_active should be False when FIPS_MODE=0, got {data['fips_mode_active']!r}"
        )

    def test_fips_mode_active_true_when_fips_env_1(self):
        """fips_mode_active must be True when FIPS_MODE=1."""
        resp = self._get_authed_response("1", None)
        assert resp.status_code == 200
        data = resp.json()
        assert data["fips_mode_active"] is True, (
            f"B9: fips_mode_active should be True when FIPS_MODE=1, got {data['fips_mode_active']!r}"
        )

    def test_cmvp_cert_none_when_env_absent(self):
        """cmvp_cert must be null/None when YASHIGANI_CMVP_CERT is not set."""
        resp = self._get_authed_response("0", None)
        assert resp.status_code == 200
        data = resp.json()
        assert data["cmvp_cert"] is None, (
            f"B9: cmvp_cert should be null when YASHIGANI_CMVP_CERT not set, "
            f"got {data['cmvp_cert']!r}"
        )

    def test_cmvp_cert_value_when_env_set(self):
        """cmvp_cert must carry the YASHIGANI_CMVP_CERT value when set."""
        resp = self._get_authed_response("1", "#4985")
        assert resp.status_code == 200
        data = resp.json()
        assert data["cmvp_cert"] == "#4985", (
            f"B9: cmvp_cert should be '#4985', got {data['cmvp_cert']!r}"
        )

    def test_existing_inventory_keys_still_present(self):
        """Original CryptoBoM keys must still be present (no regression)."""
        resp = self._get_authed_response("0", None)
        assert resp.status_code == 200
        data = resp.json()
        for key in ("algorithms", "deprecated", "post_quantum", "compliance"):
            assert key in data, f"B9 REGRESSION: original key '{key}' missing from response"
