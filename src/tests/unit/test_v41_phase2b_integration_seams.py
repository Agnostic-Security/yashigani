# Last updated: 2026-07-06T00:00:00+00:00
"""
Unit tests — v4.1 Phase 2b integration seams (coordinator brief):

  Seam 1 (/auth/verify-webhook):
    S1-b  Unknown provider → 401 unknown_provider.
    S1-c  Method not POST → 401 method_not_post.
    S1-d  Slack timestamp missing → 401.
    S1-e  Slack timestamp stale (|Δ| > 300 s) → 401.
    S1-f  Slack signature malformed → 401.
    S1-g  Slack replay dedupe: second request with same sig → 401.
    S1-h  Slack valid (fresh + sig OK + first seen) → 200.
    S1-i  Telegram token missing → 401.
    S1-j  Telegram token mismatch → 401.
    S1-k  Telegram token match → 200.

  Seam 2 (svid-init population):
    S2-a  svid-init dir is created and client.{crt,key}/ca.crt written correctly.
    S2-b  If intermediate CA missing, svid-init step fails → step is "svid_init".
    S2-c  Rollback removes the three baseline files.

  Seam 3 (grants/baselines durable storage + OPA re-push):
    S3-a  put_grant / put_baseline write to Redis; get_grant / get_baseline return
          the correct dict.
    S3-b  delete_grant / delete_baseline remove the keys.
    S3-c  build_mcp_opa_data assembles grants+baselines keyed by mcp_id.
    S3-d  build_mcp_opa_data skips entries with no grant or baseline (warns).
    S3-e  push_mcp_opa_data PUT-calls OPA /v1/data/yashigani/mcp.
    S3-f  put_grant and put_baseline are called inside the step-4b block when
          registry_store is supplied.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _fake_redis() -> MagicMock:
    """Minimal synchronous Redis stub backed by a plain dict."""
    r = MagicMock()
    _store: dict = {}

    def _set(k, v, **_kw):
        _store[k] = v

    def _get(k):
        return _store.get(k)

    def _delete(*keys):
        for k in keys:
            _store.pop(k, None)

    def _setnx(k, v):
        if k in _store:
            return 0
        _store[k] = v
        return 1

    def _expire(k, _ttl):
        pass  # no-op

    def _sadd(k, *vals):
        if k not in _store:
            _store[k] = set()
        _store[k].update(vals)

    def _srem(k, *vals):
        if isinstance(_store.get(k), set):
            for v in vals:
                _store[k].discard(v)

    def _smembers(k):
        v = _store.get(k, set())
        return {m.encode() if isinstance(m, str) else m for m in v}

    r.set.side_effect = _set
    r.get.side_effect = _get
    r.delete.side_effect = _delete
    r.setnx.side_effect = _setnx
    r.expire.side_effect = _expire
    r.sadd.side_effect = _sadd
    r.srem.side_effect = _srem
    r.smembers.side_effect = _smembers
    r._store = _store
    return r


# ---------------------------------------------------------------------------
# Seam 1: /auth/verify-webhook
# ---------------------------------------------------------------------------

class TestVerifyWebhookRoute:
    """Seam 1 — verify_webhook_ingress endpoint unit tests."""

    def _fn(self):
        from yashigani.backoffice.routes.auth import verify_webhook_ingress
        return verify_webhook_ingress

    def _req(self, headers: dict):
        req = MagicMock()
        req.headers = headers
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        return req

    def _rate_ok_redis(self):
        r = _fake_redis()
        pipe = MagicMock()
        pipe.incr.return_value = None
        pipe.expire.return_value = None
        pipe.execute.return_value = [1, None, 1, None]
        r.pipeline.return_value = pipe
        return r

    @pytest.mark.asyncio
    async def test_s1b_unknown_provider_denied(self):
        """S1-b: unknown provider → 401 unknown_provider."""
        from fastapi import HTTPException
        req = self._req({"x-forwarded-method": "POST", "x-real-ip": "1.2.3.4"})
        with pytest.raises(HTTPException) as exc:
            await self._fn()(req, provider="bad")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "unknown_provider"

    @pytest.mark.asyncio
    async def test_s1c_method_not_post_denied(self):
        """S1-c: method != POST → 401 method_not_post."""
        from fastapi import HTTPException
        req = self._req({"x-forwarded-method": "GET", "x-real-ip": "1.2.3.4"})
        with pytest.raises(HTTPException) as exc:
            await self._fn()(req, provider="slack")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "method_not_post"

    @pytest.mark.asyncio
    async def test_s1d_slack_timestamp_missing(self):
        """S1-d: X-Slack-Request-Timestamp absent → 401."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        with patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r):
            req = self._req({"x-forwarded-method": "POST", "x-real-ip": "1.2.3.4"})
            with pytest.raises(HTTPException) as exc:
                await self._fn()(req, provider="slack")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "slack_timestamp_missing"

    @pytest.mark.asyncio
    async def test_s1e_slack_timestamp_stale(self):
        """S1-e: stale timestamp (> 300 s old) → 401 slack_timestamp_stale."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        stale_ts = str(int(time.time()) - 400)
        with patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r):
            req = self._req({
                "x-forwarded-method": "POST",
                "x-real-ip": "1.2.3.4",
                "x-slack-request-timestamp": stale_ts,
            })
            with pytest.raises(HTTPException) as exc:
                await self._fn()(req, provider="slack")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "slack_timestamp_stale"

    @pytest.mark.asyncio
    async def test_s1f_slack_signature_malformed(self):
        """S1-f: bad signature format → 401 slack_signature_malformed."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        fresh_ts = str(int(time.time()))
        with patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r):
            req = self._req({
                "x-forwarded-method": "POST",
                "x-real-ip": "1.2.3.4",
                "x-slack-request-timestamp": fresh_ts,
                "x-slack-signature": "not-valid",
            })
            with pytest.raises(HTTPException) as exc:
                await self._fn()(req, provider="slack")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "slack_signature_malformed"

    @pytest.mark.asyncio
    async def test_s1g_slack_replay_detected(self):
        """S1-g: same sig seen twice → 401 slack_replay_detected."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        fresh_ts = str(int(time.time()))
        good_sig = "v0=" + "a" * 64

        call_n = {"n": 0}
        real_store: dict = {}

        def _setnx_first_then_zero(k, v):
            call_n["n"] += 1
            if call_n["n"] == 1:
                real_store[k] = v
                return 1
            return 0

        r.setnx.side_effect = _setnx_first_then_zero

        hdrs = {
            "x-forwarded-method": "POST",
            "x-real-ip": "1.2.3.4",
            "x-slack-request-timestamp": fresh_ts,
            "x-slack-signature": good_sig,
        }

        with (
            patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r),
            patch("yashigani.backoffice.routes.auth.backoffice_state") as state_mock,
        ):
            state_mock.audit_writer = MagicMock()
            # First request succeeds
            resp = await self._fn()(self._req(hdrs), provider="slack")
            assert resp.status_code == 200

            # Second request: replay
            with pytest.raises(HTTPException) as exc:
                await self._fn()(self._req(hdrs), provider="slack")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "slack_replay_detected"

    @pytest.mark.asyncio
    async def test_s1h_slack_valid_200(self):
        """S1-h: fresh ts + good sig + first seen → 200."""
        r = self._rate_ok_redis()
        r.setnx.side_effect = lambda k, v: (r._store.update({k: v}) or 1)

        fresh_ts = str(int(time.time()))
        good_sig = "v0=" + "b" * 64
        with (
            patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r),
            patch("yashigani.backoffice.routes.auth.backoffice_state") as state_mock,
        ):
            state_mock.audit_writer = MagicMock()
            req = self._req({
                "x-forwarded-method": "POST",
                "x-real-ip": "1.2.3.4",
                "x-slack-request-timestamp": fresh_ts,
                "x-slack-signature": good_sig,
            })
            resp = await self._fn()(req, provider="slack")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_s1i_telegram_token_missing(self):
        """S1-i: no Telegram token header → 401."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        with patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r):
            req = self._req({"x-forwarded-method": "POST", "x-real-ip": "1.2.3.4"})
            with pytest.raises(HTTPException) as exc:
                await self._fn()(req, provider="telegram")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "telegram_token_missing"

    @pytest.mark.asyncio
    async def test_s1j_telegram_token_mismatch(self):
        """S1-j: wrong Telegram token → 401."""
        from fastapi import HTTPException
        r = self._rate_ok_redis()
        with (
            patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r),
            patch("yashigani.backoffice.routes.auth.backoffice_state") as state_mock,
            patch("builtins.open", return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(
                    read=MagicMock(return_value="correct-token"),
                )),
                __exit__=MagicMock(return_value=False),
                read=MagicMock(return_value="correct-token"),
            )),
        ):
            state_mock.audit_writer = MagicMock()
            req = self._req({
                "x-forwarded-method": "POST",
                "x-real-ip": "1.2.3.4",
                "x-telegram-bot-api-secret-token": "wrong-token",
            })
            with pytest.raises(HTTPException) as exc:
                await self._fn()(req, provider="telegram")
        assert exc.value.status_code == 401
        assert exc.value.detail["error"] == "telegram_token_mismatch"

    @pytest.mark.asyncio
    async def test_s1k_telegram_token_match(self):
        """S1-k: correct Telegram token → 200."""
        r = self._rate_ok_redis()
        token = "secret-tg-xyz"
        import io
        fake_file = io.StringIO(token)
        with (
            patch("yashigani.backoffice.routes.auth._get_throttle_redis", return_value=r),
            patch("yashigani.backoffice.routes.auth.backoffice_state") as state_mock,
            patch("builtins.open", return_value=MagicMock(
                __enter__=MagicMock(return_value=MagicMock(
                    read=MagicMock(return_value=token),
                )),
                __exit__=MagicMock(return_value=False),
                read=MagicMock(return_value=token),
            )),
        ):
            state_mock.audit_writer = MagicMock()
            req = self._req({
                "x-forwarded-method": "POST",
                "x-real-ip": "1.2.3.4",
                "x-telegram-bot-api-secret-token": token,
            })
            resp = await self._fn()(req, provider="telegram")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Seam 2: svid-init population
# ---------------------------------------------------------------------------

class TestSvidInitPopulation:
    """Seam 2 — approve transaction writes client.{crt,key,ca.crt} into svid-init."""

    def test_s2a_svid_init_dir_created_with_correct_files(self, tmp_path: Path):
        """S2-a: svid-init dir is created and all three basenames written."""
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        # Source files (simulate minted leaf + intermediate CA)
        cert_src = secrets_dir / "leaf.crt"
        key_src = secrets_dir / "leaf.key"
        ca_src = secrets_dir / "ca_intermediate.crt"
        cert_src.write_bytes(b"CERT-BYTES")
        key_src.write_bytes(b"KEY-BYTES")
        ca_src.write_bytes(b"CA-BYTES")

        # Mirror what mcp_onboard.py step 2b does
        tenant_id, server_id = "acme", "my-mcp"
        svid_init_dir = secrets_dir / "svid-init" / tenant_id / server_id
        svid_init_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cert_src, svid_init_dir / "client.crt")
        shutil.copy2(key_src, svid_init_dir / "client.key")
        shutil.copy2(ca_src, svid_init_dir / "ca.crt")

        assert (svid_init_dir / "client.crt").read_bytes() == b"CERT-BYTES"
        assert (svid_init_dir / "client.key").read_bytes() == b"KEY-BYTES"
        assert (svid_init_dir / "ca.crt").read_bytes() == b"CA-BYTES"

    def test_s2c_rollback_removes_files(self, tmp_path: Path):
        """S2-c: rollback deletes all three baseline files."""
        svid_dir = tmp_path / "svid-init" / "acme" / "srv"
        svid_dir.mkdir(parents=True)
        for name in ("client.crt", "client.key", "ca.crt"):
            (svid_dir / name).write_bytes(b"placeholder")

        # Simulate the _undo_svid_init rollback function
        for fname in ("client.crt", "client.key", "ca.crt"):
            (svid_dir / fname).unlink(missing_ok=True)

        for name in ("client.crt", "client.key", "ca.crt"):
            assert not (svid_dir / name).exists()

    @pytest.mark.asyncio
    async def test_s2b_svid_init_failure_rolls_back_mint(self, tmp_path: Path):
        """S2-b: CA cert missing → svid_init step fail → minted cert+key removed."""
        from yashigani.backoffice.mcp_onboard import run_approve_transaction, McpOnboardError

        env_mock = MagicMock()
        env_mock.tools = {"read_file": MagicMock()}

        minted_cert = tmp_path / "leaf.crt"
        minted_key = tmp_path / "leaf.key"
        minted_cert.write_bytes(b"CERT")
        minted_key.write_bytes(b"KEY")

        fake_pki = MagicMock()
        fake_pki.agent_cert.return_value = minted_cert
        fake_pki.agent_key.return_value = minted_key
        # intermediate_cert does NOT exist → shutil.copy2 raises FileNotFoundError
        fake_pki.intermediate_cert = tmp_path / "NONEXISTENT_ca_intermediate.crt"

        with (
            patch("yashigani.backoffice.mcp_onboard._artifact_root", return_value=tmp_path),
            patch("yashigani.backoffice.mcp_onboard._runtime", return_value="docker"),
            patch(
                # IssuerPaths is a local import: from yashigani.pki.issuer import IssuerPaths
                "yashigani.pki.issuer.IssuerPaths",
                return_value=fake_pki,
            ),
            patch(
                # mint_agent_leaf is a local import: from yashigani.pki.issuer import mint_agent_leaf
                "yashigani.pki.issuer.mint_agent_leaf",
                return_value="spiffe://td/agents/t1/s1/nhi",
            ),
            patch(
                "yashigani.backoffice.mcp_onboard._validate_manifest_or_raise",
                return_value={
                    "metadata": {"name": "s1", "tenant_id": "t1"},
                    "spec": {"image": {"digest": "sha256:" + "a" * 64}},
                },
            ),
            patch(
                # tool_surface_hash is a local import: from yashigani.pki.binding import tool_surface_hash
                "yashigani.pki.binding.tool_surface_hash",
                return_value="sha384:" + "b" * 96,
            ),
            patch("os.environ.get", side_effect=lambda k, d="": {
                "YASHIGANI_ENV": "dev",
                "YASHIGANI_SECRETS_DIR": str(tmp_path / "secrets"),
                "YASHIGANI_SERVICE_MANIFEST_PATH": str(tmp_path / "svc.yaml"),
            }.get(k, d)),
            # FINDING-V412-SVID-WRITE-PATH (Captain, 2026-07-21): step 2b now
            # resolves the staging dir via $YASHIGANI_SVID_INIT_DIR (default
            # /run/secrets-rw/svid-init — not writable under pytest). Point
            # it under tmp_path so the CA-missing failure this test exercises
            # is reached via the intended shutil.copy2(intermediate_cert, ...)
            # FileNotFoundError, not an unrelated mkdir permission error.
            patch("os.getenv", side_effect=lambda k, d="": {
                "YASHIGANI_SECRETS_DIR": str(tmp_path / "secrets"),
                "YASHIGANI_SERVICE_MANIFEST_PATH": str(tmp_path / "svc.yaml"),
                "YASHIGANI_SVID_INIT_DIR": str(tmp_path / "secrets" / "svid-init"),
                "YASHIGANI_SVID_GID": str(os.getgid()),
            }.get(k, d)),
        ):
            with pytest.raises(McpOnboardError) as exc_info:
                await run_approve_transaction(
                    manifest_yaml="---",
                    server_id="s1",
                    tenant_id="t1",
                    env=env_mock,
                    topology="standalone",
                    sidecar_scan_verdict=None,
                    operator_identity="admin",
                    envelope_service=AsyncMock(),
                )

        # Step must be svid_init (fails before codegen/caddy)
        assert exc_info.value.step == "svid_init"
        # Rollback (_undo_mint) must have removed minted files
        assert not minted_cert.exists()
        assert not minted_key.exists()


# ---------------------------------------------------------------------------
# Seam 3: grants/baselines durable storage + OPA re-push
# ---------------------------------------------------------------------------

class TestDurableRegistryGrantBaseline:
    """Seam 3 — DurableMcpRegistryStore grant/baseline round-trip."""

    def _store(self):
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore
        r = _fake_redis()
        return DurableMcpRegistryStore(r), r

    def test_s3a_put_get_grant(self):
        """S3-a: put_grant / get_grant round-trip."""
        store, _ = self._store()
        grant = {
            "tools": ["list_dir", "read_file"],
            "actions": ["tools/call"],
            "caller_spiffe": "spiffe://td/gateway",
        }
        store.put_grant("acme", "my-mcp", grant)
        got = store.get_grant("acme", "my-mcp")
        assert got is not None
        assert got["tools"] == ["list_dir", "read_file"]
        assert got["caller_spiffe"] == "spiffe://td/gateway"

    def test_s3a_put_get_baseline(self):
        """S3-a: put_baseline / get_baseline round-trip."""
        store, _ = self._store()
        baseline = {"surface_hash": "sha384:" + "c" * 96, "tools": ["list_dir"]}
        store.put_baseline("acme", "my-mcp", baseline)
        got = store.get_baseline("acme", "my-mcp")
        assert got is not None
        assert got["surface_hash"].startswith("sha384:")
        assert "list_dir" in got["tools"]

    def test_s3b_delete_grant_baseline(self):
        """S3-b: delete_grant / delete_baseline remove the keys."""
        store, _ = self._store()
        store.put_grant("acme", "srv", {"tools": [], "actions": [], "caller_spiffe": ""})
        store.put_baseline("acme", "srv", {"surface_hash": "sha384:" + "d" * 96, "tools": []})
        store.delete_grant("acme", "srv")
        store.delete_baseline("acme", "srv")
        assert store.get_grant("acme", "srv") is None
        assert store.get_baseline("acme", "srv") is None

    def test_s3c_build_mcp_opa_data(self):
        """S3-c: build_mcp_opa_data assembles grants+baselines keyed by mcp_id."""
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore
        r = _fake_redis()
        store = DurableMcpRegistryStore(r)

        store.put("acme", "calc", {
            "agent_name": "calc",
            "tenant_id": "acme",
            "upstream_url": "https://caddy:8443/mcp/acme/calc",
        })
        store.put_grant("acme", "calc", {
            "tools": ["add", "multiply"],
            "actions": ["tools/call"],
            "caller_spiffe": "spiffe://td/gateway",
        })
        store.put_baseline("acme", "calc", {
            "surface_hash": "sha384:" + "e" * 96,
            "tools": ["add", "multiply"],
        })

        id_store = MagicMock()
        id_store.get_or_mint.return_value = "uuid-calc-stable"

        doc = store.build_mcp_opa_data(id_store, "acme-org")

        assert "grants" in doc and "baselines" in doc
        mcp_id = "uuid-calc-stable"
        assert mcp_id in doc["grants"]
        assert "spiffe://td/gateway" in doc["grants"][mcp_id]
        assert set(doc["grants"][mcp_id]["spiffe://td/gateway"]["tools"]) == {"add", "multiply"}
        assert mcp_id in doc["baselines"]
        assert doc["baselines"][mcp_id]["surface_hash"].startswith("sha384:")

    def test_s3d_build_opa_data_skips_missing_grant(self):
        """S3-d: entries with no grant or baseline are skipped."""
        from yashigani.mcp._durable_registry import DurableMcpRegistryStore
        r = _fake_redis()
        store = DurableMcpRegistryStore(r)

        # Register descriptor but NO grant/baseline
        store.put("acme", "orphan", {
            "agent_name": "orphan",
            "tenant_id": "acme",
            "upstream_url": "https://caddy:8443/mcp/acme/orphan",
        })
        id_store = MagicMock()
        id_store.get_or_mint.return_value = "uuid-orphan"

        doc = store.build_mcp_opa_data(id_store, "acme-org")

        # Skipped: no grant or baseline
        assert doc["grants"] == {}
        assert doc["baselines"] == {}


class TestPushMcpOpaData:
    """Seam 3 — push_mcp_opa_data PUT-calls OPA /v1/data/yashigani/mcp."""

    def test_s3e_push_calls_opa_put(self):
        """S3-e: push_mcp_opa_data PUT to /v1/data/yashigani/mcp with mTLS."""
        from yashigani.mcp._opa_push import push_mcp_opa_data

        mcp_doc = {
            "grants": {
                "uuid-x": {"spiffe://td/gateway": {"tools": ["t1"], "actions": ["tools/call"]}},
            },
            "baselines": {
                "uuid-x": {"surface_hash": "sha384:" + "f" * 96, "tools": ["t1"]},
            },
        }

        captured: dict = {}
        sync_client = MagicMock()
        response_mock = MagicMock()
        response_mock.raise_for_status.return_value = None
        sync_client.__enter__ = MagicMock(return_value=sync_client)
        sync_client.__exit__ = MagicMock(return_value=False)

        def _put(url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            return response_mock

        sync_client.put.side_effect = _put

        with patch(
            # internal_httpx_sync_client is a local import inside push_mcp_opa_data
            "yashigani.pki.client.internal_httpx_sync_client",
            return_value=sync_client,
        ):
            push_mcp_opa_data("https://policy:8181", mcp_doc)

        assert "/v1/data/yashigani/mcp" in captured["url"]
        assert captured["json"] == mcp_doc


class TestApproveTransactionGrantBaseline:
    """Seam 3 — step 4b-ii: put_grant + put_baseline called by the approve tx."""

    @pytest.mark.asyncio
    async def test_s3f_put_grant_and_put_baseline_called(self, tmp_path: Path):
        """S3-f: approve tx calls registry_store.put_grant + .put_baseline."""
        from yashigani.backoffice.mcp_onboard import run_approve_transaction

        # Build a real self-signed cert so _leaf_cert_fingerprint works.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime as _dt

        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
            .issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test")]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(_dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc))
            .not_valid_after(_dt.datetime(2027, 1, 1, tzinfo=_dt.timezone.utc))
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # Write all required files
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()
        cert_file = secrets_dir / "agent_t1_s1_nhi_client.crt"
        key_file = secrets_dir / "agent_t1_s1_nhi_client.key"
        ca_file = secrets_dir / "ca_intermediate.crt"
        for f in (cert_file, key_file, ca_file):
            f.write_bytes(cert_pem)  # all using same self-signed cert

        fake_pki = MagicMock()
        fake_pki.agent_cert.return_value = cert_file
        fake_pki.agent_key.return_value = key_file
        fake_pki.intermediate_cert = ca_file

        env_mock = MagicMock()
        env_mock.tools = {"read_file": MagicMock(), "list_dir": MagicMock()}

        registry_store = MagicMock()
        registry_store.put.return_value = None
        registry_store.put_grant.return_value = None
        registry_store.put_baseline.return_value = None

        reloader = AsyncMock()
        envelope_svc = AsyncMock()
        envelope_svc.mint_envelope.return_value = 99

        with (
            patch("yashigani.backoffice.mcp_onboard._artifact_root", return_value=tmp_path),
            patch("yashigani.backoffice.mcp_onboard._runtime", return_value="docker"),
            patch(
                # IssuerPaths is a local import inside run_approve_transaction
                "yashigani.pki.issuer.IssuerPaths",
                return_value=fake_pki,
            ),
            patch(
                # mint_agent_leaf is a local import inside run_approve_transaction
                "yashigani.pki.issuer.mint_agent_leaf",
                return_value="spiffe://td/agents/t1/s1/nhi",
            ),
            patch(
                "yashigani.backoffice.mcp_onboard._validate_manifest_or_raise",
                return_value={
                    "metadata": {"name": "s1", "tenant_id": "t1"},
                    "spec": {"image": {"digest": "sha256:" + "a" * 64}},
                },
            ),
            patch(
                # tool_surface_hash is a local import inside run_approve_transaction
                "yashigani.pki.binding.tool_surface_hash",
                return_value="sha384:" + "g" * 96,
            ),
            patch(
                # approve_mcp_onboard is a local import from yashigani.manifest.codegen
                "yashigani.manifest.codegen.approve_mcp_onboard",
                return_value={},
            ),
            patch(
                # _mcp_mesh_port is a local import inside step 3 codegen
                "yashigani.manifest.codegen._mcp_mesh_port",
                return_value=8443,
            ),
            # trust_domain: yashigani.identity.__init__ re-exports the function under
            # the same name as the submodule, so dotted patch("...trust_domain.trust_domain")
            # resolves to the function not the module.  Use patch.object on the submodule.
            patch.object(
                __import__(
                    "yashigani.identity.trust_domain",
                    fromlist=["trust_domain"],
                ),
                "trust_domain",
                return_value="td.yashigani.local",
            ),
            patch("os.environ.get", side_effect=lambda k, d="": {
                "YASHIGANI_ENV": "dev",
            }.get(k, d)),
            # FINDING-V412-SVID-WRITE-PATH — see S2-b test above for full
            # rationale (same fixture shape, same fix).
            patch("os.getenv", side_effect=lambda k, d="": {
                "YASHIGANI_SECRETS_DIR": str(secrets_dir),
                "YASHIGANI_SERVICE_MANIFEST_PATH": str(tmp_path / "svc.yaml"),
                "YASHIGANI_SVID_INIT_DIR": str(secrets_dir / "svid-init"),
                "YASHIGANI_SVID_GID": str(os.getgid()),
            }.get(k, d)),
        ):
            await run_approve_transaction(
                manifest_yaml="---",
                server_id="s1",
                tenant_id="t1",
                env=env_mock,
                topology="standalone",
                sidecar_scan_verdict=None,
                operator_identity="admin",
                envelope_service=envelope_svc,
                caddy_reloader=reloader,
                registry_store=registry_store,
            )

        # Core assertions: put_grant and put_baseline were both called
        registry_store.put_grant.assert_called_once()
        registry_store.put_baseline.assert_called_once()

        # Verify the grant data has the gateway spiffe
        grant_data = registry_store.put_grant.call_args[0][2]
        assert "caller_spiffe" in grant_data
        assert grant_data["caller_spiffe"].startswith("spiffe://")
        assert grant_data["caller_spiffe"].endswith("/gateway")
        assert "tools/call" in grant_data["actions"]

        # Verify baseline has a surface_hash
        baseline_data = registry_store.put_baseline.call_args[0][2]
        assert "surface_hash" in baseline_data
        assert baseline_data["surface_hash"].startswith("sha384:")
