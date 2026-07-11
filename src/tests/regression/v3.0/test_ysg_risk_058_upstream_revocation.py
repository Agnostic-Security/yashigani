"""
Regression — YSG-RISK-058 external-MCP-upstream revocation-watch.

Residual closed: a fingerprint pin proves identity continuity but NOT validity.
A revoked-but-unrotated leaf still matches the pinned SHA-256 fingerprint and
was therefore accepted.  These tests prove the revocation-watch overrides a
fingerprint MATCH and BLOCKS when the leaf is:

  * revoked (OCSP cert_status == REVOKED),
  * stale (L2: OCSP next_update in the past / this_update too old),
  * (strict_mode) presents no revocation channel at all,
  * over-age (pin older than max_pin_age with no fresh GOOD verdict).

And does NOT block when the leaf is GOOD with fresh evidence.

Reuses the broker pin machinery (verify_upstream_pin) so the residual is closed
on the live verify path, not just in an isolated checker.

YSG-RISK-058 / Laura external-upstream-revocation threat model (PR #35) / 3.0.
"""
from __future__ import annotations

import datetime
import hashlib

import pytest

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.x509.ocsp import (  # noqa: E402
    OCSPCertStatus,
    OCSPResponseBuilder,
    OCSPResponseStatus,
)

UTC = datetime.timezone.utc


# ---------------------------------------------------------------------------
# Cert + OCSP fixtures (self-contained — no network)
# ---------------------------------------------------------------------------


def _mk_ca():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Upstream CA")])
    now = datetime.datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _mk_leaf(ca_key, ca_cert, *, with_aia=True, with_crl=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "github-mcp.example")])
    now = datetime.datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if with_aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example/r"),
                ),
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://issuer.example/ca.crt"),
                ),
            ]),
            critical=False,
        )
    if with_crl:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://crl.example/c.crl")],
                    relative_name=None, reasons=None, crl_issuer=None,
                )
            ]),
            critical=False,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    return key, cert


def _ocsp_der(ca_key, ca_cert, leaf, *, status, this_update, next_update):
    builder = OCSPResponseBuilder().add_response(
        cert=leaf, issuer=ca_cert, algorithm=hashes.SHA1(),
        cert_status=status,
        this_update=this_update,
        next_update=next_update,
        revocation_time=(this_update if status == OCSPCertStatus.REVOKED else None),
        revocation_reason=None,
    ).responder_id(x509.ocsp.OCSPResponderEncoding.NAME, ca_cert)
    # CertID hash above uses SHA1 (RFC 6960 default, allowed); the RESPONSE
    # signature uses SHA256 (OpenSSL 3.x rejects SHA1 for signatures).
    resp = builder.sign(ca_key, hashes.SHA256())
    assert resp.response_status == OCSPResponseStatus.SUCCESSFUL
    return resp.public_bytes(Encoding.DER)


@pytest.fixture(scope="module")
def pki():
    ca_key, ca_cert = _mk_ca()
    leaf_key, leaf = _mk_leaf(ca_key, ca_cert, with_aia=True)
    return {
        "ca_key": ca_key, "ca_cert": ca_cert,
        "leaf": leaf, "leaf_der": leaf.public_bytes(Encoding.DER),
        "fp": hashlib.sha256(leaf.public_bytes(Encoding.DER)).hexdigest(),
    }


def _fresh_window():
    now = datetime.datetime.now(UTC)
    return now - datetime.timedelta(minutes=1), now + datetime.timedelta(hours=1)


def _stale_window():
    now = datetime.datetime.now(UTC)
    return now - datetime.timedelta(days=3), now - datetime.timedelta(days=1)


# ===========================================================================
# check_revocation unit cases
# ===========================================================================


class TestCheckRevocation:
    def test_good_fresh_does_not_block(self, pki):
        from yashigani.mcp import check_revocation, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.GOOD, this_update=tu, next_update=nu)
        res = check_revocation(
            pki["leaf_der"], issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            _ocsp_fetch=lambda *a, **k: der,
        )
        assert res.status == RevocationStatus.GOOD
        assert res.blocks is False

    def test_revoked_blocks(self, pki):
        from yashigani.mcp import check_revocation, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.REVOKED, this_update=tu, next_update=nu)
        res = check_revocation(
            pki["leaf_der"], issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            _ocsp_fetch=lambda *a, **k: der,
        )
        assert res.status == RevocationStatus.REVOKED
        assert res.blocks is True

    def test_stale_ocsp_blocks(self, pki):
        """L2: a replayed 'good' response past next_update is rejected."""
        from yashigani.mcp import check_revocation, RevocationStatus
        tu, nu = _stale_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.GOOD, this_update=tu, next_update=nu)
        res = check_revocation(
            pki["leaf_der"], issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            _ocsp_fetch=lambda *a, **k: der,
        )
        assert res.status == RevocationStatus.STALE
        assert res.blocks is True

    def test_no_channel_default_does_not_block(self):
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER), config=RevocationConfig(strict_mode=False)
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is False

    def test_no_channel_strict_blocks(self, monkeypatch):
        """Strict-mode in production env refuses an upstream with no revocation channel."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER), config=RevocationConfig(strict_mode=True)
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is True

    def test_over_age_pin_no_good_verdict_blocks(self, pki):
        """Residual bound: an over-age pin with no fresh GOOD verdict fails closed."""
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig

        def _boom(*a, **k):
            raise OSError("ocsp responder unreachable")

        res = check_revocation(
            pki["leaf_der"], issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            pin_age_seconds=48 * 3600,
            config=RevocationConfig(max_pin_age_seconds=24 * 3600),
            _ocsp_fetch=_boom,
        )
        assert res.status == RevocationStatus.PIN_EXPIRED
        assert res.blocks is True

    def test_no_channel_over_age_pin_blocks(self):
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER),
            pin_age_seconds=48 * 3600,
            config=RevocationConfig(strict_mode=False, max_pin_age_seconds=24 * 3600),
        )
        assert res.status == RevocationStatus.PIN_EXPIRED
        assert res.blocks is True


# ===========================================================================
# verify_upstream_pin — revocation overrides a fingerprint MATCH
# ===========================================================================


class TestRevocationOnVerifyPath:
    def _cfg(self, pki):
        from yashigani.mcp import UpstreamPinConfig, PinMode
        return UpstreamPinConfig(
            server_id="github-mcp", host="github-mcp.example", port=443,
            pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=pki["fp"],
        )

    def test_revoked_but_matching_fingerprint_is_blocked(self, pki):
        """THE residual: fingerprint matches, but the leaf is revoked => matched=False."""
        from yashigani.mcp import verify_upstream_pin, REVOKED_LABEL, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.REVOKED, this_update=tu, next_update=nu)
        res = verify_upstream_pin(
            self._cfg(pki),
            _get_fp=lambda h, p, t: pki["fp"],            # fingerprint MATCHES
            _get_der=lambda h, p, t: pki["leaf_der"],
            _check_revocation=lambda d, **k: __import__(
                "yashigani.mcp._upstream_revocation", fromlist=["check_revocation"]
            ).check_revocation(
                d, issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
                _ocsp_fetch=lambda *a, **kk: der, **k),
        )
        assert res.matched is False
        assert res.reason == REVOKED_LABEL
        assert res.revocation_status == RevocationStatus.REVOKED.value

    def test_good_fresh_matching_fingerprint_passes(self, pki):
        from yashigani.mcp import verify_upstream_pin, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.GOOD, this_update=tu, next_update=nu)
        res = verify_upstream_pin(
            self._cfg(pki),
            _get_fp=lambda h, p, t: pki["fp"],
            _get_der=lambda h, p, t: pki["leaf_der"],
            _check_revocation=lambda d, **k: __import__(
                "yashigani.mcp._upstream_revocation", fromlist=["check_revocation"]
            ).check_revocation(
                d, issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
                _ocsp_fetch=lambda *a, **kk: der, **k),
        )
        assert res.matched is True
        assert res.revocation_status == RevocationStatus.GOOD.value

    def test_stale_ocsp_matching_fingerprint_is_blocked(self, pki):
        from yashigani.mcp import verify_upstream_pin, REVOCATION_STALE_LABEL
        tu, nu = _stale_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.GOOD, this_update=tu, next_update=nu)
        res = verify_upstream_pin(
            self._cfg(pki),
            _get_fp=lambda h, p, t: pki["fp"],
            _get_der=lambda h, p, t: pki["leaf_der"],
            _check_revocation=lambda d, **k: __import__(
                "yashigani.mcp._upstream_revocation", fromlist=["check_revocation"]
            ).check_revocation(
                d, issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
                _ocsp_fetch=lambda *a, **kk: der, **k),
        )
        assert res.matched is False
        assert res.reason == REVOCATION_STALE_LABEL

    def test_skip_revocation_preserves_match(self, pki):
        """skip_revocation=True leaves the legacy fingerprint-only behaviour intact."""
        from yashigani.mcp import verify_upstream_pin
        res = verify_upstream_pin(
            self._cfg(pki),
            _get_fp=lambda h, p, t: pki["fp"],
            skip_revocation=True,
        )
        assert res.matched is True
        assert res.revocation_status is None

    def test_fingerprint_mismatch_still_blocks_without_running_watch(self, pki):
        """A mismatch is blocked by the pin BEFORE the watch runs (no regression)."""
        from yashigani.mcp import verify_upstream_pin, CERT_PIN_MISMATCH_LABEL
        res = verify_upstream_pin(
            self._cfg(pki),
            _get_fp=lambda h, p, t: "0" * 64,   # MISMATCH
        )
        assert res.matched is False
        assert res.reason == CERT_PIN_MISMATCH_LABEL
        assert res.revocation_status is None

    def test_strict_no_channel_blocks_on_verify_path(self, monkeypatch):
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        from yashigani.mcp import (
            verify_upstream_pin, UpstreamPinConfig, PinMode,
            RevocationConfig, REVOCATION_NO_CHANNEL_LABEL,
        )
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        leaf_der = leaf.public_bytes(Encoding.DER)
        fp = hashlib.sha256(leaf_der).hexdigest()
        cfg = UpstreamPinConfig(
            server_id="legacy-mcp", host="legacy.example", port=443,
            pin_mode=PinMode.CERT_FINGERPRINT, cert_fingerprint_sha256=fp,
        )
        res = verify_upstream_pin(
            cfg,
            _get_fp=lambda h, p, t: fp,
            _get_der=lambda h, p, t: leaf_der,
            revocation_config=RevocationConfig(strict_mode=True),
        )
        assert res.matched is False
        assert res.reason == REVOCATION_NO_CHANNEL_LABEL


# ===========================================================================
# Strict-by-default + env-gated NO_CHANNEL enforcement (3.1-fix)
# ===========================================================================


class TestStrictByDefault:
    """
    Tests for the strict-by-default posture introduced in v3.1-fix.

    Key invariants:
    - RevocationConfig() defaults to strict_mode=True.
    - In production/staging (YASHIGANI_ENV enforcing): NO_CHANNEL blocks.
    - In dev/test (YASHIGANI_ENV unset or non-enforcing): NO_CHANNEL is warn-only.
    - REVOKED and STALE block unconditionally in ALL environments.
    - Operator override YASHIGANI_MCP_REVOCATION_STRICT=false allows NO_CHANNEL
      even in production (self-signed upstream; residual bounded by max_pin_age).
    """

    def test_strict_mode_default_is_true(self):
        """RevocationConfig() must default to strict_mode=True (changed in v3.1-fix)."""
        from yashigani.mcp import RevocationConfig
        assert RevocationConfig().strict_mode is True

    def test_env_default_strict_is_true(self, monkeypatch):
        """_config_from_env() with YASHIGANI_MCP_REVOCATION_STRICT unset returns True."""
        monkeypatch.delenv("YASHIGANI_MCP_REVOCATION_STRICT", raising=False)
        from yashigani.mcp._upstream_revocation import _config_from_env
        cfg = _config_from_env()
        assert cfg.strict_mode is True

    def test_no_channel_strict_prod_env_blocks(self, monkeypatch):
        """Production + strict_mode=True + NO_CHANNEL → blocks=True (hard block)."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER),
            config=RevocationConfig(strict_mode=True),
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is True

    def test_no_channel_strict_staging_env_blocks(self, monkeypatch):
        """Staging + strict_mode=True + NO_CHANNEL → blocks=True."""
        monkeypatch.setenv("YASHIGANI_ENV", "staging")
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER),
            config=RevocationConfig(strict_mode=True),
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is True

    def test_no_channel_strict_dev_env_warns_not_blocks(self, monkeypatch):
        """Dev env + strict_mode=True + NO_CHANNEL → warn-only, blocks=False."""
        monkeypatch.setenv("YASHIGANI_ENV", "development")
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER),
            config=RevocationConfig(strict_mode=True),
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is False

    def test_no_channel_strict_unset_env_warns_not_blocks(self, monkeypatch):
        """Unset YASHIGANI_ENV + strict_mode=True → warn-only (dev posture)."""
        monkeypatch.delenv("YASHIGANI_ENV", raising=False)
        from yashigani.mcp import check_revocation, RevocationStatus, RevocationConfig
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(
            leaf.public_bytes(Encoding.DER),
            config=RevocationConfig(strict_mode=True),
        )
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is False

    def test_env_override_false_allows_no_channel_in_prod(self, monkeypatch):
        """Operator override: YASHIGANI_MCP_REVOCATION_STRICT=false in production → allowed."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        monkeypatch.setenv("YASHIGANI_MCP_REVOCATION_STRICT", "false")
        from yashigani.mcp import check_revocation, RevocationStatus
        from yashigani.mcp._upstream_revocation import _config_from_env
        cfg = _config_from_env()
        assert cfg.strict_mode is False
        ca_key, ca_cert = _mk_ca()
        _, leaf = _mk_leaf(ca_key, ca_cert, with_aia=False, with_crl=False)
        res = check_revocation(leaf.public_bytes(Encoding.DER), config=cfg)
        assert res.status == RevocationStatus.NO_CHANNEL
        assert res.blocks is False

    def test_revoked_blocks_in_dev_env(self, monkeypatch, pki):
        """REVOKED blocks in dev — not env-gated (belt-and-suspenders)."""
        monkeypatch.setenv("YASHIGANI_ENV", "development")
        from yashigani.mcp import check_revocation, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.REVOKED, this_update=tu, next_update=nu)
        res = check_revocation(
            pki["leaf_der"],
            issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            _ocsp_fetch=lambda *a, **k: der,
        )
        assert res.status == RevocationStatus.REVOKED
        assert res.blocks is True

    def test_revoked_blocks_in_prod_env(self, monkeypatch, pki):
        """REVOKED blocks in production — unconditional."""
        monkeypatch.setenv("YASHIGANI_ENV", "production")
        from yashigani.mcp import check_revocation, RevocationStatus
        tu, nu = _fresh_window()
        der = _ocsp_der(pki["ca_key"], pki["ca_cert"], pki["leaf"],
                        status=OCSPCertStatus.REVOKED, this_update=tu, next_update=nu)
        res = check_revocation(
            pki["leaf_der"],
            issuer_der=pki["ca_cert"].public_bytes(Encoding.DER),
            _ocsp_fetch=lambda *a, **k: der,
        )
        assert res.status == RevocationStatus.REVOKED
        assert res.blocks is True

    def test_enforce_envs_set_is_single_source(self):
        """Broker._ENFORCE_PIN_ENVS and _upstream_revocation._ENFORCE_ENVS are the same object."""
        from yashigani.mcp._upstream_revocation import _ENFORCE_ENVS
        from yashigani.mcp.broker import McpBroker
        assert McpBroker._ENFORCE_PIN_ENVS is _ENFORCE_ENVS
