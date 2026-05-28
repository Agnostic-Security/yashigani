"""
W1 — manifest signature verification tests (M7) — v2.25.0 P1.

Tests:
  - Enforcement level parsing (fail/warn/skip)
  - Missing signature block in warn mode: no error
  - Missing signature block in fail mode: ManifestSignatureError
  - cosign path: FIPS-mode block raises error
  - cosign path: cosign not found raises ManifestSignatureError (not silently pass)
  - RSA-PSS path: wrong key size (< 3072) raises ManifestSignatureError
  - RSA-PSS path: valid 3072-bit key verifies correctly (unit — no FIPS Provider needed)
  - verify_manifest_signature in skip mode: no error
"""
from __future__ import annotations

import os
import pytest


_VALID_DIGEST = "a" * 64

_BASE_PARSED: dict = {
    "apiVersion": "yashigani.io/v1alpha1",
    "kind": "AgentIntegration",
    "metadata": {"name": "goose", "tenant_id": "acme-corp"},
    "spec": {
        "image": {
            "repository": "ghcr.io/acme/goose",
            "tag": "1.0.0",
            "digest": "sha256:" + _VALID_DIGEST,
        },
    },
}

_MANIFEST_BYTES = b"canonical manifest content for signature testing"


class TestEnforcementLevel:
    def test_skip_mode_no_error(self) -> None:
        from yashigani.manifest.signatures import verify_manifest_signature
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "skip"
        try:
            # Should not raise
            verify_manifest_signature(_MANIFEST_BYTES, _BASE_PARSED)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_warn_mode_missing_sig_no_exception(self) -> None:
        from yashigani.manifest.signatures import verify_manifest_signature
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "warn"
        try:
            # warn mode: missing signature logs a warning but does not raise
            verify_manifest_signature(_MANIFEST_BYTES, _BASE_PARSED)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_fail_mode_missing_sig_raises(self) -> None:
        from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            with pytest.raises(ManifestSignatureError) as exc_info:
                verify_manifest_signature(_MANIFEST_BYTES, _BASE_PARSED)
            assert "no spec.signature" in str(exc_info.value).lower() or "missing" in str(exc_info.value).lower()
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]


class TestCosignPath:
    def test_cosign_blocked_in_fips_mode(self) -> None:
        from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError
        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        os.environ["YASHIGANI_FIPS"] = "1"
        try:
            import copy
            parsed = copy.deepcopy(_BASE_PARSED)
            parsed["spec"]["signature"] = {
                "algorithm": "cosign-bundled-key",
                "signature_hex": "deadbeef" * 16,
            }
            with pytest.raises(ManifestSignatureError) as exc_info:
                verify_manifest_signature(_MANIFEST_BYTES, parsed)
            assert "FIPS" in str(exc_info.value)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]
            del os.environ["YASHIGANI_FIPS"]

    def test_cosign_not_found_raises_not_passes(self) -> None:
        """cosign binary not in PATH must raise ManifestSignatureError, not silently pass."""
        from yashigani.manifest.signatures import _verify_cosign, ManifestSignatureError
        import os as _os
        # Temporarily remove cosign from PATH
        original_path = _os.environ.get("PATH", "")
        _os.environ["PATH"] = "/nonexistent"
        try:
            with pytest.raises(ManifestSignatureError) as exc_info:
                _verify_cosign(b"data", "deadbeef" * 8)
            # Should mention cosign not found or binary not found
            err_msg = str(exc_info.value).lower()
            assert "cosign" in err_msg or "not found" in err_msg
        finally:
            _os.environ["PATH"] = original_path

    def test_invalid_signature_hex_raises(self) -> None:
        from yashigani.manifest.signatures import _verify_cosign, ManifestSignatureError
        with pytest.raises(ManifestSignatureError) as exc_info:
            _verify_cosign(b"data", "not-valid-hex!!!")
        assert "hex" in str(exc_info.value).lower() or "signature" in str(exc_info.value).lower()


class TestRsaPssPath:
    def _generate_rsa_key(self, key_size: int):
        """Generate an RSA key of the given size for testing."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )

    def _sign_with_rsa_pss(self, data: bytes, private_key) -> str:
        """Sign using DIGEST_LENGTH — the FIPS 186-5 §5.4 compliant salt length."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        sig = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()),
                salt_length=padding.PSS.DIGEST_LENGTH,  # FIX-1: FIPS 186-5 §5.4 cap = hLen = 48 bytes
            ),
            hashes.SHA384(),
        )
        return sig.hex()

    def test_rsa_pss_3072_verifies(self) -> None:
        """End-to-end RSA-PSS-3072 verification with a freshly generated key."""
        from yashigani.manifest.signatures import _verify_rsa_pss
        from cryptography.hazmat.primitives import serialization

        private_key = self._generate_rsa_key(3072)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        data = b"canonical manifest bytes"
        sig_hex = self._sign_with_rsa_pss(data, private_key)

        # Should not raise
        _verify_rsa_pss(data, sig_hex, pub_pem)

    def test_rsa_pss_wrong_key_size_rejected(self) -> None:
        """RSA keys smaller than 3072 bits must be rejected (Nico NICO-005 guard)."""
        from yashigani.manifest.signatures import _verify_rsa_pss, ManifestSignatureError
        from cryptography.hazmat.primitives import serialization

        private_key = self._generate_rsa_key(2048)  # too small
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        data = b"canonical manifest bytes"
        sig_hex = self._sign_with_rsa_pss(data, private_key)

        with pytest.raises(ManifestSignatureError) as exc_info:
            _verify_rsa_pss(data, sig_hex, pub_pem)
        assert "3072" in str(exc_info.value)

    def test_rsa_pss_tampered_data_rejected(self) -> None:
        """Tampered manifest bytes must fail signature verification."""
        from yashigani.manifest.signatures import _verify_rsa_pss, ManifestSignatureError
        from cryptography.hazmat.primitives import serialization

        private_key = self._generate_rsa_key(3072)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        data = b"original manifest bytes"
        sig_hex = self._sign_with_rsa_pss(data, private_key)

        # Tamper with the data
        tampered = b"tampered manifest bytes"
        with pytest.raises(ManifestSignatureError) as exc_info:
            _verify_rsa_pss(tampered, sig_hex, pub_pem)
        assert "RSA-PSS" in str(exc_info.value) or "verif" in str(exc_info.value).lower()

    def test_rsa_pss_no_fips_env_logs_warning(self, caplog) -> None:
        """rsa-pss path without YASHIGANI_FIPS logs a warning (not an error)."""
        from yashigani.manifest.signatures import _verify_rsa_pss
        from cryptography.hazmat.primitives import serialization
        import logging

        private_key = self._generate_rsa_key(3072)
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        data = b"manifest data"
        sig_hex = self._sign_with_rsa_pss(data, private_key)

        original = os.environ.pop("YASHIGANI_FIPS", None)
        try:
            with caplog.at_level(logging.WARNING, logger="yashigani.manifest.signatures"):
                _verify_rsa_pss(data, sig_hex, pub_pem)  # should not raise
            # Warning should have been emitted
            assert any("FIPS" in r.message for r in caplog.records)
        finally:
            if original is not None:
                os.environ["YASHIGANI_FIPS"] = original

    def test_fips_public_key_required_for_rsa_path(self) -> None:
        """rsa-pss-3072-sha384 path without fips_public_key_pem raises immediately."""
        from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError
        import copy

        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            parsed = copy.deepcopy(_BASE_PARSED)
            parsed["spec"]["signature"] = {
                "algorithm": "rsa-pss-3072-sha384",
                "signature_hex": "deadbeef" * 16,
            }
            with pytest.raises(ManifestSignatureError) as exc_info:
                verify_manifest_signature(_MANIFEST_BYTES, parsed)
            assert "fips_public_key_pem" in str(exc_info.value)
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]

    def test_unknown_algorithm_rejected(self) -> None:
        """Unknown algorithm string is rejected in fail mode."""
        from yashigani.manifest.signatures import verify_manifest_signature, ManifestSignatureError
        import copy

        os.environ["YSG_REQUIRE_SIGNED_MANIFEST"] = "fail"
        try:
            parsed = copy.deepcopy(_BASE_PARSED)
            parsed["spec"]["signature"] = {
                "algorithm": "sha256withRSA",
                "signature_hex": "deadbeef",
            }
            with pytest.raises(ManifestSignatureError) as exc_info:
                verify_manifest_signature(_MANIFEST_BYTES, parsed)
            assert "unknown" in str(exc_info.value).lower() or "algorithm" in str(exc_info.value).lower()
        finally:
            del os.environ["YSG_REQUIRE_SIGNED_MANIFEST"]
