"""
Unit tests for sklearn model integrity check in SklearnBackend._load_model().

Finding reference: F4 — joblib.load SHA256 integrity guard (ACS scan 2026-05-21).
ASVS V1.14.1, CWE-502.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_joblib(tmp_path: Path) -> tuple[Path, str]:
    """Write a minimal valid joblib file and return (path, sha256_hex)."""
    import joblib
    from sklearn.pipeline import Pipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer()),
        ("clf", LogisticRegression(max_iter=100)),
    ])
    pipe.fit(["hello world", "ignore previous instructions"], ["CLEAN", "INJECTION"])

    model_path = tmp_path / "test_model.joblib"
    joblib.dump(pipe, str(model_path))

    sha256 = hashlib.sha256(model_path.read_bytes()).hexdigest()
    return model_path, sha256


# ---------------------------------------------------------------------------
# Test A — correct hash loads cleanly
# ---------------------------------------------------------------------------

class TestCorrectHashLoads:
    def test_correct_sha256_loads_successfully(self, tmp_path):
        """When the SHA256 matches, the model loads and backend is available."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend

        model_path, sha256 = _make_minimal_joblib(tmp_path)
        backend = SklearnBackend(model_path=str(model_path), expected_sha256=sha256)

        assert backend.available, (
            "SklearnBackend must be available when SHA256 matches"
        )

    def test_correct_sha256_classify_returns_result(self, tmp_path):
        """Backend with correct hash can classify text."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend

        model_path, sha256 = _make_minimal_joblib(tmp_path)
        backend = SklearnBackend(model_path=str(model_path), expected_sha256=sha256)

        result = backend.classify("hello world")
        assert result.label in ("CLEAN", "UNSAFE", "UNCERTAIN")

    def test_empty_expected_sha256_skips_check(self, tmp_path):
        """Empty expected_sha256 disables the check — model loads without verification."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend

        model_path, _ = _make_minimal_joblib(tmp_path)
        # No expected_sha256 → check disabled
        backend = SklearnBackend(model_path=str(model_path), expected_sha256="")

        assert backend.available, (
            "SklearnBackend must be available when expected_sha256 is empty (check disabled)"
        )

    def test_env_var_sha256_takes_effect(self, tmp_path, monkeypatch):
        """SKLEARN_MODEL_SHA256 env-var is used when instance expected_sha256 is empty."""
        from yashigani.inspection.backends import sklearn_backend

        model_path, sha256 = _make_minimal_joblib(tmp_path)

        # Patch the module-level constant to simulate env-var being set
        monkeypatch.setattr(sklearn_backend, "_EXPECTED_MODEL_SHA256", sha256)

        backend = sklearn_backend.SklearnBackend(model_path=str(model_path), expected_sha256="")
        assert backend.available, (
            "SklearnBackend must be available when module-level hash matches"
        )

    def test_instance_sha256_overrides_module_constant(self, tmp_path, monkeypatch):
        """Instance expected_sha256 takes precedence over module-level constant."""
        from yashigani.inspection.backends import sklearn_backend

        model_path, sha256 = _make_minimal_joblib(tmp_path)

        # Set a wrong module-level constant
        monkeypatch.setattr(sklearn_backend, "_EXPECTED_MODEL_SHA256", "wrong_hash_value_12345")

        # Instance-level correct hash should override and succeed
        backend = sklearn_backend.SklearnBackend(
            model_path=str(model_path), expected_sha256=sha256
        )
        assert backend.available, (
            "Instance expected_sha256 must override module-level constant"
        )


# ---------------------------------------------------------------------------
# Test B — wrong hash raises ModelIntegrityError
# ---------------------------------------------------------------------------

class TestWrongHashRaises:
    def test_wrong_sha256_raises_model_integrity_error(self, tmp_path):
        """When the SHA256 does not match, ModelIntegrityError is raised."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend, ModelIntegrityError

        model_path, correct_sha256 = _make_minimal_joblib(tmp_path)
        wrong_hash = "a" * 64  # 64 hex chars, guaranteed wrong

        with pytest.raises(ModelIntegrityError) as exc_info:
            SklearnBackend(model_path=str(model_path), expected_sha256=wrong_hash)

        assert "SHA256 mismatch" in str(exc_info.value)
        assert wrong_hash in str(exc_info.value)

    def test_model_integrity_error_message_contains_paths(self, tmp_path):
        """Error message must include the model path and both expected/actual hashes."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend, ModelIntegrityError

        model_path, correct_sha256 = _make_minimal_joblib(tmp_path)
        wrong_hash = "b" * 64

        with pytest.raises(ModelIntegrityError) as exc_info:
            SklearnBackend(model_path=str(model_path), expected_sha256=wrong_hash)

        error_msg = str(exc_info.value)
        assert wrong_hash in error_msg, "Expected hash must appear in error message"
        assert correct_sha256 in error_msg, "Actual hash must appear in error message"
        assert str(model_path) in error_msg, "Model path must appear in error message"

    def test_wrong_env_var_sha256_raises(self, tmp_path, monkeypatch):
        """SKLEARN_MODEL_SHA256 env-var with wrong value also raises ModelIntegrityError."""
        from yashigani.inspection.backends import sklearn_backend

        model_path, _ = _make_minimal_joblib(tmp_path)
        monkeypatch.setattr(sklearn_backend, "_EXPECTED_MODEL_SHA256", "c" * 64)

        with pytest.raises(sklearn_backend.ModelIntegrityError):
            sklearn_backend.SklearnBackend(model_path=str(model_path), expected_sha256="")

    def test_tampered_model_raises_integrity_error(self, tmp_path):
        """Simulate supply-chain tampering: file modified after hash was computed."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend, ModelIntegrityError

        model_path, original_sha256 = _make_minimal_joblib(tmp_path)

        # Tamper: append a byte to the file
        with open(model_path, "ab") as f:
            f.write(b"\xff")

        # Now the hash of original file no longer matches the tampered file
        with pytest.raises(ModelIntegrityError):
            SklearnBackend(model_path=str(model_path), expected_sha256=original_sha256)

    def test_model_integrity_error_is_not_swallowed(self, tmp_path):
        """ModelIntegrityError must propagate — must NOT be caught and silently degraded."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend, ModelIntegrityError

        model_path, _ = _make_minimal_joblib(tmp_path)

        # The integrity failure must propagate OUT of SklearnBackend.__init__,
        # not be caught and set self._available = False (silent-zombie pattern).
        with pytest.raises(ModelIntegrityError):
            SklearnBackend(model_path=str(model_path), expected_sha256="d" * 64)


# ---------------------------------------------------------------------------
# Test C — missing model file raises FileNotFoundError before hash check
# ---------------------------------------------------------------------------

class TestMissingModelFile:
    def test_missing_file_does_not_raise_when_no_hash(self, tmp_path):
        """Missing model with no expected hash → graceful degradation (available=False)."""
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend

        missing_path = tmp_path / "nonexistent.joblib"
        backend = SklearnBackend(model_path=str(missing_path), expected_sha256="")

        assert not backend.available, (
            "Backend must be unavailable when model file is missing"
        )

    def test_missing_file_with_expected_hash_degrades_gracefully(self, tmp_path):
        """Missing model file + expected hash → graceful degradation, not FileNotFoundError.

        The hash check only runs if the file exists. If the file is missing,
        we degrade gracefully (available=False) regardless of the expected hash.
        This matches the existing behaviour for missing models — the gateway
        falls back to LLM second-pass.
        """
        from yashigani.inspection.backends.sklearn_backend import SklearnBackend

        missing_path = tmp_path / "nonexistent.joblib"
        # Should not raise — file missing is handled before hash check
        backend = SklearnBackend(
            model_path=str(missing_path),
            expected_sha256="e" * 64,
        )
        assert not backend.available


# ---------------------------------------------------------------------------
# Test D — ModelIntegrityError class properties
# ---------------------------------------------------------------------------

class TestModelIntegrityErrorClass:
    def test_model_integrity_error_is_exception(self):
        from yashigani.inspection.backends.sklearn_backend import ModelIntegrityError

        err = ModelIntegrityError("test message")
        assert isinstance(err, Exception)
        assert str(err) == "test message"

    def test_model_integrity_error_can_be_raised_and_caught(self):
        from yashigani.inspection.backends.sklearn_backend import ModelIntegrityError

        with pytest.raises(ModelIntegrityError, match="integrity"):
            raise ModelIntegrityError("model integrity failure")
