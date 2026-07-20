"""
Regression tests — 3 real (PoC-proven) CodeQL findings from the public-repo
code-scanning triage (2026-07-19), fix/codescan-triage-20260719.

  #1870 py/stack-trace-exposure       — backoffice/routes/dashboard.py
  #1900 py/polynomial-redos           — backoffice/routes/sensitivity.py
  #1874 py/clear-text-storage TOCTOU  — secrets/rotator.py

Each test pins the fix so the original bug re-fails this file if reverted.
"""
from __future__ import annotations

import os
import stat
import threading

import pytest
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# #1870 — dashboard.py services_health(): OPA-unreachable branch must never
# put str(exc) into the JSON response body (client-facing `services[].detail`).
# Fixed upstream on this line via safe_error_envelope() (commit ea2e9f01,
# 2026-07-11) — this test pins that the *pattern* stays fixed even though the
# public alert (#1870) was raised against a snapshot predating that commit.
# ---------------------------------------------------------------------------
class TestStackTraceExposureDashboardOPA:
    def test_opa_unreachable_response_has_no_exception_text(self):
        from yashigani.common.error_envelope import safe_error_envelope

        services: list[dict] = []

        def _add(name: str, status_val: str, detail: str = "") -> None:
            entry: dict = {"name": name, "status": status_val}
            if detail:
                entry["detail"] = detail
            services.append(entry)

        # Realistic failure: OPA unreachable at an internal-only mesh hostname.
        exc = ConnectionRefusedError(
            "[Errno 111] Connection refused: "
            "('opa-internal.yashigani-mesh.svc.cluster.local', 8181)"
        )
        try:
            raise exc
        except Exception as caught:
            # Exact call made at dashboard.py services_health() OPA branch.
            payload, _ = safe_error_envelope(
                caught, public_message="opa health check failed", status=500
            )
            _add("opa", "degraded", payload["error"])

        body = str(services)
        assert "opa-internal.yashigani-mesh.svc.cluster.local" not in body
        assert "Connection refused" not in body
        assert services[0]["detail"] == "opa health check failed"

    def test_dashboard_source_has_no_raw_str_exc_in_services_health(self):
        """Structural guard: no `str(exc)` reaches _add(...) anywhere in the
        services_health handler — every except-branch must route through
        safe_error_envelope()."""
        import inspect
        from yashigani.backoffice.routes import dashboard

        src = inspect.getsource(dashboard.services_health)
        assert "str(exc)" not in src
        assert "str(caught)" not in src


# ---------------------------------------------------------------------------
# #1900 — sensitivity.py _validate_regex_safety(): hard length cap must be
# the FIRST check, so it protects BOTH the length-capped PatternRequest.pattern
# field AND the unbounded LLM-generated `generated_regex` fed in by
# generate_pattern() (which has no field-level max_length of its own).
# ---------------------------------------------------------------------------
class TestReDoSLengthCapIsCallerIndependent:
    def test_oversized_pattern_rejected_fast(self):
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        payload = "(" + "+" * 100_000  # simulates unbounded generated_regex
        import time

        t0 = time.perf_counter()
        with pytest.raises(HTTPException) as exc_info:
            _validate_regex_safety(payload)
        dt = time.perf_counter() - t0

        assert exc_info.value.status_code == 422
        assert exc_info.value.detail.get("error") == "pattern_too_long"
        # Must be rejected in well under the multi-second polynomial blowup
        # the raw heuristic exhibits on this input (proven ~3.1s @ n=100000
        # in the pre-fix PoC) — length check runs before regex ever executes.
        assert dt < 0.05, f"expected near-instant rejection, took {dt:.3f}s"

    def test_max_length_boundary_is_512(self):
        from yashigani.backoffice.routes.sensitivity import _MAX_REGEX_PATTERN_LEN

        assert _MAX_REGEX_PATTERN_LEN == 512

    def test_length_cap_is_first_check_before_redos_heuristic(self):
        """Structural guard: the length-cap raise must appear before the
        _REDOS_NESTED_RE.search() call in source order, so it is unconditionally
        evaluated first regardless of caller."""
        import inspect
        from yashigani.backoffice.routes import sensitivity

        src = inspect.getsource(sensitivity._validate_regex_safety)
        len_check_pos = src.index("pattern_too_long")
        redos_check_pos = src.index("_REDOS_NESTED_RE.search")
        assert len_check_pos < redos_check_pos

    def test_safe_pattern_under_cap_still_accepted(self):
        from yashigani.backoffice.routes.sensitivity import _validate_regex_safety

        # Should not raise.
        _validate_regex_safety(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    def test_generate_pattern_route_has_no_length_bypass(self):
        """generate_pattern() must call the shared _validate_regex_safety()
        (not a bespoke/duplicated check) so the unbounded LLM regex always
        passes through the length cap."""
        import inspect
        from yashigani.backoffice.routes import sensitivity

        src = inspect.getsource(sensitivity.generate_pattern)
        assert "_validate_regex_safety(generated_regex)" in src


# ---------------------------------------------------------------------------
# #1874 — rotator.py _write_secret_file(): the temp file must be created
# with restrictive permissions ATOMICALLY (os.open with O_CREAT|O_EXCL and
# the mode argument) — no window where write_text()+later-chmod() leaves the
# plaintext secret group/world-readable under a permissive process umask.
# ---------------------------------------------------------------------------
class TestSecretFileWriteNoTOCTOUWindow:
    def test_tmp_file_never_observed_permissive_during_write(self, tmp_path):
        from yashigani.secrets.rotator import _write_secret_file

        target = tmp_path / "postgres_password"
        tmp_file = target.parent / (target.name + ".tmp")

        old_umask = os.umask(0o022)  # typical default container/host umask
        observed_modes: list[int] = []
        stop = threading.Event()

        def poll_tmp_mode() -> None:
            while not stop.is_set():
                try:
                    observed_modes.append(stat.S_IMODE(tmp_file.stat().st_mode))
                except FileNotFoundError:
                    pass

        poller = threading.Thread(target=poll_tmp_mode, daemon=True)
        poller.start()
        try:
            _write_secret_file(target, "S3cr3t-Postgres-Password-DO-NOT-LEAK", mode=0o400)
        finally:
            stop.set()
            poller.join(timeout=2)
            os.umask(old_umask)

        permissive = [m for m in observed_modes if m & 0o077]
        assert not permissive, (
            f"TOCTOU regression: tmp file observed group/other-readable: "
            f"{[oct(m) for m in permissive]}"
        )
        assert stat.S_IMODE(target.stat().st_mode) == 0o400

    def test_source_uses_atomic_open_not_write_text_then_chmod(self):
        """Structural guard: the create+permission-set must be a single
        os.open(..., O_CREAT|O_EXCL, mode) syscall, not write_text() followed
        by a separate chmod()."""
        import inspect
        from yashigani.secrets.rotator import _write_secret_file

        src = inspect.getsource(_write_secret_file)
        assert "os.O_EXCL" in src
        assert "os.open(" in src
        assert "tmp_path.write_text(" not in src

    def test_stale_tmp_file_does_not_break_rotation(self, tmp_path):
        """A leftover .tmp from a prior interrupted rotation must not cause
        O_EXCL to fail the next legitimate write."""
        from yashigani.secrets.rotator import _write_secret_file

        target = tmp_path / "jwt_signing_key"
        tmp_file = target.parent / (target.name + ".tmp")
        tmp_file.write_text("stale-partial-write-from-a-crashed-run")

        _write_secret_file(target, "fresh-value")

        assert target.read_text() == "fresh-value"
        assert not tmp_file.exists()

    def test_group_readable_mode_still_applied_correctly(self, tmp_path):
        """mode=0o640 (redis/postgres passwords, GID 999 consumers) still
        ends up as the final on-disk mode under the atomic-create path."""
        from yashigani.secrets.rotator import _write_secret_file

        target = tmp_path / "redis_password"
        _write_secret_file(target, "group-readable-secret", mode=0o640)
        assert stat.S_IMODE(target.stat().st_mode) == 0o640
