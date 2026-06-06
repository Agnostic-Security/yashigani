"""Regression: importing ``yashigani.backoffice.state`` must NOT drag in the
backoffice FastAPI app and its module-level Prometheus metrics.

The gateway reaches ``backoffice.state`` via ``licensing.verifier`` and the
credential-exfil alert path (``inspection.pipeline._dispatch_credential_exfil_alert``).
When ``backoffice/__init__.py`` eagerly imported ``app``, app.py registered
``yashigani_backoffice_requests_*`` at module load. If app.py was re-executed
after a partial import, prometheus raised "Duplicated timeseries in
CollectorRegistry" on every exfil detection (logged ERROR, swallowed).

These tests run in fresh interpreters so the assertion is about cold-import
side effects, independent of whatever the pytest session already imported.
"""
import subprocess
import sys


def _run(code: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_importing_state_does_not_register_app_metrics():
    code = (
        "from prometheus_client import REGISTRY\n"
        "import yashigani.backoffice.state  # noqa: F401\n"
        "names = REGISTRY._names_to_collectors\n"
        "leaked = [n for n in ("
        "    'yashigani_backoffice_requests_total',\n"
        "    'yashigani_backoffice_request_duration_seconds',\n"
        "    'yashigani_backoffice_auth_failures_total',\n"
        ") if n in names]\n"
        "assert not leaked, f'app metrics leaked via backoffice.state import: {leaked}'\n"
        "print('OK')\n"
    )
    proc = _run(code)
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "OK" in proc.stdout


def test_lazy_create_backoffice_app_still_importable():
    # The public package-level re-export must keep working via PEP 562 __getattr__.
    code = (
        "from yashigani.backoffice import create_backoffice_app\n"
        "assert callable(create_backoffice_app)\n"
        "print('OK')\n"
    )
    proc = _run(code)
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "OK" in proc.stdout


def test_unknown_package_attr_raises_attributeerror():
    code = (
        "import yashigani.backoffice as b\n"
        "try:\n"
        "    b.does_not_exist\n"
        "except AttributeError:\n"
        "    print('OK')\n"
        "else:\n"
        "    raise SystemExit('expected AttributeError')\n"
    )
    proc = _run(code)
    assert proc.returncode == 0, f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
    assert "OK" in proc.stdout
