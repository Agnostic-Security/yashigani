"""
Offline self-check suite for the authenticate-once, attack-many,
multi-identity pentest harness (QA-SOP §4.17).

This is a HARNESS BUILD verification suite, not a live pentest run: no
network I/O touches a real Yashigani stack anywhere in this file. Live
traffic is simulated via ``httpx.MockTransport``. What this DOES prove,
this session:

  - the harness imports cleanly (module-level import errors would fail
    collection immediately);
  - the standalone TOTP mint function is byte-for-byte identical to the
    real ``yashigani.auth.totp._totp_at`` across a range of secrets /
    timestamps / algorithms — guards against the exact drift class in
    ``project_v412_release_gate_probe_totp_regression.md``;
  - the fresh-OTP anti-replay logic actually waits for a new window rather
    than fabricating/reusing a code;
  - identity config loading + lane partition + the five-point
    authorisation-boundary gate + the output-dir git-repo guard all behave
    correctly on both the accept and refuse paths;
  - ``AuthenticatedSession.login()`` sends the correct real-login request
    shape and handles success / 401 / restricted-provisioning / unreachable
    -target outcomes distinctly (unreachable-target fails GRACEFULLY with a
    clear message, never a bare traceback — the dispatch brief's explicit
    "no target" requirement);
  - each probe function's PASS/FAIL logic is correct against crafted
    responses (not "always green");
  - the cross-identity divergence detector actually fires when it should;
  - the CLI's ``--dry-run`` path and its unauthorised-target abort path both
    behave correctly with NO network traffic.

What still needs a live stack (explicitly NOT covered here, per the
dispatch brief's "no live stack needed yet"): real login against a running
backoffice, a live ZAP daemon, live probe verdicts against real endpoints.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import httpx
import pytest

# NOT a relative (`from .pentest_harness import ...`) import: this repo's own
# tests/conformance/conftest.py docstring documents (and this session
# independently re-confirmed empirically, under pytest 9.1.1 default
# "prepend" import-mode) that pytest's per-directory package-detection for
# cross-module imports is unreliable here — `tests/` itself has no
# `__init__.py`, so `tests/security/test_*.py` collects WITHOUT a resolvable
# parent package, and `from .pentest_harness import x` raises "attempted
# relative import with no known parent package" at collection time even
# though `tests/security/__init__.py` exists. Bootstrapping `pentest_harness`
# onto sys.path as a top-level package (its own `__init__.py` makes it a real
# package once found) sidesteps pytest's import-mode entirely and is stable
# regardless of how this suite is invoked (`pytest tests/security/...` from
# the repo root, a CI runner, or a leg's own venv).
_HARNESS_PARENT_DIR = str(Path(__file__).parent)
if _HARNESS_PARENT_DIR not in sys.path:
    sys.path.insert(0, _HARNESS_PARENT_DIR)

from pentest_harness import probes as probes_mod
from pentest_harness import zap_driver as zap_driver_mod
from pentest_harness.findings import Finding, FindingsWriter
from pentest_harness.identities import (
    Identity,
    IdentityConfigError,
    load_identities_config,
)
from pentest_harness.probes import ProbeTarget, cross_identity_isolation_matrix
from pentest_harness.session import (
    AuthenticatedSession,
    AuthenticationFailed,
    AuthFlowIncomplete,
    TargetUnreachable,
)
from pentest_harness.target import (
    OutputLocationNotAllowed,
    TargetNotAuthorised,
    assert_target_authorised,
    validate_output_dir,
)
from pentest_harness.totp import TotpSpec, mint_fresh_totp_code, mint_totp_code

_CONFIG_DIR = Path(__file__).parent / "pentest_harness" / "config"
_EXAMPLE_IDENTITIES = _CONFIG_DIR / "identities.example.yaml"
_EXAMPLE_PROBE_TARGETS = _CONFIG_DIR / "probe_targets.example.yaml"


# ---------------------------------------------------------------------------
# TOTP parity + anti-replay
# ---------------------------------------------------------------------------


def test_totp_mint_matches_real_source():
    """Cross-checks totp.mint_totp_code against the REAL
    yashigani.auth.totp._totp_at across secrets/timestamps/algorithms —
    catches drift the moment the product's algorithm changes, rather than
    silently minting wrong codes in a live leg (the exact
    release_gate_probe.sh regression class)."""
    real_totp = pytest.importorskip("yashigani.auth.totp")

    secrets = ["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "AAAAAAAAAAAAAAAA"]
    timestamps = [0, 1_700_000_000, int(time.time())]
    combos = [
        ("SHA1", 6),
        ("SHA256", 6),
        ("SHA512", 8),
    ]
    checked = 0
    for secret in secrets:
        for ts in timestamps:
            for algo, digits in combos:
                expected = real_totp._totp_at(secret, ts, algo, digits)
                spec = TotpSpec(secret_b32=secret, algorithm=algo, digits=digits)
                actual = mint_totp_code(spec, at_ts=ts)
                assert actual == expected, f"drift: secret={secret} ts={ts} algo={algo} digits={digits}"
                checked += 1
    assert checked == len(secrets) * len(timestamps) * len(combos)


def test_totp_mint_rejects_unsupported_algorithm():
    with pytest.raises(ValueError):
        mint_totp_code(TotpSpec(secret_b32="JBSWY3DPEHPK3PXP", algorithm="MD5", digits=6))


def test_totp_fresh_code_waits_for_new_window_not_fabricated():
    """Verifies the anti-replay path actually SLEEPS to the next window
    boundary (via an injected fake sleeper — no real wall-clock wait in this
    test) rather than returning the same/possibly-reused code."""
    from pentest_harness.totp import current_window_start  # local import, avoids top-level churn

    spec = TotpSpec(secret_b32="JBSWY3DPEHPK3PXP", algorithm="SHA256", digits=6)
    now = 1_700_000_010.0 + 5  # 5s into the [1700000010, 1700000040) window
    previous_code = mint_totp_code(spec, at_ts=int(now))
    next_window_start = current_window_start(now, period=30) + 30

    slept_for: list[float] = []

    def fake_sleeper(seconds: float) -> None:
        slept_for.append(seconds)

    # Monkeypatch time.time via a small shim: mint_fresh_totp_code reads
    # time.time() internally twice (once to decide, once after "sleeping").
    # We simulate the window boundary crossing by patching time.time to
    # advance past the boundary once the fake sleeper has been invoked.
    import time as time_mod

    state = {"calls": 0}
    real_time = time_mod.time

    def fake_time():
        state["calls"] += 1
        if state["calls"] == 1:
            return now  # first read: still inside the same window as previous_code
        return next_window_start + 1  # after "sleeping": safely into the NEXT window
    try:
        time_mod.time = fake_time
        fresh_code = mint_fresh_totp_code(spec, not_equal_to=previous_code, sleeper=fake_sleeper)
    finally:
        time_mod.time = real_time

    assert slept_for, "expected mint_fresh_totp_code to sleep to the next window boundary"
    assert fresh_code != previous_code


def test_totp_fresh_code_returns_immediately_if_already_new_window():
    spec = TotpSpec(secret_b32="JBSWY3DPEHPK3PXP", algorithm="SHA512", digits=8)
    called = []
    code = mint_fresh_totp_code(spec, not_equal_to="00000000", sleeper=lambda s: called.append(s))
    assert len(code) == 8
    assert not called, "should not sleep when the current code already differs"


# ---------------------------------------------------------------------------
# Identity config + lane partition
# ---------------------------------------------------------------------------


def test_load_example_identities_config_and_lanes():
    cfg = load_identities_config(_EXAMPLE_IDENTITIES)
    assert cfg.base_url == "https://localhost"
    assert set(cfg.identities) == {"admin1", "admin2", "user1", "user2"}

    admin1 = cfg.identities["admin1"]
    assert admin1.tier == "admin"
    assert admin1.algorithm == "SHA512"  # tier default, never assumed elsewhere
    assert admin1.digits == 8

    user1 = cfg.identities["user1"]
    assert user1.algorithm == "SHA256"
    assert user1.digits == 6

    pass1 = cfg.resolve_lane("pass1")
    assert {i.name for i in pass1} == {"admin2", "user2"}
    pass2 = cfg.resolve_lane("pass2")
    assert {i.name for i in pass2} == {"admin1", "user1"}
    # Identity PARTITION (Rule 5): the two passes must be disjoint.
    assert {i.name for i in pass1}.isdisjoint({i.name for i in pass2})


def test_identity_config_explicit_algorithm_override_is_honoured():
    """'read the actual algorithm from the code/URI, don't assume' — an
    identity config MAY override the tier default; the harness must honour
    the override, not silently coerce back to the tier default."""
    from pentest_harness.identities import _build_identity

    ident = _build_identity("weird-admin", {
        "username": "weird",
        "password": "x",
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "tier": "admin",
        "algorithm": "SHA256",  # explicit override away from the SHA512 admin default
        "digits": 6,
    })
    assert ident.algorithm == "SHA256"
    assert ident.digits == 6


def test_resolve_unknown_lane_raises():
    cfg = load_identities_config(_EXAMPLE_IDENTITIES)
    with pytest.raises(IdentityConfigError):
        cfg.resolve_lane("does-not-exist")


def test_load_missing_config_raises_clear_error(tmp_path):
    with pytest.raises(IdentityConfigError):
        load_identities_config(tmp_path / "nope.yaml")


def test_load_config_missing_required_field_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "base_url: https://localhost\nidentities:\n  a:\n    username: a\n"
    )  # missing password/totp_secret/tier
    with pytest.raises(IdentityConfigError):
        load_identities_config(bad)


# ---------------------------------------------------------------------------
# Authorisation boundary + output-dir guard
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "base_url",
    ["https://localhost", "http://127.0.0.1:8443", "https://yashigani.local", "https://192.168.64.2"],
)
def test_authorised_targets_pass(base_url):
    assert_target_authorised(base_url)  # must not raise


@pytest.mark.parametrize(
    "base_url",
    ["https://example.com", "https://evil.attacker.invalid", "http://8.8.8.8", "not-a-url"],
)
def test_unauthorised_targets_refused(base_url):
    with pytest.raises(TargetNotAuthorised):
        assert_target_authorised(base_url)


def test_output_dir_inside_git_repo_refused():
    repo_root = Path(__file__).parents[2]  # tests/security/.. -> repo root
    with pytest.raises(OutputLocationNotAllowed):
        validate_output_dir(repo_root / "some" / "path")


def test_output_dir_outside_git_repo_accepted(tmp_path):
    outside = tmp_path / "testing_runs" / "yashigani" / "run-1"
    resolved = validate_output_dir(outside)
    assert resolved.is_dir()


# ---------------------------------------------------------------------------
# AuthenticatedSession — mocked-transport login
# ---------------------------------------------------------------------------


def _admin_identity(algorithm="SHA512", digits=8) -> Identity:
    return Identity(
        name="admin2",
        username="admin2",
        password="correct-horse-battery-staple",
        totp_secret="JBSWY3DPEHPK3PXP",
        tier="admin",
        algorithm=algorithm,
        digits=digits,
        expected_role="admin",
        expected_policies=("POL-001",),
    )


def test_login_success_sets_cookie_and_sends_correct_code():
    identity = _admin_identity()
    expected_code = mint_totp_code(identity.totp_spec())
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            body = json.loads(request.content)
            captured["body"] = body
            assert body["totp_code"] == expected_code
            assert len(body["totp_code"]) == 8  # admin tier -> 8 digits
            return httpx.Response(
                200,
                json={"status": "ok", "force_password_change": False, "force_totp_provision": False},
                headers={"set-cookie": "__Host-yashigani_admin_session=real-token-abc; Path=/; Secure; HttpOnly"},
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    session = AuthenticatedSession(identity, base_url="https://localhost", transport=transport)
    result = session.login()
    assert result.status == "ok"
    assert session.session_cookie_value() == "real-token-abc"
    assert captured["body"]["username"] == "admin2"


def test_login_401_raises_authentication_failed():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_credentials"})

    session = AuthenticatedSession(
        identity, base_url="https://localhost", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(AuthenticationFailed):
        session.login()


def test_login_restricted_provisioning_status_raises_auth_flow_incomplete():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"status": "admin_password_change_required", "force_password_change": True},
            headers={"set-cookie": "__Host-yashigani_admin_session=restricted-token; Path=/; Secure; HttpOnly"},
        )

    session = AuthenticatedSession(
        identity, base_url="https://localhost", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(AuthFlowIncomplete):
        session.login()


def test_login_unreachable_target_fails_gracefully_not_traceback():
    """The dispatch brief's explicit requirement: a dry-run against a
    mocked/absent target must fail gracefully with a clear message, not a
    raw traceback. Simulated here via a transport that raises
    httpx.ConnectError, exactly what a real unreachable host produces."""
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused (simulated no-target)", request=request)

    session = AuthenticatedSession(
        identity, base_url="https://localhost", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(TargetUnreachable) as excinfo:
        session.login()
    assert "LAURA_HARNESS" in str(excinfo.value)
    assert "no target reachable" in str(excinfo.value)


def test_construct_session_with_unauthorised_base_url_refuses_before_any_request():
    identity = _admin_identity()
    with pytest.raises(TargetNotAuthorised):
        AuthenticatedSession(identity, base_url="https://not-ours.example.com")


def test_stepup_mints_code_different_from_login_code():
    identity = _admin_identity()
    login_code_holder = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/login":
            body = json.loads(request.content)
            login_code_holder["code"] = body["totp_code"]
            return httpx.Response(
                200,
                json={"status": "ok", "force_password_change": False, "force_totp_provision": False},
                headers={"set-cookie": "__Host-yashigani_admin_session=tok; Path=/; Secure; HttpOnly"},
            )
        if request.url.path == "/auth/stepup":
            body = json.loads(request.content)
            assert body["totp_code"] != login_code_holder["code"], "stepup must not reuse the login TOTP code"
            return httpx.Response(200, json={"status": "ok", "stepup_verified": True})
        return httpx.Response(404)

    session = AuthenticatedSession(
        identity, base_url="https://localhost", transport=httpx.MockTransport(handler)
    )
    session.login()
    result = session.stepup()
    assert result["stepup_verified"] is True


# ---------------------------------------------------------------------------
# Probes — PASS/FAIL logic against crafted responses (never "always green")
# ---------------------------------------------------------------------------


def _session_with_handler(identity: Identity, handler) -> AuthenticatedSession:
    session = AuthenticatedSession(identity, base_url="https://localhost", transport=httpx.MockTransport(handler))
    return session


def test_probe_sqli_canary_fails_on_db_error_leak():
    identity = _admin_identity()
    target = ProbeTarget(
        name="t", method="POST", path="/admin/rbac/lookup", body_template={"field": ""}, injectable_field="field"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="asyncpg.exceptions.SyntaxOrAccessError: syntax error at or near")

    session = _session_with_handler(identity, handler)
    finding = probes_mod.probe_sqli_canary(session, target)
    assert finding.verdict == "FAIL"
    assert finding.severity == "High"


def test_probe_sqli_canary_passes_on_generic_rejection():
    identity = _admin_identity()
    target = ProbeTarget(
        name="t", method="POST", path="/admin/rbac/lookup", body_template={"field": ""}, injectable_field="field"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"error": "invalid_input"})

    session = _session_with_handler(identity, handler)
    finding = probes_mod.probe_sqli_canary(session, target)
    assert finding.verdict == "PASS"


def test_probe_xss_canary_fails_on_unescaped_reflection():
    identity = _admin_identity()
    target = ProbeTarget(
        name="t", method="POST", path="/admin/audit/search", body_template={"query": ""}, injectable_field="query"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html='<div><script>alert(document.domain)</script></div>')

    session = _session_with_handler(identity, handler)
    finding = probes_mod.probe_xss_canary(session, target)
    assert finding.verdict == "FAIL"


def test_probe_totp_replay_passes_when_second_login_rejected():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_credentials"})

    session = _session_with_handler(identity, handler)
    session._last_totp_code = "12345678"
    finding = probes_mod.probe_totp_replay(session)
    assert finding.verdict == "PASS"


def test_probe_totp_replay_fails_when_replay_accepted():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "ok"})

    session = _session_with_handler(identity, handler)
    session._last_totp_code = "12345678"
    finding = probes_mod.probe_totp_replay(session)
    assert finding.verdict == "FAIL"
    assert finding.severity == "Critical"


def test_probe_session_replay_passes_on_401_after_logout():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/logout":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(401, json={"error": "no_session"})

    session = _session_with_handler(identity, handler)
    session.client.cookies.set("__Host-yashigani_admin_session", "captured-token")
    finding = probes_mod.probe_session_replay(session)
    assert finding.verdict == "PASS"


def test_probe_session_replay_fails_if_replay_accepted():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/logout":
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"status": "still_authenticated"})

    session = _session_with_handler(identity, handler)
    session.client.cookies.set("__Host-yashigani_admin_session", "captured-token")
    finding = probes_mod.probe_session_replay(session)
    assert finding.verdict == "FAIL"
    assert finding.severity == "Critical"


def test_probe_idor_cross_identity_passes_on_403():
    admin = _admin_identity()
    victim = _admin_identity()
    target = ProbeTarget(
        name="t", method="GET", path="/user/conversations/{resource_id}", resource_id_field="resource_id"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": "forbidden"})

    attacker_session = _session_with_handler(admin, handler)
    victim_session = _session_with_handler(victim, handler)
    finding = probes_mod.probe_idor_cross_identity(attacker_session, victim_session, target, "victim-resource-1")
    assert finding.verdict == "PASS"
    assert finding.counterpart_identity == victim.name


def test_probe_idor_cross_identity_fails_on_200():
    admin = _admin_identity()
    victim = _admin_identity()
    target = ProbeTarget(
        name="t", method="GET", path="/user/conversations/{resource_id}", resource_id_field="resource_id"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "victim's private data"})

    attacker_session = _session_with_handler(admin, handler)
    victim_session = _session_with_handler(victim, handler)
    finding = probes_mod.probe_idor_cross_identity(attacker_session, victim_session, target, "victim-resource-1")
    assert finding.verdict == "FAIL"
    assert finding.severity == "Critical"


def test_probe_security_headers_baseline_fails_on_missing_headers():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"server": "nginx/1.2.3"})

    session = _session_with_handler(identity, handler)
    target = ProbeTarget(name="t", method="GET", path="/dashboard")
    finding = probes_mod.probe_security_headers_baseline(session, target)
    assert finding.verdict == "FAIL"


def test_probe_security_headers_baseline_passes_on_full_baseline():
    identity = _admin_identity()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-security-policy": "default-src 'self'",
                "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
            },
        )

    session = _session_with_handler(identity, handler)
    target = ProbeTarget(name="t", method="GET", path="/dashboard")
    finding = probes_mod.probe_security_headers_baseline(session, target)
    assert finding.verdict == "PASS"


def test_cross_identity_isolation_matrix_flags_policy_divergence():
    admin_high = _admin_identity()
    admin_low = Identity(
        name="admin-low",
        username="admin-low",
        password="pw",
        totp_secret="JBSWY3DPEHPK3PXP",
        tier="admin",
        algorithm="SHA512",
        digits=8,
        expected_role="admin",
        expected_policies=("POL-002",),  # DIFFERENT policy set from admin_high
    )

    def always_200(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": "resource"})  # both get 200 — divergence expected but absent

    sessions = {
        "admin2": _session_with_handler(admin_high, always_200),
        "admin-low": _session_with_handler(admin_low, always_200),
    }
    target = ProbeTarget(name="t", method="GET", path="/user/conversations/{resource_id}", resource_id_field="resource_id")
    resource_probes = [(target, {"admin2": "res-a", "admin-low": "res-b"})]

    findings = cross_identity_isolation_matrix(sessions, resource_probes)
    divergence_findings = [f for f in findings if f.probe_class == "policy_divergence_suspected"]
    assert divergence_findings, "expected a policy-divergence finding when differing-policy identities get identical outcomes"
    assert all(f.verdict == "FAIL" for f in divergence_findings)


def test_cross_identity_isolation_matrix_no_divergence_when_outcomes_differ():
    admin_high = _admin_identity()
    admin_low = Identity(
        name="admin-low",
        username="admin-low",
        password="pw",
        totp_secret="JBSWY3DPEHPK3PXP",
        tier="admin",
        algorithm="SHA512",
        digits=8,
        expected_role="admin",
        expected_policies=("POL-002",),
    )

    def handler_factory(status_code: int):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status_code, json={})
        return handler

    sessions = {
        "admin2": _session_with_handler(admin_high, handler_factory(403)),
        "admin-low": _session_with_handler(admin_low, handler_factory(404)),
    }
    target = ProbeTarget(name="t", method="GET", path="/user/conversations/{resource_id}", resource_id_field="resource_id")
    resource_probes = [(target, {"admin2": "res-a", "admin-low": "res-b"})]

    findings = cross_identity_isolation_matrix(sessions, resource_probes)
    divergence_findings = [f for f in findings if f.probe_class == "policy_divergence_suspected"]
    assert not divergence_findings, "differing outcomes for differing-policy identities is NOT a finding"


# ---------------------------------------------------------------------------
# Findings writer
# ---------------------------------------------------------------------------


def test_findings_writer_writes_json_and_markdown(tmp_path):
    writer = FindingsWriter(tmp_path / "testing_runs" / "run-1", run_id="run-1")
    writer.add(
        Finding(
            probe_class="sqli",
            owasp_ref="WSTG-INPV-05",
            identity="admin2",
            target="POST /admin/rbac/lookup",
            expected="generic error",
            actual="status=422",
            verdict="PASS",
        )
    )
    json_path, md_path = writer.write()
    assert json_path.exists() and md_path.exists()
    data = json.loads(json_path.read_text())
    assert len(data) == 1
    assert data[0]["verdict"] == "PASS"
    assert "admin2" in md_path.read_text()
    summary = writer.summary_table()
    assert "PASS: 1" in summary


def test_findings_writer_refuses_git_repo_output_dir():
    repo_root = Path(__file__).parents[2]
    with pytest.raises(OutputLocationNotAllowed):
        FindingsWriter(repo_root / "leaked-findings", run_id="run-1")


# ---------------------------------------------------------------------------
# ZAP driver — import + graceful no-daemon handling (NOT live-invoked)
# ---------------------------------------------------------------------------


def test_zap_driver_module_imports_and_zapv2_is_installed():
    """Confirms the 'pentest' extra (zaproxy pip package / zapv2 import
    name) actually installed correctly in this environment."""
    assert zap_driver_mod.ZAPv2 is not None, (
        "zapv2 not importable — run `uv pip install -e '.[pentest]'` "
        "(pyproject.toml 'pentest' optional-dependency group)"
    )


def test_zap_driver_construct_does_not_touch_network():
    """Constructing the driver must not issue any request — only
    connect() does."""
    driver = zap_driver_mod.ZapAuthOnceDriver(zap_api_url="http://127.0.0.1:8080")
    assert driver.zap_api_url == "http://127.0.0.1:8080"


def test_zap_driver_connect_to_unreachable_daemon_fails_gracefully():
    """No live ZAP daemon is running in this build task — this proves the
    'no target' failure mode is a clear, caught exception, never a bare
    traceback surfacing from the requests/zapv2 internals."""
    # A closed, unprivileged, unused loopback port — refuses instantly, no hang.
    driver = zap_driver_mod.ZapAuthOnceDriver(zap_api_url="http://127.0.0.1:65535")
    with pytest.raises(zap_driver_mod.ZapDaemonUnreachable) as excinfo:
        driver.connect()
    assert "LAURA_HARNESS" in str(excinfo.value)
    assert "no ZAP daemon reachable" in str(excinfo.value)


# ---------------------------------------------------------------------------
# CLI — dry-run + unauthorised-target abort (no network)
# ---------------------------------------------------------------------------


def test_cli_dry_run_ok(tmp_path):
    from pentest_harness.__main__ import main

    rc = main(
        [
            "--identities-config",
            str(_EXAMPLE_IDENTITIES),
            "--probe-targets",
            str(_EXAMPLE_PROBE_TARGETS),
            "--lane",
            "pass1",
            "--output-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ]
    )
    assert rc == 0


def test_cli_unauthorised_target_aborts_cleanly(tmp_path):
    from pentest_harness.__main__ import main

    bad_config = tmp_path / "identities.yaml"
    bad_config.write_text(
        "base_url: https://not-ours.example.com\n"
        "identities:\n"
        "  x:\n"
        "    username: x\n"
        "    password: x\n"
        "    totp_secret: JBSWY3DPEHPK3PXP\n"
        "    tier: user\n"
        "lanes:\n"
        "  pass1: [x]\n"
    )
    rc = main(
        [
            "--identities-config",
            str(bad_config),
            "--probe-targets",
            str(_EXAMPLE_PROBE_TARGETS),
            "--lane",
            "pass1",
            "--output-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ]
    )
    assert rc == 2


def test_cli_missing_config_aborts_with_exit_code_2(tmp_path):
    from pentest_harness.__main__ import main

    rc = main(
        [
            "--identities-config",
            str(tmp_path / "missing.yaml"),
            "--probe-targets",
            str(_EXAMPLE_PROBE_TARGETS),
            "--lane",
            "pass1",
            "--output-dir",
            str(tmp_path / "out"),
            "--dry-run",
        ]
    )
    assert rc == 2
