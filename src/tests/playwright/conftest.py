"""
Playwright test configuration for Yashigani admin UI.

Requires a running Yashigani stack. Tests skip if the stack is not reachable.
CA cert resolution follows the same pattern as src/tests/e2e/conftest.py.

Run with:
    YASHIGANI_ADMIN_URL=https://localhost:443 \\
    YASHIGANI_CA_CERT=docker/secrets/ca_root.crt \\
    pytest src/tests/playwright/ -v --timeout=60

Last updated: 2026-07-29 (YTF consolidation: kept at src/tests/playwright/ —
see YTF.md canonical-name-vs-physical-path note (root tests/ and src/tests/
are two same-named "tests" packages; moving playwright to root tests/
would break its absolute "from tests.playwright.conftest import ..." import
in test_webui_conformance_full.py). v2.23.3: fix parents[4]->[3] path bug;
add TOTP helpers; F9: admin TOTP corrected to HMAC-SHA-512/8-digit)
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Optional

import pytest


# ---------------------------------------------------------------------------
# Domain-routed target support (added 2026-07-30, Ava, Tier-B leg
# v412-ytf-podman-13033ff9): Caddy in this deployment routes by vhost
# (e.g. https://yashigani.local:8443), and a bare-IP/bare-"localhost" Host
# falls through to a default/catch-all 200 (see YTF status.md "Health gate"
# finding) -- a false-green trap. The correct fix is DNS-level: keep the
# Host header / TLS SNI as the real domain, only change *where* it resolves.
# On a locked-down runner without sudo (no /etc/hosts edit permitted --
# feedback_mac_max_no_sudo.md), this must happen in-process:
#   - httpx/urllib3 (used by conftest's own health probes + API-plane
#     assertions in the test files) resolve via socket.getaddrinfo --
#     patched below, scoped to the exact YASHIGANI_TEST_DOMAIN hostname only.
#   - Chromium is a separate process and does its own DNS resolution;
#     it is NOT affected by the getaddrinfo patch. It needs the equivalent
#     --host-resolver-rules launch flag, which is why every browser launch
#     in this suite should go through launch_chromium() below instead of
#     calling pw.chromium.launch() directly.
# Both mechanisms are additive/reversible test-harness config -- no system
# file is touched, no other hostname's resolution is altered.
# ---------------------------------------------------------------------------

YTF_TEST_DOMAIN = os.getenv("YASHIGANI_TEST_DOMAIN", "yashigani.local")
YTF_TEST_TARGET_IP = os.getenv("YASHIGANI_TEST_TARGET_IP", "127.0.0.1")

_real_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, *args, **kwargs):
    if host == YTF_TEST_DOMAIN:
        host = YTF_TEST_TARGET_IP
    return _real_getaddrinfo(host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo  # process-scoped, single hostname only

# Chromium launch args: force DNS for YTF_TEST_DOMAIN to YTF_TEST_TARGET_IP
# while leaving the Host header / TLS SNI as the original domain, so Caddy's
# vhost routing sees the real hostname (this is what --resolve does for curl;
# --host-resolver-rules is the Chromium-native equivalent).
YTF_CHROMIUM_ARGS = [f"--host-resolver-rules=MAP {YTF_TEST_DOMAIN} {YTF_TEST_TARGET_IP}"]

# Headed/headless mode: run-test-framework.sh's --browser-mode flag maps here
# via YTF_HEADED=1 (see scripts/run-test-framework.sh Tier-B leg). Prior code
# hardcoded headless=True in every fixture across all 8 playwright test files
# -- "headed" mode never actually executed a headed browser regardless of any
# CLI flag. Fixed 2026-07-30 (Ava): every chromium.launch() call site now
# goes through launch_chromium() below.
YTF_HEADLESS = os.getenv("YTF_HEADED", "0") != "1"


# ---------------------------------------------------------------------------
# YTF screenshot evidence (restored 2026-08-01).
#
# docs/testing/YTF.md §2 makes "screenshot of every state transition" a HARD
# Tier-B requirement, and run-test-framework.sh fails a leg whose screenshot
# dir is empty. The capability previously existed ONLY in uncommitted scratch
# scripts (podman/ava/pw_sweep*.py) and was not carried across when the six
# ad-hoc suites were consolidated into YTF, so YTF has never produced one.
#
# Implemented centrally here rather than per-test: launch_chromium() is the
# single funnel every Tier-B file uses, so instrumenting pages created through
# it covers the whole suite. Capture is best-effort and never fails a test.
# ---------------------------------------------------------------------------
import itertools as _ytf_it
import re as _ytf_re

_YTF_SHOT_SEQ = _ytf_it.count(1)
_YTF_SHOT_ACTIONS = ("goto", "click", "fill", "press", "check", "select_option", "set_checked")


def _ytf_shot_dir() -> str:
    return os.environ.get("YTF_SCREENSHOT_DIR", "")


def _ytf_capture(page, label: str) -> None:
    """Write one screenshot for the current test+step. Never raises."""
    d = _ytf_shot_dir()
    if not d:
        return
    try:
        os.makedirs(d, exist_ok=True)
        cur = os.environ.get("PYTEST_CURRENT_TEST", "unknown").split(" ")[0]
        cur = _ytf_re.sub(r"[^A-Za-z0-9_.=\[\]-]", "_", cur)[-110:]
        page.screenshot(path=f"{d}/{next(_YTF_SHOT_SEQ):05d}__{cur}__{label}.png",
                        full_page=True)
    except Exception:
        pass  # evidence capture must never turn a passing test red


def _ytf_instrument_page(page):
    """Wrap state-changing page methods so each transition leaves an image."""
    for _m in _YTF_SHOT_ACTIONS:
        _orig = getattr(page, _m, None)
        if _orig is None:
            continue

        def _make(meth_name, orig_fn):
            def _wrapped(*a, **k):
                result = orig_fn(*a, **k)
                _ytf_capture(page, meth_name)
                return result
            return _wrapped

        try:
            setattr(page, _m, _make(_m, _orig))
        except Exception:
            pass
    return page


def _ytf_instrument_factory(obj):
    """Patch new_page/new_context on a Browser or BrowserContext."""
    for _factory in ("new_page", "new_context"):
        _orig = getattr(obj, _factory, None)
        if _orig is None:
            continue

        def _make(name, orig_fn):
            def _wrapped(*a, **k):
                made = orig_fn(*a, **k)
                if name == "new_page":
                    return _ytf_instrument_page(made)
                return _ytf_instrument_factory(made)
            return _wrapped

        try:
            setattr(obj, _factory, _make(_factory, _orig))
        except Exception:
            pass
    return obj


def launch_chromium(pw_or_playwright):
    """Shared Chromium launcher for every Tier-B test file. Honors YTF_HEADED
    (headed/headless parity) and always injects --host-resolver-rules so
    tests can target a domain-routed Caddy vhost without a privileged
    /etc/hosts edit. Use this instead of calling `pw.chromium.launch()`
    directly.

    Pages created through this launcher are instrumented for YTF screenshot
    evidence (see above)."""
    browser = pw_or_playwright.chromium.launch(headless=YTF_HEADLESS, args=YTF_CHROMIUM_ARGS)
    return _ytf_instrument_factory(browser)


# ---------------------------------------------------------------------------
# Screenshot capture — shared across every Tier-B Playwright file
# ---------------------------------------------------------------------------
#
# QA-fix (Ava, Tier-B triage 2026-08-02): run-test-framework.sh's Tier-B leg
# (`run_tier_b()`) exports YTF_SCREENSHOT_DIR per-mode and treats ZERO
# captured screenshots as a leg failure ("Zero screenshots captured — leg
# WebUI Tier-B is NOT complete per pass-criteria"). Before this fix, exactly
# ONE file in this entire suite (test_chat_live_e2e.py) ever called
# page.screenshot() at all — every other Playwright UI-feature file (backup,
# documents, capability-policy, hibp, permissions, pki, the conformance
# sweep) captured nothing, ever, regardless of pass/fail. On the
# ytf-docker-macos-29d9c9d8-20260731 run that one file's tests ALL failed at
# fixture setup (the auth cascade fixed elsewhere this session) before ever
# reaching a _shot() call, producing the reported "1 screenshot, essentially
# zero" result. Two independent problems, both fixed:
#   1. test_chat_live_e2e.py's own SHOT_DIR fallback hardcoded
#      ".../ytf/docker-linux/screenshots" regardless of the ACTUAL runtime/
#      platform leg being tested (this run was docker-macos) — harmless when
#      YTF_SCREENSHOT_DIR is set (the normal run-test-framework.sh path
#      always sets it), but actively misleading for anyone running this file
#      directly without the env var, or auditing evidence paths.
#   2. No shared, low-friction screenshot helper existed for the other
#      Playwright files to adopt, so nobody did — capture_screenshot() below
#      is that helper, now wired into the newly-fixed
#      get_authed_context()-based fixtures (capability-policy, hibp, backup,
#      documents, pki, permissions) at their key state-transition points
#      (post-login, post-nav-click) so this Tier-B leg produces real,
#      per-module evidence going forward, not just from one chat-specific file.
YTF_SCREENSHOT_DIR = os.environ.get("YTF_SCREENSHOT_DIR")


def capture_screenshot(page, name: str) -> Optional[str]:
    """Capture a full-page screenshot to YTF_SCREENSHOT_DIR/<name>.png.

    No-ops (returns None) if YTF_SCREENSHOT_DIR is not set — this keeps ad
    hoc/local test runs (outside run-test-framework.sh) from littering the
    repo with screenshot files nobody asked for, while still guaranteeing
    real evidence whenever the Tier-B runner (which always sets the env var)
    drives the suite. Never raises: a screenshot failure must never fail the
    test it's evidencing.
    """
    if not YTF_SCREENSHOT_DIR:
        return None
    try:
        d = Path(YTF_SCREENSHOT_DIR)
        d.mkdir(parents=True, exist_ok=True)
        p = str(d / f"{name}.png")
        page.screenshot(path=p, full_page=True)
        return p
    except Exception as exc:  # pragma: no cover — evidence capture must never break a test
        print(f"[conftest] capture_screenshot({name!r}) failed (non-fatal): {exc}")
        return None


# ---------------------------------------------------------------------------
# CA cert resolution (mirrors e2e/conftest.py Pattern A)
# ---------------------------------------------------------------------------


def _resolve_ca_cert() -> Optional[str]:
    """Return a CA cert path to verify httpx TLS connections against, or None
    to mean "don't attempt cert-chain verification" (verify=False, mirroring
    the already-accepted-risk posture every Playwright/Chromium test in this
    suite takes via new_context(ignore_https_errors=True) for local test
    traffic -- see test_backup_ui.py._tls_args docstring).

    FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
    previously auto-discovered docker/secrets/ca_root.crt unconditionally.
    For a `--tls-mode selfsigned` install (this deployment), Caddy's public
    HTTPS listener presents a cert chain issued by Caddy's OWN internal local
    CA ("Caddy Local Authority - ECC Intermediate"), NOT ca_root.crt (which is
    "Yashigani Internal Root CA" -- a distinct CA used elsewhere, e.g.
    mTLS/document-signing). Verified directly:
      openssl s_client -connect 127.0.0.1:8443 -servername yashigani.local \\
        -CAfile docker/secrets/ca_root.crt
      -> Verify return code: 20 (unable to get local issuer certificate)
    Auto-trusting ca_root.crt for the public listener therefore ALWAYS fails
    verification on a selfsigned-mode deployment (this caused ~322
    CERTIFICATE_VERIFY_FAILED / TLS-handshake failures across the httpx-based
    portion of this suite, unrelated to any product defect or DNS/host-resolver
    change). Only use an explicit CA when the caller KNOWS it matches (e.g. a
    `--tls-mode ca` deployment with a real issued cert) via YASHIGANI_CA_CERT.
    """
    explicit = os.getenv("YASHIGANI_CA_CERT")
    if explicit:
        return explicit
    return None


_CA_CERT_PATH: str | None = _resolve_ca_cert()


# ---------------------------------------------------------------------------
# Base URL resolution
# ---------------------------------------------------------------------------


def _resolve_base_url() -> str:
    """Resolve the target stack URL.

    2026-08-09 — THIS FUNCTION CAUSED THE 110 FIXTURE ERRORS PER LEG, ALL CAMPAIGN.

    `run_tier_b()` validates `--target` and then never exports it, so
    YASHIGANI_ADMIN_URL was unset and this fell through to probing
    localhost:8443 / localhost / localhost:8080. Nothing answers there, and the
    old code then RETURNED THE HARDCODED DEFAULT ANYWAY. Every request went to a
    dead address that replies 200 with an empty body to everything — including
    /healthz — so:
      * login returned 200, length 0, no Set-Cookie
      * r.json() raised JSONDecodeError, or the browser got no session
      * every admin_ctx fixture landed on /admin/login  -> 110 ERRORS
    It was blamed on the auth throttle, then SameSite, then the HTTP client.
    curl "worked" and httpx "failed" because they were pointed at DIFFERENT HOSTS.

    Three fixes:
      1. honour YASHIGANI_TEST_DOMAIN when no explicit URL is given, so the
         runner's --target reaches the tests (see run-test-framework.sh, which
         now exports YASHIGANI_ADMIN_URL);
      2. verify a probe candidate is really our stack — a 200 with an empty body
         is NOT a healthy stack;
      3. FAIL LOUD instead of returning a default nothing is listening on. A
         suite that cannot find its target must not invent one.
    """
    override = os.getenv("YASHIGANI_ADMIN_URL")
    if override:
        return override.rstrip("/")

    candidates = []
    domain = os.getenv("YASHIGANI_TEST_DOMAIN", "").strip()
    if domain:
        candidates += [f"https://{domain}", f"https://{domain}:8443"]
    candidates += ["https://localhost:8443", "https://localhost", "http://localhost:8080"]

    try:
        import httpx

        for url in candidates:
            verify: bool | str = (_CA_CERT_PATH or False) if url.startswith("https://") else False  # type: ignore[assignment]
            try:
                r = httpx.get(f"{url}/healthz", verify=verify, timeout=3)
            except Exception:
                continue
            # A live Yashigani /healthz returns a non-empty JSON body. An empty
            # 200 is something else answering on that port.
            if r.status_code == 200 and r.content and b"ok" in r.content.lower():
                return url
    except ImportError:
        pass

    raise RuntimeError(
        "YTF: cannot resolve a live Yashigani stack. Tried: "
        + ", ".join(candidates)
        + ". Set YASHIGANI_ADMIN_URL (the runner's --target) or YASHIGANI_TEST_DOMAIN. "
        "Refusing to fall back to a default address — that is what produced 110 "
        "phantom fixture errors per leg for an entire campaign."
    )


BASE_URL: str = _resolve_base_url()
ADMIN_LOGIN_URL: str = f"{BASE_URL}/admin/login"


# ---------------------------------------------------------------------------
# Stack-running check
# ---------------------------------------------------------------------------


def _stack_running() -> bool:
    try:
        import httpx
    except ImportError:
        return False
    candidates = [
        BASE_URL + "/healthz",
        "https://localhost/healthz",
        "https://localhost:8443/healthz",
        "http://localhost:8080/healthz",
    ]
    for url in candidates:
        try:
            verify: bool | str = (_CA_CERT_PATH or False) if url.startswith("https://") else False  # type: ignore[assignment]
            r = httpx.get(url, verify=verify, timeout=3)
            if r.status_code == 200:
                return True
        except Exception:
            continue
    return False


STACK_RUNNING: bool = _stack_running()

_SKIP_NO_STACK = pytest.mark.skipif(
    not STACK_RUNNING,
    reason="Yashigani stack not running — start with docker/podman compose up",
)


# ---------------------------------------------------------------------------
# Admin credential helpers
# ---------------------------------------------------------------------------


def _read_secret(name: str) -> str:
    """Read a secret from docker/secrets/. Raises FileNotFoundError if absent."""
    # __file__ = .../yashigani/src/tests/playwright/conftest.py
    # parents[3] = .../yashigani (repo root)
    # YTF_SECRETS_DIR: point the harness at a READABLE COPY of docker/secrets.
    # Needed because the live secrets dir is unreadable by the test user on BOTH
    # runtimes -- root-owned under rootful Docker, and chowned to a subuid under
    # rootless Podman (container uid 1000 maps through /etc/subuid, e.g. 166536),
    # mode 0600, so the test user is neither owner nor in the group.
    #
    # Deliberately a COPY, not a chmod: widening the mode on the live files would
    # destroy the very posture the pentest asserts (S1/CWE-732 -- no group- or
    # world-readable file under docker/secrets). Make the copy with
    #   podman unshare cat docker/secrets/<f>   (rootless podman)
    #   sudo cat docker/secrets/<f>             (rootful docker)
    #
    # This override has now been rebuilt from scratch by three separate sessions
    # because it only ever existed as an uncommitted working-tree change; the
    # risk register records it as "UNCOMMITTED ... Must be committed" after two
    # full 3.5h Tier-B runs produced 224 identical credential-read errors.
    _override = os.environ.get("YTF_SECRETS_DIR", "")
    if _override:
        return (Path(_override) / name).read_text(encoding="utf-8").strip()
    repo_root = Path(__file__).parents[3]
    p = repo_root / "docker" / "secrets" / name
    return p.read_text(encoding="utf-8").strip()


def get_admin_credentials() -> tuple[str, str]:
    """Return (username, current_password) for admin1.

    Prefers the in-process rotated password (_rotated_admin_password, set once
    this suite has actually completed the forced-password-change step this
    run) over the on-disk admin1_password secret, which stays stale for the
    lifetime of the run since nothing writes rotations back to disk. Falls
    back to admin_initial_password if admin1_password doesn't exist either
    (not yet rotated by anything, on-disk or in-process).
    """
    username = _read_secret("admin1_username")
    password = _current_admin_password(1)
    return username, password


def get_admin_totp_code() -> str:
    """Return a current HMAC-SHA-512/8-digit TOTP code for admin1.

    CORRECTED 2026-07-29 (v4.1.2 conformance suite, webui-findings.md F9):
    the server does NOT use pyotp's RFC 6238 default (HMAC-SHA1/6-digit).
    src/yashigani/auth/totp.py (Phase 13, role-tiered TOTP) implements its
    own RFC 4226/6238 logic and assigns admin accounts HMAC-SHA-512/8-digit
    (TOTP_ALGO_SHA512 / TOTP_DIGITS_ADMIN). The previous plain
    pyotp.TOTP(secret).now() call generated a SHA-1/6-digit code that would
    NOT match a freshly-bootstrapped 4.1.2 admin account (Phase 13 is the
    baseline, not an in-progress migration) — this was a live bug in the
    shared Playwright login helper, not a documentation typo.
    """
    import hashlib

    import pyotp

    # 2026-08-12: admin logins previously bypassed the anti-replay ledger entirely
    # (only user logins and do_admin_stepup used it), so a browser login spent a code
    # WITHOUT recording it. do_admin_stepup then found an empty ledger, proceeded in
    # the SAME 30s window, and the server correctly rejected the replay:
    # 401 invalid_totp_code. The ledger must be keyed on the IDENTITY (one TOTP
    # secret = one window), never on the purpose.
    secret = _read_secret("admin1_totp_secret")
    wait_for_fresh_totp("admin1")
    code = pyotp.TOTP(secret, digits=8, digest=hashlib.sha512).now()
    mark_totp_used("admin1")
    return code


def get_admin2_totp_code() -> str:
    """Return a current HMAC-SHA-512/8-digit TOTP code for admin2. See
    get_admin_totp_code() docstring — same F9 correction applies."""
    import hashlib

    import pyotp

    secret = _read_secret("admin2_totp_secret")
    return pyotp.TOTP(secret, digits=8, digest=hashlib.sha512).now()


_session_cookie_cache: "dict[int, dict]" = {}  # admin_number → cookies


# ---------------------------------------------------------------------------
# FIND-B-TOTP-CROSSPROC (4.1.2 3-runtime retest, 2026-08-04): the admin-tier
# anti-replay ledger below used to be a plain in-process dict, which resets
# to empty on every fresh pytest process. run-test-framework.sh's Tier-B leg
# invokes pytest ONCE PER FILE (run_tier_b() in scripts/run-test-framework.sh
# runs `pytest src/tests/playwright/test_X.py` per file, not the whole
# directory in one process), so a file that starts within 60s of the PRIOR
# file's last real admin1 TOTP submission has zero in-process memory of that
# submission and can regenerate/resubmit a code from the SAME 30s window —
# the server's real 60s single-use TOTP replay cache correctly rejects the
# repeat with 401, which is a harness false-negative, not a product bug
# (confirmed manually this retest: an identical on-disk password + a fresh
# real TOTP code got 200 immediately afterward; a bare re-run of the same
# test 65s later passed clean).
#
# Fix: back the SAME dict[int, float] interface with a lock-guarded JSON
# file under YTF_STATE_DIR (default: <repo>/.ytf-state/), so a fresh process
# picks up the PRIOR process's last real submission instead of starting from
# 0.0. Subclassing dict (rather than converting the 6 test files that
# `from conftest import _api_totp_last_used` and mutate it directly via
# `_api_totp_last_used[1] = ...` / `.get(admin, 0.0)` / `1 not in ...`) keeps
# every existing call site correct with zero changes there. Cross-platform
# (fcntl works on both macOS and Linux, the two supported test platforms —
# feedback_local_test_must_work_on_macos_and_linux.md).
# ---------------------------------------------------------------------------

import fcntl as _fcntl
import json as _json

_TOTP_LEDGER_STATE_DIR = Path(
    os.environ.get("YTF_STATE_DIR", str(Path(__file__).resolve().parents[3] / ".ytf-state"))
)
_TOTP_LEDGER_STATE_FILE = _TOTP_LEDGER_STATE_DIR / "admin_totp_last_used.json"


class _PersistentTotpLedger(dict):
    """dict[int, float] (admin_number -> time.time() of last real TOTP
    submission) that also persists every write to, and consults on every
    read, a shared lock-guarded JSON file — see FIND-B-TOTP-CROSSPROC above.
    Best-effort: any filesystem error degrades silently to in-process-only
    behaviour (the pre-fix status quo) rather than failing a test."""

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        self._persist(key, value)

    def get(self, key, default=None):
        self._sync(key)
        return super().get(key, default)

    def __contains__(self, key) -> bool:
        self._sync(key)
        return super().__contains__(key)

    def __getitem__(self, key):
        self._sync(key)
        return super().__getitem__(key)

    @staticmethod
    def _load() -> dict:
        try:
            with open(_TOTP_LEDGER_STATE_FILE, "r", encoding="utf-8") as f:
                _fcntl.flock(f.fileno(), _fcntl.LOCK_SH)
                try:
                    raw = f.read()
                finally:
                    _fcntl.flock(f.fileno(), _fcntl.LOCK_UN)
            return _json.loads(raw) if raw.strip() else {}
        except (FileNotFoundError, ValueError, OSError):
            return {}

    def _sync(self, key) -> None:
        """Pull the persisted value for `key` into this dict if it is newer
        than whatever this process already has in memory (0.0 on a fresh
        process) — so a fresh process sees the PRIOR process's last real
        submission instead of assuming none ever happened."""
        try:
            persisted = self._load().get(str(key))
        except Exception:
            return
        if persisted is not None and float(persisted) > dict.get(self, key, 0.0):
            dict.__setitem__(self, key, float(persisted))

    def _persist(self, key, value) -> None:
        try:
            _TOTP_LEDGER_STATE_DIR.mkdir(parents=True, exist_ok=True)
            with open(_TOTP_LEDGER_STATE_FILE, "a+", encoding="utf-8") as f:
                _fcntl.flock(f.fileno(), _fcntl.LOCK_EX)
                try:
                    f.seek(0)
                    raw = f.read()
                    try:
                        data = _json.loads(raw) if raw.strip() else {}
                    except ValueError:
                        data = {}
                    data[str(key)] = value
                    f.seek(0)
                    f.truncate()
                    f.write(_json.dumps(data))
                    f.flush()
                finally:
                    _fcntl.flock(f.fileno(), _fcntl.LOCK_UN)
        except OSError as exc:
            print(f"[conftest] FIND-B-TOTP-CROSSPROC: could not persist TOTP ledger to disk: {exc}")


_api_totp_last_used: "dict[int, float]" = _PersistentTotpLedger()  # admin_number → time.time() of last API login (cross-process persistent, see above)

# QA-fix (Ava, Tier-B tierb-on-unified consolidation): per-identity "when was
# this session actually established server-side" ledger, distinct from
# _session_cookie_cache (which never expires in-process once populated).
# The server's session idle-timeout is 900s (src/yashigani/auth/session.py
# _IDLE_TIMEOUT_SECONDS) -- a cookie cached once at the START of a long file
# (test_webui_conformance_full.py's admin_ctx/user_ctx are module-scoped,
# shared across ~15 test classes and every TOTP-replay wait those classes
# incur) can silently outlive that 900s window mid-file, producing "Still on
# login page" only once some LATER test happens to hit it -- exactly the
# measured 111+45-error cascade this consolidation fixes. These ledgers let
# refresh_admin_context_if_stale()/refresh_user_context_if_stale() (below)
# proactively re-authenticate BEFORE that happens, from one shared per-test
# autouse guard, instead of each fixture/file inventing its own staleness
# check (test_pki_admin_ui.py's unconditional force_fresh=True is the
# unconditional/expensive special case of the same idea).
_admin_session_established_at: "dict[int, float]" = {}  # admin_number → time.time() of last real (non-cache-hit) login
_user_session_established_at: "dict[str, float]" = {}  # cache_key → time.time() of last real (non-cache-hit) bootstrap
_SESSION_REFRESH_THRESHOLD_SECONDS = 600  # safety margin under the server's 900s/15-min idle timeout

# FIND-B-A (4.1.2 3-runtime retest, 2026-08-03/04, HIGH-impact cascade):
# _session_cookie_cache had NO invalidation path at all. The suite's one
# deliberate destructive-logout test (test_webui_conformance_full.py
# TestSessionLifecycle::test_logout_redirect_clears_admin_session) injects
# the SAME cached cookie value that the session-scoped admin_ctx fixture was
# ALSO seeded from (both ultimately come from _api_get_session_cookies'
# cache), then kills that session server-side via a real browser navigation
# to /auth/logout-redirect. Nothing told the cache the session was now dead:
# _session_cookie_cache[admin] and _admin_session_established_at[admin]
# both kept their pre-logout values, so refresh_admin_context_if_stale()'s
# purely time-based staleness check (below) saw a "recently established"
# session and skipped refreshing admin_ctx's own long-lived browser
# context -- every subsequent test sharing admin_ctx then ran against a
# server-dead session for up to the full 600s safety margin. Reproduced
# byte-for-byte on BOTH podman and docker legs: TestSessionLifecycle's
# logout test PASSES, the very next test FAILS, then every test from
# TestAdminModuleSweep onward ERRORs for the rest of the process (~110
# podman / ~108 docker). This is also the confirmed root cause of the
# separately-logged FIND-B-G (test_v233_webauthn_e2e.py's clean_authed_client
# fixture calls the exact same cached-cookie path).
#
# Fix: a real, deliberate logout (or any other auth-state transition that
# kills a session out from under the shared caches -- e.g. a future
# password-reset-for-value test) must call invalidate_cached_session()/
# invalidate_cached_user_session() below. Popping _session_cookie_cache
# forces the NEXT _api_get_session_cookies(force_fresh=False) caller to do
# a real login instead of returning dead cookies. Popping
# _*_session_established_at alone is not sufficient to force admin_ctx's/
# user_ctx's OWN long-lived browser context to pick up fresh cookies --
# some OTHER, unrelated caller can re-populate _admin_session_established_at
# moments later (its own real login), which would make the plain time-based
# check in refresh_admin_context_if_stale() see a falsely-fresh timestamp
# and skip refreshing THIS context. The _admin_session_dirty/
# _user_session_dirty sets are a separate, explicit "force at least one real
# refresh" flag that persists until refresh_admin_context_if_stale()/
# refresh_user_context_if_stale() actually runs and clears it, closing that
# race regardless of what else touches the shared timestamp in the meantime.
_admin_session_dirty: "set[int]" = set()
_user_session_dirty: "set[str]" = set()


def invalidate_cached_session(admin: int = 1) -> None:
    """Invalidate admin{N}'s cached session state after a REAL, deliberate
    server-side logout performed OUTSIDE _api_get_session_cookies()'s own
    internal rotate-then-relogin dance (that internal logout is always
    immediately followed by a fresh login before the cache is (re)written,
    so it never needs this). Call this right after any browser navigation
    to /auth/logout-redirect or any API POST /auth/logout that is meant to
    kill the session for good this run. See FIND-B-A note above."""
    _session_cookie_cache.pop(admin, None)
    _admin_session_established_at.pop(admin, None)
    _admin_session_dirty.add(admin)


def invalidate_cached_user_session(cache_key: str = "default") -> None:
    """User-tier equivalent of invalidate_cached_session(). Not currently
    exercised by any test (no deliberate user-tier logout test exists yet),
    added so a future one is safe by construction rather than reintroducing
    FIND-B-A for the user tier."""
    _user_session_cache.pop(cache_key, None)
    _user_session_established_at.pop(cache_key, None)
    _user_session_dirty.add(cache_key)

# QA-fix (Ava, Tier-B tierb-on-unified consolidation): per-identity "when was
# this session actually established server-side" ledger, distinct from
# _session_cookie_cache (which never expires in-process once populated).
# The server's session idle-timeout is 900s (src/yashigani/auth/session.py
# _IDLE_TIMEOUT_SECONDS) -- a cookie cached once at the START of a long file
# (test_webui_conformance_full.py's admin_ctx/user_ctx are module-scoped,
# shared across ~15 test classes and every TOTP-replay wait those classes
# incur) can silently outlive that 900s window mid-file, producing "Still on
# login page" only once some LATER test happens to hit it -- exactly the
# measured 111+45-error cascade this consolidation fixes. These ledgers let
# refresh_admin_context_if_stale()/refresh_user_context_if_stale() (below)
# proactively re-authenticate BEFORE that happens, from one shared per-test
# autouse guard, instead of each fixture/file inventing its own staleness
# check (test_pki_admin_ui.py's unconditional force_fresh=True is the
# unconditional/expensive special case of the same idea).
_admin_session_established_at: "dict[int, float]" = {}  # admin_number → time.time() of last real (non-cache-hit) login
_user_session_established_at: "dict[str, float]" = {}  # cache_key → time.time() of last real (non-cache-hit) bootstrap
_SESSION_REFRESH_THRESHOLD_SECONDS = 600  # safety margin under the server's 900s/15-min idle timeout

# QA-fix (Ava, 2026-07-31, Tier-B v412 fresh-bootstrap smoke): on a genuinely
# fresh stack (admin creds still INITIAL, force_password_change=True on first
# login) BOTH playwright_login_admin() and the (now-removed) local duplicates
# in test_v2233_login_redirect.py / test_backup_ui.py handled the forced
# password-change step by generating a random new password and submitting it
# -- but NEVER persisted that new password anywhere. get_admin_credentials()
# (and every helper's own admin2 resolution) kept reading the stale value
# from docker/secrets/, so the FIRST admin-dependent test to run would rotate
# the live password out from under every other test in the same pytest
# invocation, which would then fail with invalid_credentials. This process-
# lifetime cache is the single source of truth for "what is admin{N}'s
# CURRENT password right now" once this suite has rotated it; every login
# helper below reads/writes through it instead of re-reading the stale
# on-disk secret after first rotation.
_rotated_admin_password: "dict[int, str]" = {}


def _current_admin_password(admin: int = 1) -> str:
    """Return admin{N}'s current password: the in-process rotated value if
    this suite has already rotated it this run, else the on-disk secret."""
    if admin in _rotated_admin_password:
        return _rotated_admin_password[admin]
    if admin == 1:
        try:
            return _read_secret("admin1_password")
        except FileNotFoundError:
            return _read_secret("admin_initial_password")
    try:
        return _read_secret(f"admin{admin}_password")
    except FileNotFoundError:
        return _read_secret("admin_initial_password")


def _persist_rotated_password(admin: int, new_password: str) -> None:
    """Write admin{N}'s freshly-rotated password back to
    docker/secrets/admin{N}_password (docker/secrets/admin1_password for
    admin1, matching _current_admin_password()'s on-disk fallback naming).

    FIND-8 (Tier-B triage 2026-08-02): every rotation this suite performs was
    previously cached ONLY in the in-process _rotated_admin_password dict —
    nothing ever wrote it back to disk. That's fine within a single pytest
    process (every helper reads the shared dict), but it means the FIRST
    successful bootstrap of any given install PERMANENTLY invalidates the
    on-disk admin{N}_password secret for every subsequent, independent
    process (a fresh `pytest` invocation, a diagnostic curl/httpx script, a
    human operator) — the account is not "burned" from the server's
    perspective (the new password is real and works), only from the
    perspective of anything reading the stale on-disk file. Confirmed live
    against the still-running Tier-B stack on this run
    (ytf-docker-macos-29d9c9d8-20260731): the on-disk admin1_password
    (identical to admin_initial_password — never rotated) is now REJECTED
    with 401 invalid_credentials by the live server, while the in-process
    cache from whichever test happened to perform the real rotation still
    has the correct value, orphaned once that process exits.

    Best-effort: a permission error or read-only secrets mount should not
    fail the test run (the in-process cache is still authoritative for the
    rest of THIS process either way) — logged via print() since this module
    has no logger of its own, loud enough to show up in pytest -s output
    without needing one.
    """
    secret_name = "admin1_password" if admin == 1 else f"admin{admin}_password"

    # FIND-0805-002 (ytf-412-20260805): the original FIND-8 fix wrote ONLY to
    # Path(__file__).parents[3]/docker/secrets, while _read_secret() above prefers
    # YTF_SECRETS_DIR whenever it is set. YTF_SECRETS_DIR is set on every correctly
    # configured run (docker/secrets is unreadable to the test user on BOTH runtimes —
    # that is the whole reason the override exists), so the write always landed
    # somewhere the harness never reads back: the persist was a no-op exactly when it
    # mattered. Proven live on the docker-linux leg — after the headed pytest process
    # rotated admin1, the on-disk credential returned 401 invalid_credentials while
    # untouched admin2 returned 200, and no file on disk had been updated.
    #
    # Consequence: run_tier_b() runs headed and headless as two SEPARATE pytest
    # processes against one stack and a leg is GREEN only if BOTH pass, so the
    # mandatory double run could never pass (YTF §2 / QA SOP §4.17 Rule 4).
    #
    # Write to every location the read path might use, not just one: the override copy
    # (what _read_secret returns when set) AND the real repo secrets dir (the fallback,
    # and what a human operator or diagnostic script reads). Best-effort per target —
    # the real dir is often unwritable by the test user, which must not fail the run,
    # since the in-process cache stays authoritative for the rest of THIS process.
    targets = []
    _override = os.environ.get("YTF_SECRETS_DIR", "")
    if _override:
        targets.append(Path(_override) / secret_name)
    targets.append(Path(__file__).parents[3] / "docker" / "secrets" / secret_name)

    persisted = 0
    for p in targets:
        try:
            p.write_text(new_password, encoding="utf-8")
            try:
                p.chmod(0o600)
            except OSError:
                pass
            persisted += 1
        except OSError as exc:
            print(f"[conftest] FIND-8: could not persist rotated admin{admin} password to {p}: {exc}")
    if persisted == 0:
        print(
            f"[conftest] FIND-0805-002: rotated admin{admin} password persisted to NO target "
            f"({[str(t) for t in targets]}) — the next pytest process will read a stale "
            f"credential and fail at fixture setup."
        )


def _generate_strong_password() -> str:
    import secrets as _secrets
    import string as _string

    return "".join(
        _secrets.choice(_string.ascii_letters + _string.digits + "!*-._~,")
        for _ in range(42)
    )


def _detect_container_runtime() -> Optional[str]:
    """Return 'podman' or 'docker' -- whichever has a live container list
    right now -- or None if neither is reachable.

    Mirrors src/tests/e2e/conftest.py's _detect_runtime(), generalised: that
    helper's liveness probe hardcodes the exact container name
    "docker-gateway-1", which never matches THIS deployment's actual
    compose project name (confirmed live, 2026-08-03 Tier-B triage:
    `podman ps` on this podman-macos run returns "localhost_redis_1",
    "localhost_gateway_1", etc -- never "docker-*"), so it silently falls
    through to a "default to docker" branch every time. This helper instead
    just asks "does this runtime have ANY running containers right now",
    which works regardless of compose project-naming convention.
    """
    import shutil
    import subprocess

    for runtime in ("podman", "docker"):
        if not shutil.which(runtime):
            continue
        try:
            result = subprocess.run(
                [runtime, "ps", "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                return runtime
        except Exception:
            continue
    return None


def _find_redis_container(runtime: str) -> Optional[str]:
    """Return the name of the running redis container under `runtime`, or
    None.

    QA-fix (Ava, 2026-08-03): an earlier version of this matched by bare
    substring ("redis" in name.lower()), which on THIS deployment picked
    "localhost_budget-redis_1" (a SEPARATE redis instance used for budget
    tracking -- see docker-compose service list) instead of the actual
    auth-throttle redis, "localhost_redis_1" -- confirmed live: the
    substring version silently drained the wrong container's keys every
    time (0 auth:fail/auth:throttle keys ever actually touched). Now
    requires an EXACT compose service-name segment match ("redis"), tried
    against both "_"  (this deployment's separator -- "localhost_redis_1")
    and "-" (docker-compose v2's default separator) split conventions,
    before falling back to a broad substring match as a last resort.
    """
    import subprocess

    try:
        result = subprocess.run(
            [runtime, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        candidates = [n.strip() for n in result.stdout.splitlines() if n.strip()]
    except Exception:
        return None

    # YSG-RISK-209 (2026-08-08): the segment match above was still ambiguous.
    # On a "-"-separated project, "yashigani-demo-internal-budget-redis-1"
    # splits to [...,'budget','redis','1'] — which CONTAINS an exact "redis"
    # segment — so the BUDGET redis matched whenever docker listed it first.
    # Confirmed live: this returned "…-budget-redis-1", so clear_auth_throttle()
    # drained the wrong instance and reported 0 keys every time. That is why the
    # 110-error auth lane-bleed survived even though the primitive existed and
    # was being called.
    #
    # Match the compose SERVICE LABEL instead — exact, unambiguous, and
    # independent of project name and separator convention.
    for name in candidates:
        try:
            svc = subprocess.run(
                [runtime, "inspect", name, "--format",
                 "{{index .Config.Labels \"com.docker.compose.service\"}}"],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except Exception:
            continue
        if svc == "redis":
            return name

    # Fallbacks, narrowed: never accept a name whose service segment is a
    # *-redis sibling (budget-redis, letta-redis, …).
    for sep in ("_", "-"):
        for name in candidates:
            segs = [x.lower() for x in name.split(sep)]
            if "redis" in segs:
                i = segs.index("redis")
                if i > 0 and segs[i - 1] in ("budget", "session", "cache"):
                    continue
                return name
    return None


def clear_auth_throttle() -> int:
    """Delete every LIVE auth-throttle Redis key (per-IP and per-account
    fail-count + throttle-level buckets) so a burst-login test (or any test
    that trips the account/IP gate) doesn't leak elevated severity into the
    rest of a long-running suite.

    QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): this previously
    (a) hardcoded `docker exec docker-redis-1 ...` unconditionally -- on
    THIS run (podman-macos) the `docker` CLI binary is present (Docker
    Desktop client) but its daemon is NOT running ("Cannot connect to the
    Docker daemon at unix:///Users/max/.docker/run/docker.sock"), so every
    call failed at the FIRST subprocess step and silently returned 0, every
    single time, on every podman-only deployment -- and (b) even when a
    docker daemon IS reachable, deleted a STALE key set (auth:fail:global, a
    single hardcoded auth:fail:ip:172.23.0.2) that does not match the live
    scheme actually written by
    src/yashigani/backoffice/routes/auth.py::_apply_auth_throttle /
    _reset_auth_failures: auth:fail:ip:{client_ip}, auth:throttle:ip:{ip},
    auth:fail:acct:{bucket}, auth:throttle:acct:{bucket} -- bucket is
    "id:{account_id}" or "unk:{sha256(username)[:16]}", never a fixed
    value -- so even on a genuine docker deployment this was a no-op
    against the keys that actually matter.

    Confirmed live root-cause contributor to the 2026-08-03 172-error
    cascade: TestRateLimitLoginBurst's 20-attempt burst legitimately
    escalates auth:throttle:ip:127.0.0.1 (the real test-client IP, not the
    hardcoded 172.23.0.2); this no-op meant that elevated IP severity was
    NEVER actually cleared and persisted for the rest of the 2h24m run,
    compounding the account-level throttle hit by the chat_page/webauthn
    TOTP-replay bugs fixed alongside this.

    Now: (1) detects whichever runtime (podman or docker) actually has live
    containers right now instead of assuming docker: (2) finds the redis
    container by name-substring match instead of a hardcoded compose-project
    name; (3) SCANs for the live `auth:fail:*` / `auth:throttle:*` key
    patterns and deletes whatever actually exists, instead of a fixed stale
    list. Never touches `auth:blocked:*` (admin-managed manual IP block --
    intentionally NOT auto-cleared by this helper).

    Returns the number of keys deleted. No-ops gracefully (returns 0) if no
    container runtime / redis container / redis auth is reachable -- tests
    can still run, throttle just won't be reset.

    Last updated: 2026-08-03 (Ava, Tier-B 172-error triage: podman support +
    live key scheme; was 2026-05-09 v2.23.3 original).
    """
    import subprocess

    runtime = _detect_container_runtime()
    if runtime is None:
        return 0
    redis_container = _find_redis_container(runtime)
    if redis_container is None:
        return 0

    try:
        pw_result = subprocess.run(
            [runtime, "exec", redis_container, "cat", "/run/secrets/redis_password"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if pw_result.returncode != 0:
            return 0
        redis_pw = pw_result.stdout.strip()

        def _redis_cli(*args: str) -> "subprocess.CompletedProcess":
            return subprocess.run(
                [
                    runtime, "exec", redis_container, "redis-cli",
                    "-p", "6380",
                    "--tls",
                    "--cert", "/run/secrets/redis_client.crt",
                    "--key", "/run/secrets/redis_client.key",
                    "--cacert", "/run/secrets/ca_root.crt",
                    "--user", "default",
                    "--pass", redis_pw,
                    "-n", "1",
                    *args,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )

        _warning_line = (
            "Warning: Using a password with '-a' or '-u' option on the "
            "command line interface may not be safe."
        )

        deleted = 0
        for pattern in ("auth:fail:*", "auth:throttle:*"):
            scan_result = _redis_cli("--scan", "--pattern", pattern)
            keys = [
                k.strip() for k in scan_result.stdout.splitlines()
                if k.strip() and _warning_line not in k
            ]
            if not keys:
                continue
            del_result = _redis_cli("DEL", *keys)
            output = del_result.stdout.strip().replace(_warning_line, "").strip()
            if output.isdigit():
                deleted += int(output)
        return deleted
    except Exception:
        return 0


def _api_get_session_cookies(*, admin: int = 1, force_fresh: bool = False) -> dict:
    """
    Obtain session cookies via the httpx API client (not the browser).

    Waits for a fresh TOTP time-step if the current code is within 2s of a
    window boundary to avoid replay collisions between tests.

    Returns a dict of {cookie_name: cookie_value} for injection into Playwright
    browser contexts.

    Caches the result per admin number to avoid multiple TOTP uses in the
    same test session. Use force_fresh=True to bypass the cache.

    Last updated: 2026-05-09 (v2.23.3: new helper for cookie injection; add cache)
    """
    global _session_cookie_cache
    if not force_fresh and admin in _session_cookie_cache:
        return _session_cookie_cache[admin]

    import hashlib
    import time

    import httpx
    import pyotp

    if admin == 1:
        username = _read_secret("admin1_username")
        totp_secret = _read_secret("admin1_totp_secret")
    else:
        username = _read_secret("admin2_username")
        totp_secret = _read_secret("admin2_totp_secret")
    password = _current_admin_password(admin)

    # F9 correction (2026-07-29): admin tier is HMAC-SHA-512/8-digit
    # (src/yashigani/auth/totp.py TOTP_ALGO_SHA512/TOTP_DIGITS_ADMIN), not
    # pyotp's RFC 6238 default (SHA-1/6-digit). See get_admin_totp_code().
    totp_obj = pyotp.TOTP(totp_secret, digits=8, digest=hashlib.sha512)

    def _wait_for_fresh_code() -> str:
        last = _api_totp_last_used.get(admin, 0.0)
        now = time.time()
        elapsed = now - last
        if elapsed < 62:
            wait_for_replay = 62 - elapsed
            secs_into = now % 30
            wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
            time.sleep(max(wait_for_replay, wait_for_window))
        else:
            secs_into = time.time() % 30
            if secs_into >= 27:
                time.sleep(32 - secs_into)
        code = totp_obj.now()
        _api_totp_last_used[admin] = time.time()
        # 2026-08-12: this path kept its OWN freshness state (_api_totp_last_used) and
        # never touched the SHARED ledger, so do_admin_stepup() — which waits on the
        # shared ledger — saw no record of the code this login had just spent, ran in
        # the same 30s window, and the server rejected the replay
        # (401 invalid_totp_code). One TOTP secret must have ONE window record; publish
        # this use to the shared ledger under the same identity key step-up uses.
        mark_totp_used(f"admin{admin}")
        return code

    # Wait at least 62s since the last TOTP use for this admin to avoid replay.
    # Also wait until we're in the first 27s of a 30s window.
    wait_for_fresh_totp(f"admin{admin}")   # shared ledger (2026-08-12), then local guard
    totp_code = _wait_for_fresh_code()
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False

    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        r = c.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": username,
                "password": password,
                "totp_code": totp_code,
            },
        )
        # YSG-RISK-209 (built 2026-08-08): the functional lane was being banned
        # by the ADVERSARIAL lane. The product's auth throttle is keyed on
        # account AND source IP (correct anti-enumeration design); QA SOP §4.17
        # Rule 5 previously separated lanes by identity only, so the pentest
        # suite's deliberate bogus-credential probes drove the shared-IP counter
        # and every subsequent legitimate admin login failed. Measured cost: 110
        # errors per leg, identical on all four runs (docker headless/headed,
        # podman headless) — and that noise is what hid a genuine HIGH finding
        # (YSG-RISK-201) for the whole campaign. "Expected errors" in a gate are
        # not acceptable: they either get fixed or they mask the real signal.
        #
        # Fix at source: on a throttle response, clear the TEST-RUN throttle
        # state and retry ONCE. This does not weaken the control — it clears
        # counters our own adversarial lane created, in a test deployment. A
        # 429 that survives the retry is still a hard failure.
        if r.status_code == 429:
            cleared = clear_auth_throttle()
            print(f"auth throttle hit for admin{admin} — cleared {cleared} key(s), retrying once "
                  f"(YSG-RISK-209 lane-bleed)", flush=True)
            totp_code = _wait_for_fresh_code()
            r = c.post(
                f"{BASE_URL}/auth/login",
                json={"username": username, "password": password, "totp_code": totp_code},
            )
        assert r.status_code == 200, f"API login failed for admin{admin}: {r.status_code} {r.text[:200]}"
        data = r.json()

        # QA-fix (Ava, 2026-07-31): self-heal the forced-password-change step
        # instead of hard-asserting it already happened. On a genuinely fresh
        # stack (this Tier-B smoke: admin creds still INITIAL) this branch is
        # the FIRST and ONLY place the rotation actually happens; the result
        # is cached in _rotated_admin_password so every other helper
        # (get_admin_credentials, playwright_login_admin, this function
        # itself on a later call) sees the rotated password for the rest of
        # this pytest process.
        if data.get("force_password_change"):
            new_password = _generate_strong_password()
            change_r = c.post(
                f"{BASE_URL}/auth/password/change",
                json={"current_password": password, "new_password": new_password},
            )
            assert change_r.status_code == 200, (
                f"admin{admin} forced password-change failed: "
                f"{change_r.status_code} {change_r.text[:200]}"
            )
            _rotated_admin_password[admin] = new_password
            # Log out the restricted (password-change-required) session, then
            # re-login fresh with the rotated password to get a full session
            # and prove the rotation stuck (A2 step 4/5).
            c.post(f"{BASE_URL}/auth/logout")
            totp_code2 = _wait_for_fresh_code()
            r = c.post(
                f"{BASE_URL}/auth/login",
                json={
                    "username": username,
                    "password": new_password,
                    "totp_code": totp_code2,
                },
            )
            assert r.status_code == 200, (
                f"admin{admin} re-login after rotation failed: {r.status_code} {r.text[:200]}"
            )
            data = r.json()
            assert not data.get("force_password_change"), (
                f"admin{admin} still force_password_change=True after rotation — rotation did not stick"
            )
            # FIND-8: only persist to disk once the re-login above has PROVEN
            # the new password actually works server-side — never persist an
            # unverified write.
            _persist_rotated_password(admin, new_password)

        result = dict(r.cookies)
    _session_cookie_cache[admin] = result
    # Tierb-on-unified consolidation: record establishment time for THIS real
    # login (never touched on the early cache-hit return above), so
    # refresh_admin_context_if_stale() can detect idle-timeout staleness
    # later without re-deriving it from scratch.
    _admin_session_established_at[admin] = time.time()
    # FIND-B-CANARY-401 fix (2026-08-06, Ava, Tier-B consolidated retest):
    # ANY real login reaching this point (force_fresh=True, or the very
    # first population of the cache) evicts every OTHER already-live
    # session for this admin number server-side (single-active-session
    # policy, src/yashigani/auth/session.py SessionStore.create()) --
    # including a long-lived Playwright BrowserContext (e.g. admin_ctx)
    # that was seeded from an earlier call to this same function. Before
    # this fix, only invalidate_cached_session() (the deliberate-logout
    # path) set _admin_session_dirty, so a force_fresh=True re-login
    # elsewhere (e.g. test_relogin_after_rotation_proves_rotation_stuck's
    # own re-login) silently evicted admin_ctx's cookie without flagging
    # it dirty -- refresh_admin_context_if_stale()'s time-based check then
    # saw a falsely-fresh timestamp (this call just bumped it) and skipped
    # refreshing admin_ctx, so the NEXT test to use admin_ctx (observed
    # live: test_canary_loads_for_admin) got a 401 on the server-evicted
    # cookie. Marking dirty here closes that gap the same way the
    # deliberate-logout path already does -- the next
    # refresh_admin_context_if_stale() call for ANY long-lived context for
    # this admin number will now force one real refresh instead of trusting
    # the timestamp alone.
    _admin_session_dirty.add(admin)
    return result


def get_authed_context(pw_or_playwright, *, admin: int = 1, ignore_https_errors: bool = True,
                        force_fresh: bool = False):
    """New browser + context pre-authenticated via API session-cookie injection.

    QA-fix (Ava, Tier-B triage 2026-08-02): promoted from
    test_pentest_webui_adversarial.py's local `_authed_context()` (same
    pattern, same rationale -- see that file's module docstring "CONFTEST
    HAZARD FOUND") into a single shared conftest helper, so every Playwright
    UI-feature test file can authenticate WITHOUT re-driving the browser
    login form.

    Root cause this fixes (Tier-B triage, run
    ytf-docker-macos-29d9c9d8-20260731): test_capability_policy_ui.py,
    test_hibp_admin_ui.py, test_permissions_ui.py and test_backup_ui.py each
    hand-rolled their own browser-driven `_login()`/`_do_login()` that filled
    the login form, then -- on a genuinely fresh stack needing the forced
    password-change step -- filled and submitted #pw-form and IMMEDIATELY
    called page.wait_for_url(BASE_URL + "/admin/"). Per the real client flow
    (src/yashigani/backoffice/static/js/login.js "Step 2: Password Change"
    handler), a successful password change does NOT navigate anywhere -- it
    just re-displays #login-form with a success message and REQUIRES a
    second, fresh login submission with the new password. Since none of
    those four helpers performed that second submission, wait_for_url()
    always hit its full 30s timeout on the very first bootstrap login of the
    run (confirmed: test_capability_policy_ui.py is first in this suite's
    collection order and its ENTIRE file setup-errored on this). Worse: each
    of those helpers ALSO unconditionally wrote `_rotated_admin_password[1] =
    new_pw` right after clicking #pw-btn, with no check that the change
    actually succeeded server-side -- so a bad write there silently poisons
    the ONE shared, process-global credential cache that every OTHER test
    file in the whole 41-minute run reads from, producing the exact
    401-invalid_credentials -> 429-too-many-requests cascade seen across
    test_v233_webauthn_e2e.py and the stepup 401s in
    bootstrap_user_session()'s callers (test_chat_live_e2e.py,
    TestConversationBOLA, TestUserAgentBOLA).

    _api_get_session_cookies() already implements the correct, ASSERT-VERIFIED
    version of this dance over plain HTTP (no browser, no DOM race): it logs
    in, and if force_password_change is set, changes the password, LOGS OUT
    the restricted session, and re-logs-in with the new password -- only then
    does it cache _rotated_admin_password. Authenticating the browser by
    injecting THAT httpx-obtained cookie is strictly safer than re-doing the
    same dance a second time by clicking through the DOM, and matches the
    precedent already established by test_pki_admin_ui.py's `_login()` and
    test_pentest_webui_adversarial.py's `_authed_context()`.

    force_fresh=True bypasses _session_cookie_cache -- use this for any
    module that runs late in a long suite (a session cached at the START of
    a 40-minute run may have aged past the server's session TTL by the time
    a LATE-running file tries to reuse it; confirmed candidate cause of
    test_pki_admin_ui.py's "nav link not found at all" failures, since that
    file's own `_login()` is otherwise correct).
    """
    cookies = _api_get_session_cookies(admin=admin, force_fresh=force_fresh)
    browser = launch_chromium(pw_or_playwright)
    ctx = browser.new_context(ignore_https_errors=ignore_https_errors)
    ctx.add_cookies([{"name": k, "value": v, "url": BASE_URL} for k, v in cookies.items()])
    return browser, ctx


def get_authed_user_context(pw_or_playwright, *, cache_key: str = "default",
                             ignore_https_errors: bool = True, force_fresh: bool = False):
    """User-tier equivalent of get_authed_context(): new browser + context
    pre-authenticated via bootstrap_user_session()'s cookie injection (no
    browser form-login, no re-provisioning if cache_key is already warm).

    Tierb-on-unified consolidation: promoted so admin_ctx/user_ctx (the
    two conformance-suite fixtures previously the biggest source of the
    153-error auth-setup cascade -- see admin_ctx/user_ctx docstrings in
    test_webui_conformance_full.py) share the SAME "new browser + context,
    cookie-injected, never a browser form-login" shape for both tiers,
    instead of admin_ctx using get_authed_context() while user_ctx hand-rolled
    its own browser/context/cookie-injection inline.
    """
    creds = bootstrap_user_session(cache_key=cache_key, force_fresh=force_fresh)
    browser = launch_chromium(pw_or_playwright)
    ctx = browser.new_context(ignore_https_errors=ignore_https_errors)
    domain = BASE_URL.split("://", 1)[-1].split(":")[0]
    ctx.add_cookies([
        {
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
            "secure": BASE_URL.startswith("https://"),
        }
        for name, value in creds["cookies"].items()
    ])
    return browser, ctx


def assert_admin_dashboard_reached(page, *, admin: int = 1) -> None:
    """Single source of truth for 'is this page an authenticated admin
    dashboard'. Factored out of playwright_login_admin() so admin_ctx (and
    any other caller) asserts the identical condition instead of each
    call site re-deriving its own (subtly different) check."""
    assert "/admin/login" not in page.url, (
        f"Still on login page after admin{admin} login — URL: {page.url}\n"
        "Possible: TOTP replay, wrong credentials, throttle, or a stale/expired "
        "cached session cookie (see _api_get_session_cookies force_fresh)."
    )
    assert page.locator("ys-admin-app, a[href^='#']").count() > 0, (
        f"Admin app shell not found — URL: {page.url}"
    )


def assert_user_chat_reached(page) -> None:
    """Single source of truth for 'is this page an authenticated user
    session' (checked via the /chat SPA landing, not bounced to /login)."""
    assert "/login" not in page.url, (
        f"user session cookie injection did not authenticate — URL: {page.url}"
    )


def refresh_admin_context_if_stale(ctx, *, admin: int = 1,
                                    threshold: float = _SESSION_REFRESH_THRESHOLD_SECONDS) -> bool:
    """If admin{N}'s tracked session is older than `threshold` seconds
    (default 600s, safely under the server's 900s/15-min idle timeout --
    src/yashigani/auth/session.py _IDLE_TIMEOUT_SECONDS), force a fresh
    login and re-inject the new cookies into `ctx` (a long-lived Playwright
    BrowserContext), overwriting the old ones in place. No-ops (returns
    False) if the session is still fresh.

    This is the mid-file counterpart to admin_ctx/get_authed_context's
    force_fresh=True at CREATION time: a long-running file (e.g.
    test_webui_conformance_full.py, ~15 test classes sharing one
    module-scoped admin_ctx) can sit idle on that session for over 900s
    between two tests purely from OTHER tests' TOTP-replay waits — this
    catches that case from a shared per-test autouse guard instead of
    every test file inventing its own staleness check.

    FIND-B-A fix (2026-08-04): ALSO forces a refresh if `admin` is in
    _admin_session_dirty (set by invalidate_cached_session() after a
    deliberate logout elsewhere in the run), even if the plain elapsed-time
    check below would otherwise say "still fresh". See the
    _admin_session_dirty module-level comment for why the timestamp alone
    is not race-safe against a concurrent unrelated real login for the same
    admin number.
    """
    import time as _t

    is_dirty = admin in _admin_session_dirty
    if not is_dirty and _t.time() - _admin_session_established_at.get(admin, 0.0) <= threshold:
        return False
    cookies = _api_get_session_cookies(admin=admin, force_fresh=True)
    try:
        ctx.clear_cookies()
    except Exception:
        pass
    ctx.add_cookies([{"name": k, "value": v, "url": BASE_URL} for k, v in cookies.items()])
    _admin_session_dirty.discard(admin)
    return True


def refresh_user_context_if_stale(ctx, *, cache_key: str = "default",
                                   threshold: float = _SESSION_REFRESH_THRESHOLD_SECONDS) -> bool:
    """User-tier equivalent of refresh_admin_context_if_stale(). Also
    dirty-flag aware (see invalidate_cached_user_session())."""
    import time as _t

    is_dirty = cache_key in _user_session_dirty
    if not is_dirty and _t.time() - _user_session_established_at.get(cache_key, 0.0) <= threshold:
        return False
    creds = bootstrap_user_session(cache_key=cache_key, force_fresh=True)
    try:
        ctx.clear_cookies()
    except Exception:
        pass
    domain = BASE_URL.split("://", 1)[-1].split(":")[0]
    ctx.add_cookies([
        {
            "name": name,
            "value": value,
            "domain": domain,
            "path": "/",
            "secure": BASE_URL.startswith("https://"),
        }
        for name, value in creds["cookies"].items()
    ])
    _user_session_dirty.discard(cache_key)
    return True


def user_login_cookies(username: str, password: str, totp_secret: str, *,
                        identity_key: "str | None" = None,
                        digits: int = 6, digest=None) -> dict:
    """Shared user-tier fresh-login primitive: POST /auth/login (with the
    shared per-identity anti-replay guard -- wait_for_fresh_totp/
    mark_totp_used) for an ALREADY-bootstrapped user account, returning the
    resulting session cookies.

    Tierb-on-unified consolidation: this is the single path for any caller
    that needs a brand-new per-test user session for an existing account
    (e.g. test_chat_live_e2e.py's chat_page fixture previously inlined this
    exact POST + anti-replay dance itself instead of calling a shared
    helper -- same underlying mechanism, but duplicated rather than unified,
    the one remaining divergent path this consolidation removes).
    """
    import hashlib
    import httpx
    import pyotp

    digest = digest or hashlib.sha256
    key = identity_key or f"user:{username}"
    totp = pyotp.TOTP(totp_secret, digits=digits, digest=digest)
    wait_for_fresh_totp(key)
    code = totp.now()
    mark_totp_used(key)
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    with httpx.Client(verify=verify, follow_redirects=False, timeout=15) as c:
        r = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": password, "totp_code": code},
        )
        assert r.status_code == 200, f"user login failed for {username}: {r.status_code} {r.text[:300]}"
        assert not r.json().get("force_password_change"), (
            f"user {username} unexpectedly still force_password_change=True"
        )
        return dict(r.cookies)


def playwright_login_admin(page, *, admin: int = 1, force_fresh: bool = False) -> None:
    """
    Full Playwright login for admin1 (or admin2 if admin=2).

    QA-fix (Ava, Tier-B triage 2026-08-02): this used to drive the raw login
    <form> directly, including a hand-rolled forced-password-change step
    that clicked #pw-btn and then immediately asserted the browser had
    navigated to /admin/. Per the real client flow (static/js/login.js
    "Step 2: Password Change" handler), a successful password change does
    NOT navigate anywhere -- it just re-shows #login-form with a success
    message and requires a SECOND, fresh login submission with the new
    password. That made this helper's correctness order-dependent: it only
    ever worked because some OTHER file happened to run first and complete
    the rotation via a different path first. Delegates to
    _api_get_session_cookies() (assert-verified: login, and if
    force_password_change, change password, log out the restricted session,
    re-login with the new password, confirm force_password_change is now
    False) and injects the resulting cookie into this SAME page's browser
    context, then navigates to /admin/ -- removing the fragile browser-DOM
    password-change dance and its order-dependency entirely. Matches
    get_authed_context()'s pattern (same underlying helper).

    Raises AssertionError if admin dashboard is not reached.

    force_fresh=True (added tierb-on-unified consolidation): bypass
    _session_cookie_cache entirely for this call, guaranteeing a session
    provably fresh at the moment of THIS call, not inherited from whatever
    an earlier fixture/file cached hours before. Use for any fixture
    (e.g. admin_ctx) that is the FIRST thing to authenticate in a long file.
    """
    cookies = _api_get_session_cookies(admin=admin, force_fresh=force_fresh)
    page.context.add_cookies([{"name": k, "value": v, "url": BASE_URL} for k, v in cookies.items()])

    # SameSite=Strict priming navigation (2026-08-08).
    #
    # The admin session cookie is set SameSite=Strict
    # (backoffice/routes/auth.py::_set_session_cookie). Chromium does NOT send
    # Strict cookies on a navigation with no same-site initiator — and a
    # page.goto() straight from about:blank is exactly that. So the very first
    # goto after add_cookies arrived WITHOUT the session, the server redirected
    # to /admin/login?next=/admin/, and assert_admin_dashboard_reached failed.
    #
    # This produced 110 fixture ERRORS per leg — 81 of them from admin_ctx
    # alone (27 modules x 3 tests) — identically on docker and podman, headed
    # and headless, on every run of the 4.1.2 campaign. It was repeatedly
    # mis-attributed to the auth throttle; a throttle fix was written and fired
    # ZERO times while the 110 stayed put. It is a browser cookie-policy rule,
    # not a product fault and not a throttle: fixtures that happened to
    # navigate to the origin first (e.g. browser_page_with_va -> /admin/login)
    # never showed it.
    #
    # One cheap same-origin navigation establishes the site context; the next
    # navigation is then same-site and carries the Strict cookie.
    page.goto(f"{BASE_URL}/admin/login", wait_until="domcontentloaded")
    page.goto(f"{BASE_URL}/admin/")
    page.wait_for_timeout(1000)

    # Confirm admin dashboard elements are present. The current /admin/ app
    # is ui4 (backoffice/static/ui4/admin/admin.html -- root custom element
    # <ys-admin-app>, module nav rendered as `a[href='#module-id']` per
    # module-registry.js / admin-nav.js).
    assert_admin_dashboard_reached(page, admin=admin)


# ---------------------------------------------------------------------------
# User-tier session helpers (v4.1.2 conformance suite — webui-inventory.md)
#
# Unlike admin1/admin2, no user-tier account is seeded at install time.
# `bootstrap_user_session()` provisions a throwaway user via the admin API
# (POST /admin/users, StepUpAdminSession-gated), then drives the full
# 5-step first-login flow: initial password → forced password change →
# TOTP provision start/confirm → logout → re-login with rotated creds.
# Mirrors the admin bootstrap discipline (retro v2.23.1 §6.C / A2) but for
# the user plane, which has no pre-provisioned secrets file to read.
#
# User-tier TOTP is SHA-256/6-digit (routes/users.py: TOTP_ALGO_SHA256,
# TOTP_DIGITS_USER) — distinct from admin's SHA-512/8-digit. pyotp needs an
# explicit digest= kwarg for this; admin helpers above rely on pyotp's
# HMAC-SHA1 default, which is WRONG for both tiers in production but is a
# separate, already-tracked pin (project_totp_uses_sha256_not_sha1.md) —
# not re-litigated here. This helper uses SHA-256/6-digit unconditionally
# for user accounts, matching the server-side constant.
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import time as _time
import uuid as _uuid

_user_session_cache: "dict[str, dict]" = {}  # cache key -> cookies dict


def _admin_headers(admin: int = 1) -> dict:
    return {"X-Yashigani-Plane": "admin"}


_seeded_users_cache: "list | None" = None
_seeded_key_assignment: dict = {}


def _load_seeded_users() -> list:
    """Parse populate-demo's demo-user-creds file (path in env
    YASHIGANI_SEEDED_CREDS) into a list of pre-seeded @agnosticsec.com
    user-tier identities. Empty when the env is unset/missing -> callers
    fall back to self-provisioning. Cached for the process."""
    global _seeded_users_cache
    if _seeded_users_cache is not None:
        return _seeded_users_cache
    users: list = []
    path = os.environ.get("YASHIGANI_SEEDED_CREDS")
    if path and os.path.exists(path):
        for line in open(path, encoding="utf-8", errors="ignore"):
            m = _ytf_re.match(
                r"(\S+@agnosticsec\.com)\s+username=(\S+)\s+pw=(\S+)\s+totp=(\S+)", line
            )
            if m:
                email, uname, pw, totp = m.groups()
                users.append(
                    {"email": email, "username": uname, "password": pw, "totp_secret": totp}
                )
    _seeded_users_cache = users
    return users


def _maybe_seeded_user_session(cache_key: str) -> "dict | None":
    """PROTOCOL (coherent-methodology): reuse a pre-seeded differential
    identity instead of self-provisioning a throwaway 'ava-conf-*' user.

    Self-provisioning POST /admin/users 402s under a capped (Community, 5-seat)
    licence whose seats are already filled by the differential seed -- which
    silently starved the ENTIRE live user-plane security sweep (BOLA / path-
    traversal / injection / admin-reject / ring-fence) on both runtimes. The
    seeded @agnosticsec.com users ARE real user-tier identities (already through
    first-login + rotation by populate-demo), so reusing them -- one real login
    per identity, real OTP -- lets those tests actually execute under Community.
    Distinct cache_keys deterministically get DISTINCT seeded users (BOLA needs
    two). Returns None (-> fall back to provisioning) when no seeded creds file
    is configured, preserving the historical behaviour for uncapped tiers.
    """
    import httpx
    import pyotp

    users = _load_seeded_users()
    if not users:
        return None
    if cache_key not in _seeded_key_assignment:
        _seeded_key_assignment[cache_key] = len(_seeded_key_assignment) % len(users)
    u = users[_seeded_key_assignment[cache_key]]
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    totp = pyotp.TOTP(u["totp_secret"], digits=6, digest=_hashlib.sha256)
    wait_for_fresh_totp(f"user:{u['username']}")
    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        r = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": u["username"], "password": u["password"], "totp_code": totp.now()},
        )
        mark_totp_used(f"user:{u['username']}")
    assert r.status_code == 200, (
        f"seeded user reuse: login for {u['username']!r} failed: "
        f"{r.status_code} {r.text[:200]} (YASHIGANI_SEEDED_CREDS stale?)"
    )
    return {
        "username": u["username"],
        "email": u["email"],
        "password": u["password"],
        "totp_secret": u["totp_secret"],
        "cookies": dict(r.cookies),
    }

# --- end-user quota hygiene (module level so TESTS can use it, not just
# bootstrap_user_session) -------------------------------------------------
# 2026-08-11, FIND-0805-015a: this logic already existed as a CLOSURE inside
# bootstrap_user_session, where no test could reach it, so the create-user
# tests could not free a slot and failed with 402 end_user_limit_exceeded once
# populate-demo.py had seeded its 5 users against the 5-user Community cap
# (licensing/enforcer.py:95). Promoted rather than duplicated -- the nested
# version now delegates here, so there is exactly one implementation.
# Only ever touches this suite's own throwaway markers, never a real account.
_THROWAWAY_EMAIL_PREFIXES = ("ava-conf-", "ava-quota-", "ava-dup-")


def _seeded_user_credentials() -> "list[dict]":
    """Read the identities populate-demo.py (the users installer) seeded.

    File: $YASHIGANI_DEMO_OUT_DIR/demo-user-creds-*.txt, one user per line:
      <email>  username=<u>  pw=<p>  totp=<base32>  group=<g>

    Returns [] when the users installer has not run, so callers fall back to
    creating an account. Added 2026-08-12 (FIND-0805-016): run-users-installer.sh
    states the suite should "consume real seeded identities instead of each test
    inventing its own", and QA SOP 4.17 Rule 6 forbids bypassing the user
    pathway -- a seeded user logging in IS that pathway, whereas minting an
    account over the admin API is not.
    """
    import glob as _glob
    out_dir = os.getenv("YASHIGANI_DEMO_OUT_DIR") or os.path.join(
        os.getenv("YTF_RUN_DIR", ""), "demo-out")
    files = sorted(_glob.glob(os.path.join(out_dir, "demo-user-creds-*.txt")),
                   key=os.path.getmtime, reverse=True)
    for path in files:
        users = []
        try:
            for line in open(path):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = dict(
                    part.split("=", 1) for part in line.split() if "=" in part
                )
                if fields.get("username") and fields.get("pw") and fields.get("totp"):
                    users.append({
                        "email": line.split()[0],
                        "username": fields["username"],
                        "password": fields["pw"],
                        "totp_secret": fields["totp"],
                    })
        except OSError:
            continue
        if users:
            return users
    return []


def _login_seeded_user(candidates: "list[dict]") -> "dict | None":
    """Log a seeded user in and return the bootstrap_user_session shape.

    User tier is HMAC-SHA-256 / 6-digit (admin tier is SHA-512/8 -- do not
    confuse them). Tries each candidate so one wedged account cannot strand a
    whole leg. Returns None if none authenticate, leaving the caller's original
    402 assertion to fire with its real message rather than masking it.
    """
    for user in candidates:
        try:
            # user_login_cookies() is the single shared user-tier login primitive
            # (SHA-256/6-digit + the per-identity anti-replay guard). Do not inline
            # the POST here -- inlining it is the exact duplication the
            # tierb-on-unified consolidation removed.
            cookies = user_login_cookies(
                user["username"], user["password"], user["totp_secret"])
        except Exception:
            continue  # try the next seeded identity; one wedged account must not strand a leg
        return {
            "username": user["username"],
            "email": user["email"],
            "password": user["password"],
            "totp_secret": user["totp_secret"],
            "cookies": cookies,
        }
    return None


def delete_end_user(client, username: str) -> bool:
    """DELETE /admin/users/{username} (StepUpAdminSession-gated -- the caller's
    cookies must already carry a fresh step-up). True if it was deleted."""
    if not username:
        return False
    return client.delete(f"{BASE_URL}/admin/users/{username}").status_code == 200


def free_end_user_capacity(cookies: dict, *, min_free: int = 1) -> int:
    """Delete up to `min_free` of this suite's throwaway end users to free
    licence capacity. Returns how many were actually deleted."""
    import httpx  # module-scope import does not exist in this file — import locally
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    with httpx.Client(verify=verify, cookies=cookies, follow_redirects=False, timeout=10) as c:
        r = c.get(f"{BASE_URL}/admin/users")
        if r.status_code != 200:
            return 0
        throwaway = [
            u for u in r.json().get("users", [])
            if (u.get("email") or "").startswith(_THROWAWAY_EMAIL_PREFIXES)
            and (u.get("email") or "").endswith("@example.com")
        ]
        throwaway.sort(key=lambda u: u.get("created_at") or "")
        deleted = 0
        for u in throwaway:
            if deleted >= min_free:
                break
            if delete_end_user(c, u.get("username")):
                deleted += 1
        return deleted


def bootstrap_user_session(*, cache_key: str = "default", force_fresh: bool = False) -> dict:
    """
    Provision a throwaway user-tier account and complete the full 5-step
    first-login bootstrap. Returns a dict:
      {
        "username": str, "email": str,
        "password": str,          # ROTATED password (post force-change)
        "totp_secret": str,       # base32 secret, SHA-256/6-digit
        "cookies": dict,          # __Host-yashigani_session cookies, post-rotation login
      }

    Requires an admin1 session (uses _api_get_session_cookies(admin=1) plus a
    fresh /auth/stepup call — POST /admin/users is StepUpAdminSession-gated).

    Cached per cache_key for the pytest session so multiple test modules can
    share one throwaway user without re-provisioning (and without exhausting
    the 62s TOTP replay window on every test file). Use force_fresh=True for
    tests that need an ISOLATED user (e.g. BOLA cross-user probes need TWO
    distinct users — call with two different cache_key values).
    """
    global _user_session_cache
    if not force_fresh and cache_key in _user_session_cache:
        return _user_session_cache[cache_key]

    # PROTOCOL: under a capped licence, reuse a seeded differential identity
    # rather than self-provisioning (which 402s once the seed fills the seats).
    # No-op (returns None) when YASHIGANI_SEEDED_CREDS is unset -> provisioning.
    _seeded = _maybe_seeded_user_session(cache_key)
    if _seeded is not None:
        _user_session_cache[cache_key] = _seeded
        _user_session_established_at[cache_key] = _time.time()
        return _seeded

    import httpx
    import pyotp

    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    admin_cookies = _api_get_session_cookies(admin=1)
    admin_totp_secret = _read_secret("admin1_totp_secret")

    unique = _uuid.uuid4().hex[:10]
    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): the server's
    # email validator (email-validator, syntax-only / check_deliverability=False)
    # rejects the ".invalid" TLD outright as an RFC 2606 special-use reserved
    # name ("value is not a valid email address ... special-use or reserved
    # name") -- confirmed directly:
    #   python3 -c "from email_validator import validate_email;
    #     validate_email('a@example.invalid', check_deliverability=False)"
    #   -> EmailNotValidError. The SAME check accepts 'example.com' (also
    # RFC 2606-reserved, but not on email-validator's syntax-reject list) --
    # matches the domain already used by other test suites (test_user_
    # documents_gaps_3_4_5.py, test_per_user_ratelimit.py, etc). This was
    # blocking every bootstrap_user_session() caller (BOLA probes, documents/
    # sensitivity/chat user-plane tests) with a 422, not a product defect.
    email = f"ava-conf-{unique}@example.com"

    def _attempt_stepup_and_create(cookies: dict):
        """One stepup + create-user round-trip against a (possibly stale)
        cached admin1 session. Returns (stepup_resp, create_resp_or_None)."""
        _wait_for_fresh_totp_window(admin=1)
        code = pyotp.TOTP(admin_totp_secret, digits=8, digest=_hashlib.sha512).now()
        _api_totp_last_used[1] = _time.time()
        with httpx.Client(verify=verify, cookies=cookies, follow_redirects=False, timeout=10) as c:
            stepup_resp = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
            if stepup_resp.status_code != 200:
                return stepup_resp, None
            create_resp = c.post(f"{BASE_URL}/admin/users", json={"email": email})
            return stepup_resp, create_resp

    def _free_end_user_capacity(cookies: dict, *, min_free: int = 1) -> int:
        """Delegates to the module-level free_end_user_capacity() (promoted
        2026-08-11, FIND-0805-015a, so tests can reach it too). Kept as a thin
        alias because several call sites inside this function use the old name.
        Behaviour is unchanged: delete this suite's throwaway
        'ava-*@example.com' end users via the real DELETE
        /admin/users/{username}, reusing the step-up already on `cookies`.
        Confirmed live: 402 end_user_limit_exceeded (limit=5, current=5).
        """
        return free_end_user_capacity(cookies, min_free=min_free)

    def _free_seat_capacity_with_fresh_admin(*, min_free: int = 1) -> int:
        """Same hygiene as _free_end_user_capacity, but for the LOGIN-time
        ACTIVE-SEAT gate (403 seat_limit_exceeded) -- confirmed live
        2026-08-03 (Tier-B tierb-on-unified consolidation) to be a DIFFERENT
        accounting bucket from the CREATE-time 402 end_user_limit_exceeded
        gate _free_end_user_capacity already handles: 5 pre-existing
        'ava-conf-*@example.com' throwaway accounts from many prior pytest
        invocations against this same long-lived stack had already exhausted
        the licence's 5-seat cap, so a BRAND NEW account (itself created
        successfully -- account creation and seat activation are checked
        against different limits) failed 403 on its post-rotation re-login
        with {"error":"seat_limit_exceeded","current":5,"max":5}.

        Forces a fresh admin1 login + fresh step-up before deleting: the
        step-up taken at the very start of this bootstrap (in
        _attempt_stepup_and_create above) has, by the time a seat-limit
        retry is needed here, gone through the ~62s+ TOTP-freshness waits
        this function's caller already performed and may have aged past
        YASHIGANI_STEPUP_TTL_SECONDS -- DELETE /admin/users/{username} is
        itself StepUpAdminSession-gated, so a stale step-up would silently
        no-op this hygiene rather than actually freeing a seat.
        """
        fresh_admin_cookies = _api_get_session_cookies(admin=1, force_fresh=True)
        _wait_for_fresh_totp_window(admin=1)
        stepup_code = pyotp.TOTP(admin_totp_secret, digits=8, digest=_hashlib.sha512).now()
        _api_totp_last_used[1] = _time.time()
        with httpx.Client(verify=verify, cookies=fresh_admin_cookies, follow_redirects=False, timeout=10) as c:
            stepup_resp = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": stepup_code})
            if stepup_resp.status_code != 200:
                return 0
        return _free_end_user_capacity(fresh_admin_cookies, min_free=min_free)

    stepup_resp, create_resp = _attempt_stepup_and_create(admin_cookies)

    # QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): _api_get_session_cookies
    # caches admin1's session cookie for the lifetime of the pytest process
    # (unless a caller explicitly passes force_fresh=True). Over a multi-hour
    # run, that cached session's server-side TTL can expire before this
    # function is next called -- confirmed live this run: "stepup failed: 401
    # session_expired_or_invalid" errored EVERY Conversation/UserAgent BOLA
    # test's setup for the rest of the suite, once the cache went stale, even
    # though the underlying admin1 credentials/TOTP were completely fine and
    # BOLA itself was separately live-proven to hold (Laura, Tier-C). Rather
    # than erroring on a stale cache, force a fresh admin1 login (bypasses the
    # cache) and retry ONCE with a brand-new TOTP code before giving up.
    if stepup_resp.status_code == 401:
        admin_cookies = _api_get_session_cookies(admin=1, force_fresh=True)
        stepup_resp, create_resp = _attempt_stepup_and_create(admin_cookies)

    # Test-environment hygiene (see _free_end_user_capacity docstring): a
    # long-lived stack accumulates this suite's own throwaway end-users
    # across many pytest invocations until the license's end-user cap is
    # hit (402 end_user_limit_exceeded) -- free capacity by deleting the
    # OLDEST throwaway 'ava-conf-*@example.com' accounts (never a real
    # user), then retry the create once.
    if create_resp is not None and create_resp.status_code == 402:
        if _free_end_user_capacity(admin_cookies, min_free=1):
            stepup_resp, create_resp = _attempt_stepup_and_create(admin_cookies)

    # 2026-08-12, FIND-0805-016: freeing capacity CANNOT work when the users
    # installer has run. populate-demo.py seeds exactly 5 end users and the
    # Community/no-licence tier caps end users at 5 (licensing/enforcer.py:95),
    # so current==limit==5 with ZERO throwaway 'ava-conf-*' accounts to delete --
    # every slot is a real seeded identity. That produced 43 setup ERRORs on the
    # podman-4.9 leg and 2 failures on docker, all with the same 402.
    #
    # The correct fix is not to free a slot but to stop inventing an account at
    # all: run-users-installer.sh's own header states it runs "before the test
    # tiers, so the suite consumes real seeded identities instead of each test
    # inventing its own". The suite never implemented that half. It does now --
    # a seeded user is used when one is available, and creation stays as the
    # fallback for stacks where the users installer has not run.
    if create_resp is not None and create_resp.status_code == 402:
        seeded = _seeded_user_credentials()
        if seeded:
            session = _login_seeded_user(seeded)
            if session is not None:
                _user_session_cache[cache_key] = session
                return session

    assert stepup_resp.status_code == 200, (
        f"stepup failed (even after forcing a fresh admin1 session): "
        f"{stepup_resp.status_code} {stepup_resp.text[:200]}"
    )
    assert create_resp is not None and create_resp.status_code == 200, (
        f"POST /admin/users failed: "
        f"{getattr(create_resp, 'status_code', None)} {getattr(create_resp, 'text', '')[:300]}"
    )
    created = create_resp.json()

    username = created["username"]
    temp_password = created["temporary_password"]
    totp_secret = created["totp_secret"]
    totp = pyotp.TOTP(totp_secret, digits=6, digest=_hashlib.sha256)

    # Wait for a fresh 30s window before the first user-tier TOTP use.
    secs_into = _time.time() % 30
    if secs_into >= 27:
        _time.sleep(32 - secs_into)

    new_password = "".join(
        __import__("secrets").choice(__import__("string").ascii_letters + __import__("string").digits + "!*-._~,")
        for _ in range(40)
    )

    first_totp_code = totp.now()
    _first_totp_used_at = _time.time()
    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        # Step 1: initial login with temp password -> force_password_change:true
        login_resp = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": temp_password, "totp_code": first_totp_code},
        )
        assert login_resp.status_code == 200, (
            f"initial user login failed: {login_resp.status_code} {login_resp.text[:300]}"
        )
        login_data = login_resp.json()
        first_login_cookies = dict(login_resp.cookies)
        assert login_data.get("force_password_change") is True, (
            "expected force_password_change=True on first user login "
            f"(got {login_data})"
        )

        # Step 2: forced password change.
        c.cookies.update(first_login_cookies)
        pw_resp = c.post(
            f"{BASE_URL}/auth/password/change",
            json={"current_password": temp_password, "new_password": new_password},
        )
        assert pw_resp.status_code == 200, (
            f"user password change failed: {pw_resp.status_code} {pw_resp.text[:300]}"
        )

    # FIXED 2026-07-30 (Ava, Tier-B leg v412-ytf-podman-13033ff9): this
    # previously only aligned to a 30s window BOUNDARY (secs_into >= 25/27 ->
    # sleep to the next window), which does NOT guarantee the user-tier 60s
    # TOTP replay cache has expired since first_totp_code was used above --
    # if step 2 (password change) completes quickly, totp.now() below can
    # return the IDENTICAL code value as step 1, and the server correctly
    # rejects it as a replay (surfaced as generic "invalid_credentials" for
    # anti-enumeration, not an obviously-TOTP-shaped error). Confirmed live:
    # this crashed "user re-login after password rotation failed: 401
    # invalid_credentials" while testing the chat/PII byte-proof. Now
    # explicitly waits until >=62s have elapsed since first_totp_code was
    # used (mirrors _wait_for_fresh_totp_window's admin-tier logic), THEN
    # additionally avoids the last few seconds of whatever window that lands
    # in, guaranteeing a genuinely fresh, never-before-submitted code.
    _elapsed = _time.time() - _first_totp_used_at
    if _elapsed < 62:
        _time.sleep(62 - _elapsed)
    secs_into = _time.time() % 30
    if secs_into >= 25:
        _time.sleep(32 - secs_into)

    with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
        # Step 3/4: re-login with rotated password, proves rotation stuck (A2 step 5
        # -- here folded in since TOTP was already provisioned server-side at
        # POST /admin/users time; there is no separate provision/start+confirm
        # round-trip for admin-created user accounts, unlike self-service TOTP
        # provisioning. The re-login IS the "prove rotation stuck" step.)
        relogin_resp = c.post(
            f"{BASE_URL}/auth/login",
            json={"username": username, "password": new_password, "totp_code": totp.now()},
        )
        # QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): record THIS
        # account's TOTP use in the same shared per-identity ledger that
        # wait_for_fresh_totp()/mark_totp_used() (see below) exposes to every
        # OTHER caller -- e.g. test_chat_live_e2e.py's chat_page fixture,
        # which runs its OWN fresh login for this exact username immediately
        # after bootstrap_user_session() returns. Without this, chat_page's
        # guard had no memory of the code JUST consumed here and could
        # generate the IDENTICAL window's code a few seconds later -- a
        # replay, surfaced generically as 401 invalid_credentials. Marked
        # regardless of outcome (a used code is used whether or not the
        # server accepted it).
        mark_totp_used(f"user:{username}")

    # Test-environment hygiene (see _free_seat_capacity_with_fresh_admin
    # docstring, tierb-on-unified consolidation): the licence's ACTIVE-SEAT
    # cap is checked at THIS re-login/activation step -- a DIFFERENT
    # accounting bucket from the end-user-record cap _free_end_user_capacity
    # already handles at create time. A long-lived stack accumulates this
    # suite's own throwaway accounts until 403 seat_limit_exceeded blocks
    # even a freshly created account's first real activation. Free capacity
    # by deleting the OLDEST throwaway 'ava-conf-*@example.com' accounts
    # (oldest-first -- never this brand-new one), wait for a fresh TOTP
    # window for THIS account (the failed attempt's code must not be
    # replayed on retry), and retry the re-login exactly once.
    if relogin_resp.status_code == 403:
        try:
            _is_seat_limit = relogin_resp.json().get("detail", {}).get("error") == "seat_limit_exceeded"
        except Exception:
            _is_seat_limit = False
        if _is_seat_limit and _free_seat_capacity_with_fresh_admin(min_free=1):
            wait_for_fresh_totp(f"user:{username}")
            with httpx.Client(verify=verify, follow_redirects=False, timeout=10) as c:
                relogin_resp = c.post(
                    f"{BASE_URL}/auth/login",
                    json={"username": username, "password": new_password, "totp_code": totp.now()},
                )
                mark_totp_used(f"user:{username}")

    assert relogin_resp.status_code == 200, (
        f"user re-login after password rotation failed (even after freeing "
        f"seat capacity if seat-limited): "
        f"{relogin_resp.status_code} {relogin_resp.text[:300]}"
    )
    relogin_data = relogin_resp.json()
    assert not relogin_data.get("force_password_change"), (
        "user still force_password_change=True after completing the change flow"
    )
    final_cookies = dict(relogin_resp.cookies)

    result = {
        "username": username,
        "email": email,
        "password": new_password,
        "totp_secret": totp_secret,
        "cookies": final_cookies,
    }
    _user_session_cache[cache_key] = result
    # Tierb-on-unified consolidation: record establishment time for THIS real
    # bootstrap (never touched on the early cache-hit return above), so
    # refresh_user_context_if_stale() can detect idle-timeout staleness later.
    _user_session_established_at[cache_key] = _time.time()
    return result


def _wait_for_fresh_totp_window(*, admin: int = 1) -> None:
    """Block until at least 62s have passed since the last TOTP use for this
    admin AND we're in the first ~27s of a 30s window. Shared replay-avoidance
    logic factored out of _api_get_session_cookies/playwright_login_admin."""
    last = _api_totp_last_used.get(admin, 0.0)
    now = _time.time()
    elapsed = now - last
    if elapsed < 62:
        wait_for_replay = 62 - elapsed
        secs_into = now % 30
        wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
        _time.sleep(max(wait_for_replay, wait_for_window))
    else:
        secs_into = _time.time() % 30
        if secs_into >= 27:
            _time.sleep(32 - secs_into)


# ---------------------------------------------------------------------------
# Generic per-identity TOTP anti-replay guard (any tier, any file)
# ---------------------------------------------------------------------------
#
# QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): _wait_for_fresh_totp_window
# above only ever guarded admin-tier logins (keyed by an int admin number,
# backed by _api_totp_last_used). Several OTHER per-test-fresh-login call
# sites across the suite (test_chat_live_e2e.py's chat_page fixture is the
# confirmed first domino in this run's cascade) instead hand-rolled their own
# WEAKER check -- "am I in the first ~25s of a 30s window?" -- with no memory
# of whether THIS identity's TOTP secret had already produced a code in the
# current window. Two back-to-back parametrized tests landing in the same
# window each pass that check independently, then both submit the IDENTICAL
# code: the second is rejected as a replay (401 invalid_credentials, not
# obviously TOTP-shaped -- surfaced generically for anti-enumeration), and
# after _THROTTLE_ACCOUNT_THRESHOLD (3) such failures accumulate the
# account-level auth throttle trips (429 too_many_requests) for the REST of
# the run, since nothing else about the login was ever wrong.
#
# wait_for_fresh_totp(key)/mark_totp_used(key) below generalise the same
# "≥62s since last use of THIS EXACT identity" guard to any string key, so
# every fresh-login call site in the suite can share one process-wide replay
# ledger instead of each getting its own subtly-insufficient local check.
# Admin-tier code keeps using _wait_for_fresh_totp_window/_api_totp_last_used
# unchanged (established, working, cross-referenced by multiple call sites);
# this is additive, for every OTHER identity (chat/user-tier logins keyed by
# username, etc).
# ---------------------------------------------------------------------------

_generic_totp_last_used: "dict[str, float]" = {}  # identity key -> time.time() of last use


def wait_for_fresh_totp(key: str) -> None:
    """Block until at least 62s have passed since the last TOTP code was
    consumed for identity `key` AND we're in the first ~27s of a 30s window.
    Caller MUST call mark_totp_used(key) immediately after generating (and
    submitting) the code."""
    last = _generic_totp_last_used.get(key, 0.0)
    now = _time.time()
    elapsed = now - last
    if elapsed < 62:
        wait_for_replay = 62 - elapsed
        secs_into = now % 30
        wait_for_window = (30 - secs_into + 2) if secs_into >= 27 else 0
        _time.sleep(max(wait_for_replay, wait_for_window))
    else:
        secs_into = _time.time() % 30
        if secs_into >= 27:
            _time.sleep(32 - secs_into)


def mark_totp_used(key: str) -> None:
    """Record that identity `key` just consumed a TOTP code, for
    wait_for_fresh_totp()'s next caller (any identity, any file)."""
    _generic_totp_last_used[key] = _time.time()


def playwright_login_user(page, *, cache_key: str = "default", force_fresh: bool = False) -> dict:
    """
    Full Playwright login for a throwaway user-tier account, provisioned via
    bootstrap_user_session(). Injects the rotated-session cookie into the
    Playwright browser context (faster + avoids a second TOTP round-trip vs.
    driving the login form again) then navigates to /chat to confirm.

    Returns the same dict as bootstrap_user_session().
    """
    creds = bootstrap_user_session(cache_key=cache_key, force_fresh=force_fresh)
    page.context.add_cookies([
        {
            "name": name,
            "value": value,
            "domain": BASE_URL.split("://", 1)[-1].split(":")[0],
            "path": "/",
            "secure": BASE_URL.startswith("https://"),
        }
        for name, value in creds["cookies"].items()
    ])
    page.goto(f"{BASE_URL}/chat")
    page.wait_for_timeout(1500)
    assert_user_chat_reached(page)
    return creds


# ---------------------------------------------------------------------------
# Real admin step-up (Tiago correction, 2026-08-03): stepup-gated mutation
# endpoints (StepUpAdminSession, YASHIGANI_STEPUP_TTL_SECONDS default 300s)
# must be exercised with a GENUINE step-up -- a freshly computed, never-
# replayed TOTP code POSTed to /auth/stepup -- not tolerated as "either
# outcome is fine" by the calling test. This is the single shared primitive
# for that: any test needing a real step-up before a mutation call should use
# this instead of hand-rolling its own TOTP-compute + /auth/stepup POST.
# ---------------------------------------------------------------------------


def do_admin_stepup(cookies: dict, *, admin: int = 1) -> dict:
    """Perform a REAL admin step-up against an existing admin{N} session:
    compute a fresh HMAC-SHA-512/8-digit TOTP code (waiting, via the shared
    per-identity anti-replay ledger, for a new 30s window that has not
    already been used for this identity) and POST it to /auth/stepup using
    the given session cookies. Returns the parsed JSON response.

    Raises AssertionError if the server rejects the step-up (never silently
    tolerated by this helper -- callers that need to assert on a
    NOT-stepped-up state should simply not call this, as
    TestSessionLifecycle.test_stepup_required_endpoint_rejects_without_fresh_stepup
    already does).
    """
    import hashlib

    import httpx
    import pyotp

    totp_secret = _read_secret("admin1_totp_secret" if admin == 1 else f"admin{admin}_totp_secret")
    key = f"admin{admin}"  # identity-keyed: shared with get_admin_totp_code (2026-08-12)
    wait_for_fresh_totp(key)
    code = pyotp.TOTP(totp_secret, digits=8, digest=hashlib.sha512).now()
    mark_totp_used(key)
    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    with httpx.Client(verify=verify, cookies=cookies, follow_redirects=False, timeout=10) as c:
        r = c.post(f"{BASE_URL}/auth/stepup", json={"totp_code": code})
        assert r.status_code == 200, f"admin{admin} stepup failed: {r.status_code} {r.text[:200]}"
        return r.json()


# ---------------------------------------------------------------------------
# Session-scoped shared identities (Tiago correction, 2026-08-03)
# ---------------------------------------------------------------------------
#
# Cookie-injection-as-shortcut is NOT the answer here, and force_fresh at
# every fixture-creation is NOT either (that just trades one problem --
# staleness -- for another: MORE real logins, i.e. more TOTP-replay/
# rate-limit exposure). The actual fix: log in via the REAL /auth/login (or
# bootstrap) flow, with a REAL freshly-computed OTP, exactly ONCE per
# identity for the WHOLE pytest run, and reuse that ONE authenticated
# session for every test that needs it. pytest's ordinary scope="session"
# fixture caching gives us that for free: the fixture body below runs once
# no matter how many test files/classes across the whole invocation request
# it, and its result (a live browser context carrying that one real session
# cookie) is handed to every one of them.
#
# playwright_login_admin()/playwright_login_user() ARE the real-login
# primitives (real POST /auth/login, real computed TOTP code from the actual
# secret, no DOM form-fill) -- these fixtures call them exactly once each for
# the whole run via session scope, then every dependent test reuses the
# resulting context. Mutation endpoints gated by StepUpAdminSession still
# require their own genuine step-up (do_admin_stepup() above) -- reusing the
# base login session does not and must not imply step-up is pre-satisfied.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def _shared_pw():
    """ONE Playwright driver for the entire pytest session/invocation."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        yield pw


@pytest.fixture(scope="session")
def admin_ctx(_shared_pw):
    """ONE real admin1 session (real login, real freshly-computed TOTP),
    reused by every test in every file that requests this fixture for the
    whole pytest run. See module docstring above."""
    browser = launch_chromium(_shared_pw)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    # force_fresh=True — 2026-08-10. playwright_login_admin's OWN docstring says:
    # "Use for any fixture (e.g. admin_ctx) that is the FIRST thing to
    # authenticate in a long file." admin_ctx did not, so it reused the
    # process-cached session. Any earlier test that logs out
    # (TestSessionLifecycle::test_logout_redirect_clears_admin_session)
    # invalidates that shared cookie server-side, and EVERY admin_ctx setup
    # afterwards then injects a dead cookie and lands on /admin/login.
    # That is the 110 fixture errors per leg: they run contiguously from the
    # logout test to the end of the file, on every runtime and both browser
    # modes, because the cache is process-global and the logout is real.
    playwright_login_admin(page, admin=1, force_fresh=True)
    yield ctx, page
    ctx.close()
    browser.close()


@pytest.fixture(scope="session")
def user_ctx(_shared_pw):
    """ONE real throwaway user-tier session (real bootstrap: provision,
    forced password change, real freshly-computed TOTP code, re-login),
    reused by every test in every file that requests this fixture for the
    whole pytest run. See module docstring above."""
    browser = launch_chromium(_shared_pw)
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    playwright_login_user(page, cache_key="webui-suite-primary")
    yield ctx, page
    ctx.close()
    browser.close()


@pytest.fixture(autouse=True)
def _keep_shared_sessions_fresh(request):
    """Idle-timeout safety net for the two session-scoped fixtures above.
    The server's session idle-timeout is 900s (src/yashigani/auth/session.py
    _IDLE_TIMEOUT_SECONDS) -- across a genuinely long full-suite run there
    can be legitimate multi-hundred-second gaps between two tests that both
    happen to need the SAME identity (e.g. a long stretch of user-only
    tests while the shared admin session sits untouched). Rather than a
    routine re-login (which would reintroduce the "many logins" problem this
    whole consolidation removes), this only forces a fresh re-login when the
    tracked session is ALREADY past a 600s safety margin -- a rare safety
    net, not a routine behaviour -- and re-injects the refreshed cookies into
    the SAME long-lived context in place, so no browser/page identity
    changes underneath any test."""
    if "admin_ctx" in request.fixturenames:
        ctx, _ = request.getfixturevalue("admin_ctx")
        refresh_admin_context_if_stale(ctx, admin=1)
    if "user_ctx" in request.fixturenames:
        ctx, _ = request.getfixturevalue("user_ctx")
        refresh_user_context_if_stale(ctx, cache_key="webui-suite-primary")
    yield


# ---------------------------------------------------------------------------
# pytest_configure — register markers
# ---------------------------------------------------------------------------


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "playwright_ui: marks Playwright browser-based tests",
    )
    config.addinivalue_line(
        "markers",
        "api_contract: marks HTTP-level API contract tests (no browser)",
    )
    config.addinivalue_line(
        "markers",
        "security_probe: marks adversarial / purple-team security tests",
    )
    config.addinivalue_line(
        "markers",
        "multi_identity: test serialises multiple fresh TOTP logins (admin1+"
        "admin2+user, rotation/re-login, mixed provisioning) and needs the "
        "extended per-test timeout budget below (FIND-0813-011) instead of "
        "the default 300s ceiling.",
    )


# ---------------------------------------------------------------------------
# pytest_collection_modifyitems — auto-skip when stack not running
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    if not STACK_RUNNING:
        skip = pytest.mark.skip(reason="Yashigani stack not running — start with docker/podman compose up")
        for item in items:
            if "playwright" in str(item.fspath):
                item.add_marker(skip)

    # Item 8 / FIND-B-USERAGENTBOLA-HANG (4.1.2 3-runtime retest, 2026-08-04):
    # pytest-timeout was not installed in this harness's venv at all, so a
    # genuinely hung test (confirmed this retest: TestAgentGeneratePrompt
    # Injection's real-LLM-dependent canary blocked with ZERO output for
    # 2min then 4min, no traceback, no crash, no orphaned process visible)
    # had nothing to kill it — the class of bug that orphaned a whole
    # pytest process for 45 minutes on a prior run. Apply a default 300s
    # (5-minute) per-test ceiling to every item collected in this suite that
    # doesn't already carry an explicit @pytest.mark.timeout(...) --
    # generous enough for the slowest legitimate real-LLM round-trips + TOTP
    # anti-replay waits (up to ~90s) observed here, but bounded instead of
    # unbounded. method="thread" (not the Unix default "signal") so it
    # reliably interrupts alongside Playwright's own I/O/event-loop use on
    # both macOS and Linux — see pyproject.toml's pinned pytest-timeout dep.
    # FIND-0813-011 (2026-08-16): the "~90s" TOTP allowance above was never
    # measured against the REAL wait budget, and the ceiling had never actually
    # been enforced — pytest-timeout was absent from uv.lock (FIND-0813-004), so
    # this marker was inert. The moment it was provisioned it killed the headed
    # Tier-B leg at 17%.
    #
    # The arithmetic: one fresh login can wait up to 62s for the anti-replay
    # window (_wait_for_fresh_code / wait_for_fresh_totp: `62 - elapsed`, plus a
    # window-edge nudge). A test that authenticates ~5 times therefore burns
    # ~310s in SLEEPS ALONE and blows a 300s ceiling deterministically — it is
    # not a hang, and killing it hides a real result.
    #
    # Multi-identity tests (admin1 + admin2 + user, rotation/re-login) are
    # exactly that shape, so they get a budget that accounts for the waits they
    # are REQUIRED to perform. Everything else keeps the tight 300s ceiling: the
    # point of the guard is to bound a genuine hang, and a uniform generous
    # ceiling would restore the 45-minute-orphan failure it exists to prevent.
    #
    # The real fix is to stop paying the wait at all — seeded distinct TOTP
    # secrets per identity (SOP §4.17 Rule 7, _load_seeded_users below) so
    # logins do not serialise on one identity's window. Until every suite uses
    # them, this keeps the ceiling honest instead of arbitrary.
    #
    # 2026-08-16 (NB-3 of the pre-push code-quality review): the budget used
    # to be dispatched by substring-matching `item.nodeid.lower()` against a
    # hint tuple ("bootstrap", "mixed", "admin2", ...). nodeid INCLUDES the
    # file path, so an unrelated directory rename could silently change every
    # test's timeout underneath it with no code change — exactly the
    # "spelling heuristic" anti-pattern this campaign has been fighting,
    # applied to a budget instead of an assertion. Dispatch is now on the
    # explicit, greppable `@pytest.mark.multi_identity` marker (registered in
    # pytest_configure above) instead. The two currently-affected surfaces
    # (test_user_provisioning_mixed.py's module-level pytestmark and
    # TestAdminBootstrapBothAdmins's class-level pytestmark in
    # test_webui_conformance_full.py) were converted to carry it explicitly
    # -- same budget, same tests, stable trigger.
    _TOTP_WAIT_WORST_CASE_S = 62          # measured: conftest.py `62 - elapsed`
    for item in items:
        if any(m.name == "timeout" for m in item.iter_markers()):
            continue
        if item.get_closest_marker("multi_identity") is not None:
            # 300s of real work + the logins this shape must serialise on.
            _budget = 300 + (_TOTP_WAIT_WORST_CASE_S * 5)
        else:
            _budget = 300
        item.add_marker(pytest.mark.timeout(_budget, method="thread"))
