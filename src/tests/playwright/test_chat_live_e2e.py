"""
Live browser E2E — native /chat SPA, real user, real send, real model response.

This is the "marquee verification" for 4.1.2 Docker leg (YTF dispatch,
2026-07-30): does chat ACTUALLY work end-to-end through the real UI a user
sees, for each of the three bundled agents (@letta, @openclaw, langflow) and
the direct/no-mention model path?

Unlike src/tests/e2e/test_agent_dispatch_e2e.py (container-exec, internal
gateway:8081 dispatch -- proves the gateway-to-agent hop but never touches a
browser or the /chat SPA's own @-mention resolution logic), this file drives
an actual Chromium session: type into the real textarea, press Enter, wait
for the real assistant bubble or a real blocked/error verdict banner, and
screenshot every state.

Grounding (API-level probes run before authoring this file, same session,
evidence at testing_runs/yashigani/ytf/docker-linux/bootstrap/
probe_chat_targets{,2,3}.log -- NOT re-derived from memory/assumption):

  - @letta        -> gateway creates the Letta agent OK, but the message call
                     500s: "Failed to connect to OpenAI: Connection error"
                     (Letta container cannot reach its configured llm_config
                     endpoint). NOT in docs/risk-register.yml as of 2026-07-30.
  - @openclaw     -> gateway's own egress-eval gate DENIES openclaw's outbound
                     LLM call (reason=result_sensitivity_exceeds_caller_ceiling,
                     sensitivity=RESTRICTED, pii=True) for a trivial one-
                     sentence prompt -- causes openclaw to 500 back to gateway.
                     NOT in the risk register.
  - langflow      -> TWO stacked bugs. (a) The /chat SPA's own @-mention menu
                     can ONLY ever offer the handle "agent_langflow" (single
                     underscore -- user_agents.py::_normalize_alias() collapses
                     the registry's real name "agent__langflow", double
                     underscore, install.sh's bash case statement). Gateway's
                     global-registry lookup (openai_router.py ~2537) is an
                     EXACT string match against the registry "name" field, so
                     "@agent_langflow" (the ONLY handle a real user can ever
                     click/type from the mention menu) NEVER matches
                     "agent__langflow" -> 404 agent_not_found, always, for
                     every user, on every fresh install. This test drives the
                     REAL mention menu (types "@agent_langflow", the actual
                     UI-offered handle) -- it must NOT be "fixed" to use the
                     internal registry name, since that is not something a
                     real user can ever type from the UI. (b) Even addressed
                     by the correct raw registry name (verified via a
                     bypass-the-UI API probe, not exercised by this browser
                     test), the upstream call itself 405s
                     (POST https://caddy:9705/.../v1/chat/completions ->
                     405 Method Not Allowed) -- a second, independent bug.
                     Neither is in the risk register.
  - direct model  -> the raw Ollama model name ("qwen2.5:3b") works completely
                     (real 200, real generated content) when addressed
                     directly. The advertised local alias "fast" (which maps
                     to the SAME qwen2.5:3b, force_local=true) was DENIED by
                     the response-sensitivity classifier
                     ("response_sensitivity_exceeds_ceiling") for the exact
                     same trivial one-sentence-greeting prompt -- inconsistent
                     with the raw-model-name path succeeding on equivalent
                     content. Not in the risk register. This test exercises
                     whatever the SPA itself actually sends by default (no
                     @mention, no manual model-dropdown interaction) --
                     the real first-time-user experience -- rather than
                     hand-picking a known-good raw model name.

Mode: LIVE, per-deployment (Tier-B). Skips cleanly (not a false pass) when no
stack is reachable, via the shared conftest STACK_RUNNING gate.

Auth: reuses the throwaway user account persisted by the API grounding probes
(testing_runs/yashigani/ytf/docker-linux/bootstrap/throwaway_user_creds.json)
via playwright_login_user()'s cookie-injection path -- avoids re-provisioning
a new account (and burning another 65s+ TOTP-replay wait) purely for this
file. Falls back to force_fresh=True (new account) if that cache is stale/
absent, matching the conftest's own documented pattern.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tests.playwright.conftest import (
    BASE_URL,
    _CA_CERT_PATH,
    _SKIP_NO_STACK,
    bootstrap_user_session,
    launch_chromium,
    mark_totp_used,
    wait_for_fresh_totp,
)

pytestmark = _SKIP_NO_STACK

# __file__ = .../yashigani-docker-leg/src/tests/playwright/test_chat_live_e2e.py
# parents[3] = repo root (yashigani-docker-leg); its grandparent is the
# ~/Documents/Claude/ workspace root, sibling to testing_runs/.
_REPO_ROOT = Path(__file__).parents[3]
_CLAUDE_ROOT = _REPO_ROOT.parent.parent


# QA-fix (Ava, Tier-B triage 2026-08-02): this fallback hardcoded
# ".../ytf/docker-linux/screenshots" regardless of which runtime/platform leg
# is actually under test (this run was docker-macos) — harmless whenever
# run-test-framework.sh's Tier-B leg sets YTF_SCREENSHOT_DIR (the normal
# path, always does), but wrong/misleading for a direct/manual invocation of
# this file without the env var. Falls back to a leg-agnostic path derived
# from YTF_LEG (also exported by run_tier_b()) when available, "manual" when
# not, rather than silently mislabelling the evidence.
_leg = __import__("os").environ.get("YTF_LEG", "manual")
SHOT_DIR = Path(
    __import__("os").environ.get(
        "YTF_SCREENSHOT_DIR",
        str(_CLAUDE_ROOT / "testing_runs" / "yashigani" / "ytf" / _leg / "screenshots"),
    )
) / "chat_live_e2e"
SHOT_DIR.mkdir(parents=True, exist_ok=True)


def _shot(page, name: str) -> str:
    p = str(SHOT_DIR / f"{name}.png")
    page.screenshot(path=p, full_page=True)
    return p


def _assert_real_assistant_response(page, label: str, shot_name: str) -> None:
    """Honest verdict per A1 (retro v2.23.1 -- absence of artefact = FAIL, not
    PASS): checks the ACTUAL rendered assistant bubble (.ys-chat-assistant-wrap
    / ys-chat-stream's .ys-chat-bubble content) and the verdict banner
    (ys-verdict-banner), not merely "the log isn't empty" (the user's own
    echoed message always renders immediately client-side and would make a
    naive `.ys-chat-log inner_text() != ""` check falsely pass with ZERO
    assistant content -- this was caught live in this same session: an
    earlier version of this test false-PASSED on exactly that gap).

    Live-confirmed root cause (this session, 2026-07-30) for the "nothing
    renders at all" case: gateway/backoffice error responses for agent/model
    dispatch failures are SSE-framed even under HTTP 200
    (`data: {"error": {...}}\\n\\n`, content-type text/event-stream) --
    confirmed via a raw-bytes probe bypassing the browser. The browser's
    sse.js `streamChat()` only recognises two shapes: a token delta
    (`choices[0].delta.content`) or a structured verdict tail
    (`decision_codes`/`user_alert`/`blocked`/`yashigani`). The backend's
    `{"error": {message, type, code, agent, upstream_status}}` frame matches
    NEITHER -- it is silently discarded, the stream closes, and
    `onMessageDone('', null)` fires. The user sees their own message and
    NOTHING else: no error, no banner, no spinner-that-stops, no signal
    whatsoever that anything failed. This affects ALL FOUR chat targets in
    this deployment as of 2026-07-30 (each has its own independent backend
    root cause -- see this module's docstring -- but ALL of them are masked
    identically by this one client-side gap). Not yet in docs/risk-register.yml.
    """
    assistant_wrap = page.locator(".ys-chat-assistant-wrap")
    verdict_banner = page.locator("ys-verdict-banner")
    assistant_text = assistant_wrap.inner_text().strip() if assistant_wrap.count() else ""
    verdict_present = verdict_banner.count() > 0
    verdict_text = verdict_banner.inner_text().strip() if verdict_present else ""

    if not assistant_text and not verdict_present:
        pytest.fail(
            f"{label}: NO assistant response AND no verdict/error banner rendered — "
            f"the browser silently swallowed whatever the backend returned (see "
            f"{shot_name}.png). This matches the live-confirmed SSE-error-frame-drop "
            f"gap in sse.js::streamChat() (backend returns "
            f"`data: {{\"error\": {{...}}}}` at HTTP 200/text-event-stream for agent/"
            f"model dispatch failures; the client only recognises choices[].delta."
            f"content or decision_codes/user_alert/blocked/yashigani — neither "
            f"matches, so the frame is dropped and onMessageDone('', null) fires "
            f"with zero user-facing signal). NEW finding, not in risk-register.yml."
        )
    if verdict_present:
        pytest.fail(
            f"{label}: chat surfaced a blocked/error verdict banner (not a real "
            f"assistant response): {verdict_text[:300]} — see {shot_name}.png"
        )
    if any(tok in assistant_text.lower() for tok in ("unreachable", "not found", "error", "not available", "500", "404", "405")):
        pytest.fail(
            f"{label}: assistant bubble rendered but contains an error string, not a "
            f"real model response: {assistant_text[:300]} — see {shot_name}.png"
        )
    assert assistant_text, f"{label}: assistant bubble present but empty — see {shot_name}.png"


@pytest.fixture(scope="module")
def chat_user_creds():
    """Reuse the persisted throwaway user from the API grounding probes if
    present (same repo-root-relative path the bootstrap scripts wrote to);
    otherwise provision a fresh one via the conftest helper."""
    persisted = (
        _CLAUDE_ROOT
        / "testing_runs"
        / "yashigani"
        / "ytf"
        / "docker-linux"
        / "bootstrap"
        / "throwaway_user_creds.json"
    ).resolve()
    if persisted.exists():
        data = json.loads(persisted.read_text())
        return {"username": data["username"], "password": data["password"], "totp_secret": data["totp_secret"]}
    creds = bootstrap_user_session(cache_key="chat_live_e2e")
    return creds


@pytest.fixture()
def chat_page(chat_user_creds):
    import hashlib

    import httpx
    import pyotp

    verify: "bool | str" = _CA_CERT_PATH if _CA_CERT_PATH else False
    totp = pyotp.TOTP(chat_user_creds["totp_secret"], digits=6, digest=hashlib.sha256)

    # Fresh login via the API (not cookie-cache) so every test in this module
    # gets a live, non-replayed session -- chat_page is function-scoped
    # deliberately (each test sends real chat turns; sharing one session
    # across parametrized targets is fine for cookies, but re-login per test
    # keeps TOTP replay windows unambiguous in the evidence log).
    #
    # QA-fix (Ava, 2026-08-03, Tier-B 172-error triage): this previously only
    # checked "am I in the first ~25s of a 30s window?" with no memory of
    # whether THIS username's TOTP secret had already produced a code in the
    # CURRENT window -- confirmed as the first domino in this run's 172-error
    # cascade: test_chat_page_loads_authenticated and
    # test_direct_model_no_mention (the first two parametrized tests in this
    # module's collection order) ran back-to-back, landed in the same 30s
    # window, and the second submitted the IDENTICAL code the first had just
    # used -- 401 invalid_credentials (replay, not a real credential problem).
    # After _THROTTLE_ACCOUNT_THRESHOLD (3) such accumulated failures the
    # account-level auth throttle tripped, turning every subsequent login for
    # the rest of the module (then, via IP severity, much of the rest of the
    # 2h24m run) into 429 too_many_requests. wait_for_fresh_totp/mark_totp_used
    # (shared conftest helper, keyed per-identity) replaces the local
    # window-position-only check with the same "≥62s since THIS identity's
    # last use" guard already proven correct for admin-tier logins.
    identity_key = f"user:{chat_user_creds['username']}"
    wait_for_fresh_totp(identity_key)
    code = totp.now()
    mark_totp_used(identity_key)
    with httpx.Client(verify=verify, follow_redirects=False, timeout=15) as c:
        r = c.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": chat_user_creds["username"],
                "password": chat_user_creds["password"],
                "totp_code": code,
            },
        )
        assert r.status_code == 200, f"chat_page login failed: {r.status_code} {r.text[:300]}"
        assert not r.json().get("force_password_change")
        cookies = dict(r.cookies)

    with __import__("playwright.sync_api", fromlist=["sync_playwright"]).sync_playwright() as pw:
        browser = launch_chromium(pw)
        ctx = browser.new_context(ignore_https_errors=True)
        ctx.add_cookies(
            [
                {
                    "name": name,
                    "value": value,
                    "domain": BASE_URL.split("://", 1)[-1].split(":")[0],
                    "path": "/",
                    "secure": BASE_URL.startswith("https://"),
                }
                for name, value in cookies.items()
            ]
        )
        page = ctx.new_page()
        page.goto(f"{BASE_URL}/chat")
        page.wait_for_timeout(2000)
        yield page
        browser.close()
    # Space out TOTP consumption for the NEXT test in this module.
    time.sleep(35)


class TestChatLiveE2E:
    """Marquee live-browser chat verification -- one test per addressing
    mode, matching exactly what a real user can type/click."""

    def test_chat_page_loads_authenticated(self, chat_page):
        assert "/login" not in chat_page.url, f"chat page redirected to login: {chat_page.url}"
        assert chat_page.locator("ys-user-app").count() > 0, "ys-user-app root element not found on /chat"
        _shot(chat_page, "01_chat_loaded")

    def test_direct_model_no_mention(self, chat_page):
        """Real first-time-user path: type a plain message, no @mention,
        never touch the model dropdown. Reports whatever the SPA actually
        does -- does NOT hand-pick a known-good raw model name."""
        page = chat_page
        ta = page.locator(".ys-chat-input")
        ta.click()
        ta.fill("Please reply with a one-sentence greeting.")
        page.click(".ys-chat-send")
        page.wait_for_timeout(15000)
        shot = _shot(page, "02_direct_model_response")
        print(f"\n[direct-model] chat log after send:\n{page.locator('.ys-chat-log').inner_text()}\n")
        _assert_real_assistant_response(page, "direct-model (no mention)", "02_direct_model_response")

    @pytest.mark.parametrize(
        "handle,label",
        [
            ("letta", "letta"),
            ("openclaw", "openclaw"),
            ("agent_langflow", "langflow_via_real_ui_mention_handle"),
        ],
    )
    def test_agent_via_real_mention(self, chat_page, handle, label):
        """Types the mention EXACTLY as the real mention-menu autocomplete
        offers it (confirmed via GET /user/mentions in the grounding probe:
        handles are exactly 'letta', 'openclaw', 'agent_langflow' -- the
        langflow one is a single-underscore slug that will never match the
        registry's real double-underscore name; this test intentionally
        does NOT work around that, since a real user cannot either)."""
        page = chat_page
        ta = page.locator(".ys-chat-input")
        ta.click()
        ta.fill(f"@{handle} Please reply with a one-sentence greeting.")
        page.click(".ys-chat-send")
        page.wait_for_timeout(20000)
        shot = _shot(page, f"03_{label}_response")
        print(f"\n[{label}] chat log after send:\n{page.locator('.ys-chat-log').inner_text()}\n")
        _assert_real_assistant_response(page, label, f"03_{label}_response")
