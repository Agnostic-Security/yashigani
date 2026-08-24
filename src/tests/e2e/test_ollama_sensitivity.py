"""
E2E: sensitivity classification and local inference — over the REAL USER PATHWAY.

Last updated: 2026-08-06

WHAT CHANGED AND WHY (2026-08-06)
--------------------------------
This module previously proved nothing about the product. Both of its helpers
reached INSIDE the gateway container:

  * ``_ollama_query()``  ->  ``runtime_run(gateway, "urllib ... http://ollama:11434/api/chat")``
  * ``_classify_via_gateway()``  ->  ``runtime_run(gateway, "SensitivityClassifier(...).classify(...)")``

Two separate problems with that shape:

1. **It asserted a deliberately-closed control.** Ollama sits alone on
   ``*_ollama_ringfence``; the gateway is not attached to it, so
   ``gethostbyname('ollama')`` from the gateway returns ``Errno -3``. That is
   YSG-RISK-193 working as designed. The test could only pass if the mesh-bypass
   were re-opened.

2. **It bypassed the user pathway entirely.** ``docker exec`` + direct class
   instantiation is a unit test of a library function wearing an e2e costume: no
   authentication, no session, no gateway, no OPA, no enforcement path, no audit.
   A user never does this, so a green result here is false information — it can
   stay green while every real request fails, and it did.

Both are now driven end-to-end the way a real user reaches them:

    real user account (bootstrap_user_session)
      -> real POST /auth/login with a freshly-computed, never-replayed TOTP
      -> real POST /user/chat/completions with the session cookie
         (the browser path; direct /v1/chat/completions from a browser 401s by
          design — user_ui.py:888)
      -> gateway -> classifier -> OPA -> local inference

and assertions are **effect-verified, not response-verified** (YTF §5.3): a
sensitive payload must produce the documented enforcement EFFECT on the real
path, not merely a 200 with a plausible body.

No ``docker exec``. No internal bearer. No direct class construction. If the
enforcement path breaks, these tests go red — which is the entire point.
"""
from __future__ import annotations

import json
import os
import re

import httpx
import pytest

from tests.e2e.conftest import _CA_CERT_PATH  # noqa: F401  (TLS anchor for the real hop)
from tests.e2e.conftest import (  # negative control only — see TestOllamaRingfenceNegativeControl
    _YTF_PROJ,
    _YTF_SEP,
    runtime_run,
)

BASE_URL = os.getenv("YASHIGANI_ADMIN_URL") or os.getenv(
    "YASHIGANI_HEALTH_URL", "https://localhost:8443"
).replace("/healthz", "")

# Reuse the framework's canonical real-user primitives rather than re-inventing a
# login (the divergent-login-path consolidation in the Playwright conftest exists
# precisely to stop that).
try:  # pragma: no cover - import shape differs when run outside the YTF tree
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "playwright"))
    from conftest import bootstrap_user_session, user_login_cookies  # type: ignore
except Exception as _exc:  # pragma: no cover
    bootstrap_user_session = None  # type: ignore
    user_login_cookies = None  # type: ignore
    _IMPORT_ERR = _exc


def _verify():
    return _CA_CERT_PATH if _CA_CERT_PATH else False


def _stack_reachable() -> bool:
    try:
        return httpx.get(f"{BASE_URL}/healthz", verify=_verify(), timeout=5).status_code == 200
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(not _stack_reachable(), reason=f"no live stack at {BASE_URL}"),
    pytest.mark.skipif(
        bootstrap_user_session is None,
        reason="real-user primitives unavailable — refusing to fall back to a container-exec bypass",
    ),
]


@pytest.fixture(scope="module")
def user_creds():
    """A real, fully-bootstrapped user account (5-step first-login completed)."""
    return bootstrap_user_session(cache_key="e2e_sensitivity_user")


@pytest.fixture()
def user_client(user_creds):
    """A live httpx client carrying a REAL, freshly-issued user session cookie.

    Fresh per test: the TOTP anti-replay guard in the shared primitive makes a
    cached session a silent source of cross-test coupling.
    """
    cookies = user_login_cookies(
        user_creds["username"], user_creds["password"], user_creds["totp_secret"],
        identity_key=f"user:{user_creds['username']}",
    )
    with httpx.Client(
        base_url=BASE_URL, cookies=cookies, verify=_verify(), timeout=180, follow_redirects=False
    ) as c:
        yield c


def _chat(client: httpx.Client, content: str, model: str = "@agent_langflow") -> httpx.Response:
    """Send one chat turn down the real browser path."""
    return client.post(
        "/user/chat/completions",
        json={"model": model, "messages": [{"role": "user", "content": content}], "stream": False},
    )


def _body_text(resp: httpx.Response) -> str:
    """Flatten an SSE or JSON chat response to searchable text."""
    raw = resp.text or ""
    chunks = [raw]
    for line in raw.splitlines():
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload and payload != "[DONE]":
                try:
                    chunks.append(json.dumps(json.loads(payload)))
                except Exception:
                    chunks.append(payload)
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Sensitivity enforcement — effect-verified on the real path (YTF §5.3)
# ---------------------------------------------------------------------------

SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"
EMAIL = "alice@company.com"


class TestSensitivityEnforcementOnUserPath:
    """A sensitive payload must be ACTED ON before it can leave the governed path.

    The assertion is deliberately about the EFFECT, not a classifier return value:
    the raw secret must not survive the round trip verbatim, whichever of the four
    documented actions the deployed policy selects (block / redact / pseudonymize /
    log-and-pass with an audit record). Encoding one specific action here would
    make the test a mirror of whatever policy happens to be installed.
    """

    @pytest.mark.parametrize(
        "label,payload,secret",
        [
            ("ssn", f"Employee SSN is {SSN}", SSN),
            ("card", f"Payment card: {CARD}", CARD.replace(" ", "")),
            ("email", f"Send it to {EMAIL} please", EMAIL),
        ],
    )
    def test_sensitive_payload_is_acted_on_not_echoed(self, user_client, label, payload, secret):
        resp = _chat(user_client, payload)
        assert resp.status_code in (200, 403, 422), (
            f"[{label}] unexpected status {resp.status_code}: {resp.text[:300]}"
        )
        text = _body_text(resp)

        if resp.status_code != 200:
            # Blocked outright — a documented enforcement action. Must be a
            # policy denial, not a crash, and must not leak the payload back.
            assert "Traceback" not in text and "Internal Server Error" not in text, text[:300]
            assert secret not in text, f"[{label}] blocked response echoed the raw secret"
            return

        normalised = re.sub(r"[\s-]", "", text)
        assert re.sub(r"[\s-]", "", secret) not in normalised, (
            f"[{label}] the raw sensitive value survived the governed path verbatim — "
            f"no redaction, pseudonymisation or block was applied.\n{text[:400]}"
        )

    def test_benign_payload_is_not_over_blocked(self, user_client):
        """The control must not be so blunt that ordinary traffic dies.

        This is the negative half of the pair (YTF §5.2) and the reason it exists:
        an over-broad detector that denies everything would otherwise look 'secure'
        to the positive tests above.
        """
        resp = _chat(user_client, "What is the capital of France?")
        assert resp.status_code == 200, f"benign prompt rejected {resp.status_code}: {resp.text[:300]}"
        text = _body_text(resp)
        assert "Traceback" not in text, text[:300]


# ---------------------------------------------------------------------------
# Local inference — reachable for a real user, over the real path
# ---------------------------------------------------------------------------

class TestLocalInferenceOnUserPath:
    def test_user_gets_a_real_assistant_response(self, user_client):
        """Proves the whole chain a user depends on: session -> proxy -> gateway
        -> OPA -> local model -> content back. Replaces the old container-exec
        `ollama:11434` probe, which proved only that a closed network path was
        still closed."""
        resp = _chat(user_client, "Say hello in exactly two words.")
        assert resp.status_code == 200, f"chat failed {resp.status_code}: {resp.text[:400]}"
        text = _body_text(resp)
        assert ("content" in text) or ("message" in text), f"no assistant payload: {text[:400]}"
        assert "agent_unreachable" not in text, (
            "agent reported unreachable on the user path — see YSG-RISK-200 "
            f"(egress secret-detector false-positive): {text[:400]}"
        )


class TestOllamaRingfenceNegativeControl:
    """YSG-RISK-193 positive assert, ported from the container-exec suite.

    Convergence note (integ/v412-unified-20260813): the rest of this file was
    deliberately rewritten by x8x (c683bc2a) to drive sensitivity and local
    inference over the REAL USER PATHWAY instead of `runtime_run` container-exec,
    per YTF §5.4 (no-bypass) — that rewrite supersedes the mac-air
    `TestOllamaSensitivity`/`TestOllamaLive` classes, whose value was correcting
    expectations for probes this file no longer performs.

    This ONE test is carried over, because it is not a bypass: it asserts a path
    is CLOSED. There is by construction no user pathway to a ring-fenced socket,
    so the only way to prove the ring-fence holds is to attempt the direct
    connection from inside the gateway. Dropping it would have silently retired a
    security-control assert during the merge.
    """

    def test_direct_ollama_socket_is_ringfenced(self):
        """Direct http://ollama:11434 from the gateway MUST be closed (DNS
        failure or connection refused). The pre-2026-08-06 version of this file
        asserted this control BACKWARDS — a reachable direct socket is the
        failure mode, not the success mode."""
        result = runtime_run(f"{_YTF_PROJ}{_YTF_SEP}gateway{_YTF_SEP}1", """
import urllib.request
try:
    urllib.request.urlopen("http://ollama:11434/api/tags", timeout=5)
    print("RINGFENCE-OPEN")
except Exception as e:
    print(f"RINGFENCE-CLOSED:{type(e).__name__}")
""", timeout=20)
        assert "RINGFENCE-CLOSED" in result, (
            f"Direct ollama:11434 socket is REACHABLE from the gateway — "
            f"YSG-RISK-193 ring-fence regression: {result}"
        )
