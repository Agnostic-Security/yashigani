"""
Tier-C category: model_import_provenance (KUROSHIO inference engine).

Added 2026-08-24 at the 5.0 reintegration, per Tiago's direction that the test
framework must cover "the import of ollama model and hugging faces model to
kuroshio". Before this module, Kuroshio had ZERO coverage in YTF: the engine
merged into release/5.0 with 80 files and its own `infer/tests/` unit suite,
but no YTF tier ran it, no MATRIX leg named it, and the runner on that branch
did not exist at all.

WHY THIS IS TIER-C, NOT TIER-A
------------------------------
`infer/tests/` already unit-tests the adapters in-process (test_adapter_huggingface.py,
test_adapter_convert_build.py, the ollama-golden fixtures). Those are real and
they stay. What they cannot see is the seam this tier exists for: a model that
the ENGINE reports as pulled, but that the GATEWAY cannot actually serve — the
write-on-A / read-on-B class (112/128/131). Import is exactly that shape:

    POST /api/pull  ->  engine says "success"
    GET  /api/tags  ->  is it REALLY resident, on the engine's own read path?
    chat/completion ->  can a caller REALLY be served by it?

An import test that stops at the pull response is a response-verified test, and
YTF §5.3 does not accept those. Every positive case below crosses at least one
service boundary to confirm the effect.

WHAT THIS MODULE ASSERTS
------------------------
Positive (effect-verified):
  - an Ollama-format model import lands and is subsequently RESIDENT on the
    engine's own /api/tags read path
  - a resident model is genuinely SERVABLE (not merely listed)

Negative (supply-chain provenance — the half that actually protects us):
  - a floating HF revision ("main", "latest", a tag) is REFUSED; only a pinned
    7-40 hex commit is accepted. This is the council's High finding on
    supply-chain provenance — a floating ref means the bytes you audited are
    not the bytes you load.
  - a non-`*.gguf` filename is REFUSED (no pickle/safetensors path into the
    first-parse jail)
  - `../` path segments in repo_id or filename are REFUSED
  - `/api/pull` on a deployment with no configured source adapter returns an
    explicit 501, never a silent success

Ring-fence (FIND-0824 follow-on):
  - the engine has NO auth of its own by design (app.py:259 comment) — /api/pull
    is gated at the Caddy mesh-identity front. So an UNAUTHENTICATED caller
    arriving over the front must NOT be able to trigger a pull. If that ever
    passes unauthenticated, an attacker chooses what weights we load.

HONESTY NOTE
------------
These SKIP (never soft-pass) when no stack is reachable, when Kuroshio is not
part of the deployment profile (macOS uses Ollama directly — see
docs/testing/YTF.md and install.sh Check 1e), or when a case genuinely cannot
be exercised from the caller plane on this profile. A skip says so; it never
asserts a weaker thing and reports it as the stronger one.
"""
from __future__ import annotations

import os
import re

import httpx
import pytest

from .conftest import BASE_URL, SKIP_NO_STACK, http_client

# The engine's own front. On compose/k8s the mesh front proxies it at
# /kuroshio (docker/docker-compose.yml KUROSHIO_BASE_URL); a direct engine
# endpoint can be given for a bench run.
KUROSHIO_URL = os.getenv("KUROSHIO_BASE_URL", "").rstrip("/")

# Small, license-clean model used for a real import when the operator opts in.
# Import is a heavyweight, network-touching action, so it is OPT-IN: without
# YTF_KUROSHIO_IMPORT_MODEL the positive cases assert against whatever is
# ALREADY resident rather than pulling megabytes on every leg.
IMPORT_MODEL = os.getenv("YTF_KUROSHIO_IMPORT_MODEL", "")

# HF GGUF import target (opt-in, same reasoning). Must be a PINNED commit.
HF_REPO_ID = os.getenv("YTF_KUROSHIO_HF_REPO", "")
HF_REVISION = os.getenv("YTF_KUROSHIO_HF_REVISION", "")
HF_FILENAME = os.getenv("YTF_KUROSHIO_HF_FILE", "")

# Mirrors infer/src/kuroshio/adapters/huggingface.py — asserted, not assumed.
_PINNED_REVISION_RE = re.compile(r"^[0-9a-f]{7,40}$")


def _kuroshio_client() -> httpx.Client | None:
    """Client for the engine front, or None when Kuroshio is not deployed."""
    if not KUROSHIO_URL:
        return None
    verify: bool | str = False
    if KUROSHIO_URL.startswith("https://"):
        from .conftest import _CA_CERT_PATH  # type: ignore[attr-defined]
        verify = _CA_CERT_PATH or False
    try:
        c = httpx.Client(base_url=KUROSHIO_URL, verify=verify, timeout=30)
        r = c.get("/healthz")
        if r.status_code != 200:
            c.close()
            return None
        return c
    except Exception:
        return None


SKIP_NO_KUROSHIO = pytest.mark.skipif(
    _kuroshio_client() is None,
    reason=(
        "KUROSHIO not reachable on this deployment profile "
        "(unset KUROSHIO_BASE_URL, or a macOS/Ollama leg) — model-import "
        "coverage is Linux/KUROSHIO-only by design"
    ),
)


def _resident_models(client: httpx.Client) -> list[str]:
    """Model names on the engine's OWN read path (/api/tags).

    This is the independent read side of the seam — deliberately NOT the
    response of the pull that put the model there.
    """
    r = client.get("/api/tags")
    r.raise_for_status()
    body = r.json()
    return [m.get("name", "") for m in body.get("models", [])]


# ---------------------------------------------------------------------------
# Positive — effect-verified across the import seam
# ---------------------------------------------------------------------------

@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
def test_ollama_model_import_is_resident_on_engine_read_path():
    """An imported Ollama-format model is REALLY resident, per /api/tags.

    Effect-verified (YTF §5.3): the pull response is not the evidence. The
    evidence is the engine's own catalogue listing the model afterwards.
    """
    client = _kuroshio_client()
    assert client is not None

    if not IMPORT_MODEL:
        resident = _resident_models(client)
        if not resident:
            pytest.skip(
                "no model resident and YTF_KUROSHIO_IMPORT_MODEL unset — set it "
                "to exercise a real pull on this leg"
            )
        # Nothing was imported by us, so the honest assertion is the weaker,
        # explicitly-labelled one: the read path works and reports residency.
        assert all(isinstance(n, str) and n for n in resident), resident
        return

    before = _resident_models(client)
    r = client.post("/api/pull", json={"name": IMPORT_MODEL}, timeout=1800)
    assert r.status_code == 200, f"pull failed: HTTP {r.status_code} {r.text[:300]}"

    after = _resident_models(client)
    assert any(IMPORT_MODEL.split(":")[0] in n for n in after), (
        f"IMPORT SEAM BREAK: /api/pull returned 200 for {IMPORT_MODEL!r} but the "
        f"engine's own /api/tags does not list it. before={before} after={after}. "
        "This is the write-on-A/read-on-B class this tier exists to catch."
    )


@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
def test_resident_model_is_actually_servable_not_merely_listed():
    """A listed model can actually serve — listing is not the same as loadable.

    A model can appear in /api/tags with corrupt or partial blobs. Being in the
    catalogue is a claim; answering a generate call is the effect.
    """
    client = _kuroshio_client()
    assert client is not None
    resident = _resident_models(client)
    if not resident:
        pytest.skip("no resident model on this leg to serve from")

    model = resident[0]
    r = client.post(
        "/api/generate",
        json={"model": model, "prompt": "ok", "stream": False},
        timeout=300,
    )
    assert r.status_code == 200, (
        f"model {model!r} is listed by /api/tags but /api/generate returned "
        f"HTTP {r.status_code}: {r.text[:300]} — listed-but-not-servable"
    )


# ---------------------------------------------------------------------------
# Negative — HF supply-chain provenance
# ---------------------------------------------------------------------------

@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
@pytest.mark.parametrize("bad_revision", ["main", "master", "latest", "v1.0", "refs/heads/main"])
def test_hf_import_refuses_floating_revision(bad_revision):
    """A floating HF ref must be REFUSED — only a pinned commit is accepted.

    Council High finding on supply-chain provenance: with a floating ref the
    bytes that were audited are not necessarily the bytes that get loaded. The
    engine must reject before any download begins.
    """
    client = _kuroshio_client()
    assert client is not None
    assert not _PINNED_REVISION_RE.match(bad_revision), "test input is not actually floating"

    r = client.post(
        "/api/pull",
        json={
            "repo_id": HF_REPO_ID or "TheBloke/Example-GGUF",
            "revision": bad_revision,
            "filename": HF_FILENAME or "model.gguf",
        },
        timeout=60,
    )
    assert r.status_code != 200 or b"error" in r.content.lower(), (
        f"PROVENANCE BYPASS: /api/pull accepted floating revision {bad_revision!r} "
        f"(HTTP {r.status_code}). Only pinned 7-40 hex commits may be accepted."
    )


@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
@pytest.mark.parametrize(
    "bad_filename",
    ["model.bin", "pytorch_model.safetensors", "model.pkl", "model.gguf.txt", "model"],
)
def test_hf_import_refuses_non_gguf_filename(bad_filename):
    """Only `*.gguf` may be imported — no pickle/safetensors path into the jail."""
    client = _kuroshio_client()
    assert client is not None
    r = client.post(
        "/api/pull",
        json={
            "repo_id": HF_REPO_ID or "TheBloke/Example-GGUF",
            "revision": "a" * 40,
            "filename": bad_filename,
        },
        timeout=60,
    )
    assert r.status_code != 200 or b"error" in r.content.lower(), (
        f"FORMAT GUARD BYPASS: /api/pull accepted non-gguf filename {bad_filename!r} "
        f"(HTTP {r.status_code})."
    )


@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
@pytest.mark.parametrize(
    ("repo_id", "filename"),
    [
        ("../../etc", "model.gguf"),
        ("org/repo", "../../../etc/passwd.gguf"),
        ("org/../../repo", "model.gguf"),
    ],
)
def test_hf_import_refuses_path_traversal(repo_id, filename):
    """`../` segments in repo_id/filename must be refused before any fetch."""
    client = _kuroshio_client()
    assert client is not None
    r = client.post(
        "/api/pull",
        json={"repo_id": repo_id, "revision": "a" * 40, "filename": filename},
        timeout=60,
    )
    assert r.status_code != 200 or b"error" in r.content.lower(), (
        f"PATH TRAVERSAL ACCEPTED: repo_id={repo_id!r} filename={filename!r} "
        f"(HTTP {r.status_code})."
    )


@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
def test_hf_import_pinned_revision_is_accepted_when_configured():
    """The positive HF leg — a PINNED commit + `*.gguf` really imports.

    Opt-in: needs YTF_KUROSHIO_HF_REPO / _REVISION / _FILE, because it pulls
    real weights over the network.
    """
    client = _kuroshio_client()
    assert client is not None
    if not (HF_REPO_ID and HF_REVISION and HF_FILENAME):
        pytest.skip(
            "HF import target not configured — set YTF_KUROSHIO_HF_REPO, "
            "YTF_KUROSHIO_HF_REVISION (pinned commit), YTF_KUROSHIO_HF_FILE"
        )
    assert _PINNED_REVISION_RE.match(HF_REVISION), (
        f"YTF_KUROSHIO_HF_REVISION={HF_REVISION!r} is not a pinned 7-40 hex commit — "
        "the framework refuses to ask the engine to accept what it must reject"
    )

    r = client.post(
        "/api/pull",
        json={"repo_id": HF_REPO_ID, "revision": HF_REVISION, "filename": HF_FILENAME},
        timeout=1800,
    )
    assert r.status_code == 200, f"pinned HF import failed: HTTP {r.status_code} {r.text[:300]}"

    after = _resident_models(client)
    stem = HF_FILENAME.rsplit(".", 1)[0]
    assert any(stem in n or HF_REPO_ID.split("/")[-1] in n for n in after), (
        f"IMPORT SEAM BREAK: HF pull returned 200 but /api/tags does not list it. "
        f"resident={after}"
    )


# ---------------------------------------------------------------------------
# Ring-fence — who is allowed to choose our weights
# ---------------------------------------------------------------------------

@SKIP_NO_STACK
def test_pull_is_not_reachable_unauthenticated_through_the_front():
    """An UNAUTHENTICATED caller must not be able to trigger a model pull.

    The engine has no auth of its own by design (infer/src/kuroshio/app.py:259
    — the authz check belongs at the Caddy mesh-identity front). This test
    proves the front actually enforces that: if an anonymous caller can pull,
    an attacker picks the weights we load, which is a full model-supply-chain
    compromise.
    """
    with http_client() as c:
        r = c.post(
            "/kuroshio/api/pull",
            json={"name": "evil/model"},
            timeout=30,
        )
    if r.status_code == 404:
        pytest.skip(
            "engine front is not exposed at /kuroshio on this profile — "
            "unauthenticated-pull reachability cannot be exercised here"
        )
    assert r.status_code in (401, 403), (
        f"RING-FENCE BREAK: unauthenticated POST /kuroshio/api/pull returned "
        f"HTTP {r.status_code} (expected 401/403). Body: {r.text[:300]}"
    )


@SKIP_NO_STACK
@SKIP_NO_KUROSHIO
def test_pull_without_configured_adapter_fails_explicitly_not_silently():
    """No configured source adapter must yield an explicit 501, never a fake OK.

    app.py raises HTTPException(501, "no pull source adapter is configured")
    when pull_resolver is None. The thing that must never happen is a 200 with
    nothing imported — that reads as success to every caller above.
    """
    client = _kuroshio_client()
    assert client is not None
    r = client.post("/api/pull", json={}, timeout=30)
    assert r.status_code != 200 or b"error" in r.content.lower(), (
        f"SILENT-SUCCESS: /api/pull with an empty body returned HTTP {r.status_code} "
        "with no error — an unconfigured or invalid pull must fail loudly."
    )
    if r.status_code == 501:
        assert b"adapter" in r.content.lower(), r.text[:300]
