# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-022 (High; Laura filed as "LAURA-V50-018", renumbered by
the coordinator to avoid colliding with the already-fixed principal-token
LAURA-V50-018): ``rbac/opa_push.py::push_rbac_data()`` PUT the PARENT OPA
data path ``/v1/data/yashigani`` with a body of only ``{"rbac": ...,
"agents": ...}`` on EVERY RBAC group/user/grant mutation. OPA's Data API
PUT-to-a-path REPLACES the ENTIRE subtree at that path — a parent-path PUT
with a partial body silently WIPES every sibling sub-document OPA holds
under ``data.yashigani.*`` that this module doesn't know about:
``data.yashigani.mcp`` (grants/baselines/egress_grants —
mcp/_opa_push.py), ``data.yashigani.document`` (documents/opa_push.py),
``data.yashigani.allocations`` (models/opa_push.py).

Concretely, this is WORSE than the LAURA-V50-017 Gap-C bug it looks like at
first: the MCP push genuinely lands and (post-Gap-C-fix) is verified to
land — then a LATER, unrelated RBAC mutation (an admin creating the user's
group, adding a grant, anything that calls push_rbac_data) silently wipes
it. Sequence: onboard MCP server (correctly, scopedly writes
data.yashigani.mcp) -> admin creates the RBAC group/grant the user needs
(push_rbac_data fires, PUTs the parent path) -> data.yashigani.mcp is gone
-> tools/call denies rbac_capability_envelope_not_active, baselines read
back {}. ANY RBAC change after an MCP onboard breaks the broker.

Fix under test (Tom, 2026-07-29): push_rbac_data() now PUTs TWO scoped
sub-paths — ``/v1/data/yashigani/rbac`` and ``/v1/data/yashigani/agents`` —
mirroring the convention mcp/_opa_push.py already used correctly. Never a
parent-path replace of ``/v1/data/yashigani``.

Class audit (every OPA data-write call site under data.yashigani.*):
  - rbac/opa_push.py         — WAS the offender (parent-path PUT). FIXED.
  - mcp/_opa_push.py         — already scoped (/v1/data/yashigani/mcp[/
                                egress_grants]). No change needed.
  - documents/opa_push.py    — already scoped (/v1/data/yashigani/
                                document). No change needed (docstring
                                corrected — it claimed independence from
                                the RBAC push that was, at the time,
                                actually clobbering it too).
  - models/opa_push.py       — already scoped (/v1/data/yashigani/
                                allocations). No change needed (docstring
                                corrected, same reason).
  - policy_bindings/opa_push.py — different TOP-LEVEL namespace entirely
                                (/v1/data/client_bindings, not under
                                /v1/data/yashigani at all). Never at risk.
  - opa_assistant/*, backoffice/routes/opa_assistant.py — write to OPA's
                                POLICY API (/v1/policies/...), a completely
                                different OPA REST surface from the DATA
                                API (/v1/data/...). No clobber risk.

This suite proves the fix against a REAL, disposable, LOCAL `opa run
--server` process (started/stopped entirely within this test — NOT the
live docker/podman stack; static/unit-only per the coordinator's brief) —
never mocking OPA's PUT-by-path semantics, since the whole bug is about
those semantics being misunderstood.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

_OPA_BIN = shutil.which("opa")
_REPO_ROOT = Path(__file__).resolve().parents[3].parent  # src/tests/regression/v5.0 -> repo root
_POLICY_DIR = _REPO_ROOT / "policy"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def local_opa():
    """Start a disposable, LOCAL `opa run --server` bound to a free port,
    loaded with the REAL, unmodified policy/ dir. Torn down at test end.
    Not the live stack — a throwaway process for this test only, same
    posture as `opa test policy/` itself."""
    if _OPA_BIN is None:
        pytest.skip("opa CLI not found on PATH")

    port = _free_port()
    proc = subprocess.Popen(
        [_OPA_BIN, "run", "--server", "--addr", f"127.0.0.1:{port}", str(_POLICY_DIR)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 10.0
        last_exc: Exception | None = None
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(base_url + "/health", timeout=1.0)
                if resp.status_code == 200:
                    break
            except Exception as exc:  # noqa: BLE001 — retry until deadline
                last_exc = exc
            time.sleep(0.2)
        else:
            proc.kill()
            raise RuntimeError(f"local opa server did not become healthy: {last_exc}")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _plain_sync_client(**_kwargs):
    """Stand-in for internal_httpx_sync_client() against the local plain-HTTP
    test OPA (no mesh mTLS needed for a throwaway local process)."""
    return httpx.Client(timeout=10.0)


class TestRbacPushNeverClobbersSiblings:
    def test_mcp_data_survives_an_rbac_mutation(self, local_opa):
        """The core V50-022 interleaving: write data.yashigani.mcp (an MCP
        onboard push), then call push_rbac_data (an RBAC mutation) — assert
        data.yashigani.mcp is STILL intact afterwards, and rbac/agents data
        is correct."""
        from yashigani.mcp._opa_push import push_mcp_opa_data
        from yashigani.rbac.opa_push import push_rbac_data

        mcp_doc = {
            "grants": {
                "mcp-id-1": {
                    "spiffe://yashigani.internal/gateway": {
                        "tools": ["echo"], "actions": ["tools/call"],
                    },
                    "spiffe://yashigani.internal/agents/t1/cloud9-demo": {
                        "tools": ["echo"], "actions": ["tools/call"],
                    },
                },
            },
            "baselines": {
                "mcp-id-1": {"surface_hash": "sha256:" + "ab" * 32, "tools": ["echo"]},
            },
            "egress_grants": {},
        }

        with patch("yashigani.pki.client.internal_httpx_sync_client", _plain_sync_client):
            # LAURA-V50-017 Gap C readback verification must ALSO pass here —
            # proves the MCP push genuinely landed before the RBAC push runs.
            push_mcp_opa_data(local_opa, mcp_doc)

        # Sanity: confirm it's really there before the interleaving step.
        pre = httpx.get(local_opa + "/v1/data/yashigani/mcp", timeout=5.0).json()["result"]
        assert pre.get("grants", {}).get("mcp-id-1") is not None
        assert pre.get("baselines", {}).get("mcp-id-1") is not None

        # ── The interleaving: an RBAC mutation fires AFTER the MCP push ────
        rbac_doc = {
            "groups": {"g-power-users": {"id": "g-power-users", "display_name": "Power Users",
                                          "allowed_resources": ["mcp:cloud9-demo"]}},
            "user_groups": {"alice@example.com": ["g-power-users"]},
        }
        with patch("yashigani.rbac.opa_push.internal_httpx_sync_client", _plain_sync_client):
            push_rbac_data(store=None, opa_url=local_opa, raw_document=rbac_doc)

        # ── data.yashigani.mcp must be COMPLETELY untouched ────────────────
        post = httpx.get(local_opa + "/v1/data/yashigani/mcp", timeout=5.0).json()["result"]
        assert post.get("grants") == mcp_doc["grants"], (
            "V50-022 REGRESSION: an RBAC mutation (push_rbac_data) wiped "
            "data.yashigani.mcp.grants — this is the exact clobber Laura "
            "found: onboard MCP -> admin creates the user's RBAC group -> "
            "the onboarded server's grants vanish."
        )
        assert post.get("baselines") == mcp_doc["baselines"], (
            "V50-022 REGRESSION: an RBAC mutation wiped data.yashigani.mcp."
            "baselines."
        )

        # ── rbac/agents data must ALSO be correct (the push must still work,
        #    just scoped) ────────────────────────────────────────────────
        rbac_result = httpx.get(local_opa + "/v1/data/yashigani/rbac", timeout=5.0).json()["result"]
        assert rbac_result == rbac_doc
        agents_result = httpx.get(local_opa + "/v1/data/yashigani/agents", timeout=5.0).json()["result"]
        assert agents_result == {}  # no agent_registry supplied in this call

    def test_end_to_end_onboard_then_rbac_grant_then_benign_gate_check(self, local_opa):
        """onboard -> grant via RBAC group -> the mcp grant survives -> a
        benign gate check passes (data.yashigani.mcp.allow == true) for the
        REAL, unmodified policy/mcp.rego, evaluated by the REAL running OPA
        with BOTH pushes' data live simultaneously."""
        from yashigani.mcp._opa_push import push_mcp_opa_data
        from yashigani.rbac.opa_push import push_rbac_data

        mcp_id = "mcp-id-2"
        rbac_spiffe = "spiffe://yashigani.internal/agents/t1/cloud9-demo"
        surface_hash = "sha256:" + "cd" * 32
        mcp_doc = {
            "grants": {
                mcp_id: {
                    "spiffe://yashigani.internal/gateway": {
                        "tools": ["echo"], "actions": ["tools/call"],
                    },
                    rbac_spiffe: {
                        "tools": ["echo"], "actions": ["tools/call"],
                    },
                },
            },
            "baselines": {mcp_id: {"surface_hash": surface_hash, "tools": ["echo"]}},
            "egress_grants": {},
        }
        with patch("yashigani.pki.client.internal_httpx_sync_client", _plain_sync_client):
            push_mcp_opa_data(local_opa, mcp_doc)

        # Admin now creates the RBAC group + grant for the calling user —
        # the exact "later, unrelated RBAC change" step of Laura's sequence.
        rbac_doc = {
            "groups": {"g-power-users": {"id": "g-power-users", "display_name": "Power Users",
                                          "allowed_resources": ["mcp:cloud9-demo"]}},
            "user_groups": {"alice@example.com": ["g-power-users"]},
        }
        with patch("yashigani.rbac.opa_push.internal_httpx_sync_client", _plain_sync_client):
            push_rbac_data(store=None, opa_url=local_opa, raw_document=rbac_doc)

        # ── Benign gate check: the mcp grant must have survived, and the
        #    REAL policy/mcp.rego must allow a benign RBAC tools/call ──────
        benign_input = {
            "posture": "mcp-b",
            "action": "mcp.tools.call",
            "identity": {
                "spiffe": rbac_spiffe, "verified": False, "chain": [], "rbac_verified": True,
            },
            "caller": {"agent_id": "", "user_id": "alice@example.com"},
            "tool": {"name": "echo", "args_redacted": {}},
            "target": {"mcp_id": mcp_id, "cert_fingerprint": "", "surface_hash": surface_hash},
        }
        resp = httpx.post(
            local_opa + "/v1/data/yashigani/mcp/allow",
            json={"input": benign_input}, timeout=5.0,
        )
        resp.raise_for_status()
        assert resp.json()["result"] is True, (
            "V50-022 REGRESSION: the onboard -> RBAC-grant -> benign-call "
            "sequence must succeed end to end; if this is False, the RBAC "
            "push clobbered the MCP grant/baseline the benign call depends "
            "on."
        )

        deny_resp = httpx.post(
            local_opa + "/v1/data/yashigani/mcp/deny_reason",
            json={"input": benign_input}, timeout=5.0,
        )
        assert deny_resp.json()["result"] == "ok"
