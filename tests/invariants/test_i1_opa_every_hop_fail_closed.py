"""
I1 — Every-hop OPA on the data plane, both legs, FAIL-CLOSED.

INVARIANT (must ALWAYS hold): every CONFORMS data-plane dispatch surface evaluates
OPA on BOTH the request and response legs, and on ANY OPA failure (unreachable,
exception, undefined sub-decision) it DENIES — never fail-open. The three CONFORMS
surfaces (Iris S1/S3/S4 audit):
  * chat  — `/v1/chat/completions`  (openai_router: _opa_v1_check + _opa_response_check)
  * agent — `/agents/{id}/*`        (agent_router: _opa_agent_check + _opa_agent_response_check)
  * catch-all/MCP proxy — `/{path}` (proxy: _opa_check + _opa_proxy_response_check  ← GAP-002 closed)
plus the production startup guard: no OPA URL in production ⇒ the gateway refuses to
start (cannot run un-gated).

Why an invariant: OPA is the authorisation plane. A single fail-open path (an
exception that returns allow, an undefined decision that defaults permissive, a
production boot without OPA) silently disables policy. v2.25.2 already burned us on
OPA-003/004 (undefined sub-decision defaulting permissive) and LAURA-OPA-001 — this
locks the fail-closed posture in code.

Asserted here: the request- AND response-leg OPA functions exist on each surface,
every one has an exception handler that returns a denial (``allow: False`` /
``False``), and the production-OPA-mandatory startup guard is present. Source-level
so it is stable across internal refactors while pinning the load-bearing posture.

LIVE-PROOF (#44): a real OPA-down request over the wire (kill OPA, expect 403 on
each surface, both legs, every principal) is the VM probe; here we prove the code
contract.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "yashigani" / "gateway"

OPENAI_ROUTER = SRC / "openai_router.py"
AGENT_ROUTER = SRC / "agent_router.py"
PROXY = SRC / "proxy.py"


def _funcs(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out[node.name] = node
    return out


def _has_fail_closed_except(fn: ast.AST) -> bool:
    """A function whose try/except returns a DENIAL on exception.

    A denial is a return of ``False`` or a dict/structure containing
    ``allow=False`` / ``"allow": False``. We look for an ``except`` handler that
    returns something denying.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for ret in ast.walk(node):
            if not isinstance(ret, ast.Return):
                continue
            v = ret.value
            # return False
            if isinstance(v, ast.Constant) and v.value is False:
                return True
            # return (False, "...")
            if isinstance(v, ast.Tuple) and v.elts:
                first = v.elts[0]
                if isinstance(first, ast.Constant) and first.value is False:
                    return True
            # return {"allow": False, ...}
            if isinstance(v, ast.Dict):
                for k, val in zip(v.keys, v.values):
                    if (
                        isinstance(k, ast.Constant)
                        and k.value == "allow"
                        and isinstance(val, ast.Constant)
                        and val.value is False
                    ):
                        return True
    return False


# --------------------------------------------------------------------------- #
# Both OPA legs present on each CONFORMS surface
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "path,request_leg,response_leg",
    [
        (OPENAI_ROUTER, "_opa_v1_check", "_opa_response_check"),
        (AGENT_ROUTER, "_opa_agent_check", "_opa_agent_response_check"),
        (PROXY, "_opa_check", "_opa_proxy_response_check"),
    ],
)
def test_both_opa_legs_present(path: Path, request_leg: str, response_leg: str) -> None:
    funcs = _funcs(path)
    assert request_leg in funcs, (
        f"{path.name} missing the request-leg OPA function {request_leg!r} — the "
        f"data-plane surface would not be OPA-gated on request."
    )
    assert response_leg in funcs, (
        f"{path.name} missing the response-leg OPA function {response_leg!r} — the "
        f"data-plane surface would deliver upstream content without a response-leg "
        f"OPA check (the GAP-002 regression class)."
    )


@pytest.mark.parametrize(
    "path,fns",
    [
        (OPENAI_ROUTER, ["_opa_v1_check", "_opa_response_check"]),
        (AGENT_ROUTER, ["_opa_agent_check", "_opa_agent_response_check"]),
        (PROXY, ["_opa_check", "_opa_proxy_response_check"]),
    ],
)
def test_each_opa_leg_fails_closed(path: Path, fns: list[str]) -> None:
    funcs = _funcs(path)
    for name in fns:
        fn = funcs[name]
        assert _has_fail_closed_except(fn), (
            f"{path.name}:{name} has no except-handler that returns a denial — an "
            f"OPA error/unreachable must FAIL CLOSED (deny), never fail-open."
        )


def test_opa_unreachable_marker_present() -> None:
    """The explicit fail-closed reason string is present on each surface (a guard
    against a refactor that drops the deny-on-error path)."""
    for path in (OPENAI_ROUTER, AGENT_ROUTER, PROXY):
        assert "opa_unreachable" in path.read_text(encoding="utf-8"), (
            f"{path.name} lost its 'opa_unreachable' fail-closed denial marker."
        )


def test_production_opa_mandatory_startup_guard() -> None:
    """In production, no OPA URL ⇒ the gateway refuses to start (cannot run
    un-gated). The dev-only opt-out must be an explicit, non-default env flag."""
    text = OPENAI_ROUTER.read_text(encoding="utf-8")
    assert "YASHIGANI_OPA_URL is required in production" in text, (
        "openai_router must hard-fail startup when OPA is unset in production "
        "(zero-trust fail-closed boot guard)."
    )
    assert "YASHIGANI_OPA_OPTIONAL" in text, (
        "the OPA opt-out must be an explicit env flag (never the default)."
    )


def test_streaming_force_disabled_when_opa_active() -> None:
    """When OPA is active, streaming is force-disabled so the response leg's
    buffered OPA check applies (S13 — a streamed response can't be response-leg
    gated)."""
    text = OPENAI_ROUTER.read_text(encoding="utf-8")
    assert "use_streaming" in text and "_state.opa_url" in text, (
        "openai_router must couple streaming-disable to OPA being active so the "
        "response-leg OPA check is not bypassed by a streamed response."
    )
