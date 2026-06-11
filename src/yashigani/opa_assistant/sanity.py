"""Client-policy sanity check (#17, OPA Phase 3a).

Before a client policy is saved/activated, run a behavioural sanity check so an
admin doesn't ship a policy that silently blocks everything (deny fires
unconditionally / allow is never true) or is otherwise inert. OPA's own PUT
already rejects syntax errors and unsafe recursion (a compile error in rego.v1),
so the additional value here is BEHAVIOURAL: PUT the candidate into a throwaway
sandbox module, evaluate its decision against a handful of benign sample inputs,
and observe whether it denies ALL of them (over-block) or never allows.

Plus an optional advisory LLM review (ollama) and a one-shot compile-repair for
the NL->Rego generator. Everything here is ADVISORY except the deny-all/never-allow
HIGH warnings the caller may gate on; nothing is auto-applied.

Pure async functions, no FastAPI deps — unit-testable. All OPA traffic uses the
internal mTLS client; the LLM uses the plain-http ollama pattern.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Severities
SEV_HIGH = "high"      # deny-all / never-allow — caller should gate save on confirm
SEV_INFO = "info"      # advisory (LLM notes, degraded checks)

# Benign sample inputs spanning the decision-contract input vocabulary (#16):
# a normal human request, an agent call, and a low/high sensitivity mix. A healthy
# policy should ALLOW at least one of these; a deny-all policy denies every one.
_BENIGN_SAMPLES: list[dict] = [
    {
        "identity": {"agent": "alice", "role": "human", "clearance": "PUBLIC", "groups": ["staff"]},
        "request": {"path": "/v1/chat/completions", "method": "POST"},
        "routing_decision": {"route": "local", "provider": "ollama", "model": "gemma3:4b"},
    },
    {
        "identity": {"agent": "openclaw", "role": "agent", "clearance": "RESTRICTED", "groups": ["agents"]},
        "request": {"path": "/v1/chat/completions", "method": "POST"},
        "routing_decision": {"route": "cloud", "provider": "openai", "model": "gpt-4o"},
    },
    {
        "identity": {"agent": "svc-budget", "role": "service", "clearance": "CONFIDENTIAL", "groups": ["platform"]},
        "request": {"path": "/v1/models", "method": "GET"},
        "routing_decision": {"route": "local", "provider": "ollama", "model": "gemma3:4b"},
    },
]


def _opa_base() -> str:
    return os.getenv("YASHIGANI_OPA_URL", "https://policy:8181").rstrip("/")


async def _sandbox_decision(rego: str, name: str, samples: list[dict]) -> dict:
    """PUT the candidate Rego into a throwaway sandbox module, evaluate its
    decision against each sample, then DELETE the module (always, in finally).

    Returns {"compiled": bool, "compile_error": str|None,
             "results": [{"allow": bool|None, "deny": [...]}], "undefined": bool}.
    The sandbox module id is clients/_sanity_<name>; the package inside the Rego is
    rewritten to clients._sanity_<name> so the candidate's own package name doesn't
    collide with a live clients/<name>.
    """
    from yashigani.pki.client import internal_httpx_client  # lazy: keeps the module
    # importable (and classify_results unit-testable) where httpx isn't installed.
    base = _opa_base()
    mod_id = f"clients/_sanity_{name}"
    pkg = f"clients._sanity_{name}"
    # Rewrite the leading `package clients.<whatever>` to the sandbox package so we
    # can evaluate data.<pkg>.decision without touching/needing the real module.
    import re
    sandbox_rego = re.sub(r"(?m)^\s*package\s+[A-Za-z0-9_.]+", f"package {pkg}", rego, count=1)

    out = {"compiled": False, "compile_error": None, "results": [], "undefined": False}
    try:
        async with internal_httpx_client(timeout=10.0) as client:
            put = await client.put(
                base + "/v1/policies/" + mod_id,
                content=sandbox_rego.encode("utf-8"),
                headers={"Content-Type": "text/plain"},
            )
            if put.status_code == 400:
                try:
                    out["compile_error"] = json.dumps(put.json())
                except Exception:
                    out["compile_error"] = "compile error"
                return out
            if put.status_code not in (200, 204):
                out["compile_error"] = f"opa_put_status_{put.status_code}"
                return out
            out["compiled"] = True
            # Evaluate decision per sample.
            for s in samples:
                r = await client.post(
                    base + f"/v1/data/{pkg.replace('.', '/')}/decision",
                    json={"input": s},
                    headers={"Content-Type": "application/json"},
                )
                res = r.json().get("result") if r.status_code == 200 else None
                if not isinstance(res, dict):
                    out["undefined"] = True
                    out["results"].append({"allow": None, "deny": []})
                else:
                    out["results"].append({
                        "allow": bool(res.get("allow", False)),
                        "deny": list(res.get("deny", []) or []),
                    })
            return out
    finally:
        # Always remove the sandbox module, even on exception/early return.
        try:
            async with internal_httpx_client(timeout=10.0) as client:
                await client.delete(base + "/v1/policies/" + mod_id)
        except Exception as exc:  # pragma: no cover — best-effort cleanup
            logger.warning("sanity: sandbox cleanup failed for %s: %s", mod_id, exc)


def classify_results(undefined: bool, results: list[dict]) -> list[dict]:
    """Pure heuristic: derive warnings from sandbox eval results. No I/O — unit-testable.

    HIGH warnings: deny_all (denies every benign sample), never_allow (allow never
    true but not all explicitly denied), decision_undefined (undefined for a sample
    — likely a decision-contract mismatch).
    """
    warnings: list[dict] = []
    allows = [r for r in results if r.get("allow") is True]
    denied = [r for r in results if r.get("allow") is False]
    if undefined:
        warnings.append({"code": "decision_undefined", "severity": SEV_HIGH,
                         "message": "The policy's decision was undefined for at least one normal request — "
                                    "it likely doesn't match the decision contract (allow/deny/obligations)."})
    if results and len(denied) == len(results) and not allows:
        warnings.append({"code": "deny_all", "severity": SEV_HIGH,
                         "message": "This policy DENIES every benign sample request — bound to a wildcard scope it "
                                    "would block an entire subject class. Confirm this is intended."})
    if results and not allows and not undefined and len(denied) != len(results):
        warnings.append({"code": "never_allow", "severity": SEV_HIGH,
                         "message": "This policy never returns allow=true for any benign sample — it may be "
                                    "over-broad. Confirm this is intended."})
    return warnings


async def static_sanity_check(rego: str, name: str, samples: Optional[list[dict]] = None) -> dict:
    """Behavioural sanity check. Returns
    {"ok": bool, "compiled": bool, "compile_error": str|None, "warnings": [ {code,severity,message} ]}.
    """
    samples = samples or _BENIGN_SAMPLES
    sb = await _sandbox_decision(rego, name, samples)
    if not sb["compiled"]:
        return {"ok": False, "compiled": False, "compile_error": sb["compile_error"], "warnings": []}
    warnings = classify_results(sb["undefined"], sb["results"])
    ok = not any(w["severity"] == SEV_HIGH for w in warnings)
    return {"ok": ok, "compiled": True, "compile_error": None, "warnings": warnings}


async def llm_review(rego: str) -> list[dict]:
    """Optional advisory LLM review (ollama). Returns a list of INFO warnings.
    Degrades to a single advisory note if the LLM is unavailable — never raises,
    never blocks. Reuses the plain-http ollama pattern used by generate_policy."""
    import httpx
    ollama_url = os.getenv("YASHIGANI_OLLAMA_URL", "http://ollama:11434").rstrip("/")
    model = os.getenv("YASHIGANI_OPA_ASSISTANT_MODEL") or os.getenv("OLLAMA_MODEL") or "gemma3:4b"
    prompt = (
        "You are reviewing an OPA Rego authorization policy for risky logic. In 1-3 short "
        "bullet points, flag ONLY concrete risks: does it block everything, never allow, "
        "ignore its input, or contain obviously wrong logic? If it looks fine, say 'No issues found.'\n\n"
        f"Policy:\n{rego[:6000]}\n"
    )
    try:
        async with httpx.AsyncClient(timeout=60.0) as c:
            r = await c.post(ollama_url + "/api/generate",
                             json={"model": model, "prompt": prompt, "stream": False})
            r.raise_for_status()
            text = (r.json().get("response") or "").strip()
        if not text or "no issues" in text.lower():
            return []
        return [{"code": "llm_review", "severity": SEV_INFO, "message": text[:1000]}]
    except Exception as exc:  # noqa: BLE001 — advisory only
        logger.info("sanity: LLM review unavailable (%s) — skipped", exc)
        return [{"code": "llm_review_unavailable", "severity": SEV_INFO,
                 "message": "LLM review was unavailable; static sanity check still ran."}]


async def compile_repair_once(draft_rego: str, name: str, regenerate) -> dict:
    """One-shot compile-repair for the NL->Rego generator. PUT the draft into the
    sandbox; if it compiles, return it unchanged. On a compile error, call
    `regenerate(error_text)` (an async callable that returns a corrected draft) ONCE
    and re-check. Returns {"rego": str, "repaired": bool, "repair_error": str|None}."""
    sb = await _sandbox_decision(draft_rego, name, [])  # PUT-only (empty samples)
    if sb["compiled"]:
        return {"rego": draft_rego, "repaired": False, "repair_error": None}
    err = sb["compile_error"] or "compile error"
    try:
        fixed = await regenerate(err)
    except Exception as exc:  # noqa: BLE001
        return {"rego": draft_rego, "repaired": False, "repair_error": f"regenerate failed: {exc}"}
    sb2 = await _sandbox_decision(fixed, name, [])
    if sb2["compiled"]:
        return {"rego": fixed, "repaired": True, "repair_error": None}
    return {"rego": fixed, "repaired": True, "repair_error": sb2["compile_error"] or "still failed to compile"}
