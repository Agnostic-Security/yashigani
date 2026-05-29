"""
MCP Broker — OPA enforcement with fail-closed 500ms timeout.

Queries /v1/data/yashigani/mcp/mcp_decision per the locked policy contract.

Input shape (must exactly match mcp.rego):
  {
    "input": {
      "posture":   "mcp-a" | "mcp-b" | "mcp-c",
      "action":    "mcp.tools.call" | ...,
      "identity":  {"spiffe": "<uri>", "chain": ["<uri>", ...]},
      "tool":      {"name": "<name>", "args_redacted": {<k>: <v>, ...}},  // or prompt/resource
    }
  }

  BINDING: identity.chain MUST be a JSON array of strings.
           An object or non-string element causes _chain_depth=0 (OPA deny).

Decision shape:
  {
    "allow":          bool,
    "deny_reason":    str,
    "redact_args":    set[str],  (empty set → no redaction)
    "audit_capture":  bool,
    "rate_limit_key": str | null,
  }

Fail-closed:
  - OPA timeout (500ms): deny, emit OPA_DECISION_ON_MCP with error.
  - OPA unreachable (connection error): deny.
  - OPA returns non-200: deny.
  - OPA returns allow=false: deny.

C9 fail-closed: a missing/misconfigured OPA MUST NOT allow MCP calls through.

v2.25.0 / P1 W3 Phase 2b-ii / YSG-RISK-054.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# OPA query path — matches policy/mcp.rego `package yashigani.mcp`
MCP_OPA_PATH = "/v1/data/yashigani/mcp/mcp_decision"
OPA_TIMEOUT_SECONDS = 0.5   # 500ms — C9 requirement


@dataclass
class OpaDecisionResult:
    """Parsed result from OPA mcp_decision query."""

    allow: bool
    deny_reason: str
    redact_args: set[str]
    audit_capture: bool
    rate_limit_key: Optional[str]
    elapsed_ms: int
    error: Optional[str] = None  # set when OPA was unreachable or timed out


def _build_opa_input(
    posture: str,
    action: str,
    spiffe_uri: str,
    chain: list[str],
    tool_name: Optional[str] = None,
    tool_args_redacted: Optional[dict] = None,
    prompt_name: Optional[str] = None,
    resource_uri: Optional[str] = None,
    resource_sensitivity: Optional[str] = None,
    prompt_sensitivity: Optional[str] = None,
) -> dict:
    """
    Build the OPA input document.

    BINDING: chain MUST be a list of strings. If anything else is passed,
    this function raises ValueError before the OPA query fires
    (belt-and-suspenders against OPA receiving a malformed chain).
    """
    if not isinstance(chain, list):
        raise ValueError(
            f"identity.chain must be a list; got {type(chain).__name__}. "
            "OPA guard will deny non-array chains. Rejecting before OPA call."
        )
    for i, e in enumerate(chain):
        if not isinstance(e, str):
            raise ValueError(
                f"identity.chain[{i}] must be a string; got {type(e).__name__}: {e!r}. "
                "OPA guard will deny. Rejecting before OPA call."
            )

    identity: dict = {"spiffe": spiffe_uri, "chain": chain}
    doc: dict = {
        "posture": posture,
        "action": action,
        "identity": identity,
    }

    if prompt_name is not None:
        prompt_obj: dict = {"name": prompt_name}
        if prompt_sensitivity:
            prompt_obj["sensitivity"] = prompt_sensitivity
        doc["prompt"] = prompt_obj
    elif resource_uri is not None:
        resource_obj: dict = {"uri": resource_uri}
        if resource_sensitivity:
            resource_obj["sensitivity"] = resource_sensitivity
        doc["resource"] = resource_obj
    else:
        doc["tool"] = {
            "name": tool_name or "",
            "args_redacted": tool_args_redacted or {},
        }

    return {"input": doc}


def _parse_opa_response(raw: dict, elapsed_ms: int) -> OpaDecisionResult:
    """Parse the raw OPA JSON response into OpaDecisionResult."""
    result = raw.get("result", {})
    if not isinstance(result, dict):
        # OPA may return {"result": null} on undefined rule — treat as deny
        return OpaDecisionResult(
            allow=False,
            deny_reason="opa_undefined_result",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=elapsed_ms,
            error="OPA returned undefined result",
        )

    redact_raw = result.get("redact_args", [])
    if isinstance(redact_raw, (list, set)):
        redact_args = set(str(k) for k in redact_raw)
    else:
        redact_args = set()

    return OpaDecisionResult(
        allow=bool(result.get("allow", False)),
        deny_reason=str(result.get("deny_reason", "opa_no_reason")),
        redact_args=redact_args,
        audit_capture=bool(result.get("audit_capture", True)),
        rate_limit_key=result.get("rate_limit_key") or None,
        elapsed_ms=elapsed_ms,
    )


async def query_mcp_decision(
    opa_url: str,
    posture: str,
    action: str,
    spiffe_uri: str,
    chain: list[str],
    tool_name: Optional[str] = None,
    tool_args_redacted: Optional[dict] = None,
    prompt_name: Optional[str] = None,
    resource_uri: Optional[str] = None,
    resource_sensitivity: Optional[str] = None,
    prompt_sensitivity: Optional[str] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> OpaDecisionResult:
    """
    Query OPA for an MCP call decision. Fail-closed on any failure.

    Parameters
    ----------
    opa_url:
        Base URL of OPA (e.g. "http://localhost:8181").

    Returns OpaDecisionResult. Never raises — all errors result in a deny
    decision with error field populated (fail-closed per C9).
    """
    t0 = time.monotonic()

    try:
        input_doc = _build_opa_input(
            posture=posture,
            action=action,
            spiffe_uri=spiffe_uri,
            chain=chain,
            tool_name=tool_name,
            tool_args_redacted=tool_args_redacted,
            prompt_name=prompt_name,
            resource_uri=resource_uri,
            resource_sensitivity=resource_sensitivity,
            prompt_sensitivity=prompt_sensitivity,
        )
    except ValueError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error("mcp-broker: OPA input construction failed: %s", exc)
        return OpaDecisionResult(
            allow=False,
            deny_reason="invalid_opa_input",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )

    url = f"{opa_url.rstrip('/')}{MCP_OPA_PATH}"
    own_client = http_client is None

    # FIX-F(2) / Iris FIND-003: previously had BOTH httpx timeout (500ms) AND
    # asyncio.wait_for (500ms).  Two concurrent timeouts mean the deny_reason
    # label ("opa_timeout" vs "opa_unreachable") was race-dependent depending on
    # which fired first.  Fix: rely on a SINGLE timeout mechanism — httpx's own
    # built-in timeout — and catch httpx.TimeoutException explicitly.
    # asyncio.wait_for wrapper removed.  Label is now deterministic: httpx always
    # raises httpx.TimeoutException on its own timeout, giving "opa_timeout".

    try:
        if own_client:
            http_client = httpx.AsyncClient(timeout=OPA_TIMEOUT_SECONDS)

        assert http_client is not None
        resp = await http_client.post(url, json=input_doc)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        resp.raise_for_status()
        raw = resp.json()
        result = _parse_opa_response(raw, elapsed_ms)

        if not result.allow:
            logger.info(
                "mcp-broker: OPA deny posture=%s action=%s reason=%s elapsed_ms=%d",
                posture, action, result.deny_reason, elapsed_ms,
            )
        else:
            logger.debug(
                "mcp-broker: OPA allow posture=%s action=%s elapsed_ms=%d",
                posture, action, elapsed_ms,
            )
        return result

    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: OPA timeout after %dms (limit=%dms) posture=%s action=%s — "
            "fail-closed (C9)",
            elapsed_ms, int(OPA_TIMEOUT_SECONDS * 1000), posture, action,
        )
        return OpaDecisionResult(
            allow=False,
            deny_reason="opa_timeout",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=elapsed_ms,
            error=f"OPA timeout after {elapsed_ms}ms",
        )
    except httpx.HTTPStatusError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: OPA HTTP error %d posture=%s action=%s — fail-closed (C9)",
            exc.response.status_code, posture, action,
        )
        return OpaDecisionResult(
            allow=False,
            deny_reason="opa_http_error",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=elapsed_ms,
            error=f"OPA returned HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: OPA unreachable posture=%s action=%s error=%s — fail-closed (C9)",
            posture, action, exc,
        )
        return OpaDecisionResult(
            allow=False,
            deny_reason="opa_unreachable",
            redact_args=set(),
            audit_capture=True,
            rate_limit_key=None,
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )
    finally:
        if own_client and http_client is not None:
            try:
                await http_client.aclose()
            except Exception:
                pass
