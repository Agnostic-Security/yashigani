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

FIX-P3-001 (LAURA-P3-001 — encoded path traversal):
  Path-bearing tool args are NFKC-normalised and iteratively percent-decoded
  before the OPA input document is built.  This prevents encoded traversal
  bypasses (..%2f, %252e%252e%252f, etc.) from reaching the OPA policy as
  opaque strings that bypass the literal "../" check.

  Normalisation applies to:
    - args.path  (singular — read_file, list_directory, directory_tree, etc.)
    - args.paths (array — read_multiple_files; FIX-P3-002)
    - args.source / args.destination (move_file)

  Normalisation order:
    1. Iterative urllib.parse.unquote until stable (handles double-encoding)
    2. unicodedata.normalize("NFKC") (collapses Unicode lookalikes)

  A normalized path that still contains %2e or %2f (ASCII percent-encoded dots/
  slashes that survived normalization) is an anomaly; OPA's belt-and-suspenders
  rule rejects it.

v2.25.0 / P1 W3 Phase 2b-ii + P3 filesystem bundle /
YSG-RISK-054 / LAURA-P3-001 / LAURA-P3-002.
"""
from __future__ import annotations

import logging
import time
import unicodedata
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote

import httpx

logger = logging.getLogger(__name__)

# OPA query path — matches policy/mcp.rego `package yashigani.mcp`
MCP_OPA_PATH = "/v1/data/yashigani/mcp/mcp_decision"
# Filesystem-specific tool-gating OPA path (FIX-P3-ENFORCE / Iris F2).
# The broker queries this for any Shape-C / mcp_server agent AFTER the global
# mcp_decision allow; a deny here aborts the call with fs_tool_not_permitted.
MCP_FS_TOOL_OPA_PATH = "/v1/data/yashigani/mcp/filesystem_tool_allowed"
# Git-specific tool-gating OPA path (P3-GIT / GIT-TM-001..004).
# Queried for agents with is_git_agent=True after mcp_decision allow.
MCP_GIT_TOOL_OPA_PATH = "/v1/data/yashigani/mcp/git_tool_allowed"
OPA_TIMEOUT_SECONDS = 0.5   # 500ms — C9 requirement


def _make_opa_http_client(timeout: float = OPA_TIMEOUT_SECONDS) -> httpx.AsyncClient:
    """
    FIX-OPA-SSL (2026-05-30): OPA is exposed only via HTTPS with the internal
    Yashigani PKI CA.  httpx's default trust store does NOT include the internal
    CA → [SSL: CERTIFICATE_VERIFY_FAILED] → opa_unreachable → tools/call denied.

    Read YASHIGANI_CA_CERT env var (= /run/secrets/ca_root.crt in the gateway
    container) and pass it as the CA bundle to httpx.AsyncClient.

    If the env var is unset or the file does not exist, fall back to the default
    trust store so that dev/test environments with a public-CA OPA still work.
    The fallback is intentional: local/unit-test OPA may run over plain HTTP or
    with a public cert; we only hard-require the CA for the production stack.

    This function is the SINGLE place AsyncClient is created for OPA queries —
    both query_mcp_decision and query_filesystem_tool_allowed use it.
    """
    import os
    ca_cert = os.environ.get("YASHIGANI_CA_CERT", "").strip()
    if ca_cert and os.path.isfile(ca_cert):
        logger.debug("mcp-broker: OPA client using CA cert %s", ca_cert)
        return httpx.AsyncClient(timeout=timeout, verify=ca_cert)
    # Fallback: system trust store (covers HTTP OPA in dev, or public-CA OPA)
    if ca_cert:
        logger.warning(
            "mcp-broker: YASHIGANI_CA_CERT=%r set but file not found — "
            "falling back to system trust store",
            ca_cert,
        )
    return httpx.AsyncClient(timeout=timeout)


# ---------------------------------------------------------------------------
# FIX-P3-001 — path argument normalisation (encoded traversal prevention)
# ---------------------------------------------------------------------------

def _normalize_path_arg(raw: str) -> str:
    """
    Normalise a single path argument string before it is included in the OPA
    input document.

    Steps (order is significant):
      1. Iterative urllib.parse.unquote until the string is stable.
         Handles single- and double-encoded traversals:
           ..%2fetc%2fshadow → ../etc/shadow  (one pass)
           %252e%252e%252fetc → %2e%2e%2fetc → ../etc  (two passes)
      2. unicodedata.normalize("NFKC"): collapses Unicode lookalikes
         (e.g. U+2025 TWO DOT LEADER, U+FF0F FULLWIDTH SOLIDUS) to their
         ASCII equivalents where canonically equivalent.

    The normalised value is what OPA receives; OPA's belt-and-suspenders
    rules then apply the standard literal "../" and startswith("/") checks
    against the already-decoded string.

    Returns the normalised string.
    """
    s = raw
    while True:
        decoded = unquote(s)
        if decoded == s:
            break
        s = decoded
    return unicodedata.normalize("NFKC", s)


def _normalize_tool_args(args: Optional[dict]) -> Optional[dict]:
    """
    Return a copy of ``args`` with all path-bearing values normalised.

    Normalised keys:
      - args["path"]        (str  — most tools)
      - args["paths"]       (list[str] — read_multiple_files; FIX-P3-002)
      - args["source"]      (str  — move_file)
      - args["destination"] (str  — move_file)

    Other keys are copied verbatim.  The original dict is NOT mutated.
    """
    if not isinstance(args, dict):
        return args

    normalised = dict(args)  # shallow copy; values replaced below

    # Singular path keys
    for key in ("path", "source", "destination"):
        val = normalised.get(key)
        if isinstance(val, str):
            normalised[key] = _normalize_path_arg(val)

    # Array path key (read_multiple_files)
    paths_val = normalised.get("paths")
    if isinstance(paths_val, list):
        normalised["paths"] = [
            _normalize_path_arg(p) if isinstance(p, str) else p
            for p in paths_val
        ]

    return normalised


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
    agent_name: Optional[str] = None,
    # FIX-P3-001: raw tool args (NOT redacted) for path normalisation.
    # The broker passes the full args here so path-bearing keys can be
    # normalised before OPA evaluation.  Redaction is applied separately
    # to tool_args_redacted.
    tool_args: Optional[dict] = None,
) -> dict:
    """
    Build the OPA input document.

    BINDING: chain MUST be a list of strings. If anything else is passed,
    this function raises ValueError before the OPA query fires
    (belt-and-suspenders against OPA receiving a malformed chain).

    FIX-P3-001: path-bearing args are NFKC-normalised + iteratively
    percent-decoded before being embedded in the input document.  This
    prevents encoded traversal strings (..%2f, %252e%252e, etc.) from
    bypassing OPA's literal ../ check.
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

    # FIX-P3-ENFORCE / Iris F2: embed agent.name so per-agent rego packages
    # can inspect it (e.g. package yashigani.agents.filesystem allow rule).
    if agent_name is not None:
        doc["agent"] = {"name": agent_name}

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
        # FIX-P3-001: normalise path-bearing args BEFORE embedding.
        # tool_args carries the full (non-redacted) arg map for path checking.
        # tool_args_redacted carries the sanitised version for audit.
        normalised_args = _normalize_tool_args(tool_args) or {}
        doc["tool"] = {
            "name": tool_name or "",
            "args": normalised_args,
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
    tool_args: Optional[dict] = None,
    prompt_name: Optional[str] = None,
    resource_uri: Optional[str] = None,
    resource_sensitivity: Optional[str] = None,
    prompt_sensitivity: Optional[str] = None,
    agent_name: Optional[str] = None,
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
            tool_args=tool_args,
            prompt_name=prompt_name,
            resource_uri=resource_uri,
            resource_sensitivity=resource_sensitivity,
            prompt_sensitivity=prompt_sensitivity,
            agent_name=agent_name,
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
            # FIX-OPA-SSL (2026-05-30): use _make_opa_http_client so the internal
            # CA cert is applied when YASHIGANI_CA_CERT env var is set.
            http_client = _make_opa_http_client()

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


# ---------------------------------------------------------------------------
# FIX-P3-ENFORCE / Iris F2 — filesystem tool-gating runtime query
# ---------------------------------------------------------------------------


@dataclass
class FsToolDecisionResult:
    """
    Result of querying data.yashigani.mcp.filesystem_tool_allowed.

    allowed: True when the tool call is permitted by the filesystem-specific
             OPA rules. False on any deny or error (fail-closed).
    deny_reason: string label for the deny case (audit).
    error: set when the query failed (OPA unreachable, timeout, etc.).
    elapsed_ms: query round-trip time.
    """

    allowed: bool
    deny_reason: str
    elapsed_ms: int
    error: Optional[str] = None


async def query_filesystem_tool_allowed(
    opa_url: str,
    tool_name: str,
    tool_args: Optional[dict] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> FsToolDecisionResult:
    """
    FIX-P3-ENFORCE (Iris F2) — query OPA filesystem_tool_allowed at runtime.

    This is the second OPA gate for Shape-C / mcp_server tool calls.  It
    executes AFTER query_mcp_decision returns allow=True and ONLY for agents
    whose manifest declares category=mcp_server (filesystem bundle).

    The input document shape matches what policy/mcp.rego filesystem rules
    expect: {"input": {"tool": {"name": ..., "args": {...}}}}.

    FIX-P3-001 NOTE: path-bearing args are normalised by the caller via
    _normalize_tool_args() before they are passed here.  This function
    receives already-normalised args so OPA sees the decoded paths.

    Fail-closed: any error (OPA unreachable, timeout, HTTP error, unexpected
    response shape) returns allowed=False.  A missing or undefined rule
    (OPA returns {"result": null}) is treated as deny.

    Returns FsToolDecisionResult (never raises).
    """
    t0 = time.monotonic()
    url = f"{opa_url.rstrip('/')}{MCP_FS_TOOL_OPA_PATH}"
    own_client = http_client is None

    # Normalise args (belt-and-suspenders — caller should also normalise)
    normalised_args = _normalize_tool_args(tool_args) or {}

    input_doc = {
        "input": {
            "tool": {
                "name": tool_name,
                "args": normalised_args,
            }
        }
    }

    try:
        if own_client:
            # FIX-OPA-SSL (2026-05-30): use _make_opa_http_client so the internal
            # CA cert is applied when YASHIGANI_CA_CERT env var is set.
            http_client = _make_opa_http_client()

        assert http_client is not None
        resp = await http_client.post(url, json=input_doc)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        resp.raise_for_status()
        raw = resp.json()

        # OPA returns {"result": true} or {"result": false} for a scalar rule.
        # {"result": null} means the rule is undefined (treat as deny — fail-closed).
        result_val = raw.get("result")
        if result_val is True:
            logger.debug(
                "mcp-broker: [P3] filesystem_tool_allowed=true tool=%s elapsed_ms=%d",
                tool_name, elapsed_ms,
            )
            return FsToolDecisionResult(
                allowed=True,
                deny_reason="ok",
                elapsed_ms=elapsed_ms,
            )

        # Determine deny reason via a secondary OPA query for the reason string.
        # For simplicity and to keep latency low we use the reason already embedded
        # in the mcp.rego filesystem_deny_reason rule; query it as a separate call
        # only when denied.  If the secondary query fails, we use the generic label.
        deny_reason = "fs_tool_not_permitted"
        if result_val is False or result_val is None:
            logger.info(
                "mcp-broker: [P3] filesystem_tool_allowed=false tool=%s elapsed_ms=%d",
                tool_name, elapsed_ms,
            )

        return FsToolDecisionResult(
            allowed=False,
            deny_reason=deny_reason,
            elapsed_ms=elapsed_ms,
            error=None if result_val is False else "OPA returned undefined result for filesystem_tool_allowed",
        )

    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3] OPA timeout querying filesystem_tool_allowed tool=%s — "
            "fail-closed",
            tool_name,
        )
        return FsToolDecisionResult(
            allowed=False,
            deny_reason="fs_opa_timeout",
            elapsed_ms=elapsed_ms,
            error=f"OPA timeout after {elapsed_ms}ms",
        )
    except httpx.HTTPStatusError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3] OPA HTTP error %d querying filesystem_tool_allowed tool=%s — "
            "fail-closed",
            exc.response.status_code, tool_name,
        )
        return FsToolDecisionResult(
            allowed=False,
            deny_reason="fs_opa_http_error",
            elapsed_ms=elapsed_ms,
            error=f"OPA returned HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3] OPA unreachable querying filesystem_tool_allowed tool=%s "
            "error=%s — fail-closed",
            tool_name, exc,
        )
        return FsToolDecisionResult(
            allowed=False,
            deny_reason="fs_opa_unreachable",
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )
    finally:
        if own_client and http_client is not None:
            try:
                await http_client.aclose()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# P3-GIT / GIT-TM-001..004 — git tool-gating runtime query
# ---------------------------------------------------------------------------

@dataclass
class GitToolDecisionResult:
    """
    Result of querying data.yashigani.mcp.git_tool_allowed.

    allowed: True when the tool call is permitted by the git-specific OPA rules.
             False on any deny or error (fail-closed).
    deny_reason: string label for the deny case (audit).
    error: set when the query failed (OPA unreachable, timeout, etc.).
    elapsed_ms: query round-trip time.
    """

    allowed: bool
    deny_reason: str
    elapsed_ms: int
    error: Optional[str] = None


async def query_git_tool_allowed(
    opa_url: str,
    tool_name: str,
    tool_args: Optional[dict] = None,
    http_client: Optional[httpx.AsyncClient] = None,
) -> GitToolDecisionResult:
    """
    P3-GIT — query OPA git_tool_allowed at runtime.

    Second OPA gate for git MCP-server agents.  Executes AFTER
    query_mcp_decision returns allow=True and ONLY for agents whose registry
    entry has is_git_agent=True.

    Input document shape:
        {"input": {"tool": {"name": ..., "args": {...}}}}

    Implements GIT-TM-001 (repo_path boundary), GIT-TM-004 (timestamp
    option injection guard) via the mcp.rego git_tool_allowed rule.

    Fail-closed: any error (OPA unreachable, timeout, HTTP error, undefined
    rule) returns allowed=False.  Never raises.
    """
    t0 = time.monotonic()
    url = f"{opa_url.rstrip('/')}{MCP_GIT_TOOL_OPA_PATH}"
    own_client = http_client is None

    normalised_args = _normalize_tool_args(tool_args) or {}

    input_doc = {
        "input": {
            "tool": {
                "name": tool_name,
                "args": normalised_args,
            }
        }
    }

    try:
        if own_client:
            http_client = _make_opa_http_client()

        assert http_client is not None
        resp = await http_client.post(url, json=input_doc)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        resp.raise_for_status()
        raw = resp.json()

        result_val = raw.get("result")
        if result_val is True:
            logger.debug(
                "mcp-broker: [P3-GIT] git_tool_allowed=true tool=%s elapsed_ms=%d",
                tool_name, elapsed_ms,
            )
            return GitToolDecisionResult(
                allowed=True,
                deny_reason="ok",
                elapsed_ms=elapsed_ms,
            )

        if result_val is False or result_val is None:
            logger.info(
                "mcp-broker: [P3-GIT] git_tool_allowed=false tool=%s elapsed_ms=%d",
                tool_name, elapsed_ms,
            )

        return GitToolDecisionResult(
            allowed=False,
            deny_reason="git_tool_not_permitted",
            elapsed_ms=elapsed_ms,
            error=None if result_val is False else "OPA returned undefined result for git_tool_allowed",
        )

    except httpx.TimeoutException:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3-GIT] OPA timeout querying git_tool_allowed tool=%s — "
            "fail-closed",
            tool_name,
        )
        return GitToolDecisionResult(
            allowed=False,
            deny_reason="git_opa_timeout",
            elapsed_ms=elapsed_ms,
            error=f"OPA timeout after {elapsed_ms}ms",
        )
    except httpx.HTTPStatusError as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3-GIT] OPA HTTP error %d querying git_tool_allowed tool=%s — "
            "fail-closed",
            exc.response.status_code, tool_name,
        )
        return GitToolDecisionResult(
            allowed=False,
            deny_reason="git_opa_http_error",
            elapsed_ms=elapsed_ms,
            error=f"OPA returned HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        logger.error(
            "mcp-broker: [P3-GIT] OPA unreachable querying git_tool_allowed tool=%s "
            "error=%s — fail-closed",
            tool_name, exc,
        )
        return GitToolDecisionResult(
            allowed=False,
            deny_reason="git_opa_unreachable",
            elapsed_ms=elapsed_ms,
            error=str(exc),
        )
    finally:
        if own_client and http_client is not None:
            try:
                await http_client.aclose()
            except Exception:
                pass
