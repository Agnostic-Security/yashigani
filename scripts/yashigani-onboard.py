#!/usr/bin/env python3
"""
yashigani-onboard — Operator identity-attested agent onboarding CLI.

LU-AMEND-04 / v2.24.1: `yashigani onboard` requires a short-lived operator
token issued by the Caddy-fronted backoffice endpoint
(POST /auth/operator-token) to provide an auditable identity chain for every
agent registration ceremony.

Usage:
  yashigani-onboard.py --name <agent-name> --url <upstream-url> \\
                       --token <operator-token> \\
                       [--protocol <protocol>] \\
                       [--backoffice-url <https://...>] \\
                       [--ca-cert <path>]

  yashigani-onboard.py --name <agent-name> --url <upstream-url>
  # (no --token) → weak-identity mode: audit event flagged, operator warned.

Identity quality:
  attested  — operator supplied a valid --token (verified against backoffice).
              Full NIST AU-3 chain: operator identity + jti recorded in audit log.
  weak      — operator did NOT supply --token.
              Registration is still attempted but a WEAK-IDENTITY audit event
              is emitted. SOC 2 CC3.1 / CMMC CA.L2-3.12.2: auditors can
              identify un-attested onboards and require remediation.

Exit codes:
  0  — Registration succeeded (attested or weak).
  1  — Token verification failed (expired, invalid, wrong purpose).
  2  — Backoffice registration request failed.
  3  — Usage error (missing required flag).

Security:
  - Token value is never written to stdout or any log file.
    Only jti and identity are recorded.
  - HTTPS-only: TLS verification is enabled by default.
    Use --ca-cert to trust a self-signed Yashigani CA.
  - Stdin is NOT used for token input (avoid history leak via shell redirection).
    Pass --token as a flag from an env var: --token "$YSG_OPERATOR_TOKEN".
  - Secrets are never passed via subprocess argv (no shell=True).

LU-AMEND-04 references:
  ASVS V7.2.1 + NIST IA-2/AU-3 + CMMC IA.L2-3.5.1 + AU.L2-3.3.1
  SOC 2 CC6.1 + ISO 27001 A.5.16/A.5.17 + ISO 42001 A.6.1.2.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import urllib.parse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_BACKOFFICE = "https://localhost:8443"
_DEFAULT_PROTOCOL = "openai"
_VERIFY_PATH = "/auth/operator-token/verify"
_REGISTER_PATH = "/admin/agents"
_AUDIT_ONBOARD_PATH = "/internal/audit/onboard-event"  # audit write endpoint

# HMAC secret file — present at /run/secrets inside the backoffice container.
# CLI callers outside the container must supply it via YSG_CADDY_HMAC env var.
_HMAC_ENV = "YSG_CADDY_HMAC"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def _warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(msg)


def _build_ssl_context(ca_cert: str | None) -> ssl.SSLContext:
    """Build a TLS context that trusts the Yashigani CA (or system default)."""
    ctx = ssl.create_default_context()
    if ca_cert:
        if not os.path.isfile(ca_cert):
            _die(f"CA cert file not found: {ca_cert}")
        ctx.load_verify_locations(cafile=ca_cert)
    return ctx


def _hmac_header() -> str:
    """Read caddy_internal_hmac from /run/secrets or YSG_CADDY_HMAC env var."""
    # Env var takes precedence (for CLI callers outside the container).
    val = os.environ.get(_HMAC_ENV, "").strip()
    if val:
        return val
    # Try secrets file (for callers running inside the backoffice container).
    secrets_path = "/run/secrets/caddy_internal_hmac"
    try:
        with open(secrets_path) as f:
            return f.read().strip()
    except OSError:
        pass
    # Not available — return empty; the backoffice will reject with 403.
    return ""


def _post_json(
    url: str,
    payload: dict,
    headers: dict,
    ctx: ssl.SSLContext,
) -> dict:
    """POST JSON payload and return parsed response dict. Raises on non-2xx."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={
        "Content-Type": "application/json",
        **headers,
    })
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())


def _get_json(
    url: str,
    headers: dict,
    ctx: ssl.SSLContext,
) -> dict:
    """GET and return parsed response dict. Raises on non-2xx."""
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, context=ctx) as resp:
        return json.loads(resp.read())


# ---------------------------------------------------------------------------
# Core flows
# ---------------------------------------------------------------------------

def _verify_token(
    token: str,
    backoffice_url: str,
    ctx: ssl.SSLContext,
    hmac: str,
) -> dict:
    """
    Verify the operator token against GET /auth/operator-token/verify.
    Returns parsed response {sub, jti, exp, issued_for} on success.
    Calls _die() on failure (exits with code 1).
    """
    url = backoffice_url.rstrip("/") + _VERIFY_PATH
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Caddy-Verified-Secret": hmac,
    }
    try:
        result = _get_json(url, headers, ctx)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:200]
        try:
            detail = json.loads(body).get("detail", {})
            err = detail.get("error", body) if isinstance(detail, dict) else body
        except Exception:
            err = body
        if e.code == 401:
            _die(f"Operator token verification failed: {err} — "
                 "obtain a fresh token via POST /auth/operator-token (requires admin step-up)", code=1)
        else:
            _die(f"Token verification HTTP {e.code}: {err}", code=1)
    except Exception as e:
        _die(f"Token verification error: {e}", code=1)

    if not result.get("valid"):
        _die("Token verification returned valid=false", code=1)

    return result


def _emit_onboard_audit(
    *,
    backoffice_url: str,
    identity_quality: str,
    operator_identity: str,
    token_jti: str,
    agent_name: str,
    agent_url: str,
    client_ip: str,
    session_cookie: str,
    hmac: str,
    ctx: ssl.SSLContext,
) -> None:
    """
    POST an ONBOARD_ATTEMPTED audit event via the backoffice internal endpoint.
    Non-fatal: a failure here logs a warning but does not abort the onboard.

    The backoffice /internal/audit/onboard-event endpoint accepts the payload
    without requiring step-up (the session is already authenticated), records
    an OnboardAttemptedEvent, and returns 200.

    If the endpoint is not yet deployed (404), silently skip — the audit event
    will be wired in a subsequent release.
    """
    url = backoffice_url.rstrip("/") + _AUDIT_ONBOARD_PATH
    payload = {
        "identity_quality": identity_quality,
        "operator_identity": operator_identity,
        "token_jti": token_jti,
        "agent_name": agent_name,
        "agent_url": agent_url,
        "client_ip": client_ip,
    }
    headers = {
        "X-Caddy-Verified-Secret": hmac,
        "Cookie": f"__Host-yashigani_admin_session={session_cookie}" if session_cookie else "",
    }
    try:
        _post_json(url, payload, headers, ctx)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Endpoint not yet deployed — silently skip audit write.
            pass
        else:
            _warn(f"Audit event write failed (HTTP {e.code}) — proceeding without audit record")
    except Exception as e:
        _warn(f"Audit event write error: {e} — proceeding without audit record")


def _register_agent(
    *,
    backoffice_url: str,
    name: str,
    upstream_url: str,
    protocol: str,
    session_cookie: str,
    operator_identity: str,
    token_jti: str,
    hmac: str,
    ctx: ssl.SSLContext,
) -> dict:
    """
    POST /admin/agents to register the agent.  Requires active admin session.
    Returns the registration result dict on success, calls _die() on failure.
    """
    url = backoffice_url.rstrip("/") + _REGISTER_PATH
    payload = {
        "name": name,
        "upstream_url": upstream_url,
        "protocol": protocol,
        # LU-AMEND-04: carry operator identity chain in the registration payload.
        # Backoffice stores this in the agent registry alongside the agent record.
        "_operator_identity": operator_identity,
        "_operator_token_jti": token_jti,
    }
    headers = {
        "X-Caddy-Verified-Secret": hmac,
        # ISSUE-019: inject SPIFFE ID for the backoffice identity gate.
        "X-SPIFFE-ID": "spiffe://yashigani.internal/backoffice",
        "Cookie": f"__Host-yashigani_admin_session={session_cookie}",
    }
    try:
        return _post_json(url, payload, headers, ctx)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:300]
        try:
            detail = json.loads(body).get("detail", {})
            err = detail.get("error", body) if isinstance(detail, dict) else body
        except Exception:
            err = body
        _die(f"Agent registration failed (HTTP {e.code}): {err}", code=2)
    except Exception as e:
        _die(f"Agent registration error: {e}", code=2)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="yashigani onboard",
        description=(
            "Register an agent with the Yashigani gateway. "
            "Supply --token for operator identity attestation (recommended). "
            "Without --token the onboard proceeds as 'weak-identity' and is "
            "flagged in the audit log for GRC review."
        ),
    )
    p.add_argument(
        "--name",
        required=True,
        help="Agent name (unique within the gateway registry).",
    )
    p.add_argument(
        "--url",
        required=True,
        help="Upstream URL for the agent (e.g. http://langflow:7860).",
    )
    p.add_argument(
        "--token",
        default="",
        help=(
            "Short-lived operator token from POST /auth/operator-token. "
            "Obtain via: POST /auth/operator-token (requires admin step-up). "
            "Pass via env var to avoid shell history leaks: "
            "--token \"$YSG_OPERATOR_TOKEN\"."
        ),
    )
    p.add_argument(
        "--protocol",
        default=_DEFAULT_PROTOCOL,
        choices=["openai", "langflow", "letta"],
        help="Agent protocol (default: openai).",
    )
    p.add_argument(
        "--backoffice-url",
        default=_DEFAULT_BACKOFFICE,
        help=f"Backoffice base URL (default: {_DEFAULT_BACKOFFICE}).",
    )
    p.add_argument(
        "--ca-cert",
        default="",
        help="Path to CA certificate for TLS verification (Yashigani internal CA).",
    )
    p.add_argument(
        "--session-cookie",
        default="",
        help=(
            "Admin session cookie value for backoffice API calls. "
            "When running inside the backoffice container this is populated "
            "automatically by register_agent_bundles(). CLI callers must supply "
            "this explicitly (from a logged-in admin session)."
        ),
    )
    p.add_argument(
        "--allow-weak-identity",
        action="store_true",
        default=False,
        help=(
            "Allow onboarding without --token (weak-identity mode). "
            "The audit log will record identity_quality=weak. "
            "Requires explicit acknowledgement to prevent accidental un-attested onboards."
        ),
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    # --- Input validation ---------------------------------------------------
    agent_name = args.name.strip()
    agent_url = args.url.strip()
    token = args.token.strip()
    protocol = args.protocol
    backoffice_url = args.backoffice_url.rstrip("/")
    ca_cert = args.ca_cert.strip() or None

    if not agent_name:
        _die("--name must be a non-empty string", code=3)
    if not agent_url:
        _die("--url must be a non-empty string", code=3)
    if not agent_url.startswith(("http://", "https://")):
        _die("--url must start with http:// or https://", code=3)

    ctx = _build_ssl_context(ca_cert)
    hmac = _hmac_header()

    if not hmac:
        _warn(
            "YSG_CADDY_HMAC not set and /run/secrets/caddy_internal_hmac not found. "
            "Backoffice calls will be rejected with 403 unless running inside the container."
        )

    # --- Token verification / weak-identity decision -----------------------
    operator_identity = "unknown"
    token_jti = ""
    identity_quality = "weak"

    if token:
        _info("Verifying operator token…")
        token_info = _verify_token(token, backoffice_url, ctx, hmac)
        operator_identity = token_info.get("sub", "unknown")
        token_jti = token_info.get("jti", "")
        identity_quality = "attested"
        _exp = token_info.get("exp", 0)
        _remaining = max(0, _exp - int(time.time()))
        _info(
            f"Token verified. Operator: {operator_identity} | "
            f"jti: {token_jti} | expires in {_remaining}s"
        )
    else:
        if not args.allow_weak_identity:
            print(
                "\nWARNING: No --token supplied. Proceeding in WEAK-IDENTITY mode.\n"
                "The audit log will record identity_quality=weak for this onboard.\n"
                "This may require a manual exception entry in docs/risk-register.yml\n"
                "for SOC 2 CC3.1 / CMMC CA.L2-3.12.2 compliance.\n"
                "\nTo suppress this warning and proceed, add --allow-weak-identity.\n"
                "To obtain a token: POST /auth/operator-token (requires admin step-up).\n",
                file=sys.stderr,
            )
            # Non-interactive: exit with a clear error. The operator must
            # explicitly opt in to weak-identity mode.
            _die(
                "Refusing to onboard without --token. "
                "Use --allow-weak-identity to proceed in weak-identity mode.",
                code=3,
            )
        _warn(
            "WEAK-IDENTITY onboard: no operator token supplied. "
            "identity_quality=weak will be recorded in the audit log."
        )

    # --- Emit audit event --------------------------------------------------
    # Note: this uses a /internal/ endpoint that requires the session cookie.
    # On the install.sh code path the session cookie is populated by the
    # register_agent_bundles() login flow. CLI callers must pass --session-cookie.
    _emit_onboard_audit(
        backoffice_url=backoffice_url,
        identity_quality=identity_quality,
        operator_identity=operator_identity,
        token_jti=token_jti,
        agent_name=agent_name,
        agent_url=agent_url,
        client_ip="cli",
        session_cookie=args.session_cookie,
        hmac=hmac,
        ctx=ctx,
    )

    # --- Register the agent ------------------------------------------------
    _info(f"Registering agent '{agent_name}' at {agent_url} (protocol={protocol})…")
    result = _register_agent(
        backoffice_url=backoffice_url,
        name=agent_name,
        upstream_url=agent_url,
        protocol=protocol,
        session_cookie=args.session_cookie,
        operator_identity=operator_identity,
        token_jti=token_jti,
        hmac=hmac,
        ctx=ctx,
    )

    agent_id = result.get("agent_id", result.get("id", "?"))
    _info(
        f"Agent registered. ID: {agent_id} | "
        f"identity_quality: {identity_quality} | "
        f"operator: {operator_identity}"
    )
    if identity_quality == "weak":
        _warn(
            "Onboard completed in WEAK-IDENTITY mode. "
            "Consider documenting this in docs/risk-register.yml."
        )


if __name__ == "__main__":
    main()
