#!/usr/bin/env python3
"""
yashigani-manifest — Manifest registration ledger CLI (LU-AMEND-02/03).

Commands:
  history  --tenant <id>          List registrations for a tenant, newest first.
  show     --id <record_id>       Display a single record incl. signed provenance.
  verify   --id <record_id>       Re-verify SHA-256 against the stored YAML blob.
  register --agent <id>           Display manifest, capture ack, sign, and register.

Auth pattern (matching yashigani-onboard.py / LU-AMEND-04):
  --token <operator-token>        Short-lived token from POST /auth/operator-token.
  --backoffice-url <https://...>  Default: https://localhost:8443
  --ca-cert <path>                Trust a Yashigani CA cert (self-signed installs).

Ceremony flow (register sub-command):
  1. Read manifest YAML from --manifest-file or stdin.
  2. Compute SHA-256 of the YAML blob.
  3. Display SHA-256 + first 20 lines of manifest to operator.
  4. Require explicit 'Y' acknowledgement (case-insensitive; anything else aborts).
  5. Build ceremony JSON: {manifest_sha256, operator_identity, confirmed_at,
                           ack_text_shown, ack_response: "Y",
                           signature_provenance: {alg, signer, sig}}.
  6. Sign ceremony JSON with SPIFFE HMAC (internal PKI, NOT Sigstore).
     v2 (deferred): Sigstore/RSA-PSS-SHA-384 manifest signature verification
     before `yashigani onboard` accepts. See LU-AMEND-03 spec §v2.
  7. POST to /admin/manifest-registrations/ceremony.

Security:
  - Token value is never written to stdout or any log file.
  - HTTPS-only TLS verification by default; use --ca-cert for self-signed CAs.
  - Stdin is NOT used for token input (avoid shell history leak).
    Pass --token from env var: --token "$YSG_OPERATOR_TOKEN".
  - No secrets are passed via subprocess argv.
  - HMAC key is read from /run/secrets/caddy_internal_hmac or YSG_CADDY_HMAC env var.
    If neither is available, signature_provenance.sig will be empty and the
    server records the ceremony as "unsigned" (auditable but lower assurance).

Exit codes:
  0  — Command succeeded.
  1  — API error or network failure.
  2  — Ceremony aborted (operator did not acknowledge).
  3  — Usage error (missing required flag).
  4  — SHA-256 verification failed (verify sub-command).

Compliance:
  LU-AMEND-02/03 / v2.24.1.
  NIST AU-2/AU-3/AU-12/SR-4/SR-4(3) + CMMC AU.L2-3.3.1/2/SR.L2-3.11.2
  SOC 2 CC6.2/6.3/CC8.1 + ISO 42001 A.6.1.2/A.6.2.6
  ISO 27001 A.5.21/A.5.23.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac_mod
import json
import os
import ssl
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_BACKOFFICE = "https://localhost:8443"
_HISTORY_PATH = "/admin/manifest-registrations"
_SHOW_PATH = "/admin/manifest-registrations/{id}"
_CEREMONY_PATH = "/admin/manifest-registrations/ceremony"
_HMAC_ENV = "YSG_CADDY_HMAC"

# Number of YAML lines shown in the ceremony ack prompt
_ACK_PREVIEW_LINES = 20


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
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # TLS 1.3 only (2.25.1)
    if ca_cert:
        if not os.path.isfile(ca_cert):
            _die(f"CA cert file not found: {ca_cert}")
        ctx.load_verify_locations(cafile=ca_cert)
    return ctx


def _hmac_secret() -> str:
    """Read caddy_internal_hmac from /run/secrets or YSG_CADDY_HMAC env var."""
    val = os.environ.get(_HMAC_ENV, "").strip()
    if val:
        return val
    try:
        with open("/run/secrets/caddy_internal_hmac") as f:
            return f.read().strip()
    except OSError:
        pass
    return ""


def _sign_ceremony(ceremony_json: str) -> str:
    """
    Compute HMAC-SHA256 over the ceremony JSON using the caddy_internal_hmac key.

    Returns the hex digest, or empty string if the key is unavailable.
    This is the internal SPIFFE-identity signing mechanism (NOT Sigstore).
    v2 (deferred): Sigstore/RSA-PSS-SHA-384 manifest signature verification.
    """
    secret = _hmac_secret()
    if not secret:
        _warn(
            "caddy_internal_hmac not available — ceremony will be recorded as "
            "unsigned. Set YSG_CADDY_HMAC env var or run from inside the "
            "backoffice container for signed ceremonies."
        )
        return ""
    h = _hmac_mod.new(
        secret.encode("utf-8"),
        ceremony_json.encode("utf-8"),
        hashlib.sha256,
    )
    return h.hexdigest()


def _spiffe_id() -> str:
    """Return the local SPIFFE ID, or an empty string if not available."""
    try:
        with open("/run/secrets/backoffice_spiffe_id") as f:
            return f.read().strip()
    except OSError:
        pass
    return os.environ.get("YSG_SPIFFE_ID", "")


def _post_json(
    url: str,
    payload: dict,
    token: str,
    ctx: ssl.SSLContext,
) -> dict:
    """POST JSON payload; return parsed response body."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}" if token else "",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            detail = json.loads(raw)
        except Exception:
            detail = {"raw": raw.decode("utf-8", errors="replace")}
        _die(f"API error {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        _die(f"Network error: {exc.reason}")
    return {}  # unreachable


def _get_json(
    url: str,
    token: str,
    ctx: ssl.SSLContext,
) -> dict | list:
    """GET JSON; return parsed response body."""
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}" if token else "",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            raw = resp.read()
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            detail = json.loads(raw)
        except Exception:
            detail = {"raw": raw.decode("utf-8", errors="replace")}
        _die(f"API error {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        _die(f"Network error: {exc.reason}")
    return {}  # unreachable


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_history(args: argparse.Namespace) -> None:
    """List manifest registrations for a tenant, newest first."""
    ctx = _build_ssl_context(args.ca_cert)
    qs = urllib.parse.urlencode({
        "tenant": args.tenant,
        "limit": args.limit,
        "offset": args.offset,
    })
    url = f"{args.backoffice_url.rstrip('/')}{_HISTORY_PATH}?{qs}"
    result = _get_json(url, args.token or "", ctx)

    items = result.get("items", []) if isinstance(result, dict) else result
    total = result.get("total", len(items)) if isinstance(result, dict) else len(items)

    if not items:
        _info(f"No manifest registrations found for tenant={args.tenant!r}")
        return

    _info(f"Manifest registrations for tenant={args.tenant!r} "
          f"(showing {len(items)} of {total}):")
    _info("-" * 72)
    for item in items:
        provenance_flag = " [signed]" if item.get("has_signature_provenance") else ""
        prev = item.get("previous_manifest_sha256") or "null (first registration)"
        _info(
            f"  id={item['id']:>6}  agent={item['agent_id']}\n"
            f"           sha256={item['manifest_sha256']}\n"
            f"           prev  ={prev}\n"
            f"           by    ={item['registered_by_operator_identity']}\n"
            f"           at    ={item['registered_at']}{provenance_flag}"
        )


def cmd_show(args: argparse.Namespace) -> None:
    """Display a single manifest registration record."""
    ctx = _build_ssl_context(args.ca_cert)
    url = f"{args.backoffice_url.rstrip('/')}{_SHOW_PATH.format(id=args.id)}"
    record = _get_json(url, args.token or "", ctx)

    if not isinstance(record, dict) or "id" not in record:
        _die(f"Unexpected response: {record}")

    _info(f"Manifest Registration Record id={record['id']}")
    _info("-" * 72)
    _info(f"  tenant_id  : {record['tenant_id']}")
    _info(f"  agent_id   : {record['agent_id']}")
    _info(f"  sha256     : {record['manifest_sha256']}")
    _info(f"  by         : {record['registered_by_operator_identity']}")
    _info(f"  at         : {record['registered_at']}")
    _info(f"  prev_sha256: {record.get('previous_manifest_sha256') or 'null (first)'}")
    prov = record.get("signature_provenance")
    if prov:
        _info("  provenance :")
        _info(textwrap.indent(json.dumps(prov, indent=4), "    "))
    else:
        _info("  provenance : (none — unsigned registration)")
    _info("")
    _info("  manifest_yaml_blob:")
    _info(textwrap.indent(record.get("manifest_yaml_blob", ""), "    "))


def cmd_verify(args: argparse.Namespace) -> None:
    """Re-verify SHA-256 of stored blob against stored manifest_sha256."""
    ctx = _build_ssl_context(args.ca_cert)
    url = f"{args.backoffice_url.rstrip('/')}{_SHOW_PATH.format(id=args.id)}"
    record = _get_json(url, args.token or "", ctx)

    if not isinstance(record, dict) or "manifest_yaml_blob" not in record:
        _die(f"Unexpected response: {record}")

    blob = record["manifest_yaml_blob"]
    stored = record["manifest_sha256"]
    recomputed = hashlib.sha256(blob.encode("utf-8")).hexdigest()

    if recomputed == stored:
        _info(f"OK: id={args.id} sha256={recomputed}")
    else:
        _info(
            f"MISMATCH: id={args.id}\n"
            f"  stored    : {stored}\n"
            f"  recomputed: {recomputed}",
            file=sys.stderr,
        )
        sys.exit(4)


def cmd_register(args: argparse.Namespace) -> None:
    """
    Interactive manifest signing ceremony.

    Reads manifest YAML, shows SHA-256 + preview to operator, captures 'Y' ack,
    signs, and POSTs to /admin/manifest-registrations/ceremony.
    """
    # -- Read manifest
    if args.manifest_file:
        if not os.path.isfile(args.manifest_file):
            _die(f"Manifest file not found: {args.manifest_file}", code=3)
        with open(args.manifest_file) as f:
            manifest_yaml = f.read()
    else:
        _info("Reading manifest YAML from stdin (end with Ctrl-D):")
        manifest_yaml = sys.stdin.read()

    if not manifest_yaml.strip():
        _die("Manifest YAML is empty", code=3)

    # -- Compute SHA-256
    manifest_sha = hashlib.sha256(manifest_yaml.encode("utf-8")).hexdigest()

    # -- Build ack text
    preview_lines = manifest_yaml.splitlines()[:_ACK_PREVIEW_LINES]
    preview = "\n".join(preview_lines)
    if len(manifest_yaml.splitlines()) > _ACK_PREVIEW_LINES:
        preview += f"\n... ({len(manifest_yaml.splitlines()) - _ACK_PREVIEW_LINES} more lines)"

    ack_text = (
        f"Manifest signing ceremony\n"
        f"{'=' * 72}\n"
        f"Agent    : {args.agent}\n"
        f"Tenant   : {args.tenant}\n"
        f"SHA-256  : {manifest_sha}\n"
        f"\nManifest preview:\n{preview}\n"
        f"{'=' * 72}\n"
        f"You are about to register this manifest in the immutable ledger.\n"
        f"This action cannot be undone.\n"
        f"\nType 'Y' to confirm or anything else to abort: "
    )

    # -- Capture ack
    try:
        response = input(ack_text).strip()
    except (EOFError, KeyboardInterrupt):
        _info("\nAborted.")
        sys.exit(2)

    if response != "Y":
        _info("Ceremony aborted — acknowledgement was not 'Y'.")
        sys.exit(2)

    confirmed_at = datetime.now(tz=timezone.utc).isoformat()

    # -- Determine operator identity
    if args.operator_identity:
        operator_identity = args.operator_identity
    elif args.token:
        # Parse the JWT sub claim (no verification — the server verifies)
        try:
            import base64
            parts = args.token.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (-len(parts[1]) % 4)
                claims = json.loads(base64.urlsafe_b64decode(padded))
                operator_identity = claims.get("sub", "unknown")
            else:
                operator_identity = "unknown"
        except Exception:
            operator_identity = "unknown"
    else:
        operator_identity = "unknown"

    # -- Build ceremony provenance and sign
    signer = _spiffe_id()
    ceremony_data = {
        "manifest_sha256": manifest_sha,
        "operator_identity": operator_identity,
        "confirmed_at": confirmed_at,
        "ack_text_shown": ack_text,
        "ack_response": "Y",
        "alg": "spiffe-internal-hmac",
        "signer": signer,
    }
    ceremony_json = json.dumps(ceremony_data, sort_keys=True)
    sig_hex = _sign_ceremony(ceremony_json)

    signature_provenance = {
        "alg": "spiffe-internal-hmac",
        "signer": signer,
        "sig": sig_hex,
        "signed_payload": ceremony_json,
    }

    # -- POST to ceremony endpoint
    ctx = _build_ssl_context(args.ca_cert)
    payload = {
        "tenant_id": args.tenant,
        "agent_id": args.agent,
        "manifest_yaml": manifest_yaml,
        "operator_identity": operator_identity,
        "manifest_sha256": manifest_sha,
        "confirmed_at": confirmed_at,
        "ack_text_shown": ack_text,
        "ack_response": "Y",
        "signature_provenance": signature_provenance,
    }

    url = f"{args.backoffice_url.rstrip('/')}{_CEREMONY_PATH}"
    result = _post_json(url, payload, args.token or "", ctx)

    _info(f"\nCeremony recorded successfully.")
    _info(f"  manifest_registration_id : {result.get('manifest_registration_id')}")
    _info(f"  manifest_sha256          : {result.get('manifest_sha256')}")
    _info(f"  audit_event_id           : {result.get('audit_event_id')}")
    _info(f"  recorded_at              : {result.get('recorded_at')}")
    if not sig_hex:
        _warn("Ceremony was recorded without an HMAC signature (key unavailable).")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yashigani-manifest",
        description="Yashigani manifest registration ledger CLI (LU-AMEND-02/03)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--backoffice-url",
        default=os.environ.get("YSG_BACKOFFICE_URL", _DEFAULT_BACKOFFICE),
        help=f"Backoffice base URL (default: {_DEFAULT_BACKOFFICE})",
    )
    p.add_argument(
        "--token",
        default=os.environ.get("YSG_OPERATOR_TOKEN", ""),
        help="Short-lived operator token (do NOT pass as inline value — use env var YSG_OPERATOR_TOKEN)",
    )
    p.add_argument("--ca-cert", default=None, help="Path to CA certificate for TLS verification")

    sub = p.add_subparsers(dest="command", required=True)

    # history
    hist = sub.add_parser("history", help="List manifest registrations for a tenant")
    hist.add_argument("--tenant", required=True, help="Tenant ID")
    hist.add_argument("--limit", type=int, default=50)
    hist.add_argument("--offset", type=int, default=0)

    # show
    show = sub.add_parser("show", help="Show a single manifest registration record")
    show.add_argument("--id", type=int, required=True, help="Record ID")

    # verify
    ver = sub.add_parser("verify", help="Re-verify SHA-256 against stored YAML blob")
    ver.add_argument("--id", type=int, required=True, help="Record ID")

    # register (ceremony)
    reg = sub.add_parser("register", help="Interactive manifest signing ceremony")
    reg.add_argument("--agent", required=True, help="Agent ID")
    reg.add_argument("--tenant", required=True, help="Tenant ID")
    reg.add_argument("--manifest-file", default=None, help="Path to manifest YAML file (stdin if omitted)")
    reg.add_argument("--operator-identity", default=None, help="Override operator identity (default: from token sub claim)")

    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "history":
        cmd_history(args)
    elif args.command == "show":
        cmd_show(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "register":
        cmd_register(args)
    else:
        parser.print_help()
        sys.exit(3)


if __name__ == "__main__":
    main()
