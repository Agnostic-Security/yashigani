"""
Yashigani Auth — Step-up authentication (ASVS V6.8.4 / V2.4.x).

Per-route step-up logic: high-value admin endpoints require a fresh
TOTP code submitted within the last N minutes (default 5), independent
of session state and IdP/SSO claims.

Even a fully-authenticated admin must re-prove TOTP at the moment of a
dangerous action.  This is belt-and-braces: IdP compromise or session
hijack cannot bypass the per-action TOTP gate.

Last updated: 2026-04-27T00:00:00+01:00

ASVS references:
  V6.8.4 — Re-authentication before critical operations.
  V2.4.x — Verifier impersonation resistance (step-up is app-layer,
            not solely IdP-derived).
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional

from fastapi import HTTPException, status

if TYPE_CHECKING:
    from yashigani.auth.session import Session

_log = logging.getLogger("yashigani.auth.stepup")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: How long (seconds) a step-up TOTP verification remains valid.
#: Configurable via YASHIGANI_STEPUP_TTL_SECONDS. Default: 300 (5 minutes).
STEPUP_TTL_SECONDS: int = int(os.getenv("YASHIGANI_STEPUP_TTL_SECONDS", "300"))

#: How long (seconds) a minted privileged-mutation step-up PROOF token remains
#: valid.  This is the headless/CLI counterpart of the in-session step-up window:
#: an operator does a fresh TOTP step-up in the API, mints a proof, and hands it
#: to install.sh (--stepup-token) for a single destructive lifecycle op.  Short
#: by design — long enough for one ceremony, short enough that a leaked token has
#: little value.  Configurable via YASHIGANI_STEPUP_PROOF_TTL_SECONDS.
STEPUP_PROOF_TTL_SECONDS: int = int(
    os.getenv("YASHIGANI_STEPUP_PROOF_TTL_SECONDS", "300")
)

#: Stable JWT claims for the privileged-mutation step-up proof.  The verifier
#: rejects any token whose ``purpose`` / ``iss`` do not match exactly — an
#: operator-onboard token (LU-AMEND-04, purpose="operator-onboard") can NEVER be
#: replayed as a privileged-mutation proof, and vice-versa.
STEPUP_PROOF_PURPOSE = "privileged-mutation"
STEPUP_PROOF_ISSUER = "yashigani.backoffice"

#: Default location of the per-install HMAC signing key.  This is the same
#: secret install.sh generates (caddy_internal_hmac) and that the operator-token
#: surface (LU-AMEND-04) already signs with — so the host-shell verifier shim and
#: the API mint/verify share one key with zero new secret material.
#: Overridable via YASHIGANI_STEPUP_SIGNING_KEY_PATH for tests / non-default mounts.
_DEFAULT_SIGNING_KEY_PATH = "/run/secrets/caddy_internal_hmac"


# ---------------------------------------------------------------------------
# Core logic (pure — no FastAPI imports needed here)
# ---------------------------------------------------------------------------

def has_fresh_stepup(session: "Session") -> bool:
    """
    Return True if the session has a recent (<STEPUP_TTL_SECONDS) step-up
    TOTP event.

    Rules:
    - last_totp_verified_at is None (never performed) → False.
    - last_totp_verified_at > now (clock skew / tampered) → False (conservative).
    - Age >= TTL → False (expired).
    - Age < TTL → True.
    """
    if session.last_totp_verified_at is None:
        return False
    age_seconds = time.time() - session.last_totp_verified_at
    if age_seconds < 0:
        # Clock skew or tampered timestamp — reject conservatively.
        return False
    return age_seconds < STEPUP_TTL_SECONDS


class StepUpRequired(HTTPException):
    """
    Raised when a step-up TOTP verification is required before proceeding.
    HTTP 401 with detail.error = "step_up_required" — the JS interceptor
    catches this and shows the TOTP modal before retrying.
    """

    def __init__(self) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "step_up_required",
                "message": (
                    "This action requires fresh TOTP verification. "
                    "POST a current TOTP code to /auth/stepup and retry."
                ),
                "stepup_endpoint": "/auth/stepup",
                "ttl_seconds": STEPUP_TTL_SECONDS,
            },
        )


def assert_fresh_stepup(session: "Session") -> None:
    """
    Raise StepUpRequired if the session does not have a fresh step-up.
    Call this at the top of any high-value route handler.
    """
    if not has_fresh_stepup(session):
        raise StepUpRequired()


# ---------------------------------------------------------------------------
# Shared privileged-mutation gate (designed ONCE for #3/#4/#5)
#
# Per Iris architecture §5 + Laura §8 (R3-9): tensions #3 (MCP envelope
# re-approval), #4, and #5 ALL need the same step-up.  Build it once as a
# reusable gate, not three bespoke ones.  Su's #4 (MI-4) reuses this.
#
# Contract:
#   1. requires a FRESH step-up (assert_fresh_stepup) — IdP-compromise /
#      session-hijack cannot bypass it.
#   2. requires the OPERATOR identity (admin RBAC tier).
#   3. emits a uniform PRIVILEGED_MUTATION audit event so every privileged
#      action across #3/#4/#5 lands in one tamper-evident audit shape.
#   4. surfaces the I6 decision contract on the deny side (code=STEP_UP_REQUIRED
#      / NOT_AUTHORISED).
#
# The fresh-TOTP requirement is UNCONDITIONAL regardless of whether the
# re-approval action is later rendered as an OPA admin-plane decision or as
# broker-internal-fail-closed (Tiago design-call #1 / GAP-003); the OPA
# rendering is a wrapper that follows that ruling.
# ---------------------------------------------------------------------------


class NotAuthorisedForPrivilegedMutation(HTTPException):
    """
    Raised when the principal lacks the operator (admin) RBAC tier required for
    a privileged mutation.  Distinct from StepUpRequired: a non-admin can never
    satisfy this by re-proving TOTP — they are simply not authorised.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "not_authorised",
                "code": "NOT_AUTHORISED",
                "message": (
                    "This action requires operator (admin) privileges."
                ),
                "reason": reason,
            },
        )


@dataclass
class PrivilegedMutationContext:
    """
    The decision context for a privileged mutation, passed to the gate.

    reason:
        Stable machine reason, e.g. "mcp.envelope.reapprove" (#3).
    principal:
        The operator identity (session.account_id / sub claim).
    target:
        The object being mutated, e.g. the provenance_id (#3).
    justification:
        Optional free-text operator justification (recorded, never trusted).
    before / after:
        Optional state snapshots for the audit event (e.g. the field-level
        diff for an envelope re-approval).
    """
    reason: str
    principal: str
    target: str
    justification: Optional[str] = None
    before: Optional[dict] = None
    after: Optional[dict] = None


#: Admin tier value (matches auth.session.Session.account_tier).
_OPERATOR_TIER = "admin"


def assert_privileged_mutation(
    session: "Session",
    ctx: PrivilegedMutationContext,
    *,
    audit_writer: Any = None,
) -> None:
    """
    The shared privileged-mutation gate.  Call this at the top of any
    privileged-mutation handler (envelope re-approval, #4/#5 surfaces).

    Enforcement order (fail-closed):
      1. operator (admin) RBAC tier — else NotAuthorisedForPrivilegedMutation.
      2. FRESH step-up TOTP — else StepUpRequired.
      3. emit the uniform PRIVILEGED_MUTATION audit event (best-effort; the
         mutation proceeds only AFTER both gates pass).

    Raises StepUpRequired (401) or NotAuthorisedForPrivilegedMutation (403)
    on failure; returns None on success (the caller then performs the mutation).
    """
    # Gate 1 — operator RBAC.  A non-admin is never authorised, full stop.
    if getattr(session, "account_tier", None) != _OPERATOR_TIER:
        _log.warning(
            "privileged_mutation DENIED (not operator): reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )
        raise NotAuthorisedForPrivilegedMutation(ctx.reason)

    # Gate 2 — fresh step-up TOTP (unconditional).
    if not has_fresh_stepup(session):
        _log.info(
            "privileged_mutation STEP-UP REQUIRED: reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )
        raise StepUpRequired()

    # Gate 3 — uniform audit event (both gates passed; mutation is authorised).
    _emit_privileged_mutation_event(ctx, audit_writer)


def _emit_privileged_mutation_event(
    ctx: PrivilegedMutationContext,
    audit_writer: Any,
) -> None:
    """Emit the uniform PRIVILEGED_MUTATION audit event (best-effort)."""
    try:
        from yashigani.audit.schema import PrivilegedMutationEvent
    except Exception as exc:  # noqa: BLE001 — audit import must never block the gate
        _log.error("privileged_mutation: audit schema import failed: %s", exc)
        return

    event = PrivilegedMutationEvent(
        reason=ctx.reason,
        principal=ctx.principal,
        target=ctx.target,
        justification=ctx.justification or "",
        before=ctx.before,
        after=ctx.after,
    )
    if audit_writer is not None:
        try:
            audit_writer.write(event)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "privileged_mutation: audit write failed reason=%s target=%s: %s",
                ctx.reason, ctx.target, exc,
            )
    else:
        _log.warning(
            "privileged_mutation: no audit_writer — PRIVILEGED_MUTATION NOT written "
            "reason=%s principal=%s target=%s",
            ctx.reason, ctx.principal, ctx.target,
        )


# ---------------------------------------------------------------------------
# MI-4 — step-up PROOF token contract (headless / install.sh call-site)
#
# The in-session gate (assert_privileged_mutation) covers FastAPI routes that
# hold a live Session (e.g. #3 envelope re-approval).  The destructive
# lifecycle ops on the install.sh side (#4 MI-4: add-component / uninstall on a
# running stack) have NO Session — they run in a host shell.  Su's call-site
# (_require_stepup_mi4) accepts a --stepup-token and DEFERS its cryptographic
# verification to this contract.
#
# Token shape (HS256 JWT, signed with the per-install caddy_internal_hmac — the
# same key the LU-AMEND-04 operator-token already uses, so NO new secret):
#   sub      operator (admin) username who stepped up
#   jti      uuid4 (audit correlation; single-use is enforced by the short TTL +
#            the op being interactive — we do not keep a server-side jti cache on
#            the host-shell path, the TTL is the replay bound)
#   iat/exp  iat .. iat + STEPUP_PROOF_TTL_SECONDS
#   iss      "yashigani.backoffice"
#   purpose  "privileged-mutation"   (NOT "operator-onboard" — purpose pinning
#            stops an onboard token being replayed as a mutation proof)
#   op       the lifecycle op label this proof authorises (e.g. "add-component"),
#            optionally bound so a proof minted for one op cannot authorise another
#
# verify_stepup_proof() is the SINGLE verification surface, shared by:
#   * assert_privileged_mutation_token() (this module — programmatic callers), and
#   * the install.sh host-shell shim (python -m yashigani.auth.stepup --verify-proof).
# Fail-closed: any signature / expiry / purpose / issuer / op mismatch raises.
# ---------------------------------------------------------------------------


class StepUpProofInvalid(Exception):
    """
    Raised when a privileged-mutation step-up proof token fails verification.

    Distinct from StepUpRequired (which is an HTTP 401 for the in-session path):
    this is the headless/CLI failure shape.  The caller (gate or install.sh shim)
    fails closed on it.  ``reason`` is a stable machine label for audit/logs.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def _load_signing_key(signing_key_path: Optional[str] = None) -> str:
    """
    Load the per-install HMAC signing key (caddy_internal_hmac).

    Resolution order:
      1. ``YASHIGANI_STEPUP_SIGNING_KEY`` env var (raw value — used by tests).
      2. ``signing_key_path`` argument, else ``YASHIGANI_STEPUP_SIGNING_KEY_PATH``
         env var, else the default /run/secrets/caddy_internal_hmac.

    Raises StepUpProofInvalid("signing_key_unavailable") if no key can be loaded
    — fail-closed: an unverifiable proof must never be treated as valid.
    """
    raw = os.environ.get("YASHIGANI_STEPUP_SIGNING_KEY", "").strip()
    if raw:
        return raw
    path = (
        signing_key_path
        or os.environ.get("YASHIGANI_STEPUP_SIGNING_KEY_PATH")
        or _DEFAULT_SIGNING_KEY_PATH
    )
    try:
        with open(path) as fh:
            key = fh.read().strip()
    except OSError as exc:
        _log.error("stepup-proof: signing key not readable at %s: %s", path, exc)
        raise StepUpProofInvalid("signing_key_unavailable") from exc
    if not key:
        raise StepUpProofInvalid("signing_key_empty")
    return key


def mint_stepup_proof(
    *,
    subject: str,
    op: str,
    signing_key_path: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
) -> tuple[str, str]:
    """
    Mint a privileged-mutation step-up proof token.

    Called by the admin API ONLY after a fresh TOTP step-up has been verified for
    the operator (the route is responsible for that prerequisite, mirroring the
    LU-AMEND-04 operator-token route).  This function does NOT itself verify TOTP
    — it signs a proof asserting that step-up already happened.

    Parameters
    ----------
    subject:
        The operator (admin) username who stepped up.
    op:
        The lifecycle-op label this proof authorises (e.g. "add-component").
        Bound into the token so a proof for one op cannot authorise another.
    signing_key_path:
        Override for the HMAC key path (default caddy_internal_hmac).
    ttl_seconds:
        Override the proof TTL (default STEPUP_PROOF_TTL_SECONDS).

    Returns
    -------
    (token, jti) — the encoded JWT and its jti (for audit correlation).
    """
    import jwt as _pyjwt

    key = _load_signing_key(signing_key_path)
    jti = str(uuid.uuid4())
    now = int(time.time())
    ttl = STEPUP_PROOF_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    payload = {
        "sub": subject,
        "jti": jti,
        "iat": now,
        "exp": now + ttl,
        "iss": STEPUP_PROOF_ISSUER,
        "purpose": STEPUP_PROOF_PURPOSE,
        "op": op,
    }
    token = _pyjwt.encode(payload, key, algorithm="HS256")
    return token, jti


def verify_stepup_proof(
    token: str,
    *,
    expected_op: Optional[str] = None,
    signing_key_path: Optional[str] = None,
) -> dict:
    """
    Verify a privileged-mutation step-up proof token.  THE single verification
    surface shared by the programmatic gate and the install.sh host-shell shim.

    Fail-closed contract — raises StepUpProofInvalid(reason) on ANY of:
      * empty / malformed token            -> "empty_token" / "malformed"
      * bad HMAC signature (forged)        -> "bad_signature"
      * expired (stale)                    -> "expired"
      * wrong purpose (e.g. onboard token) -> "wrong_purpose"
      * wrong issuer                       -> "wrong_issuer"
      * op mismatch (proof minted for a    -> "op_mismatch"
        different lifecycle op), when
        expected_op is supplied
      * signing key unavailable            -> "signing_key_unavailable"

    Returns the decoded claims dict on success.

    Note on algorithm pinning: algorithms=["HS256"] is explicit so a token with
    ``alg: none`` (the classic JWT bypass) is rejected by PyJWT before any
    claim check runs.
    """
    import jwt as _pyjwt

    if not token or not token.strip():
        raise StepUpProofInvalid("empty_token")

    key = _load_signing_key(signing_key_path)

    try:
        claims = _pyjwt.decode(
            token.strip(),
            key,
            algorithms=["HS256"],
            options={"require": ["sub", "jti", "exp", "iat", "iss", "purpose"]},
        )
    except _pyjwt.ExpiredSignatureError as exc:
        raise StepUpProofInvalid("expired") from exc
    except _pyjwt.InvalidSignatureError as exc:
        raise StepUpProofInvalid("bad_signature") from exc
    except _pyjwt.InvalidTokenError as exc:
        raise StepUpProofInvalid("malformed") from exc

    if claims.get("purpose") != STEPUP_PROOF_PURPOSE:
        raise StepUpProofInvalid("wrong_purpose")
    if claims.get("iss") != STEPUP_PROOF_ISSUER:
        raise StepUpProofInvalid("wrong_issuer")
    if expected_op is not None and claims.get("op") != expected_op:
        raise StepUpProofInvalid("op_mismatch")

    return claims


def assert_privileged_mutation_token(
    token: str,
    *,
    expected_op: str,
    signing_key_path: Optional[str] = None,
    audit_writer: Any = None,
    target: str = "",
) -> dict:
    """
    The PROOF-based privileged-mutation gate — the headless counterpart of
    assert_privileged_mutation (which takes a live Session).

    Used by the install.sh host-shell path (#4 MI-4) and any non-session caller.
    Verifies the proof token end-to-end (signature + freshness + purpose + op),
    emits the uniform PRIVILEGED_MUTATION audit event, and returns the verified
    claims.  Raises StepUpProofInvalid (fail-closed) on any verification failure;
    the caller must NOT proceed with the mutation on the exception.

    The fresh-TOTP property is carried by the token itself: it was minted only
    after a fresh in-session step-up, and it is bounded by STEPUP_PROOF_TTL_SECONDS.
    """
    claims = verify_stepup_proof(
        token, expected_op=expected_op, signing_key_path=signing_key_path
    )
    ctx = PrivilegedMutationContext(
        reason=f"lifecycle.{expected_op}",
        principal=claims.get("sub", "unknown"),
        target=target or expected_op,
    )
    _emit_privileged_mutation_event(ctx, audit_writer)
    return claims


# ---------------------------------------------------------------------------
# Host-shell verifier shim entrypoint.
#
# install.sh calls:  python3 -m yashigani.auth.stepup --verify-proof \
#                       --op add-component --token "<jwt>"
# Exit 0 + prints "OK sub=<operator> jti=<jti>" when the proof verifies.
# Exit 1 + prints "DENY <reason>" (to stderr) otherwise.  Fail-closed: any
# unexpected error is also a non-zero exit.
# ---------------------------------------------------------------------------


def _verify_proof_cli(argv: Optional[list[str]] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="yashigani.auth.stepup",
        description="Verify a privileged-mutation step-up proof token (MI-4).",
    )
    parser.add_argument("--verify-proof", action="store_true", required=True)
    parser.add_argument("--op", required=True, help="Lifecycle op label to bind.")
    parser.add_argument(
        "--token",
        default=None,
        help="Proof token. If omitted, read from YASHIGANI_STEPUP_TOKEN env.",
    )
    parser.add_argument(
        "--signing-key-path",
        default=None,
        help="Override HMAC signing-key path (default caddy_internal_hmac).",
    )
    args = parser.parse_args(argv)

    token = args.token or os.environ.get("YASHIGANI_STEPUP_TOKEN", "")
    try:
        claims = verify_stepup_proof(
            token, expected_op=args.op, signing_key_path=args.signing_key_path
        )
    except StepUpProofInvalid as exc:
        print(f"DENY {exc.reason}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — fail-closed on anything unexpected
        print(f"DENY unexpected_error:{type(exc).__name__}", file=sys.stderr)
        return 1

    print(f"OK sub={claims.get('sub', '')} jti={claims.get('jti', '')}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_verify_proof_cli())
