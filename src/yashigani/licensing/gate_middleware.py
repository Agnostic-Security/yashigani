"""
Licence gate ASGI middleware — third, cross-cutting enforcement layer for
licence-gated capabilities (OIDC/SAML/SCIM).

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §5 (fail-modes) + §11 (accepted residual) — LAURA-V2-001 follow-up,
     2026-07-16 ("replacing require_feature()'s whole body still yields the
     feature").

WHY THIS FILE EXISTS
---------------------
Before this fix, every licence-gated capability had (at most) two layers —
the backoffice route handler (backoffice/routes/sso.py, routes/scim.py) and,
for OIDC/SAML, the provider class (sso/oidc.py, sso/saml.py) — but BOTH
layers called the exact same `enforcer.require_feature()` function. Patching
that one function in that one file (enforcer.py) silently defeated every
call site at once, in every layer, in every file — the "v1 killer" bypass
(LAURA-V2-001).

The fix has two parts, both required:

  1. Each point-of-use file (oidc.py, saml.py, routes/sso.py, routes/scim.py)
     now carries its OWN local `_licence_hard_gate()` — a genuinely separate
     function definition per file (not a shared import) that reads the
     SIGNED hash authority directly: verifier.get_integrity_status() (the
     live, externally-re-derived, BUNDLE_SIG-verified flag) OR
     enforcer.get_enforcer_integrity_status() (enforcer's own independent
     cross-check of verifier.py's bytes — covers the "verifier.py tampered
     alone" case). This means patching enforcer.require_feature() has ZERO
     effect on any of them — none of them call it anymore.

  2. THIS middleware — a FOURTH, wholly independent file, wired at ASGI
     level in app.py (mounted before routing) — re-runs the identical check
     for every request whose path matches a licence-gated prefix, BEFORE the
     route handler (and therefore before the provider) ever executes. This
     is what defeats "patch each individual point-of-use guard" (the redteam
     brief's attack (b)): if an attacker strips the local guard OUT of
     routes/sso.py (a single-file edit confined to that file), THIS
     middleware — untouched, a separate file — still blocks the request at
     the ASGI layer. Symmetrically, if an attacker patches THIS middleware
     file alone, routes/sso.py's and sso/oidc.py's own local guards
     (untouched) still block once the route handler / provider method runs.

All four guards (this middleware + 3 point-of-use files) are themselves
listed in verifier._LIVE_HASH_TARGETS (GATE_MIDDLEWARE_HASH,
OIDC_MODULE_HASH, SAML_MODULE_HASH, SSO_ROUTES_HASH, SCIM_ROUTES_HASH) —
tampering with ANY of them, including this file, changes that file's bytes
and is independently detected by verifier.py's live re-derivation (a file
none of these edits ever touches).

HONEST CEILING (do not overclaim, per design §11 / verifier.py's own honest-
ceiling notes): a "coordinated multi-file edit" that touches ALL of {this
middleware, every point-of-use file, enforcer.py, AND either verifier.py or
_integrity.py's signed constants} simultaneously is not defended against by
source-available Python running without a hardware root of trust — that
residual is architecturally identical to forking and recompiling your own
binary (Apache-2.0 + the release treadmill is the accepted answer to that
class, per design §11) and is explicitly OUT OF SCOPE for this fix. What
THIS design guarantees is that no SINGLE file edit — including specifically
patching enforcer.require_feature()'s body, or patching any ONE of the four
independent point-of-use/middleware guards individually — yields a
licence-gated capability without either a valid licence or the hard-refuse
described in §5 firing.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Path prefix -> feature name. Every request whose path starts with one of
# these prefixes is gated here, independently of whatever the route handler
# and/or provider class do (or fail to do, under tamper).
_GATED_PATH_PREFIXES: tuple[tuple[str, str], ...] = (
    ("/auth/sso/oidc/", "oidc"),
    ("/auth/sso/saml/", "saml"),
    ("/scim/v2/", "scim"),
)


def _licence_hard_gate(feature: str) -> "tuple[bool, str]":
    """
    Independent, externally-derived licence gate — see module docstring.

    Returns (allowed, reason). Never raises: any failure while consulting
    the authority (ImportError, AttributeError, or any other exception —
    e.g. because an attacker's edit to enforcer.py/verifier.py broke their
    import entirely) is treated as an integrity violation and fails closed
    (IMPL-03 discipline, matching enforcer._any_integrity_violated()).

    Deliberately does NOT call enforcer.require_feature() — the whole point
    of this layer is to be unaffected by an edit confined to that one
    function/file.
    """
    try:
        from yashigani.licensing import verifier as _verifier
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: could not import verifier/enforcer for "
            "integrity check — treating as violation and refusing (IMPL-03): %s",
            exc,
        )
        return False, "integrity_module_unavailable"

    try:
        verifier_violated = bool(_verifier.get_integrity_status())
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: verifier.get_integrity_status() raised — "
            "treating as violation and refusing: %s", exc,
        )
        return False, "verifier_integrity_check_failed"

    try:
        enforcer_violated = bool(_enforcer.get_enforcer_integrity_status())
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: enforcer.get_enforcer_integrity_status() "
            "raised — treating as violation and refusing: %s", exc,
        )
        return False, "enforcer_integrity_check_failed"

    if verifier_violated or enforcer_violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: gate middleware refusing feature=%s "
            "(verifier_violated=%s, enforcer_violated=%s) — hard-refuse, not "
            "merely a banner (design §5/§11)",
            feature, verifier_violated, enforcer_violated,
        )
        return False, "build_integrity_violated"

    try:
        lic = _enforcer.get_license()
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: enforcer.get_license() raised — "
            "treating as violation and refusing: %s", exc,
        )
        return False, "license_state_unavailable"

    if not lic.has_feature(feature):
        return False, "feature_not_licensed"

    return True, ""


class LicenseGateMiddleware(BaseHTTPMiddleware):
    """
    ASGI middleware: for any request path matching a gated prefix, hard-
    refuses BEFORE the route is dispatched if either (a) build-integrity has
    been violated (unforgeable — see _licence_hard_gate()) or (b) the active
    licence does not grant the feature. Independent of, and redundant with,
    each point-of-use file's own local `_licence_hard_gate()` — see module
    docstring for why both layers are required.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        feature = None
        for prefix, feat in _GATED_PATH_PREFIXES:
            if path.startswith(prefix):
                feature = feat
                break

        if feature is not None:
            allowed, reason = _licence_hard_gate(feature)
            if not allowed:
                return JSONResponse(
                    status_code=402,
                    content={
                        "error": "LICENSE_FEATURE_GATED",
                        "feature": feature,
                        "reason": reason,
                        "upgrade_url": "https://agnosticsec.com/pricing",
                        "message": f"{feature.upper()} is not available — refused at gate middleware ({reason}).",
                    },
                )

        return await call_next(request)
