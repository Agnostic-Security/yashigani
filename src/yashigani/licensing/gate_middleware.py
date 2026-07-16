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

HONEST CEILING (Phase C, 2026-07-16 — updated after red-team LAURA-V2-003
proved the PREVIOUS version of this claim wrong; do NOT overclaim again):

  The PREVIOUS claim here (Phase B) was that the only remaining bypass was a
  2-file edit of verifier.py + enforcer.py, "materially cheaper [than
  fork-and-recompile] but not equivalent to it". LAURA-V2-003 (2026-07-16)
  proved that framing was ALSO wrong in the OTHER direction: because every
  comparison for every OTHER protected file (OIDC_MODULE_HASH,
  SSO_ROUTES_HASH, GATE_MIDDLEWARE_HASH, etc.) physically lived INSIDE
  verifier.py, a 2-file edit confined to verifier.py+enforcer.py didn't just
  hide their own tamper — it silently suppressed the tamper ALARM for every
  file in the system, with zero CRITICAL logs and zero audit events. That
  was worse than a "cheap but honest" residual; it was a silent, total
  bypass of the detection layer.

  THE FIX (this file, 2026-07-16): verifier.py, enforcer.py, this file, and
  the OIDC/SCIM/SSO-routes point-of-use files now form a genuine mesh — each
  independently re-derives the SHA-256 of its two RING-NEIGHBOURS (per this
  release's topology — see MESH_TOPOLOGY_JSON / licensing/chain/
  mesh_topology.py) straight off disk, using a distinctly-shaped inline
  comparison per file (not a shared function), and hard-refuses + writes a
  typed audit event the moment a licence-gated feature is invoked while any
  such mismatch is standing. Because the 6 files form ONE connected cycle
  (not 3 isolated pairs), tampering ANY 1 to 5 of them — including the
  verifier.py+enforcer.py pair Laura used — leaves at least one untouched
  file whose ring-check independently catches it (basic graph connectivity:
  a proper nonempty subset of a connected cycle always has an edge crossing
  to its complement). Confirmed by direct test against every such subset
  (see src/tests/regression/v4.1.1/test_laura_v2_003_mesh_hardening.py and
  the real-signed-build edit-matrix proof in the dispatch verification run).

  THE HONEST REMAINING CEILING: only a coordinated edit touching ALL 6
  mesh files AT ONCE — replacing each one's gate-function body so neither
  the neighbour-hash comparison NOR the audit-emit call ever executes —
  removes every detector simultaneously. Even then, the CRITICAL log lines
  already written at each file's own module-load time (before the
  coordinated edit could apply, if the attacker edits a running deployment
  rather than re-building from scratch) and any audit event already written
  by an EARLIER gate invocation are not retroactively erased — but a
  from-scratch tampered build that never runs the real check code at all
  produces no such trail. AND: this raises the coordinated-edit cost from 2
  files to 6, but a determined box owner with local write access to all 6
  files CAN still do it, and can also suppress the audit write itself (the
  audit hash-chain's own tamper-evidence depends on a customer-held signing/
  verification key outside this process — see audit/schema.py). This is
  therefore TAMPER-EVIDENT and HIGH-COST, not tamper-PROOF. Do not claim
  "impossible", "needs the code-leaf private key", or "fork-and-recompile
  equivalent" for this residual — none of those are true. What IS true: (a)
  licence-FORGING (creating a new, differently-tiered licence that verifies)
  remains cryptographically impossible without the master/leaf private keys
  — completely unaffected by any of this; (b) the per-release randomized
  ring topology means a strip-script written against one release's specific
  file-edit recipe does not carry over to the next, forcing the attacker to
  re-derive the topology every release (raises attacker TIME, not a new
  cryptographic property); (c) any INCOMPLETE (1-5 file) coordinated edit is
  always caught and audited; (d) contract, trademark, and the release
  treadmill carry the remainder, same as before. Closing the FULL 6-file
  ceiling needs a hardware root of trust or an out-of-process watchdog —
  OUT OF SCOPE for source-available, offline, Apache-2.0 Python.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp

from yashigani.licensing import _integrity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mesh ring-check (licence-hardening-v2 Phase C, 2026-07-16 — LAURA-V2-003
# hardening). See verifier.py's module-level comment block above
# _check_mesh_ring_neighbours() for the full rationale. This is
# gate_middleware.py's OWN independently-authored copy — deliberately a
# DIFFERENT code shape (a small stateful class) from verifier.py's for-loop
# and enforcer.py's list-comprehension, so a single AST/regex strip-script
# cannot pattern-match and remove all three at once.
# ---------------------------------------------------------------------------


class _MeshRingChecker:
    """Style: stateful class, instantiated once at module load."""

    _ROLE = "GATE_MIDDLEWARE"

    def __init__(self) -> None:
        licensing_dir = Path(__file__).parent
        pkg_dir = licensing_dir.parent
        self._targets: dict = {
            "VERIFIER": ("VERIFIER_HASH", licensing_dir / "verifier.py"),
            "ENFORCER": ("ENFORCER_HASH", licensing_dir / "enforcer.py"),
            "GATE_MIDDLEWARE": ("GATE_MIDDLEWARE_HASH", licensing_dir / "gate_middleware.py"),
            "OIDC": ("OIDC_MODULE_HASH", pkg_dir / "sso" / "oidc.py"),
            "SSO_ROUTES": ("SSO_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "sso.py"),
            "SCIM_ROUTES": ("SCIM_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "scim.py"),
        }
        self.violated = False

    def _neighbours(self):
        try:
            ring_order = json.loads(_integrity.MESH_TOPOLOGY_JSON)["ring_order"]
        except Exception:
            return None
        if not isinstance(ring_order, list) or sorted(ring_order) != sorted(self._targets):
            return None
        if ring_order.count(self._ROLE) != 1:
            return None
        i = ring_order.index(self._ROLE)
        n = len(ring_order)
        return ring_order[i - 1], ring_order[(i + 1) % n]

    def run(self) -> bool:
        is_dev = os.environ.get("YASHIGANI_ENV") == "dev"
        if _integrity.is_any_hash_placeholder() or _integrity.is_mesh_topology_placeholder():
            if not is_dev:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh ring-check "
                    "(gate_middleware.py) — hash or topology constants still "
                    "placeholders in a non-dev environment; hard-refusing"
                )
            return self.violated

        neighbours = self._neighbours()
        if neighbours is None:
            self.violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh ring-check "
                "(gate_middleware.py) — MESH_TOPOLOGY_JSON malformed or "
                "missing this file's role; treating as tamper (fail-closed)"
            )
            return self.violated

        for role in neighbours:
            const_name, path = self._targets[role]
            expected = getattr(_integrity, const_name, "")
            try:
                live = hashlib.sha256(path.read_bytes()).hexdigest()
            except Exception as exc:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh ring-check "
                    "(gate_middleware.py) — could not read ring-neighbour "
                    "role=%s (%s): %s", role, path, exc,
                )
                continue
            if live != expected:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh ring-check "
                    "(gate_middleware.py) — ring-neighbour role=%s (%s) live "
                    "hash mismatch (expected=%s, actual=%s) — independent "
                    "detection (LAURA-V2-003 hardening)",
                    role, const_name, expected[:16], live[:16],
                )
        return self.violated


_mesh_checker = _MeshRingChecker()
_mesh_checker.run()


def get_mesh_integrity_status() -> bool:
    """Return True if this file's independent ring-check has detected a
    ring-neighbour tamper (LAURA-V2-003 hardening)."""
    return _mesh_checker.violated


def _emit_mesh_tamper_event(check_type: str, expected_hash: str, actual_hash: str) -> None:
    """
    Emit a tamper-evidence audit event AT THE POINT a licence-gated feature
    is invoked while tamper has been detected — "any INCOMPLETE tamper is
    logged" as a genuine entry in the tamper-evident audit hash-chain, not
    just a log line. Own inline copy — not a shared import — mirrors
    verifier.py's/enforcer.py's existing _emit_licence_integrity_violation_
    event(), duplicated per LAURA-V2-003 "no chokepoint" discipline. Wrapped
    in a broad except so a missing/uninitialised audit subsystem never
    blocks the hard-refuse itself.
    """
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        writer.write(LicenceIntegrityViolationEvent(
            module="licensing.gate_middleware",
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        ))
    except Exception:
        pass

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
    if _mesh_checker.violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: gate middleware hard-refusing "
            "feature=%s — this file's own mesh ring-check detected a "
            "tampered neighbour (LAURA-V2-003 hardening, independent of "
            "verifier.py/enforcer.py)",
            feature,
        )
        _emit_mesh_tamper_event("mesh_ring_neighbour_mismatch", "clean", "tampered")
        return False, "mesh_ring_integrity_violated"

    try:
        from yashigani.licensing import verifier as _verifier
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: could not import verifier/enforcer for "
            "integrity check — treating as violation and refusing (IMPL-03): %s",
            exc,
        )
        _emit_mesh_tamper_event("integrity_module_unavailable", "n/a", "import_failed")
        return False, "integrity_module_unavailable"

    try:
        verifier_violated = bool(_verifier.get_integrity_status())
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: verifier.get_integrity_status() raised — "
            "treating as violation and refusing: %s", exc,
        )
        _emit_mesh_tamper_event("verifier_integrity_check_failed", "n/a", "raised")
        return False, "verifier_integrity_check_failed"

    try:
        enforcer_violated = bool(_enforcer.get_enforcer_integrity_status())
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: enforcer.get_enforcer_integrity_status() "
            "raised — treating as violation and refusing: %s", exc,
        )
        _emit_mesh_tamper_event("enforcer_integrity_check_failed", "n/a", "raised")
        return False, "enforcer_integrity_check_failed"

    if verifier_violated or enforcer_violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: gate middleware refusing feature=%s "
            "(verifier_violated=%s, enforcer_violated=%s) — hard-refuse, not "
            "merely a banner (design §5/§11)",
            feature, verifier_violated, enforcer_violated,
        )
        _emit_mesh_tamper_event("build_integrity_violated", "clean", "tampered")
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
