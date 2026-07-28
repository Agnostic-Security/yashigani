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
     function definition per file (not a shared import). As of Phase D
     (2026-07-17, LAURA-V2-003 RE-VERIFY hardening — see below), each gate's
     decision is derived SOLELY from that file's own inline full-mesh check
     (every OTHER mesh member's bytes, independently re-derived and compared
     against the SIGNED hash constants in _integrity.py) — none of them
     route their decision through verifier.get_integrity_status()/
     enforcer.get_enforcer_integrity_status() any more. This means patching
     enforcer.require_feature() has ZERO effect on any of them — none of
     them call it anymore — and patching verifier.py+enforcer.py together no
     longer silently defeats every OTHER gate's alarm either (the exact
     Laura RE-VERIFY finding this fix closes).

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

All five guards (this middleware + 4 point-of-use files: oidc.py, saml.py,
routes/sso.py, routes/scim.py) are themselves listed in
verifier._LIVE_HASH_TARGETS (GATE_MIDDLEWARE_HASH, OIDC_MODULE_HASH,
SAML_MODULE_HASH, SSO_ROUTES_HASH, SCIM_ROUTES_HASH) — tampering with ANY of
them, including this file, changes that file's bytes and is independently
detected by verifier.py's live re-derivation (a file none of these edits
ever touches), AND by every other mesh member's own full-mesh check below.

HONEST CEILING (Phase D, 2026-07-17 — updated after Laura's independent
RE-VERIFY of the Phase C ring proved THAT version of this claim wrong; do
NOT overclaim again):

  Phase B's claim was that the only remaining bypass was a 2-file edit of
  verifier.py + enforcer.py. LAURA-V2-003 (2026-07-16) proved that wrong in
  the other direction: because every comparison for every OTHER protected
  file physically lived INSIDE verifier.py, a 2-file edit confined to
  verifier.py+enforcer.py silently suppressed the tamper ALARM for every
  file in the system. Phase C's fix (2026-07-16) connected all 6 mesh files
  (verifier, enforcer, this file, oidc.py, routes/sso.py, routes/scim.py)
  into a RING, each checking its 2 neighbours, and claimed "any 1-5 file
  edit is caught, only a full 6-file edit escapes".

  LAURA'S RE-VERIFY (2026-07-17) DISPROVED THAT CLAIM: she found a live,
  silent 3-file {verifier.py, enforcer.py, gate_middleware.py} edit that
  fully defeated BOTH of SCIM's real enforcement layers (gate_middleware's
  ASGI gate and routes/scim.py's route gate) with ZERO CRITICAL log or
  audit event mentioning "scim" anywhere, and a 4-file {..., routes/sso.py}
  edit that fully defeated all THREE of SAML's real enforcement layers
  (gate_middleware, routes/sso.py, sso/saml.py) with ZERO mention of "saml"
  anywhere. Root cause: a ring only gives each file 2 neighbours; for that
  release's specific random permutation, routes/scim.py's 2 neighbours
  didn't happen to include the touched files, so its OWN ring-check never
  fired — and its FALLBACK (calling verifier.get_integrity_status()/
  enforcer.get_enforcer_integrity_status()) was exactly the pair the
  attacker had already neutered. "Some detector fires somewhere in the
  process" (true — oidc.py/routes.sso DID log CRITICAL for the V+E edit)
  is NOT the same guarantee as "the gate deciding THIS feature is blocked"
  (false — SCIM's and SAML's own gates silently granted). sso/saml.py's
  complete exclusion from the Phase C ring (zero mesh coverage of its own)
  compounded this for the SAML case specifically.

  THE FIX (Phase D, this file, 2026-07-17): verifier.py, enforcer.py, this
  file, sso/oidc.py, sso/saml.py (now a full member for the first time),
  routes/sso.py, and routes/scim.py — ALL SEVEN files — now form a
  COMPLETE graph, not a ring: each independently re-derives the SHA-256 of
  EVERY OTHER mesh member (6 peer-checks per file, not 2 ring-neighbour
  checks) straight off disk, using a distinctly-shaped inline comparison
  per file (not a shared function), and hard-refuses + writes a typed audit
  event the moment a licence-gated feature is invoked while any such
  mismatch is standing. Critically, each gate's decision now comes SOLELY
  from its own inline full-mesh result — the shared verifier/enforcer-getter
  fallback that Laura's 3-/4-file attacks exploited has been REMOVED from
  every point-of-use gate, not merely supplemented. Because every member
  checks every OTHER member, ANY untouched member independently detects ANY
  nonempty subset of tampered members in FULL — there is no "blind
  neighbour" configuration to land in, for any per-release topology, for
  any feature. Confirmed by direct test against every proper subset (see
  src/tests/regression/v4.1.1/test_laura_v2_003_mesh_hardening.py) and by
  reproducing Laura's exact 3-file SCIM and 4-file SAML attacks against a
  real signed build and showing both are now caught (dispatch verification
  run, testing_runs/yashigani/).

  THE HONEST REMAINING CEILING: only a coordinated edit touching ALL 7
  mesh files AT ONCE — replacing each one's gate-function body so neither
  the peer-hash comparison NOR the audit-emit call ever executes —
  removes every detector simultaneously. Even then, the CRITICAL log lines
  already written at each file's own module-load time (before the
  coordinated edit could apply, if the attacker edits a running deployment
  rather than re-building from scratch) and any audit event already written
  by an EARLIER gate invocation are not retroactively erased — but a
  from-scratch tampered build that never runs the real check code at all
  produces no such trail. AND: this raises the coordinated-edit cost from 2
  files to 7, but a determined box owner with local write access to all 7
  files CAN still do it, and can also suppress the audit write itself (the
  audit hash-chain's own tamper-evidence depends on a customer-held signing/
  verification key outside this process — see audit/schema.py). This is
  therefore TAMPER-EVIDENT and HIGH-COST, not tamper-PROOF. Do not claim
  "impossible", "needs the code-leaf private key", or "fork-and-recompile
  equivalent" for this residual — none of those are true. What IS true: (a)
  licence-FORGING (creating a new, differently-tiered licence that verifies)
  remains cryptographically impossible without the master/leaf private keys
  — completely unaffected by any of this; (b) the per-release randomized
  member order means a strip-script written against one release's specific
  file-edit recipe does not carry over to the next, forcing the attacker to
  re-derive the topology every release (raises attacker TIME, not a new
  cryptographic property — and, unlike Phase C, this no longer matters for
  detection COMPLETENESS, only for strip-script reuse cost, since every
  member checks every other member regardless of order); (c) any
  INCOMPLETE (1-6 file) coordinated edit is always caught and audited, for
  every feature, not just "for some functionally-unrelated gate somewhere
  in the process"; (d) contract, trademark, and the release treadmill carry
  the remainder, same as before. Closing the FULL 7-file ceiling needs a
  hardware root of trust or an out-of-process watchdog — OUT OF SCOPE for
  source-available, offline, Apache-2.0 Python.
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
# Mesh FULL-graph check (licence-hardening-v2 Phase D, 2026-07-17 —
# LAURA-V2-003 RE-VERIFY hardening). See verifier.py's module-level comment
# block above _check_mesh_full() for the full rationale. This is
# gate_middleware.py's OWN independently-authored copy — deliberately a
# DIFFERENT code shape (a small stateful class) from verifier.py's for-loop
# and enforcer.py's list-comprehension, so a single AST/regex strip-script
# cannot pattern-match and remove all three at once.
# ---------------------------------------------------------------------------


class _MeshFullChecker:
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
            "SAML": ("SAML_MODULE_HASH", pkg_dir / "sso" / "saml.py"),
            "SSO_ROUTES": ("SSO_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "sso.py"),
            "SCIM_ROUTES": ("SCIM_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "scim.py"),
        }
        self.violated = False

    def _peers(self):
        try:
            member_order = json.loads(_integrity.MESH_TOPOLOGY_JSON)["member_order"]
        except Exception:
            return None
        if not isinstance(member_order, list) or sorted(member_order) != sorted(self._targets):
            return None
        if member_order.count(self._ROLE) != 1:
            return None
        return [role for role in member_order if role != self._ROLE]

    def run(self) -> bool:
        is_dev = os.environ.get("YASHIGANI_ENV") == "dev"
        if _integrity.is_any_hash_placeholder() or _integrity.is_mesh_topology_placeholder():
            if not is_dev:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh full-check "
                    "(gate_middleware.py) — hash or topology constants still "
                    "placeholders in a non-dev environment; hard-refusing"
                )
            return self.violated

        peers = self._peers()
        if peers is None:
            self.violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh full-check "
                "(gate_middleware.py) — MESH_TOPOLOGY_JSON malformed or "
                "missing this file's role; treating as tamper (fail-closed)"
            )
            return self.violated

        for role in peers:
            const_name, path = self._targets[role]
            expected = getattr(_integrity, const_name, "")
            try:
                live = hashlib.sha256(path.read_bytes()).hexdigest()
            except Exception as exc:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh full-check "
                    "(gate_middleware.py) — could not read mesh peer "
                    "role=%s (%s): %s", role, path, exc,
                )
                continue
            if live != expected:
                self.violated = True
                logger.critical(
                    "LICENSE INTEGRITY VIOLATION: mesh full-check "
                    "(gate_middleware.py) — mesh peer role=%s (%s) live "
                    "hash mismatch (expected=%s, actual=%s) — independent "
                    "detection (LAURA-V2-003 Phase D hardening)",
                    role, const_name, expected[:16], live[:16],
                )
        return self.violated


_mesh_checker = _MeshFullChecker()
_mesh_checker.run()


def get_mesh_integrity_status() -> bool:
    """Return True if this file's independent full-mesh check has detected
    a tampered peer (LAURA-V2-003 Phase D hardening)."""
    return _mesh_checker.violated


# ---------------------------------------------------------------------------
# Root-of-trust pin (LAURA-V2-005, 2026-07-17) — this file's OWN copy of the
# _integrity.py root-of-trust pin. See licensing/verifier.py's module-level
# comment block above _check_integrity_root_pin() for the full rationale
# (self-reference solved by hardcoding the expected hash HERE, injected at
# build time before this file's own GATE_MIDDLEWARE_HASH is computed — no
# circularity) and the named residual (covers only the 5 root-of-trust
# fields; the rest of _integrity.py stays covered by BUNDLE_SIG/
# INTEGRITY_HASH). Style: a standalone module-level function that writes
# straight into `_mesh_checker.violated`, deliberately NOT a method on
# _MeshFullChecker (a different code shape from the class-based mesh check
# above, matching this file's own "distinct shape per check" convention).
# ---------------------------------------------------------------------------

_EXPECTED_INTEGRITY_ROOT_HASH: str = "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH"


def _live_integrity_root_hash() -> str:
    canonical = "\n".join([
        f"MASTER_ANCHOR_SET_JSON={_integrity.MASTER_ANCHOR_SET_JSON}",
        f"CODE_LEAF_CERT_JSON={_integrity.CODE_LEAF_CERT_JSON}",
        f"CODE_LEAF_CERT_SIG={_integrity.CODE_LEAF_CERT_SIG}",
        f"KILL_LIST_JSON={_integrity.KILL_LIST_JSON}",
        f"CLIENT_DOMAIN_REGISTRY_JSON={_integrity.CLIENT_DOMAIN_REGISTRY_JSON}",
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_integrity_root_pin() -> None:
    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH" in _EXPECTED_INTEGRITY_ROOT_HASH:
        if not is_dev:
            _mesh_checker.violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: root-of-trust pin "
                "(gate_middleware.py) — _EXPECTED_INTEGRITY_ROOT_HASH is "
                "still a placeholder in a non-dev environment; hard-refusing"
            )
        return

    live = _live_integrity_root_hash()
    if live != _EXPECTED_INTEGRITY_ROOT_HASH:
        _mesh_checker.violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: root-of-trust pin "
            "(gate_middleware.py) — _integrity.py's root-of-trust fields do "
            "not match this file's hardcoded pin (expected=%s, actual=%s) — "
            "_integrity.py has been modified since this build was signed "
            "(LAURA-V2-005)",
            _EXPECTED_INTEGRITY_ROOT_HASH[:16], live[:16],
        )


_check_integrity_root_pin()


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
    e.g. because an attacker's edit to enforcer.py broke its import
    entirely) is treated as an integrity violation and fails closed
    (IMPL-03 discipline, matching enforcer._any_integrity_violated()).

    Deliberately does NOT call enforcer.require_feature() — the whole point
    of this layer is to be unaffected by an edit confined to that one
    function/file.

    Phase D (2026-07-17, LAURA-V2-003 RE-VERIFY): the integrity decision
    below comes SOLELY from `_mesh_checker.violated` — this file's OWN
    inline full-mesh check of every OTHER mesh member's bytes. Phase C's
    fallback (calling verifier.get_integrity_status()/enforcer.get_enforcer_
    integrity_status() when the ring-check itself hadn't fired) has been
    REMOVED, not merely supplemented: that fallback was the single point of
    failure Laura's 3-file SCIM / 4-file SAML re-verify attacks exploited —
    it was exactly the {verifier.py, enforcer.py} pair the attacker had
    already neutered, called by a gate whose own (then 2-neighbour) check
    hadn't happened to cover the touched files. Under the complete graph,
    `_mesh_checker.violated` already reflects ALL 6 other members' bytes,
    so no fallback is needed — and none is consulted. `enforcer.get_license()`
    below is still called (it is a DATA read, not an integrity decision):
    it is safe precisely because enforcer.py's own bytes are one of the 6
    peers `_mesh_checker` already verified above.
    """
    if _mesh_checker.violated:
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: gate middleware hard-refusing "
            "feature=%s — this file's own full-mesh check detected a "
            "tampered peer (LAURA-V2-003 Phase D hardening, no fallback to "
            "verifier.py/enforcer.py getters)",
            feature,
        )
        _emit_mesh_tamper_event("mesh_full_check_mismatch", "clean", "tampered")
        return False, "mesh_full_integrity_violated"

    try:
        from yashigani.licensing import enforcer as _enforcer
    except Exception as exc:
        logger.critical(
            "Licence gate middleware: could not import enforcer for license "
            "state — treating as violation and refusing (IMPL-03): %s",
            exc,
        )
        _emit_mesh_tamper_event("integrity_module_unavailable", "n/a", "import_failed")
        return False, "integrity_module_unavailable"

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
