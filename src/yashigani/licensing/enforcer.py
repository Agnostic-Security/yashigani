"""
Feature gate enforcement.

The active license is loaded once at startup and cached in module state.
All gate functions are synchronous — called from FastAPI route handlers.
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseState, LicenseTier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level license state
# ---------------------------------------------------------------------------

_license: LicenseState = COMMUNITY_LICENSE

# Module-level integrity state (T1)
_enforcer_integrity_violated = False


def _emit_licence_integrity_violation_event(
    module: str,
    check_type: str,
    expected_hash: str,
    actual_hash: str,
    classification: str = "unknown",
) -> None:
    """Emit a typed LicenceIntegrityViolationEvent (defence-in-depth — never raises)."""
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        event = LicenceIntegrityViolationEvent(
            module=module,
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        )
        event._internal_classification = classification
        writer.write(event)
    except Exception:
        pass


def _check_enforcer_integrity() -> None:
    """
    T1: Self-check enforcer.py SHA-256 against _integrity.ENFORCER_HASH.
    Also cross-checks verifier.py against _integrity.VERIFIER_HASH.
    Sets _enforcer_integrity_violated = True on any mismatch.
    Called at module load (DG-04: consuming module, not _integrity.py).
    """
    global _enforcer_integrity_violated
    from yashigani.licensing import _integrity

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    # Self-check
    if _integrity.is_enforcer_hash_placeholder():
        if not is_dev:
            _enforcer_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: ENFORCER_HASH is still a placeholder "
                "in a non-dev environment; forcing COMMUNITY tier (T1)"
            )
        return

    try:
        digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except Exception as exc:
        logger.warning("License integrity: could not read enforcer.py for hash check: %s", exc)
        return

    if digest != _integrity.ENFORCER_HASH:
        _enforcer_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: enforcer.py has been tampered with "
            "(expected=%s, actual=%s); forcing COMMUNITY tier (T1)",
            _integrity.ENFORCER_HASH[:16],
            digest[:16],
        )
        _emit_licence_integrity_violation_event(
            module="enforcer",
            check_type="self_hash",
            expected_hash=_integrity.ENFORCER_HASH,
            actual_hash=digest,
        )

    # Cross-check verifier.py
    if _integrity.is_verifier_hash_placeholder():
        return  # already handled by verifier's own check

    try:
        verifier_path = Path(__file__).parent / "verifier.py"
        v_digest = hashlib.sha256(verifier_path.read_bytes()).hexdigest()
    except Exception as exc:
        logger.warning("License integrity: could not read verifier.py for cross-check: %s", exc)
        return

    if v_digest != _integrity.VERIFIER_HASH:
        _enforcer_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: verifier.py cross-check failed from enforcer "
            "(expected=%s, actual=%s); forcing COMMUNITY tier (T1)",
            _integrity.VERIFIER_HASH[:16],
            v_digest[:16],
        )
        _emit_licence_integrity_violation_event(
            module="enforcer",
            check_type="cross_hash",
            expected_hash=_integrity.VERIFIER_HASH,
            actual_hash=v_digest,
        )


def get_enforcer_integrity_status() -> bool:
    """Return True if the enforcer integrity has been violated.

    LAURA-V2-003 Phase D hardening: also reflects this file's own full-mesh
    check (_check_enforcer_mesh_full(), a genuinely separate code path from
    _check_enforcer_integrity() above). This getter remains an accessor to
    THIS file's own state (used by _any_integrity_violated() below, the
    unrelated T1-T4 aggregation) — as of Phase D no OTHER mesh file's
    point-of-use gate calls this getter as part of its OWN tamper decision
    any more (see gate_middleware.py's module docstring: that shared-getter
    fallback was itself the single point of failure Laura's 3-/4-file
    bypasses exploited)."""
    return _enforcer_integrity_violated or _enforcer_mesh_integrity_violated


# ---------------------------------------------------------------------------
# Mesh FULL-graph check (licence-hardening-v2 Phase D, 2026-07-17 —
# LAURA-V2-003 RE-VERIFY hardening). See verifier.py's module-level comment
# block above _check_mesh_full() for the full rationale (complete graph,
# randomized per-release member order, why a ring was insufficient). This is
# enforcer.py's OWN independently-authored copy — deliberately a DIFFERENT
# code shape (list-comprehension + collected-mismatch list) from
# verifier.py's plain for-loop, so a single strip-script pattern cannot
# match and remove both at once.
# ---------------------------------------------------------------------------

_enforcer_mesh_integrity_violated = False

_MY_MESH_ROLE = "ENFORCER"


def _mesh_role_targets() -> dict:
    """role -> (signed hash constant name, path). Built fresh each call
    (cheap — 7 entries) rather than cached at import time, a deliberate
    stylistic difference from verifier.py's module-level dict."""
    licensing_dir = Path(__file__).parent
    pkg_dir = licensing_dir.parent
    return {
        "VERIFIER": ("VERIFIER_HASH", licensing_dir / "verifier.py"),
        "ENFORCER": ("ENFORCER_HASH", licensing_dir / "enforcer.py"),
        "GATE_MIDDLEWARE": ("GATE_MIDDLEWARE_HASH", licensing_dir / "gate_middleware.py"),
        "OIDC": ("OIDC_MODULE_HASH", pkg_dir / "sso" / "oidc.py"),
        "SAML": ("SAML_MODULE_HASH", pkg_dir / "sso" / "saml.py"),
        "SSO_ROUTES": ("SSO_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "sso.py"),
        "SCIM_ROUTES": ("SCIM_ROUTES_HASH", pkg_dir / "backoffice" / "routes" / "scim.py"),
    }


def _live_hash_or_none(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def _check_enforcer_mesh_full() -> None:
    """
    Style: resolve peers, build a list of mismatch tuples via
    list-comprehension, then act on the collected list — deliberately not a
    for-loop (verifier.py's shape) or a while-loop (sso/oidc.py's shape).
    """
    global _enforcer_mesh_integrity_violated
    from yashigani.licensing import _integrity
    import json as _json

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if _integrity.is_any_hash_placeholder() or _integrity.is_mesh_topology_placeholder():
        if not is_dev:
            _enforcer_mesh_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh full-check (enforcer.py) — "
                "hash or topology constants still placeholders in a non-dev "
                "environment; forcing COMMUNITY tier"
            )
        return

    targets = _mesh_role_targets()
    try:
        member_order = _json.loads(_integrity.MESH_TOPOLOGY_JSON)["member_order"]
        if not isinstance(member_order, list) or sorted(member_order) != sorted(targets.keys()):
            raise ValueError("member_order is not a permutation of the 7 mesh roles")
        if member_order.count(_MY_MESH_ROLE) != 1:
            raise ValueError("member_order missing this file's role")
        peer_roles = [role for role in member_order if role != _MY_MESH_ROLE]
    except Exception as exc:
        _enforcer_mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: mesh full-check (enforcer.py) — "
            "MESH_TOPOLOGY_JSON malformed or missing this file's role: %s — "
            "treating as tamper (fail-closed)", exc,
        )
        return

    checks = [
        (role, targets[role][0], getattr(_integrity, targets[role][0], ""), _live_hash_or_none(targets[role][1]))
        for role in peer_roles
    ]
    mismatches = [c for c in checks if c[3] is None or c[3] != c[2]]

    if mismatches:
        _enforcer_mesh_integrity_violated = True
        for role, const_name, expected, live in mismatches:
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: mesh full-check (enforcer.py) — "
                "mesh peer role=%s (%s) %s (expected=%s, actual=%s) — "
                "independent detection (LAURA-V2-003 Phase D hardening)",
                role, const_name,
                "could not be read" if live is None else "live hash mismatch",
                (expected or "")[:16], (live or "<unreadable>")[:16],
            )


def get_enforcer_mesh_integrity_status() -> bool:
    """Return True if this file's independent full-mesh check has detected
    a tampered peer (LAURA-V2-003 Phase D hardening)."""
    return _enforcer_mesh_integrity_violated


# ---------------------------------------------------------------------------
# Root-of-trust pin (LAURA-V2-005, 2026-07-17) — this file's OWN copy of the
# _integrity.py root-of-trust pin. See licensing/verifier.py's module-level
# comment block above _check_integrity_root_pin() for the full rationale
# (self-reference solved by hardcoding the expected hash HERE, injected at
# build time before this file's own ENFORCER_HASH is computed — no
# circularity) and the named residual (covers only the 5 root-of-trust
# fields; the rest of _integrity.py stays covered by BUNDLE_SIG/
# INTEGRITY_HASH). Deliberately a DIFFERENT code shape (early-return guard
# clauses) from verifier.py's sequential-checks shape, matching this file's
# existing "distinct shape per mesh member" convention.
# ---------------------------------------------------------------------------

_EXPECTED_INTEGRITY_ROOT_HASH: str = "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH"


def _live_integrity_root_hash() -> str:
    from yashigani.licensing import _integrity
    canonical = "\n".join([
        f"MASTER_ANCHOR_SET_JSON={_integrity.MASTER_ANCHOR_SET_JSON}",
        f"CODE_LEAF_CERT_JSON={_integrity.CODE_LEAF_CERT_JSON}",
        f"CODE_LEAF_CERT_SIG={_integrity.CODE_LEAF_CERT_SIG}",
        f"KILL_LIST_JSON={_integrity.KILL_LIST_JSON}",
        f"CLIENT_DOMAIN_REGISTRY_JSON={_integrity.CLIENT_DOMAIN_REGISTRY_JSON}",
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _check_enforcer_root_pin() -> None:
    """Style: early-return guard clauses (placeholder guard, then the
    comparison) — deliberately not verifier.py's sequential-checks shape."""
    global _enforcer_mesh_integrity_violated
    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if "PLACEHOLDER_YASHIGANI_INTEGRITY_ROOT_HASH" not in _EXPECTED_INTEGRITY_ROOT_HASH:
        live = _live_integrity_root_hash()
        if live == _EXPECTED_INTEGRITY_ROOT_HASH:
            return
        _enforcer_mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: root-of-trust pin (enforcer.py) — "
            "_integrity.py's root-of-trust fields do not match this file's "
            "hardcoded pin (expected=%s, actual=%s) — _integrity.py has been "
            "modified since this build was signed (LAURA-V2-005)",
            _EXPECTED_INTEGRITY_ROOT_HASH[:16], live[:16],
        )
        return

    if not is_dev:
        _enforcer_mesh_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: root-of-trust pin (enforcer.py) — "
            "_EXPECTED_INTEGRITY_ROOT_HASH is still a placeholder in a "
            "non-dev environment; hard-refusing"
        )


def _emit_set_license_audit(lic: LicenseState) -> None:
    """Emit a LicenceStateSetEvent on every set_license() call (T8)."""
    try:
        import inspect
        from yashigani.audit.schema import LicenceStateSetEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        frame = inspect.stack()[2] if len(inspect.stack()) > 2 else None
        caller = frame.filename.split("/")[-1].replace(".py", "") if frame else "unknown"
        event = LicenceStateSetEvent(
            tier=lic.tier.value,
            org_domain=lic.org_domain,
            license_id=lic.license_id or "",
            caller_module=caller,
        )
        writer.write(event)
    except Exception:
        pass


def set_license(lic: LicenseState) -> None:
    """Set the active license. Called once at startup. Emits a LicenceStateSetEvent (T8)."""
    global _license
    _license = lic
    _emit_set_license_audit(lic)


def _any_integrity_violated() -> bool:
    """
    T5 / design §5: check integrity flags across the FULL trust surface —
    verifier (which also covers the chain-based build-integrity check §4a
    and, as of LAURA-V2-005, verifier's own root-of-trust pin), enforcer
    (its own T1 self/cross-hash AND, as of LAURA-V2-006 below, its Phase D
    full-mesh + root-pin flags via get_enforcer_integrity_status()), loader,
    agents_registry, identity_registry, and — LAURA-V2-006 (2026-07-17) —
    the five OTHER Phase D mesh members that were previously never
    consulted here: gate_middleware.py, sso/oidc.py, sso/saml.py,
    backoffice/routes/sso.py, backoffice/routes/scim.py. Returns True if
    ANY flag is set. Lazy imports to avoid circular dependencies.

    LAURA-V2-006 fix: prior to this fix, this function only read the raw
    `_enforcer_integrity_violated` global (T1 self-hash only) and never
    consulted `get_enforcer_integrity_status()` (which ORs in THIS file's
    own Phase D mesh + root-pin flags), and never consulted the other 5
    mesh members' independently-computed `get_mesh_integrity_status()` at
    all. Consequence: a 2-file {verifier.py, _integrity.py} root-swap that
    left all 7 mesh files' OWN hash-comparison code untouched still forged
    the core get_license()/require_feature()/check_*_limit() surface, even
    though 5 of those 6 untouched mesh files correctly, independently
    detected and CRITICAL-logged the tamper via their own point-of-use
    gates. See Agnostic Security/Operations/Compliance/yashigani/v4.1.1/
    laura-pentest/findings/LAURA-V2-006_core_grant_bypasses_phase_d_mesh_2file.md.

    DISTRIBUTED, not a new chokepoint: each of the 5 new checks below reads
    that OTHER file's OWN already-computed module-level flag (set by that
    file's own _check_mesh_full()/_check_integrity_root_pin(), which
    independently re-derives every OTHER member's on-disk bytes against the
    SIGNED hash constants in _integrity.py) — this function does not
    recompute anything itself, and none of those 5 files' own point-of-use
    gates (oidc.py's/saml.py's/routes/sso.py's/routes/scim.py's own
    `_licence_hard_gate()`) are changed to depend on THIS function (they
    deliberately still don't call back into enforcer.get_license() for
    their integrity DECISION — only for the license STATE read, same as
    before Phase D). Patching enforcer.py alone (e.g. to make this whole
    function return False) does not touch what the other 5 files computed
    about their OWN full-mesh checks — importing and reading their getters
    from a genuine, unpatched enforcer.py still surfaces True. Only a
    coordinated edit of ALL 7 mesh files removes every detector — the same
    honest ceiling already documented in gate_middleware.py's module
    docstring.

    Shared by get_license() (fails the active license to COMMUNITY) and
    is_license_tampered() (the standalone tamper-banner signal, §5:
    "Community + persistent user-facing banner ... to ALL users, NO user
    deletion") — kept as ONE function so the two call sites can never drift
    on what counts as tampered.
    """
    # Verifier integrity (lazy import — circular-safe). This also reflects
    # the chain-based build-integrity check (§4a) — verifier._integrity_violated
    # is set by BOTH _check_self_integrity() and _check_build_integrity_chain() —
    # and verifier's own Phase D mesh-check + LAURA-V2-005 root-pin (both ORed
    # into get_integrity_status() already).
    try:
        from yashigani.licensing.verifier import get_integrity_status as _v_status
        if _v_status():
            return True
    except Exception:
        pass  # verifier unavailable — conservative: don't block

    # LAURA-V2-006: read via get_enforcer_integrity_status(), not the raw
    # T1-only global — this ORs in THIS file's own Phase D full-mesh check
    # (_check_enforcer_mesh_full()) and LAURA-V2-005 root-pin
    # (_check_enforcer_root_pin()) results, both of which were computed at
    # module load but, before this fix, never actually consulted here.
    # Wrapped the same way as the verifier check immediately above (swallow
    # and continue, don't block) — this getter is a trivial OR of two
    # already-computed module-level booleans with no I/O, so a raised
    # exception here can only mean the getter's own body was replaced by an
    # attacker (test_laura_v2_001_pou_hardening.py's
    # TestSharedGetterFallbackRemoved proves this exact resilience property
    # for the POU gates' identical fallback license-state read) — the same
    # already-documented "whole function body replaced" honest ceiling
    # require_feature() describes, not a new gap: that scenario is still
    # tamper-EVIDENT via every OTHER untouched mesh member's own full-mesh
    # check (which independently re-derives enforcer.py's live bytes),
    # exactly as before this fix.
    try:
        if get_enforcer_integrity_status():
            return True
    except Exception:
        pass  # conservative: don't block — see comment above

    # LAURA-V2-006: the five OTHER Phase D mesh members — each read is that
    # file's OWN independently-computed get_mesh_integrity_status() (set by
    # that file's own full-mesh re-derivation of every OTHER member's bytes
    # against the SIGNED hash constants in _integrity.py, ORing in that
    # file's own LAURA-V2-005 root-pin result too). Import failure is
    # itself treated as a violation (IMPL-03 discipline, matching the
    # agents_registry/identity_registry checks below) — an attacker who
    # breaks the import while having tampered the target module would
    # otherwise silently bypass this check.
    import importlib

    for _mesh_module_name, _mesh_member_label in (
        ("yashigani.licensing.gate_middleware", "gate_middleware"),
        ("yashigani.sso.oidc", "sso.oidc"),
        ("yashigani.sso.saml", "sso.saml"),
        ("yashigani.backoffice.routes.sso", "backoffice.routes.sso"),
        ("yashigani.backoffice.routes.scim", "backoffice.routes.scim"),
    ):
        try:
            _mesh_module = importlib.import_module(_mesh_module_name)
            if _mesh_module.get_mesh_integrity_status():
                return True
        except Exception as _exc_mesh:
            logger.critical(
                "License gate: failed to import/consult %s's mesh integrity "
                "check — treating as integrity violation and restraining to "
                "Community (IMPL-03, LAURA-V2-006): %s",
                _mesh_member_label, _exc_mesh,
            )
            return True

    try:
        from yashigani.licensing.loader import get_loader_integrity_status as _l_status
        if _l_status():
            return True
    except Exception:
        pass

    try:
        from yashigani.agents.registry import get_agents_registry_integrity_status as _a_status
        if _a_status():
            return True
    except Exception as _exc_agents:
        # IMPL-03: import failure of an integrity module is treated as a
        # violation — an attacker who can cause the import to fail while
        # having patched agents/registry.py would otherwise bypass this check.
        # Log critical and fail to Community rather than silently pass.
        logger.critical(
            "License gate: failed to import agents.registry integrity check — "
            "treating as integrity violation and restraining to Community (IMPL-03): %s",
            _exc_agents,
        )
        return True

    try:
        from yashigani.identity.registry import get_identity_registry_integrity_status as _id_status
        if _id_status():
            return True
    except Exception as _exc_identity:
        # IMPL-03: same treatment as agents.registry — import failure → Community.
        logger.critical(
            "License gate: failed to import identity.registry integrity check — "
            "treating as integrity violation and restraining to Community (IMPL-03): %s",
            _exc_identity,
        )
        return True

    return False


def is_license_tampered() -> bool:
    """
    Design §5: standalone signal for the persistent "Yashigani license
    tampered" banner — distinct from get_license() returning COMMUNITY_LICENSE,
    which is ALSO the (indistinguishable) return value for "no license
    configured at all". A caller that needs to show the tamper banner (vs.
    silently running Community because no key was ever added) must call
    this, not infer tamper from get_license().tier == COMMUNITY.

    Never raises — any integrity-check import failure is itself treated as
    a violation by _any_integrity_violated() (IMPL-03), so this function is
    safe to call from a request-handling path without its own try/except.
    """
    return _any_integrity_violated()


def get_license() -> LicenseState:
    """
    Return the currently active license.

    T5: Checks ALL five integrity flags (verifier, enforcer, loader,
    agents_registry, identity_registry). If ANY flag is True → returns
    COMMUNITY_LICENSE.
    """
    if _any_integrity_violated():
        return COMMUNITY_LICENSE
    return _license


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LicenseFeatureGated(Exception):
    def __init__(self, feature: str, tier: LicenseTier) -> None:
        self.feature = feature
        self.tier = tier
        super().__init__(f"Feature '{feature}' is not available on {tier.value} tier")


class LicenseLimitExceeded(Exception):
    def __init__(self, limit_name: str, current: int, max_val: int) -> None:
        self.limit_name = limit_name
        self.current = current
        self.max_val = max_val
        super().__init__(
            f"License limit exceeded: {limit_name} ({current}/{max_val})"
        )


# ---------------------------------------------------------------------------
# Features that are always available regardless of tier (ENT-001, 2026-06-14)
# ---------------------------------------------------------------------------
# PII detection (LOG / REDACT / BLOCK) is available on every tier including
# Community/free.  This aligns with README §8 Feature Matrix (only OIDC/SAML/SCIM
# are tier-gated) and the product narrative "PII filtering runs on all traffic,
# by default".  The LicenseFeature enum values are kept for back-compat with
# license payloads issued under v2.2 that carry pii_log/pii_redact in their
# features claim — but those claims are never *required* at gate time.

_ALWAYS_AVAILABLE_FEATURES: frozenset[str] = frozenset({"pii_log", "pii_redact"})


# ---------------------------------------------------------------------------
# Gate functions
# ---------------------------------------------------------------------------

def require_feature(feature: str) -> None:
    """Raise LicenseFeatureGated if feature not in active license.

    Features listed in _ALWAYS_AVAILABLE_FEATURES are unconditionally permitted
    regardless of tier or what the license payload carries.

    LAURA-V2-001 fix (2026-07-15): this now reads get_license() — which
    fails closed to COMMUNITY_LICENSE when ANY of the five integrity flags
    (verifier/enforcer/loader/agents_registry/identity_registry) is set —
    instead of the raw module-global `_license`. Previously this function
    consulted `_license` directly, completely bypassing the tamper-detection
    state that get_license() already aggregated: even when a self-check
    correctly fired (e.g. loader.py or verifier.py was tampered, with
    enforcer.py itself untouched), this gate ignored it and kept granting
    whatever tier `_license` happened to hold. Routing through get_license()
    closes that class of bypass for every file OTHER than this one.

    HONEST CEILING (do not overclaim — state this plainly, per design §11):
    if an attacker with local write access to this exact file replaces this
    entire function's body (not merely adds a bypass branch), no code living
    inside the function — including this integrity check — can prevent the
    resulting grant. That is an unavoidable property of any enforcement
    point implemented in readable, locally-writable Python source; it is not
    unique to this design and is not solvable without a hardware root of
    trust or a compiled/obfuscated runtime, neither of which exists here
    (Apache-2.0, offline, source-available by design).
    What THIS fix DOES guarantee, even under that worst case: the resulting
    tamper is never silent. verifier._check_build_integrity_chain() (a
    SEPARATE file, external to this one, re-derived live from disk — see
    verifier.py's module docstring) independently detects that enforcer.py's
    bytes no longer match ENFORCER_HASH and sets verifier._integrity_violated
    = True, which get_license()/is_license_tampered() correctly surface
    (CRITICAL log + typed audit event + persistent tamper banner) regardless
    of what this function's body has been replaced with. This raises the
    bypass from "silent, zero-evidence" (worse than the design's own
    accepted residual) up to "a knowing, unambiguous act with a visible
    diff, always alarmed, always audited" — the accepted §11 residual — not
    further than that, and this docstring says so rather than implying more.
    """
    if feature in _ALWAYS_AVAILABLE_FEATURES:
        return  # ENT-001: PII is always available
    active = get_license()
    if not active.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=active.tier)


def check_agent_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_agents (and max != -1).

    LAURA-V2-001 fix: reads get_license() (integrity-checked), not the raw
    `_license` global — see require_feature()'s docstring for the full
    rationale and honest ceiling, which applies identically here.
    """
    active = get_license()
    if active.max_agents == -1:
        return
    if current_count >= active.max_agents:
        raise LicenseLimitExceeded(
            limit_name="max_agents",
            current=current_count,
            max_val=active.max_agents,
        )


def check_end_user_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_end_users (and max != -1).

    LAURA-V2-001 fix: reads get_license() (integrity-checked) — see
    require_feature()'s docstring.
    """
    active = get_license()
    if active.max_end_users == -1:
        return
    if current_count >= active.max_end_users:
        raise LicenseLimitExceeded(
            limit_name="max_end_users",
            current=current_count,
            max_val=active.max_end_users,
        )


def check_admin_seat_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_admin_seats (and max != -1).

    LAURA-V2-001 fix: reads get_license() (integrity-checked) — see
    require_feature()'s docstring.
    """
    active = get_license()
    if active.max_admin_seats == -1:
        return
    if current_count >= active.max_admin_seats:
        raise LicenseLimitExceeded(
            limit_name="max_admin_seats",
            current=current_count,
            max_val=active.max_admin_seats,
        )


def check_org_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_orgs (and max != -1).

    LAURA-V2-001 fix: reads get_license() (integrity-checked) — see
    require_feature()'s docstring.
    """
    active = get_license()
    if active.max_orgs == -1:
        return
    if current_count >= active.max_orgs:
        raise LicenseLimitExceeded(
            limit_name="max_orgs",
            current=current_count,
            max_val=active.max_orgs,
        )


# ---------------------------------------------------------------------------
# Canonical end-user count (GROUP-2-3 / v2.23.2)
# ---------------------------------------------------------------------------

def count_canonical_end_users() -> int:
    """
    Return the canonical end-user count as the union of three pools,
    deduplicated by lowercase email address.

    Pools:
      1. auth_service — Postgres users table (non-admin accounts)
      2. IdentityRegistry — Redis identity:index:kind:human members
      3. RBAC store — all group members via RBACStore.list_groups()

    Design note (2026-05-05): canonical count = union(auth_service users,
    IdentityRegistry HUMAN, RBAC users), deduped by lowercase email.

    Async caveat: auth_service uses async Postgres. When called from within a
    running asyncio event loop (FastAPI route handlers) we cannot use
    run_until_complete(). In that context the auth_service pool is skipped
    and only the synchronous Redis pools (identity_registry + RBAC) are counted.
    The caller (check_end_user_limit) is still called with the result; the count
    may be an undercount in that context but it is never zero for a non-empty
    deployment, and the atomicity of the Lua scripts in IdentityRegistry/
    AgentRegistry provides the primary enforcement barrier.

    Never raises — returns 0 on any error (fail-open for count, fail-closed for
    limit enforcement in the Lua scripts).
    """
    try:
        from yashigani.backoffice.state import backoffice_state
    except Exception:
        return 0

    emails: set[str] = set()

    # Pool 1: IdentityRegistry HUMAN members (synchronous Redis SMEMBERS)
    try:
        registry = getattr(backoffice_state, "identity_registry", None)
        if registry is not None:
            r = getattr(registry, "_r", None)
            if r is not None:
                members = r.smembers("identity:index:kind:human")
                for identity_id_raw in (members or []):
                    identity_id = (
                        identity_id_raw.decode("utf-8")
                        if isinstance(identity_id_raw, bytes)
                        else identity_id_raw
                    )
                    # Slug is not the email; use name as proxy or identity_id as fallback.
                    # We need the email field from the hash — not always present for
                    # HUMAN identities provisioned via SSO (email only in audit logs).
                    # Fall back to identity_id as a unique key — prevents double-counting
                    # entries without email fields.
                    try:
                        email_raw = r.hget(f"identity:reg:{identity_id}", "email")
                        if email_raw:
                            email = (
                                email_raw.decode("utf-8")
                                if isinstance(email_raw, bytes)
                                else email_raw
                            )
                            emails.add(email.strip().lower())
                        else:
                            # No email field — use identity_id as surrogate key
                            emails.add(f"__idnt__{identity_id}")
                    except Exception:
                        emails.add(f"__idnt__{identity_id}")
    except Exception as exc:
        logger.debug("count_canonical_end_users: identity_registry pool error: %s", exc)

    # Pool 2: RBAC store group members
    try:
        rbac = getattr(backoffice_state, "rbac_store", None)
        if rbac is not None:
            groups = rbac.list_groups()
            for group in (groups or []):
                for member_raw in (group.members if hasattr(group, "members") else []):
                    member = member_raw.strip().lower() if isinstance(member_raw, str) else ""
                    if member:
                        emails.add(member)
    except Exception as exc:
        logger.debug("count_canonical_end_users: rbac_store pool error: %s", exc)

    # Pool 3: auth_service (async — use Redis cache when event loop is running) (T13)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if not loop.is_running():
            auth = getattr(backoffice_state, "auth_service", None)
            if auth is not None:
                count = loop.run_until_complete(auth.total_user_count())
                for i in range(count):
                    emails.add(f"__auth__{i}")
        else:
            # Event loop running (FastAPI context) — use Redis-cached count (T13)
            try:
                registry = getattr(backoffice_state, "identity_registry", None)
                if registry is not None:
                    r = getattr(registry, "_r", None)
                    if r is not None:
                        cached = r.get("license:count:auth_users")
                        if cached is not None:
                            count = int(
                                cached if isinstance(cached, int)
                                else (cached.decode("utf-8") if isinstance(cached, bytes) else cached)
                            )
                            for i in range(count):
                                emails.add(f"__auth__{i}")
            except Exception as exc:
                logger.debug("count_canonical_end_users: auth_cache pool error: %s", exc)
    except Exception as exc:
        logger.debug("count_canonical_end_users: auth_service pool error: %s", exc)

    return len(emails)


async def _sync_auth_user_count() -> None:
    """
    Background job: sync auth_service user count to Redis (T13).

    Wired into APScheduler in app.py as a 60s interval job.
    """
    try:
        from yashigani.backoffice.state import backoffice_state
        auth = getattr(backoffice_state, "auth_service", None)
        if auth is None:
            return
        count = await auth.total_user_count()
        registry = getattr(backoffice_state, "identity_registry", None)
        if registry is None:
            return
        r = getattr(registry, "_r", None)
        if r is None:
            return
        r.set("license:count:auth_users", str(count))
    except Exception as exc:
        logger.debug("_sync_auth_user_count: %s", exc)


# ---------------------------------------------------------------------------
# FastAPI exception handler helpers
# ---------------------------------------------------------------------------

# Which tier unlocks each feature — used in upgrade messages.
# ENT-001 (2026-06-14): pii_log/pii_redact removed — PII is always available
# and will never reach this lookup via license_feature_gated_response().
_FEATURE_UPGRADE_TIER: dict[str, str] = {
    "oidc":  "Starter",
    "saml":  "Professional",
    "scim":  "Professional",
}


def license_feature_gated_response(exc: LicenseFeatureGated) -> dict:
    upgrade_tier = _FEATURE_UPGRADE_TIER.get(exc.feature, "Professional")
    return {
        "error": "LICENSE_FEATURE_GATED",
        "feature": exc.feature,
        "tier": exc.tier.value,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": f"{exc.feature.upper()} requires {upgrade_tier} or higher",
    }


def license_limit_exceeded_response(exc: LicenseLimitExceeded) -> dict:
    # LAURA-V2-001 fix: reflect get_license() (integrity-checked), not the
    # raw `_license` global, so a degraded-to-COMMUNITY tier is reported
    # accurately in this error payload too.
    tier = get_license().tier.value
    limit_label = {
        "max_agents":      "Agent",
        "max_end_users":   "End user",
        "max_admin_seats": "Admin seat",
        "max_orgs":        "Organization",
    }.get(exc.limit_name, exc.limit_name)
    return {
        "error": "LICENSE_LIMIT_EXCEEDED",
        "limit": exc.limit_name,
        "current": exc.current,
        "maximum": exc.max_val,
        "tier": tier,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": (
            f"{limit_label} limit reached ({exc.current}/{exc.max_val}). "
            f"Upgrade your license at yashigani.io/pricing."
        ),
    }


# Run integrity check at module load (T1 / DG-04)
_check_enforcer_integrity()
# LAURA-V2-003 Phase D hardening: mesh full-check (separate code path, see above)
_check_enforcer_mesh_full()
# LAURA-V2-005 hardening: root-of-trust pin (separate code path, see above)
_check_enforcer_root_pin()
