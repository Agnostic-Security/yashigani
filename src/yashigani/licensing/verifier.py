"""
Offline license verifier — v5 chain-of-trust (root master -> leaf -> licence).

Last updated: 2026-07-14T00:00:00+00:00 (licence-hardening-v2 Phase B-CORE)

Ref: AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md
     §3.2 (Licence format v5) + §4a (Build-integrity verify) +
     §4b (Licence v5 verify) + §5 (Fail-modes) + §6 (kill-list).

License file format:
    v5 (current, ONLY accepted format):
        base64url(payload) . base64url(leaf_sig) . base64url(canonical(leaf_cert)) . base64url(leaf_cert_sig)
        (4 dot-separated segments)

v3 (2-segment) and v4 (3-segment, primary+counter signature) formats are
NO LONGER ACCEPTED — "v3/v4 dropped — v5 mandatory, no downgrade path"
(design §3.2). Anything that isn't exactly 4 segments is rejected before
any signature is attempted (see chain.licence_v5.parse_licence_v5()).

Chain-of-trust model (supersedes the old two-parallel-key v4 model): every
build embeds a master trust-anchor SET (never a single key —
_integrity.MASTER_ANCHOR_SET_JSON) and this release's code leaf_cert. A v5
licence carries its OWN licence-role leaf_cert + the master's signature over
it, so the verifier — holding only the embedded anchor-SET — validates the
whole chain offline. Because verification is "chains to master", a licence
signed by leaf-N still verifies on release N+1, N+2, ... (this closes the
v4 bug where a licence's counter-signature stopped verifying after a
release rotated the counter key — see design §0).

Payload versions (unchanged field-resolution logic from v4 — see
_build_license_state()):
    v1 — max_agents, max_orgs only
    v2 — adds max_users (renamed to max_end_users in v3)
    v3 — max_agents, max_end_users, max_admin_seats, max_orgs, key_alg
    v5 — v3's fields carried forward unchanged, PLUS client_id,
         licence_serial, signed_at, alg (design §3.2)

Backwards compat: v1/v2 payloads missing new fields fall back to
TIER_DEFAULTS[tier] so existing customer license files keep working.

Fail-modes (design §5):
    - No licence / invalid / chain fails / revoked -> COMMUNITY tier, never
      block, never delete users.
    - Build's OWN integrity fails (tamper / self-hash mismatch / leaf_cert
      won't chain) -> COMMUNITY + persistent tamper banner (surfaced via
      get_integrity_status(); backoffice/routes/license.py reads it).

Self-integrity check
--------------------
At module load this file computes its own SHA-256 digest and compares it
against _integrity.VERIFIER_HASH (T1-T4 self-hash bundle, unchanged
mechanism). A mismatch (when the hash is not a placeholder) indicates
post-build tampering. Separately, the chain-based build-integrity check
(§4a: anchor-chain + bundle_sig, chain.build_integrity.
verify_build_integrity_chain()) supersedes the old counter-key/
HASH_BUNDLE_SIG/EXPECTED_TOKEN_HMAC scheme. Either failure sets
_integrity_violated and forces COMMUNITY tier for any subsequently
verified license.

Requires: cryptography>=42.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from yashigani.licensing import _integrity
from yashigani.licensing.chain import (
    AnchorSet,
    KillList,
    anchor_set_from_json,
    kill_list_from_json,
    leaf_cert_from_json,
    verify_build_integrity_chain,
    verify_licence_v5,
)
from yashigani.licensing.model import (
    COMMUNITY_LICENSE,
    TIER_DEFAULTS,
    LicenseFeature,
    LicenseState,
    LicenseTier,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Self-integrity state (set at module load)
# ---------------------------------------------------------------------------

# True when tamper detection has fired for this process lifetime.
_integrity_violated = False


def _check_self_integrity() -> None:
    """
    Compute SHA-256 of this source file and compare against _integrity.VERIFIER_HASH.

    Skipped (fail-open) when the hash constant is still a placeholder.
    Sets _integrity_violated = True on mismatch, which causes verify_license()
    to return COMMUNITY tier for all calls in this process.
    """
    global _integrity_violated

    if _integrity.is_verifier_hash_placeholder():
        # #104 (LICENSE-2024-002 / CVSS 9.1) — placeholder skip is only
        # permitted in dev/CI builds (YASHIGANI_ENV=dev).  In any other
        # environment a placeholder hash means the build pipeline failed to
        # embed the real hash; treat that as a tamper event (fail-closed).
        if os.environ.get("YASHIGANI_ENV") != "dev":
            _integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: VERIFIER_HASH is still a placeholder "
                "in a non-dev environment — build pipeline did not embed hash; "
                "forcing COMMUNITY tier (LICENSE-2024-002)"
            )
        return

    try:
        source_path = Path(__file__)
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    except Exception as exc:
        # Cannot read own source — treat as suspicious but do not crash the
        # process.  Log a warning; do not set _integrity_violated (benefit of
        # doubt — compiled .pyc or unusual packaging).
        logger.warning(
            "License integrity: could not read own source for hash check: %s", exc
        )
        return

    if digest != _integrity.VERIFIER_HASH:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: verifier.py has been tampered with "
            "(expected=%s, actual=%s)",
            _integrity.VERIFIER_HASH,
            digest,
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="self_hash",
            expected_hash=_integrity.VERIFIER_HASH,
            actual_hash=digest,
        )


def _emit_licence_integrity_violation_event(
    module: str,
    check_type: str,
    expected_hash: str,
    actual_hash: str,
    classification: str = "unknown",
) -> None:
    """
    Write a typed LicenceIntegrityViolationEvent if an AuditLogWriter is available.

    Wrapped in a broad except so that a missing / uninitialised audit subsystem
    never blocks the integrity check result.  The CRITICAL log is the primary alert;
    audit is defence-in-depth.
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

        event = LicenceIntegrityViolationEvent(
            module=module,
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        )
        event._internal_classification = classification
        writer.write(event)
    except Exception:
        pass  # audit subsystem unavailable — integrity violation already logged via CRITICAL


# ---------------------------------------------------------------------------
# §4a — chain-based build-integrity verify (supersedes the v1 counter-key/
# HASH_BUNDLE_SIG/EXPECTED_TOKEN_HMAC mechanism)
# ---------------------------------------------------------------------------

def _build_hash_bundle_str() -> str:
    """Canonical hash-bundle string built from the STATIC constants
    _integrity.py claims (5 module hashes, sorted by key name).

    HISTORICAL NOTE / CORRECTION (LAURA-V2-001, 2026-07-15): earlier
    revisions of this docstring claimed "INTEGRITY_HASH already receives
    independent protection via the enforcer cross-check" — that claim was
    FALSE (grep confirmed no module anywhere read _integrity.py's own bytes
    and compared to INTEGRITY_HASH; the enforcer cross-check only ever
    covered verifier.py). It has been corrected here rather than left
    standing (honest-claims discipline).

    This function is kept, UNCHANGED IN BEHAVIOUR, only because existing
    test fixtures (src/tests/integration/test_licence_hardening_v2_integration.py
    ::_embed_build) call it by name to build a bundle_str for signing in
    test setup. It is NOT what module-load-time verification actually
    checks BUNDLE_SIG against any more — see
    _compute_live_hash_bundle_str() below, which is the authoritative,
    externally-computed (outside every one of the 5 protected files)
    bundle string _check_build_integrity_chain() verifies BUNDLE_SIG
    against. The distinction matters: this function proves "_integrity.py's
    own claimed hashes are internally self-consistent" (tautological — it
    reads the constants and re-states them); it does NOT prove "the file on
    disk right now matches those hashes" (that was root cause #3 of
    LAURA-V2-001 — BUNDLE_SIG only ever covered this tautology).
    """
    return "\n".join([
        f"AGENTS_REGISTRY_HASH={_integrity.AGENTS_REGISTRY_HASH}",
        f"ENFORCER_HASH={_integrity.ENFORCER_HASH}",
        f"IDENTITY_REGISTRY_HASH={_integrity.IDENTITY_REGISTRY_HASH}",
        f"LOADER_HASH={_integrity.LOADER_HASH}",
        f"VERIFIER_HASH={_integrity.VERIFIER_HASH}",
    ])


# ---------------------------------------------------------------------------
# LAURA-V2-001/002 fix (2026-07-15) — external, live-from-disk re-derivation.
#
# Root causes closed here:
#   (LAURA-V2-001 #2/#3) Every module's self-check previously lived INSIDE
#   the file it protects (enforcer.py checks enforcer.py; loader.py checks
#   loader.py) — a single coordinated edit to one of those files can neuter
#   both the gate AND its own checker in the same edit, with zero external
#   evidence. The functions below live in verifier.py — a SEPARATE FILE —
#   and read every protected module's bytes straight off disk at THIS
#   module's own load time, independent of what any of those files'
#   in-process code currently does. An edit confined to enforcer.py (or
#   loader.py) cannot suppress this computation.
#
#   (LAURA-V2-001 #3) BUNDLE_SIG previously only ever covered
#   _build_hash_bundle_str() above — the STATIC constants _integrity.py
#   claims, which is tautological (it never touched a live file).
#   _check_build_integrity_chain() below now verifies BUNDLE_SIG against
#   _compute_live_hash_bundle_str()'s output instead — a bundle built from
#   hashes computed from the CURRENT bytes on disk. Any post-build edit to
#   any of the 6 covered files invalidates the signature.
#
#   (LAURA-V2-002) INTEGRITY_HASH — previously dead code (nothing computed
#   or compared it) — is now wired as the 6th line of that live bundle,
#   computed via the blank-then-hash self-referential convention below.
#   Because INTEGRITY_HASH's live value spans the ENTIRE current
#   _integrity.py file (kill-list, client-domain registry, anchor-set, code
#   leaf_cert/leaf_cert_sig — everything except its own line and BUNDLE_SIG's
#   own line, which must be blanked to avoid the chicken-and-egg problem of
#   a hash containing itself), editing ANY of those fields (e.g. Laura's
#   PoC: KILL_LIST_JSON="[]") without re-signing now invalidates either the
#   live INTEGRITY_HASH comparison, the live BUNDLE_SIG check, or both.
#
# Honest ceiling (do not overclaim): this raises the cost of a silent,
# undetected patch — it does NOT make source-available Python
# tamper-*proof*. An attacker who edits enforcer.py's require_feature() body
# in isolation can still, unavoidably, cause THAT specific call to grant
# access (no code living inside a function can defend against the entire
# function body being replaced by someone with local write access to the
# file it's defined in — see enforcer.require_feature()'s own docstring for
# the full honest-ceiling note). What THIS fix guarantees is that such an
# edit can no longer ALSO suppress the alarm: verifier.get_integrity_status()
# (and therefore enforcer.get_license()/is_license_tampered(), which read
# it) will correctly report tamper = True, log CRITICAL, and emit a typed
# audit event, regardless of what enforcer.py's own code does — matching
# design §11's accepted residual ("a knowing, unambiguous act with a
# visible diff") rather than the previous "zero alarm, zero evidence"
# behaviour, which was worse than that residual. No hardware root of trust
# is available in this design (Apache-2.0, offline, readable source).
# ---------------------------------------------------------------------------

_LICENSING_DIR = Path(__file__).parent
_YASHIGANI_PKG_DIR = _LICENSING_DIR.parent  # .../src/yashigani

# The T1-T4 protected files, keyed by their _integrity.py constant name —
# resolved by PATH, never by importing those modules (importing would run
# their own, potentially-tampered, code).
#
# Extended 2026-07-16 (LAURA-V2-001 follow-up — "replacing require_feature()'s
# whole body still yields the feature"): the 5 point-of-use (POU) files below
# do the ACTUAL privileged work of a licence-gated capability. Each of them
# now carries its OWN local `_licence_hard_gate()` (see oidc.py/saml.py/
# routes/sso.py/routes/scim.py) that reads verifier.get_integrity_status()
# and enforcer.get_enforcer_integrity_status() directly — NOT via
# enforcer.require_feature() — so patching require_feature() alone has zero
# effect on them. Adding them here closes the OTHER half: tampering with a
# POU file itself (e.g. deleting its own `_licence_hard_gate()` call) changes
# that file's bytes, which THIS dict causes verifier.py — a separate file,
# untouched by that edit — to detect independently at its own module-load
# time, exactly like ENFORCER_HASH/LOADER_HASH always have.
_LIVE_HASH_TARGETS: dict[str, Path] = {
    "VERIFIER_HASH": _LICENSING_DIR / "verifier.py",
    "ENFORCER_HASH": _LICENSING_DIR / "enforcer.py",
    "LOADER_HASH": _LICENSING_DIR / "loader.py",
    "AGENTS_REGISTRY_HASH": _YASHIGANI_PKG_DIR / "agents" / "registry.py",
    "IDENTITY_REGISTRY_HASH": _YASHIGANI_PKG_DIR / "identity" / "registry.py",
    "OIDC_MODULE_HASH": _YASHIGANI_PKG_DIR / "sso" / "oidc.py",
    "SAML_MODULE_HASH": _YASHIGANI_PKG_DIR / "sso" / "saml.py",
    "SSO_ROUTES_HASH": _YASHIGANI_PKG_DIR / "backoffice" / "routes" / "sso.py",
    "SCIM_ROUTES_HASH": _YASHIGANI_PKG_DIR / "backoffice" / "routes" / "scim.py",
    "GATE_MIDDLEWARE_HASH": _LICENSING_DIR / "gate_middleware.py",
}

_INTEGRITY_PY_PATH = _LICENSING_DIR / "_integrity.py"

# Fixed, deterministic placeholders used ONLY inside the blank-then-hash
# self-referential digest below — never real hash/signature values, never
# compared against anything themselves. Any fixed string works as long as
# scripts/inject_hashes.sh's independent Python implementation of this same
# algorithm uses the IDENTICAL placeholders (see that script's Step —
# "compute INTEGRITY_HASH" — comment cross-referencing this function).
_SELF_HASH_BLANK_INTEGRITY_HASH = "0" * 64
_SELF_HASH_BLANK_BUNDLE_SIG = "0" * 64

# Match the WHOLE right-hand-side of the assignment, to end of line — NOT
# just a `"..."` quoted-literal shape. _integrity.py's PRISTINE placeholder
# state is a Python EXPRESSION (`_PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"`),
# not a bare string literal; a regex that only matched `"[^"]*"` silently
# failed to blank that pristine form (no match => no substitution => the
# literal placeholder-expression text stayed in the hashed bytes), while the
# SAME regex correctly matched and blanked the line once a real value had
# been injected (`"deadbeef...".`) — producing two DIFFERENT digests for
# what should be the identical blanked file, and a false-positive tamper
# report on every freshly-built, wholly untampered package. Matching to end
# of line (mirroring inject_hashes.sh's own `_replace_constant()` pattern)
# handles both the pristine-expression and injected-literal shapes
# identically. Caught by end-to-end verification against a freshly signed
# build (2026-07-15) — see
# src/tests/regression/v4.1.1/test_laura_v2_001_002_external_authority.py::
# TestIntegrityHashAlgorithmRoundTrip and
# TestLauraV2001EnforcerNeuterNowAlarms::test_clean_build_no_violation.
_INTEGRITY_HASH_LINE_RE = re.compile(r'^(INTEGRITY_HASH\s*:\s*str\s*=\s*).*$', re.MULTILINE)
_BUNDLE_SIG_LINE_RE = re.compile(r'^(BUNDLE_SIG\s*:\s*str\s*=\s*).*$', re.MULTILINE)


def _compute_integrity_self_hash(file_text: str) -> str:
    """
    Compute _integrity.py's own self-referential integrity hash
    (LAURA-V2-002 — wires up the previously dead-code INTEGRITY_HASH).

    Self-referential file hashing has a chicken-and-egg problem: a file's
    hash can't include the hash's own final value. This uses the standard
    "blank-then-hash" convention — BOTH the INTEGRITY_HASH line's value AND
    the BUNDLE_SIG line's value are replaced with fixed, deterministic
    placeholders before hashing, regardless of whatever value currently sits
    in those two lines. That makes the digest reproducible independent of
    injection order (INTEGRITY_HASH is folded into the bundle BUNDLE_SIG
    signs — see _compute_live_hash_bundle_str() — so BUNDLE_SIG is always
    written to the file AFTER INTEGRITY_HASH; blanking BUNDLE_SIG too means
    that write does not change what a fresh recompute of INTEGRITY_HASH
    would produce).

    scripts/inject_hashes.sh implements this EXACT SAME algorithm
    independently, in its own Python heredoc (deliberately NOT by importing
    this function — importing from _integrity.py's own package for the
    BUILD side is fine, but this function must stay usable for the VERIFY
    side without ever importing anything from a file it is trying to
    verify). The two implementations must be kept byte-identical; a
    regression test round-trips build-time embed -> verify-time recompute
    against a synthetic _integrity.py to catch drift.

    Callers MUST pass text read directly off disk (never anything derived
    from `import yashigani.licensing._integrity` or any of its functions) —
    the whole point of this living in verifier.py is that the computation is
    independent of whatever code currently executes inside _integrity.py.
    """
    blanked = _INTEGRITY_HASH_LINE_RE.sub(
        lambda m: m.group(1) + '"' + _SELF_HASH_BLANK_INTEGRITY_HASH + '"',
        file_text,
        count=1,
    )
    blanked = _BUNDLE_SIG_LINE_RE.sub(
        lambda m: m.group(1) + '"' + _SELF_HASH_BLANK_BUNDLE_SIG + '"',
        blanked,
        count=1,
    )
    return hashlib.sha256(blanked.encode("utf-8")).hexdigest()


def _compute_live_hash_bundle_str() -> "tuple[Optional[str], dict[str, Optional[str]]]":
    """
    Read the CURRENT bytes of every T1-T4 + point-of-use (POU) protected file
    straight off disk — independent of any of those modules' own in-process
    state/self-checks — plus _integrity.py's own blanked self-hash, and build
    the SAME canonical "KEY=hex" bundle-string shape BUNDLE_SIG is signed
    over (11 lines: the 5 T1-T4 hashes + INTEGRITY_HASH + the 5 POU hashes —
    OIDC/SAML/SSO-routes/SCIM-routes/gate-middleware, added 2026-07-16).

    Returns (bundle_str, live_hashes). bundle_str is None if ANY file could
    not be read — the caller must treat that as a verification failure
    (fail-closed), never silently skip the check.
    """
    live_hashes: dict[str, Optional[str]] = {}
    ok = True
    for const_name, path in _LIVE_HASH_TARGETS.items():
        try:
            live_hashes[const_name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception as exc:
            logger.warning(
                "License integrity: could not read %s for live hash re-derivation: %s",
                path, exc,
            )
            live_hashes[const_name] = None
            ok = False

    try:
        integrity_text = _INTEGRITY_PY_PATH.read_text(encoding="utf-8")
        live_hashes["INTEGRITY_HASH"] = _compute_integrity_self_hash(integrity_text)
    except Exception as exc:
        logger.warning(
            "License integrity: could not read _integrity.py for live self-hash "
            "re-derivation: %s", exc,
        )
        live_hashes["INTEGRITY_HASH"] = None
        ok = False

    if not ok:
        return None, live_hashes

    bundle_str = "\n".join([
        f"AGENTS_REGISTRY_HASH={live_hashes['AGENTS_REGISTRY_HASH']}",
        f"ENFORCER_HASH={live_hashes['ENFORCER_HASH']}",
        f"GATE_MIDDLEWARE_HASH={live_hashes['GATE_MIDDLEWARE_HASH']}",
        f"IDENTITY_REGISTRY_HASH={live_hashes['IDENTITY_REGISTRY_HASH']}",
        f"INTEGRITY_HASH={live_hashes['INTEGRITY_HASH']}",
        f"LOADER_HASH={live_hashes['LOADER_HASH']}",
        f"OIDC_MODULE_HASH={live_hashes['OIDC_MODULE_HASH']}",
        f"SAML_MODULE_HASH={live_hashes['SAML_MODULE_HASH']}",
        f"SCIM_ROUTES_HASH={live_hashes['SCIM_ROUTES_HASH']}",
        f"SSO_ROUTES_HASH={live_hashes['SSO_ROUTES_HASH']}",
        f"VERIFIER_HASH={live_hashes['VERIFIER_HASH']}",
    ])
    return bundle_str, live_hashes


def _check_build_integrity_chain() -> None:
    """
    §4a steps 1-5: validate the embedded code leaf_cert chains to the
    embedded master anchor-SET, then verify BUNDLE_SIG against that leaf's
    public key — using a bundle built from LIVE hashes re-derived from disk
    (LAURA-V2-001/002 fix, see _compute_live_hash_bundle_str()), not the
    static _integrity.py constants alone. Each protected module's own local
    self-check (enforcer._check_enforcer_integrity(),
    loader._check_loader_integrity(), agents/registry.py's and
    identity/registry.py's own checks) still runs independently too —
    defense in depth — but is no longer the ONLY place tamper of those
    files is detected: this function is now the external, un-suppressible
    authority.

    Placeholder behaviour: skip (dev) / fail-closed (prod) — mirrors the v1
    _check_hash_bundle_attestation()/_check_kdf_token() placeholder
    handling this function replaces.
    """
    global _integrity_violated

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if _integrity.is_any_hash_placeholder():
        if is_dev:
            return  # dev: skip — no per-module hashes to bind the bundle to
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: one or more module hashes are still "
            "placeholders in a non-dev environment — build-integrity chain check "
            "cannot proceed; forcing COMMUNITY tier"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="build_integrity_chain",
            expected_hash="<real_hash>",
            actual_hash="<placeholder>",
        )
        return

    if _integrity.is_any_chain_placeholder():
        if is_dev:
            return  # dev: skip — no anchor set / code leaf_cert / bundle_sig to verify
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: master anchor-set / code leaf_cert / "
            "leaf_cert_sig / bundle_sig is still a placeholder in a non-dev "
            "environment — build pipeline did not embed the chain; forcing "
            "COMMUNITY tier"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="build_integrity_chain",
            expected_hash="<chain>",
            actual_hash="<placeholder>",
        )
        return

    try:
        anchor_set = anchor_set_from_json(_integrity.MASTER_ANCHOR_SET_JSON)
        code_leaf_cert = leaf_cert_from_json(_integrity.CODE_LEAF_CERT_JSON)
        code_leaf_cert_sig = base64.b64decode(_integrity.CODE_LEAF_CERT_SIG)
        bundle_sig = base64.b64decode(_integrity.BUNDLE_SIG)
        kill_list = kill_list_from_json(_integrity.KILL_LIST_JSON)
    except Exception as exc:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: could not parse embedded chain constants "
            "(anchor set / code leaf_cert / bundle_sig / kill-list) — forcing "
            "COMMUNITY tier: %s",
            exc,
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="build_integrity_chain",
            expected_hash="<parseable>",
            actual_hash="<parse_error>",
        )
        return

    # LAURA-V2-001/002 fix: live re-derivation from disk, computed entirely
    # in THIS file (external to every one of the 5 protected modules and to
    # _integrity.py itself) — see the block comment above
    # _compute_live_hash_bundle_str() for the full rationale.
    live_bundle_str, live_hashes = _compute_live_hash_bundle_str()

    if live_bundle_str is None:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: could not independently re-derive one "
            "or more protected module hashes from disk (files missing/unreadable) "
            "— treating as tamper (fail-closed); forcing COMMUNITY tier"
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="live_hash_rederivation",
            expected_hash="<readable>",
            actual_hash="<unreadable>",
        )
        return

    # Diagnostic per-module comparison — identifies WHICH file was tampered,
    # computed and logged from verifier.py regardless of whether that file's
    # OWN self-check (e.g. enforcer._check_enforcer_integrity()) was also
    # neutered by the same edit (LAURA-V2-001 #2). This is what guarantees
    # the alarm cannot be suppressed by an edit confined to any one of the
    # other protected files.
    _static_hash_constants = {
        "VERIFIER_HASH": _integrity.VERIFIER_HASH,
        "ENFORCER_HASH": _integrity.ENFORCER_HASH,
        "LOADER_HASH": _integrity.LOADER_HASH,
        "AGENTS_REGISTRY_HASH": _integrity.AGENTS_REGISTRY_HASH,
        "IDENTITY_REGISTRY_HASH": _integrity.IDENTITY_REGISTRY_HASH,
        "INTEGRITY_HASH": _integrity.INTEGRITY_HASH,
        "OIDC_MODULE_HASH": _integrity.OIDC_MODULE_HASH,
        "SAML_MODULE_HASH": _integrity.SAML_MODULE_HASH,
        "SSO_ROUTES_HASH": _integrity.SSO_ROUTES_HASH,
        "SCIM_ROUTES_HASH": _integrity.SCIM_ROUTES_HASH,
        "GATE_MIDDLEWARE_HASH": _integrity.GATE_MIDDLEWARE_HASH,
    }
    any_module_mismatch = False
    for const_name, expected in _static_hash_constants.items():
        live = live_hashes.get(const_name)
        if live is not None and live != expected:
            any_module_mismatch = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: %s live re-derivation from disk does "
                "NOT match the embedded, signed value (expected=%s, actual=%s) — "
                "this file has been modified since the build was signed; forcing "
                "COMMUNITY tier. Detected externally by verifier.py, independent "
                "of the protected file's own self-check (LAURA-V2-001).",
                const_name, expected[:16], live[:16],
            )
            _emit_licence_integrity_violation_event(
                module="verifier",
                check_type=f"live_hash_{const_name.lower()}",
                expected_hash=expected,
                actual_hash=live,
            )

    if any_module_mismatch:
        _integrity_violated = True
        # Continue to the cryptographic bundle_sig check too (defense in
        # depth / additional evidence) rather than returning early.

    result = verify_build_integrity_chain(
        anchor_set=anchor_set,
        code_leaf_cert=code_leaf_cert,
        code_leaf_cert_sig=code_leaf_cert_sig,
        bundle_str=live_bundle_str,
        bundle_sig=bundle_sig,
        kill_list=kill_list,
    )
    if not result.valid:
        _integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: build-integrity chain check failed "
            "(error=%s) — binary may have been tampered with; forcing COMMUNITY "
            "tier. License integrity check failed — system restrained to "
            "Community limits. Contact support@agnosticsec.com or re-activate.",
            result.error,
        )
        _emit_licence_integrity_violation_event(
            module="verifier",
            check_type="build_integrity_chain",
            expected_hash=result.error or "<unknown>",
            actual_hash="<invalid>",
        )


def get_integrity_status() -> bool:
    """Return True if the integrity has been violated in this process."""
    return _integrity_violated


# Run at module load.
_check_self_integrity()
_check_build_integrity_chain()


# ---------------------------------------------------------------------------
# Cached embedded chain state — loaded once at module load for use by
# verify_license()'s v5 path. Reuses the SAME anchor-set/kill-list already
# parsed above where possible; re-parsed defensively here in case
# _check_build_integrity_chain() bailed early (placeholder/dev) and never
# populated a module-level cache.
# ---------------------------------------------------------------------------

def _load_anchor_set() -> AnchorSet:
    try:
        return anchor_set_from_json(_integrity.MASTER_ANCHOR_SET_JSON)
    except Exception as exc:
        logger.warning("License verifier: could not parse MASTER_ANCHOR_SET_JSON: %s", exc)
        return AnchorSet([])


def _load_kill_list() -> KillList:
    try:
        return kill_list_from_json(_integrity.KILL_LIST_JSON)
    except Exception as exc:
        logger.warning("License verifier: could not parse KILL_LIST_JSON: %s", exc)
        return KillList.empty()


def _load_client_domain_registry() -> Optional[dict]:
    try:
        raw = _integrity.CLIENT_DOMAIN_REGISTRY_JSON
        if not raw or not raw.strip() or raw.strip() == "{}":
            return {}
        return json.loads(raw)
    except Exception as exc:
        logger.warning("License verifier: could not parse CLIENT_DOMAIN_REGISTRY_JSON: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (no padding required)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


# Sentinel used by enterprise tier to signal "unlimited".  -1 is the documented
# value; we preserve it through _safe_int so enforcer can treat it specially.
_UNLIMITED_SENTINEL = -1

# Sanity ceiling: no license should grant more than 10 million seats of any type.
# A value above this (other than the -1 unlimited sentinel) indicates a corrupt
# or adversarially crafted payload and is clamped to COMMUNITY defaults.
_SEAT_CEILING = 10_000_000


def _safe_int(value: object, default: int) -> int:
    """
    Coerce *value* to int; return *default* on any failure.

    Handles:
      - None / missing field
      - Empty string or whitespace-only string
      - Non-numeric strings ("abc", "null", etc.)
      - Float (truncated to int via int())
      - Negative values other than the documented -1 unlimited sentinel
        → clamp to *default* (LAURA-LICENSE-08: negative seat counts are
        adversarial — they would bypass enforcer's >= check entirely)
      - Values above _SEAT_CEILING that are not -1 → clamp to *default*

    Never raises. Prevents LAURA-V231-002 DoS-on-boot via null seat fields.
    Prevents LAURA-LICENSE-08 negative-seat bypass.
    """
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return default
    try:
        result = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default

    # Preserve the -1 unlimited sentinel without clamping.
    if result == _UNLIMITED_SENTINEL:
        return result

    # LAURA-LICENSE-08: any other negative value is adversarial (a seat count
    # of -2 would satisfy enforcer's `current >= max_agents` check with any
    # positive current count, bypassing the limit entirely). Clamp to default.
    if result < 0:
        logger.warning(
            "License verifier: negative seat field value %d — "
            "using tier default %d (LAURA-LICENSE-08)",
            result, default,
        )
        return default

    # Reject implausibly large values (corrupt / adversarial payload).
    if result > _SEAT_CEILING:
        logger.warning(
            "License verifier: seat field value %d exceeds ceiling %d — "
            "using tier default %d",
            result, _SEAT_CEILING, default,
        )
        return default

    return result


def _build_license_state(payload: dict, valid: bool, error: Optional[str] = None) -> LicenseState:
    tier_str = payload.get("tier", "community")
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        tier = LicenseTier.COMMUNITY
        tier_str = "community"

    # GROUP-5-3: canary sentinel — this tier must never appear in a verifiable
    # license. If we receive one it means someone has issued a canary token to
    # probe for patched verifiers. Reject with a specific error so monitoring
    # can alert on it. Map to COMMUNITY (fail-closed).
    if tier == LicenseTier.CANARY:
        logger.critical(
            "License verifier: CANARY tier token presented — potential verifier-patch "
            "probe detected (GROUP-5-3); forcing COMMUNITY"
        )
        return _community_invalid("canary_token_rejected")

    # Coerce string feature values to LicenseFeature enum; unknown strings are silently dropped
    # for forwards-compat (new features added server-side before client ships).
    features_raw = payload.get("features", [])
    if isinstance(features_raw, list):
        coerced: list[LicenseFeature] = []
        for f in features_raw:
            try:
                coerced.append(LicenseFeature(f))
            except ValueError:
                pass
        features: frozenset[LicenseFeature] = frozenset(coerced)
    else:
        features = frozenset()

    issued_at = _parse_datetime(payload.get("issued_at")) or datetime(2020, 1, 1, tzinfo=timezone.utc)
    expires_at = _parse_datetime(payload.get("expires_at"))

    # GROUP-1-2: License Service produces {"domains": ["x.com"]} not {"org_domain": "x.com"}.
    # Read domains[0] first; fall back to legacy org_domain key for older payloads.
    domains_list = payload.get("domains")
    if isinstance(domains_list, list) and domains_list:
        org_domain = str(domains_list[0])
    else:
        org_domain = payload.get("org_domain", "*")
    if not org_domain:
        org_domain = "*"

    # LAURA-LIMIT-DOMAINS-02: wildcard domain is only valid for Community and
    # Academic/Nonprofit tiers. Paid tiers (Starter, Professional, Professional Plus,
    # Enterprise) must have a specific domain binding. A wildcard on a paid tier means
    # the license was issued without domain binding and could be replayed to any deployment.
    if (
        valid
        and org_domain == "*"
        and tier not in (LicenseTier.COMMUNITY, LicenseTier.ACADEMIC_NONPROFIT)
    ):
        logger.warning(
            "License verifier: paid tier %r has wildcard org_domain — "
            "rejecting (LAURA-LIMIT-DOMAINS-02)",
            tier_str,
        )
        return _community_invalid("wildcard_domain_not_permitted_for_paid_tier")

    # Resolve limits with backwards-compat fallback to tier defaults.
    # _safe_int guards against null/None/empty/non-numeric values in any field
    # (LAURA-V231-002: null seat fields previously caused TypeError → DoS on boot).
    defaults = TIER_DEFAULTS.get(tier_str, TIER_DEFAULTS["community"])
    max_agents      = _safe_int(payload.get("max_agents"),                                       defaults["max_agents"])
    max_end_users   = _safe_int(payload.get("max_end_users", payload.get("max_users")),          defaults["max_end_users"])
    max_admin_seats = _safe_int(payload.get("max_admin_seats"),                                  defaults["max_admin_seats"])
    max_orgs        = _safe_int(payload.get("max_orgs"),                                         defaults["max_orgs"])

    # v5: licence_serial is the per-issued-licence identifier (design §3.2)
    # and maps onto the existing LicenseState.license_id field (v4's
    # per-token identifier concept — unchanged shape, renamed source field).
    license_id = payload.get("licence_serial") or payload.get("license_id")

    return LicenseState(
        tier=tier,
        org_domain=org_domain,
        max_agents=max_agents,
        max_end_users=max_end_users,
        max_admin_seats=max_admin_seats,
        max_orgs=max_orgs,
        features=features,
        issued_at=issued_at,
        expires_at=expires_at,
        license_id=license_id,
        valid=valid,
        error=error,
    )


def _community_invalid(error: str) -> LicenseState:
    """Return a typed invalid LicenseState using community defaults."""
    d = TIER_DEFAULTS["community"]
    return LicenseState(
        tier=LicenseTier.COMMUNITY,
        org_domain="*",
        max_agents=d["max_agents"],
        max_end_users=d["max_end_users"],
        max_admin_seats=d["max_admin_seats"],
        max_orgs=d["max_orgs"],
        features=frozenset(),
        issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        expires_at=None,
        license_id=None,
        valid=False,
        error=error,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_license(content: str) -> LicenseState:
    """
    Verify a license string and return a LicenseState.

    Format detection:
        4 dot-separated segments → v5 (payload + leaf_sig + leaf_cert +
                                   leaf_cert_sig) — the ONLY accepted format
        3 or 2 segments          → rejected: "license_format_deprecated_v5_required"
                                   (v3/v4 dropped — no downgrade path, design §3.2)
        Anything else            → fail-open (COMMUNITY_LICENSE)

    Security behaviour:
        - v5 licences: chain.verify_licence_v5() runs the full §4b sequence
          (role check, anchor-chain validation, kill-list, client_id bind,
          leaf_sig verify, own-term expiry). Any failure returns
          LicenseState(valid=False, error=<specific>) — COMMUNITY tier,
          never block, never delete users (§5).
        - Tampered build (integrity violation at module load): all licenses
          are downgraded to COMMUNITY tier regardless of licence validity.

    Returns COMMUNITY_LICENSE for empty/garbage content that doesn't even
    split into segments.
    Returns LicenseState(valid=False, error="license_format_deprecated_v5_required")
    for 2- or 3-segment (old v3/v4) licences.
    Returns LicenseState(valid=False, error=<see chain.licence_v5 error codes>)
    for v5 licences that fail any §4b check.
    Returns LicenseState(valid=False, error="license_expired") for expired licences.

    Requires: cryptography>=42.
    """
    # If the build itself has been tampered with, deny all non-community access.
    if _integrity_violated:
        return COMMUNITY_LICENSE

    content = content.strip()
    if not content:
        return COMMUNITY_LICENSE

    segments = content.split(".")
    if len(segments) == 4:
        return _verify_v5(content)
    elif len(segments) in (2, 3):
        # v3/v4 dropped — v5 mandatory, no downgrade path (design §3.2).
        logger.warning(
            "License verifier: rejected %d-segment license — only v5 (4-segment) "
            "format is accepted; v3/v4 are no longer supported (re-issue in v5)",
            len(segments),
        )
        return _community_invalid("license_format_deprecated_v5_required")
    else:
        logger.warning("License verifier: unexpected segment count (%d) in license content", len(segments))
        return COMMUNITY_LICENSE


def _verify_v5(content: str) -> LicenseState:
    """Verify a v5 license via the chain-of-trust (§4b)."""
    anchor_set = _load_anchor_set()
    kill_list = _load_kill_list()
    client_domain_registry = _load_client_domain_registry()

    try:
        result = verify_licence_v5(
            content,
            anchor_set=anchor_set,
            kill_list=kill_list,
            client_domain_registry=client_domain_registry,
        )
    except Exception as exc:
        # LAURA-V231-002 discipline: any uncaught exception during v5 verify
        # must not crash the caller — fail-closed to COMMUNITY.
        logger.warning("License verifier: unexpected error during v5 verification: %s", exc)
        return COMMUNITY_LICENSE

    if result.payload is None:
        # Parse-level failure — nothing usable to build a LicenseState from.
        return _community_invalid(result.error or "licence_format_invalid")

    if not result.valid:
        try:
            return _build_license_state(result.payload, valid=False, error=result.error)
        except Exception:
            return _community_invalid(result.error or "invalid_licence")

    return _parse_and_finalise_v5(result.payload)


def _parse_and_finalise_v5(payload: dict) -> LicenseState:
    """Build the final LicenseState after all v5 chain checks passed.

    Re-applies the licence's own expiry as a defence-in-depth belt-and-
    braces check (verify_licence_v5() already checked this at step 7; this
    mirrors v4's _parse_and_finalise() shape so LicenseState.error is
    populated identically for callers that branch on it)."""
    try:
        license_state = _build_license_state(payload, valid=True)
    except Exception as exc:
        # Defensive catch: _build_license_state should not raise with _safe_int in place,
        # but guard against any future field additions or model changes (LAURA-V231-002).
        logger.warning(
            "License verifier: unexpected error building license state after valid v5 "
            "verification: %s — failing to COMMUNITY tier",
            exc,
        )
        return COMMUNITY_LICENSE

    if license_state.is_expired():
        return LicenseState(
            tier=license_state.tier,
            org_domain=license_state.org_domain,
            max_agents=license_state.max_agents,
            max_end_users=license_state.max_end_users,
            max_admin_seats=license_state.max_admin_seats,
            max_orgs=license_state.max_orgs,
            features=license_state.features,
            issued_at=license_state.issued_at,
            expires_at=license_state.expires_at,
            license_id=license_state.license_id,
            valid=False,
            error="license_expired",
        )

    return license_state
