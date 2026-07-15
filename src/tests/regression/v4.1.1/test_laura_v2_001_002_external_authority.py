"""
Regression tests — LAURA-V2-001 (CRITICAL) / LAURA-V2-002 (HIGH) fixes.

Ref: testing_runs/yashigani/licence-v2-redteam-laura-hack-20260715T211215Z.md
     AgnosticSecurity/Products/Yashigani/licence-hardening-v2-design-20260713.md §11

LAURA-V2-001 root causes closed:
  (1) require_feature()/check_*_limit() never consulted any integrity flag —
      they read the raw `_license` module-global directly. Fixed: they now
      call get_license(), which fails closed to COMMUNITY_LICENSE whenever
      ANY of the 5 integrity flags is set.
  (2) Every module's self-check lived INSIDE the file it protects, so one
      coordinated edit to enforcer.py could neuter both the gate
      (require_feature()) and its own checker (_check_enforcer_integrity())
      with zero external evidence. Fixed: verifier.py (a separate file) now
      independently re-derives live SHA-256 hashes of every protected file
      from disk at its own module-load time.
  (3) BUNDLE_SIG only ever covered the STATIC _integrity.py hash constants
      (a tautology), never live file bytes. Fixed:
      verifier._compute_live_hash_bundle_str() builds the signed bundle from
      LIVE re-derived hashes; BUNDLE_SIG is verified against THAT.

LAURA-V2-002 root causes closed:
  KILL_LIST_JSON (and CLIENT_DOMAIN_REGISTRY_JSON / MASTER_ANCHOR_SET_JSON /
  CODE_LEAF_CERT_JSON / CODE_LEAF_CERT_SIG) were outside the signed bundle —
  editing KILL_LIST_JSON alone (no crypto) silently un-revoked a licence.
  Fixed: INTEGRITY_HASH is now a REAL, wired self-hash of the entire
  _integrity.py file (blank-then-hash convention) folded in as the bundle's
  6th signed line — any edit to those fields, without a matching re-sign,
  is now detected.

This file replicates Laura's exact PoC diffs (verified byte-for-byte against
testing_runs/yashigani/licence-v2-redteam-scratch/attack{1,2,3}-*/) against
the FIXED code and documents the honest outcome for each.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from yashigani.licensing.chain import Alg, LeafCert, Role
from yashigani.licensing.chain.algorithms import sign_message
from yashigani.licensing.chain.canonical import bundle_signing_digest, leaf_cert_signing_digest


def _gen_p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def _pem_pub(key: ec.EllipticCurvePrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _anchor_set_json(master_key: ec.EllipticCurvePrivateKey) -> str:
    return json.dumps([{
        "anchor_id": "M1",
        "pubkey_pem": _pem_pub(master_key),
        "alg": Alg.ECDSA_P384_SHA384.value,
        "status": "active",
        "added": _now().isoformat(),
    }])


def _make_code_leaf(master_key: ec.EllipticCurvePrivateKey):
    code_key = _gen_p384()
    now = _now()
    leaf = LeafCert(
        role=Role.CODE, client_id="*", release="4.1.1", leaf_pubkey_pem=_pem_pub(code_key),
        not_before=now - timedelta(days=1), not_after=now + timedelta(days=60),
        serial="code-leaf-4.1.1", signed_at=now, alg=Alg.ECDSA_P384_SHA384,
    )
    sig = sign_message(Alg.ECDSA_P384_SHA384, master_key, leaf_cert_signing_digest(leaf.to_canonical_dict()))
    return leaf, sig, code_key


# Minimal, realistic _integrity.py-shaped source text — enough for the
# blank-then-hash regex (INTEGRITY_HASH / BUNDLE_SIG lines) to match, and for
# KILL_LIST_JSON to be independently editable, mirroring the real module's
# constant-assignment-line format exactly.
_SYNTHETIC_INTEGRITY_PY_TEMPLATE = '''"""Synthetic _integrity.py for regression testing."""
from __future__ import annotations

MASTER_ANCHOR_SET_JSON: str = {anchor_set!r}
CODE_LEAF_CERT_JSON: str = {leaf_cert!r}
CODE_LEAF_CERT_SIG: str = {leaf_cert_sig!r}
KILL_LIST_JSON: str = {kill_list!r}
CLIENT_DOMAIN_REGISTRY_JSON: str = "{{}}"
INTEGRITY_HASH: str = "{integrity_hash}"
BUNDLE_SIG: str = "{bundle_sig}"
'''


def _write_synthetic_integrity_py(
    path: Path, anchor_set: str, leaf_cert: str, leaf_cert_sig: str, kill_list: str,
    integrity_hash: str = "0" * 64, bundle_sig: str = "",
) -> None:
    path.write_text(
        _SYNTHETIC_INTEGRITY_PY_TEMPLATE.format(
            anchor_set=anchor_set, leaf_cert=leaf_cert, leaf_cert_sig=leaf_cert_sig,
            kill_list=kill_list, integrity_hash=integrity_hash, bundle_sig=bundle_sig,
        ),
        encoding="utf-8",
    )


@pytest.fixture()
def _live_hash_env(tmp_path, monkeypatch):
    """
    Build a fully self-consistent, correctly-signed "build" using the SAME
    live-re-derivation machinery _check_build_integrity_chain() uses in
    production, but with every target path redirected to tmp files this
    test controls — so we can deterministically tamper with ONE file
    (exactly mirroring Laura's PoC on the real enforcer.py) and observe
    detection, without touching the actual checked-out source tree.

    Returns a dict of helpers/paths the individual tests use.
    """
    import yashigani.licensing._integrity as integrity_mod
    import yashigani.licensing.verifier as verifier_mod

    # T1-T4 + point-of-use (POU) "protected files" — start as clean, arbitrary
    # content. POU files added 2026-07-16 (LAURA-V2-001 follow-up) — see
    # verifier._LIVE_HASH_TARGETS / _integrity.py module docstring.
    targets = {}
    for name, content in [
        ("VERIFIER_HASH", "# verifier.py contents (unpatched)\n"),
        ("ENFORCER_HASH", "# enforcer.py contents (unpatched)\n"),
        ("LOADER_HASH", "# loader.py contents (unpatched)\n"),
        ("AGENTS_REGISTRY_HASH", "# agents/registry.py contents (unpatched)\n"),
        ("IDENTITY_REGISTRY_HASH", "# identity/registry.py contents (unpatched)\n"),
        ("OIDC_MODULE_HASH", "# sso/oidc.py contents (unpatched)\n"),
        ("SAML_MODULE_HASH", "# sso/saml.py contents (unpatched)\n"),
        ("SSO_ROUTES_HASH", "# backoffice/routes/sso.py contents (unpatched)\n"),
        ("SCIM_ROUTES_HASH", "# backoffice/routes/scim.py contents (unpatched)\n"),
        ("GATE_MIDDLEWARE_HASH", "# licensing/gate_middleware.py contents (unpatched)\n"),
    ]:
        p = tmp_path / f"{name}.py"
        p.write_text(content, encoding="utf-8")
        targets[name] = p
        monkeypatch.setitem(verifier_mod._LIVE_HASH_TARGETS, name, p)

    integrity_py_path = tmp_path / "_integrity.py"
    monkeypatch.setattr(verifier_mod, "_INTEGRITY_PY_PATH", integrity_py_path)

    master_key = _gen_p384()
    code_leaf, code_leaf_sig, code_key = _make_code_leaf(master_key)

    def _sign_and_embed(kill_list_json: str = "[]") -> None:
        """(Re)compute live hashes from the CURRENT tmp files, fold
        INTEGRITY_HASH in, sign the 6-line bundle with the code leaf, and
        embed everything into _integrity.py — exactly what a legitimate
        build (inject_hashes.sh) would do."""
        anchor_set_json = _anchor_set_json(master_key)
        leaf_cert_json = json.dumps(code_leaf.to_canonical_dict())
        leaf_cert_sig_b64 = base64.b64encode(code_leaf_sig).decode()

        # Write _integrity.py with placeholder INTEGRITY_HASH/BUNDLE_SIG first
        # (their values are blanked by the algorithm anyway, so any content
        # works), then compute INTEGRITY_HASH from what's now on disk.
        _write_synthetic_integrity_py(
            integrity_py_path, anchor_set_json, leaf_cert_json, leaf_cert_sig_b64, kill_list_json,
        )
        integrity_text = integrity_py_path.read_text(encoding="utf-8")
        integrity_hash = verifier_mod._compute_integrity_self_hash(integrity_text)

        live_bundle_str, live_hashes = verifier_mod._compute_live_hash_bundle_str()
        assert live_bundle_str is not None
        # Sanity: our own independently-computed INTEGRITY_HASH must equal
        # what _compute_live_hash_bundle_str() derived from the same file.
        assert live_hashes["INTEGRITY_HASH"] == integrity_hash

        bundle_sig = sign_message(Alg.ECDSA_P384_SHA384, code_key, bundle_signing_digest(live_bundle_str))
        bundle_sig_b64 = base64.b64encode(bundle_sig).decode()

        _write_synthetic_integrity_py(
            integrity_py_path, anchor_set_json, leaf_cert_json, leaf_cert_sig_b64, kill_list_json,
            integrity_hash=integrity_hash, bundle_sig=bundle_sig_b64,
        )

        monkeypatch.setattr(integrity_mod, "MASTER_ANCHOR_SET_JSON", anchor_set_json)
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_JSON", leaf_cert_json)
        monkeypatch.setattr(integrity_mod, "CODE_LEAF_CERT_SIG", leaf_cert_sig_b64)
        monkeypatch.setattr(integrity_mod, "KILL_LIST_JSON", kill_list_json)
        monkeypatch.setattr(integrity_mod, "CLIENT_DOMAIN_REGISTRY_JSON", "{}")
        monkeypatch.setattr(integrity_mod, "INTEGRITY_HASH", integrity_hash)
        monkeypatch.setattr(integrity_mod, "BUNDLE_SIG", bundle_sig_b64)
        for name, path in targets.items():
            monkeypatch.setattr(integrity_mod, name, hashlib.sha256(path.read_bytes()).hexdigest())

        monkeypatch.setattr(verifier_mod, "_integrity_violated", False)

    return {
        "targets": targets,
        "integrity_py_path": integrity_py_path,
        "sign_and_embed": _sign_and_embed,
        "verifier_mod": verifier_mod,
    }


class TestLauraV2001EnforcerNeuterNowAlarms:
    """LAURA-V2-001 — replicates both of Laura's PoC variants (attack1
    'smart' = checker + gate both neutered; attack2 'naive' = gate only,
    checker left intact) against the FIXED external-authority mechanism."""

    def test_clean_build_no_violation(self, _live_hash_env):
        _live_hash_env["sign_and_embed"]()
        vm = _live_hash_env["verifier_mod"]
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is False

    def test_smart_variant_enforcer_tamper_detected_externally(self, _live_hash_env):
        """attack1-enforcer-neuter: enforcer.py edited (both
        _check_enforcer_integrity() AND require_feature() neutered in one
        coordinated edit — exact same file Laura patched). verifier.py never
        sees or depends on enforcer.py's in-process state; it re-reads
        enforcer.py's bytes off disk independently. Must now flag tamper —
        this is the 'zero alarm' bug LAURA-V2-001 reported, now closed."""
        _live_hash_env["sign_and_embed"]()
        vm = _live_hash_env["verifier_mod"]

        # Baseline: signed and clean.
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is False

        # Simulate Laura's exact "smart" patch: enforcer.py's bytes on disk
        # change (require_feature + _check_enforcer_integrity bodies
        # replaced with `return`) WITHOUT re-signing (attacker has no code
        # leaf private key).
        enforcer_target = _live_hash_env["targets"]["ENFORCER_HASH"]
        enforcer_target.write_text(
            "# enforcer.py contents (PATCHED: require_feature + "
            "_check_enforcer_integrity both neutered — attack1)\n",
            encoding="utf-8",
        )

        vm._integrity_violated = False
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is True, (
            "LAURA-V2-001 regression: enforcer.py tamper must be detected "
            "externally by verifier.py even when enforcer.py's own checker "
            "was also neutered in the same edit"
        )

    def test_naive_variant_gate_only_still_detected(self, _live_hash_env):
        """attack2-naive-gate-only: only require_feature() edited, checker
        left intact. Laura's finding: the checker DID fire, but
        require_feature() didn't consult it — 'the banner doesn't gate
        anything either'. Root-cause (a) fix (require_feature() now calls
        get_license()) is exercised in TestRequireFeatureConsultsIntegrity
        below; this test proves the EXTERNAL alarm dimension holds
        identically for the naive variant too (any edit to enforcer.py's
        bytes is caught, regardless of which functions within it changed)."""
        _live_hash_env["sign_and_embed"]()
        vm = _live_hash_env["verifier_mod"]

        vm._check_build_integrity_chain()
        assert vm._integrity_violated is False

        enforcer_target = _live_hash_env["targets"]["ENFORCER_HASH"]
        enforcer_target.write_text(
            "# enforcer.py contents (PATCHED: require_feature neutered only, "
            "checker left intact — attack2)\n",
            encoding="utf-8",
        )

        vm._integrity_violated = False
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is True


class TestRequireFeatureConsultsIntegrity:
    """LAURA-V2-001 root cause (a): require_feature()/check_*_limit()
    previously read the raw `_license` global directly, never consulting
    any integrity flag. Now routes through get_license(), which fails
    closed to COMMUNITY_LICENSE on any violation."""

    def test_require_feature_denies_when_verifier_flags_tamper(self, monkeypatch):
        import yashigani.licensing.enforcer as enforcer_mod
        import yashigani.licensing.verifier as verifier_mod
        from yashigani.licensing.model import LicenseFeature, LicenseState, LicenseTier

        paid_license = LicenseState(
            tier=LicenseTier.PROFESSIONAL, org_domain="acme.example.com",
            max_agents=500, max_end_users=1000, max_admin_seats=50, max_orgs=1,
            features=frozenset({LicenseFeature.OIDC}),
            issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc), expires_at=None,
            license_id="lic-0001", valid=True, error=None,
        )

        original_license = enforcer_mod._license
        try:
            enforcer_mod.set_license(paid_license)

            # Sanity: with NO integrity violation, the paid feature is granted.
            monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
            monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
            enforcer_mod.require_feature("oidc")  # must not raise

            # Now flag a verifier-side integrity violation (e.g. loader.py or
            # verifier.py itself was tampered — a DIFFERENT file from
            # enforcer.py, which is never touched in this test). Before the
            # fix, require_feature() ignored this entirely because it read
            # `_license` directly.
            monkeypatch.setattr(verifier_mod, "_integrity_violated", True)
            with pytest.raises(enforcer_mod.LicenseFeatureGated):
                enforcer_mod.require_feature("oidc")
        finally:
            enforcer_mod._license = original_license

    def test_check_agent_limit_denies_when_integrity_violated(self, monkeypatch):
        import yashigani.licensing.enforcer as enforcer_mod
        import yashigani.licensing.verifier as verifier_mod
        from yashigani.licensing.model import LicenseState, LicenseTier

        unlimited_license = LicenseState(
            tier=LicenseTier.ENTERPRISE, org_domain="acme.example.com",
            max_agents=-1, max_end_users=-1, max_admin_seats=-1, max_orgs=-1,
            features=frozenset(),
            issued_at=datetime(2020, 1, 1, tzinfo=timezone.utc), expires_at=None,
            license_id="lic-ent", valid=True, error=None,
        )
        try:
            enforcer_mod.set_license(unlimited_license)
            monkeypatch.setattr(verifier_mod, "_integrity_violated", False)
            monkeypatch.setattr(enforcer_mod, "_enforcer_integrity_violated", False)
            enforcer_mod.check_agent_limit(1_000_000)  # unlimited — must not raise

            monkeypatch.setattr(verifier_mod, "_integrity_violated", True)
            with pytest.raises(enforcer_mod.LicenseLimitExceeded):
                # COMMUNITY_LICENSE.max_agents == 20 once integrity is violated.
                enforcer_mod.check_agent_limit(20)
        finally:
            enforcer_mod.set_license(unlimited_license)


class TestLauraV2002KillListEditDetected:
    """LAURA-V2-002 — replicates attack3-killlist-strip: KILL_LIST_JSON
    edited to '[]' without touching MASTER_ANCHOR_SET_JSON or re-signing.
    Previously silent (empty kill-list treated as a legitimate safe
    default). Now: INTEGRITY_HASH (folded into the signed bundle) covers
    the ENTIRE _integrity.py file including KILL_LIST_JSON, so this edit is
    detected."""

    def test_killlist_populated_build_clean(self, _live_hash_env):
        revoked_entry = json.dumps([{
            "namespace": "licence", "identifier": "lic-AgnosticSecurity-20260714222624",
            "revoked_at": _now().isoformat(), "semantics": "immediate", "reason": "chargeback",
        }])
        _live_hash_env["sign_and_embed"](kill_list_json=revoked_entry)
        vm = _live_hash_env["verifier_mod"]
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is False

    def test_killlist_stripped_without_resign_detected(self, _live_hash_env):
        """The exact attack: KILL_LIST_JSON edited from a populated list back
        to the 'safe default' "[]" — no other file touched, no re-signing
        (attacker has no code leaf private key)."""
        revoked_entry = json.dumps([{
            "namespace": "licence", "identifier": "lic-AgnosticSecurity-20260714222624",
            "revoked_at": _now().isoformat(), "semantics": "immediate", "reason": "chargeback",
        }])
        _live_hash_env["sign_and_embed"](kill_list_json=revoked_entry)
        vm = _live_hash_env["verifier_mod"]
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is False

        # Attacker edits ONLY the KILL_LIST_JSON line in the on-disk
        # _integrity.py — mirrors attack3-killlist-strip exactly. Note: the
        # `_integrity` module's cached Python attribute (KILL_LIST_JSON) is
        # NOT re-patched here — that models a fresh process re-importing the
        # tampered file from disk, which is when module-load checks run in
        # production. We simulate that fresh-import by re-running the check
        # against the mutated file's live bytes while leaving the (stale,
        # signed) constants as they were embedded — exactly what
        # _check_build_integrity_chain() would see on next process start.
        integrity_py_path = _live_hash_env["integrity_py_path"]
        text = integrity_py_path.read_text(encoding="utf-8")
        stripped = text.replace(
            f'KILL_LIST_JSON: str = {revoked_entry!r}',
            'KILL_LIST_JSON: str = \'[]\'',
        )
        assert stripped != text, "test setup bug: KILL_LIST_JSON line not found to strip"
        integrity_py_path.write_text(stripped, encoding="utf-8")

        vm._integrity_violated = False
        vm._check_build_integrity_chain()
        assert vm._integrity_violated is True, (
            "LAURA-V2-002 regression: stripping KILL_LIST_JSON without "
            "re-signing must be detected via the live INTEGRITY_HASH/"
            "BUNDLE_SIG re-derivation"
        )


class TestIntegrityHashAlgorithmRoundTrip:
    """inject_hashes.sh's Python heredoc implements the SAME blank-then-hash
    algorithm as verifier._compute_integrity_self_hash() independently (by
    design — the verify side must never import from the file it's
    verifying). This test proves the two stay byte-identical, so a future
    edit to one that isn't mirrored in the other is caught here rather than
    at release time."""

    def test_inject_hashes_sh_matches_verifier_algorithm(self, tmp_path):
        import subprocess
        import sys

        import yashigani.licensing.verifier as verifier_mod

        sample_integrity_py = _SYNTHETIC_INTEGRITY_PY_TEMPLATE.format(
            anchor_set="[]", leaf_cert="{}", leaf_cert_sig="AAAA", kill_list="[]",
            integrity_hash="deadbeef" * 8, bundle_sig="cafebabe" * 8,
        )
        sample_path = tmp_path / "_integrity_sample.py"
        sample_path.write_text(sample_integrity_py, encoding="utf-8")

        expected = verifier_mod._compute_integrity_self_hash(sample_integrity_py)

        # Extract the ACTUAL Python heredoc body from scripts/inject_hashes.sh
        # (never a hand-copied duplicate — a duplicate is exactly how the
        # 2026-07-15 regex drift slipped past unit tests undetected; only the
        # end-to-end run against a freshly signed real build caught it).
        script_path = Path(__file__).parents[4] / "scripts" / "inject_hashes.sh"
        script_text = script_path.read_text(encoding="utf-8")
        start_marker = "INTEGRITY_HASH=\"$(python3 - \"${INTEGRITY_PY}\" <<'PYEOF'\n"
        end_marker = "\nPYEOF\n"
        start = script_text.index(start_marker) + len(start_marker)
        end = script_text.index(end_marker, start)
        heredoc_body = script_text[start:end]
        assert len(heredoc_body) > 100, "heredoc extraction from inject_hashes.sh failed — markers drifted"

        result = subprocess.run(
            [sys.executable, "-c", heredoc_body, str(sample_path)],
            capture_output=True, text=True, check=True,
        )
        actual = result.stdout.strip()
        assert actual == expected, (
            "inject_hashes.sh's blank-then-hash algorithm has drifted from "
            "verifier._compute_integrity_self_hash() — these MUST stay "
            "byte-identical (build-time embed vs verify-time recompute)"
        )

    def test_blanking_handles_pristine_placeholder_expression_form(self):
        """Regression for the exact bug found via end-to-end verification
        against a freshly signed real build (2026-07-15): _integrity.py's
        PRISTINE (never-yet-built) source defines INTEGRITY_HASH/BUNDLE_SIG
        as a Python EXPRESSION (`_PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"`),
        not a bare string literal. A blanking regex that only matched
        `"[^"]*"` silently failed to blank that pristine form (no match =>
        no substitution => the literal placeholder-expression text stayed in
        the hashed bytes), while the SAME regex correctly matched and
        blanked the line once inject_hashes.sh had since written a real
        quoted value — producing two DIFFERENT digests for what must be the
        IDENTICAL blanked file, and a false-positive tamper report on every
        freshly-built, wholly untampered package. Every combination of
        pristine-expression / quoted-literal across both fields must blank
        to the SAME digest, since only the OTHER (unrelated) content
        changed."""
        import yashigani.licensing.verifier as verifier_mod

        other_const = 'VERIFIER_HASH: str = "abc123"\n'

        # State A: exactly scripts/inject_hashes.sh's Step-4 INPUT — T1-T4 +
        # chain constants already embedded (represented here by other_const),
        # but INTEGRITY_HASH and BUNDLE_SIG are STILL in their pristine,
        # never-built form.
        state_a = (
            other_const
            + 'INTEGRITY_HASH: str = _PLACEHOLDER_INTEGRITY + "_INTEGRITY_HASH"\n'
            + 'BUNDLE_SIG: str = _PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"\n'
        )

        # State B: same file, immediately after Step 4 writes the just-computed
        # INTEGRITY_HASH — BUNDLE_SIG is still pristine (Step 5 hasn't run yet).
        state_b = (
            other_const
            + 'INTEGRITY_HASH: str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"\n'
            + 'BUNDLE_SIG: str = _PLACEHOLDER_INTEGRITY + "_BUNDLE_SIG"\n'
        )

        # State C: same file, after Step 5 has also written a real BUNDLE_SIG
        # — this is the state verify-time (verifier.py) actually reads.
        state_c = (
            other_const
            + 'INTEGRITY_HASH: str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"\n'
            + 'BUNDLE_SIG: str = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe=="\n'
        )

        hash_a = verifier_mod._compute_integrity_self_hash(state_a)
        hash_b = verifier_mod._compute_integrity_self_hash(state_b)
        hash_c = verifier_mod._compute_integrity_self_hash(state_c)

        assert hash_a == hash_b == hash_c, (
            "Blanking must produce the IDENTICAL digest across the pristine-"
            "expression form (state A), the mid-injection form (state B), "
            "and the fully-injected quoted-literal form (state C) — "
            f"got a={hash_a!r} b={hash_b!r} c={hash_c!r}"
        )
