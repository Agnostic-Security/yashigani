"""
YTF Tier-A — mechanical wiring/config audit.

Static grep/AST checks that catch the INTEGRATION-SEAM bug class that
per-endpoint conformance tests structurally cannot see: a handler wired to
one env var but not its peer service, a hardcoded version-tag fallback that
silently diverges from the real pinned version, two datastores standing in
for what production treats as one (or vice versa), dead stub branches, and
security flags that are quietly permissive by default. This is Iris's own
"intersection plane" audit, expressed as pytest so it runs in every Tier-A
invocation, on every commit, matrix-invariant (no stack required).

Convention: every check either (a) asserts a documented, evidence-backed
finding IS still present (a regression guard proving the check works, mirrors
tests/security/test_pentest_regression_table.py's F1-F4 style), or (b) fails
loudly with file:line evidence when a genuinely NEW anti-pattern instance
appears that isn't in the checked-in allowlist below. NEVER a blanket
`assert True` / swallow-and-pass — a check that can't fail is not an audit.

Framework-build discipline (Iris dispatch brief, YTF 2026-07-29): this module
BUILDS AND RUNS the audit and reports what it finds. It does NOT fix product
code. Every finding below is routed to its owning specialist in the module
docstring, not silently patched here.

Last updated: 2026-07-29.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.conformance

REPO_ROOT = Path(__file__).parents[2]
SRC = REPO_ROOT / "src" / "yashigani"
DOCKER_DIR = REPO_ROOT / "docker"
HELM_DIR = REPO_ROOT / "helm"


def _iter_py_files(root: Path):
    return sorted(p for p in root.rglob("*.py") if "test" not in p.parts and "__pycache__" not in p.parts)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Check 1 — dark-default security flags: os.environ.get(<ENFORCE/VERIFY/
# REQUIRE/MTLS/AUTH/STRICT flag>, "false") means the control is OFF unless an
# operator explicitly opts in. Each instance needs an explicit sign-off (some
# are legitimately opt-in features); anything NOT in the allowlist is new and
# blocks the audit until reviewed (route to Tom + Lu).
# ---------------------------------------------------------------------------

_DARK_DEFAULT_RE = re.compile(
    r'os\.(?:environ|getenv)\.?get?\(\s*["\'][A-Z0-9_]*'
    r'(?:ENFORCE|VERIFY|REQUIRE|MTLS|AUTH|STRICT)[A-Z0-9_]*["\']\s*,\s*["\']false["\']',
)

# FINDING W2 (2026-07-29, Iris YTF audit): YASHIGANI_PERMISSION_STRICT
# defaults OFF. Two call sites, same flag. Not fixed here — route to Tom/Lu
# for a signed-off decision on whether "off by default" is the intended
# posture for this specific permission-strictness knob (it gates a
# tightening behaviour, not a base auth/mTLS control, so off-by-default MAY
# be correct — needs an explicit owner decision, not a silent audit-pass).
_KNOWN_DARK_DEFAULTS = {
    ("src/yashigani/gateway/openai_router.py", "YASHIGANI_PERMISSION_STRICT"),
}


def _find_dark_defaults() -> list[tuple[str, int, str]]:
    hits = []
    for path in _iter_py_files(SRC):
        rel = str(path.relative_to(REPO_ROOT))
        for i, line in enumerate(_read(path).splitlines(), start=1):
            if _DARK_DEFAULT_RE.search(line):
                m = re.search(r'["\']([A-Z0-9_]+)["\']', line)
                varname = m.group(1) if m else "?"
                hits.append((rel, i, varname))
    return hits


def test_dark_default_security_flags_are_all_known():
    """Every os.environ.get(<security-flag>, "false") dark-default must be in
    the reviewed allowlist. A NEW one appearing means a security-relevant
    control just landed permissive-by-default without a sign-off — fail
    loudly, don't silently accept it."""
    hits = _find_dark_defaults()
    unknown = [(rel, ln, var) for (rel, ln, var) in hits if (rel, var) not in _KNOWN_DARK_DEFAULTS]
    assert not unknown, (
        f"NEW unreviewed dark-default security flag(s) found: {unknown} — "
        "route to Tom+Lu for an explicit off-by-default sign-off before "
        "adding to _KNOWN_DARK_DEFAULTS."
    )
    # Regression guard: the known ones must still be present and unchanged —
    # if YASHIGANI_PERMISSION_STRICT's default flips to "true" or the line is
    # removed, this fails too (proves the check isn't a fossil).
    known_rels_vars = {(rel, var) for (rel, ln, var) in hits}
    assert _KNOWN_DARK_DEFAULTS <= known_rels_vars, (
        "A previously-known dark-default flag disappeared or changed shape — "
        "re-verify before removing it from _KNOWN_DARK_DEFAULTS (may indicate "
        "the flag was fixed, in which case update this allowlist, don't just "
        "delete the assertion)."
    )


# ---------------------------------------------------------------------------
# Check 2 — hardcoded version-tag fallbacks (YSG-RISK-123 class): a literal
# "yashigani/<service>:<version>" fallback baked into product code, reachable
# whenever the corresponding env var is unset. These are dangerous precisely
# because they're normally masked (install.sh/compose/helm always set the
# var) — the same shape as YSG-RISK-123's extractor:2.26.0 gap.
# ---------------------------------------------------------------------------

_IMAGE_TAG_RE = re.compile(r'"yashigani/([a-z0-9_-]+):(\d+\.\d+\.\d+)"')

_PYPROJECT_VERSION = re.search(
    r'^\s*version\s*=\s*"([^"]+)"', _read(REPO_ROOT / "pyproject.toml"), re.MULTILINE
).group(1)

# FINDING W1 (2026-07-29, Iris YTF audit): src/yashigani/documents/sandbox.py
# DEFAULT_IMAGE is hardcoded to "yashigani/extractor:2.26.0" — stale (current
# pinned version is 4.1.2; 2.26 predates the 3.0 rename entirely, see
# MEMORY project_yashigani_v50_scope_and_build.md history). This is the SAME
# class as YSG-RISK-123 (the K8s leg of this exact fallback was fixed by
# YSG-RISK-123b — helm/yashigani/templates/gateway.yaml now wires
# YASHIGANI_EXTRACTOR_IMAGE explicitly — but the Python constant itself, the
# fallback of last resort if that env var is ever unset on ANY runtime
# (compose included), was never bumped). Compounding drift: compose's OWN
# fallback for the same image (docker/docker-compose.extractor.yml:33,61)
# is "yashigani/extractor:${YASHIGANI_VERSION:-4.1.0}" — a DIFFERENT stale
# value (4.1.0) than sandbox.py's 2.26.0. Two unreachable-in-practice
# fallbacks for the same image, agreeing with neither each other nor the
# real pinned version. Not fixed here (framework-build only) — route to
# Captain (owns image provenance / YSG-RISK-123 lineage) + Su (compose
# fallback literal).
_KNOWN_STALE_IMAGE_FALLBACKS = {
    ("src/yashigani/documents/sandbox.py", "extractor", "2.26.0"),
}


def test_hardcoded_image_tag_fallbacks_are_all_known_and_flagged_stale():
    """Every hardcoded "yashigani/<svc>:<ver>" literal fallback in product
    Python code must be in the reviewed allowlist, AND (this is the actual
    audit value) must be flagged if it no longer matches pyproject's pinned
    version — proving the fallback is stale, not just present."""
    hits: list[tuple[str, str, str]] = []
    for path in _iter_py_files(SRC):
        rel = str(path.relative_to(REPO_ROOT))
        for m in _IMAGE_TAG_RE.finditer(_read(path)):
            hits.append((rel, m.group(1), m.group(2)))

    unknown = [h for h in hits if h not in _KNOWN_STALE_IMAGE_FALLBACKS]
    assert not unknown, (
        f"NEW hardcoded image-tag fallback(s) found, not yet triaged: {unknown} "
        "— route to Captain for a live-version-tracking decision before "
        "adding to _KNOWN_STALE_IMAGE_FALLBACKS."
    )

    stale = [h for h in hits if h[2] != _PYPROJECT_VERSION]
    assert stale, (
        "Expected the known extractor fallback to still be stale relative to "
        f"pyproject version {_PYPROJECT_VERSION} — if someone bumped it to "
        "match, update _KNOWN_STALE_IMAGE_FALLBACKS (good news) rather than "
        "deleting this assertion."
    )


def test_compose_and_python_extractor_fallback_versions_agree():
    """FINDING W1's cross-manifest half: compose's own last-resort fallback
    for the extractor image (docker/docker-compose.extractor.yml) and
    sandbox.py's DEFAULT_IMAGE constant are two independent sources of truth
    for the SAME unreachable-fallback concept. This assertion documents that
    they currently DISAGREE (4.1.0 vs 2.26.0) — a real, live cross-manifest
    drift, not a hypothetical. Route to Su+Captain: either wire both from one
    source (preferred) or bump both to the same, current value."""
    compose_file = DOCKER_DIR / "docker-compose.extractor.yml"
    compose_text = _read(compose_file)
    compose_fallback = re.search(
        r"yashigani/extractor:\$\{YASHIGANI_VERSION:-([0-9.]+)\}", compose_text
    )
    assert compose_fallback, "compose extractor fallback pattern not found — sandbox.py:DEFAULT_IMAGE drift check needs updating, not silently dropped"

    py_fallback = re.search(_IMAGE_TAG_RE, _read(SRC / "documents" / "sandbox.py"))
    assert py_fallback, "sandbox.py DEFAULT_IMAGE literal not found — re-verify before trusting this check"

    compose_ver = compose_fallback.group(1)
    py_ver = py_fallback.group(2)
    assert compose_ver != py_ver, (
        f"compose fallback ({compose_ver}) and sandbox.py fallback ({py_ver}) "
        "now AGREE — if this was a deliberate fix, great: update this test to "
        "assert equality instead of documenting the drift."
    )


# ---------------------------------------------------------------------------
# Check 3 — dead catch-all stub endpoints: routes that ALWAYS return a fixed/
# fake payload regardless of real state, self-documented as such. Scoped
# narrowly to the two NAMED examples (broad "not wired" / NotImplementedError
# regex scanning was tried first and produced 13 false positives — every hit
# was a legitimate fail-closed/lazy-init defensive guard, e.g.
# "agent_registry not wired — reconcile skipped", NOT a dead stub. That
# broad check is dropped as noise, not shipped as a 0-tolerance gate).
# ---------------------------------------------------------------------------

_KNOWN_PERMANENT_STUBS = {
    # (file, route decorator line substring, must-contain marker)
    ("src/yashigani/backoffice/routes/budget.py", '@router.get("/tree")',
     "Placeholder — will be populated from Postgres in integration"),
    ("src/yashigani/backoffice/routes/user_ui.py", '@router.get("/user/memory")',
     "Phase 3"),
}


def test_named_permanent_stubs_are_still_tracked_not_silently_wired():
    """Regression/graduation guard for the two NAMED dead-stub endpoints
    (GET /admin/budget/tree, GET /user/memory) called out in the YTF dispatch
    brief. Asserts each is STILL self-documented as a stub. If either gets
    properly wired to real state, this test will fail — at which point
    update _KNOWN_PERMANENT_STUBS (good news, not a check to just delete)."""
    for rel, decorator_line, marker in _KNOWN_PERMANENT_STUBS:
        text = _read(REPO_ROOT / rel)
        assert decorator_line in text, f"{rel}: expected route {decorator_line} not found — re-verify before trusting this check"
        idx = text.index(decorator_line)
        window = text[idx: idx + 1200]
        assert marker in window, (
            f"{rel} route {decorator_line}: expected stub marker "
            f"{marker!r} not found within 1200 chars of the route decorator — "
            "either the stub was wired to real state (update this test) or "
            "the self-documentation was removed without wiring it (worse — "
            "route to Tom immediately)."
        )


# ---------------------------------------------------------------------------
# Check 4 — env-var cross-manifest presence: a curated set of env vars that
# MUST be wired identically on every service manifest that references the
# concept, WITHIN a given runtime family. Catches the "122 BUDGET_REDIS_HOST
# on one service manifest but not its peers" class. This is a REGRESSION
# GUARD for an already-fixed bug (YSG-RISK-122) — it currently passes,
# proving the fix holds; it exists so a future edit that re-drops the var
# from one manifest fails the build immediately.
#
# Verified against the actual YSG-RISK-122 commit (495351e8): the fix is
# explicitly K8s-only ("No-op on compose — redis up at boot" per the merge
# commit message) — compose's flat network gives budget-redis a stable,
# already-correct hostname at boot with no race, so BUDGET_REDIS_HOST is
# legitimately absent from docker-compose.yml BY DESIGN, not by omission.
# The peer set below is therefore Helm-only (backoffice.yaml + gateway.yaml —
# the original 122 gap was specifically gateway.yaml missing it while
# backoffice.yaml had it).
# ---------------------------------------------------------------------------

_CROSS_MANIFEST_VARS = {
    "BUDGET_REDIS_HOST": {
        "helm": [HELM_DIR / "yashigani" / "templates" / "backoffice.yaml",
                 HELM_DIR / "yashigani" / "templates" / "gateway.yaml"],
    },
}


def test_budget_redis_host_wired_on_every_declared_peer_manifest():
    """YSG-RISK-122 regression guard: BUDGET_REDIS_HOST must be present on
    every K8s manifest declared as a peer for this var (BOTH the backoffice
    AND gateway Helm templates — the original 122 gap was gateway.yaml
    missing it while backoffice.yaml had it). Compose is deliberately NOT
    checked here (see module note: 122 is a documented K8s-only fix)."""
    for var, manifests in _CROSS_MANIFEST_VARS.items():
        missing = []
        for kind, paths in manifests.items():
            for p in paths:
                if not p.exists():
                    missing.append(f"{p} (FILE MISSING)")
                    continue
                if var not in _read(p):
                    missing.append(str(p.relative_to(REPO_ROOT)))
        assert not missing, f"{var} missing from declared peer manifest(s): {missing}"
