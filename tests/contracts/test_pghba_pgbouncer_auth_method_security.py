# Last updated: 2026-05-25T00:00:00+00:00 (cycle 6: YSG-RISK-073/075 auth-method security guard)
"""
pg_hba auth-method security contract test — YSG-RISK-073 / YSG-RISK-075.

This test module is the dedicated security guard against the class of bug documented
in YSG-RISK-075 (trust auth without CN binding): any `trust` carveout for
`pgbouncer_authenticator` that is NOT paired with a `map=` clause is a confirmed
security gap (Laura cycle 5 adversarial probe).

Attack chain (YSG-RISK-075):
  1. Attacker compromises any container on the `data` network that holds a CA-signed cert.
  2. Opens TLS to postgres:5432, asserts role `pgbouncer_authenticator`, presents stolen cert.
  3. CA validates → `trust` accepts (CA-only check; no CN check; no password).
  4. `SELECT ysg_pgbouncer_get_auth('yashigani_app')` returns SCRAM verifier from pg_shadow.
  5. Verifier used to authenticate as yashigani_app → full DB read/write.
  Blast radius: CRITICAL — all tenant data, audit logs, RBAC tables.
  Probability: MEDIUM — 11 CA-cert holders on `data` network (gateway, backoffice, etc.)

Fix (cycle 6):
  `scram-sha-256 clientcert=verify-ca` — two-factor: cert (CA chain + private key) + password.
  An attacker who steals a CA-signed cert from another service cannot authenticate without
  the pgbouncer_authenticator password (mounted as Docker/K8s secret to pgbouncer only).

This module asserts three invariants:
  1. `trust` does NOT appear as auth method for pgbouncer_authenticator UNLESS paired
     with a `map=` clause (which binds CN → role and narrows the cert pool).
  2. `scram-sha-256 clientcert=verify-ca` (or `map=`-bound trust) IS present.
  3. The Helm copy of 10-pgbouncer-auth.sh matches the docker copy on this invariant.

These are the forward-looking tests that catch the unmaped-trust class of bug.

YSG-RISK-073: pgbouncer_authenticator pg_hba carveout history.
YSG-RISK-075: trust-without-CN-binding class — lateral-pivot from CA-cert-holder to full DB.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

PGBOUNCER_AUTH_SCRIPT_DOCKER = REPO_ROOT / "docker" / "postgres" / "10-pgbouncer-auth.sh"
PGBOUNCER_AUTH_SCRIPT_HELM = REPO_ROOT / "helm" / "yashigani" / "files" / "10-pgbouncer-auth.sh"
ENABLE_SSL_SCRIPT = REPO_ROOT / "docker" / "postgres" / "05-enable-ssl.sh"

# The forbidden pattern: trust for pgbouncer_authenticator WITHOUT a map= clause.
# map= would bind the cert CN to the role name, which narrows the cert pool.
# Without map=, any CA-signed cert from any data-network service suffices.
_UNMAPPED_TRUST_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust(?!\s+clientcert[^\n]*\bmap=)",
    re.MULTILINE,
)

# The allowed pattern: scram-sha-256 + clientcert (two-factor, cycle 6 fix)
_SCRAM_CLIENTCERT_RE = re.compile(
    r"hostssl\s+yashigani\s+pgbouncer_authenticator\s+[\d.:a-fA-F/]+\s+scram-sha-256\s+clientcert=verify-ca",
)

# The allowed alternative: trust + clientcert + map= (CN-binding closes the lateral pivot)
_MAPPED_TRUST_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust\s+clientcert=[^\n]+\bmap=\S+",
    re.MULTILINE,
)


def _read(path: Path) -> str:
    assert path.exists(), f"Required file missing: {path}"
    return path.read_text()


def _extract_awk_printed_lines(content: str) -> list[tuple[int, str]]:
    """Extract lines that awk would print into pg_hba.conf.

    Returns list of (line_number, printed_content) tuples for lines in
    awk print statements that contain pgbouncer_authenticator.
    """
    results = []
    lines = content.splitlines()
    in_awk = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "awk '" in stripped or 'awk "' in stripped:
            in_awk = True
        if in_awk and ("' \"${_hba}\"" in line or "' \"${_tmp}\"" in line):
            in_awk = False
        if in_awk and stripped.startswith("print ") and "pgbouncer_authenticator" in stripped:
            # Extract the printed string content
            m = re.match(r'print\s+"([^"]*)"', stripped) or re.match(r"print\s+'([^']*)'", stripped)
            if m:
                results.append((i + 1, m.group(1)))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: `trust` without `map=` MUST NOT appear for pgbouncer_authenticator
# This is the class-of-bug guard. Catches the cycle 5 form and any regression.
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_no_unmapped_trust_for_pgbouncer_authenticator() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must not insert unmapped trust for pgbouncer_authenticator.

    YSG-RISK-075: `trust clientcert=verify-ca` without `map=` is a confirmed HIGH security gap.
    Any compromised container on the `data` network with a CA-signed cert can authenticate
    as pgbouncer_authenticator and extract SCRAM verifiers from pg_shadow.

    Allowed forms:
    - `scram-sha-256 clientcert=verify-ca` (two-factor — cycle 6 fix)
    - `trust clientcert=verify-ca map=<ident_map>` (CN-bound — option β, also acceptable)

    Forbidden:
    - `trust clientcert=verify-ca` (no map= — any CA cert works — YSG-RISK-075)
    - `trust` (bare — no cert at all — old A2 carveout)
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    # Check awk-inserted lines (the actual pg_hba carveout text)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        if "pgbouncer_authenticator" in text:
            # Forbidden: trust without map=
            if re.search(r"\btrust\b", text) and "map=" not in text:
                pytest.fail(
                    f"docker/postgres/10-pgbouncer-auth.sh line {lineno}: "
                    f"unmapped trust carveout for pgbouncer_authenticator: '{text}'. "
                    "YSG-RISK-075: trust without map= allows any CA-cert holder to impersonate "
                    "pgbouncer_authenticator → full DB compromise via ysg_pgbouncer_get_auth. "
                    "Use `scram-sha-256 clientcert=verify-ca` or `trust ... map=<ident_map>`."
                )


def test_helm_script_no_unmapped_trust_for_pgbouncer_authenticator() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must not insert unmapped trust for pgbouncer_authenticator.

    Same invariant as test_docker_script_no_unmapped_trust_for_pgbouncer_authenticator.
    Compose-Helm parity: both copies must be secure.
    YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        if "pgbouncer_authenticator" in text:
            if re.search(r"\btrust\b", text) and "map=" not in text:
                pytest.fail(
                    f"helm/yashigani/files/10-pgbouncer-auth.sh line {lineno}: "
                    f"unmapped trust carveout for pgbouncer_authenticator: '{text}'. "
                    "YSG-RISK-075: trust without map= allows any CA-cert holder to impersonate "
                    "pgbouncer_authenticator. Use `scram-sha-256 clientcert=verify-ca`."
                )


def test_enable_ssl_no_unmapped_trust_for_pgbouncer_authenticator() -> None:
    """05-enable-ssl.sh must not contain unmapped trust for pgbouncer_authenticator.

    BUG-C4-002 confirmed 05-enable-ssl.sh should NOT write any pgbouncer_authenticator carveout.
    This test additionally guards against a future regression where a trust carveout
    is accidentally re-added to 05-enable-ssl.sh. YSG-RISK-075.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _UNMAPPED_TRUST_RE.findall(content)
    assert not matches, (
        f"05-enable-ssl.sh: unmapped trust carveout for pgbouncer_authenticator found: {matches}. "
        "05-enable-ssl.sh must NOT write any pgbouncer_authenticator carveout (BUG-C4-002 fix). "
        "YSG-RISK-075: trust without map= is a confirmed security gap."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Either scram-sha-256 OR mapped-trust MUST be present (positive assertion)
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_has_secure_auth_method_for_pgbouncer_authenticator() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must use a secure auth method for pgbouncer_authenticator.

    A secure auth method is one that requires MORE than just a CA-signed cert:
    - scram-sha-256 clientcert=verify-ca (two-factor: cert + password) — preferred
    - trust clientcert=verify-ca map=<ident> (CN-bound: cert with CN check) — acceptable

    This test catches the case where NEITHER secure form is present (e.g., step 4b
    was removed or contains only bare trust).
    YSG-RISK-073 cycle 6.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    has_scram = bool(_SCRAM_CLIENTCERT_RE.search(content))
    has_mapped_trust = bool(_MAPPED_TRUST_RE.search(content))
    assert has_scram or has_mapped_trust, (
        "docker/postgres/10-pgbouncer-auth.sh: no secure auth method for pgbouncer_authenticator found. "
        "Expected either: "
        "(a) `scram-sha-256 clientcert=verify-ca` — two-factor (cert + password), OR "
        "(b) `trust clientcert=verify-ca map=<ident_map>` — CN-bound (narrows cert pool). "
        "Neither pattern found. YSG-RISK-073 cycle 6 / YSG-RISK-075."
    )


def test_helm_script_has_secure_auth_method_for_pgbouncer_authenticator() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must use a secure auth method for pgbouncer_authenticator.

    Same invariant as test_docker_script_has_secure_auth_method_for_pgbouncer_authenticator.
    Compose-Helm parity: both copies must be secure.
    YSG-RISK-073 cycle 6.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    has_scram = bool(_SCRAM_CLIENTCERT_RE.search(content))
    has_mapped_trust = bool(_MAPPED_TRUST_RE.search(content))
    assert has_scram or has_mapped_trust, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: no secure auth method for pgbouncer_authenticator found. "
        "Expected either scram-sha-256+clientcert or trust+clientcert+map=. "
        "YSG-RISK-073 cycle 6 / YSG-RISK-075."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Compose-Helm parity on auth method
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_helm_scripts_agree_on_auth_method() -> None:
    """Both copies of 10-pgbouncer-auth.sh must agree on the auth method for pgbouncer_authenticator.

    If the docker copy uses scram and the helm copy uses trust (or vice versa), that is
    a parity gap — one runtime would have a security gap while the other is hardened.
    YSG-RISK-073 cycle 6.
    """
    docker_content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    helm_content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)

    docker_has_scram = bool(_SCRAM_CLIENTCERT_RE.search(docker_content))
    helm_has_scram = bool(_SCRAM_CLIENTCERT_RE.search(helm_content))

    docker_has_mapped_trust = bool(_MAPPED_TRUST_RE.search(docker_content))
    helm_has_mapped_trust = bool(_MAPPED_TRUST_RE.search(helm_content))

    docker_secure = docker_has_scram or docker_has_mapped_trust
    helm_secure = helm_has_scram or helm_has_mapped_trust

    assert docker_secure and helm_secure, (
        f"Compose-Helm parity failure: "
        f"docker scram={docker_has_scram} mapped-trust={docker_has_mapped_trust}; "
        f"helm scram={helm_has_scram} mapped-trust={helm_has_mapped_trust}. "
        "Both copies must use a secure auth method. "
        "A gap in one runtime means a security regression on that deployment path. "
        "YSG-RISK-073 cycle 6 / YSG-RISK-075."
    )

    # Also assert they agree on WHICH method (both scram, or both mapped-trust)
    if docker_has_scram and not helm_has_scram:
        pytest.fail(
            "Parity gap: docker uses scram-sha-256 but helm does not. "
            "Sync helm/yashigani/files/10-pgbouncer-auth.sh to match docker version. "
            "YSG-RISK-073 cycle 6."
        )
    if helm_has_scram and not docker_has_scram:
        pytest.fail(
            "Parity gap: helm uses scram-sha-256 but docker does not. "
            "Sync docker/postgres/10-pgbouncer-auth.sh to match helm version. "
            "YSG-RISK-073 cycle 6."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: Regression guard — YSG-RISK-075 class documentation present
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_documents_ysg_risk_075() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must document YSG-RISK-075.

    The script must reference the lateral-pivot class to ensure future maintainers
    understand WHY trust+clientcert without map= is forbidden for this role.
    YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    assert "YSG-RISK-075" in content, (
        "docker/postgres/10-pgbouncer-auth.sh: YSG-RISK-075 reference not found. "
        "The script must document the lateral-pivot class (Laura cycle 5) that cycle 6 closes. "
        "Add a comment citing YSG-RISK-075 in step 4b."
    )


def test_helm_script_documents_ysg_risk_075() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must document YSG-RISK-075.

    Same invariant as test_docker_script_documents_ysg_risk_075.
    Compose-Helm parity on documentation.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    assert "YSG-RISK-075" in content, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: YSG-RISK-075 reference not found. "
        "The helm copy must also document the lateral-pivot class. "
        "Add a comment citing YSG-RISK-075 in step 4b."
    )
