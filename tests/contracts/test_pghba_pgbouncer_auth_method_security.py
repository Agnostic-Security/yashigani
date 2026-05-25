# Last updated: 2026-05-25T00:00:00+00:00 (cycle 8: cert+pg_ident; YSG-RISK-073/075/077)
"""
pg_hba auth-method security contract test — YSG-RISK-073 / YSG-RISK-075 / YSG-RISK-077.

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

Cycle 6 attempted fix (scram-sha-256+clientcert) — broken on ARM64/Mac Podman:
  pgbouncer 1.25.1 (edoburu, ARM64) computes incorrect SCRAM proofs when acting as
  SASL client on ARM64 Linux (YSG-RISK-077). Cycle 6 live test PASS was Linux VM only
  (10.89.7.x Podman network). Mac Podman uses 10.89.0.x — different runtime, same bug.
  Ava release gate cycle 7 confirmed FATAL error on Mac/Podman ARM64. Superseded below.

Cycle 7/8 fix (cert+pg_ident — FINAL CLOSE):
  `cert map=pgb-auth-map` — cert method implies verify-full + pg_ident CN mapping.
  pg_ident map pgb-auth-map restricts to ONLY:
    CN=pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer)
    CN=letta-pgbouncer   → pgbouncer_authenticator  (letta sidecar)
  All 11 other data-network cert holders have different CNs — none can impersonate.
  No SCRAM computation — avoids YSG-RISK-077 ARM64 SCRAM bug entirely.
  Stronger than cycle 6: verify-full + CN-specific binding vs verify-ca + broken password.

This module asserts five classes of invariant:
  1. `trust` (unmapped) does NOT appear as auth method for pgbouncer_authenticator.
  2. `scram-sha-256` does NOT appear as auth method for pgbouncer_authenticator (YSG-RISK-077).
  3. `cert` WITHOUT `map=` does NOT appear for pgbouncer_authenticator (bare-cert guard).
  4. `cert map=pgb-auth-map` IS present (positive assertion — cycle 7/8 form).
  5. pg_ident.conf map binds CN → pgbouncer_authenticator (cycle 7/8 closure assertion).

Compose-Helm parity: both docker/ and helm/ copies are checked.

YSG-RISK-073: pgbouncer_authenticator pg_hba carveout history.
YSG-RISK-075: trust-without-CN-binding class — lateral-pivot from CA-cert-holder to full DB.
YSG-RISK-077: pgbouncer 1.25.1 ARM64 SCRAM computation bug — avoids SCRAM via cert method.
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

# The forbidden pattern: scram-sha-256 for pgbouncer_authenticator (YSG-RISK-077 guard).
# pgbouncer 1.25.1 ARM64 SCRAM computation bug — cert method avoids SCRAM entirely.
_SCRAM_FOR_PGBOUNCER_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+scram-sha-256",
    re.MULTILINE,
)

# The forbidden pattern: bare `cert` for pgbouncer_authenticator WITHOUT `map=` clause.
# Without map=, PG16 cert auth defaults to CN==rolename check. Since CN=pgbouncer-auth !=
# role pgbouncer_authenticator, the connection is rejected OR (if CN were manipulated
# to match the role name) any CA-cert holder who crafts CN=pgbouncer_authenticator could
# authenticate. The map= clause restricts to the explicit CN allowlist.
_BARE_CERT_WITHOUT_MAP_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+cert(?!\s+map=)(?:\s|$)",
    re.MULTILINE,
)

# The required pattern: cert + map=pgb-auth-map (cycle 7/8 fix).
# `cert` method: PG16 implies verify-full (chain + CN verified against pg_ident).
# `map=pgb-auth-map`: pg_ident restricts to two specific CNs only (CN=pgbouncer-auth,
# CN=letta-pgbouncer). Any other cert (even CA-signed) cannot authenticate.
# Security posture: STRONGER than SCRAM+clientcert (verify-full + CN-specific).
# YSG-RISK-073 cycle 7/8 / YSG-RISK-077 (ARM64 SCRAM bug bypassed).
_CERT_PGIDENT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+cert\s+map=\S+",
    re.MULTILINE,
)

# pg_ident.conf CN map entries (written by 10-pgbouncer-auth.sh step 4a)
_PGIDENT_PGBOUNCER_AUTH_RE = re.compile(
    r"pgb-auth-map\s+pgbouncer-auth\s+pgbouncer_authenticator"
)
_PGIDENT_LETTA_PGBOUNCER_RE = re.compile(
    r"pgb-auth-map\s+letta-pgbouncer\s+pgbouncer_authenticator"
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

    Allowed form: `cert map=pgb-auth-map` (verify-full + CN-bound via pg_ident — cycle 7/8 fix)

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
                    "Use `cert map=pgb-auth-map` (cycle 7/8 fix)."
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
                    "pgbouncer_authenticator. Use `cert map=pgb-auth-map` (cycle 7/8 fix)."
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
# Test 2: `scram-sha-256` MUST NOT appear for pgbouncer_authenticator (YSG-RISK-077)
# Catches regression to cycle 6 form — broken on ARM64/Mac Podman.
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_no_scram_for_pgbouncer_authenticator() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must not insert scram-sha-256 for pgbouncer_authenticator.

    YSG-RISK-077: pgbouncer 1.25.1 (edoburu, ARM64) has a SCRAM client-side computation bug
    on ARM64 Linux. When acting as SASL client (auth_user authenticating to postgres), it
    computes incorrect SCRAM proofs. Affects Mac Podman (ARM64 Lima/QEMU VM) + K8s ARM64 nodes.
    Cycle 6 live test "PASS" was on Linux VM only — confirmed by IP addresses in postgres logs.
    Ava release gate cycle 7 confirmed FATAL error on Mac/Podman ARM64.

    The fix is `cert map=pgb-auth-map` — cert method avoids SCRAM computation entirely.
    This test catches regression to the cycle 6 scram-sha-256+clientcert form.
    YSG-RISK-077.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        if "pgbouncer_authenticator" in text:
            if re.search(r"\bscram-sha-256\b", text):
                pytest.fail(
                    f"docker/postgres/10-pgbouncer-auth.sh line {lineno}: "
                    f"scram-sha-256 carveout for pgbouncer_authenticator found: '{text}'. "
                    "YSG-RISK-077: scram-sha-256 breaks on ARM64/Mac Podman (pgbouncer 1.25.1 bug). "
                    "Use `cert map=pgb-auth-map` (cycle 7/8 fix — avoids SCRAM computation)."
                )


def test_helm_script_no_scram_for_pgbouncer_authenticator() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must not insert scram-sha-256 for pgbouncer_authenticator.

    Same invariant as test_docker_script_no_scram_for_pgbouncer_authenticator.
    Compose-Helm parity: both copies must avoid the ARM64 SCRAM bug.
    YSG-RISK-077.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        if "pgbouncer_authenticator" in text:
            if re.search(r"\bscram-sha-256\b", text):
                pytest.fail(
                    f"helm/yashigani/files/10-pgbouncer-auth.sh line {lineno}: "
                    f"scram-sha-256 carveout for pgbouncer_authenticator found: '{text}'. "
                    "YSG-RISK-077: scram-sha-256 breaks on ARM64/Mac Podman (pgbouncer 1.25.1 bug). "
                    "Use `cert map=pgb-auth-map` (cycle 7/8 fix)."
                )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: `cert` WITHOUT `map=` MUST NOT appear for pgbouncer_authenticator
# Catches the cycle 3/4 bare-cert form (BUG-C4-001) plus future naked-cert variants.
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_no_bare_cert_without_map_for_pgbouncer_authenticator() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must not insert bare `cert` (no map=) for pgbouncer_authenticator.

    BUG-C4-001 class guard (updated for cycle 7/8):
    PG16 cert auth without map= uses CN==rolename check by default.
    CN=pgbouncer-auth != pgbouncer_authenticator → connection rejected.
    Even if a cert with CN=pgbouncer_authenticator were crafted, no CN restriction applies
    without a pg_ident map — the cert pool is only limited by the CA trust.

    Laura cycle 5 attack-chain extension: any CA-cert holder who can obtain/forge a cert
    with CN=pgbouncer_authenticator bypasses the carveout entirely without a map= clause.

    The ONLY correct form is `cert map=pgb-auth-map` — map= clause restricts to the
    explicit CN allowlist (pgbouncer-auth and letta-pgbouncer only).
    YSG-RISK-073 / YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        # Skip comment lines (awk prints comment lines starting with # for inline documentation)
        if text.lstrip().startswith("#"):
            continue
        if "pgbouncer_authenticator" in text:
            if re.search(r"\bcert\b", text) and "map=" not in text:
                pytest.fail(
                    f"docker/postgres/10-pgbouncer-auth.sh line {lineno}: "
                    f"bare cert (no map=) for pgbouncer_authenticator: '{text}'. "
                    "BUG-C4-001: bare cert fails CN check (CN=pgbouncer-auth != rolename). "
                    "YSG-RISK-075: without map=, CN restriction is not enforced by pg_ident. "
                    "Use `cert map=pgb-auth-map` — the only correct cycle 7/8 form."
                )


def test_helm_script_no_bare_cert_without_map_for_pgbouncer_authenticator() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must not insert bare `cert` (no map=) for pgbouncer_authenticator.

    Same invariant as test_docker_script_no_bare_cert_without_map_for_pgbouncer_authenticator.
    Compose-Helm parity. YSG-RISK-073 / YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    inserted_lines = _extract_awk_printed_lines(content)
    for lineno, text in inserted_lines:
        # Skip comment lines (awk prints comment lines starting with # for inline documentation)
        if text.lstrip().startswith("#"):
            continue
        if "pgbouncer_authenticator" in text:
            if re.search(r"\bcert\b", text) and "map=" not in text:
                pytest.fail(
                    f"helm/yashigani/files/10-pgbouncer-auth.sh line {lineno}: "
                    f"bare cert (no map=) for pgbouncer_authenticator: '{text}'. "
                    "BUG-C4-001: bare cert fails CN check without pg_ident map. "
                    "Use `cert map=pgb-auth-map` (cycle 7/8 fix). YSG-RISK-073 / YSG-RISK-075."
                )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4: `cert map=pgb-auth-map` MUST be present (positive assertion — cycle 7/8)
# Catches the case where step 4c was removed or contains wrong form.
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_has_cert_pgident_auth_method_for_pgbouncer_authenticator() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must use `cert map=pgb-auth-map` for pgbouncer_authenticator.

    Cycle 7/8 fix: `cert map=pgb-auth-map` — cert method (implies verify-full) + pg_ident
    CN mapping. This is the ONLY secure form that:
    (a) avoids the ARM64 SCRAM computation bug (YSG-RISK-077)
    (b) closes the lateral-pivot via CN-specific pg_ident map (YSG-RISK-075)
    (c) is valid PG16 syntax (cert method does not require explicit clientcert= option)

    This test catches the case where the cert+map form is absent (e.g., step 4c removed
    or contains only trust/scram/md5).
    YSG-RISK-073 cycle 7/8.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    has_cert_map = bool(_CERT_PGIDENT_RE.search(content))
    assert has_cert_map, (
        "docker/postgres/10-pgbouncer-auth.sh: `cert map=pgb-auth-map` for pgbouncer_authenticator not found. "
        "Expected: `hostssl yashigani pgbouncer_authenticator <addr>  cert  map=pgb-auth-map`. "
        "YSG-RISK-073 cycle 7/8: cert+pg_ident is the final closed form. "
        "YSG-RISK-077: scram-sha-256 breaks on ARM64/Mac Podman. "
        "YSG-RISK-075: cert+pg_ident closes lateral-pivot via CN-specific map."
    )


def test_helm_script_has_cert_pgident_auth_method_for_pgbouncer_authenticator() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must use `cert map=pgb-auth-map` for pgbouncer_authenticator.

    Same invariant as test_docker_script_has_cert_pgident_auth_method_for_pgbouncer_authenticator.
    Compose-Helm parity: both copies must be secure.
    YSG-RISK-073 cycle 7/8.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    has_cert_map = bool(_CERT_PGIDENT_RE.search(content))
    assert has_cert_map, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: `cert map=pgb-auth-map` for pgbouncer_authenticator not found. "
        "Expected: `hostssl yashigani pgbouncer_authenticator <addr>  cert  map=pgb-auth-map`. "
        "YSG-RISK-073 cycle 7/8 / YSG-RISK-075 / YSG-RISK-077."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 5: pg_ident.conf map binds CN → pgbouncer_authenticator (cycle 7/8 closure)
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_script_writes_pgident_map_for_both_cns() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must write pg_ident.conf entries for both pgbouncer CNs.

    The `cert map=pgb-auth-map` carveout is meaningless without pg_ident.conf entries that
    bind the CN to the role. Without these entries postgres rejects the connection:
      FATAL: no match in ident map "pgb-auth-map" for user "pgbouncer_authenticator"
    Both entries must be present:
      pgb-auth-map  pgbouncer-auth    pgbouncer_authenticator   (main pgbouncer)
      pgb-auth-map  letta-pgbouncer   pgbouncer_authenticator   (letta sidecar)
    Missing either means that pgbouncer instance cannot authenticate as auth_user.
    YSG-RISK-073 cycle 7/8 — CN-specific mapping is what closes YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    has_pgbouncer_auth_entry = bool(_PGIDENT_PGBOUNCER_AUTH_RE.search(content))
    has_letta_pgbouncer_entry = bool(_PGIDENT_LETTA_PGBOUNCER_RE.search(content))
    assert has_pgbouncer_auth_entry, (
        "docker/postgres/10-pgbouncer-auth.sh: pg_ident.conf entry "
        "`pgb-auth-map  pgbouncer-auth  pgbouncer_authenticator` not found. "
        "Step 4a must write this mapping. Without it, postgres rejects the main pgbouncer's cert. "
        "YSG-RISK-073 cycle 7/8."
    )
    assert has_letta_pgbouncer_entry, (
        "docker/postgres/10-pgbouncer-auth.sh: pg_ident.conf entry "
        "`pgb-auth-map  letta-pgbouncer  pgbouncer_authenticator` not found. "
        "Step 4a must write this mapping. Without it, postgres rejects the letta sidecar's cert. "
        "YSG-RISK-073 cycle 7/8."
    )


def test_helm_script_writes_pgident_map_for_both_cns() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must write pg_ident.conf entries for both pgbouncer CNs.

    Same invariant as test_docker_script_writes_pgident_map_for_both_cns.
    Compose-Helm parity on pg_ident entries.
    YSG-RISK-073 cycle 7/8.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    has_pgbouncer_auth_entry = bool(_PGIDENT_PGBOUNCER_AUTH_RE.search(content))
    has_letta_pgbouncer_entry = bool(_PGIDENT_LETTA_PGBOUNCER_RE.search(content))
    assert has_pgbouncer_auth_entry, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: pg_ident.conf entry "
        "`pgb-auth-map  pgbouncer-auth  pgbouncer_authenticator` not found. "
        "YSG-RISK-073 cycle 7/8."
    )
    assert has_letta_pgbouncer_entry, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: pg_ident.conf entry "
        "`pgb-auth-map  letta-pgbouncer  pgbouncer_authenticator` not found. "
        "YSG-RISK-073 cycle 7/8."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6: Compose-Helm parity on auth method
# ─────────────────────────────────────────────────────────────────────────────

def test_docker_helm_scripts_agree_on_auth_method() -> None:
    """Both copies of 10-pgbouncer-auth.sh must agree on the auth method for pgbouncer_authenticator.

    If the docker copy uses cert+pg_ident and the helm copy uses trust or scram (or vice versa),
    that is a parity gap — one runtime would have a security/stability gap while the other is hardened.
    YSG-RISK-073 cycle 7/8.
    """
    docker_content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    helm_content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)

    docker_has_cert_map = bool(_CERT_PGIDENT_RE.search(docker_content))
    helm_has_cert_map = bool(_CERT_PGIDENT_RE.search(helm_content))

    assert docker_has_cert_map and helm_has_cert_map, (
        f"Compose-Helm parity failure: "
        f"docker cert+pg_ident={docker_has_cert_map}; "
        f"helm cert+pg_ident={helm_has_cert_map}. "
        "Both copies must use `cert map=pgb-auth-map`. "
        "A gap in one runtime means a security or stability regression on that deployment path. "
        "YSG-RISK-073 cycle 7/8 / YSG-RISK-075 / YSG-RISK-077."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 7: Regression guard — risk register documentation present
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
        "The script must document the lateral-pivot class (Laura cycle 5) that cycle 7/8 closes. "
        "Add a comment citing YSG-RISK-075 in step 4."
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
        "Add a comment citing YSG-RISK-075 in step 4."
    )


def test_docker_script_documents_ysg_risk_077() -> None:
    """docker/postgres/10-pgbouncer-auth.sh must document YSG-RISK-077.

    The script must reference the ARM64 SCRAM bug to ensure future maintainers
    understand WHY scram-sha-256 is forbidden for this role.
    YSG-RISK-077.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_DOCKER)
    assert "YSG-RISK-077" in content, (
        "docker/postgres/10-pgbouncer-auth.sh: YSG-RISK-077 reference not found. "
        "The script must document the ARM64 SCRAM computation bug that necessitated cert+pg_ident. "
        "Add a comment citing YSG-RISK-077 in step 4."
    )


def test_helm_script_documents_ysg_risk_077() -> None:
    """helm/yashigani/files/10-pgbouncer-auth.sh must document YSG-RISK-077.

    Same invariant as test_docker_script_documents_ysg_risk_077.
    Compose-Helm parity on documentation.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT_HELM)
    assert "YSG-RISK-077" in content, (
        "helm/yashigani/files/10-pgbouncer-auth.sh: YSG-RISK-077 reference not found. "
        "The helm copy must also document the ARM64 SCRAM bug. "
        "Add a comment citing YSG-RISK-077 in step 4."
    )
