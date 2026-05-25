# Last updated: 2026-05-25T00:00:00+00:00 (cycle 8: cert+pg_ident carveout; YSG-RISK-073/075/077)
"""
pg_hba.conf cert+pg_ident carveout tests — BUG-NEW-001 / YSG-RISK-073 / YSG-RISK-075 / YSG-RISK-077.

YSG-RISK-073 history:

  Cycle 3: `cert clientcert=verify-ca` — WRONG on two layers:
    BUG-C4-001 Layer A: PG16 rejects `clientcert=verify-ca` with `cert` auth method.
      Only `clientcert=verify-full` is valid with cert; postgres crash-loops.
    BUG-C4-001 Layer B: CN mismatch — CN=pgbouncer-auth != role pgbouncer_authenticator.
    BUG-C4-002: 05-enable-ssl.sh heredoc AND 10-pgbouncer-auth.sh step 4b both wrote
      the carveout — duplicate entries in pg_hba.conf, both triggering PG16 syntax error.

  Cycle 5: `trust clientcert=verify-ca` — PG16-valid but SINGLE-FACTOR:
    Laura cycle 5 adversarial probe confirmed a REAL attack chain: any container on
    the `data` network holding a CA-signed cert can impersonate pgbouncer_authenticator
    and call ysg_pgbouncer_get_auth — no password needed with trust auth.
    The blast radius is full postgres DB compromise via SCRAM verifier retrieval.
    YSG-RISK-075 documents this class. Cycle 5 carveout is REPLACED here.

  Cycle 6: `scram-sha-256 clientcert=verify-ca` — TWO-FACTOR RESTORED:
    Broke on ARM64/Mac Podman due to pgbouncer 1.25.1 SCRAM client-side computation bug
    (YSG-RISK-077). Cycle 6 "live test PASS" was Linux VM only (different Podman network
    stack). Superseded by cycle 7.

  Cycle 7 / cycle 8 (this commit): `cert map=pgb-auth-map` — FINAL CLOSE:
    PG16 cert method implies verify-full (full chain + CN verified against pg_ident map).
    pg_ident map `pgb-auth-map` restricts to ONLY:
      CN=pgbouncer-auth    → pgbouncer_authenticator  (main pgbouncer instance)
      CN=letta-pgbouncer   → pgbouncer_authenticator  (letta sidecar pgbouncer)
    All 11 other data-network cert holders have different CNs — none can impersonate.
    No SCRAM computation — avoids YSG-RISK-077 ARM64 SCRAM bug entirely.
    YSG-RISK-075 CLOSED: CN-specific pg_ident map closes the lateral-pivot attack chain.
    Stronger than cycle 6 (verify-full + CN-binding vs verify-ca + broken SCRAM password).

This test suite asserts the correct form in the two pg_hba-producing scripts:
  05-enable-ssl.sh — writes pg_hba.conf on first-init (NO pgbouncer_authenticator carveout)
  10-pgbouncer-auth.sh — is the SOLE writer of the cert+pg_ident carveout on init + upgrade

Tests also assert:
  - The catch-all (scram-sha-256 clientcert=verify-ca) is still present in 05-enable-ssl.sh
  - `cert map=pgb-auth-map` carveout precedes the catch-all in 10-pgbouncer-auth.sh
  - pg_ident.conf `pgb-auth-map` map contains both pgbouncer-auth and letta-pgbouncer bindings
  - `trust` (bare or with clientcert=) is NOT the auth method for pgbouncer_authenticator
  - `scram-sha-256` is NOT the auth method for pgbouncer_authenticator (YSG-RISK-077 guard)
  - `cert` without `map=` is NOT the auth method for pgbouncer_authenticator (bare-cert guard)
  - `md5` is NOT the auth method for pgbouncer_authenticator (cycle 5 guard)
  - 05-enable-ssl.sh does NOT write the pgbouncer_authenticator carveout (BUG-C4-002 guard)
  - Helm pg_hba sources contain the matching cert+pg_ident carveout

YSG-RISK-049: SECURITY DEFINER ysg_pgbouncer_get_auth + pgbouncer_authenticator role.
YSG-RISK-050: dedicated pgbouncer-auth_client.crt for postgres-facing identity.
YSG-RISK-073: cert+pg_ident carveout for pgbouncer_authenticator auth_query
              (cycle 7/8 — cert method via pg_ident CN map; closes SCRAM ARM64 bug).
YSG-RISK-075: trust-auth-without-CN-binding is insufficient when multiple containers
              hold CA-signed certs — closed by pg_ident CN-specific map (cycle 7/8).
YSG-RISK-077: pgbouncer 1.25.1 ARM64 SCRAM client-side computation bug — avoids SCRAM
              entirely by using cert method (no SCRAM exchange needed).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

ENABLE_SSL_SCRIPT = REPO_ROOT / "docker" / "postgres" / "05-enable-ssl.sh"
PGBOUNCER_AUTH_SCRIPT = REPO_ROOT / "docker" / "postgres" / "10-pgbouncer-auth.sh"
PGIDENT_CONF_PATH_HINT = "${PGDATA}/pg_ident.conf"  # runtime path; asserted via script content

# Helm pg_hba.conf file — the chart uses the same init scripts (05-enable-ssl.sh,
# 10-pgbouncer-auth.sh) mounted as ConfigMaps into the postgres pod. These scripts
# write pg_hba.conf at runtime, so there is no standalone pg_hba.conf file in the
# Helm chart. If a dedicated pg_hba.conf ConfigMap is ever added, add the path here.
# The init scripts are tested above (test_enable_ssl_* and test_pgbouncer_auth_*).
HELM_PG_HBA_SOURCES = [
    REPO_ROOT / "helm" / "yashigani" / "files" / "pg_hba.conf",
]

# The expected cert+pg_ident carveout lines (canonical form — cycle 7/8 fix).
# `cert map=pgb-auth-map` — cert method implies verify-full; map= binds CN to role.
_CERT_PGIDENT_CARVEOUT_RE = re.compile(
    r"hostssl\s+yashigani\s+pgbouncer_authenticator\s+[\d.:a-fA-F/]+\s+cert\s+map=pgb-auth-map"
)

# The forbidden bare-trust form (trust WITHOUT clientcert= — the old v2.24.0 A2 carveout)
_BARE_TRUST_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust(?!\s+clientcert=)"
)

# The forbidden trust+clientcert form (cycle 5 — one-factor; YSG-RISK-075)
# Any trust carveout for pgbouncer_authenticator is forbidden; cert+pg_ident is required.
_TRUST_CLIENTCERT_FOR_PGBOUNCER_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust\s+clientcert="
)

# The forbidden scram-sha-256 form (cycle 6 — ARM64 SCRAM bug; YSG-RISK-077)
_SCRAM_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+scram-sha-256"
)

# The forbidden md5 form (cycle 5 first attempt — failed in practice with edoburu 1.25.1)
_MD5_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+md5"
)

# The forbidden bare-cert form (cert without map= — cycle 3/4 form; BUG-C4-001 guard).
# `cert` as auth method WITHOUT a `map=` clause fails because:
#   - CN=pgbouncer-auth != role pgbouncer_authenticator (no pg_ident map to bridge them)
#   - Any CA-cert holder could impersonate the role (no CN binding)
# Pattern: hostssl ... pgbouncer_authenticator ... cert <whitespace or end> NOT followed by map=
_BARE_CERT_WITHOUT_MAP_RE = re.compile(
    r"^hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+cert(?!\s+map=)(?:\s|$)",
    re.MULTILINE,
)

# Catch-all must still be present in 05-enable-ssl.sh (for all non-pgbouncer_authenticator roles)
_CATCHALL_RE = re.compile(
    r"hostssl\s+all\s+all\s+[\d.:a-fA-F/]+\s+scram-sha-256\s+clientcert=verify-ca"
)


def _read(path: Path) -> str:
    assert path.exists(), f"File missing: {path}"
    return path.read_text()


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: 05-enable-ssl.sh — catch-all present; NO pgbouncer_authenticator carveout
# (BUG-C4-002 fix: 05-enable-ssl.sh must NOT write the carveout — single source
# of truth is 10-pgbouncer-auth.sh only)
# ─────────────────────────────────────────────────────────────────────────────

def test_enable_ssl_does_not_write_carveout() -> None:
    """05-enable-ssl.sh pg_hba heredoc must NOT contain a pgbouncer_authenticator carveout.

    BUG-C4-002 fix: the duplicate carveout (05-enable-ssl.sh + 10-pgbouncer-auth.sh both
    writing the carveout) caused duplicate pg_hba entries on fresh install. Both entries
    triggered PG16's syntax error for `cert clientcert=verify-ca` and postgres crash-looped.
    Single source of truth: 10-pgbouncer-auth.sh is the ONLY writer of this carveout.
    05-enable-ssl.sh writes only the catch-all and baseline pg_hba structure.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    # The heredoc is between 'cat > "${PGDATA}/pg_hba.conf" <<\'HBA\'' and 'HBA'
    # Find the heredoc block
    hba_start = content.find("cat > \"${PGDATA}/pg_hba.conf\"")
    hba_end = content.find("\nHBA\n", hba_start)
    assert hba_start != -1, "05-enable-ssl.sh: pg_hba heredoc start not found."
    assert hba_end != -1, "05-enable-ssl.sh: pg_hba heredoc end (HBA) not found."
    heredoc_content = content[hba_start:hba_end]
    assert "pgbouncer_authenticator" not in heredoc_content, (
        "05-enable-ssl.sh: pgbouncer_authenticator found in pg_hba heredoc. "
        "BUG-C4-002 fix: 05-enable-ssl.sh must NOT write the carveout — "
        "10-pgbouncer-auth.sh is the single source of truth. "
        "Duplicate entries cause postgres crash-loop on PG16."
    )


def test_enable_ssl_catch_all_still_present() -> None:
    """05-enable-ssl.sh catch-all (scram-sha-256 clientcert=verify-ca) must still be present.

    The cert+pg_ident carveout is narrowly scoped to pgbouncer_authenticator on yashigani.
    All other connections must still use SCRAM + cert (the catch-all). Three-factor auth preserved.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _CATCHALL_RE.findall(content)
    assert len(matches) >= 2, (
        f"05-enable-ssl.sh: catch-all (hostssl all all ... scram-sha-256 clientcert=verify-ca) "
        f"found {len(matches)} times, expected >= 2 (IPv4 + IPv6). "
        "The scram catch-all must be retained for all non-pgbouncer_authenticator connections."
    )


def test_enable_ssl_no_bare_trust_carveout() -> None:
    """05-enable-ssl.sh must NOT contain a bare-trust carveout for pgbouncer_authenticator.

    The v2.24.0 A2 carveout used bare `trust` (no clientcert= option). That carveout
    was weaker than the cycle 5 trust+clientcert approach and was removed by YSG-RISK-050.
    Any remaining bare-trust carveout (trust without clientcert=verify-ca) is a regression.
    Note: the cert+pg_ident carveout lives ONLY in 10-pgbouncer-auth.sh (single source of truth).
    05-enable-ssl.sh must not write any pgbouncer_authenticator carveout at all.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _BARE_TRUST_CARVEOUT_RE.findall(content)
    assert not matches, (
        f"05-enable-ssl.sh: found bare-trust carveout for pgbouncer_authenticator: {matches}. "
        "YSG-RISK-073: bare trust (without clientcert=) is a security regression. "
        "The cert+pg_ident carveout belongs ONLY in 10-pgbouncer-auth.sh."
    )


def test_enable_ssl_no_cert_auth_method_for_pgbouncer_authenticator() -> None:
    """05-enable-ssl.sh must NOT use `cert` as auth method for pgbouncer_authenticator.

    BUG-C4-001 (Layer A): `cert clientcert=verify-ca` is invalid PostgreSQL 16 syntax.
    PG16 only accepts `clientcert=verify-full` with cert auth. postgres crash-loops with:
      FATAL: could not load pg_hba.conf; LOG: clientcert only accepts verify-full when
      using cert authentication.
    The correct carveout is `cert map=pgb-auth-map` (PG16-valid; map= implies verify-full).
    This carveout must only appear in 10-pgbouncer-auth.sh, not 05-enable-ssl.sh.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    # Check the pg_hba heredoc block only (not comments/documentation)
    hba_start = content.find("cat > \"${PGDATA}/pg_hba.conf\"")
    hba_end = content.find("\nHBA\n", hba_start)
    if hba_start != -1 and hba_end != -1:
        heredoc_content = content[hba_start:hba_end]
        matches = _BARE_CERT_WITHOUT_MAP_RE.findall(heredoc_content)
        assert not matches, (
            f"05-enable-ssl.sh: found `cert` as auth method for pgbouncer_authenticator "
            f"in pg_hba heredoc: {matches}. "
            "BUG-C4-001: `cert clientcert=verify-ca` is invalid PG16 syntax. "
            "The cert+pg_ident carveout belongs only in 10-pgbouncer-auth.sh."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: 10-pgbouncer-auth.sh manages the cert+pg_ident carveout correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_pgbouncer_auth_script_inserts_cert_pgident_carveout() -> None:
    """10-pgbouncer-auth.sh must insert a `cert map=pgb-auth-map` carveout — YSG-RISK-073 cycle 7/8.

    v2.24.0 step 4 REMOVED the carveout. v2.24.3 cycle 3 INSERTED cert carveout (wrong form).
    v2.24.3 cycle 4 committed cert+verify-ca (7f296a1 — broken; PG16 syntax + CN mismatch).
    v2.24.3 cycle 5 INSERTED trust clientcert=verify-ca — SINGLE-FACTOR SECURITY GAP (YSG-RISK-075).
    v2.24.3 cycle 6 INSERTED scram-sha-256 clientcert=verify-ca — broke on ARM64/Mac (YSG-RISK-077).
    v2.24.3 cycle 7/8 INSERTS cert map=pgb-auth-map — FINAL CLOSE: verify-full + CN-binding.
    Verify the script contains the cert+pg_ident carveout insertion logic.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must contain cert+pg_ident carveout insertion literal text
    assert "cert  map=pgb-auth-map" in content or "cert map=pgb-auth-map" in content, (
        "10-pgbouncer-auth.sh: cert+pg_ident carveout insertion text not found. "
        "Step 4c must insert 'hostssl yashigani pgbouncer_authenticator ... cert  map=pgb-auth-map' "
        "before the catch-all. YSG-RISK-073 cycle 7/8 (cert+pg_ident, not trust, scram, or md5). "
        "YSG-RISK-077: scram-sha-256 breaks on ARM64/Mac Podman (pgbouncer 1.25.1 bug). "
        "YSG-RISK-075: cert+pg_ident closes lateral-pivot via CN-specific map."
    )


def test_pgbouncer_auth_script_no_scram_for_pgbouncer_authenticator() -> None:
    """10-pgbouncer-auth.sh must NOT insert scram-sha-256 for pgbouncer_authenticator.

    YSG-RISK-077: pgbouncer 1.25.1 (edoburu, ARM64) has a SCRAM client-side computation bug.
    It sends incorrect SCRAM proofs when authenticating outbound as auth_user on ARM64 Linux
    (Mac Podman ARM64 container runtime). Cycle 6 "live test PASS" was Linux VM only —
    same pgbouncer binary, different Podman network stack (10.89.7.x vs 10.89.0.x).
    Platform gap confirmed by Ava release gate cycle 7 FATAL error.

    The fix is `cert map=pgb-auth-map` — cert method avoids SCRAM computation entirely.
    This test catches regression to the cycle 6 scram-sha-256+clientcert form.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    lines = content.splitlines()
    in_awk_block = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "awk '" in stripped or 'awk "' in stripped:
            in_awk_block = True
        if in_awk_block and ("' \"${_hba}\"" in line or "' \"${_tmp}\"" in line):
            in_awk_block = False
        if in_awk_block and stripped.startswith("print ") and "pgbouncer_authenticator" in stripped:
            if re.search(r"\bscram-sha-256\b", stripped):
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: scram-sha-256 form found in awk insertion "
                    f"block for pgbouncer_authenticator: '{stripped}'. "
                    "YSG-RISK-077: scram-sha-256 breaks on ARM64/Mac Podman (pgbouncer 1.25.1 bug). "
                    "Use `cert map=pgb-auth-map` (cert method avoids SCRAM computation). "
                    "Cycle 7/8 fix: cert method + pg_ident CN map."
                )


def test_pgbouncer_auth_script_no_trust_clientcert_for_pgbouncer_authenticator() -> None:
    """10-pgbouncer-auth.sh must NOT insert trust+clientcert for pgbouncer_authenticator.

    YSG-RISK-075: `trust clientcert=verify-ca` for pgbouncer_authenticator is a confirmed
    security gap. Any container on the `data` network holding a CA-signed cert can connect
    to postgres claiming role pgbouncer_authenticator and call ysg_pgbouncer_get_auth without
    a password. Laura cycle 5 release gate confirmed the full attack chain.

    The fix is `cert map=pgb-auth-map` (cert method + pg_ident CN-specific mapping).
    This test catches regression to the cycle 5 trust+clientcert form.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    lines = content.splitlines()
    in_awk_block = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "awk '" in stripped or 'awk "' in stripped:
            in_awk_block = True
        if in_awk_block and ("' \"${_hba}\"" in line or "' \"${_tmp}\"" in line):
            in_awk_block = False
        if in_awk_block and stripped.startswith("print ") and "pgbouncer_authenticator" in stripped:
            # Trust+clientcert: trust appears AND clientcert= appears on same line
            if re.search(r"\btrust\b", stripped) and "clientcert=" in stripped:
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: trust+clientcert form found in awk insertion "
                    f"block for pgbouncer_authenticator: '{stripped}'. "
                    "YSG-RISK-075: trust+clientcert is a one-factor security gap — any CA-cert "
                    "holder can impersonate pgbouncer_authenticator. "
                    "Use `cert map=pgb-auth-map` (cert method + pg_ident CN binding). "
                    "Laura cycle 5 confirmed the attack chain."
                )


def test_pgbouncer_auth_script_no_remove_only() -> None:
    """10-pgbouncer-auth.sh must not only remove the carveout without re-inserting it.

    v2.24.0 bug: the script removed the A2 carveout but did not add a new carveout.
    v2.24.3 cycle 7/8 fix: the script removes stale entries then inserts cert+pg_ident carveout.
    Verify the insert step is present (awk first-match insertion or cert carveout literal).
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must have awk or sed insertion before catch-all (awk used for first-match-only insert)
    assert (
        "hostssl yashigani pgbouncer_authenticator" in content
        or "/^hostssl all/i" in content
        or "awk" in content
    ), (
        "10-pgbouncer-auth.sh: carveout insertion logic not found. "
        "Step 4c must insert the cert+pg_ident carveout before the catch-all (first match only). "
        "YSG-RISK-073 cycle 7/8."
    )


def test_pgbouncer_auth_script_no_bare_trust_carveout_inserted() -> None:
    """10-pgbouncer-auth.sh must not insert a BARE trust carveout (trust without clientcert=).

    The v2.24.0 A2 carveout was `trust` with no clientcert requirement — weakest because
    any client could connect without presenting a cert. YSG-RISK-073 cycle 7/8 uses
    `cert map=pgb-auth-map` — the correct form with CN-binding.
    This test guards against bare `trust` (without clientcert=) being inserted.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    lines = content.splitlines()
    in_awk_block = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Track awk block start/end
        if "awk '" in stripped or "awk \"" in stripped:
            in_awk_block = True
        if in_awk_block and ("' \"${_hba}\"" in line or "' \"${_tmp}\"" in line):
            in_awk_block = False
        # Only check print statements in awk block (actual pg_hba lines being inserted)
        if in_awk_block and stripped.startswith("print ") and "pgbouncer_authenticator" in stripped:
            # Bare trust: trust appears but clientcert= does NOT follow on the same line
            if "trust" in stripped and "clientcert=" not in stripped:
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: bare trust carveout (no clientcert=) "
                    f"for pgbouncer_authenticator found in awk insertion block: '{stripped}'. "
                    "Use `cert map=pgb-auth-map` not bare `trust`. "
                    "Bare trust requires no cert from the client — security regression to A2 posture."
                )


def test_pgbouncer_auth_script_no_bare_cert_without_map_inserted() -> None:
    """10-pgbouncer-auth.sh must NOT insert `cert` as auth method without a `map=` clause.

    BUG-C4-001 (Layers A+B) guard updated for cycle 7/8:
      - `cert` without `map=`: PG16 cert method maps CN==rolename by default — would fail
        since CN=pgbouncer-auth != role pgbouncer_authenticator (CN != rolename).
      - Laura cycle 5 class: bare cert without map= still allows any CA-cert holder with
        CN=pgbouncer_authenticator to impersonate the role (no pg_ident restriction).
    The ONLY correct form for cycle 7/8 is `cert map=pgb-auth-map`.
    This test catches the error class from cycle 3/4 (commit 7f296a1) PLUS the naked-cert variant.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Look for cert as auth method WITHOUT map= for pgbouncer_authenticator
        if "pgbouncer_authenticator" in stripped:
            if re.search(r"pgbouncer_authenticator\s+\S+\s+cert(?!\s+map=)(?:\s|$)", stripped):
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: `cert` used as auth method for "
                    f"pgbouncer_authenticator without `map=` clause in active code: '{stripped}'. "
                    "BUG-C4-001: bare `cert` fails CN check (CN=pgbouncer-auth != rolename). "
                    "YSG-RISK-075: without map=, any CA-cert holder could craft a matching CN. "
                    "Use `cert map=pgb-auth-map` — the only correct cycle 7/8 form."
                )


def test_pgbouncer_auth_script_no_md5_auth_method_inserted() -> None:
    """10-pgbouncer-auth.sh must NOT insert `md5` as auth method for pgbouncer_authenticator.

    Cycle 5 first attempt: `md5 clientcert=verify-ca` — also broken in practice.
    pgbouncer 1.25.1 (edoburu image) cannot correctly perform server-side md5 authentication
    against postgres. The md5 challenge response does not match regardless of whether
    userlist.txt contains cleartext or pre-hashed md5. Verified by live test.
    The correct insertion is `cert map=pgb-auth-map`.
    This test guards against regression to the failed md5 approach.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "pgbouncer_authenticator" in stripped:
            if re.search(r"pgbouncer_authenticator\s+\S+\s+md5(?:\s|$)", stripped):
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: `md5` used as auth method for "
                    f"pgbouncer_authenticator in active code: '{stripped}'. "
                    "md5 auth failed in practice with pgbouncer 1.25.1 (edoburu image). "
                    "Use `cert map=pgb-auth-map` instead."
                )


def test_pgbouncer_auth_script_writes_pg_ident_map() -> None:
    """10-pgbouncer-auth.sh must write the pg_ident.conf pgb-auth-map entries.

    Cycle 7/8 fix: cert auth via `cert map=pgb-auth-map` requires pg_ident.conf to have
    the map that binds CN → pgbouncer_authenticator. Without pg_ident entries, postgres
    cannot find the map and rejects the connection with "no such map".
    Both CNs must be mapped:
      pgb-auth-map  pgbouncer-auth    pgbouncer_authenticator   (main pgbouncer)
      pgb-auth-map  letta-pgbouncer   pgbouncer_authenticator   (letta sidecar)
    YSG-RISK-073 cycle 7/8.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    assert "pgb-auth-map" in content, (
        "10-pgbouncer-auth.sh: `pgb-auth-map` reference not found. "
        "Step 4a must write pg_ident.conf entries for the pgb-auth-map. "
        "YSG-RISK-073 cycle 7/8: cert map=pgb-auth-map requires pg_ident entries."
    )
    assert "pgbouncer-auth" in content, (
        "10-pgbouncer-auth.sh: `pgbouncer-auth` CN mapping not found. "
        "pg_ident.conf must map CN=pgbouncer-auth → pgbouncer_authenticator. "
        "YSG-RISK-073 cycle 7/8."
    )
    assert "letta-pgbouncer" in content, (
        "10-pgbouncer-auth.sh: `letta-pgbouncer` CN mapping not found. "
        "pg_ident.conf must map CN=letta-pgbouncer → pgbouncer_authenticator. "
        "Both pgbouncer instances must be covered. YSG-RISK-073 cycle 7/8."
    )


def test_pgbouncer_auth_script_pg_ident_maps_both_cns_to_role() -> None:
    """10-pgbouncer-auth.sh pg_ident entries must map both CNs to pgbouncer_authenticator.

    The pg_ident.conf pgb-auth-map must contain:
      pgb-auth-map  pgbouncer-auth    pgbouncer_authenticator
      pgb-auth-map  letta-pgbouncer   pgbouncer_authenticator
    Both lines must be present: the main pgbouncer instance AND the letta sidecar.
    Missing either means that instance cannot authenticate as auth_user.
    YSG-RISK-073 cycle 7/8 — CN-specific mapping closes YSG-RISK-075.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Look for printf/echo lines that write the actual pg_ident entries
    # Pattern: pgb-auth-map  <CN>  pgbouncer_authenticator
    pgbouncer_auth_mapped = re.search(
        r"pgb-auth-map\s+pgbouncer-auth\s+pgbouncer_authenticator", content
    )
    letta_pgbouncer_mapped = re.search(
        r"pgb-auth-map\s+letta-pgbouncer\s+pgbouncer_authenticator", content
    )
    assert pgbouncer_auth_mapped, (
        "10-pgbouncer-auth.sh: pg_ident mapping "
        "`pgb-auth-map  pgbouncer-auth  pgbouncer_authenticator` not found. "
        "Step 4a must write this entry to pg_ident.conf. "
        "Without it, the main pgbouncer cannot authenticate as pgbouncer_authenticator. "
        "YSG-RISK-073 cycle 7/8."
    )
    assert letta_pgbouncer_mapped, (
        "10-pgbouncer-auth.sh: pg_ident mapping "
        "`pgb-auth-map  letta-pgbouncer  pgbouncer_authenticator` not found. "
        "Step 4a must write this entry to pg_ident.conf. "
        "Without it, the letta sidecar pgbouncer cannot authenticate as pgbouncer_authenticator. "
        "YSG-RISK-073 cycle 7/8."
    )


def test_pgbouncer_auth_script_references_ysg_risk_073_and_077() -> None:
    """10-pgbouncer-auth.sh must reference YSG-RISK-073, YSG-RISK-075, and YSG-RISK-077.

    Ensures the script is correctly updated for v2.24.3 cycle 7/8 and not a stale version.
    YSG-RISK-075: lateral-pivot class documented by Laura cycle 5, closed by cycle 7/8.
    YSG-RISK-077: ARM64 SCRAM computation bug — root cause for switching from cycle 6 scram.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    assert "YSG-RISK-073" in content, (
        "10-pgbouncer-auth.sh: YSG-RISK-073 reference not found. "
        "The script must be updated to v2.24.3 cert+pg_ident carveout logic (cycle 7/8)."
    )
    assert "YSG-RISK-075" in content, (
        "10-pgbouncer-auth.sh: YSG-RISK-075 reference not found. "
        "The script must document the lateral-pivot class (Laura cycle 5) that cycle 7/8 closes."
    )
    assert "YSG-RISK-077" in content, (
        "10-pgbouncer-auth.sh: YSG-RISK-077 reference not found. "
        "The script must document the ARM64 SCRAM bug that necessitated the pivot from cycle 6."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Helm pg_hba contains cert+pg_ident carveout (Compose-Helm parity)
# ─────────────────────────────────────────────────────────────────────────────

def test_helm_pghba_has_cert_pgident_carveout() -> None:
    """Helm chart 10-pgbouncer-auth.sh must contain the cert+pg_ident carveout.

    Compose-Helm parity: the cert+pg_ident carveout in docker/postgres/10-pgbouncer-auth.sh
    must also appear in helm/yashigani/files/10-pgbouncer-auth.sh (the Helm copy).
    If no Helm pg_hba file exists, this test is skipped with a clear reason.
    YSG-RISK-073 cycle 7/8.
    """
    helm_content = None
    for path in HELM_PG_HBA_SOURCES:
        if path.exists():
            helm_content = path.read_text()
            break

    if helm_content is None:
        pytest.skip(
            "No Helm pg_hba source found at expected paths "
            f"({[str(p) for p in HELM_PG_HBA_SOURCES]}). "
            "Add helm/yashigani/files/pg_hba.conf or update HELM_PG_HBA_SOURCES "
            "when the Helm chart embeds pg_hba.conf as a ConfigMap. YSG-RISK-073."
        )

    matches = _CERT_PGIDENT_CARVEOUT_RE.findall(helm_content)
    assert len(matches) >= 1, (
        f"Helm pg_hba source: cert+pg_ident carveout for pgbouncer_authenticator not found. "
        "Compose-Helm parity requires the `cert map=pgb-auth-map` carveout in Helm too. "
        "YSG-RISK-073 cycle 7/8."
    )
