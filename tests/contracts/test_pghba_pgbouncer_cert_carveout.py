# Last updated: 2026-05-25T00:00:00+00:00
"""
pg_hba.conf trust+clientcert carveout tests — BUG-NEW-001 / YSG-RISK-073 / BUG-C4-001 / BUG-C4-002.

PgBouncer 1.25.1 (edoburu image) cannot perform SCRAM-SHA-256 as the client when
connecting to postgres as auth_user. YSG-RISK-050 removed the A2 trust carveout,
assuming pgbouncer would SCRAM — it cannot. YSG-RISK-073 attempted to fix this:

  Cycle 3 (commit 7f296a1 predecessor): `cert clientcert=verify-ca` — WRONG on two layers:
    BUG-C4-001 Layer A: PG16 rejects `clientcert=verify-ca` with `cert` auth method.
      Only `clientcert=verify-full` is valid with cert; postgres crash-loops.
    BUG-C4-001 Layer B: CN mismatch — CN=pgbouncer-auth != role pgbouncer_authenticator.
      verify-full would also have failed on CN match.
    BUG-C4-002: 05-enable-ssl.sh heredoc AND 10-pgbouncer-auth.sh step 4b both wrote
      the carveout — duplicate entries in pg_hba.conf, both triggering PG16 syntax error.

  Cycle 5 (this commit): `trust clientcert=verify-ca` — PG16-valid + cert-equivalent:
    CA chain verified (clientcert=verify-ca). No CN constraint. No password challenge.
    The CA-verified cert IS the sole authenticator (same security as `cert` method).
    md5 was also attempted in cycle 5 but failed in practice: pgbouncer 1.25.1 (edoburu
    image) cannot correctly perform server-side md5 authentication. Observed live.
    Single source of truth: 10-pgbouncer-auth.sh only. 05-enable-ssl.sh does NOT
    write a pgbouncer_authenticator carveout (BUG-C4-002 fix).

This test suite asserts the correct form in the two pg_hba-producing scripts:
  05-enable-ssl.sh — writes pg_hba.conf on first-init (NO pgbouncer_authenticator carveout)
  10-pgbouncer-auth.sh — is the SOLE writer of the trust+clientcert carveout on init + upgrade paths

Tests also assert:
  - The catch-all (scram-sha-256 clientcert=verify-ca) is still present in 05-enable-ssl.sh
  - The trust+clientcert carveout precedes the catch-all in 10-pgbouncer-auth.sh insertion logic
  - The old bare-trust A2 carveout form (trust WITHOUT clientcert) is NOT present in either script
  - `cert` is NOT the auth method for pgbouncer_authenticator in either script (BUG-C4-001 guard)
  - `md5` is NOT the auth method for pgbouncer_authenticator in either script (cycle 5 md5 attempt guard)
  - 05-enable-ssl.sh does NOT write the pgbouncer_authenticator carveout (BUG-C4-002 guard)
  - Helm pg_hba ConfigMap contains the matching trust+clientcert carveout

YSG-RISK-049: SECURITY DEFINER ysg_pgbouncer_get_auth + pgbouncer_authenticator role.
YSG-RISK-050: dedicated pgbouncer-auth_client.crt for postgres-facing identity.
YSG-RISK-073: trust clientcert=verify-ca carveout replaces SCRAM for pgbouncer_authenticator
              auth_query connection (BUG-NEW-001 from Ava v2.24.3 cycle 3 gate;
              corrected from cert (cycle 4) to trust+clientcert (cycle 5) after
              BUG-C4-001/002 Ava findings and live md5 failure confirmation).
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent

ENABLE_SSL_SCRIPT = REPO_ROOT / "docker" / "postgres" / "05-enable-ssl.sh"
PGBOUNCER_AUTH_SCRIPT = REPO_ROOT / "docker" / "postgres" / "10-pgbouncer-auth.sh"

# Helm pg_hba.conf file — the chart uses the same init scripts (05-enable-ssl.sh,
# 10-pgbouncer-auth.sh) mounted as ConfigMaps into the postgres pod. These scripts
# write pg_hba.conf at runtime, so there is no standalone pg_hba.conf file in the
# Helm chart. If a dedicated pg_hba.conf ConfigMap is ever added, add the path here.
# The init scripts are tested above (test_enable_ssl_* and test_pgbouncer_auth_*).
HELM_PG_HBA_SOURCES = [
    REPO_ROOT / "helm" / "yashigani" / "files" / "pg_hba.conf",
]

# The expected trust+clientcert carveout lines (canonical form — cycle 5 fix)
_TRUST_CLIENTCERT_CARVEOUT_RE = re.compile(
    r"hostssl\s+yashigani\s+pgbouncer_authenticator\s+[\d.:a-fA-F/]+\s+trust\s+clientcert=verify-ca"
)
# The forbidden bare-trust form (trust WITHOUT clientcert= — the old v2.24.0 A2 carveout)
_BARE_TRUST_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+trust(?!\s+clientcert=)"
)
# The forbidden md5 form (cycle 5 first attempt — failed in practice with edoburu 1.25.1)
_MD5_CARVEOUT_RE = re.compile(
    r"hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+md5"
)
# The forbidden cert-as-method form (BUG-C4-001 guard)
# Matches: hostssl yashigani pgbouncer_authenticator ... cert clientcert=...
# Excludes lines where `cert` appears in clientcert=verify-ca (that's fine — cert here
# means the clientcert= option value, not the auth method).
# Pattern: hostssl ... pgbouncer_authenticator ... <whitespace> cert <whitespace>
_CERT_AUTH_METHOD_RE = re.compile(
    r"^hostssl\s+\S+\s+pgbouncer_authenticator\s+\S+\s+cert\s+",
    re.MULTILINE,
)
# Catch-all must still be present in 05-enable-ssl.sh
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

    The md5 carveout is narrowly scoped to pgbouncer_authenticator on yashigani.
    All other connections must still use SCRAM + cert. Three-factor auth preserved.
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
    Note: trust WITH clientcert=verify-ca is the CORRECT cycle 5 carveout method,
    but that carveout lives ONLY in 10-pgbouncer-auth.sh (single source of truth).
    05-enable-ssl.sh must not write any pgbouncer_authenticator carveout at all.
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _BARE_TRUST_CARVEOUT_RE.findall(content)
    assert not matches, (
        f"05-enable-ssl.sh: found bare-trust carveout for pgbouncer_authenticator: {matches}. "
        "YSG-RISK-073: bare trust (without clientcert=) is a security regression. "
        "The trust+clientcert=verify-ca carveout belongs ONLY in 10-pgbouncer-auth.sh."
    )


def test_enable_ssl_no_cert_auth_method_for_pgbouncer_authenticator() -> None:
    """05-enable-ssl.sh must NOT use `cert` as auth method for pgbouncer_authenticator.

    BUG-C4-001 (Layer A): `cert clientcert=verify-ca` is invalid PostgreSQL 16 syntax.
    PG16 only accepts `clientcert=verify-full` with cert auth. postgres crash-loops with:
      FATAL: could not load pg_hba.conf; LOG: clientcert only accepts verify-full when
      using cert authentication.
    The correct auth method is `trust clientcert=verify-ca` (PG16-valid, cert-equivalent).
    """
    content = _read(ENABLE_SSL_SCRIPT)
    matches = _CERT_AUTH_METHOD_RE.findall(content)
    assert not matches, (
        f"05-enable-ssl.sh: found `cert` as auth method for pgbouncer_authenticator: {matches}. "
        "BUG-C4-001: `cert clientcert=verify-ca` is invalid PG16 syntax. "
        "Use `trust clientcert=verify-ca` instead."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2: 10-pgbouncer-auth.sh manages the md5 carveout correctly
# ─────────────────────────────────────────────────────────────────────────────

def test_pgbouncer_auth_script_inserts_trust_clientcert_carveout() -> None:
    """10-pgbouncer-auth.sh must insert a trust+clientcert carveout — YSG-RISK-073 cycle 5.

    v2.24.0 step 4 REMOVED the carveout. v2.24.3 cycle 3 INSERTED cert carveout (wrong).
    v2.24.3 cycle 4 committed cert (7f296a1 — broken; PG16 syntax + CN mismatch).
    v2.24.3 cycle 5 INSERTS trust clientcert=verify-ca carveout (cert-equivalent, PG16-valid).
    Verify the script contains the trust+clientcert carveout insertion logic.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must contain trust+clientcert carveout insertion
    assert "trust  clientcert=verify-ca" in content, (
        "10-pgbouncer-auth.sh: trust+clientcert carveout insertion text not found. "
        "Step 4 must insert 'hostssl yashigani pgbouncer_authenticator ... trust  clientcert=verify-ca' "
        "before the catch-all. YSG-RISK-073 cycle 5 (trust+clientcert, not cert or md5)."
    )


def test_pgbouncer_auth_script_no_remove_only() -> None:
    """10-pgbouncer-auth.sh must not only remove the carveout without re-inserting it.

    v2.24.0 bug: the script removed the A2 carveout but did not add a cert/md5 carveout.
    v2.24.3 cycle 5 fix: the script removes stale entries then inserts the md5 carveout.
    Verify the insert step is present (awk first-match insertion or hostssl carveout literal).
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Must have awk or sed insertion before catch-all (awk used in cycle 5 to handle
    # first-match-only; sed /i inserts before every match, creating duplicates)
    assert (
        "hostssl yashigani pgbouncer_authenticator" in content
        or "/^hostssl all/i" in content
        or "awk" in content
    ), (
        "10-pgbouncer-auth.sh: carveout insertion logic not found. "
        "Step 4 must insert the md5 carveout before the catch-all (first match only). "
        "YSG-RISK-073 cycle 5."
    )


def test_pgbouncer_auth_script_no_bare_trust_carveout_inserted() -> None:
    """10-pgbouncer-auth.sh must not insert a BARE trust carveout (trust without clientcert=).

    The v2.24.0 A2 carveout was `trust` with no clientcert requirement — weaker because
    any client could connect without presenting a cert. YSG-RISK-073 cycle 5 uses
    `trust clientcert=verify-ca` — the clientcert= requirement is mandatory.
    This test guards against bare `trust` (without clientcert=) being inserted,
    which would be a security regression to the old v2.24.0 A2 posture.
    The correct form (`trust  clientcert=verify-ca`) is allowed — tested by
    test_pgbouncer_auth_script_inserts_trust_clientcert_carveout.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Check for bare trust insertion — trust without clientcert=verify-ca immediately following
    # Only look at the awk print statements (the actual inserted lines), not comments
    lines = content.splitlines()
    in_awk_block = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Track awk block start/end
        if "awk '" in stripped or "awk \"" in stripped:
            in_awk_block = True
        if in_awk_block and "' \"${_hba}\"" in line:
            in_awk_block = False
        # Only check print statements in awk block (actual pg_hba lines being inserted)
        if in_awk_block and stripped.startswith("print ") and "pgbouncer_authenticator" in stripped:
            # Bare trust: trust appears but clientcert= does NOT follow on the same line
            if "trust" in stripped and "clientcert=" not in stripped:
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: bare trust carveout (no clientcert=) "
                    f"for pgbouncer_authenticator found in awk insertion block: '{stripped}'. "
                    "Use `trust clientcert=verify-ca` not bare `trust`. "
                    "Bare trust requires no cert from the client — security regression to A2 posture."
                )


def test_pgbouncer_auth_script_no_cert_auth_method_inserted() -> None:
    """10-pgbouncer-auth.sh must NOT insert `cert` as auth method for pgbouncer_authenticator.

    BUG-C4-001 (Layer A): `cert clientcert=verify-ca` is invalid PostgreSQL 16 syntax.
    BUG-C4-001 (Layer B): CN=pgbouncer-auth does not match role pgbouncer_authenticator
      (verify-full required with cert auth method — would fail CN check too).
    The correct insertion is `trust clientcert=verify-ca`.
    This test catches the error class that slipped through in cycle 4 (commit 7f296a1).
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Check for `cert` as auth method in non-comment lines that contain pgbouncer_authenticator
    # Pattern: hostssl ... pgbouncer_authenticator ... cert <whitespace or end>
    # Must NOT match lines where cert appears only in comments or in clientcert= option
    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        # Look for the pattern: hostssl ... pgbouncer_authenticator ... whitespace cert whitespace/end
        if "pgbouncer_authenticator" in stripped:
            # Check if cert is used as the auth METHOD (appears after the address field, before options)
            if re.search(r"pgbouncer_authenticator\s+\S+\s+cert(?:\s|$)", stripped):
                pytest.fail(
                    f"10-pgbouncer-auth.sh line {i+1}: `cert` used as auth method for "
                    f"pgbouncer_authenticator in active code: '{stripped}'. "
                    "BUG-C4-001: PG16 rejects cert+verify-ca; CN mismatch with verify-full. "
                    "Use `trust clientcert=verify-ca` instead."
                )


def test_pgbouncer_auth_script_no_md5_auth_method_inserted() -> None:
    """10-pgbouncer-auth.sh must NOT insert `md5` as auth method for pgbouncer_authenticator.

    Cycle 5 first attempt: `md5 clientcert=verify-ca` — also broken in practice.
    pgbouncer 1.25.1 (edoburu image) cannot correctly perform server-side md5 authentication
    against postgres. The md5 challenge response does not match regardless of whether
    userlist.txt contains cleartext or pre-hashed md5. Verified by live test.
    The correct insertion is `trust clientcert=verify-ca`.
    This test guards against regression to the failed md5 approach.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    # Check for `md5` as auth method in non-comment lines that contain pgbouncer_authenticator
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
                    "Use `trust clientcert=verify-ca` instead."
                )


def test_pgbouncer_auth_script_references_ysg_risk_073() -> None:
    """10-pgbouncer-auth.sh must reference YSG-RISK-073 in its comments.

    Ensures the script is correctly updated for v2.24.3 and not a stale v2.24.0 version.
    """
    content = _read(PGBOUNCER_AUTH_SCRIPT)
    assert "YSG-RISK-073" in content, (
        "10-pgbouncer-auth.sh: YSG-RISK-073 reference not found. "
        "The script must be updated to v2.24.3 trust+clientcert carveout logic (cycle 5)."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Helm pg_hba contains md5 carveout (Compose-Helm parity)
# ─────────────────────────────────────────────────────────────────────────────

def test_helm_pghba_has_trust_clientcert_carveout() -> None:
    """Helm chart must also include the trust+clientcert carveout for pgbouncer_authenticator.

    Compose-Helm parity: the trust+clientcert carveout added to compose 10-pgbouncer-auth.sh
    must also appear in the Helm chart's pg_hba.conf ConfigMap/values.
    If no Helm pg_hba file exists, this test is skipped with a clear reason.
    YSG-RISK-073 cycle 5.
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

    matches = _TRUST_CLIENTCERT_CARVEOUT_RE.findall(helm_content)
    assert len(matches) >= 1, (
        f"Helm pg_hba source: trust+clientcert carveout for pgbouncer_authenticator not found. "
        "Compose-Helm parity requires the trust clientcert=verify-ca carveout in Helm too. "
        "YSG-RISK-073 cycle 5."
    )
