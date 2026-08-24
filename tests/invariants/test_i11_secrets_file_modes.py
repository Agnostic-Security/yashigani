"""
I11 — docker/secrets/ file modes never regress to world-readable/writable
(CWE-732), on Docker AND Podman (compose-mode; K8s uses Secret objects with
defaultMode, out of scope — YSG-RISK-053 established this class as
Compose-only).

## Prior art (Lu's audit finding, v4.1.2)

Lu's ASVS L3 gate audit: this exact invariant was flagged NEEDS REVIEW
because NOTHING in the test tree asserted docker/secrets/ file modes, and
CWE-732 on this exact surface HAS ALREADY REGRESSED TWICE in v2.23.1:

  1. §6.B / #64 (v2.23.1 retro): install.sh wrote credentials and private
     keys with `chmod 644` (world-readable) — same class of bug that had
     JUST been fixed in restore.sh's P0-1 (`f285b8f`). Parked to v2.23.2
     rather than re-scoped onto the tagged release. §8.G's corrective
     action: "explicit chmod 400 on ca_*.key + *_client.key, chmod 440 on
     credentials with container-UID ownership, nothing chmod 644 under
     docker/secrets/. Post-install invariant asserts no world-readable
     file." — this is the FIRST time that invariant was proposed and it
     was never actually landed as a test (§8.B: "the single fix that would
     have prevented the majority of the process failures ... that alone
     would have caught ... the install.sh CWE-732 that required Lu and a
     `ls` to find").
  2. LIVE-BACKUP-PERMS-001 (v2.23.1 retro, VM smoke 2026-05-28): the
     general "make bind-mounted config readable" o+rX sweep re-exposed
     BACKUP COPIES of docker/secrets (postgres dump, admin passwords,
     agent tokens, .env) to world-read, because the prune list covered
     the LIVE docker/secrets/ dir but not backups/<ts>/ — the S1
     assertion passed while the backup copies sat at 0604/0644.

Both regressions were on the SAME underlying mechanism: install.sh's single
`_fix_config_perms()` sweep (`install.sh` ~7134) that makes bind-mounted
config world-readable for container UIDs to consume, MUST prune every path
holding secret material before that sweep runs, and MUST then positively
assert (not just intend) that no non-cert secret file is world-readable.

## Real intended modes -- derived from install.sh's own logic, not invented

install.sh's own `_fix_config_perms()` (the CURRENT, evolved implementation
-- superseding the 2023.1-era `chmod 400`/`chmod 440` prescription with the
GID-2002-based Option B scheme, per YSG-SECRETS-DIST-002 / Su 2026-05-21)
implements the CWE-732 contract as:

  * `docker/secrets/`, `docker/secrets-caddy/`, `docker/secrets-pki-attest/`
    are PRUNED from the general o+rX "make everything container-readable"
    sweep (they have their own perms logic; widening them would defeat it).
  * Within `docker/secrets/` and `docker/secrets-caddy/`: every file EXCEPT
    `*.crt` (certs are intentionally 0644 -- public material needed by
    every container UID for mTLS peer verification) must NOT be
    world-readable (`-perm -004`). The check is explicitly NOT `-perm -040`
    (group-readable) -- group-readable is a legitimate, intentional design
    choice for GID-2002 shared-consumer files (`caddy_internal_hmac`,
    `pgbouncer_authenticator_password`, `langflow_yashigani_token`, all
    0640) and asserting on it would be a false-positive abort (this was
    itself a bug, fixed as "A1 / Iris BLOCKING", per the comment at
    install.sh ~7206).
  * The check SELF-HEALS (`chmod o-rwx`) before asserting, then FAILS
    CLOSED (`exit 1`) if any non-cert secret file is still world-readable
    after the heal attempt -- tightening rather than aborting keeps
    upgrades moving; an unfixable residual still hard-aborts the install.
  * `docker/secrets-pki-attest/` holds one file whose VALUE is non-sensitive
    (a SHA-256 digest, not key material -- FINDING-V412-RESTART-012) so it
    is not subject to the world-READABLE check, but the DIRECTORY itself
    must never be world-WRITABLE (`-perm -002`) -- same self-heal +
    fail-closed pattern.
  * The individual `chmod 600` calls throughout `generate_secrets()`
    (admin passwords, TOTP secrets, postgres/redis passwords, agent
    tokens) establish owner-only as the DEFAULT posture for
    single-consumer secrets; `_do_chmod_0640` + GID 2002 chgrp is the
    explicit, narrow exception for the small set of genuinely
    multi-consumer shared secrets (YSG-SECRETS-DIST-002).

## Docker vs Podman

`_fix_config_perms()` is NOT runtime-branched -- it runs identically for
`--runtime docker` and `--runtime podman` (verified: no `$RUNTIME`/
`$YSG_RUNTIME` conditional anywhere in the function body). Mode BITS are
not namespace-relative (unlike OWNERSHIP, which legitimately differs under
rootless Podman's subuid remap -- see ISSUE-027, a documented case where a
host-side WRITE is expected to fail under rootless Podman because the
container already wrote the file as a subuid-mapped UID the host installer
process cannot claim). A file's raw `st_mode` world-read/write bits are
identical whether inspected from inside or outside a user namespace, so the
MODE invariant this test asserts is legitimately IDENTICAL for both
runtimes -- there is no "runtime A allows X, runtime B doesn't" split to
encode here, unlike ownership-mechanics tests elsewhere in this repo
(`test_risk172_langflow_token_perms.py`).

## What this test does NOT do (and why)

Per this directory's own convention (README.md "Code-asserted-here vs
live-VM (#44) proof" -- these are pure-Python source/file assertions, no
live stack, no Docker/Podman binary required, CI-portable), this test:

  (a) statically parses install.sh's `_fix_config_perms()` source text to
      assert the fail-closed contract described above is PRESENT (mirrors
      the existing I1-I8 pattern and
      `test_risk172_langflow_token_perms.py`'s source-grep pattern) --
      this is the part that would have caught both v2.23.1 regressions
      before they shipped, and

  (b) ADDITIONALLY walks a REAL `docker/secrets/` tree if one is present on
      the machine running the suite (env var `YASHIGANI_TEST_SECRETS_DIR`,
      falling back to `<repo_root>/docker/secrets` -- this repo checkout
      has neither, so (b) is SKIPPED here; on a live install/VM smoke run
      it is NOT skipped and asserts real octal modes) -- this is the
      LIVE-PROOF (#44) half, proving the actual on-disk state matches the
      contract (a) only proves is intended.

install.sh is Su's file (HANDS OFF per dispatch) -- this test reads it, it
never writes to it. If (a) ever needs a NEW contract element that isn't yet
in install.sh, that is an install.sh change routed to Su, not something
this test works around.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_INSTALL_SH = _REPO_ROOT / "install.sh"


def _read_install_sh() -> str:
    return _INSTALL_SH.read_text(encoding="utf-8")


def _extract_fix_config_perms(source: str) -> str:
    """Return the body of _fix_config_perms() as a raw string, from its
    definition line to the closing brace at column 0 (matches the function's
    own `}` dedent -- install.sh functions in this file are not nested)."""
    m = re.search(r"^_fix_config_perms\(\)\s*\{", source, re.MULTILINE)
    assert m is not None, (
        "I11: install.sh no longer defines _fix_config_perms() -- the "
        "CWE-732 secrets-mode contract this test guards has been removed "
        "or renamed. If intentional, route through Su (install.sh owner) "
        "and update this test's target function name."
    )
    start = m.start()
    end = source.index("\n}\n", start)
    return source[start:end]


class TestFixConfigPermsContractPresent:
    """(a) Static source-text assertions against install.sh's
    _fix_config_perms() -- proves the CWE-732 self-heal + fail-closed
    contract is present in the shipped installer, for BOTH Docker and
    Podman (the function is not runtime-branched)."""

    @pytest.fixture(scope="class")
    def fn_body(self) -> str:
        return _extract_fix_config_perms(_read_install_sh())

    def test_secrets_dirs_pruned_from_general_widen_sweep(self, fn_body):
        for path in (
            "docker/secrets",
            "docker/secrets-caddy",
            "docker/secrets-pki-attest",
        ):
            assert f'-path "${{work_dir}}/{path}" -prune' in fn_body, (
                f"I11 regression: {path!r} is no longer pruned from the "
                f"general o+rX bind-mount-readability sweep -- this is "
                f"exactly the v2.23.1 LIVE-BACKUP-PERMS-001 regression "
                f"class (a secrets-bearing path silently re-exposed to "
                f"world-read by the general sweep because the prune list "
                f"didn't cover it)."
            )

    def test_backups_dir_pruned(self, fn_body):
        # The SPECIFIC v2.23.1 LIVE-BACKUP-PERMS-001 regression: backup
        # copies of docker/secrets (under backups/<ts>/) were re-exposed
        # because backups/ itself wasn't in the prune list, even though the
        # live docker/secrets/ was.
        assert '-path "${work_dir}/backups" -prune' in fn_body, (
            "I11 regression (LIVE-BACKUP-PERMS-001 class): backups/ is no "
            "longer pruned from the o+rX sweep -- backup copies of "
            "docker/secrets (admin passwords, agent tokens, .env, DB dump) "
            "would be silently widened to world-readable even though the "
            "live secrets dir is correctly pruned."
        )

    def test_world_read_check_uses_perm_004_not_perm_040(self, fn_body):
        # A1 (Iris BLOCKING): checking -perm -040 (group-readable) instead
        # of -perm -004 (world-readable) is itself a bug -- it false-
        # positive-aborts on legitimate GID-2002 shared secrets like
        # caddy_internal_hmac (intentionally 0640).
        assert "-perm -004" in fn_body, (
            "I11 regression: the CWE-732 world-readable check no longer "
            "uses -perm -004 -- either the check was removed, or it "
            "regressed to checking group-readability (-perm -040), which "
            "the A1/Iris fix explicitly rejected as a false-positive "
            "generator against legitimate GID-2002 shared secrets."
        )
        # "-perm -040" is allowed to appear in EXPLANATORY COMMENTS (the A1
        # fix documents, in prose, why -perm -040 is the wrong check) --
        # what must never reappear is an ACTIVE `find` predicate using it.
        active_perm040_lines = [
            line for line in fn_body.splitlines()
            if "find " in line and "-perm -040" in line and not line.lstrip().startswith("#")
        ]
        assert active_perm040_lines == [], (
            f"I11 regression: an active `find ... -perm -040` predicate "
            f"reappeared in _fix_config_perms() -- this reintroduces the "
            f"exact false-positive the A1/Iris fix removed (aborts on "
            f"legitimate 0640 GID-2002 shared secrets, e.g. "
            f"caddy_internal_hmac): {active_perm040_lines!r}"
        )

    def test_cert_files_excluded_from_world_read_check(self, fn_body):
        # *.crt files are intentionally 0644 (public material for mTLS peer
        # verification by every container UID) -- must not be flagged.
        assert '! -name "*.crt"' in fn_body, (
            "I11 regression: the world-readable check no longer excludes "
            "*.crt files -- public certificate material would trip the "
            "CWE-732 self-heal/abort, which is both wrong (certs are "
            "meant to be world-readable) and would break mTLS peer "
            "verification if self-healed."
        )

    def test_self_heals_before_asserting(self, fn_body):
        assert "chmod o-rwx" in fn_body, (
            "I11 regression: the self-heal chmod (o-rwx) on world-readable "
            "non-cert secret files is missing -- installs/upgrades that "
            "land a stray 0644 secret (e.g. from a prior install or a "
            "widened umask) would hard-abort instead of self-healing."
        )

    def test_fails_closed_on_residual_world_readable_secret(self, fn_body):
        # Must find "CWE-732" error log + exit 1 AFTER the self-heal
        # attempt -- proves this is fail-CLOSED, not fail-open (a self-heal
        # that silently swallows an unfixable residual would be worse than
        # no check at all -- it would look green while shipping a
        # world-readable secret).
        assert re.search(
            r"CWE-732:.*world-readable.*STILL present", fn_body,
        ), (
            "I11 regression: no fail-closed error log for a residual "
            "world-readable secret file that survived the self-heal "
            "attempt -- see this file's module docstring for why "
            "fail-closed (not fail-open / warn-and-continue) is required "
            "here."
        )
        # The abort must be a genuine `exit 1`, not a log_warn/continue.
        heal_idx = fn_body.index("chmod o-rwx")
        residual_check_region = fn_body[heal_idx:]
        assert re.search(r"exit 1", residual_check_region), (
            "I11 regression: the residual-world-readable-secret path does "
            "not exit 1 -- this is a Lifespan/install-fail-closed-class "
            "violation (SOP 1): a secret that could not be tightened must "
            "hard-abort the install, not warn and continue with the "
            "secret exposed."
        )

    def test_secrets_caddy_dir_also_swept(self, fn_body):
        # YSG-RISK-053 extended the sweep from docker/secrets/ alone to
        # ALSO cover docker/secrets-caddy/ (Caddy mesh key + HMAC). Guard
        # against the sweep loop regressing to a single hardcoded dir.
        assert re.search(
            r'for\s+_sweep_dir\s+in\s+"\$\{work_dir\}/docker/secrets"\s+'
            r'"\$\{work_dir\}/docker/secrets-caddy"',
            fn_body,
        ), (
            "I11 regression: the CWE-732 sweep loop no longer iterates "
            "BOTH docker/secrets/ AND docker/secrets-caddy/ -- see "
            "YSG-RISK-053 (Caddy mesh key + HMAC in a separate scoped "
            "secrets dir, which must get the identical CWE-732 guard as "
            "the flat docker/secrets/ dir)."
        )

    def test_pki_attest_dir_world_write_guard_present(self, fn_body):
        # FINDING-V412-RESTART-012: docker/secrets-pki-attest/'s one file
        # is non-sensitive (a SHA-256 digest, not key material) so it's
        # exempt from the world-READ check, but the DIRECTORY must never
        # be world-WRITABLE (an attacker able to write into this dir could
        # forge a fake "attested" digest for a rogue CA).
        assert "docker/secrets-pki-attest" in fn_body
        assert "chmod o-w" in fn_body, (
            "I11 regression: docker/secrets-pki-attest/ world-write "
            "self-heal (chmod o-w) is missing."
        )
        assert "-perm -002" in fn_body, (
            "I11 regression: docker/secrets-pki-attest/ world-write "
            "assertion (-perm -002) is missing."
        )
        assert "FINDING-V412-RESTART-012" in fn_body, (
            "I11 regression: the pki-attest world-write fail-closed check "
            "lost its FINDING-V412-RESTART-012 traceability comment."
        )


# ─────────────────────────────────────────────────────────────────────────────
# (b) LIVE-PROOF (#44) — real filesystem, only when a real secrets dir exists.
# ─────────────────────────────────────────────────────────────────────────────

def _live_secrets_dir() -> Path | None:
    override = os.environ.get("YASHIGANI_TEST_SECRETS_DIR")
    candidates = [Path(override)] if override else [_REPO_ROOT / "docker" / "secrets"]
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _live_secrets_caddy_dir() -> Path | None:
    override = os.environ.get("YASHIGANI_TEST_SECRETS_CADDY_DIR")
    candidates = (
        [Path(override)] if override else [_REPO_ROOT / "docker" / "secrets-caddy"]
    )
    for c in candidates:
        if c.is_dir():
            return c
    return None


def _mode_octal(p: Path) -> str:
    return oct(stat.S_IMODE(p.stat().st_mode))


# Git-tracked directory placeholders -- NOT secret material, intentionally
# world-readable (they are committed to the repo so an empty secrets/
# directory survives a clone). Excluded from the world-read/write walkers
# below so this test doesn't false-positive on the repo's own .gitkeep
# files (e.g. docker/secrets-caddy/.gitkeep, present in this checkout).
_NON_SECRET_PLACEHOLDERS = frozenset({".gitkeep", ".gitignore"})


# Files established by install.sh's own `chmod 600 "${secrets_dir}/..."`
# call sites (generate_secrets()) as owner-only, single-consumer secrets.
# Not exhaustive of every secret install.sh writes -- a representative
# sample across the categories (admin creds, TOTP, DB creds, agent tokens).
_EXPECT_0600 = (
    "admin1_password",
    "admin1_username",
    "admin1_totp_secret",
    "admin2_password",
    "admin2_username",
    "admin2_totp_secret",
    "postgres_password",
    "redis_password",
    "admin_initial_password",
)

# GID-2002 shared-consumer secrets (YSG-SECRETS-DIST-002 Option B):
# group-readable by design, never world-readable.
_EXPECT_0640 = (
    "pgbouncer_authenticator_password",
    "langflow_yashigani_token",
)


@pytest.mark.skipif(
    _live_secrets_dir() is None,
    reason=(
        "No live docker/secrets/ directory found (this repo checkout has "
        "none) -- this half of I11 is the LIVE-PROOF (#44) VM-smoke check; "
        "it runs (and is NOT skipped) against a real install/upgrade, "
        "asserting actual on-disk octal modes rather than install.sh's "
        "source-level intent. Set YASHIGANI_TEST_SECRETS_DIR to point at "
        "a live secrets dir to exercise it locally."
    ),
)
class TestLiveSecretsDirModes:
    """(b) Walk a REAL docker/secrets/ tree and assert the actual on-disk
    modes match the CWE-732 contract asserted statically above. Runtime
    (Docker vs Podman) is irrelevant here — mode bits are not namespace-
    relative; only ownership legitimately differs by runtime (ISSUE-027),
    and ownership is out of scope for this file-MODE invariant."""

    def test_no_non_cert_file_is_world_readable(self):
        secrets_dir = _live_secrets_dir()
        offenders = []
        for f in secrets_dir.rglob("*"):
            if not f.is_file() or f.suffix == ".crt" or f.name in _NON_SECRET_PLACEHOLDERS:
                continue
            mode = f.stat().st_mode
            if mode & stat.S_IROTH:
                offenders.append((str(f), oct(stat.S_IMODE(mode))))
        assert offenders == [], (
            f"CWE-732: world-readable non-cert secret file(s) found under "
            f"{secrets_dir}: {offenders}"
        )

    def test_no_non_cert_file_is_world_writable(self):
        secrets_dir = _live_secrets_dir()
        offenders = []
        for f in secrets_dir.rglob("*"):
            if not f.is_file() or f.suffix == ".crt" or f.name in _NON_SECRET_PLACEHOLDERS:
                continue
            mode = f.stat().st_mode
            if mode & stat.S_IWOTH:
                offenders.append((str(f), oct(stat.S_IMODE(mode))))
        assert offenders == [], (
            f"CWE-732: world-writable non-cert secret file(s) found under "
            f"{secrets_dir}: {offenders}"
        )

    def test_owner_only_secrets_are_0600(self):
        secrets_dir = _live_secrets_dir()
        for name in _EXPECT_0600:
            p = secrets_dir / name
            if not p.exists():
                continue  # not every secret exists on every deployment (e.g. admin2_* on single-admin dev installs)
            assert _mode_octal(p) == "0o600", (
                f"CWE-732: {p} is {_mode_octal(p)}, expected 0o600 "
                f"(owner-only single-consumer secret per generate_secrets())."
            )

    def test_gid2002_shared_secrets_are_0640(self):
        secrets_dir = _live_secrets_dir()
        for name in _EXPECT_0640:
            p = secrets_dir / name
            if not p.exists():
                continue
            assert _mode_octal(p) == "0o640", (
                f"CWE-732 / YSG-SECRETS-DIST-002: {p} is {_mode_octal(p)}, "
                f"expected 0o640 (GID-2002 shared-consumer secret) -- "
                f"NOT 0o644 (the pre-Option-B world-readable posture) and "
                f"NOT 0o600 (would break the legitimate second consumer's "
                f"group-read access)."
            )

    def test_ca_keys_are_0400_if_present(self):
        secrets_dir = _live_secrets_dir()
        for name in ("ca_root.key", "ca_intermediate.key"):
            p = secrets_dir / name
            if not p.exists():
                continue
            assert _mode_octal(p) == "0o400", (
                f"CWE-732: {p} is {_mode_octal(p)}, expected 0o400 "
                f"(CA private key -- owner-read-only, never leaves the "
                f"install host, never mounted into any workload container)."
            )


@pytest.mark.skipif(
    _live_secrets_caddy_dir() is None,
    reason="No live docker/secrets-caddy/ directory found (see TestLiveSecretsDirModes docstring).",
)
class TestLiveSecretsCaddyDirModes:
    def test_hmac_is_0640(self):
        d = _live_secrets_caddy_dir()
        p = d / "caddy_internal_hmac"
        if not p.exists():
            pytest.skip("caddy_internal_hmac not present")
        assert _mode_octal(p) == "0o640", (
            f"CWE-732: {p} is {_mode_octal(p)}, expected 0o640 "
            f"(caddy<->backoffice HMAC handoff -- group-readable by "
            f"design, per the A1/Iris fix comment in install.sh)."
        )

    def test_no_non_cert_file_is_world_readable(self):
        d = _live_secrets_caddy_dir()
        offenders = []
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix == ".crt" or f.name in _NON_SECRET_PLACEHOLDERS:
                continue
            if f.stat().st_mode & stat.S_IROTH:
                offenders.append(str(f))
        assert offenders == []
