"""
v4.1 issue #144 (DB-crypto half) — AES-256 pgcrypto drift guards.

Static guards proving every pgp_sym_encrypt() call site in the codebase
carries the AES-256 options argument, and that the migration's frozen copy
of the option string matches the single source of truth
(yashigani.db.pgcrypto.PGP_SYM_ENCRYPT_OPTIONS).

Live-DB behaviour (packet cipher byte == 9, decrypt of 128- and 256-framed
rows, migration idempotency) is covered by
src/tests/integration/test_v41_pgcrypto_aes256_integration.py.

Last updated: 2026-07-06T00:00:00+00:00
"""
from __future__ import annotations

import pathlib
import re

SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "yashigani"

# pgp_sym_encrypt( followed by a real argument (not the bare "()" mention in
# the db/postgres.py docstring).
_ENCRYPT_CALL = re.compile(r"pgp_sym_encrypt\(\s*[^)\s]")

_OPTIONS = "cipher-algo=aes256"


def _encrypt_call_sites() -> list[tuple[pathlib.Path, int, str]]:
    """Every pgp_sym_encrypt(<arg> occurrence in src/yashigani/**/*.py with
    the 300 chars of source that follow it (enough to cover the argument
    list of every call site in the repo)."""
    sites = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for m in _ENCRYPT_CALL.finditer(text):
            # Skip pure comment mentions (SQL '--' / Python '#'), e.g. the
            # column comment in migration 0008's frozen DDL.
            line_start = text.rfind("\n", 0, m.start()) + 1
            prefix = text[line_start: m.start()]
            if "--" in prefix or "#" in prefix:
                continue
            line = text.count("\n", 0, m.start()) + 1
            sites.append((path, line, text[m.start(): m.start() + 300]))
    return sites


def test_encrypt_call_sites_found() -> None:
    """Sanity: the scan actually sees the known call sites (guards against
    the regex rotting and the drift test passing vacuously)."""
    files = {site[0].name for site in _encrypt_call_sites()}
    for expected in (
        "settings_store.py",       # auth_settings upsert (x2)
        "pg_webauthn.py",          # webauthn public_key insert
        "webauthn_credential.py",  # INSERT_WEBAUTHN_CREDENTIAL
        "models.py",               # shadowed INSERT_INFERENCE_EVENT copy
        "__init__.py",             # db/models INSERT_INFERENCE_EVENT
        "0027_pgcrypto_aes256_reencrypt.py",  # migration re-encrypts
    ):
        assert expected in files, f"scan no longer sees {expected}"


def test_every_encrypt_call_is_aes256() -> None:
    """DRIFT GUARD: a pgp_sym_encrypt call without cipher-algo=aes256
    silently writes AES-128. Every call site must carry the option
    (interpolated from yashigani.db.pgcrypto.PGP_SYM_ENCRYPT_OPTIONS, or the
    migration's frozen literal)."""
    # Accept the literal, the app-side constant placeholder, or the
    # migration's frozen-copy placeholder (f-string source text).
    tokens = (_OPTIONS, "{PGP_SYM_ENCRYPT_OPTIONS}", "{_PGP_OPTS}")
    offenders = [
        f"{path.relative_to(SRC_ROOT.parent)}:{line}"
        for path, line, ctx in _encrypt_call_sites()
        if not any(tok in ctx for tok in tokens)
    ]
    assert not offenders, (
        "pgp_sym_encrypt call site(s) missing 'cipher-algo=aes256' "
        f"(AES-128 write regression): {offenders}"
    )


def test_single_source_of_truth_constant() -> None:
    from yashigani.db.pgcrypto import AES256_PGP_ALGO_ID, PGP_SYM_ENCRYPT_OPTIONS

    assert PGP_SYM_ENCRYPT_OPTIONS == _OPTIONS
    assert AES256_PGP_ALGO_ID == 9  # RFC 4880 §9.2


def test_migration_frozen_literal_matches_constant() -> None:
    """Migrations must not import app code, so 0027 freezes its own copy of
    the option string — assert it hasn't drifted."""
    from yashigani.db.pgcrypto import PGP_SYM_ENCRYPT_OPTIONS

    mig = (
        SRC_ROOT / "db" / "migrations" / "versions"
        / "0027_pgcrypto_aes256_reencrypt.py"
    ).read_text(encoding="utf-8")
    assert f'_PGP_OPTS = "{PGP_SYM_ENCRYPT_OPTIONS}"' in mig


def test_generated_sql_constants_carry_option() -> None:
    """The f-string interpolation actually lands in the SQL the app
    executes (module constants imported by payload_logger / webauthn)."""
    from yashigani.db.models import INSERT_INFERENCE_EVENT
    from yashigani.db.models.webauthn_credential import INSERT_WEBAUTHN_CREDENTIAL

    assert INSERT_INFERENCE_EVENT.count(f"'{_OPTIONS}'") == 2
    assert INSERT_WEBAUTHN_CREDENTIAL.count(f"'{_OPTIONS}'") == 1


def test_migration_row_sql_rewrite_applied() -> None:
    """0027 derives its per-row UPDATE from the bulk UPDATE via .replace();
    assert the rewrite actually took (a silent no-op .replace() would make
    the per-row path update every pending row on each iteration)."""
    import importlib.util

    path = (
        SRC_ROOT / "db" / "migrations" / "versions"
        / "0027_pgcrypto_aes256_reencrypt.py"
    )
    spec = importlib.util.spec_from_file_location("mig_0027", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert "WHERE id = :id AND created_at = :created_at" in mod._REENCRYPT_INFERENCE_ROW
    assert mod._REENCRYPT_INFERENCE_ROW != mod._REENCRYPT_INFERENCE_BULK
    assert mod._REENCRYPT_INFERENCE_ROW.count(f"'{_OPTIONS}'") == 2
