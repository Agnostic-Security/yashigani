"""
I10 — PKI chain-of-continuity + root-attestation isolation
(FINDING-V412-RESTART-012 / laura-012-rogue-reattack.md).

INVARIANT (must ALWAYS hold): no compose/K8s service other than ``postgres`` can
read *or* write ``ca_root.attested_sha256`` — the operator-attested root-rotation
pin that ``docker/postgres/05-enable-ssl.sh`` trusts absolutely (root CAs are
self-signed; there is nothing to cryptographically verify a NEW root against, so
the attestation file IS the trust anchor for "is this root swap operator-
sanctioned").

Laura proved (2026-07-20, ``testing_runs/yashigani/v412-acc-podman-20260720/
evidence/laura-012-rogue-reattack.md``) that when this file lived inside the
shared ``docker/secrets/`` tree — which backoffice ALSO mounted, nominally
read-only — a podman-compose fork bug silently dropped backoffice's ``:ro`` flag
whenever a ``:rw`` child mount shared its path prefix. A compromised backoffice
process could then: forge ``ca_root.attested_sha256`` -> poison
``.ysg_pinned_root_sha256`` -> trigger a ``pg_ctl reload`` of a fully
attacker-controlled CA bundle -> get a rogue mTLS leaf accepted by
``clientcert=verify-ca``. Full rogue-system-injection, proven live.

The fix has TWO independent, complementary layers (both required — Laura
verdict, do NOT rely on either alone):

  A. The RO-mount bug itself is closed: backoffice's ``/run/secrets`` is now a
     PURE ``:ro`` mount with no nested ``:rw`` children (the 4 legitimately
     writable secrets — admin_initial_password, grafana_admin_password,
     redis_password, license_key — moved to a separate top-level mount,
     ``/run/secrets-rw``, that shares no path prefix with ``/run/secrets``).

  B. Defence in depth: ``ca_root.attested_sha256`` no longer lives inside the
     shared ``docker/secrets/`` tree AT ALL. It lives in a dedicated,
     postgres-ONLY directory (``docker/secrets-pki-attest/``) that NO other
     compose service or K8s manifest mounts, at any permission. Even if some
     FUTURE regression re-drops a ``:ro`` flag on any other service's
     ``/run/secrets`` mount, that service still cannot reach this file — it
     simply isn't part of any mount it has.

This suite is text-level / static (always runs, no root, no running stack,
mirrors the ``tests/invariants/test_i9_*`` convention) plus one optional live
probe that only runs when a Yashigani podman/docker stack from THIS repo is
already up (skipped otherwise — see test_i9's "live adversarial probe" split).
"""
from __future__ import annotations

import difflib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_YAML = REPO_ROOT / "docker" / "docker-compose.yml"
PODMAN_VIRTIOFS_OVERRIDE = REPO_ROOT / "docker" / "docker-compose.podman-virtiofs-override.yml"
DOCKER_SSL_SH = REPO_ROOT / "docker" / "postgres" / "05-enable-ssl.sh"
HELM_SSL_SH = REPO_ROOT / "helm" / "yashigani" / "files" / "postgres-05-enable-ssl.sh"
HELM_POSTGRES_YAML = REPO_ROOT / "helm" / "yashigani" / "templates" / "postgres.yaml"
HELM_BACKOFFICE_YAML = REPO_ROOT / "helm" / "yashigani" / "templates" / "backoffice.yaml"

ATTEST_FILENAME = "ca_root.attested_sha256"
ATTEST_HOST_DIR = "secrets-pki-attest"
ATTEST_MOUNT_PATH = "/run/secrets-pki-attest"


# --------------------------------------------------------------------------- #
# Helpers — parse docker-compose.yml into per-service text blocks.
# --------------------------------------------------------------------------- #

def _compose_text() -> str:
    return COMPOSE_YAML.read_text(encoding="utf-8")


def _service_block(text: str, service: str) -> str:
    """
    Return the raw text of a single top-level compose service block
    (2-space-indented ``  <service>:`` through the next 2-space-indented key,
    or EOF). Good enough for this file's fixed 2-space indent convention —
    same technique used elsewhere in the invariant suite for YAML slicing.
    """
    pattern = re.compile(
        rf"^  {re.escape(service)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        re.DOTALL | re.MULTILINE,
    )
    m = pattern.search(text)
    assert m, f"docker-compose.yml: could not locate service block '{service}:'"
    return m.group(1)


def _all_service_names(text: str) -> list[str]:
    # Stop at the top-level `volumes:` block (named-volume declarations, not
    # a service) which docker-compose.yml places after the services block.
    names = re.findall(r"^  ([a-zA-Z0-9_-]+):\n", text, re.MULTILINE)
    # De-dup while preserving order (dict.fromkeys trick).
    return list(dict.fromkeys(names))


# --------------------------------------------------------------------------- #
# A — backoffice /run/secrets is a PURE :ro mount (root cause fix)
# --------------------------------------------------------------------------- #

def test_backoffice_run_secrets_is_pure_ro_no_nested_rw_children() -> None:
    block = _service_block(_compose_text(), "backoffice")
    assert "- ./secrets:/run/secrets:ro" in block, (
        "backoffice must mount the shared secrets dir at /run/secrets:ro"
    )
    # The historical bug: a `:rw` child mount sharing the /run/secrets/ prefix
    # silently drops the parent's `:ro` on this podman-compose fork. Assert
    # NO volume line targets a path nested under /run/secrets/ with :rw.
    nested_rw = re.findall(r"^\s*-\s+\S+:/run/secrets/\S+:rw\s*$", block, re.MULTILINE)
    assert not nested_rw, (
        "FINDING-V412-RESTART-012 regression: a :rw mount is nested under "
        "/run/secrets/ on backoffice again — this silently drops the parent's "
        ":ro on the podman-compose fork (laura-012-rogue-reattack.md Attack 1). "
        f"Offending line(s): {nested_rw}"
    )


def test_backoffice_writable_secrets_moved_to_separate_mount() -> None:
    block = _service_block(_compose_text(), "backoffice")
    for name in (
        "admin_initial_password",
        "grafana_admin_password",
        "redis_password",
        "license_key",
    ):
        assert f"/run/secrets-rw/{name}:rw" in block, (
            f"backoffice must shadow-mount {name} at /run/secrets-rw/{name}:rw "
            "(separate top-level path, no prefix collision with /run/secrets)"
        )


def test_podman_virtiofs_override_backoffice_secrets_is_ro() -> None:
    """The ACTUAL live root cause on macOS Podman (found during runtime
    verification of this fix, 2026-07-21): docker-compose.podman-virtiofs-
    override.yml's backoffice.volumes entry for /run/secrets was ":rw,U" —
    podman-compose's list-merge replaces the base file's entry by matching
    in-container TARGET, so this override silently won over the (correct)
    base docker-compose.yml ":ro" entry. Confirmed live via `podman inspect`
    showing RW=true even after the base-file nested-mount fix alone. Every
    OTHER service in this file uses ro,U for /run/secrets — backoffice must
    too."""
    text = PODMAN_VIRTIOFS_OVERRIDE.read_text(encoding="utf-8")
    block = _service_block(text, "backoffice")
    assert "./secrets:/run/secrets:ro,U" in block, (
        "docker-compose.podman-virtiofs-override.yml backoffice must mount "
        "/run/secrets as ro,U — this override REPLACES the base file's entry "
        "by target, so an :rw here silently defeats the base-file RO fix "
        "(FINDING-V412-RESTART-012 root cause on macOS Podman)"
    )
    assert not re.search(r"/run/secrets:rw", block), (
        "backoffice must not mount /run/secrets rw anywhere in this override file"
    )


def test_podman_virtiofs_override_postgres_mounts_attest_dir() -> None:
    text = PODMAN_VIRTIOFS_OVERRIDE.read_text(encoding="utf-8")
    block = _service_block(text, "postgres")
    assert f"./{ATTEST_HOST_DIR}:{ATTEST_MOUNT_PATH}:ro,U" in block, (
        "postgres must mount the attestation dir ro,U in the macOS virtiofs "
        "override too (directory-level bind mounts need :U on this virtiofs "
        "setup, same as /run/secrets)"
    )


def test_podman_virtiofs_override_no_other_service_mounts_attest_dir() -> None:
    text = PODMAN_VIRTIOFS_OVERRIDE.read_text(encoding="utf-8")
    for service in _all_service_names(text):
        if service == "postgres":
            continue
        block = _service_block(text, service)
        assert ATTEST_HOST_DIR not in block, (
            f"service '{service}' must NOT mount {ATTEST_HOST_DIR}/ in the "
            "macOS virtiofs override either — postgres-only isolation"
        )


def test_bootstrap_write_docker_secrets_supports_separate_write_dir() -> None:
    bootstrap_py = (REPO_ROOT / "src" / "yashigani" / "auth" / "bootstrap.py").read_text(
        encoding="utf-8"
    )
    assert "write_dir" in bootstrap_py, (
        "write_docker_secrets() must accept a write_dir param distinct from "
        "the (now read-only) secrets_dir — see FINDING-V412-RESTART-012"
    )


def test_license_route_writes_via_separate_rw_mount() -> None:
    license_py = (
        REPO_ROOT / "src" / "yashigani" / "backoffice" / "routes" / "license.py"
    ).read_text(encoding="utf-8")
    assert "_LICENSE_SECRET_WRITE_PATH" in license_py
    assert "YASHIGANI_SECRETS_RW_DIR" in license_py
    # The write/delete calls must use the write path, not the (RO) read path.
    assert 'open(_LICENSE_SECRET_WRITE_PATH, "w")' in license_py
    assert "os.remove(_LICENSE_SECRET_WRITE_PATH)" in license_py


# --------------------------------------------------------------------------- #
# B — ca_root.attested_sha256 isolated to a postgres-ONLY mount
# --------------------------------------------------------------------------- #

def test_postgres_mounts_dedicated_attest_dir_ro() -> None:
    block = _service_block(_compose_text(), "postgres")
    assert f"./{ATTEST_HOST_DIR}:{ATTEST_MOUNT_PATH}:ro" in block, (
        "postgres must mount the dedicated root-attestation dir read-only"
    )


def test_no_other_service_mounts_attest_dir() -> None:
    """The highest-value assertion in this suite: NO service but postgres may
    reference the attestation directory, at any permission. This is what makes
    the file unforgeable even if a future :ro regression reappears elsewhere —
    the compromised service simply has no path to it."""
    text = _compose_text()
    for service in _all_service_names(text):
        if service == "postgres":
            continue
        block = _service_block(text, service)
        assert ATTEST_HOST_DIR not in block, (
            f"service '{service}' must NOT mount {ATTEST_HOST_DIR}/ at all "
            "(postgres-only isolation — FINDING-V412-RESTART-012 defence B)"
        )


def test_attest_dir_gitignored_and_tracked_via_gitkeep() -> None:
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert f"docker/{ATTEST_HOST_DIR}/*" in gitignore
    assert f"!docker/{ATTEST_HOST_DIR}/.gitkeep" in gitignore
    assert (REPO_ROOT / "docker" / ATTEST_HOST_DIR).is_dir(), (
        f"docker/{ATTEST_HOST_DIR}/ must exist on disk (Podman rootless "
        "bind-mount fails hard on a missing host path — .gitkeep tracks it)"
    )
    assert (REPO_ROOT / "docker" / ATTEST_HOST_DIR / ".gitkeep").is_file()


def test_05_enable_ssl_reads_attestation_from_dedicated_dir() -> None:
    for script in (DOCKER_SSL_SH, HELM_SSL_SH):
        text = script.read_text(encoding="utf-8")
        assert f'_ATTEST_DIR="${{YASHIGANI_PG_ATTEST_DIR:-{ATTEST_MOUNT_PATH}}}"' in text, (
            f"{script}: _ATTEST_DIR must default to {ATTEST_MOUNT_PATH}, "
            "not the shared /run/secrets tree"
        )
        assert '_ATTESTED_ROOT_FILE="${_ATTEST_DIR}/ca_root.attested_sha256"' in text
        # Regression guard: the OLD (vulnerable) definition must be gone.
        assert '_ATTESTED_ROOT_FILE="${_SECRETS_DIR}/ca_root.attested_sha256"' not in text, (
            f"{script}: attestation file must not be re-derived from the "
            "shared _SECRETS_DIR again (FINDING-V412-RESTART-012 regression)"
        )


_CHOWN_DROP_RE = re.compile(r'^\s*chown postgres:postgres\b')
_INSTALL_OWNERSHIP_FLAGS_RE = re.compile(
    r'^(\s*install\s+-m\s+\S+\s+)-o postgres -g postgres\s+(.*)$'
)


def _is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return s == "" or s.startswith("#")


def _hunk_is_k8s_pg_ssl_ownership_delta(a_chunk: list[str], b_chunk: list[str]) -> bool:
    """True iff a diffing docker-vs-helm hunk reduces to nothing once the two
    documented, allowlisted exceptions are accounted for:

    1. The one pre-existing cosmetic doc-comment file-extension typo
       (`.py` vs `.sh` in a `# see tests/invariants/...` comment) — any
       comment/blank-only hunk is prose, not the executed contract, and is
       allowed to reword freely (mirrors the original normalise() behaviour).
    2. FINDING-V412-K8S-PG-SSL (2026-07-24, commit `5a00c14f`): the k8s copy
       deliberately drops every `chown postgres:postgres ...` call and every
       `-o postgres -g postgres` install-ownership flag, because
       templates/postgres.yaml pins runAsUser/runAsGroup/fsGroup: 999 to
       match the pgvector image's real postgres UID/GID exactly — every file
       this script creates on k8s is already owned uid999:gid999 by
       construction, so an explicit chown/-o/-g is both redundant and is the
       exact CAP_CHOWN failure mode that broke k8s postgres TLS before this
       fix. The compose copy is DELIBERATELY unchanged (compose's
       `user: "999:999"` pin makes its chown calls a same-UID no-op, so
       they're not broken there and are not touched) — this is the ONE
       intended functional delta between the two copies.

    Any residual, non-comment content left after stripping (1) comment/blank
    lines, (2) docker-only `chown postgres:postgres` lines, and (3) the
    `-o postgres -g postgres` flags off `install` lines must still match
    exactly — this is what keeps the assertion from degrading into a blanket
    skip: any OTHER functional divergence still fails loudly.
    """
    a_code = [l for l in a_chunk if not _is_comment_or_blank(l)]
    b_code = [l for l in b_chunk if not _is_comment_or_blank(l)]
    a_code = [l for l in a_code if not _CHOWN_DROP_RE.match(l)]
    a_code = [_INSTALL_OWNERSHIP_FLAGS_RE.sub(r"\1\2", l) for l in a_code]
    return a_code == b_code


def test_docker_and_helm_ssl_scripts_stay_in_parity() -> None:
    """Verification Protocol #4 — two copies of the same file must not drift,
    except for the two DOCUMENTED, DELIBERATE exceptions named in
    `_hunk_is_k8s_pg_ssl_ownership_delta` above: the pre-existing cosmetic
    .py/.sh doc-comment typo, and FINDING-V412-K8S-PG-SSL's chown/-o/-g
    ownership-flag removal on the k8s copy. Every other line, in every other
    hunk, must still be byte-identical — this is a named allowlist, not a
    blanket skip; any unrelated functional drift between the two runtimes'
    SSL init scripts still fails this test."""
    docker_lines = DOCKER_SSL_SH.read_text(encoding="utf-8").splitlines()
    helm_lines = HELM_SSL_SH.read_text(encoding="utf-8").splitlines()

    sm = difflib.SequenceMatcher(a=docker_lines, b=helm_lines, autojunk=False)
    unexplained: list[str] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        a_chunk = docker_lines[i1:i2]
        b_chunk = helm_lines[j1:j2]
        if _hunk_is_k8s_pg_ssl_ownership_delta(a_chunk, b_chunk):
            continue
        unexplained.append(
            f"docker[{i1}:{i2}]={a_chunk!r} vs helm[{j1}:{j2}]={b_chunk!r}"
        )

    assert not unexplained, (
        "docker/postgres/05-enable-ssl.sh and "
        "helm/yashigani/files/postgres-05-enable-ssl.sh have drifted beyond "
        "the two documented exceptions (cosmetic .py/.sh typo; "
        "FINDING-V412-K8S-PG-SSL chown/-o/-g removal) — Verification "
        "Protocol #4. Unexplained hunks:\n" + "\n".join(unexplained)
    )


def test_helm_backoffice_does_not_project_attestation_file() -> None:
    text = HELM_BACKOFFICE_YAML.read_text(encoding="utf-8")
    assert f"key: {ATTEST_FILENAME}" not in text, (
        "backoffice's K8s pki-ro Secret items list must never project "
        f"{ATTEST_FILENAME} into the writable /run/secrets emptyDir "
        "(K8s equivalent of the podman RO-mount bypass)"
    )


def test_helm_postgres_root_rotation_documented_as_unimplemented() -> None:
    """Not a functional gate (K8s root rotation is genuinely out of scope for
    this fix) — asserts the parity note exists so a future implementer doesn't
    silently re-add ca_root.attested_sha256 to a Secret shared with other
    services (reintroducing the exact vulnerability class this fix closes)."""
    text = HELM_POSTGRES_YAML.read_text(encoding="utf-8")
    assert "FINDING-V412-RESTART-012" in text
    assert ATTEST_FILENAME not in re.sub(r"#.*", "", text), (
        "helm postgres.yaml must not reference ca_root.attested_sha256 "
        "outside of comments (no K8s items: entry exists yet)"
    )


# --------------------------------------------------------------------------- #
# Live probe — only runs against an already-running stack from THIS repo.
# Mirrors test_i9's optional live-adversarial-probe split: skipped (not
# failed) when no stack is up, so this never blocks CI without a live rig.
# --------------------------------------------------------------------------- #

def _runtime_cmd() -> str | None:
    for candidate in ("podman", "docker"):
        if shutil.which(candidate):
            return candidate
    return None


def _container_running(rt: str, name: str) -> bool:
    try:
        out = subprocess.run(
            [rt, "inspect", name, "--format", "{{.State.Running}}"],
            capture_output=True, text=True, timeout=10,
        )
        return out.returncode == 0 and out.stdout.strip() == "true"
    except Exception:
        return False


@pytest.mark.skipif(_runtime_cmd() is None, reason="no podman/docker on PATH")
def test_live_backoffice_cannot_write_attestation_file() -> None:
    rt = _runtime_cmd()
    backoffice = "localhost_backoffice_1"
    if not _container_running(rt, backoffice):
        pytest.skip(f"{backoffice} not running — live probe requires an up stack")

    # 1. The path must not even exist inside backoffice's mount namespace.
    probe = subprocess.run(
        [rt, "exec", backoffice, "sh", "-c", f"test -e {ATTEST_MOUNT_PATH}"],
        capture_output=True, text=True, timeout=10,
    )
    assert probe.returncode != 0, (
        f"{ATTEST_MOUNT_PATH} exists inside backoffice — it must not be "
        "mounted there at all (FINDING-V412-RESTART-012 defence B)"
    )

    # 2. A write attempt at the OLD (pre-fix) flat location must not land on
    #    the attestation filename, and /run/secrets itself must be RW=false.
    inspect = subprocess.run(
        [rt, "inspect", backoffice, "--format",
         '{{range .Mounts}}{{if eq .Destination "/run/secrets"}}{{.RW}}{{end}}{{end}}'],
        capture_output=True, text=True, timeout=10,
    )
    assert inspect.stdout.strip() == "false", (
        f"backoffice /run/secrets RW={inspect.stdout.strip()!r} — expected "
        "RW=false (podman inspect); FINDING-V412-RESTART-012 regression"
    )

    write_probe = subprocess.run(
        [rt, "exec", backoffice, "sh", "-c",
         f"echo rogue > /run/secrets/{ATTEST_FILENAME}"],
        capture_output=True, text=True, timeout=10,
    )
    assert write_probe.returncode != 0, (
        f"backoffice could write /run/secrets/{ATTEST_FILENAME} — the RO "
        "mount is not enforced (regression of the root cause this fix closes)"
    )
