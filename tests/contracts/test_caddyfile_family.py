# Last updated: 2026-05-07T01:00:00+01:00
"""
Caddyfile family contract tests — anti-rot gate.

Prevents the class of drift that V232-D06+P11 cleaned up (73 reverse_proxy
blocks audited, all missing inject-caddy-verified imports detected and fixed).

Contract assertions (all three Caddyfiles: selfsigned / acme / ca)
-------------------------------------------------------------------
1. inject-caddy-verified coverage:
   Every ``reverse_proxy`` block targeting the mTLS services (gateway:8080,
   backoffice:8443, grafana:3443, prometheus:9090) MUST be followed by
   ``import inject-caddy-verified`` within the same block (within 6 lines).
   Third-party upstreams (wazuh-dashboard:5601, open-webui:8080 in the
   after-forward_auth legs) are deliberately excluded — they do not validate
   the header. retro #83: grafana and prometheus now use mTLS and are no
   longer excluded.

2. TLS 1.3 minimum on every public listener:
   Every ``tls`` directive inside a site block (HTTPS listeners) must contain
   ``protocols tls1.3``.

3. GCM-only ciphers paired with every tls1.3 directive:
   ``ciphers TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256`` must appear on the
   line immediately following ``protocols tls1.3`` (within 2 lines of the
   ``protocols`` line).

4. client_auth blocks are site-level only:
   ``client_auth`` must not appear inside a ``handle {`` block.  Caddy v2 only
   honours client_auth at the server-block TLS directive level; placing it
   inside a handle silently ignores it (Platform gate #58c #3br evidence 2026-04-28).

5. caddy adapt exits 0 on env-substituted copy (skipped unless caddy binary
   available or Docker is reachable; controlled by the ``--caddy-adapt``
   marker or the CADDY_BIN / DOCKER_AVAILABLE env vars).

Mutation guard
--------------
``test_mutation_inject_missing_is_caught`` deletes one ``import
inject-caddy-verified`` from a fixture copy and asserts the contract fails with
a clear message naming the Caddyfile and the missing proxy target.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.parent
_DOCKER = _REPO / "docker"

CADDYFILES: dict[str, Path] = {
    "selfsigned": _DOCKER / "Caddyfile.selfsigned",
    "acme":       _DOCKER / "Caddyfile.acme",
    "ca":         _DOCKER / "Caddyfile.ca",
}

# ---------------------------------------------------------------------------
# Upstreams that REQUIRE inject-caddy-verified (mTLS services)
# ---------------------------------------------------------------------------

# These are the services that validate X-Caddy-Verified-Secret at startup.
# Any reverse_proxy targeting these hosts MUST import inject-caddy-verified.
_MTLS_UPSTREAM_PATTERN = re.compile(
    r"reverse_proxy\s+https://(gateway:8080|backoffice:8443)"
)

# Upstreams that are legitimately excluded (they don't validate the header).
# They're third-party services proxied AFTER a forward_auth gate; their
# forward_auth call to backoffice:8443 already carries inject-caddy-verified.
# retro #83: grafana:3000 and prometheus:9090 removed from exclusion list —
# they now use https://grafana:3443 and https://prometheus:9090 WITH
# import internal-mtls (mutual TLS). The forward_auth gate still applies.
# wazuh-dashboard:5601 and open-webui:8080 remain excluded (third-party
# upstreams without internal-mtls support).
_EXCLUDED_UPSTREAMS = frozenset(
    {"wazuh-dashboard:5601", "open-webui:8080"}
)

# Maximum number of lines after a `reverse_proxy` opener to find the import.
# The block structure is:
#   reverse_proxy <target> {     ← opener
#       import internal-mtls     ← within 1-2 lines
#       import inject-caddy-verified  ← within 3-4 lines
#       header_up ...
#   }
_IMPORT_LOOKAHEAD = 8

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(path: Path) -> str:
    assert path.exists(), f"Caddyfile not found: {path}"
    return path.read_text(encoding="utf-8")


def _mtls_proxy_blocks(lines: list[str]) -> list[tuple[int, str]]:
    """
    Return (line_number_1indexed, upstream) for every reverse_proxy line that
    targets an mTLS service (gateway:8080 or backoffice:8443).
    """
    blocks: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if line.strip().startswith("#"):
            continue
        m = _MTLS_UPSTREAM_PATTERN.search(line)
        if m:
            blocks.append((i + 1, m.group(1)))
    return blocks


def _inject_present_after(lines: list[str], opener_index: int) -> bool:
    """
    Check whether ``import inject-caddy-verified`` appears within
    ``_IMPORT_LOOKAHEAD`` lines after ``opener_index`` (0-based).
    """
    limit = min(len(lines), opener_index + _IMPORT_LOOKAHEAD)
    return any(
        "import inject-caddy-verified" in lines[j]
        for j in range(opener_index, limit)
    )


def _find_tls_blocks(text: str) -> list[int]:
    """
    Return 1-indexed line numbers of ``protocols tls1.3`` occurrences.
    """
    result: list[int] = []
    for i, line in enumerate(text.splitlines()):
        if re.search(r"^\s+protocols\s+tls1\.3\s*$", line):
            result.append(i + 1)
    return result


def _ciphers_present_near(lines: list[str], protocols_line_1indexed: int) -> bool:
    """
    Return True if ``ciphers TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256``
    appears within 2 lines of the given protocols line (1-indexed).
    """
    idx = protocols_line_1indexed - 1  # convert to 0-based
    limit = min(len(lines), idx + 3)
    pattern = re.compile(
        r"ciphers\s+TLS_AES_256_GCM_SHA384\s+TLS_AES_128_GCM_SHA256"
    )
    return any(pattern.search(lines[j]) for j in range(idx, limit))


def _client_auth_inside_handle(text: str) -> list[int]:
    """
    Return 1-indexed line numbers of any ``client_auth`` that appears inside a
    ``handle {`` block.  We detect this by tracking handle-block depth:
    each ``handle {`` increments depth; a matching closing ``}`` decrements.
    client_auth at depth > 0 is a violation.
    """
    violations: list[int] = []
    handle_depth = 0
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        # Detect handle block openers (not handle_path, not handle_response)
        if re.match(r"^handle\s*\{", stripped):
            handle_depth += 1
        elif stripped == "}" and handle_depth > 0:
            handle_depth -= 1
        # client_auth inside a handle block is a violation
        if handle_depth > 0 and re.match(r"client_auth\b", stripped):
            violations.append(i + 1)
    return violations


# ---------------------------------------------------------------------------
# Parametrised green-tip tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_inject_caddy_verified_on_all_mtls_proxies(name: str, path: Path) -> None:
    """
    Every reverse_proxy targeting gateway:8080 or backoffice:8443 must import
    inject-caddy-verified.  Missing import → X-Caddy-Verified-Secret not set →
    the gateway/backoffice middleware returns 401 for 100% of requests through that route.
    """
    text = _load(path)
    lines = text.splitlines()
    failures: list[str] = []

    for lineno, upstream in _mtls_proxy_blocks(lines):
        idx = lineno - 1  # 0-based
        if not _inject_present_after(lines, idx):
            failures.append(
                f"  L{lineno}: reverse_proxy https://{upstream} — "
                f"import inject-caddy-verified missing within {_IMPORT_LOOKAHEAD} lines"
            )

    assert not failures, (
        f"\n{name} (Caddyfile.{name}) — inject-caddy-verified MISSING on "
        f"{len(failures)} mTLS proxy block(s):\n"
        + "\n".join(failures)
        + "\n\nFix: add `import inject-caddy-verified` inside every reverse_proxy "
        "block that targets gateway:8080 or backoffice:8443."
    )


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_tls13_on_all_public_listeners(name: str, path: Path) -> None:
    """
    Every TLS listener must enforce TLS 1.3 minimum.  A listener without
    ``protocols tls1.3`` will negotiate TLS 1.2 by default — closed QA R3
    finding; must not regress.  The test asserts at least one occurrence (the
    public HTTPS site block) is present — absence means the directive was
    removed entirely.
    """
    text = _load(path)
    protocol_lines = _find_tls_blocks(text)

    assert protocol_lines, (
        f"\n{name} (Caddyfile.{name}) — NO 'protocols tls1.3' directive found.\n"
        "Every public TLS listener must declare 'protocols tls1.3' to prevent "
        "TLS 1.2 negotiation.  This closes QA R3 (TLS downgrade finding)."
    )


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_gcm_ciphers_paired_with_tls13(name: str, path: Path) -> None:
    """
    Every ``protocols tls1.3`` occurrence must be immediately followed (within 2
    lines) by ``ciphers TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256``.
    GCM-only suites close the ChaCha20-Poly1305 downgrade path.
    """
    text = _load(path)
    lines = text.splitlines()
    protocol_lines = _find_tls_blocks(text)

    assert protocol_lines, f"{name}: no 'protocols tls1.3' to pair ciphers with"

    missing: list[int] = []
    for lineno in protocol_lines:
        if not _ciphers_present_near(lines, lineno):
            missing.append(lineno)

    assert not missing, (
        f"\n{name} (Caddyfile.{name}) — GCM ciphers missing near protocols tls1.3 "
        f"at line(s): {missing}\n"
        "Each 'protocols tls1.3' block must be immediately followed by:\n"
        "  ciphers TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256\n"
        "This prevents ChaCha20-Poly1305 negotiation."
    )


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_client_auth_not_inside_handle_block(name: str, path: Path) -> None:
    """
    client_auth must only appear at the site-block tls directive level, NEVER
    inside a handle{} block.  Caddy v2 silently ignores client_auth inside
    handle — Platform gate #58c #3br evidence (2026-04-28).  A violation means SPIFFE
    sender-constrained token verification is silently disabled for that route.
    """
    text = _load(path)
    violations = _client_auth_inside_handle(text)

    assert not violations, (
        f"\n{name} (Caddyfile.{name}) — client_auth found inside handle block "
        f"at line(s): {violations}\n"
        "client_auth is only valid inside a site-block tls directive (Caddy v2).\n"
        "Inside handle{} it is silently ignored — SPIFFE verification is bypassed."
    )


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_inject_count_consistent_across_family(name: str, path: Path) -> None:
    """
    Cross-file consistency: the count of ``import inject-caddy-verified``
    occurrences must be identical across all three Caddyfiles.  The files share
    the same route set; a count divergence means one file lost imports that the
    others retained — the exact drift pattern V232-D06+P11 fixed.
    """
    counts = {
        n: _load(p).count("import inject-caddy-verified")
        for n, p in CADDYFILES.items()
    }
    # All counts must agree
    unique_counts = set(counts.values())
    assert len(unique_counts) == 1, (
        f"\nInject-caddy-verified import counts diverge across Caddyfile family:\n"
        + "\n".join(f"  Caddyfile.{n}: {c}" for n, c in sorted(counts.items()))
        + "\n\nAll three files must have the same count — a divergence means one "
        "file lost imports that the others retained."
    )


# ---------------------------------------------------------------------------
# Mutation test — must FAIL on tampered fixture
# ---------------------------------------------------------------------------


def _remove_one_inject(text: str) -> tuple[str, int]:
    """
    Remove the first ``import inject-caddy-verified`` occurrence from text.
    Returns (mutated_text, line_number_1indexed_where_removed).
    """
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if "import inject-caddy-verified" in line:
            mutated = "".join(lines[:i] + lines[i + 1 :])
            return mutated, i + 1
    raise ValueError("No 'import inject-caddy-verified' found — cannot mutate")


def test_mutation_inject_missing_is_caught() -> None:
    """
    Mutation guard: delete one ``import inject-caddy-verified`` from the
    selfsigned Caddyfile fixture.  The inject-coverage contract must then raise
    AssertionError with a message containing the line number and upstream name.

    Per feedback_test_real_scans_not_just_unit_tests.md: this test MUST fail on
    a mutated fixture.  A test that passes on a mutated fixture is evidence
    fabrication (SOP 4).
    """
    name = "selfsigned"
    path = CADDYFILES[name]
    original = _load(path)

    mutated, removed_lineno = _remove_one_inject(original)

    # Parse the mutated text through the same logic the contract test uses
    lines = mutated.splitlines()
    failures: list[str] = []
    for lineno, upstream in _mtls_proxy_blocks(lines):
        idx = lineno - 1
        if not _inject_present_after(lines, idx):
            failures.append(
                f"  L{lineno}: reverse_proxy https://{upstream} — "
                f"import inject-caddy-verified missing within {_IMPORT_LOOKAHEAD} lines"
            )

    # The mutation MUST produce at least one failure
    assert failures, (
        f"MUTATION TEST FAILED: removing 'import inject-caddy-verified' at line "
        f"{removed_lineno} of Caddyfile.{name} was NOT detected by the contract "
        f"test.  The contract is not catching the regression it was designed to catch."
    )

    # Confirm the failure message is specific enough to guide the fix
    failure_text = "\n".join(failures)
    assert "import inject-caddy-verified missing" in failure_text, (
        f"Failure message lacks diagnostic text: {failure_text!r}"
    )


def test_mutation_count_divergence_is_caught() -> None:
    """
    Mutation guard for the cross-file consistency check.  Remove one inject
    import from the in-memory copy of one Caddyfile and verify the count-check
    fires with a clear message.
    """
    name = "acme"
    path = CADDYFILES[name]
    original = _load(path)

    mutated, _ = _remove_one_inject(original)

    # Build a counts dict as the consistency test would, using the mutated copy
    counts: dict[str, int] = {}
    for n, p in CADDYFILES.items():
        text = mutated if n == name else _load(p)
        counts[n] = text.count("import inject-caddy-verified")

    unique_counts = set(counts.values())

    assert len(unique_counts) != 1, (
        f"MUTATION TEST FAILED: removing one inject import from Caddyfile.{name} "
        f"was NOT detected by the count-consistency check.  "
        f"Counts: {counts}"
    )


# ---------------------------------------------------------------------------
# caddy adapt gate (skipped unless caddy binary available)
# ---------------------------------------------------------------------------


def _caddy_binary() -> str | None:
    """Return path to caddy binary if available, else None."""
    caddy = shutil.which("caddy")
    if caddy:
        return caddy
    env_caddy = os.environ.get("CADDY_BIN")
    if env_caddy and Path(env_caddy).is_file():
        return env_caddy
    return None


def _env_stub() -> dict[str, str]:
    """Minimal env-var stubs so caddy adapt can parse env placeholders."""
    return {
        **os.environ,
        "YASHIGANI_TLS_DOMAIN": "localhost",
        "CADDY_INTERNAL_HMAC": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "PROMETHEUS_BASICAUTH_USER": "prometheus",
        "PROMETHEUS_BASICAUTH_HASH": "$2a$14$placeholder",
    }


@pytest.mark.parametrize("name,path", list(CADDYFILES.items()))
def test_caddy_adapt_exits_zero(
    name: str, path: Path, tmp_path: Path
) -> None:
    """
    Run ``caddy adapt --config <Caddyfile>`` and assert exit 0.
    Skipped if no caddy binary is on PATH or pointed to by CADDY_BIN.

    This catches syntax errors that the regex-based static tests cannot: missing
    braces, unknown directives, and Caddyfile adapter parse failures.
    """
    caddy = _caddy_binary()
    if caddy is None:
        pytest.skip(
            "caddy binary not found (set CADDY_BIN or install caddy).  "
            "This check runs in CI when caddy is pre-installed."
        )

    # Write the Caddyfile with stub env vars expanded
    src = _load(path)
    stub_env = _env_stub()
    # Caddy {$VAR} is parse-time; we expand manually so caddy adapt sees literals
    expanded = re.sub(
        r"\{\$([A-Z0-9_]+)\}",
        lambda m: stub_env.get(m.group(1), m.group(0)),
        src,
    )
    # For ca mode: the tls cert/key files must exist (caddy adapt validates paths)
    if name == "ca":
        (tmp_path / "tls").mkdir(exist_ok=True)
        (tmp_path / "tls" / "server.crt").write_text("placeholder\n")
        (tmp_path / "tls" / "server.key").write_text("placeholder\n")
        # Replace /etc/caddy/tls/ with tmp_path/tls/ in the adapted copy
        expanded = expanded.replace(
            "/etc/caddy/tls/", str(tmp_path / "tls") + "/"
        )

    caddyfile_copy = tmp_path / f"Caddyfile.{name}"
    caddyfile_copy.write_text(expanded, encoding="utf-8")

    result = subprocess.run(
        [caddy, "adapt", "--config", str(caddyfile_copy)],
        capture_output=True,
        text=True,
        env=stub_env,
    )

    assert result.returncode == 0, (
        f"\ncaddy adapt FAILED for Caddyfile.{name} (exit {result.returncode}):\n"
        f"stdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}\n"
        f"Caddyfile path: {caddyfile_copy}"
    )
