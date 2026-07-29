# Last updated: 2026-07-06T00:00:00+00:00 (v4.1 unified-sidecar must-fix #9 — Captain C5/C10)
"""
:18790 openclaw egress gateway — single-source contract tests.

Design (unified-sidecar-design-review-synthesis-20260706.md must-fix #9):
the static :18790 listener was hand-duplicated between
``docker/Caddyfile.openclaw-egress`` (compose) and an inline rewrite in
``helm/yashigani/templates/configmaps.yaml``.  It is now single-sourced:

* CANONICAL:  docker/Caddyfile.openclaw-egress
* MIRROR:     helm/yashigani/files/Caddyfile.openclaw-egress
              (byte-identical; maintained by scripts/sync-caddyfile-egress-helm.sh
              — same pattern as the mcp.rego → helm policy-bundle fix)
* K8s RENDER: configmaps.yaml loads the mirror via .Files.Get and applies
              exactly four documented `replace` substitutions (service name,
              trust anchor, SPIFFE trust domain, telegram bot-ID default).

Contracts pinned here
---------------------
1. Byte parity: canonical == mirror.  FAILS on drift, names the sync script.
2. Mutation guard: a planted one-byte drift is caught by the same comparison.
3. No re-inlined copy: configmaps.yaml must use .Files.Get and must NOT
   contain the listener internals (caller gate / deliver handles) inline.
4. The four documented K8s delta substitutions are present in configmaps.yaml
   (dropping one silently breaks the K8s render — e.g. compose service names
   leaking into K8s DNS).
5. C10 (compose): the canonical file adapts + validates under a compose-shim
   main Caddyfile (defines the (internal-mtls) snippet the monoliths provide).
6. C10 (helm-side — must-fix #9 extension): `caddy adapt` + substituted-cert
   `caddy validate` run against the helm-RENDERED yashigani-caddy-config
   ConfigMap Caddyfile, not just the compose file.

Skip policy: 5 requires a caddy binary; 6 requires helm + caddy.  Both skip
cleanly when the tooling is absent (CI installs both; the byte-parity gates
1-4 always run).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.parent
_CANONICAL = _REPO / "docker" / "Caddyfile.openclaw-egress"
_MIRROR = _REPO / "helm" / "yashigani" / "files" / "Caddyfile.openclaw-egress"
_CONFIGMAPS = _REPO / "helm" / "yashigani" / "templates" / "configmaps.yaml"
_CHART = _REPO / "helm" / "yashigani"
_SYNC_SCRIPT = "scripts/sync-caddyfile-egress-helm.sh"
_COMPOSE = _REPO / "docker" / "docker-compose.yml"

# The five caller-gate SPIFFE identities the :18790 listener's static gates
# (openclaw-egress-caller-gate, llm-egress-caller-gate,
# gateway-egress-deliver-gate) resolve via Caddy parse-time `{$VAR:default}`
# substitution.  Every one of these MUST be composed from the per-instance
# YASHIGANI_SPIFFE_TRUST_DOMAIN in the compose caddy service env block —
# the Caddyfile's inline default literal (`spiffe://yashigani.internal/<name>`)
# is UN-qualified and only matches a leaf's real URI SAN on a legacy
# single-instance install where the trust domain happens to be the bare
# default.  A missing entry here silently falls back to the bare literal and
# 403s every caller whose leaf carries the per-instance-qualified SAN.
_REQUIRED_CALLER_GATE_SPIFFE_ENV_VARS = (
    "YASHIGANI_CADDY_SPIFFE_ID",
    "YASHIGANI_OPENCLAW_SPIFFE_ID",
    "YASHIGANI_LANGFLOW_SPIFFE_ID",
    "YASHIGANI_LETTA_SPIFFE_ID",
    # YSG-RISK-142: gateway is the caller on ALL FOUR /deliver/* routes
    # (llm/slack/slack-hooks/telegram) — this was the missing one.
    "YASHIGANI_GATEWAY_SPIFFE_ID",
)

# Markers of the listener INTERNALS.  If any of these appear in
# configmaps.yaml the hand-coded duplicate has been re-inlined — the exact
# drift pattern must-fix #9 killed.  (The (internal-mtls) snippet shim and the
# four `replace` lines are the ONLY sanctioned :18790 content in the template.)
_INLINE_COPY_MARKERS = (
    "(openclaw-egress-caller-gate)",
    "(gateway-egress-deliver-gate)",
    "handle_path /deliver/slack/*",
    "handle_path /deliver/slack-hooks/*",
    "handle_path /deliver/telegram/*",
    "rewrite * /egress/eval{uri}",
)

# The four documented K8s delta substitutions (must-fix #9).  Literal
# fragments of the `replace` pipeline in configmaps.yaml.
_REQUIRED_DELTAS = (
    'replace "https://gateway:8080" "https://yashigani-gateway:8080"',
    'replace "/run/secrets/ca_intermediate.crt" "/run/secrets/ca_bundle.crt"',
    'replace "spiffe://yashigani.internal/" (printf "spiffe://%s/" $egressTd)',
    'replace "{$YASHIGANI_OPENCLAW_TELEGRAM_BOT_ID:}"',
)


def _read_bytes(path: Path) -> bytes:
    assert path.exists(), f"file not found: {path}"
    return path.read_bytes()


# ---------------------------------------------------------------------------
# 1 + 2 — byte parity + mutation guard
# ---------------------------------------------------------------------------


def test_mirror_exists_and_byte_identical() -> None:
    """The helm mirror must be a byte-identical copy of the canonical file."""
    assert _MIRROR.exists(), (
        f"\nhelm mirror MISSING: {_MIRROR}\n"
        f"The :18790 listener is single-sourced from {_CANONICAL.name} "
        f"(must-fix #9).\nFIX: run {_SYNC_SCRIPT}"
    )
    canonical = _read_bytes(_CANONICAL)
    mirror = _read_bytes(_MIRROR)
    assert canonical == mirror, (
        "\n:18790 DRIFT — helm/yashigani/files/Caddyfile.openclaw-egress "
        "differs from the canonical docker/Caddyfile.openclaw-egress.\n"
        "NEVER edit the helm copy: edit the canonical file, then run "
        f"{_SYNC_SCRIPT}\n"
        "(byte-parity contract, unified-sidecar must-fix #9 / Captain C5)"
    )


def test_mutation_planted_drift_is_caught(tmp_path: Path) -> None:
    """
    Mutation guard (SOP: a gate that passes on a mutated fixture is evidence
    fabrication).  Plant a one-byte drift in a copy of the mirror and assert
    the SAME comparison the parity test uses detects it.
    """
    canonical = _read_bytes(_CANONICAL)
    planted = canonical + b"\n# planted drift\n"
    mutated_mirror = tmp_path / "Caddyfile.openclaw-egress"
    mutated_mirror.write_bytes(planted)
    assert _read_bytes(_CANONICAL) != _read_bytes(mutated_mirror), (
        "MUTATION TEST FAILED: a planted one-byte drift between canonical and "
        "mirror was NOT detected by the byte comparison. The contract is broken."
    )


def test_sync_script_check_mode_catches_planted_drift(tmp_path: Path) -> None:
    """The sync script's --check mode is the pre-commit fix-path twin of the
    parity test — verify it fails on a planted drift against a staged repo
    copy (never mutates the real tree)."""
    script = _REPO / _SYNC_SCRIPT
    assert script.exists(), f"sync script missing: {script}"
    # Stage a minimal repo shape: scripts/ + docker/ + helm/yashigani/files/
    (tmp_path / "scripts").mkdir()
    (tmp_path / "docker").mkdir()
    files_dir = tmp_path / "helm" / "yashigani" / "files"
    files_dir.mkdir(parents=True)
    staged_script = tmp_path / "scripts" / script.name
    shutil.copy(script, staged_script)
    staged_script.chmod(0o755)
    shutil.copy(_CANONICAL, tmp_path / "docker" / _CANONICAL.name)
    (files_dir / _CANONICAL.name).write_bytes(
        _read_bytes(_CANONICAL) + b"\n# planted drift\n"
    )
    result = subprocess.run(
        [str(staged_script), "--check"], capture_output=True, text=True,
    )
    assert result.returncode != 0, (
        "MUTATION TEST FAILED: sync-caddyfile-egress-helm.sh --check exited 0 "
        "on a planted drift.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "DRIFT" in result.stderr, (
        f"--check failure message lacks 'DRIFT' diagnostic: {result.stderr!r}"
    )


# ---------------------------------------------------------------------------
# 3 + 4 — configmaps.yaml single-source discipline
# ---------------------------------------------------------------------------


def test_configmap_uses_files_get_not_inline_copy() -> None:
    """configmaps.yaml must render the listener via .Files.Get of the mirror
    and must NOT contain a re-inlined hand-coded copy of the internals."""
    text = _CONFIGMAPS.read_text(encoding="utf-8")

    assert '.Files.Get "files/Caddyfile.openclaw-egress"' in text, (
        "\nconfigmaps.yaml no longer loads the :18790 listener via "
        '.Files.Get "files/Caddyfile.openclaw-egress" — the single-source '
        "render (must-fix #9) has been removed or renamed."
    )

    reinlined = [m for m in _INLINE_COPY_MARKERS if m in text]
    assert not reinlined, (
        "\n:18790 listener internals RE-INLINED in configmaps.yaml:\n"
        + "\n".join(f"  - {m}" for m in reinlined)
        + "\n\nThe listener is single-sourced from "
        "docker/Caddyfile.openclaw-egress (must-fix #9). Edit the canonical "
        f"file + run {_SYNC_SCRIPT}; never hand-code the routes in the "
        "helm template."
    )


def test_configmap_documents_all_four_k8s_deltas() -> None:
    """The four sanctioned K8s substitutions must all be present — dropping
    one silently ships compose literals (e.g. `gateway:8080`) into K8s DNS."""
    text = _CONFIGMAPS.read_text(encoding="utf-8")
    missing = [d for d in _REQUIRED_DELTAS if d not in text]
    assert not missing, (
        "\nconfigmaps.yaml is missing sanctioned K8s delta substitution(s):\n"
        + "\n".join(f"  - {d}" for d in missing)
        + "\n\nAll four documented deltas (service name, trust anchor, SPIFFE "
        "trust domain, telegram bot-ID default) are load-bearing for the K8s "
        "render of the single-source :18790 listener."
    )


def test_compose_caddy_service_declares_all_caller_gate_spiffe_ids() -> None:
    """YSG-RISK-142 regression: docker/docker-compose.yml's ``caddy`` service
    ``environment:`` block must compose ALL FIVE :18790 caller-gate SPIFFE
    identities (caddy, openclaw, langflow, letta, gateway) from
    ``YASHIGANI_SPIFFE_TRUST_DOMAIN`` — never leave one to the Caddyfile's
    un-qualified inline default.

    Root cause this guards: ``YASHIGANI_GATEWAY_SPIFFE_ID`` was absent from
    the compose env block while the other four were present.
    ``gateway-egress-deliver-gate`` therefore fell back to the bare literal
    ``spiffe://yashigani.internal/gateway``, which never matches
    ``gateway_client.crt``'s real (trust-domain-qualified) URI SAN on any
    install whose ``YASHIGANI_SPIFFE_TRUST_DOMAIN`` differs from the bare
    default (e.g. ``localhost.yashigani.internal`` — every per-instance
    install). Every ``/deliver/{llm,slack,slack-hooks,telegram}/*`` call —
    the ONLY path from egress/eval back out to Slack/Telegram/the inference
    surface — 403'd, confirmed live on the v4.1.2 Docker e2e stack (caddy
    access log: client_common_name=gateway, mTLS handshake succeeded, static
    ``respond ... 403`` fired anyway because the stamped
    X-Yashigani-Verified-Spiffe compared unequal to the un-qualified default).

    K8s is NOT covered by this test — it is structurally immune: the Helm
    render (configmaps.yaml Delta 3) string-replaces the bare
    ``spiffe://yashigani.internal/`` prefix across the WHOLE egress Caddyfile
    at template time, before Caddy ever parses the inline default literal
    (see ``test_configmap_documents_all_four_k8s_deltas`` above).
    """
    text = _COMPOSE.read_text(encoding="utf-8")

    # Scope to the `caddy:` service block only — a false-positive match
    # against an unrelated service's env would defeat the point of the test.
    caddy_block_match = re.search(r"^  caddy:\n(?:^ {4}.*\n|^\n)*", text, re.MULTILINE)
    assert caddy_block_match, (
        "docker-compose.yml: could not locate the `caddy:` service block "
        "(top-level indentation drifted? update the regex in this test)."
    )
    caddy_block = caddy_block_match.group(0)

    missing = [
        var
        for var in _REQUIRED_CALLER_GATE_SPIFFE_ENV_VARS
        if f"{var}: spiffe://${{YASHIGANI_SPIFFE_TRUST_DOMAIN:-yashigani.internal}}/"
        not in caddy_block
    ]
    assert not missing, (
        "\ndocker-compose.yml `caddy:` service is missing per-instance-domain "
        "composition for :18790 caller-gate SPIFFE ID(s):\n"
        + "\n".join(f"  - {v}" for v in missing)
        + "\n\nEach MUST be set as "
        "`<VAR>: spiffe://${YASHIGANI_SPIFFE_TRUST_DOMAIN:-yashigani.internal}/<name>` "
        "in the caddy service environment block (mirrors the other caller-gate "
        "IDs) — YSG-RISK-142."
    )


# ---------------------------------------------------------------------------
# C10 helpers — env substitution, throwaway certs, caddy/helm binaries
# ---------------------------------------------------------------------------


def _caddy_binary() -> str | None:
    caddy = shutil.which("caddy")
    if caddy:
        return caddy
    env_caddy = os.environ.get("CADDY_BIN")
    if env_caddy and Path(env_caddy).is_file():
        return env_caddy
    return None


def _helm_binary() -> str | None:
    return shutil.which("helm") or None


_PLACEHOLDER_RE = re.compile(r"\{\$([A-Z0-9_]+)(?::([^}]*))?\}")


def _substitute_env(text: str, env: dict[str, str]) -> str:
    """Expand Caddy parse-time ``{$VAR}`` / ``{$VAR:default}`` placeholders the
    way Caddy does: env value wins, else the inline default, else empty."""
    def _sub(m: re.Match[str]) -> str:
        var, default = m.group(1), m.group(2)
        if var in env:
            return env[var]
        return default if default is not None else ""
    return _PLACEHOLDER_RE.sub(_sub, text)


def _gen_cert_key(tmp: Path) -> tuple[Path, Path]:
    """Generate a REAL self-signed EC cert + key so ``caddy validate`` can
    load them (substituted-cert validate — must-fix #9 helm-side C10)."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c10-test")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crt_path = tmp / "c10-test.crt"
    key_path = tmp / "c10-test.key"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return crt_path, key_path


_SECRET_REF_RE = re.compile(r"/run/secrets/([A-Za-z0-9_.-]+)")


def _materialise_paths(text: str, tmp: Path) -> str:
    """Rewrite /run/secrets/* + /etc/caddy/agents/* references to tmp-backed
    paths and create real files behind them (keys get a PEM key, everything
    else a PEM cert) so both adapt AND validate succeed."""
    crt, key = _gen_cert_key(tmp)
    secrets_dir = tmp / "run-secrets"
    secrets_dir.mkdir(exist_ok=True)
    for name in sorted(set(_SECRET_REF_RE.findall(text))):
        target = secrets_dir / name
        if name.endswith(".key"):
            shutil.copy(key, target)
        else:
            shutil.copy(crt, target)
    text = text.replace("/run/secrets/", str(secrets_dir) + "/")

    agents_dir = tmp / "etc-caddy-agents"
    agents_dir.mkdir(exist_ok=True)
    text = text.replace("/etc/caddy/agents/", str(agents_dir) + "/")
    return text


def _run_caddy_gate(caddy: str, caddyfile: Path, tmp: Path) -> None:
    """caddy adapt (syntax/adapter) + caddy validate (module provisioning,
    real cert loading) — both must exit 0."""
    env = {
        **os.environ,
        # local_certs / storage: keep caddy's writes inside the sandbox.
        "HOME": str(tmp),
        "XDG_DATA_HOME": str(tmp / "xdg-data"),
        "XDG_CONFIG_HOME": str(tmp / "xdg-config"),
    }
    for step in ("adapt", "validate"):
        result = subprocess.run(
            [caddy, step, "--config", str(caddyfile), "--adapter", "caddyfile"],
            capture_output=True, text=True, env=env,
        )
        assert result.returncode == 0, (
            f"\ncaddy {step} FAILED (exit {result.returncode}) for {caddyfile}:\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


# Stub env for placeholder substitution.  SPIFFE IDs / telegram-bot-ID /
# slack pins keep their inline defaults (that is the production K8s posture —
# the pod may not set them); only default-less placeholders need stubs.
# Verified placeholder inventory (helm render + canonical file):
#   CADDY_INTERNAL_HMAC (no default), YASHIGANI_{GATEWAY,OPENCLAW}_SPIFFE_ID,
#   YASHIGANI_OPENCLAW_{SLACK_BOT_TOKEN,SLACK_WEBHOOK_PATH,TELEGRAM_BOT_ID}
#   (all with inline defaults).
_ENV_STUBS = {
    "CADDY_INTERNAL_HMAC": "deadbeef" * 8,
}


# ---------------------------------------------------------------------------
# 5 — C10 compose side: canonical file adapts + validates under a shim
# ---------------------------------------------------------------------------


def test_canonical_adapts_and_validates_under_compose_shim(tmp_path: Path) -> None:
    """The canonical :18790 file must adapt + validate when combined with the
    (internal-mtls) snippet the compose monoliths define.  Catches structural
    breakage of the canonical file itself (missing brace, bad directive)
    without needing the full monolith."""
    caddy = _caddy_binary()
    if caddy is None:
        pytest.skip("caddy binary not found (set CADDY_BIN or install caddy)")

    canonical = _CANONICAL.read_text(encoding="utf-8")
    # Compose-shim main file: the snippet Caddyfile.{selfsigned,ca,acme}
    # provide, byte-for-byte (docker/Caddyfile.acme:91).
    shim = (
        "(internal-mtls) {\n"
        "    transport http {\n"
        "        tls\n"
        "        tls_trust_pool file /run/secrets/ca_intermediate.crt\n"
        "        tls_client_auth /run/secrets/caddy_client.crt /run/secrets/caddy_client.key\n"
        "        versions 1.1\n"
        "    }\n"
        "}\n\n"
    )
    combined = _substitute_env(shim + canonical, _ENV_STUBS)
    combined = _materialise_paths(combined, tmp_path)
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(combined, encoding="utf-8")
    _run_caddy_gate(caddy, caddyfile, tmp_path)


# ---------------------------------------------------------------------------
# 6 — C10 helm side: adapt + substituted-cert validate on the RENDERED ConfigMap
# ---------------------------------------------------------------------------


def _helm_render_caddyfile(tmp_path: Path) -> str:
    helm = _helm_binary()
    if helm is None:
        pytest.skip("helm binary not found")
    result = subprocess.run(
        [
            helm, "template", "c10test", str(_CHART),
            "--set", "agentBundles.openclaw.enabled=true",
            "--set", "internalBearer.value=" + "ab" * 32,
            "-s", "templates/configmaps.yaml",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"\nhelm template FAILED (exit {result.returncode}):\n{result.stderr}"
    )
    import yaml as _yaml
    for doc in _yaml.safe_load_all(result.stdout):
        if (
            doc
            and doc.get("kind") == "ConfigMap"
            and doc.get("metadata", {}).get("name") == "yashigani-caddy-config"
        ):
            caddyfile = doc.get("data", {}).get("Caddyfile", "")
            assert caddyfile, "yashigani-caddy-config ConfigMap has no Caddyfile key"
            return caddyfile
    pytest.fail("yashigani-caddy-config ConfigMap not found in helm template output")


def test_helm_rendered_caddyfile_adapts_and_validates(tmp_path: Path) -> None:
    """Must-fix #9 helm-side C10: `caddy adapt` + substituted-cert
    `caddy validate` against the helm-RENDERED Caddyfile ConfigMap (openclaw
    egress enabled) — not just the compose file.  Catches K8s-render-only
    breakage: bad substitutions, helm whitespace mangling, snippet-shim drift."""
    caddy = _caddy_binary()
    if caddy is None:
        pytest.skip("caddy binary not found (set CADDY_BIN or install caddy)")

    rendered = _helm_render_caddyfile(tmp_path)

    # The rendered text must carry the K8s deltas (sanity before the gate —
    # a wrong replace would still adapt fine with compose literals).
    assert "https://yashigani-gateway:8080" in rendered, (
        "K8s render lost the yashigani-gateway service-name delta"
    )
    assert "/run/secrets/ca_intermediate.crt" not in rendered, (
        "K8s render leaked the compose ca_intermediate.crt trust anchor"
    )
    assert ":18790" in rendered, "K8s render lost the :18790 listener entirely"

    substituted = _substitute_env(rendered, _ENV_STUBS)
    substituted = _materialise_paths(substituted, tmp_path)
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(substituted, encoding="utf-8")
    _run_caddy_gate(caddy, caddyfile, tmp_path)
