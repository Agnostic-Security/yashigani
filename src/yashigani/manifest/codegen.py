"""
Yashigani Manifest — Codegen engine for Shape A (LLM-calling / Hermes-class).

W3 Phase 1 — Shape A only.  Given a validated parsed manifest and a detected
runtime string, emit the full artifact set for onboarding an LLM-calling agent
into the ring-fence.

Security controls baked in (each has a proving test):
  C1   (SHIP-BLOCKER) Caddy routes use uri strip_prefix; upstreams hardcoded
       from egress_allow config; rejects any RFC1918/loopback/link-local upstream.
  C3   (HIGH)         Routes namespaced /agents/{tenant_id}/{agent_id}/;
                      duplicate (tenant_id, agent_id) aborts codegen.
  C5   (MED)          Per-upstream TLS verification: each reverse_proxy transport
                      block emits explicit `tls_server_name <provider-host>` set
                      from manifest config; tls_insecure_skip_verify NEVER emitted;
                      Caddy verifies upstream cert against system roots by default.
  C8   (MED)          Connection-pool exhaustion cap: `max_conns_per_host 64`
                      (default; see _C8_MAX_CONNS_PER_HOST_DEFAULT) in each
                      transport block limits upstream connections per
                      (tenant, agent, provider) → DoS resistance.
                      OPA budget-gate half of C8 is deferred (policy layer,
                      finding YSG-C8-OPA-BUDGET).
  C10  (HIGH)         caddy validate on each snippet; absent caddy binary →
                      skip with WARNING; present → must pass.
  M9   (MEDIUM)       All writes via realpath + allowed-roots prefix check +
                      atomic rename; refuses to write outside allowed roots;
                      refuses symlinked output paths.
  S6   (SHIP-BLOCKER) Emitted shell fragments are bash-3.2 safe (no declare -A,
                      no ${var,,}, no mapfile); gated by bash -n + shellcheck.
  L9               Hardened K8s/Compose defaults: runAsNonRoot, no privilege
                   escalation, readOnlyRootFilesystem, drop ALL, seccomp
                   RuntimeDefault.
  L3   (compose)   IPv6 default-deny sysctls.
  L7   (compose)   depends_on with condition: service_completed_successfully.
  S7              group_add 2002 for agents declaring kms secrets.

Artifact set (Shape A):
  docker-compose.override.yml stanza
  values-<agent>.yaml + -networkpolicy overlay (Helm)
  templates/agents/<agent>-policy-exception.yaml (Kyverno)
  docker/caddy/agents/<agent>.caddy (Caddy snippet)
  service_identities.yaml append entry
  pki_ownership.sh tuple fragment (shell)
  opa/<agent>.rego stub (deep authoring is a later phase)
  tests/contracts/test_<agent>_compose.py stub
  tests/contracts/test_<agent>_helm.py stub

Each generated file carries:
  - .yashigani-manifest-hash comment (M9 drift detection)
  - YSG_RUNTIME comment (L10 — wrong-runtime codegen silently produces no ring-fence)

Dry-run render mode: CodegenEngine(manifest, runtime).render(dry_run=True) returns a
dict of {relative_path: content} without writing any files.

Shapes B + C, offboard, and deep OPA authoring are out of scope (later phases).

Last updated: 2026-05-29T00:00:00+00:00
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
import textwrap
from pathlib import Path
from typing import Any, Callable, Optional

from yashigani.manifest.linter import _is_private_address

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Valid runtime strings (4-way from detect_runtime.sh)
VALID_RUNTIMES: frozenset[str] = frozenset({
    "docker",
    "podman-rootful",
    "podman-rootless",
    "k8s",
})

# Allowed roots for file writes (M9).
# Codegen writes into an output_root supplied by the caller.
# The realpath of every output file must be under the realpath of output_root.

# C8 (MED) — connection-pool exhaustion cap.
# Max simultaneous upstream connections per (tenant, agent, provider) in Caddy's
# transport pool.  64 is a generous upper bound for a single ring-fenced agent:
#   - OpenAI / Anthropic / Mistral rate-limit at the API key level; 64 concurrent
#     calls per agent is already well above any sane workload.
#   - Keeps the Caddy FD budget bounded: 64 * (active agents) << 1024 default.
#   - OPA budget-gate (per-token / per-minute spend cap) is the complementary
#     control at the policy layer — see YSG-C8-OPA-BUDGET (deferred, policy layer).
# Manifest schema override deferred to avoid cross-branch schema changes this wave;
# this constant is the single place to bump the default.
_C8_MAX_CONNS_PER_HOST_DEFAULT: int = 64

_ROOTLESS_L1_GAP_WARNING = (
    "# ROOTLESS-PODMAN-L1-GAP: ringfence-init iptables sidecar cannot apply "
    "L1 containment (CAP_NET_ADMIN unavailable rootless). "
    "L2 (Caddy egress) + L3 (OPA) remain active. Review HIGH-01."
)

# ---------------------------------------------------------------------------
# CodegenError
# ---------------------------------------------------------------------------


class CodegenError(ValueError):
    """Raised for any codegen failure (C1, C3, M9, etc.)."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__("[%s] %s" % (code, detail))


# ---------------------------------------------------------------------------
# Manifest hash for M9 drift detection
# ---------------------------------------------------------------------------

def _manifest_hash(parsed: dict) -> str:
    """
    Stable SHA-256 of the manifest's canonical fields for M9 drift detection.
    Uses tenant_id + name + image.digest as the stable key.
    """
    spec = parsed.get("spec") or {}
    meta = parsed.get("metadata") or {}
    image = spec.get("image") or {}
    key = "%s/%s@%s" % (
        meta.get("tenant_id", ""),
        meta.get("name", ""),
        image.get("digest", ""),
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# C1 — upstream SSRF guard (reuses linter._is_private_address)
# ---------------------------------------------------------------------------

def _assert_not_private(host: str, context: str) -> None:
    """
    C1 (SHIP-BLOCKER): reject any upstream that is a private/loopback/link-local
    or cloud-metadata IP.  Reuses W1's _is_private_address.

    Also explicitly checks 169.254.169.254 (AWS IMDS) which is link-local
    and therefore covered by _is_private_address, but named here for clarity.

    Args:
        host: hostname or IP extracted from egress_allow / base_url.
        context: human description for error message.

    Raises:
        CodegenError: C1_private_upstream if host is a private address.
    """
    if _is_private_address(host):
        raise CodegenError(
            "C1_private_upstream",
            "upstream %r in %s resolves to an RFC1918/loopback/link-local address. "
            "Codegen aborted (C1 — SSRF prevention). "
            "Use a public hostname or contact your security team." % (host, context),
        )


# ---------------------------------------------------------------------------
# C3 — duplicate (tenant_id, agent_id) guard
# ---------------------------------------------------------------------------

# Module-level registry: set of (tenant_id, agent_id) tuples seen this process.
# In production use, the caller resets between unrelated onboard sessions.
_SEEN_PAIRS: set[tuple[str, str]] = set()


def _assert_unique_agent_pair(tenant_id: str, agent_id: str) -> None:
    """
    C3 (HIGH): reject duplicate (tenant_id, agent_id) within a codegen session.

    Raises:
        CodegenError: C3_duplicate_agent if the pair was already registered.
    """
    pair = (tenant_id, agent_id)
    if pair in _SEEN_PAIRS:
        raise CodegenError(
            "C3_duplicate_agent",
            "duplicate (tenant_id=%r, agent_id=%r) detected. "
            "Each agent must be unique within a codegen session (C3). "
            "Call reset_codegen_registry() between independent onboard sessions." % (
                tenant_id, agent_id),
        )
    _SEEN_PAIRS.add(pair)


def reset_codegen_registry() -> None:
    """Reset the C3 duplicate-pair registry. Call between independent onboard sessions."""
    _SEEN_PAIRS.clear()


# ---------------------------------------------------------------------------
# C10 — Caddy snippet validator
# ---------------------------------------------------------------------------

def _c10_require_caddy_validate() -> bool:
    """
    LAURA-005: return True if an absent caddy binary is a hard failure.

    Controlled by two env vars (mirrors M7 enforcement-level pattern):
      YSG_REQUIRE_CADDY_VALIDATE=true/1/yes/fail  — explicit opt-in
      YASHIGANI_ENV=production or YASHIGANI_ENV=staging               — implicit production gate

    Dev environments (unset, "dev", "development", "test") keep skip-with-warning.
    """
    explicit = os.environ.get("YSG_REQUIRE_CADDY_VALIDATE", "").lower()
    if explicit in ("true", "1", "yes", "fail"):
        return True
    env = os.environ.get("YASHIGANI_ENV", "").lower()
    return env in ("production", "staging", "prod")


def _validate_caddy_snippet(
    snippet: str,
    *,
    _validator: Optional[Callable[[str], int]] = None,
) -> None:
    """
    C10 (HIGH ship-gate): run caddy validate on a generated snippet.

    The snippet is wrapped in a minimal Caddyfile shell and validated.

    If ``_validator`` is not provided, this function searches for the ``caddy``
    binary.

    LAURA-005 enforcement-level gate:
      - If caddy is absent AND _c10_require_caddy_validate() is True
        (YSG_REQUIRE_CADDY_VALIDATE=true or YASHIGANI_ENV=production/staging):
        HARD FAIL — codegen aborted.  caddy must be on PATH during onboard
        in production environments.
      - Otherwise (dev / unset): skip with WARNING (original behaviour).
    If caddy IS present (or a validator callable is injected), any validation
    failure aborts codegen regardless of mode.

    Args:
        snippet: Caddy configuration snippet to validate.
        _validator: Optional injectable callable ``(caddyfile_text) -> exit_code``.
                    Used in tests to mock both pass and fail paths.
    """
    if _validator is not None:
        # Injected mock validator
        caddyfile = "{\n    admin off\n}\n\n" + snippet
        rc = _validator(caddyfile)
        if rc != 0:
            raise CodegenError(
                "C10_caddy_validate_failed",
                "caddy validate returned exit code %d for snippet. "
                "Codegen aborted (C10). Fix the Caddy configuration fragment." % rc,
            )
        return

    # Real path: locate caddy binary
    caddy_bin = shutil.which("caddy")
    if caddy_bin is None:
        if _c10_require_caddy_validate():
            raise CodegenError(
                "C10_caddy_binary_absent",
                "caddy binary not found and YSG_REQUIRE_CADDY_VALIDATE / YASHIGANI_ENV "
                "mandates validation. Install caddy on PATH before running "
                "`yashigani onboard` in production/staging (LAURA-005 / C10).",
            )
        _log.warning(
            "C10: caddy binary not found — Caddy snippet validation SKIPPED. "
            "Install caddy and re-run `yashigani onboard` to enforce C10. "
            "Set YSG_REQUIRE_CADDY_VALIDATE=true or YASHIGANI_ENV=production "
            "to make absent caddy a hard failure (LAURA-005)."
        )
        return

    # Write to temp file and validate
    caddyfile = "{\n    admin off\n}\n\n" + snippet
    fd, tmp_path = tempfile.mkstemp(suffix=".Caddyfile", prefix="ysg-codegen-")
    try:
        os.write(fd, caddyfile.encode("utf-8"))
        os.close(fd)
        result = subprocess.run(  # noqa: S603 — caddy binary is system-installed
            [caddy_bin, "validate", "--config", tmp_path],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode("utf-8", errors="replace")[:512]
            raise CodegenError(
                "C10_caddy_validate_failed",
                "caddy validate failed (exit %d): %s\nCodegen aborted (C10). "
                "Fix the Caddy configuration fragment." % (result.returncode, stderr),
            )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# M9 — safe write (realpath + allowed-roots + atomic rename + O_NOFOLLOW)
# ---------------------------------------------------------------------------

def _safe_write(dest: Path, content: str, allowed_root: Path) -> None:
    """
    M9 (MEDIUM): write ``content`` to ``dest`` with:
      - realpath + allowed-roots prefix check (refuse to write outside output_root)
      - symlink guard (refuse to write through a symlinked dest)
      - atomic rename via tempfile-then-os.rename

    LAURA-004 comment accuracy: this is a check-then-atomic-rename pattern.
    It is NOT true O_NOFOLLOW semantics (which would require per-component
    openat(O_NOFOLLOW) at each path element).  A TOCTOU residual exists: if
    the output directory is attacker-writable, a symlink planted between the
    realpath check and the os.rename call will not be caught.  In the intended
    deployment model (operator-owned output root, single-user process) this
    risk is negligible.  Operator runbook must document: output_root must be
    owned by and writable only by the yashigani process user.

    Raises:
        CodegenError: M9_path_traversal, M9_symlink_write
    """
    # Resolve the parent directory to detect symlinks in the path
    allowed_root_real = Path(os.path.realpath(str(allowed_root)))

    # Resolve dest: if the path already exists we realpath it; if not, realpath the parent
    if dest.exists():
        dest_real = Path(os.path.realpath(str(dest)))
    else:
        dest_real = Path(os.path.realpath(str(dest.parent))) / dest.name

    # Allowed-roots prefix check
    try:
        dest_real.relative_to(allowed_root_real)
    except ValueError:
        raise CodegenError(
            "M9_path_traversal",
            "output path %r resolves to %r which is outside the allowed root %r. "
            "Codegen refused (M9 — path traversal prevention)." % (
                str(dest), str(dest_real), str(allowed_root_real)),
        )

    # Symlink guard: if any component of the original path is a symlink, refuse
    # We check the original (pre-realpath) dest for symlink components
    check_path = dest
    while str(check_path) != str(check_path.parent):
        if check_path.is_symlink():
            raise CodegenError(
                "M9_symlink_write",
                "output path component %r is a symlink. "
                "Codegen refuses to write through symlinks (M9 — symlink attack prevention)." % str(check_path),
            )
        check_path = check_path.parent

    # Ensure parent directory exists
    dest_real.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write: write to temp, then rename
    fd, tmp_path_str = tempfile.mkstemp(
        dir=str(dest_real.parent),
        prefix=".ysg-codegen-tmp-",
        suffix=dest_real.suffix or ".tmp",
    )
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        fd = -1
        # Atomic rename
        os.rename(tmp_path_str, str(dest_real))
    except Exception:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_path_str)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# S6 — shell fragment validation (bash -n + shellcheck)
# ---------------------------------------------------------------------------

def _validate_shell_fragment(fragment: str, fragment_name: str) -> None:
    """
    S6 (SHIP-BLOCKER): validate an emitted shell fragment with bash -n and shellcheck.

    bash -n: syntax check (always available, bash 3.2 safe).
    shellcheck: semantic shell linting (used if available; NOT an error if absent).

    Raises:
        CodegenError: S6_bash_syntax, S6_shellcheck_failure
    """
    bash_bin = shutil.which("bash")
    if bash_bin is None:
        _log.warning("S6: bash not found — shell fragment syntax check SKIPPED for %s", fragment_name)
    else:
        # Write fragment to temp file
        fd, tmp_sh = tempfile.mkstemp(suffix=".sh", prefix="ysg-s6-")
        try:
            os.write(fd, fragment.encode("utf-8"))
            os.close(fd)
            fd = -1
            result = subprocess.run(  # noqa: S603
                [bash_bin, "-n", tmp_sh],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")[:512]
                raise CodegenError(
                    "S6_bash_syntax",
                    "bash -n syntax check failed for %s: %s" % (fragment_name, stderr),
                )
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            try:
                os.unlink(tmp_sh)
            except OSError:
                pass

    # shellcheck (optional — warn if absent)
    sc_bin = shutil.which("shellcheck")
    if sc_bin is None:
        _log.warning("S6: shellcheck not found — semantic shell check SKIPPED for %s", fragment_name)
        return

    fd2, tmp_sc = tempfile.mkstemp(suffix=".sh", prefix="ysg-sc-")
    try:
        os.write(fd2, fragment.encode("utf-8"))
        os.close(fd2)
        fd2 = -1
        result2 = subprocess.run(  # noqa: S603
            [sc_bin, "--shell=sh", "--enable=all", "--severity=error", tmp_sc],
            capture_output=True,
            timeout=15,
        )
        if result2.returncode != 0:
            stderr2 = result2.stderr.decode("utf-8", errors="replace")[:512]
            stdout2 = result2.stdout.decode("utf-8", errors="replace")[:512]
            raise CodegenError(
                "S6_shellcheck_failure",
                "shellcheck failed for %s:\n%s%s" % (fragment_name, stdout2, stderr2),
            )
    finally:
        if fd2 != -1:
            try:
                os.close(fd2)
            except OSError:
                pass
        try:
            os.unlink(tmp_sc)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def _header_comment(
    manifest_hash: str,
    runtime: str,
    comment_char: str = "#",
) -> str:
    """
    Generate the M9 + L10 header comment for a generated artifact.

    M9: .yashigani-manifest-hash for drift detection.
    L10: YSG_RUNTIME — wrong-runtime codegen silently produces no ring-fence.
    """
    return (
        "{c} GENERATED BY yashigani codegen — DO NOT EDIT MANUALLY\n"
        "{c} .yashigani-manifest-hash: {hash}\n"
        "{c} YSG_RUNTIME: {runtime}\n"
        "{c} Editing this file manually breaks drift detection (M9).\n"
        "{c} Re-generate with: yashigani onboard <manifest.yaml>\n"
    ).format(c=comment_char, hash=manifest_hash, runtime=runtime)


# ---------------------------------------------------------------------------
# Shape A artifact generators
# ---------------------------------------------------------------------------

def _gen_compose_override(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate the docker-compose.override.yml stanza for a Shape A agent.

    S10: override file, not core compose — offboard can delete atomically.
    L9: hardened security defaults.
    L3: IPv6 default-deny sysctls.
    L7: depends_on with service_completed_successfully.
    S7: group_add 2002 for kms-secret agents.
    """
    meta = parsed.get("metadata") or {}
    spec = parsed.get("spec") or {}
    image = spec.get("image") or {}
    secrets_list = spec.get("secrets") or []

    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")
    repo = image.get("repository", "")
    tag = image.get("tag", "")
    digest = image.get("digest", "")

    # S7: kms-source agents get supplemental group 2002
    has_kms_secrets = any(
        s.get("source") == "kms" for s in secrets_list if isinstance(s, dict)
    )
    group_add_line = ('      group_add:\n        - "2002"\n' if has_kms_secrets else "")

    rootless_note = ""
    if runtime == "podman-rootless":
        rootless_note = "      # %s\n" % _ROOTLESS_L1_GAP_WARNING.lstrip("# ")

    # L7: depends_on — ringfence-init must complete before agent starts
    init_svc = "ringfence-init-%s" % agent_name

    # W3-F1: emit BOTH the isolated ringfence bridge and caddy_internal.
    # Replicates the existing <agent>_isolated pattern at docker-compose.yml:2405-2413
    # (langflow_isolated, letta_isolated, openclaw_isolated — internal:true,
    # enable_ipv6:false).  The ringfence bridge provides L2 default-deny
    # containment; caddy_internal is the only bridge that reaches Caddy egress.
    ringfence_bridge = "ringfence_%s" % agent_name

    lines = [
        _header_comment(manifest_hash, runtime),
        "# Shape A compose override for agent: %s (tenant: %s)" % (agent_name, tenant_id),
        "services:",
        "  %s:" % agent_name,
        "    image: %s:%s@%s" % (repo, tag, digest),
        "    networks:",
        "      - %s" % ringfence_bridge,
        "      - caddy_internal",
        "    # L9 — hardened security defaults",
        "    security_opt:",
        "      - no-new-privileges:true",
        "    cap_drop:",
        "      - ALL",
        "    read_only: true",
        "    user: \"65534:65534\"",
        group_add_line.rstrip("\n") if group_add_line else "",
        "    # L3 — IPv6 default-deny",
        "    sysctls:",
        "      net.ipv6.conf.all.disable_ipv6: 1",
        "      net.ipv6.conf.default.disable_ipv6: 1",
        "    # L7 — block on ringfence-init completion",
        "    depends_on:",
        "      %s:" % init_svc,
        "        condition: service_completed_successfully",
        rootless_note.rstrip("\n") if rootless_note else "",
        "",
        "# W3-F1: isolated ringfence bridge — L2 default-deny containment (YSG-RISK-055)",
        "networks:",
        "  %s:" % ringfence_bridge,
        "    driver: bridge",
        "    enable_ipv6: false",
        "    internal: true",
    ]

    # Remove empty lines (optional disabled features)
    content = "\n".join(line for line in lines if line != "")
    return content + "\n"


def _gen_values_yaml(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate values-<agent>.yaml for Helm.

    L9: hardened K8s security context defaults.
    S7: supplementalGroups 2002 for kms-secret agents.
    """
    meta = parsed.get("metadata") or {}
    spec = parsed.get("spec") or {}
    image = spec.get("image") or {}
    secrets_list = spec.get("secrets") or []

    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")
    repo = image.get("repository", "")
    tag = image.get("tag", "")
    digest = image.get("digest", "")

    has_kms_secrets = any(
        s.get("source") == "kms" for s in secrets_list if isinstance(s, dict)
    )
    supp_groups = "supplementalGroups: [2002]" if has_kms_secrets else "# supplementalGroups: [] # no kms secrets"

    rootless_note = ""
    if runtime == "podman-rootless":
        rootless_note = "  # %s\n" % _ROOTLESS_L1_GAP_WARNING.lstrip("# ")

    content = textwrap.dedent("""\
        {header}
        # Shape A Helm values for agent: {agent_name} (tenant: {tenant_id})
        agent{agent_name_camel}:
          enabled: true
          image:
            repository: {repo}
            tag: "{tag}"
            digest: "{digest}"
          # L9 — hardened K8s security context
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
            seccompProfile:
              type: RuntimeDefault
          podSecurityContext:
            {supp_groups}
          # L10 — runtime tag embedded for drift detection
          runtimeTag: "{runtime}"
        {rootless_note}
    """).format(
        header=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        agent_name_camel=_to_camel(agent_name),
        tenant_id=tenant_id,
        repo=repo,
        tag=tag,
        digest=digest,
        supp_groups=supp_groups,
        runtime=runtime,
        rootless_note=rootless_note,
    )
    return content


def _gen_networkpolicy_overlay(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate values-<agent>-networkpolicy.yaml Helm overlay.

    Emits deny-all ingress/egress defaults with explicit allow for
    configured egress hosts.
    """
    meta = parsed.get("metadata") or {}
    spec = parsed.get("spec") or {}
    network = spec.get("network") or {}

    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")
    egress_allow = network.get("egress_allow") or []

    egress_rules = []

    # W3-F2: always allow egress to Caddy pod on port 443.
    # Replicates allow-agent-bundle-egress + allow-agent-bundle-ingress pattern
    # from networkpolicy.yaml:1177-1247.  Without this, under default-deny egress,
    # all LLM calls to Caddy are silently dropped.
    # 8-space indent: matches the {egress_section} placeholder inside the
    # textwrap.dedent template below (the template dedents everything 8 spaces,
    # but since textwrap.dedent removes the COMMON leading whitespace from the
    # template string, the {egress_section} placeholder is at 8-space indent
    # relative to the YAML root).  We emit our rules at 8-space indent so they
    # nest correctly under egress:.
    egress_rules.append(
        "        # W3-F2: allow egress to Caddy (ring-fence egress gateway) — port 443\n"
        "        - to:\n"
        "            - podSelector:\n"
        "                matchLabels:\n"
        "                  app.kubernetes.io/name: caddy\n"
        "          ports:\n"
        "            - protocol: TCP\n"
        "              port: 443"
    )

    # W3-F2: always allow egress to kube-dns (UDP+TCP 53).
    # Without this, service-name resolution inside the agent pod fails under
    # default-deny egress (the agent cannot resolve "caddy" or any other svc name).
    egress_rules.append(
        "        # W3-F2: allow egress to kube-dns — UDP+TCP 53\n"
        "        - to:\n"
        "            - namespaceSelector:\n"
        "                matchLabels:\n"
        "                  kubernetes.io/metadata.name: kube-system\n"
        "              podSelector:\n"
        "                matchLabels:\n"
        "                  k8s-app: kube-dns\n"
        "          ports:\n"
        "            - protocol: UDP\n"
        "              port: 53\n"
        "            - protocol: TCP\n"
        "              port: 53"
    )

    for entry in egress_allow:
        if not isinstance(entry, dict):
            continue
        host = entry.get("host", "")
        if not host:
            continue
        ports = entry.get("ports") or []
        port_block = ""
        if ports:
            port_lines = "\n".join("            - port: %d" % p for p in ports)
            port_block = "\n          ports:\n%s" % port_lines
        egress_rules.append(
            "        - to:\n"
            "            - ipBlock:\n"
            "                cidr: 0.0.0.0/0%s  # %s" % (port_block, host)
        )

    egress_section = "\n".join(egress_rules)

    content = textwrap.dedent("""\
        {header}
        # Shape A NetworkPolicy overlay for agent: {agent_name} (tenant: {tenant_id})
        networkPolicy:
          enabled: true
          agent{agent_name_camel}:
            ingress: []  # deny all ingress (empty list = deny-all per K8s NP spec)
            egress:
        {egress_section}
    """).format(
        header=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        agent_name_camel=_to_camel(agent_name),
        tenant_id=tenant_id,
        egress_section=egress_section,
    )
    return content


def _gen_kyverno_policy_exception(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate templates/agents/<agent>-policy-exception.yaml (Kyverno NET_ADMIN).

    L1: PolicyException scoped to yashigani.io/ringfence-init: "true".
    Separate file — cannot live in a values range-over block (L1 requirement).
    """
    meta = parsed.get("metadata") or {}

    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")

    content = textwrap.dedent("""\
        {header}
        # Kyverno PolicyException for ringfence-init NET_ADMIN
        # L1: scoped to yashigani.io/ringfence-init: "true" pods only
        # agent: {agent_name} (tenant: {tenant_id})
        apiVersion: kyverno.io/v2
        kind: PolicyException
        metadata:
          name: ringfence-init-{agent_name}-net-admin
          namespace: yashigani
          labels:
            yashigani.io/agent: "{agent_name}"
            yashigani.io/tenant: "{tenant_id}"
        spec:
          exceptions:
            - policyName: restrict-capabilities
              ruleNames:
                - restrict-net-admin
          match:
            any:
              - resources:
                  kinds:
                    - Pod
                  selector:
                    matchLabels:
                      yashigani.io/ringfence-init: "true"
                      yashigani.io/agent: "{agent_name}"
                      yashigani.io/tenant: "{tenant_id}"
    """).format(
        header=_header_comment(manifest_hash, runtime, comment_char="#"),
        agent_name=agent_name,
        tenant_id=tenant_id,
    )
    return content


def _extract_tls_server_name(base_url: str) -> str:
    """
    C5 (MED): extract the TLS SNI hostname from model_egress.base_url.

    The SNI is always the hostname from the manifest-configured base_url —
    NEVER derived from request headers, query parameters, or any runtime input.
    This prevents Host-header injection from influencing TLS verification.

    Returns the bare hostname (no port) for use as tls_server_name.
    Returns empty string if base_url is absent or unparseable.
    """
    if not base_url:
        return ""
    from urllib.parse import urlparse
    parsed_url = urlparse(base_url)
    # urlparse.hostname strips port and lowercases the host
    return parsed_url.hostname or ""


def _gen_caddy_snippet(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate docker/caddy/agents/<agent>.caddy snippet (Shape A LLM egress route).

    C1: upstreams hardcoded from manifest egress_allow; NEVER from headers/query params.
        URI strip_prefix path canonicalisation applied.
        Private IP upstreams rejected before reaching this function (CodegenEngine).
    C3: route namespaced /agents/{tenant_id}/{agent_id}/.
    C5: per-upstream TLS verification — explicit transport http block with
        tls_server_name set from manifest base_url (hardcoded, never from request).
        tls_insecure_skip_verify is NEVER emitted.  Caddy verifies the upstream
        certificate against system roots.  The SNI hostname is always the provider
        host from model_egress.base_url — Caddy never proxies a client-supplied
        Host value to the upstream TLS handshake.
    C8: max_conns_per_host _C8_MAX_CONNS_PER_HOST_DEFAULT caps upstream connection
        pool to prevent (tenant, agent, provider) connection exhaustion DoS.
        OPA budget-gate half deferred — see YSG-C8-OPA-BUDGET.
    """
    meta = parsed.get("metadata") or {}
    spec = parsed.get("spec") or {}
    network = spec.get("network") or {}
    model_egress = spec.get("model_egress") or {}

    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")

    # C5: extract primary provider host for tls_server_name (from manifest config,
    # NEVER from request headers).  This is set once at codegen time.
    base_url = model_egress.get("base_url", "")
    tls_server_name = _extract_tls_server_name(base_url)

    # Build upstream list from egress_allow + model_egress.base_url
    upstreams: list[str] = []

    # model_egress.base_url is the primary upstream for Shape A.
    # MUST include an explicit port so Caddy's reverse_proxy dials the correct
    # port. Without an explicit port, Caddy always dials :80 regardless of the
    # transport http { tls } subdirective — caddy adapt exposes this as
    # {"dial":"host:80"} even for HTTPS upstreams (Captain gate, v2.25.0 P1).
    if base_url:
        from urllib.parse import urlparse
        parsed_url = urlparse(base_url)
        _hostname = parsed_url.hostname  # lowercased, no port
        if _hostname:
            _scheme = parsed_url.scheme.lower() if parsed_url.scheme else ""
            _port = parsed_url.port or (443 if _scheme == "https" else 80)
            upstreams.append("%s:%d" % (_hostname, _port))

    # Additional egress_allow entries
    egress_allow = network.get("egress_allow") or []
    for entry in egress_allow:
        if not isinstance(entry, dict):
            continue
        host = entry.get("host", "")
        ports = entry.get("ports") or []
        if host:
            if ports:
                for port in ports:
                    upstreams.append("%s:%d" % (host, port))
            else:
                upstreams.append(host)

    # Deduplicate preserving order
    seen: set[str] = set()
    deduped_upstreams: list[str] = []
    for u in upstreams:
        if u not in seen:
            seen.add(u)
            deduped_upstreams.append(u)

    route_prefix = "/agents/%s/%s" % (tenant_id, agent_name)

    if not deduped_upstreams:
        # No upstream configured — emit a placeholder route that returns 502
        upstream_block = "        respond \"no upstream configured\" 502"
    else:
        # C5 + C8: always use block form so we can embed the transport http
        # subdirective.  Both single- and multi-upstream paths use block form.
        #
        # transport http subdirective layout:
        #   tls                     — enable TLS to the upstream (mandatory for C5)
        #   tls_server_name <host>  — hardcode SNI from manifest (C5 SSRF guard)
        #                             NEVER from request headers/Host
        #   max_conns_per_host <N>  — connection-pool cap (C8 DoS resistance)
        #
        # Note: tls_insecure_skip_verify is intentionally absent.  Caddy verifies
        # the upstream certificate against system roots by default when tls is set.
        # Absent tls_insecure_skip_verify = verification ON (fail-closed).
        to_lines = "\n".join("            to %s" % u for u in deduped_upstreams)
        if tls_server_name:
            transport_block = (
                "            # C5: TLS to upstream — SNI hardcoded from manifest (NEVER from request)\n"
                "            # C8: connection-pool cap — DoS resistance (OPA budget-gate: YSG-C8-OPA-BUDGET)\n"
                "            transport http {{\n"
                "                tls\n"
                "                tls_server_name {tls_server_name}\n"
                "                max_conns_per_host {max_conns}\n"
                "            }}"
            ).format(
                tls_server_name=tls_server_name,
                max_conns=_C8_MAX_CONNS_PER_HOST_DEFAULT,
            )
        else:
            # No base_url → no SNI to pin; still cap connections (C8)
            transport_block = (
                "            # C8: connection-pool cap — DoS resistance (OPA budget-gate: YSG-C8-OPA-BUDGET)\n"
                "            transport http {{\n"
                "                tls\n"
                "                max_conns_per_host {max_conns}\n"
                "            }}"
            ).format(max_conns=_C8_MAX_CONNS_PER_HOST_DEFAULT)

        upstream_block = (
            "        reverse_proxy {{\n"
            "{to_lines}\n"
            "{transport_block}\n"
            "        }}"
        ).format(
            to_lines=to_lines,
            transport_block=transport_block,
        )

    rootless_note = ""
    if runtime == "podman-rootless":
        rootless_note = "\t# %s\n" % _ROOTLESS_L1_GAP_WARNING.lstrip("# ")

    content = textwrap.dedent("""\
        {header}
        # Shape A LLM egress route for agent: {agent_name} (tenant: {tenant_id})
        # C1: upstreams hardcoded — never from request headers/query (SSRF prevention)
        # C3: route namespaced /agents/{{tenant_id}}/{{agent_id}}/
        # C5: transport http tls_server_name hardcoded from manifest — SSRF/SNI guard
        # C8: max_conns_per_host {max_conns} — connection-pool DoS cap
        :443 {{
            handle_path {route_prefix}/* {{
                # C1 — path canonicalisation (strip_prefix equivalent)
                uri strip_prefix {route_prefix}
        {rootless_note}
                # Forward auth via Caddy — app-layer auth gate
                forward_auth /api/auth/agent {{
                    uri /api/auth/agent?agent={agent_name}&tenant={tenant_id}
                    copy_headers X-Agent-Identity X-Tenant-Id
                }}

        {upstream_block}
            }}
        }}
    """).format(
        header=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        tenant_id=tenant_id,
        route_prefix=route_prefix,
        upstream_block=upstream_block,
        rootless_note=rootless_note,
        max_conns=_C8_MAX_CONNS_PER_HOST_DEFAULT,
    )
    return content


def _gen_service_identity_entry(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate service_identities.yaml append entry.

    Includes SPIFFE URI resolved from manifest (via resolve_spiffe_uri).
    """
    from yashigani.manifest.linter import resolve_spiffe_uri

    meta = parsed.get("metadata") or {}
    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")

    # W3-F4: let ValueError propagate so a future validation addition cannot
    # be silently bypassed.  The linter must reject manifests with missing
    # name/tenant_id before codegen is invoked.
    spiffe_id = resolve_spiffe_uri(parsed)

    content = textwrap.dedent("""\
        {header}
        # service_identities.yaml append entry for agent: {agent_name} (tenant: {tenant_id})
        - name: {agent_name}
          tenant_id: {tenant_id}
          spiffe_id: {spiffe_id}
          shape: "a"
          manifest_hash: "{manifest_hash}"
          runtime: "{runtime}"
    """).format(
        header=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        tenant_id=tenant_id,
        spiffe_id=spiffe_id,
        manifest_hash=manifest_hash,
        runtime=runtime,
    )
    return content


def _gen_pki_ownership_fragment(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate pki_ownership.sh tuple fragment (shell — S6).

    Bash-3.2-safe: no declare -A, no ${var,,}, no mapfile.
    Uses only POSIX-compatible shell constructs.
    """
    meta = parsed.get("metadata") or {}
    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")

    # Emit a POSIX-safe tuple entry (space-separated, no associative arrays)
    # Format: PKI_OWNER_<AGENT>="<tenant_id>:<agent_name>:<spiffe_path>"
    # Variable names use uppercase alphanumeric + underscore only (POSIX var names)
    var_suffix = agent_name.upper().replace("-", "_")
    tenant_suffix = tenant_id.upper().replace("-", "_")

    content = textwrap.dedent("""\
        {header}
        # pki_ownership.sh tuple fragment for agent: {agent_name} (tenant: {tenant_id})
        # S6: bash-3.2-safe (POSIX sh, no declare -A, no mapfile)
        # Append to pki_ownership.sh — do NOT edit manually (M9)
        PKI_OWNER_{tenant_suffix}_{var_suffix}="{tenant_id}:{agent_name}:agents/{tenant_id}/{agent_name}"
        export PKI_OWNER_{tenant_suffix}_{var_suffix}
    """).format(
        header=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        tenant_id=tenant_id,
        var_suffix=var_suffix,
        tenant_suffix=tenant_suffix,
    )
    return content


def _gen_opa_stub(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate OPA policy stub opa/<agent>.rego.

    Deep mcp.rego / OPA authoring is a later phase.
    This stub registers the agent in the OPA registry and returns
    a deny-all default (fail-closed) for all MCP calls.
    """
    meta = parsed.get("metadata") or {}
    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")

    content = textwrap.dedent("""\
        {header}
        # OPA policy stub for agent: {agent_name} (tenant: {tenant_id})
        # STUB: deep mcp.rego authoring is a later phase (P1 W3 out-of-scope).
        # This stub is fail-closed: all MCP calls are denied by default.
        # Replace with full policy when MCP broker runtime is implemented.
        package yashigani.agents.{pkg_name}

        import future.keywords

        # Agent metadata (informational)
        agent_name := "{agent_name}"
        tenant_id := "{tenant_id}"
        shape := "a"
        manifest_hash := "{manifest_hash}"

        # STUB: deny all MCP calls by default (fail-closed)
        # TODO(later-phase): implement per-tool OPA authz (P9)
        default allow := false

        # Allow egress to registered sanctioned upstreams only
        # Populated at full OPA authoring phase
        allow {{
            # Stub: no rules — remains false
            false
        }}
    """).format(
        header=_header_comment(manifest_hash, runtime, comment_char="#"),
        agent_name=agent_name,
        tenant_id=tenant_id,
        pkg_name=agent_name.replace("-", "_"),
        manifest_hash=manifest_hash,
    )
    return content


def _gen_contract_test_compose(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate contract test stub tests/contracts/test_<agent>_compose.py.

    Stub with TODO placeholders — full compose parity tests written at
    integration test phase.
    """
    meta = parsed.get("metadata") or {}
    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")
    class_name = "Test%sCompose" % _to_class_name(agent_name)

    content = textwrap.dedent("""\
        {header_py}
        \"\"\"
        Contract test stub: docker-compose.override.yml parity for agent {agent_name}.

        Codegen is the SINGLE source of truth for compose and Helm artifacts.
        These tests prove compose parity (§3.5). Stubs — flesh out at integration phase.

        Manifest hash: {manifest_hash}
        Runtime: {runtime}
        \"\"\"
        from __future__ import annotations
        import pathlib
        import pytest


        COMPOSE_OVERRIDE = pathlib.Path(__file__).parent.parent.parent / "docker" / "{agent_name}-compose.override.yml"


        class {class_name}:
            \"\"\"Compose parity contract tests for agent {agent_name} (tenant {tenant_id}).\"\"\"

            def test_compose_override_file_exists(self) -> None:
                \"\"\"STUB: override file should exist after onboard.\"\"\"
                # TODO(integration-phase): assert COMPOSE_OVERRIDE.is_file()
                pytest.skip("compose override not yet written to disk in this test env")

            def test_l9_no_new_privileges(self) -> None:
                \"\"\"STUB: security_opt must include no-new-privileges:true (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes override file")

            def test_l9_cap_drop_all(self) -> None:
                \"\"\"STUB: cap_drop must include ALL (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes override file")

            def test_l3_ipv6_disable_sysctls(self) -> None:
                \"\"\"STUB: IPv6 disable sysctls must be present (L3).\"\"\"
                pytest.skip("stub — implement after onboard writes override file")

            def test_l7_depends_on_ringfence_init(self) -> None:
                \"\"\"STUB: depends_on ringfence-init with service_completed_successfully (L7).\"\"\"
                pytest.skip("stub — implement after onboard writes override file")

            def test_c1_no_private_upstream_in_caddy_snippet(self) -> None:
                \"\"\"STUB: Caddy snippet must not contain private IP upstreams (C1).\"\"\"
                pytest.skip("stub — implement after onboard writes Caddy snippet")
    """).format(
        header_py=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        tenant_id=tenant_id,
        manifest_hash=manifest_hash,
        runtime=runtime,
        class_name=class_name,
    )
    return content


def _gen_contract_test_helm(
    parsed: dict,
    *,
    manifest_hash: str,
    runtime: str,
) -> str:
    """
    Generate contract test stub tests/contracts/test_<agent>_helm.py.

    Paired with the compose stub (§3.5 — codegen is single source of truth).
    """
    meta = parsed.get("metadata") or {}
    agent_name = meta.get("name", "")
    tenant_id = meta.get("tenant_id", "")
    class_name = "Test%sHelm" % _to_class_name(agent_name)

    content = textwrap.dedent("""\
        {header_py}
        \"\"\"
        Contract test stub: Helm values parity for agent {agent_name}.

        Codegen is the SINGLE source of truth for compose and Helm artifacts.
        These tests prove Helm parity (§3.5). Stubs — flesh out at integration phase.

        Manifest hash: {manifest_hash}
        Runtime: {runtime}
        \"\"\"
        from __future__ import annotations
        import pathlib
        import subprocess
        import pytest


        HELM_VALUES = pathlib.Path(__file__).parent.parent.parent / "helm" / "yashigani" / "values-{agent_name}.yaml"


        class {class_name}:
            \"\"\"Helm parity contract tests for agent {agent_name} (tenant {tenant_id}).\"\"\"

            def test_helm_values_file_exists(self) -> None:
                \"\"\"STUB: Helm values file should exist after onboard.\"\"\"
                # TODO(integration-phase): assert HELM_VALUES.is_file()
                pytest.skip("helm values not yet written to disk in this test env")

            def test_l9_security_context_run_as_non_root(self) -> None:
                \"\"\"STUB: securityContext.runAsNonRoot must be true (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes values file")

            def test_l9_security_context_no_privilege_escalation(self) -> None:
                \"\"\"STUB: securityContext.allowPrivilegeEscalation must be false (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes values file")

            def test_l9_security_context_read_only_root_filesystem(self) -> None:
                \"\"\"STUB: securityContext.readOnlyRootFilesystem must be true (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes values file")

            def test_l9_security_context_drop_all_caps(self) -> None:
                \"\"\"STUB: capabilities.drop must include ALL (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes values file")

            def test_l9_seccomp_runtime_default(self) -> None:
                \"\"\"STUB: seccompProfile.type must be RuntimeDefault (L9).\"\"\"
                pytest.skip("stub — implement after onboard writes values file")

            def test_helm_compose_parity_image_digest(self) -> None:
                \"\"\"STUB: image digest must match between compose and helm artifacts (§3.5).\"\"\"
                pytest.skip("stub — implement after both artifacts written")
    """).format(
        header_py=_header_comment(manifest_hash, runtime),
        agent_name=agent_name,
        tenant_id=tenant_id,
        manifest_hash=manifest_hash,
        runtime=runtime,
        class_name=class_name,
    )
    return content


# ---------------------------------------------------------------------------
# String utilities
# ---------------------------------------------------------------------------

def _to_camel(name: str) -> str:
    """Convert kebab-case to CamelCase for YAML/Python identifiers."""
    return "".join(part.capitalize() for part in name.split("-"))


def _to_class_name(name: str) -> str:
    """Convert kebab-case agent name to a Python class-name fragment."""
    return "".join(part.capitalize() for part in name.split("-"))


# ---------------------------------------------------------------------------
# CodegenEngine — public API
# ---------------------------------------------------------------------------


class CodegenEngine:
    """
    Codegen engine for Shape A (LLM-calling / Hermes-class) agents.

    Usage::

        engine = CodegenEngine(parsed_manifest, runtime="docker")
        # Dry-run (no file writes):
        artifacts = engine.render(dry_run=True)
        # Real run (write to output_root):
        artifacts = engine.render(output_root=Path("/srv/yashigani"), dry_run=False)

    Args:
        parsed: validated parsed manifest (output of parse_manifest + validate_manifest).
        runtime: 4-way runtime string — one of "docker", "podman-rootful",
                 "podman-rootless", "k8s".
        caddy_validator: optional injectable callable for C10 Caddy validation.
                         Signature: (caddyfile_text: str) -> int (exit code).
                         If None, uses the real caddy binary (or skips with WARNING).
    """

    def __init__(
        self,
        parsed: dict,
        runtime: str,
        *,
        caddy_validator: Optional[Callable[[str], int]] = None,
    ) -> None:
        if runtime not in VALID_RUNTIMES:
            raise CodegenError(
                "INVALID_RUNTIME",
                "runtime %r is not one of %s" % (runtime, sorted(VALID_RUNTIMES)),
            )
        self._parsed = parsed
        self._runtime = runtime
        self._caddy_validator = caddy_validator

        meta = parsed.get("metadata") or {}
        self._tenant_id = meta.get("tenant_id", "")
        self._agent_id = meta.get("name", "")
        self._manifest_hash = _manifest_hash(parsed)

    def _validate_upstreams(self) -> None:
        """
        C1 (SHIP-BLOCKER): check all upstreams (egress_allow + model_egress.base_url)
        for RFC1918/loopback/link-local addresses.

        Raises CodegenError C1_private_upstream on any violation.
        """
        spec = self._parsed.get("spec") or {}
        network = spec.get("network") or {}
        model_egress = spec.get("model_egress") or {}

        # Check egress_allow
        for entry in network.get("egress_allow") or []:
            if not isinstance(entry, dict):
                continue
            host = entry.get("host", "")
            if host:
                _assert_not_private(host, "spec.network.egress_allow")

        # Check model_egress.base_url
        base_url = model_egress.get("base_url", "")
        if base_url:
            from urllib.parse import urlparse
            parsed_url = urlparse(base_url)
            host = parsed_url.hostname or ""
            if host:
                _assert_not_private(host, "spec.model_egress.base_url")

    def render(
        self,
        *,
        output_root: Optional[Path] = None,
        dry_run: bool = True,
    ) -> dict[str, str]:
        """
        Render all Shape A artifacts.

        Args:
            output_root: root directory for file writes (required if dry_run=False).
            dry_run: if True, return rendered content without writing files.

        Returns:
            dict mapping relative artifact paths to their rendered content.

        Raises:
            CodegenError: on any security violation or validation failure.
        """
        if not dry_run and output_root is None:
            raise CodegenError(
                "MISSING_OUTPUT_ROOT",
                "output_root is required when dry_run=False",
            )

        # C1 — upstream validation (SHIP-BLOCKER)
        self._validate_upstreams()

        # C3 — duplicate pair check
        _assert_unique_agent_pair(self._tenant_id, self._agent_id)

        agent_name = self._agent_id
        mhash = self._manifest_hash
        runtime = self._runtime

        # Generate all artifacts
        kwargs: dict[str, Any] = {"manifest_hash": mhash, "runtime": runtime}

        compose_content = _gen_compose_override(self._parsed, **kwargs)
        values_content = _gen_values_yaml(self._parsed, **kwargs)
        netpol_content = _gen_networkpolicy_overlay(self._parsed, **kwargs)
        kyverno_content = _gen_kyverno_policy_exception(self._parsed, **kwargs)
        caddy_content = _gen_caddy_snippet(self._parsed, **kwargs)
        svcid_content = _gen_service_identity_entry(self._parsed, **kwargs)
        pki_content = _gen_pki_ownership_fragment(self._parsed, **kwargs)
        opa_content = _gen_opa_stub(self._parsed, **kwargs)
        test_compose_content = _gen_contract_test_compose(self._parsed, **kwargs)
        test_helm_content = _gen_contract_test_helm(self._parsed, **kwargs)

        # C10 — validate Caddy snippet
        _validate_caddy_snippet(caddy_content, _validator=self._caddy_validator)

        # S6 — validate shell fragment
        _validate_shell_fragment(pki_content, "pki_ownership-%s.sh" % agent_name)

        # Artifact map: relative paths → content
        artifacts: dict[str, str] = {
            "docker/%s-compose.override.yml" % agent_name: compose_content,
            "helm/yashigani/values-%s.yaml" % agent_name: values_content,
            "helm/yashigani/values-%s-networkpolicy.yaml" % agent_name: netpol_content,
            "helm/yashigani/templates/agents/%s-policy-exception.yaml" % agent_name: kyverno_content,
            "docker/caddy/agents/%s.caddy" % agent_name: caddy_content,
            "service_identities.yaml.fragment": svcid_content,
            "pki_ownership-%s.sh" % agent_name: pki_content,
            "opa/%s.rego" % agent_name: opa_content,
            "tests/contracts/test_%s_compose.py" % agent_name: test_compose_content,
            "tests/contracts/test_%s_helm.py" % agent_name: test_helm_content,
        }

        if not dry_run:
            assert output_root is not None  # already checked above
            for rel_path, content in artifacts.items():
                dest = output_root / rel_path
                _safe_write(dest, content, output_root)
                _log.info("codegen: wrote %s", rel_path)

        return artifacts
