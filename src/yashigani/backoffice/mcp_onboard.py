# Last updated: 2026-07-06T00:00:00+00:00 (v4.1 Phase 1c — approve = transaction)
"""
MCP approve transaction — atomic onboarding of a Shape-C MCP server.

SYNTHESIS.md Issue-1 step 6: "Approve = transaction … mint leaf + codegen
snippet + network attach + caddy reload atomically.  No more 'DB row only.'"

Sequence (fail-CLOSED, rolled back LIFO on ANY step failure):

  1. manifest        — parse_manifest + validate_manifest (M1–M8 guards) +
                       identity-consistency checks (name == server_id,
                       tenant_id == install tenant, Shape-C category).
  2. mint_leaf       — pki.issuer.mint_agent_leaf per Nico's contract:
                       ``spiffe://<td>/agents/<tenant>/<server>/<nhi_id>``
                       with GAP-2 change-prevention binding
                       (scope_hash = tool_surface_hash(envelope tools),
                       image_digest from the pinned manifest).
  3. codegen         — manifest.codegen.approve_mcp_onboard(dry_run=False):
                       renders + writes ALL Shape-C artifacts (Caddy-front
                       wrap snippet, compose override, helm values/netpol,
                       …) under YASHIGANI_MCP_ARTIFACT_ROOT.  Raises
                       CodegenError on any security violation.
  4. caddy_reload    — POST the monolith Caddyfile to Caddy's admin API
                       (Content-Type: text/caddyfile; Caddy adapts
                       server-side, resolving the
                       ``import /etc/caddy/agents/*.caddy`` sentinel that
                       picks up the new wrap).  Caddy reloads are atomic and
                       zero-downtime; a failed load leaves the old config
                       running.  Transport branches on
                       YASHIGANI_CONTAINER_RUNTIME (SU-SEAM-1d-04 fix):
                         docker / podman-*  — shared unix admin socket
                                              (single-host compose; caddy and
                                              backoffice share /run/caddy).
                         k8s                — Caddy's mesh-mTLS admin relay
                                              listener (:2019 site block that
                                              proxies POST /load to the
                                              caddy-pod-local unix socket).
                                              backoffice authenticates with
                                              its mesh ServiceIdentity leaf;
                                              the relay requires
                                              require_and_verify + the
                                              backoffice SPIFFE URI.  Unix
                                              sockets cannot span pods —
                                              caddy and backoffice are
                                              separate pods on K8s.
  4b. broker_registry — v4.1 Phase 2a (Iris SEAM-1d-07): durably register
                       the broker descriptor (upstream = the Caddy-front
                       wrap URL, per-instance leaf fingerprint) into the
                       DurableMcpRegistryStore, keyed on the canonical
                       ``<tenant>:<server>``.  The gateway McpBrokerRegistry
                       lazily loads it on first ``/mcp/<server>`` lookup —
                       the broker dials the wrap WITHOUT a gateway reboot.
                       Rolled back (key deleted) on any later failure.
  5. envelope_mint   — durable registry INSERT (mcp_tool_surface_pins) with
                       ``svid_instance_id`` / ``svid_spiffe_id`` /
                       ``svid_issued=True``.  This is the COMMIT POINT: the
                       svid flags ride the same INSERT and can therefore
                       never be persisted without the real cert minted in
                       step 2 (the BUG-A fail-open pattern must not
                       reappear).

INVARIANT (Iris SEAM-1d-03 — do NOT "fix" the ordering): steps 4/4b run
BEFORE the envelope commit (step 5).  This is safe ONLY because
/auth/verify-mcp fails CLOSED on a missing envelope (auth.py get_active_envelope
→ None → 403 server_not_onboarded), so a request racing the window between
reload/registration and commit is DENIED, never leaked.  Reordering the
commit before the reload would invert that into a fail-open window.

Rollback on failure: minted cert/key files are removed and written artifacts
deleted (with a best-effort re-reload to restore Caddy state if step 4 had
already applied).  The runtime service-identity manifest entry appended by
mint_agent_leaf is left in place — with the cert files gone it is inert
(informational only), and rewriting the shared YAML during error handling is
a worse failure mode.  A ``MCP_ONBOARD_TRANSACTION_FAILED`` audit event is
emitted on the tamper-evident chain.

Deployment wiring (Phase-3 stack rebuild — Su/Captain):
  * ``YASHIGANI_MCP_ARTIFACT_ROOT`` — writable bind of the install's
    ``docker/``-rooted tree into the backoffice container (the caddy
    container reads ``docker/caddy/agents/`` from the same tree).
  * ``YASHIGANI_CADDY_ADMIN_SOCKET`` (default ``/run/caddy/admin.sock``) —
    the caddy admin unix socket volume must be shared with backoffice
    (today it is a caddy-local tmpfs, mode 0700).  Compose runtimes only.
  * ``YASHIGANI_CADDY_ADMIN_URL`` (default
    ``https://yashigani-caddy-admin:2019``) — K8s runtime only: base URL of
    Caddy's mesh-mTLS admin relay listener
    (helm configmaps.yaml ``:2019`` site block).  MUST be https on the mesh;
    the client is ``yashigani.pki.client.internal_httpx_client()`` (the
    backoffice ServiceIdentity leaf + internal-CA trust) — there is NO
    identity-less fallback on this path (fail-closed).
  * ``YASHIGANI_CADDY_CADDYFILE`` (default ``/etc/caddy/Caddyfile``) — the
    active monolith Caddyfile mounted read-only into backoffice.
  * ``YASHIGANI_CONTAINER_RUNTIME`` — one of codegen.VALID_RUNTIMES
    (default ``docker``); install.sh sets it per selected runtime.
Until that wiring lands, the transaction fails CLOSED (503/502 + rollback) —
no partial onboarding is possible.
"""
from __future__ import annotations

import logging
import os
import shutil
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

_DEFAULT_ADMIN_SOCKET = "/run/caddy/admin.sock"
_DEFAULT_CADDYFILE = "/etc/caddy/Caddyfile"
# K8s only — Caddy's mesh-mTLS admin relay (helm configmaps.yaml :2019 site
# block). https is mandatory: the relay is require_and_verify + SPIFFE-gated.
# yashigani-caddy-admin is the DEDICATED ClusterIP Service (caddy.yaml) — the
# public yashigani-caddy Service is type LoadBalancer and must never carry
# the admin relay port. The caddy leaf carries the yashigani-caddy-admin DNS
# SAN (service_identities.yaml) so hostname verification passes.
_DEFAULT_ADMIN_API_URL = "https://yashigani-caddy-admin:2019"


class McpOnboardError(Exception):
    """The approve transaction failed at *step* and was rolled back."""

    def __init__(self, step: str, message: str, *, http_status: int = 502) -> None:
        super().__init__(message)
        self.step = step
        self.http_status = http_status


@dataclass
class McpOnboardResult:
    """Outcome of a committed approve transaction."""

    envelope_id: int
    instance_id: str
    spiffe_id: str
    artifact_paths: list[str] = field(default_factory=list)


def _artifact_root() -> Path:
    root = os.getenv("YASHIGANI_MCP_ARTIFACT_ROOT", "").strip()
    if not root:
        raise McpOnboardError(
            "config",
            "YASHIGANI_MCP_ARTIFACT_ROOT is not set — the approve transaction "
            "cannot write wrap artifacts (Phase-3 wiring; see mcp_onboard.py "
            "module docstring). Onboarding fails closed.",
            http_status=503,
        )
    return Path(root)


def _runtime() -> str:
    from yashigani.manifest.codegen import VALID_RUNTIMES
    runtime = os.getenv("YASHIGANI_CONTAINER_RUNTIME", "docker").strip() or "docker"
    if runtime not in VALID_RUNTIMES:
        raise McpOnboardError(
            "config",
            "YASHIGANI_CONTAINER_RUNTIME=%r is not one of %s"
            % (runtime, sorted(VALID_RUNTIMES)),
            http_status=503,
        )
    return runtime


def _read_caddyfile_text() -> str:
    """Read the active monolith Caddyfile (shared by both reload transports)."""
    caddyfile_path = os.getenv("YASHIGANI_CADDY_CADDYFILE", _DEFAULT_CADDYFILE)
    try:
        return Path(caddyfile_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"cannot read Caddyfile at {caddyfile_path!r}: {exc} "
            "(Phase-3 wiring — mount the active Caddyfile into backoffice)",
        ) from exc


async def _reload_via_admin_socket() -> None:
    """Compose runtimes (docker / podman-*) — shared unix admin socket.

    POSTs the active monolith Caddyfile with ``Content-Type: text/caddyfile``;
    Caddy adapts it server-side (parse-time ``{$ENV}`` substitution and the
    ``import /etc/caddy/agents/*.caddy`` sentinel both resolve inside the
    caddy container).  A non-2xx response or an unreachable socket raises —
    the transaction rolls back (fail-closed).
    """
    import httpx  # noqa: PLC0415 — keep module import light

    socket_path = os.getenv("YASHIGANI_CADDY_ADMIN_SOCKET", _DEFAULT_ADMIN_SOCKET)
    caddyfile_text = _read_caddyfile_text()

    transport = httpx.AsyncHTTPTransport(uds=socket_path)
    try:
        async with httpx.AsyncClient(transport=transport, timeout=15.0) as client:
            resp = await client.post(
                # Host is ignored for unix-socket admin endpoints; Caddy
                # requires a well-formed origin.
                "http://localhost/load",
                content=caddyfile_text.encode("utf-8"),
                headers={"Content-Type": "text/caddyfile"},
            )
    except httpx.HTTPError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"caddy admin socket {socket_path!r} unreachable: {exc} "
            "(Phase-3 wiring — share /run/caddy with backoffice)",
        ) from exc
    if resp.status_code // 100 != 2:
        raise McpOnboardError(
            "caddy_reload",
            "caddy /load rejected the config (HTTP %d): %.300s"
            % (resp.status_code, resp.text),
        )
    logger.info("mcp-onboard: caddy reload OK (admin socket %s)", socket_path)


async def _reload_via_admin_api() -> None:
    """K8s runtime — Caddy's mesh-mTLS admin relay listener (SU-SEAM-1d-04).

    On K8s, caddy and backoffice are separate pods: the unix admin socket
    cannot be shared (emptyDir is pod-local; same-node co-location / RWX PVC
    is not the architecture).  Instead the helm Caddyfile exposes a ``:2019``
    site block that:

      * terminates mesh mTLS with ``client_auth require_and_verify`` against
        the internal CA bundle (identity-less clients are refused at the
        TLS handshake — the raw admin API is NEVER on the pod network), and
      * admits ONLY ``POST /load`` from the backoffice SPIFFE URI (CEL
        expression on the client-cert URI SAN), then proxies to the
        caddy-pod-local unix admin socket.

    The client here is ``internal_httpx_client()`` — the backoffice
    ServiceIdentity leaf + internal-CA trust, the SAME factory every other
    internal mesh call uses (MCP-001 pattern).  There is deliberately NO
    identity-less fallback: an admin config-mutation surface must fail
    CLOSED when the mesh identity is unavailable.
    """
    import httpx  # noqa: PLC0415 — keep module import light

    admin_url = os.getenv(
        "YASHIGANI_CADDY_ADMIN_URL", _DEFAULT_ADMIN_API_URL
    ).strip().rstrip("/")
    if not admin_url.startswith("https://"):
        raise McpOnboardError(
            "caddy_reload",
            f"YASHIGANI_CADDY_ADMIN_URL={admin_url!r} must be https:// — the "
            "K8s admin relay is mesh-mTLS only (fail-closed).",
        )
    caddyfile_text = _read_caddyfile_text()

    try:
        from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415
        client = internal_httpx_client(timeout=15.0)
    except Exception as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"mesh ServiceIdentity unavailable for the caddy admin relay "
            f"({exc}) — the K8s reload path has no identity-less fallback "
            "(fail-closed; check YASHIGANI_SERVICE_NAME + /run/secrets PKI).",
        ) from exc

    try:
        async with client:
            resp = await client.post(
                f"{admin_url}/load",
                content=caddyfile_text.encode("utf-8"),
                headers={"Content-Type": "text/caddyfile"},
            )
    except httpx.HTTPError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"caddy admin relay {admin_url!r} unreachable: {exc} "
            "(check the helm :2019 admin-relay listener + NetworkPolicy "
            "backoffice→caddy:2019)",
        ) from exc
    if resp.status_code // 100 != 2:
        raise McpOnboardError(
            "caddy_reload",
            "caddy /load (admin relay) rejected the config (HTTP %d): %.300s"
            % (resp.status_code, resp.text),
        )
    logger.info("mcp-onboard: caddy reload OK (mesh admin relay %s)", admin_url)


async def default_caddy_reloader() -> None:
    """Reload Caddy — transport selected by YASHIGANI_CONTAINER_RUNTIME.

    docker / podman-rootful / podman-rootless → shared unix admin socket
    (single-host compose).  k8s → mesh-mTLS admin relay (separate pods; unix
    sockets cannot span pods).  Both transports POST the same monolith
    Caddyfile to Caddy's ``/load`` and fail CLOSED on any error.
    """
    if _runtime() == "k8s":
        await _reload_via_admin_api()
    else:
        await _reload_via_admin_socket()


def _leaf_cert_fingerprint(cert_path: Any) -> str:
    """SHA-256 fingerprint of the minted per-instance leaf, ``sha256:<hex>``.

    v4.1 Phase 2a (LU-MCP-A2): the fingerprint rides the durable broker
    descriptor and ends up in the OPA input ``target.cert_fingerprint``.
    Raises on unreadable/unparsable cert — the caller treats that as a
    broker_registry step failure (fail-closed; a descriptor without the cert
    binding must not be registered silently).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    pem = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    return "sha256:%s" % cert.fingerprint(hashes.SHA256()).hex()


def _validate_manifest_or_raise(
    manifest_yaml: str, *, server_id: str, tenant_id: str,
) -> dict:
    """Step 1 — parse + lint + identity-consistency. Returns the parsed dict."""
    from yashigani.manifest.codegen import _is_shape_c
    from yashigani.manifest.linter import validate_manifest
    from yashigani.manifest.parser import ManifestParseError, parse_manifest

    try:
        parsed = parse_manifest(manifest_yaml)
    except ManifestParseError as exc:
        raise McpOnboardError(
            "manifest", f"manifest parse failed: {exc}", http_status=422,
        ) from exc

    result = validate_manifest(
        parsed, manifest_bytes=manifest_yaml.encode("utf-8"),
    )
    if not result.passed:
        codes = ", ".join(e.rule for e in result.errors[:8])
        raise McpOnboardError(
            "manifest", f"manifest lint failed: {codes}", http_status=422,
        )

    meta = parsed.get("metadata") or {}
    if not _is_shape_c(parsed):
        raise McpOnboardError(
            "manifest",
            "manifest is not a Shape-C MCP-server manifest "
            "(metadata.category must be 'mcp_server')",
            http_status=422,
        )
    # Identity consistency: the wrap route, the SVID paths, the envelope row
    # and /auth/verify-mcp all key on (tenant_id, server_id) — a manifest
    # naming a DIFFERENT identity would onboard a wrap that verify-mcp denies.
    if meta.get("name") != server_id:
        raise McpOnboardError(
            "manifest",
            "manifest metadata.name %r must equal server_id %r"
            % (meta.get("name"), server_id),
            http_status=422,
        )
    if meta.get("tenant_id") != tenant_id:
        raise McpOnboardError(
            "manifest",
            "manifest metadata.tenant_id %r must equal this install's tenant %r"
            % (meta.get("tenant_id"), tenant_id),
            http_status=422,
        )
    return parsed


async def run_approve_transaction(
    *,
    manifest_yaml: str,
    server_id: str,
    tenant_id: str,
    env: Any,                    # yashigani.mcp._envelope.ServerEnvelope
    topology: str,
    sidecar_scan_verdict: Optional[dict],
    operator_identity: str,
    envelope_service: Any,       # CapabilityEnvelopeService
    audit_writer: Any = None,
    caddy_reloader: Optional[Callable[[], Awaitable[None]]] = None,
    registry_store: Any = None,  # DurableMcpRegistryStore — v4.1 Ph2a / SEAM-1d-07
) -> McpOnboardResult:
    """Run the atomic approve transaction (see module docstring).

    ``registry_store`` (v4.1 Phase 2a — Iris SEAM-1d-07): the durable broker
    registry.  When supplied, step 4b writes the broker descriptor keyed on
    the canonical ``<tenant>:<server>`` so the gateway lazily registers the
    onboarded MCP WITHOUT a reboot.  When None:
      * production/staging → the transaction fails CLOSED up-front (503) —
        a wrap the broker can never dial is a partial onboarding.
      * dev/test           → step 4b is skipped with a warning
        (backwards-compatible with unit tests / pre-Phase-3 wiring).

    Raises McpOnboardError after rolling back on any step failure.  On
    success returns the committed identifiers + written artifact paths.
    """
    from yashigani.manifest.codegen import CodegenError, approve_mcp_onboard
    from yashigani.pki.binding import tool_surface_hash
    from yashigani.pki.issuer import IssuerPaths, mint_agent_leaf

    reloader = caddy_reloader or default_caddy_reloader
    rollback: list[Callable[[], None]] = []

    def _run_rollback() -> None:
        for undo in reversed(rollback):
            try:
                undo()
            except Exception as undo_exc:  # noqa: BLE001 — rollback is best-effort
                logger.error("mcp-onboard: rollback step failed: %s", undo_exc)

    def _audit_failure(step: str, exc: Exception, instance_id: str, spiffe_id: str) -> None:
        if audit_writer is None:
            return
        try:
            from yashigani.audit.schema import McpOnboardTransactionFailedEvent
            audit_writer.write(McpOnboardTransactionFailedEvent(
                approver_account=operator_identity,
                tenant_id=tenant_id,
                server_id=server_id,
                instance_id=instance_id,
                spiffe_id=spiffe_id,
                failed_step=step,
                error_type=type(exc).__name__,
            ))
        except Exception as audit_exc:  # noqa: BLE001 — audit never masks the abort
            logger.error(
                "mcp-onboard: MCP_ONBOARD_TRANSACTION_FAILED audit write failed: %s",
                audit_exc,
            )

    # Resolve config up-front (fail fast, nothing to roll back yet).
    output_root = _artifact_root()
    runtime = _runtime()

    # v4.1 Phase 2a (SEAM-1d-07) — the durable broker registry is REQUIRED in
    # production/staging: without it the wrap goes live but the gateway broker
    # can never dial it (boot-env-only registry).  Fail closed BEFORE minting.
    _env_name = os.environ.get("YASHIGANI_ENV", "").lower().strip()
    if registry_store is None and _env_name in {"production", "staging"}:
        raise McpOnboardError(
            "config",
            "durable broker-registry store is not wired (registry_store=None) "
            f"in a {_env_name} environment — the onboarded MCP would never be "
            "routable by the gateway broker (SEAM-1d-07). Onboarding fails "
            "closed. Wire Redis db/3 (DurableMcpRegistryStore) into the "
            "backoffice.",
            http_status=503,
        )

    # ── C1 (unified-sidecar must-fix #10): reconcile the codegen mesh-port
    # registry with PERSISTED state before codegen runs.  _SEEN_MESH_PORTS is
    # in-process only and cleared on backoffice restart; without this seed a
    # restart forgets every claimed port and this onboard can hash (or be
    # pinned) onto an occupied one — an opaque C10 validator failure
    # mid-transaction instead of the explicit MCP_mesh_port_collision abort.
    # Idempotent (same-pair re-claims are no-ops; re-approve stays safe).
    # Non-fatal on seed failure: the degradation is availability-shaped only —
    # a genuine collision still aborts fail-closed at codegen time.
    if registry_store is not None:
        try:
            from yashigani.manifest.codegen import seed_mesh_ports_from_descriptors
            _seeded = seed_mesh_ports_from_descriptors(registry_store.list_all())
            if _seeded:
                logger.info(
                    "mcp-onboard: seeded %d persisted mesh-port claim(s) into "
                    "the codegen registry (C1)", _seeded,
                )
        except Exception as exc:  # noqa: BLE001 — availability-only degradation
            logger.warning(
                "mcp-onboard: mesh-port seed from the durable registry failed "
                "(%s) — collision guard degraded to session-only; a real "
                "collision still aborts fail-closed at codegen (C10)", exc,
            )

    # ── Step 1: manifest ────────────────────────────────────────────────────
    parsed = _validate_manifest_or_raise(
        manifest_yaml, server_id=server_id, tenant_id=tenant_id,
    )
    image_digest = (
        ((parsed.get("spec") or {}).get("image") or {}).get("digest") or ""
    )

    # ── Step 2: mint the per-instance leaf (Nico's contract) ────────────────
    instance_id = f"nhi_{uuid.uuid4().hex[:12]}"
    spiffe_id = ""
    scope_hash = tool_surface_hash(sorted(env.tools.keys()))
    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
    manifest_path = os.getenv(
        "YASHIGANI_SERVICE_MANIFEST_PATH",
        "/etc/yashigani/service_identities.yaml",
    )
    pki_paths = IssuerPaths(
        secrets_dir=Path(secrets_dir),
        manifest_path=Path(manifest_path),
    )
    try:
        spiffe_id = mint_agent_leaf(
            pki_paths,
            tenant_id=tenant_id,
            agent_name=server_id,
            instance_id=instance_id,
            scope_hash=scope_hash,
            image_digest=image_digest,
            approved_by=operator_identity,
            audit_writer=audit_writer,
        )
    except Exception as exc:
        _audit_failure("mint_leaf", exc, instance_id, spiffe_id)
        logger.error(
            "mcp-onboard: mint_agent_leaf FAILED for %s/%s (%s) — aborted "
            "fail-closed, nothing onboarded: %s",
            tenant_id, server_id, instance_id, exc,
        )
        raise McpOnboardError(
            "mint_leaf",
            "PKI leaf issuance failed — onboarding aborted (fail-closed). "
            "svid_issued was NOT recorded.",
        ) from exc

    cert_path = pki_paths.agent_cert(tenant_id, server_id, instance_id)
    key_path = pki_paths.agent_key(tenant_id, server_id, instance_id)

    def _undo_mint() -> None:
        for p in (cert_path, key_path):
            try:
                Path(p).unlink(missing_ok=True)
            except OSError as unlink_exc:
                logger.error("mcp-onboard: rollback unlink %s failed: %s", p, unlink_exc)
        logger.warning(
            "mcp-onboard: rolled back minted leaf for %s (cert+key removed; "
            "runtime-manifest entry left inert)", spiffe_id,
        )

    rollback.append(_undo_mint)

    # ── Step 2b: svid-init directory population (Captain d2931113 / SEAM-1d-06) ─
    #
    # Captain's svid-sidecar reads INIT_DIR (bind: secrets/svid-init/<t>/<s>/)
    # expecting the basenames rotate.sh projects into the shared SVID volume:
    #   client.crt  — the per-instance leaf cert (minted above)
    #   client.key  — the corresponding private key
    #   ca.crt      — the intermediate CA cert (Caddy's trust anchor)
    # Without these files the sidecar has nothing to project and Caddy cannot
    # present a leaf at the wrap's mTLS listener — requests to /mcp/<server>
    # would fail with a TLS handshake error rather than an authz deny.
    #
    # Ordering invariant: step 2b runs BEFORE step 3 (codegen) and BEFORE step 4
    # (caddy reload).  The sidecar service is started by the compose
    # _gen_svid_sidecar_service stanza; it copies INIT_DIR → SVID_DIR during its
    # init phase.  Caddy mounts the SVID volume read-only, so the cert must be
    # in place before the caddy reload at step 4 loads the new snippet.
    _svid_init_dir = Path(secrets_dir) / "svid-init" / tenant_id / server_id
    try:
        _svid_init_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cert_path, _svid_init_dir / "client.crt")
        shutil.copy2(key_path, _svid_init_dir / "client.key")
        shutil.copy2(pki_paths.intermediate_cert, _svid_init_dir / "ca.crt")
        logger.info(
            "mcp-onboard: svid-init populated for %s/%s at %s",
            tenant_id, server_id, _svid_init_dir,
        )
    except Exception as exc:
        _run_rollback()
        _audit_failure("svid_init", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "svid_init",
            f"svid-init directory population failed — onboarding aborted and "
            "rolled back (fail-closed; Captain SEAM-1d-06): {exc}",
        ) from exc

    def _undo_svid_init() -> None:
        for _fname in ("client.crt", "client.key", "ca.crt"):
            try:
                (_svid_init_dir / _fname).unlink(missing_ok=True)
            except OSError as _unlink_exc:
                logger.error(
                    "mcp-onboard: rollback svid-init unlink %s failed: %s",
                    _fname, _unlink_exc,
                )
        logger.warning(
            "mcp-onboard: rolled back svid-init dir for %s/%s", tenant_id, server_id,
        )

    rollback.append(_undo_svid_init)

    # ── Step 3: codegen + artifact write (Captain's approve-hook) ───────────
    try:
        artifacts = approve_mcp_onboard(
            parsed, runtime, output_root=output_root, dry_run=False,
        )
    except CodegenError as exc:
        _run_rollback()
        _audit_failure("codegen", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "codegen",
            f"codegen security violation ({exc}) — onboarding aborted and "
            "rolled back (fail-closed).",
            http_status=422,
        ) from exc
    except Exception as exc:
        _run_rollback()
        _audit_failure("artifact_write", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "artifact_write",
            "artifact write failed — onboarding aborted and rolled back.",
        ) from exc

    artifact_paths = sorted(artifacts.keys())

    def _undo_artifacts() -> None:
        for rel in artifact_paths:
            try:
                (output_root / rel).unlink(missing_ok=True)
            except OSError as unlink_exc:
                logger.error(
                    "mcp-onboard: rollback unlink %s failed: %s", rel, unlink_exc,
                )
        logger.warning(
            "mcp-onboard: rolled back %d written artifacts under %s",
            len(artifact_paths), output_root,
        )

    rollback.append(_undo_artifacts)

    # ── Step 4: caddy reload (wrap goes live) ────────────────────────────────
    reload_applied = False
    try:
        await reloader()
        reload_applied = True
    except McpOnboardError as exc:
        _run_rollback()
        _audit_failure("caddy_reload", exc, instance_id, spiffe_id)
        raise
    except Exception as exc:
        _run_rollback()
        _audit_failure("caddy_reload", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "caddy_reload",
            "caddy reload failed — onboarding aborted and rolled back.",
        ) from exc

    # ── Step 4b: durable broker-registry registration (SEAM-1d-07) ──────────
    #
    # Register the broker descriptor keyed on the canonical <tenant>:<server>
    # (== envelope provenance_id == wrap route == verify-mcp key, iris §1).
    # The gateway McpBrokerRegistry lazily loads this on the first
    # /mcp/<server> lookup miss — no gateway reboot, no env edit.
    #
    # Runs BEFORE the envelope commit: a request racing this window is DENIED
    # by verify-mcp (no envelope yet → 403 server_not_onboarded, fail-closed —
    # the SEAM-1d-03 invariant).  Rolled back (key deleted) if step 5 fails.
    if registry_store is not None:
        try:
            from yashigani.manifest.codegen import _mcp_mesh_port
            _mesh_port = _mcp_mesh_port(parsed)
            _leaf_fp = _leaf_cert_fingerprint(cert_path)
            _meta_name = str((parsed.get("metadata") or {}).get("name", ""))
            descriptor = {
                "agent_name": server_id,
                # Base URL only — McpHttpTransport.forward() appends /mcp;
                # the wrap's handle_path strips the /mcp/<t>/<s> prefix
                # (FIX-UPSTREAM-URL-DOUBLE-MCP + codegen.py wrap contract).
                "upstream_url": "https://caddy:%d/mcp/%s/%s" % (
                    _mesh_port, tenant_id, server_id,
                ),
                "tenant_id": tenant_id,
                # Per registry.py contract: the second OPA tool-gates apply to
                # the filesystem / git bundles by metadata.name.
                "is_filesystem_agent": _meta_name in {"filesystem", "filesystem-mcp"},
                "is_git_agent": _meta_name in {"git", "git-mcp"},
                # v4.1 Phase 2a (LU-MCP-A2): per-instance leaf fingerprint —
                # threaded into the OPA input target.cert_fingerprint.
                "cert_fingerprint": _leaf_fp,
                "spiffe_id": spiffe_id,
                "svid_instance_id": instance_id,
                # v4.1 Phase 1 (Nico Q1 — cert/rotate): persist the pinned OCI
                # digest so the rotation endpoint can re-mint with the SAME
                # binding inputs (image_digest ‖ scope_hash).  "" when the
                # manifest pinned no digest — recorded honestly (binding.py).
                "image_digest": image_digest,
            }
            registry_store.put(tenant_id, server_id, descriptor)

            # ── Step 4b-ii: store OPA grant + baseline (Seam-3 / SEAM-1d-07) ──
            #
            # Write the per-instance OPA grant and capability-envelope baseline
            # into Redis so the gateway's startup push (and any subsequent
            # re-push on OPA reconnect) can rebuild data.yashigani.mcp without
            # querying the envelope DB.  Both writes use the same registry_store
            # client (Redis db/3) as the descriptor above.
            #
            # grant:    caller is always the gateway mesh identity (the only
            #           caller that reaches OPA via the broker transport path).
            #           tools = the envelope's declared tool surface.
            # baseline: surface_hash = scope_hash (sha384:...) — stored as-is;
            #           normalised to the same format the broker sends in the OPA
            #           input target.surface_hash at push time via list_all().
            from yashigani.identity.trust_domain import trust_domain as _trust_domain
            _gateway_spiffe = "spiffe://%s/gateway" % _trust_domain()
            _sorted_tools = sorted(env.tools.keys())
            registry_store.put_grant(tenant_id, server_id, {
                "tools": _sorted_tools,
                "actions": ["tools/call"],
                "caller_spiffe": _gateway_spiffe,
            })
            registry_store.put_baseline(tenant_id, server_id, {
                "surface_hash": scope_hash,   # sha384:<hex> — normalised at push time
                "tools": _sorted_tools,
            })
            logger.info(
                "mcp-onboard: stored OPA grant+baseline for %s/%s "
                "tools=%d surface=%s",
                tenant_id, server_id, len(_sorted_tools), scope_hash[:24],
            )
        except Exception as exc:
            _run_rollback()
            if reload_applied:
                try:
                    await reloader()
                except Exception as re_exc:  # noqa: BLE001 — best-effort restore
                    logger.error(
                        "mcp-onboard: post-rollback caddy re-reload failed: %s",
                        re_exc,
                    )
            _audit_failure("broker_registry", exc, instance_id, spiffe_id)
            raise McpOnboardError(
                "broker_registry",
                "durable broker-registry registration failed — onboarding "
                "aborted and rolled back (fail-closed; SEAM-1d-07).",
            ) from exc

        def _undo_registry() -> None:
            try:
                registry_store.delete(tenant_id, server_id)
            except Exception as del_exc:  # noqa: BLE001 — rollback best-effort
                logger.error(
                    "mcp-onboard: rollback broker-registry delete failed: %s",
                    del_exc,
                )
            registry_store.delete_grant(tenant_id, server_id)
            registry_store.delete_baseline(tenant_id, server_id)

        rollback.append(_undo_registry)
    else:
        logger.warning(
            "mcp-onboard: no durable broker-registry store wired "
            "(registry_store=None, env=%r) — the gateway broker will NOT "
            "route /mcp/%s until YASHIGANI_MCP_SERVERS is updated and the "
            "gateway recreated (SEAM-1d-07; dev/test only).",
            _env_name, server_id,
        )

    # ── Step 5: durable registry commit (envelope + svid flags) ─────────────
    try:
        envelope_id = await envelope_service.mint_envelope(
            env,
            server_id=server_id,
            operator_identity=operator_identity,
            topology=topology,
            sidecar_scan_verdict=sidecar_scan_verdict,
            svid_instance_id=instance_id,
            svid_spiffe_id=spiffe_id,
            svid_issued=True,   # the leaf minted in step 2 exists on disk
        )
    except Exception as exc:
        # Roll back files, then best-effort re-reload so Caddy drops the
        # now-removed wrap snippet (the old snippet file is gone; a reload
        # re-adapts without it).
        _run_rollback()
        if reload_applied:
            try:
                await reloader()
            except Exception as re_exc:  # noqa: BLE001 — best-effort restore
                logger.error(
                    "mcp-onboard: post-rollback caddy re-reload failed: %s", re_exc,
                )
        _audit_failure("envelope_mint", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "envelope_mint",
            "durable envelope INSERT failed — onboarding aborted and rolled "
            "back (fail-closed).",
        ) from exc

    logger.info(
        "mcp-onboard: COMMITTED server=%s tenant=%s envelope_id=%d "
        "instance=%s spiffe=%s artifacts=%d",
        server_id, tenant_id, envelope_id, instance_id, spiffe_id,
        len(artifact_paths),
    )
    return McpOnboardResult(
        envelope_id=envelope_id,
        instance_id=instance_id,
        spiffe_id=spiffe_id,
        artifact_paths=artifact_paths,
    )


__all__ = [
    "McpOnboardError",
    "McpOnboardResult",
    "default_caddy_reloader",
    "run_approve_transaction",
]
