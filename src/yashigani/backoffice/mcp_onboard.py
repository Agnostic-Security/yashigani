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
  4. caddy_reload    — FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21)
                       REWORK: register the route with caddy-config-broker
                       via narrow, typed DATA (tenant_id, server_id,
                       mesh_port, shim_port) — NEVER a raw Caddyfile body or
                       a raw admin ``/load`` call. The broker independently
                       re-validates every field, renders the MCP-front wrap
                       from its OWN fixed template (never backoffice-
                       supplied text), writes it into its OWN
                       dynamic-agents volume (never bind-mounted into this
                       container), and triggers the real Caddy reload
                       itself. See docker/caddy/config_broker.py module
                       docstring ("NEW CONTRACT") for the full R1+R2
                       threat-model rework this replaces (the prior
                       ``POST /load``-of-the-monolith design — Su
                       5443f11f — FAILED live under the real
                       no-new-privileges security context; see
                       laura-final-reattack.md). Registration is atomic and
                       zero-downtime on the Caddy side; a failed
                       registration leaves the old config running. Transport
                       branches on YASHIGANI_CONTAINER_RUNTIME
                       (SU-SEAM-1d-04 precedent, same branch shape):
                         docker / podman-*  — dedicated unix socket to
                                              caddy-config-broker
                                              (single-host compose; NEVER
                                              shared with caddy itself).
                         k8s                — Caddy's mesh-mTLS admin relay
                                              listener (:2019 site block)
                                              now proxies POST/DELETE
                                              /route to the caddy-config-
                                              broker SIDECAR co-located in
                                              the caddy pod (loopback TCP),
                                              not a raw /load to the local
                                              admin socket. backoffice
                                              authenticates with its mesh
                                              ServiceIdentity leaf; the
                                              relay requires
                                              require_and_verify + the
                                              backoffice SPIFFE URI. Unix
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

Deployment wiring (Phase-3 stack rebuild — Su/Captain; route-registration
rework — Captain, FINDING-V412-CADDYADMIN-002):
  * ``YASHIGANI_AGENTS_DIR`` (default ``/run/secrets-rw/agents``) — FINDING-
    V412-SVID-WRITE-PATH (Captain, 2026-07-21): writable mount, SEPARATE from
    ``YASHIGANI_SECRETS_DIR`` (/run/secrets, RO since RESTART-012), for
    dynamically-minted agent leaf cert/key + the runtime identity manifest
    (pki.issuer.IssuerPaths.agents_dir). Never contains CA trust material.
  * ``YASHIGANI_SVID_INIT_DIR`` (default ``/run/secrets-rw/svid-init``) —
    same finding: writable staging dir step 2b copies the freshly-minted
    leaf + ca.crt into (basenames the svid-sidecar's rotate.sh contract
    expects), read back by the per-instance svid-sidecar via its OWN RO
    bind of the SAME host directory (docker/secrets/svid-init/<t>/<s>/ —
    unchanged host path, see codegen._gen_svid_sidecar_service). Compose/
    podman ONLY — skipped on K8s (Secret+fsGroup delivery instead).
  * ``YASHIGANI_SVID_GID`` (default ``2003``, matches manifest/codegen.py
    ``_MCP_SVID_GID``) — FINDING-V412-SVID-INIT-KEY-PERM: GID step 2b
    chgrps the staged key copy to (0440) so the svid-sidecar (UID 1002)
    can read it. Requires backoffice's ``group_add: ["2003"]`` in
    docker-compose.yml.
  * ``YASHIGANI_MCP_ARTIFACT_ROOT`` — writable bind of the install's
    ``docker/``-rooted tree into the backoffice container for the NON-Caddy
    Shape-C artifacts only (compose override, helm values/netpol, OPA
    bundle, pki ownership fragment, contract test). The Caddy-front wrap is
    NOT among these — see step 4 above.
  * ``YASHIGANI_CADDY_BROKER_ROUTE_SOCKET`` (default
    ``/run/caddy-broker-route/route.sock``) — the dedicated unix socket to
    caddy-config-broker's POST/DELETE /route contract. Shared ONLY between
    backoffice and caddy-config-broker (never caddy). Compose runtimes only.
  * ``YASHIGANI_CADDY_ADMIN_URL`` (default
    ``https://yashigani-caddy-admin:2019``) — K8s runtime only: base URL of
    Caddy's mesh-mTLS admin relay listener (helm configmaps.yaml ``:2019``
    site block), which now proxies POST/DELETE /route to the
    caddy-config-broker sidecar co-located in the caddy pod. MUST be https
    on the mesh; the client is ``yashigani.pki.client.internal_httpx_client()``
    (the backoffice ServiceIdentity leaf + internal-CA trust) — there is NO
    identity-less fallback on this path (fail-closed).
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

# FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21) — compose default: the
# dedicated unix socket to caddy-config-broker's POST/DELETE /route contract.
# NEVER shared with caddy itself (only backoffice <-> caddy-config-broker).
_DEFAULT_BROKER_ROUTE_SOCKET = "/run/caddy-broker-route/route.sock"
# K8s only — Caddy's mesh-mTLS admin relay (helm configmaps.yaml :2019 site
# block), now proxying POST/DELETE /route to the caddy-config-broker sidecar
# co-located in the caddy pod. https is mandatory: the relay is
# require_and_verify + SPIFFE-gated. yashigani-caddy-admin is the DEDICATED
# ClusterIP Service (caddy.yaml) — the public yashigani-caddy Service is type
# LoadBalancer and must never carry the admin relay port. The caddy leaf
# carries the yashigani-caddy-admin DNS SAN (service_identities.yaml) so
# hostname verification passes.
_DEFAULT_BROKER_RELAY_URL = "https://yashigani-caddy-admin:2019"


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
    deploy_hint: dict = field(default_factory=dict)


@dataclass
class McpDecommissionResult:
    """Outcome of a decommission transaction (FINDING-V412-ONBOARDING-
    ROBUSTNESS #4). ``steps`` records the per-step outcome so a partial
    failure is fully visible to the caller — see run_decommission_transaction
    docstring for why decommission does not roll back on partial failure."""

    server_id: str
    tenant_id: str
    already_decommissioned: bool
    instance_id: str = ""
    spiffe_id: str = ""
    artifact_paths_removed: list[str] = field(default_factory=list)
    steps: dict[str, str] = field(default_factory=dict)
    container_teardown: dict[str, Any] = field(default_factory=dict)


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


def _route_payload(*, tenant_id: str, server_id: str, mesh_port: int, shim_port: int) -> bytes:
    import json  # noqa: PLC0415 — keep module import light
    return json.dumps({
        "tenant_id": tenant_id,
        "server_id": server_id,
        "mesh_port": mesh_port,
        "shim_port": shim_port,
    }).encode("utf-8")


async def _register_route_via_broker_socket(
    *, tenant_id: str, server_id: str, mesh_port: int, shim_port: int,
) -> None:
    """Compose runtimes (docker / podman-*) — dedicated unix socket to
    caddy-config-broker.

    FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21): POSTs narrow, typed
    route DATA — NEVER a raw Caddyfile body. caddy-config-broker
    independently re-validates every field, renders the wrap from its own
    fixed template, writes it into its own volume, and reloads the real
    Caddy admin socket itself. A non-2xx response or an unreachable socket
    raises — the transaction rolls back (fail-closed).
    """
    import httpx  # noqa: PLC0415 — keep module import light

    socket_path = os.getenv(
        "YASHIGANI_CADDY_BROKER_ROUTE_SOCKET", _DEFAULT_BROKER_ROUTE_SOCKET,
    )
    body = _route_payload(
        tenant_id=tenant_id, server_id=server_id,
        mesh_port=mesh_port, shim_port=shim_port,
    )

    transport = httpx.AsyncHTTPTransport(uds=socket_path)
    try:
        async with httpx.AsyncClient(transport=transport, timeout=15.0) as client:
            resp = await client.post(
                "http://localhost/route",
                content=body,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"caddy-config-broker route socket {socket_path!r} unreachable: "
            f"{exc} (Phase-3 wiring — share caddy_broker_route_sock with "
            "backoffice)",
        ) from exc
    if resp.status_code // 100 != 2:
        raise McpOnboardError(
            "caddy_reload",
            "caddy-config-broker /route rejected the request (HTTP %d): %.300s"
            % (resp.status_code, resp.text),
        )
    logger.info(
        "mcp-onboard: route registered OK (broker socket %s, tenant=%s server=%s)",
        socket_path, tenant_id, server_id,
    )


async def _unregister_route_via_broker_socket(
    *, tenant_id: str, server_id: str,
) -> None:
    """Rollback counterpart of _register_route_via_broker_socket() — best
    effort (logs, does not raise): rollback must never itself abort a
    rollback that is already in progress."""
    import httpx  # noqa: PLC0415 — keep module import light
    import json  # noqa: PLC0415

    socket_path = os.getenv(
        "YASHIGANI_CADDY_BROKER_ROUTE_SOCKET", _DEFAULT_BROKER_ROUTE_SOCKET,
    )
    body = json.dumps({"tenant_id": tenant_id, "server_id": server_id}).encode("utf-8")
    transport = httpx.AsyncHTTPTransport(uds=socket_path)
    try:
        async with httpx.AsyncClient(transport=transport, timeout=15.0) as client:
            resp = await client.request(
                "DELETE", "http://localhost/route",
                content=body, headers={"Content-Type": "application/json"},
            )
        if resp.status_code // 100 != 2:
            logger.error(
                "mcp-onboard: rollback route unregister rejected (HTTP %d): %.300s",
                resp.status_code, resp.text,
            )
    except Exception as exc:  # noqa: BLE001 — rollback is best-effort
        logger.error("mcp-onboard: rollback route unregister failed: %s", exc)


async def _register_route_via_broker_relay(
    *, tenant_id: str, server_id: str, mesh_port: int, shim_port: int,
) -> None:
    """K8s runtime — Caddy's mesh-mTLS admin relay listener (SU-SEAM-1d-04),
    which now proxies POST/DELETE /route to the caddy-config-broker sidecar
    co-located in the caddy pod (FINDING-V412-CADDYADMIN-002 rework —
    previously proxied a raw POST /load).

    On K8s, caddy and backoffice are separate pods: the unix socket cannot
    be shared (emptyDir is pod-local; same-node co-location / RWX PVC is not
    the architecture). Instead the helm Caddyfile exposes a ``:2019`` site
    block that:

      * terminates mesh mTLS with ``client_auth require_and_verify`` against
        the internal CA bundle (identity-less clients are refused at the
        TLS handshake — the raw admin API is NEVER on the pod network), and
      * admits ONLY POST/DELETE ``/route`` from the backoffice SPIFFE URI
        (CEL expression on the client-cert URI SAN), then proxies to the
        caddy-config-broker sidecar's loopback TCP listener.

    The client here is ``internal_httpx_client()`` — the backoffice
    ServiceIdentity leaf + internal-CA trust, the SAME factory every other
    internal mesh call uses (MCP-001 pattern). There is deliberately NO
    identity-less fallback: a config-mutation surface must fail CLOSED when
    the mesh identity is unavailable.
    """
    import httpx  # noqa: PLC0415 — keep module import light

    relay_url = os.getenv(
        "YASHIGANI_CADDY_ADMIN_URL", _DEFAULT_BROKER_RELAY_URL,
    ).strip().rstrip("/")
    if not relay_url.startswith("https://"):
        raise McpOnboardError(
            "caddy_reload",
            f"YASHIGANI_CADDY_ADMIN_URL={relay_url!r} must be https:// — the "
            "K8s admin relay is mesh-mTLS only (fail-closed).",
        )
    body = _route_payload(
        tenant_id=tenant_id, server_id=server_id,
        mesh_port=mesh_port, shim_port=shim_port,
    )

    try:
        from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415
        client = internal_httpx_client(timeout=15.0)
    except Exception as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"mesh ServiceIdentity unavailable for the caddy admin relay "
            f"({exc}) — the K8s route-registration path has no "
            "identity-less fallback (fail-closed; check "
            "YASHIGANI_SERVICE_NAME + /run/secrets PKI).",
        ) from exc

    try:
        async with client:
            resp = await client.post(
                f"{relay_url}/route",
                content=body,
                headers={"Content-Type": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"caddy admin relay {relay_url!r} unreachable: {exc} "
            "(check the helm :2019 relay listener + NetworkPolicy "
            "backoffice→caddy:2019)",
        ) from exc
    if resp.status_code // 100 != 2:
        raise McpOnboardError(
            "caddy_reload",
            "caddy admin relay /route rejected the request (HTTP %d): %.300s"
            % (resp.status_code, resp.text),
        )
    logger.info(
        "mcp-onboard: route registered OK (mesh admin relay %s, tenant=%s server=%s)",
        relay_url, tenant_id, server_id,
    )


async def _unregister_route_via_broker_relay(
    *, tenant_id: str, server_id: str,
) -> None:
    """Rollback counterpart of _register_route_via_broker_relay() — best
    effort (logs, does not raise)."""
    import httpx  # noqa: PLC0415 — keep module import light
    import json  # noqa: PLC0415

    relay_url = os.getenv(
        "YASHIGANI_CADDY_ADMIN_URL", _DEFAULT_BROKER_RELAY_URL,
    ).strip().rstrip("/")
    body = json.dumps({"tenant_id": tenant_id, "server_id": server_id}).encode("utf-8")
    try:
        from yashigani.pki.client import internal_httpx_client  # noqa: PLC0415
        client = internal_httpx_client(timeout=15.0)
        async with client:
            resp = await client.request(
                "DELETE", f"{relay_url}/route",
                content=body, headers={"Content-Type": "application/json"},
            )
        if resp.status_code // 100 != 2:
            logger.error(
                "mcp-onboard: rollback route unregister (relay) rejected "
                "(HTTP %d): %.300s", resp.status_code, resp.text,
            )
    except Exception as exc:  # noqa: BLE001 — rollback is best-effort
        logger.error("mcp-onboard: rollback route unregister (relay) failed: %s", exc)


async def register_mcp_route(
    *, tenant_id: str, server_id: str, mesh_port: int, shim_port: int,
) -> None:
    """Register the MCP-front route with caddy-config-broker — transport
    selected by YASHIGANI_CONTAINER_RUNTIME. docker / podman-rootful /
    podman-rootless -> dedicated unix socket (single-host compose). k8s ->
    mesh-mTLS admin relay (separate pods; unix sockets cannot span pods).
    Both transports send the SAME narrow typed-DATA contract — NEVER a raw
    Caddyfile body — and fail CLOSED on any error (FINDING-V412-CADDYADMIN-002)."""
    if _runtime() == "k8s":
        await _register_route_via_broker_relay(
            tenant_id=tenant_id, server_id=server_id,
            mesh_port=mesh_port, shim_port=shim_port,
        )
    else:
        await _register_route_via_broker_socket(
            tenant_id=tenant_id, server_id=server_id,
            mesh_port=mesh_port, shim_port=shim_port,
        )


async def unregister_mcp_route(*, tenant_id: str, server_id: str) -> None:
    """Rollback counterpart of register_mcp_route() — best effort."""
    if _runtime() == "k8s":
        await _unregister_route_via_broker_relay(tenant_id=tenant_id, server_id=server_id)
    else:
        await _unregister_route_via_broker_socket(tenant_id=tenant_id, server_id=server_id)


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


def _agent_container_deploy_hint(
    *, tenant_id: str, server_id: str, runtime: str,
) -> dict:
    """Deterministic, component-isolated compose/helm command guidance for
    deploying the newly-approved agent's CONTAINER (FINDING-V412-ONBOARDING-
    ROBUSTNESS #5, Tom, 2026-07-21 — "is onboard-without-deploy by design or
    a gap?").

    DETERMINATION (see the finding writeup for the full analysis): the
    separation between "register the capability envelope + broker route"
    (this transaction — an app-tier action) and "start the container" (a
    host-tier action) IS deliberate — backoffice has no docker/podman socket
    access (LAURA-30-001 / YSG-RISK-080, the SAME boundary
    ``_agent_container_teardown_hint`` documents for decommission). That
    separation is not the gap.

    The GAP is the absence of any discoverable, actionable guidance for the
    operator once ``POST /import`` returns. The pre-existing
    ``install.sh --onboard <manifest>`` CLI is NOT that guidance: it is a
    wholly separate, non-interoperating onboarding mechanism (its own
    boot-env-only ``YASHIGANI_MCP_SERVERS`` registry, no capability-envelope
    row, no caddy-config-broker route registration — it manipulates a Caddy
    include line directly, pre-dating FINDING-V412-CADDYADMIN-002's broker
    rework) — pointing an API-onboarded operator at it would either do
    nothing useful or double-register the agent under two different
    registries. Nor does ``install.sh --onboard`` itself deploy the new
    agent's own container (it only recreates ``gateway`` — verified by
    inspection; no ``compose up`` for the new service exists anywhere in
    ``handle_onboard_subcommand``). This function closes the documentation
    gap the same way ``_agent_container_teardown_hint`` closes it for
    decommission: return the exact scoped command, never execute it.

    FINDING-V412-ONBOARDING-ROBUSTNESS N5 (Su, 2026-07-21) — blast-radius fix:
    the command this function returned previously was bare ``up -d`` (no
    service name), which the note claimed was "scoped to server_id ... only
    via the -f override file". That claim was FALSE for the vendored
    podman-compose fork (``vendor/podman-compose-ysg/podman_compose.py``):
    the fork computes ONE project-wide compose-config hash
    (``compose.yaml_hash``), not a per-service hash. Merging in the override
    file changes that global hash, so on the NEXT ``up -d`` every existing
    container's ``io.podman.compose.config-hash`` label mismatches the new
    global hash and the fork tears down + recreates the WHOLE STACK — proven
    live by Ava (demo-mcp re-onboarding) and reproduced with an isolated
    2-service compose fixture during this fix (an untouched ``db`` service's
    container ID changed on a bare ``up -d`` after an unrelated override
    merge; the same fixture with an explicit service list left it
    untouched). The fork DOES support scoped ``up -d <service...>`` — both
    create/start AND the hash-mismatch teardown branch respect
    ``args.services`` (``get_excluded()`` in the fork, used by both
    ``compose_up`` and ``compose_down``) — the CALL SITE simply never
    supplied it, so scoping degraded to "all services".

    Fix: name the exact services this override touches. The Shape-C compose
    override (``_gen_compose_override_shape_c`` in codegen.py) always
    defines exactly three services: the agent itself (``server_id``), its
    svid-sidecar (``"%s-svid-sidecar" % server_id``, SEAM-1d-06), and a
    PATCH onto the existing ``caddy:`` service (adds the new ringfence
    bridge network + SVID volume mount — caddy legitimately bounces briefly
    to pick these up). No other service (postgres/redis/backoffice/gateway/
    any OTHER onboarded agent) is ever named in the override, so naming
    these three explicitly on the command line makes the fork's own
    scoping correct instead of accidentally-disabled.
    """
    compose_override = "docker/%s-compose.override.yml" % server_id
    if runtime == "k8s":
        return {
            "runtime": "k8s",
            "commands": [
                "helm upgrade --install %s-mcp yashigani/yashigani-mcp-agent "
                "-n yashigani -f helm/yashigani/values-%s.yaml" % (server_id, server_id),
            ],
            "note": (
                "backoffice has no cluster-admin credentials by design "
                "(LAURA-30-001 analogue) — run this from an operator "
                "kubeconfig context, scoped to the yashigani namespace only."
            ),
        }
    svid_sidecar = "%s-svid-sidecar" % server_id
    # N5: name the services explicitly — see the docstring above. `caddy` IS
    # named (it reconnects to the new ringfence bridge + SVID volume and
    # WILL restart briefly) but nothing else in the base stack is.
    deploy_services = "%s %s caddy" % (server_id, svid_sidecar)
    return {
        "runtime": runtime,
        "commands": [
            "docker compose -f docker/docker-compose.yml -f %s up -d %s"
            % (compose_override, deploy_services),
        ],
        "note": (
            "backoffice has no docker/podman socket access by design "
            "(LAURA-30-001 / YSG-RISK-080) — this envelope/route registration "
            "does NOT start the container. Run this from the host/operator "
            "shell. SCOPED explicitly to the 3 services this override "
            "touches: %r (the agent), %r (its svid-sidecar), and caddy "
            "(reconnected to the new ringfence bridge + SVID volume — it "
            "WILL restart briefly). No OTHER service is named, so "
            "postgres/redis/backoffice/gateway/other onboarded agents are "
            "never recreated (FINDING-V412-ONBOARDING-ROBUSTNESS N5 — naming "
            "no service here previously let the compose engine's own "
            "project-wide config-hash mismatch recreate the WHOLE stack on "
            "every add-agent deploy). This is NOT the same mechanism as "
            "`install.sh --onboard` (that CLI uses a separate, "
            "non-interoperating registry — do not mix the two for the same "
            "server_id)."
        ) % (server_id, svid_sidecar),
    }


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
    import functools

    from yashigani.manifest.codegen import (
        CodegenError,
        _mcp_mesh_port,
        _mcp_shim_port,
        approve_mcp_onboard,
        is_artifact_relevant_for_runtime,
    )
    from yashigani.pki.binding import tool_surface_hash
    from yashigani.pki.issuer import IssuerPaths, mint_agent_leaf

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

    # FINDING-V412-CADDYADMIN-002 (Captain, 2026-07-21): resolve the
    # route-registration ("reloader") + rollback ("route_unregisterer")
    # callables now that `parsed` is available. Production default sends
    # narrow typed DATA to caddy-config-broker (register_mcp_route /
    # unregister_mcp_route — see module docstring); the injectable
    # `caddy_reloader` test seam is reused for BOTH forward and rollback
    # calls (unchanged contract — existing tests assert the injected stub is
    # called twice on a later-step failure: once to apply, once to restore).
    # _mcp_mesh_port() is idempotent for a repeat (tenant_id, server_id) pair
    # in the same codegen session (CodegenEngineShapeC.render(), step 3
    # below, already resolves+claims it once) — calling it again here
    # returns the SAME port, never a second claim.
    if caddy_reloader is not None:
        reloader: Callable[[], Awaitable[None]] = caddy_reloader
        route_unregisterer: Callable[[], Awaitable[None]] = caddy_reloader
    else:
        reloader = functools.partial(
            register_mcp_route,
            tenant_id=tenant_id, server_id=server_id,
            mesh_port=_mcp_mesh_port(parsed), shim_port=_mcp_shim_port(parsed),
        )
        route_unregisterer = functools.partial(
            unregister_mcp_route, tenant_id=tenant_id, server_id=server_id,
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
    # FINDING-V412-SVID-WRITE-PATH (Captain, 2026-07-21): RESTART-012 made
    # secrets_dir (/run/secrets) pure :ro on backoffice (CA root/intermediate
    # + attestation pin must never be writable from this process). The ONE
    # legitimate write backoffice makes through IssuerPaths — the dynamically
    # minted agent leaf cert/key + the runtime identity manifest — now goes
    # to a SEPARATE writable mount instead (default /run/secrets-rw/agents,
    # backed by a NEW host dir with no path-prefix overlap with ca_root.crt /
    # ca_intermediate.* / ca_root.attested_sha256). secrets_dir itself is
    # unchanged here — CA reads (intermediate_cert/intermediate_key below)
    # still resolve under the RO mount, exactly as before.
    agents_dir = os.getenv("YASHIGANI_AGENTS_DIR", "/run/secrets-rw/agents")
    pki_paths = IssuerPaths(
        secrets_dir=Path(secrets_dir),
        manifest_path=Path(manifest_path),
        agents_dir=Path(agents_dir),
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
    #
    # FINDING-V412-SVID-WRITE-PATH: this directory used to live under
    # secrets_dir (/run/secrets — now :ro since RESTART-012) and broke the
    # same way mint_agent_leaf did. It now lives under a dedicated writable
    # mount (default /run/secrets-rw/svid-init). The HOST-side bind SOURCE
    # is UNCHANGED — still docker/secrets/svid-init/<tenant>/<server> — so
    # codegen._gen_svid_sidecar_service's `init_dir_host` literal
    # ("secrets/svid-init/%s/%s") needs no change; only the container-side
    # path backoffice writes through changes.
    #
    # K8s GATE (Captain, 2026-07-21): this whole step is the filesystem
    # hand-off to the compose/podman svid-sidecar CONTAINER, which does not
    # exist on K8s at all — K8s SVID delivery is a Kubernetes Secret +
    # fsGroup (see helm/yashigani/templates/caddy.yaml SEAM-1d-04 comment).
    # Before FINDING-V412-SVID-INIT-KEY-PERM this step silently no-op'd on
    # K8s (wrote a file nobody read, no error). The chgrp-to-2003 fix below
    # would turn that into a HARD FAILURE on K8s (backoffice's pod has no
    # supplementalGroup 2003 there — same comment). Skip entirely off
    # docker/podman so this step stays a true no-op on K8s, matching prior
    # (harmless) behaviour rather than regressing K8s onboarding.
    svid_init_root = os.getenv("YASHIGANI_SVID_INIT_DIR", "/run/secrets-rw/svid-init")
    _svid_init_dir = Path(svid_init_root) / tenant_id / server_id
    _svid_init_applies = runtime in ("docker", "podman-rootful", "podman-rootless")
    try:
        if _svid_init_applies:
            _svid_init_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cert_path, _svid_init_dir / "client.crt")
            shutil.copy2(key_path, _svid_init_dir / "client.key")
            shutil.copy2(pki_paths.intermediate_cert, _svid_init_dir / "ca.crt")
            # FINDING-V412-SVID-INIT-KEY-PERM (Captain, 2026-07-21):
            # shutil.copy2 preserves the SOURCE mode — key_path was written
            # by mint_agent_leaf at _FILE_MODE_KEY (0o400, owner=backoffice
            # UID 1001 only). The svid-sidecar reads INIT_DIR as UID 1002
            # (docker/svid-sidecar/rotate.sh `cp "${INIT_DIR}/client.key"
            # ...`) — 0400 owner-only denies it (EACCES), so onboarding
            # would mint successfully but the sidecar's init phase would die
            # and Caddy would never get a leaf to present. Fix: mirror
            # rotate.sh's OWN least-privilege pattern for this exact key
            # (0440 + group _MCP_SVID_GID=2003, the group already shared
            # between the svid-sidecar and Caddy — see manifest/codegen.py
            # _MCP_SVID_GID) instead of the blunter world-readable 0444.
            # Requires backoffice to carry supplementary group 2003
            # (docker-compose.yml backoffice group_add: ["2003"]).
            _svid_key_dest = _svid_init_dir / "client.key"
            os.chmod(_svid_key_dest, 0o440)
            try:
                _svid_gid = int(os.getenv("YASHIGANI_SVID_GID", "2003"))
                os.chown(_svid_key_dest, -1, _svid_gid)
            except (PermissionError, OSError, KeyError) as _chown_exc:
                # Fail-closed rather than silently leaving a key the sidecar
                # cannot read: without supplementary group 2003, backoffice
                # cannot chgrp to a group it does not belong to (Linux DAC —
                # not CAP_CHOWN-eligible for a foreign group). Surfaced
                # loudly; the onboarding transaction still aborts+rolls
                # back below.
                raise RuntimeError(
                    "svid-init key chown to GID %s failed (%s) — backoffice "
                    "is missing supplementary group %s (docker-compose.yml "
                    "backoffice group_add). The svid-sidecar (UID 1002) "
                    "would not be able to read this key."
                    % (_svid_gid, _chown_exc, _svid_gid)
                ) from _chown_exc
            logger.info(
                "mcp-onboard: svid-init populated for %s/%s at %s (key 0440:%s)",
                tenant_id, server_id, _svid_init_dir,
                os.getenv("YASHIGANI_SVID_GID", "2003"),
            )
        else:
            logger.info(
                "mcp-onboard: svid-init staging skipped for %s/%s — runtime "
                "%r has no svid-sidecar container (K8s SVID delivery is "
                "Secret+fsGroup based).", tenant_id, server_id, runtime,
            )
    except Exception as exc:
        _run_rollback()
        _audit_failure("svid_init", exc, instance_id, spiffe_id)
        raise McpOnboardError(
            "svid_init",
            "svid-init directory population failed — onboarding aborted and "
            f"rolled back (fail-closed; Captain SEAM-1d-06): {exc}",
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

    # v4.1.2 fix (RESTART-013 MCP leg, Gap B): approve_mcp_onboard() returns
    # the FULL rendered artifact map (unchanged contract, every runtime), but
    # render()'s disk-write step now only PERSISTS the subset relevant to
    # `runtime` (codegen.is_artifact_relevant_for_runtime — the
    # artifact_write 502 root-cause fix). artifact_paths must reflect what is
    # actually on disk — both for the rollback below (unlinking a key that
    # was never written is harmless but wrong bookkeeping) and for the
    # response's "svid_issued=True is backed by the cert on disk" evidentiary
    # principle: report only what is actually there.
    artifact_paths = sorted(
        rel for rel in artifacts if is_artifact_relevant_for_runtime(rel, runtime)
    )

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

            # ── Step 4b-iii: (caller, prefix) egress grant (v4.1 Phase 1 /
            #                 Lu M1 — synthesis must-fix #1) ────────────────
            #
            # POSITIVE-grant, closed-world: the ONLY prefixes this instance
            # may egress through /egress/eval are the ones declared in the
            # manifest's spec.egress.needs[].prefix — keyed on the EXACT
            # per-instance SPIFFE minted in step 2 (byte-match at decision
            # time; never name-collapsed).  An empty declaration writes an
            # explicit empty grant (instance granted NO egress) — closed
            # world either way.  Written inside this step-up-gated
            # transaction (StepUpAdminSession on POST /import) and audited
            # via MCP_EGRESS_GRANT_WRITTEN.  Revocation = grant absence in
            # the pushed OPA data (the kill switch — Nico Q3); rollback
            # deletes the record.
            _egress_needs = (
                (parsed.get("spec") or {}).get("egress") or {}
            ).get("needs") or []
            _egress_prefixes = sorted({
                str(n.get("prefix")).strip()
                for n in _egress_needs
                if isinstance(n, dict) and str(n.get("prefix") or "").strip()
            })
            registry_store.put_egress_grant(tenant_id, server_id, {
                "spiffe": spiffe_id,
                "tenant": tenant_id,
                "prefixes": _egress_prefixes,
            })
            if audit_writer is not None:
                try:
                    from yashigani.audit.schema import McpEgressGrantWrittenEvent  # noqa: PLC0415
                    audit_writer.write(McpEgressGrantWrittenEvent(
                        approver_account=operator_identity,
                        tenant_id=tenant_id,
                        server_id=server_id,
                        instance_id=instance_id,
                        spiffe_id=spiffe_id,
                        prefixes=list(_egress_prefixes),
                    ))
                except Exception as audit_exc:  # noqa: BLE001 — audit never masks the tx
                    logger.error(
                        "mcp-onboard: MCP_EGRESS_GRANT_WRITTEN audit write "
                        "failed: %s", audit_exc,
                    )

            logger.info(
                "mcp-onboard: stored OPA grant+baseline+egress-grant for %s/%s "
                "tools=%d surface=%s egress_prefixes=%s",
                tenant_id, server_id, len(_sorted_tools), scope_hash[:24],
                _egress_prefixes,
            )
        except Exception as exc:
            _run_rollback()
            if reload_applied:
                try:
                    await route_unregisterer()
                except Exception as re_exc:  # noqa: BLE001 — best-effort restore
                    logger.error(
                        "mcp-onboard: post-rollback route unregister failed: %s",
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
            # v4.1 Phase 1 (Lu M1): a rolled-back onboarding must leave NO
            # egress grant behind (grant-absence is the kill switch).
            registry_store.delete_egress_grant(tenant_id, server_id)

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
        # Roll back files, then best-effort unregister so Caddy drops the
        # now-invalid wrap route (FINDING-V412-CADDYADMIN-002: the broker
        # owns the route file — unregister asks IT to remove + reload, not
        # a re-POST of a local artifact that no longer exists here).
        _run_rollback()
        if reload_applied:
            try:
                await route_unregisterer()
            except Exception as re_exc:  # noqa: BLE001 — best-effort restore
                logger.error(
                    "mcp-onboard: post-rollback route unregister failed: %s", re_exc,
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

    # ── Post-commit: push egress grants to OPA (v4.1 Phase 1 / Lu M1) ───────
    # Sub-path PUT of the FULL egress_grants document — the new grant goes
    # live without a gateway restart; the same re-push mechanism is the
    # revocation path (grant absence in the document = kill switch, Nico Q3).
    # Best-effort AFTER the commit point: a failed push never unwinds a
    # committed onboarding — the instance simply DENIES egress (fail-closed)
    # until the gateway startup push (or a later approve) re-pushes.
    if registry_store is not None:
        try:
            from yashigani.mcp._egress_grants import build_egress_grants_doc  # noqa: PLC0415
            from yashigani.mcp._opa_push import push_egress_grants  # noqa: PLC0415
            _opa_url = os.environ.get(
                "YASHIGANI_OPA_URL", "https://policy:8181",
            ).strip() or "https://policy:8181"
            push_egress_grants(_opa_url, build_egress_grants_doc(registry_store))
        except Exception as push_exc:  # noqa: BLE001 — committed tx; deny-until-pushed
            logger.error(
                "mcp-onboard: egress-grant OPA push failed after commit (%s) — "
                "server=%s will DENY egress (caller_not_granted_prefix, "
                "fail-closed) until the gateway startup push or the next "
                "approve re-pushes data.yashigani.mcp.egress_grants",
                push_exc, server_id,
            )

    return McpOnboardResult(
        envelope_id=envelope_id,
        instance_id=instance_id,
        spiffe_id=spiffe_id,
        artifact_paths=artifact_paths,
        deploy_hint=_agent_container_deploy_hint(
            tenant_id=tenant_id, server_id=server_id, runtime=runtime,
        ),
    )


# ---------------------------------------------------------------------------
# Decommission — the mirror-image of run_approve_transaction()
# FINDING-V412-ONBOARDING-ROBUSTNESS #4 (Tom, 2026-07-21)
# ---------------------------------------------------------------------------

def _agent_container_teardown_hint(
    *, tenant_id: str, server_id: str, runtime: str, mode: str,
) -> dict:
    """Deterministic, component-isolated compose/helm command guidance for
    the container+volume layer.

    Backoffice deliberately has NO docker/podman socket access
    (LAURA-30-001 / YSG-RISK-080 — the container-API surface was a proven
    privilege-escalation vector; see docker-compose.yml's backoffice service
    comment). This function therefore never executes anything — it returns
    command GUIDANCE (the operator's real invocation combines this override
    with the install's base docker-compose.yml, exactly as install.sh's own
    ``COMPOSE_CMD`` array does) scoped ONLY to (tenant_id, server_id) via the
    override filename / network name / helm release name, so it can never
    accidentally target another agent or a core service.

    mode="keep": stop the container, keep its volumes (re-onboardable later
                 without losing state).
    mode="nuke": remove container + the agent's dedicated ringfence network +
                 named volumes (full teardown; matches uninstall.sh's own
                 --remove-volumes convention for the same keep-vs-nuke split).
    """
    compose_override = "docker/%s-compose.override.yml" % server_id
    network = "ringfence_%s" % server_id
    if runtime == "k8s":
        return {
            "runtime": "k8s",
            "mode": mode,
            "commands": [
                "helm uninstall %s-mcp -n yashigani" % server_id
                if mode == "nuke" else
                "kubectl scale deployment/%s-mcp -n yashigani --replicas=0" % server_id,
            ],
            "note": (
                "backoffice has no cluster-admin credentials by design "
                "(LAURA-30-001 analogue) — run this from an operator "
                "kubeconfig context, scoped to the yashigani namespace only."
            ),
        }
    down_cmd = "docker compose -f %s down" % compose_override
    if mode == "nuke":
        down_cmd += " --volumes --rmi local"
    return {
        "runtime": runtime,
        "mode": mode,
        "commands": [
            down_cmd,
            "docker network rm %s" % network if mode == "nuke" else
            "# network %s left in place (mode=keep)" % network,
        ],
        "note": (
            "backoffice has no docker/podman socket access by design "
            "(LAURA-30-001 / YSG-RISK-080) — run this from the host/operator "
            "shell (or install.sh's remove-agent op), scoped to server_id=%r "
            "only via the -f override file and network name; no other "
            "agent or core service is named in these commands."
        ) % server_id,
    }


async def run_decommission_transaction(
    *,
    tenant_id: str,
    server_id: str,
    operator_identity: str,
    envelope_service: Any,       # CapabilityEnvelopeService
    audit_writer: Any = None,
    registry_store: Any = None,  # DurableMcpRegistryStore — same store onboarding uses
    container_teardown_mode: str = "keep",  # "keep" | "nuke" — informational only
) -> McpDecommissionResult:
    """Cleanly reverse a ring_fenced MCP agent's onboarding — component-
    isolated (only this (tenant_id, server_id) pair's resources are ever
    touched) and idempotent (safe to call repeatedly, including on a
    server_id that was never onboarded).

    Steps, in DENY-FIRST order (the opposite ordering rule from
    run_approve_transaction's GRANT-LAST commit point — see that function's
    module docstring "INVARIANT (Iris SEAM-1d-03)"): the goal there was
    "never grant before everything is ready"; the goal here is "never leave
    a live access path open a moment longer than necessary while cleanup
    proceeds":

      1. envelope_decommission — transition the ACTIVE envelope (if any) to
         'decommissioned' FIRST. The instant this commits, /auth/verify-mcp
         (get_active_envelope() -> None -> 403 server_not_onboarded) denies
         every subsequent call, and GET /admin/mcp/servers/ stops listing
         the server. This is the SECURITY-CRITICAL step.
      2. registry — delete the durable broker descriptor + OPA grant +
         baseline + egress grant (Redis db/3), then re-push the egress-
         grants document so revocation (grant absence = kill switch, Nico
         Q3) is live immediately, not just on the next gateway restart.
      3. route — DELETE the broker route (unregister_mcp_route): Caddy
         drops the per-instance :mesh_port wrap and reloads. Best-effort:
         even if this fails, step 1 already denies every request at the
         application layer.
      4. svid — remove the per-instance leaf cert/key from
         YASHIGANI_AGENTS_DIR and the svid-init staging files, using the
         instance_id recorded on the envelope row (migration 0026 columns) —
         no manifest is needed at decommission time.
      5. artifacts — unlink the runtime-relevant codegen artifacts (compose
         override / helm values — the SAME deterministic filenames
         approve_mcp_onboard() writes, predictable from server_id alone).

    UNLIKE the approve transaction, a failure partway through does NOT roll
    back the steps already completed: every step here only TIGHTENS the
    deny posture (removes a grant/route/cert), so a partial reversal is
    strictly SAFER than the pre-decommission state, never worse. Each step's
    outcome is recorded in the returned ``steps`` dict; the caller (the
    DELETE /admin/mcp/servers/{server_id} route) surfaces the full picture
    rather than an opaque single failure — the whole transaction is safe to
    retry (every step is independently idempotent).

    Container/volume teardown is INTENTIONALLY NOT performed here —
    backoffice has no docker/podman socket (LAURA-30-001 / YSG-RISK-080).
    ``container_teardown_mode`` only selects which scoped command guidance
    ``_agent_container_teardown_hint()`` returns for the operator to run.
    """
    from yashigani.manifest.codegen import is_artifact_relevant_for_runtime
    from yashigani.pki.issuer import IssuerPaths

    provenance_id = "%s:%s" % (tenant_id, server_id)
    runtime = _runtime()
    steps: dict[str, str] = {}
    instance_id = ""
    spiffe_id = ""

    def _audit_failure(step: str, exc: Exception) -> None:
        if audit_writer is None:
            return
        try:
            from yashigani.audit.schema import McpDecommissionTransactionFailedEvent
            audit_writer.write(McpDecommissionTransactionFailedEvent(
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
                "mcp-decommission: MCP_DECOMMISSION_TRANSACTION_FAILED audit "
                "write failed: %s", audit_exc,
            )

    # ── Step 1: envelope_decommission (SECURITY-CRITICAL, deny-first) ───────
    try:
        record = await envelope_service.get_active_envelope(provenance_id)
        if record is not None:
            instance_id = record.svid_instance_id or ""
            spiffe_id = record.svid_spiffe_id or ""
            decommissioned = await envelope_service.decommission_envelope(provenance_id)
            steps["envelope"] = "decommissioned" if decommissioned else "already_inactive"
        else:
            steps["envelope"] = "already_inactive"
    except Exception as exc:
        _audit_failure("envelope_decommission", exc)
        logger.error(
            "mcp-decommission: envelope_decommission FAILED for %s (%s) — "
            "aborting decommission (fail-closed: could not confirm the "
            "server is no longer active, so no further reversal is safe to "
            "attempt)", provenance_id, exc,
        )
        raise McpOnboardError(
            "envelope_decommission",
            "capability-envelope deactivation failed — decommission "
            "aborted. The server may still be onboarded; retry.",
        ) from exc

    already_decommissioned = steps["envelope"] == "already_inactive" and not instance_id

    # ── Step 2: registry (durable broker descriptor + OPA grant/baseline/egress) ─
    if registry_store is not None:
        try:
            registry_store.delete(tenant_id, server_id)
            registry_store.delete_grant(tenant_id, server_id)
            registry_store.delete_baseline(tenant_id, server_id)
            registry_store.delete_egress_grant(tenant_id, server_id)
            steps["registry"] = "removed"
        except Exception as exc:  # noqa: BLE001 — best-effort, does not abort
            _audit_failure("registry", exc)
            steps["registry"] = "error: %s" % type(exc).__name__
            logger.error(
                "mcp-decommission: registry cleanup failed for %s (%s) — "
                "continuing (envelope already decommissioned; this is a "
                "residual-cleanup failure, not an access-control failure)",
                provenance_id, exc,
            )
        else:
            try:
                from yashigani.mcp._egress_grants import build_egress_grants_doc  # noqa: PLC0415
                from yashigani.mcp._opa_push import push_egress_grants  # noqa: PLC0415
                _opa_url = os.environ.get(
                    "YASHIGANI_OPA_URL", "https://policy:8181",
                ).strip() or "https://policy:8181"
                push_egress_grants(_opa_url, build_egress_grants_doc(registry_store))
            except Exception as push_exc:  # noqa: BLE001 — revocation-by-absence still holds
                logger.error(
                    "mcp-decommission: post-decommission egress-grant OPA "
                    "push failed (%s) — revocation is still recorded (grant "
                    "absence = kill switch); the next gateway startup push "
                    "or approve re-pushes data.yashigani.mcp.egress_grants",
                    push_exc,
                )
    else:
        steps["registry"] = "skipped_no_store"

    # ── Step 3: route (broker DELETE /route) ─────────────────────────────────
    try:
        await unregister_mcp_route(tenant_id=tenant_id, server_id=server_id)
        steps["route"] = "removed"
    except Exception as exc:  # noqa: BLE001 — best-effort, does not abort
        _audit_failure("route_unregister", exc)
        steps["route"] = "error: %s" % type(exc).__name__
        logger.error(
            "mcp-decommission: broker route unregister failed for %s (%s) — "
            "continuing (envelope already decommissioned so /auth/verify-mcp "
            "denies regardless; Caddy may still 404/serve a stale wrap until "
            "this is retried)", provenance_id, exc,
        )

    # ── Step 4: svid (per-instance leaf + svid-init staging) ────────────────
    if instance_id:
        try:
            secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
            manifest_path = os.getenv(
                "YASHIGANI_SERVICE_MANIFEST_PATH",
                "/etc/yashigani/service_identities.yaml",
            )
            agents_dir = os.getenv("YASHIGANI_AGENTS_DIR", "/run/secrets-rw/agents")
            pki_paths = IssuerPaths(
                secrets_dir=Path(secrets_dir),
                manifest_path=Path(manifest_path),
                agents_dir=Path(agents_dir),
            )
            cert_path = pki_paths.agent_cert(tenant_id, server_id, instance_id)
            key_path = pki_paths.agent_key(tenant_id, server_id, instance_id)
            for p in (cert_path, key_path):
                Path(p).unlink(missing_ok=True)

            if runtime in ("docker", "podman-rootful", "podman-rootless"):
                svid_init_root = os.getenv(
                    "YASHIGANI_SVID_INIT_DIR", "/run/secrets-rw/svid-init",
                )
                svid_init_dir = Path(svid_init_root) / tenant_id / server_id
                for fname in ("client.crt", "client.key", "ca.crt"):
                    (svid_init_dir / fname).unlink(missing_ok=True)
            steps["svid"] = "removed"
        except Exception as exc:  # noqa: BLE001 — best-effort, does not abort
            _audit_failure("svid_revoke", exc)
            steps["svid"] = "error: %s" % type(exc).__name__
            logger.error(
                "mcp-decommission: svid leaf removal failed for %s/%s "
                "instance=%s (%s) — continuing (envelope already "
                "decommissioned so the leaf is now orphaned/inert even if "
                "the file removal itself failed)",
                tenant_id, server_id, instance_id, exc,
            )
    else:
        steps["svid"] = "skipped_no_instance" if already_decommissioned else "skipped_no_svid_on_record"

    # ── Step 5: artifacts (compose override / helm values — deterministic) ──
    artifact_paths_removed: list[str] = []
    try:
        output_root = _artifact_root()
        candidates = [
            "docker/%s-compose.override.yml" % server_id,
            "helm/yashigani/values-%s.yaml" % server_id,
            "helm/yashigani/values-%s-networkpolicy.yaml" % server_id,
            "helm/yashigani/templates/agents/%s-policy-exception.yaml" % server_id,
        ]
        for rel in candidates:
            if not is_artifact_relevant_for_runtime(rel, runtime):
                continue
            p = output_root / rel
            if p.exists():
                p.unlink(missing_ok=True)
                artifact_paths_removed.append(rel)
        steps["artifacts"] = "removed_%d" % len(artifact_paths_removed)
    except McpOnboardError as exc:
        # _artifact_root() not configured — dev/test only; not fatal.
        steps["artifacts"] = "skipped: %s" % exc
    except Exception as exc:  # noqa: BLE001 — best-effort, does not abort
        _audit_failure("artifacts", exc)
        steps["artifacts"] = "error: %s" % type(exc).__name__
        logger.error(
            "mcp-decommission: artifact cleanup failed for %s (%s) — "
            "continuing (cosmetic — a stray compose-override file does not "
            "grant access; the envelope is already decommissioned)",
            provenance_id, exc,
        )

    if audit_writer is not None:
        try:
            from yashigani.audit.schema import McpDecommissionedEvent
            audit_writer.write(McpDecommissionedEvent(
                approver_account=operator_identity,
                tenant_id=tenant_id,
                server_id=server_id,
                instance_id=instance_id,
                spiffe_id=spiffe_id,
                container_teardown_mode=container_teardown_mode,
            ))
        except Exception as audit_exc:  # noqa: BLE001 — audit never masks success
            logger.error(
                "mcp-decommission: MCP_DECOMMISSIONED audit write failed: %s",
                audit_exc,
            )

    logger.info(
        "mcp-decommission: %s for %s (instance=%s steps=%s)",
        "ALREADY-DECOMMISSIONED" if already_decommissioned else "COMPLETE",
        provenance_id, instance_id or "n/a", steps,
    )

    return McpDecommissionResult(
        server_id=server_id,
        tenant_id=tenant_id,
        already_decommissioned=already_decommissioned,
        instance_id=instance_id,
        spiffe_id=spiffe_id,
        artifact_paths_removed=artifact_paths_removed,
        steps=steps,
        container_teardown=_agent_container_teardown_hint(
            tenant_id=tenant_id, server_id=server_id, runtime=runtime,
            mode=container_teardown_mode,
        ),
    )


__all__ = [
    "McpOnboardError",
    "McpOnboardResult",
    "McpDecommissionResult",
    "register_mcp_route",
    "unregister_mcp_route",
    "run_approve_transaction",
    "run_decommission_transaction",
]
