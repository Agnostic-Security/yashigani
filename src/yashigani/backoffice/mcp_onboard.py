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
  4. caddy_reload    — POST the monolith Caddyfile to Caddy's admin API over
                       the shared unix socket (Content-Type: text/caddyfile;
                       Caddy adapts server-side, resolving the
                       ``import /etc/caddy/agents/*.caddy`` sentinel that
                       picks up the new wrap).  Caddy reloads are atomic and
                       zero-downtime; a failed load leaves the old config
                       running.
  5. envelope_mint   — durable registry INSERT (mcp_tool_surface_pins) with
                       ``svid_instance_id`` / ``svid_spiffe_id`` /
                       ``svid_issued=True``.  This is the COMMIT POINT: the
                       svid flags ride the same INSERT and can therefore
                       never be persisted without the real cert minted in
                       step 2 (the BUG-A fail-open pattern must not
                       reappear).

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
    (today it is a caddy-local tmpfs, mode 0700).
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
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger(__name__)

_DEFAULT_ADMIN_SOCKET = "/run/caddy/admin.sock"
_DEFAULT_CADDYFILE = "/etc/caddy/Caddyfile"


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


async def default_caddy_reloader() -> None:
    """Reload Caddy via the admin API over the shared unix socket.

    POSTs the active monolith Caddyfile with ``Content-Type: text/caddyfile``;
    Caddy adapts it server-side (parse-time ``{$ENV}`` substitution and the
    ``import /etc/caddy/agents/*.caddy`` sentinel both resolve inside the
    caddy container).  A non-2xx response or an unreachable socket raises —
    the transaction rolls back (fail-closed).
    """
    import httpx  # noqa: PLC0415 — keep module import light

    socket_path = os.getenv("YASHIGANI_CADDY_ADMIN_SOCKET", _DEFAULT_ADMIN_SOCKET)
    caddyfile_path = os.getenv("YASHIGANI_CADDY_CADDYFILE", _DEFAULT_CADDYFILE)

    try:
        caddyfile_text = Path(caddyfile_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise McpOnboardError(
            "caddy_reload",
            f"cannot read Caddyfile at {caddyfile_path!r}: {exc} "
            "(Phase-3 wiring — mount the active Caddyfile into backoffice)",
        ) from exc

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
) -> McpOnboardResult:
    """Run the atomic approve transaction (see module docstring).

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
