"""
Yashigani MCP — durable broker-registry store (v4.1 Phase 2a / SEAM-1d-07).

Problem (Iris SEAM-1d-07)
-------------------------
The gateway's McpBrokerRegistry is populated ONLY from the boot-time
``YASHIGANI_MCP_SERVERS`` env var.  The v4.1 approve transaction
(backoffice/mcp_onboard.py) mints the leaf, writes the Caddy-front wrap and
commits the durable envelope — but never updates the broker registry.  The
wrap exists, verify-mcp admits it, and the broker never dials it until an
operator edits the gateway env and recreates the container.

Fix
---
The approve transaction durably registers the onboarded MCP's broker
descriptor here (Redis, same db/3 the permission/id stores use), keyed on the
canonical ``<tenant>:<server>`` — the SAME key the envelope row, the Caddy
route, the minted leaf SPIFFE path and /auth/verify-mcp all agree on
(iris-phase1d-audit.md §1).  The gateway's McpBrokerRegistry consults this
store on a lookup MISS (lazy load — see registry.py) and builds the broker on
first use: ``/mcp/<server>`` routes WITHOUT a gateway reboot, and the
registration survives reboots (Redis-persisted; the boot env stays authoritative
for boot-time entries and is never mutated).

Descriptor shape (JSON)::

    {
      "agent_name":          "<server_id>",        # registry key == path param
      "upstream_url":        "https://caddy:<mesh_port>/mcp/<tenant>/<server>",
      "tenant_id":           "<tenant>",
      "is_filesystem_agent": bool,
      "is_git_agent":        bool,
      "mcp_id":              "",                    # minted lazily gateway-side
      "cert_fingerprint":    "sha256:<hex>",        # per-instance leaf fp
      "spiffe_id":           "spiffe://.../agents/<t>/<s>/<nhi>",
      "svid_instance_id":    "nhi_<hex>",
      "registered_at":       "<ISO 8601 UTC>",
    }

Failure posture: every read path degrades to None (registry miss → 404, the
pre-existing behaviour).  Write paths raise — the approve transaction treats
a failed registration as a step failure and rolls back (fail-closed; a wrap
the broker can never dial is a partial onboarding).

Last updated: 2026-07-08T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_KEY_SERVER = "mcp:broker:server:{tenant}:{server}"
_KEY_INDEX = "mcp:broker:server_index"
# Grant + baseline keys — written at approve time, read at OPA startup push.
# grant:   {tools: [...], actions: [...], caller_spiffe: "spiffe://..."}
# baseline: {surface_hash: "sha384:<hex>", tools: [...]}
_KEY_GRANT = "mcp:broker:grant:{tenant}:{server}"
_KEY_BASELINE = "mcp:broker:baseline:{tenant}:{server}"
# v4.1 unified-sidecar Phase 1 (Lu M1) — (caller SPIFFE, egress prefixes)
# grant, written inside the approve transaction, read by the OPA data push.
# egress_grant: {spiffe: "<exact per-instance URI>", tenant: "<tenant_id>",
#                prefixes: ["slack", ...], connect?: {...}}
_KEY_EGRESS_GRANT = "mcp:broker:egress_grant:{tenant}:{server}"
# v4.1 Phase B — policy template application record.
# template_application: {template_id, version, overrides, acknowledgements,
#                        applied_by, applied_at}
_KEY_TEMPLATE_APPLICATION = "mcp:tmpl:{tenant}:{system}"
# Seed-claimed set (Redis SET, write-only grow) — every SPIFFE that has ever
# had put_egress_grant called for it.  Used by build_egress_grants_doc to
# suppress the transitional seed for claimed SPIFFEs so that a revocation
# (delete_egress_grant) cannot be overridden by the seed (Lu MF-2 / §4.4).
# Never cleared — claiming is permanent for the lifetime of the installation.
_KEY_EGRESS_SEED_CLAIMED = "mcp:broker:egress_seed_claimed_set"


def canonical_server_key(tenant_id: str, server_id: str) -> str:
    """The canonical ``<tenant>:<server>`` key (== envelope provenance_id)."""
    return f"{tenant_id}:{server_id}"


class DurableMcpRegistryStore:
    """Redis-backed store of onboarded MCP broker descriptors.

    Written by the backoffice approve transaction; read by the gateway
    McpBrokerRegistry lazy-load path.  Both sides share Redis db/3.
    """

    def __init__(self, redis_client: Any) -> None:
        if redis_client is None:
            raise RuntimeError(
                "DurableMcpRegistryStore requires a non-None Redis client."
            )
        self._redis = redis_client

    # ── write side (approve transaction) ─────────────────────────────────

    def put(self, tenant_id: str, server_id: str, descriptor: dict) -> None:
        """Durably register (or update) the broker descriptor.

        Raises on any Redis failure — the caller (approve transaction) must
        treat that as a step failure and roll back.
        """
        if not tenant_id or not server_id:
            raise ValueError("tenant_id and server_id must be non-empty")
        desc = dict(descriptor)
        desc.setdefault("agent_name", server_id)
        desc.setdefault("tenant_id", tenant_id)
        desc.setdefault(
            "registered_at", datetime.now(tz=timezone.utc).isoformat()
        )
        key = canonical_server_key(tenant_id, server_id)
        self._redis.set(_KEY_SERVER.format(tenant=tenant_id, server=server_id),
                        json.dumps(desc))
        self._redis.sadd(_KEY_INDEX, key)
        logger.info(
            "mcp-durable-registry: registered %s (upstream=%r)",
            key, desc.get("upstream_url"),
        )

    def delete(self, tenant_id: str, server_id: str) -> None:
        """Remove a registration (approve-transaction rollback / offboard)."""
        key = canonical_server_key(tenant_id, server_id)
        try:
            self._redis.delete(
                _KEY_SERVER.format(tenant=tenant_id, server=server_id)
            )
            self._redis.srem(_KEY_INDEX, key)
            logger.info("mcp-durable-registry: deleted %s", key)
        except Exception as exc:  # noqa: BLE001 — rollback path is best-effort
            logger.error("mcp-durable-registry: delete %s failed: %s", key, exc)

    def put_grant(self, tenant_id: str, server_id: str, grant_data: dict) -> None:
        """Store the per-instance OPA grant for ``<tenant>:<server>``.

        Raises on Redis failure — the approve transaction treats this as a step
        failure and rolls back (fail-closed, same as put()).
        grant_data shape: {tools: [...], actions: [...], caller_spiffe: "..."}.
        """
        if not tenant_id or not server_id:
            raise ValueError("tenant_id and server_id must be non-empty")
        self._redis.set(
            _KEY_GRANT.format(tenant=tenant_id, server=server_id),
            json.dumps(grant_data),
        )
        logger.debug(
            "mcp-durable-registry: stored grant for %s:%s tools=%d",
            tenant_id, server_id, len(grant_data.get("tools", [])),
        )

    def put_baseline(self, tenant_id: str, server_id: str, baseline_data: dict) -> None:
        """Store the capability-envelope OPA baseline for ``<tenant>:<server>``.

        baseline_data shape: {surface_hash: "sha384:<hex>", tools: [...]}.
        Raises on Redis failure.
        """
        if not tenant_id or not server_id:
            raise ValueError("tenant_id and server_id must be non-empty")
        self._redis.set(
            _KEY_BASELINE.format(tenant=tenant_id, server=server_id),
            json.dumps(baseline_data),
        )
        logger.debug(
            "mcp-durable-registry: stored baseline for %s:%s hash=%s",
            tenant_id, server_id, baseline_data.get("surface_hash", "?")[:20],
        )

    def claim_egress_seed(self, spiffe: str) -> None:
        """Permanently mark ``spiffe`` as store-claimed in the seed-claimed set.

        Idempotent (Redis SADD is a no-op if already a member).  Raises on
        Redis failure — callers that write a grant MUST claim first so that a
        future revocation (delete_egress_grant) cannot be overridden by the
        transitional seed (design §4.4, Lu MF-2a).

        The set is write-only-grow: it is NEVER cleared, even by
        delete_egress_grant.  Once claimed, the SPIFFE is permanently excluded
        from the seed in build_egress_grants_doc.
        """
        if not spiffe:
            return  # non-bundled /agents/ SPIFFEs are fine either way
        self._redis.sadd(_KEY_EGRESS_SEED_CLAIMED, spiffe)
        logger.debug(
            "mcp-durable-registry: egress seed claimed for spiffe=%s", spiffe,
        )

    def get_claimed_egress_seed_spiffes(self) -> frozenset:
        """Return all SPIFFEs ever claimed via put_egress_grant.

        Used by build_egress_grants_doc to suppress seed entries for claimed
        SPIFFEs (design §4.4).  Returns frozenset() if the key does not exist
        (no claims yet).  Raises on Redis failure — caller decides whether to
        skip suppression (fail-open on seed) or abort the push.
        """
        members = self._redis.smembers(_KEY_EGRESS_SEED_CLAIMED)
        if not members:
            return frozenset()
        return frozenset(
            m.decode() if isinstance(m, bytes) else str(m)
            for m in members
        )

    def put_egress_grant(self, tenant_id: str, server_id: str, grant_data: dict) -> None:
        """Store the (caller SPIFFE, egress prefixes) grant for ``<tenant>:<server>``.

        v4.1 unified-sidecar Phase 1 (Lu M1).  Raises on Redis failure — the
        approve transaction treats this as a step failure and rolls back
        (fail-closed, same as put()/put_grant()).

        grant_data shape::

            {"spiffe": "<EXACT per-instance SPIFFE URI>",
             "tenant": "<tenant_id>",
             "prefixes": ["slack", ...],   # positive set; [] = no egress
             "connect": {...}}             # optional Mode-B map (Phase 3+)

        The OPA data push keys the grant on the EXACT ``spiffe`` value
        (byte-match at decision time — never name-collapsed).

        Seed-claim ordering: ``claim_egress_seed`` is called BEFORE the main
        SET so that the claim is permanent even if the SET fails (fail-closed
        for future revocations — better to deny a bundled system temporarily
        than to allow a revoked seed grant to resurface).
        """
        if not tenant_id or not server_id:
            raise ValueError("tenant_id and server_id must be non-empty")
        spiffe = str(grant_data.get("spiffe", "")).strip()
        if not spiffe:
            raise ValueError("egress grant requires a non-empty spiffe key")
        # Claim BEFORE the main write: permanent seed-suppression for this
        # SPIFFE regardless of whether the grant is later revoked (Lu MF-2a).
        self.claim_egress_seed(spiffe)
        self._redis.set(
            _KEY_EGRESS_GRANT.format(tenant=tenant_id, server=server_id),
            json.dumps(grant_data),
        )
        logger.info(
            "mcp-durable-registry: stored egress grant for %s:%s spiffe=%s prefixes=%s",
            tenant_id, server_id, spiffe,
            sorted(grant_data.get("prefixes", [])),
        )

    def get_egress_grant(self, tenant_id: str, server_id: str) -> Optional[dict]:
        """Return the stored egress grant for ``<tenant>:<server>``, or None."""
        try:
            raw = self._redis.get(
                _KEY_EGRESS_GRANT.format(tenant=tenant_id, server=server_id)
            )
        except Exception as exc:  # noqa: BLE001 — read degrades to miss (OPA denies)
            logger.warning(
                "mcp-durable-registry: get_egress_grant %s:%s failed: %s",
                tenant_id, server_id, exc,
            )
            return None
        return self._decode(raw)

    def delete_egress_grant(self, tenant_id: str, server_id: str) -> None:
        """Remove an egress grant (rollback/offboard — best-effort delete;
        the authoritative revocation is the grant's ABSENCE from the next
        OPA data push — grant-absence is the kill switch)."""
        try:
            self._redis.delete(
                _KEY_EGRESS_GRANT.format(tenant=tenant_id, server=server_id)
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "mcp-durable-registry: delete_egress_grant %s:%s failed: %s",
                tenant_id, server_id, exc,
            )

    def build_egress_grants_data(self) -> dict:
        """Build the ``egress_grants`` OPA data sub-document from the store.

        Returns a mapping from exact SPIFFE URI to grant entry::

            {
              "<spiffe>": {
                "tenant":        "<tenant_id>",
                "prefixes":      ["slack", ...],
                "legacy_system": True,           # ONLY for bundled SPIFFEs
                "connect":       {...},           # ONLY if stored (Mode-B)
              }
            }

        **Field passthrough rules (Nico gap-1 / Lu MF-5, HIGH):**

        - ``legacy_system``: SERVER-DERIVED only — never read from the stored
          grant.  Set to ``True`` iff the SPIFFE is in the current bundled-
          system set (``bundled_system_spiffe_set()``).  Any other SPIFFE
          gets no ``legacy_system`` key (OPA treats absence as falsy).
          Rationale: a store-suppliable ``legacy_system`` is a tenant-conjunct
          bypass (Lu MF-1, HIGH) — any SPIFFE without a ``/agents/`` tenant
          segment could use it to satisfy ``_egress_grant_tenant_ok`` without
          a real per-tenant check.

        - ``connect``: passed through verbatim from the stored grant if
          present.  This is the Mode-B destination-host allowlist; it is
          admin-applied data (not a security bypass vector), and the OPA
          ``egress_connect_decision`` (Phase 3) requires it to be present.

        Descriptors without an egress grant record are simply absent from the
        document → OPA denies their egress fail-closed (closed world).
        Callers that need the transitional bundled-system seed merged in
        should use ``yashigani.mcp._egress_grants.build_egress_grants_doc``.
        """
        try:
            from yashigani.mcp._egress_grants import bundled_system_spiffe_set  # noqa: PLC0415
            _bundled = bundled_system_spiffe_set()
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "mcp-durable-registry: bundled_system_spiffe_set failed (%s) — "
                "legacy_system will NOT be set for any SPIFFE (fail-closed: "
                "bundled pre-migration systems deny egress; fix trust_domain)", exc,
            )
            _bundled: frozenset = frozenset()

        out: dict = {}
        for desc in self.list_all():
            server_id = desc.get("agent_name", "")
            tenant_id = desc.get("tenant_id", "")
            if not server_id or not tenant_id:
                continue
            grant = self.get_egress_grant(tenant_id, server_id)
            if grant is None:
                continue
            spiffe = str(grant.get("spiffe", "")).strip()
            if not spiffe:
                continue
            entry: dict = {
                "tenant": str(grant.get("tenant", tenant_id)),
                "prefixes": sorted(
                    str(p) for p in grant.get("prefixes", []) if p
                ),
            }
            # Server-derived: only hardcoded bundled SPIFFEs get legacy_system.
            # NEVER copied from the stored grant value (Lu MF-1 bypass fix).
            if spiffe in _bundled:
                entry["legacy_system"] = True
            # Mode-B connect map: pass through if present (admin-applied; safe
            # to forward as-is — it is not a bypass vector, and OPA
            # egress_connect_decision validates it separately).
            if "connect" in grant:
                entry["connect"] = grant["connect"]
            out[spiffe] = entry
        return out

    def delete_grant(self, tenant_id: str, server_id: str) -> None:
        """Remove a grant entry (rollback path — best-effort)."""
        try:
            self._redis.delete(_KEY_GRANT.format(tenant=tenant_id, server=server_id))
        except Exception as exc:  # noqa: BLE001
            logger.error("mcp-durable-registry: delete_grant %s:%s failed: %s", tenant_id, server_id, exc)

    def delete_baseline(self, tenant_id: str, server_id: str) -> None:
        """Remove a baseline entry (rollback path — best-effort)."""
        try:
            self._redis.delete(_KEY_BASELINE.format(tenant=tenant_id, server=server_id))
        except Exception as exc:  # noqa: BLE001
            logger.error("mcp-durable-registry: delete_baseline %s:%s failed: %s", tenant_id, server_id, exc)

    def get_grant(self, tenant_id: str, server_id: str) -> Optional[dict]:
        """Return the stored grant for ``<tenant>:<server>``, or None."""
        try:
            raw = self._redis.get(_KEY_GRANT.format(tenant=tenant_id, server=server_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("mcp-durable-registry: get_grant %s:%s failed: %s", tenant_id, server_id, exc)
            return None
        return self._decode(raw)

    def get_baseline(self, tenant_id: str, server_id: str) -> Optional[dict]:
        """Return the stored baseline for ``<tenant>:<server>``, or None."""
        try:
            raw = self._redis.get(_KEY_BASELINE.format(tenant=tenant_id, server=server_id))
        except Exception as exc:  # noqa: BLE001
            logger.warning("mcp-durable-registry: get_baseline %s:%s failed: %s", tenant_id, server_id, exc)
            return None
        return self._decode(raw)

    def build_mcp_opa_data(self, mcp_id_store: Any, org_id: str) -> dict:
        """Build the OPA MCP data document for startup push (Seam-3 / SEAM-1d-07).

        Returns::

            {
              "grants":    {mcp_id: {caller_spiffe: {tools: [...], actions: [...]}}},
              "baselines": {mcp_id: {surface_hash: "sha384:<hex>", tools: [...]}},
              "egress_grants": {spiffe: {tenant: ..., prefixes: [...]}},
            }

        ``egress_grants`` (v4.1 Phase 1 — Lu M1) rides the SAME document
        because the Seam-3 startup push PUTs the whole
        ``data.yashigani.mcp`` subtree — omitting it here would wipe any
        previously pushed egress grants.  It includes the transitional
        bundled-system seed (see _egress_grants.py).

        The ``mcp_id`` is resolved via ``mcp_id_store.get_or_mint(server_id)``
        (same key the broker uses at call time).  Entries whose grant OR baseline
        is missing in Redis are skipped with a warning (they were onboarded before
        Seam-3 wiring — the OPA will fail-closed for those instances until they
        are re-approved or until the data is back-filled).
        """
        grants: dict = {}
        baselines: dict = {}
        descriptors = self.list_all()
        for desc in descriptors:
            server_id = desc.get("agent_name", "")
            tenant_id = desc.get("tenant_id", "")
            if not server_id or not tenant_id:
                continue
            # Resolve stable mcp_id (same UUID the broker uses in ctx.mcp_id).
            try:
                mcp_id: str = mcp_id_store.get_or_mint(server_id)
            except Exception as exc:
                logger.warning(
                    "mcp-durable-registry: build_mcp_opa_data mcp_id lookup "
                    "failed for %s:%s — skipping: %s", tenant_id, server_id, exc,
                )
                continue

            # Grant
            grant = self.get_grant(tenant_id, server_id)
            if grant is not None:
                caller_spiffe = grant.get("caller_spiffe", "")
                if caller_spiffe:
                    grants.setdefault(mcp_id, {})[caller_spiffe] = {
                        "tools": grant.get("tools", []),
                        "actions": grant.get("actions", ["tools/call"]),
                    }

            # Baseline — normalise surface_hash to the same format the broker
            # sends in the OPA input (sha384:<hex> as stored; _sha256_label not
            # applied here — the broker normalises at send time using the same
            # raw value from the live catalogue; the baseline must match that).
            baseline = self.get_baseline(tenant_id, server_id)
            if baseline is not None:
                baselines[mcp_id] = {
                    "surface_hash": baseline.get("surface_hash", ""),
                    "tools": baseline.get("tools", []),
                }

            if grant is None or baseline is None:
                logger.warning(
                    "mcp-durable-registry: build_mcp_opa_data: %s:%s has no %s in "
                    "Redis — OPA will fail-closed for this instance until re-approved "
                    "(pre-Seam-3 onboard or data evicted)",
                    tenant_id, server_id,
                    "grant" if grant is None else "baseline",
                )

        # v4.1 Phase 1 (Lu M1): egress grants (store + transitional seed) —
        # must ride the same document; the startup push replaces the whole
        # data.yashigani.mcp subtree.
        from yashigani.mcp._egress_grants import build_egress_grants_doc  # noqa: PLC0415

        egress_grants = build_egress_grants_doc(self)

        logger.info(
            "mcp-durable-registry: build_mcp_opa_data: %d grant(s) + %d baseline(s) "
            "+ %d egress grant(s) from %d descriptor(s)",
            len(grants), len(baselines), len(egress_grants), len(descriptors),
        )
        return {
            "grants": grants,
            "baselines": baselines,
            "egress_grants": egress_grants,
        }

    # ── read side (gateway lazy load) ─────────────────────────────────────

    def get(self, tenant_id: str, server_id: str) -> Optional[dict]:
        """Return the descriptor for ``<tenant>:<server>``, or None."""
        try:
            raw = self._redis.get(
                _KEY_SERVER.format(tenant=tenant_id, server=server_id)
            )
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-durable-registry: get %s:%s failed: %s",
                tenant_id, server_id, exc,
            )
            return None
        return self._decode(raw)

    def get_by_agent_name(self, agent_name: str) -> Optional[dict]:
        """Return the descriptor whose server component == ``agent_name``.

        The runtime route is ``/mcp/<agent_name>`` (single segment); the
        onboard transaction enforces ``metadata.name == server_id`` so the
        path param equals the server component of the canonical key.  The
        index is scanned (small N — one entry per onboarded MCP); an ambiguous
        name (same server_id under two tenants) returns None and logs — the
        caller falls through to a 404 rather than guessing a tenant.
        """
        if not agent_name:
            return None
        try:
            members = self._redis.smembers(_KEY_INDEX) or set()
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-durable-registry: index read failed for %r: %s",
                agent_name, exc,
            )
            return None
        matches = []
        for m in members:
            key = m.decode("utf-8", errors="replace") if isinstance(m, bytes) else str(m)
            tenant, sep, server = key.partition(":")
            if sep and server == agent_name:
                matches.append((tenant, server))
        if not matches:
            return None
        if len(matches) > 1:
            logger.error(
                "mcp-durable-registry: agent_name=%r is ambiguous across "
                "tenants %s — refusing to guess (404)",
                agent_name, sorted(t for t, _ in matches),
            )
            return None
        tenant, server = matches[0]
        return self.get(tenant, server)

    def list_all(self) -> list[dict]:
        """Return every registered descriptor (health probes / admin views)."""
        out: list[dict] = []
        try:
            members = self._redis.smembers(_KEY_INDEX) or set()
        except Exception as exc:  # noqa: BLE001
            logger.warning("mcp-durable-registry: list_all failed: %s", exc)
            return out
        for m in members:
            key = m.decode("utf-8", errors="replace") if isinstance(m, bytes) else str(m)
            tenant, sep, server = key.partition(":")
            if not sep:
                continue
            desc = self.get(tenant, server)
            if desc is not None:
                out.append(desc)
        return out

    # ── v4.1 Phase B: policy template application record ─────────────────────

    def put_template_application(
        self, tenant_id: str, system_id: str, app_data: dict
    ) -> None:
        """Store the policy template application record for ``{tenant}:{system}``.

        v4.1 Phase B (design §4.2).  Called inside the apply transaction.
        Raises on Redis failure — the transaction treats this as a step failure.

        app_data shape::

            {
              "template_id":    "tmpl-openclaw-default",
              "version":        1,
              "overrides":      {},               # optional per-instance overrides
              "acknowledgements": [],             # [{residual_id, justification}]
              "applied_by":     "<admin_account_id>",
              "applied_at":     "<ISO 8601 UTC>",
            }
        """
        if not tenant_id or not system_id:
            raise ValueError("tenant_id and system_id must be non-empty")
        self._redis.set(
            _KEY_TEMPLATE_APPLICATION.format(tenant=tenant_id, system=system_id),
            json.dumps(app_data),
        )
        logger.info(
            "mcp-durable-registry: stored template application for %s:%s tmpl=%s v%s",
            tenant_id, system_id,
            app_data.get("template_id", "?"), app_data.get("version", "?"),
        )

    def get_template_application(
        self, tenant_id: str, system_id: str
    ) -> Optional[dict]:
        """Return the stored template application for ``{tenant}:{system}``, or None."""
        try:
            raw = self._redis.get(
                _KEY_TEMPLATE_APPLICATION.format(tenant=tenant_id, system=system_id)
            )
        except Exception as exc:  # noqa: BLE001 — read degrades to miss
            logger.warning(
                "mcp-durable-registry: get_template_application %s:%s failed: %s",
                tenant_id, system_id, exc,
            )
            return None
        return self._decode(raw)

    def delete_template_application(
        self, tenant_id: str, system_id: str
    ) -> None:
        """Remove a template application record (rollback / revoke — best-effort)."""
        try:
            self._redis.delete(
                _KEY_TEMPLATE_APPLICATION.format(tenant=tenant_id, system=system_id)
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "mcp-durable-registry: delete_template_application %s:%s failed: %s",
                tenant_id, system_id, exc,
            )

    @staticmethod
    def _decode(raw: Any) -> Optional[dict]:
        if raw is None:
            return None
        try:
            data = json.loads(
                raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
            )
        except Exception:  # noqa: BLE001 — corrupt entry degrades to miss
            logger.error("mcp-durable-registry: corrupt descriptor JSON — treated as miss")
            return None
        return data if isinstance(data, dict) else None


__all__ = [
    "DurableMcpRegistryStore",
    "canonical_server_key",
]
