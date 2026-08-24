"""
Yashigani Agent Registry — Manages registered agent identities and PSK tokens.
# Last updated: 2026-06-27T00:00:00+00:00

Key schema (Redis db/3, namespace agent:* and nhi:*):
  agent:reg:{agent_id}      Hash: name, upstream_url, status, created_at,
                             last_seen_at, groups (JSON), allowed_caller_groups (JSON),
                             allowed_paths (JSON)
  agent:token:{agent_id}    String: bcrypt hash of PSK (cost 12)
  agent:index:all           Set: all agent_id values
  agent:index:active        Set: active agent_id values

  NHI extensions (4.0 Phase 3 — RISK-097/108):
  NHI IDs use prefix nhi_ (not agnt_) for fast identity-dispatch discrimination.
  agent:reg:{nhi_id}        Hash: name, upstream_url, status, kind="nhi",
                             template_id, owner_identity_id, allowed_tools (JSON),
                             budget_cap (JSON), svid_issued (0|1), pids_limit,
                             memory_mb, spiffe_id, created_at, ...
  nhi:token:{nhi_id}        String: PLAINTEXT bearer token (256-bit hex).
                             Distinct from agent:token which holds bcrypt hashes.
                             Used for fast hmac.compare_digest in _resolve_identity.
                             The gateway loads all live NHI tokens at startup via
                             get_nhi_token_map() and caches them in _state.token_role_map.
  nhi:index:active          Set: nhi_id values with svid_issued=1 and status=active
"""
from __future__ import annotations

import bcrypt
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import uuid
from pathlib import Path
from typing import Optional

from yashigani.licensing.enforcer import LicenseLimitExceeded

logger = logging.getLogger(__name__)

# Module-level integrity state (T3)
_agents_registry_integrity_violated = False


def _emit_agents_registry_integrity_violation_event(
    check_type: str,
    expected_hash: str,
    actual_hash: str,
) -> None:
    """Emit a typed LicenceIntegrityViolationEvent (defence-in-depth)."""
    try:
        from yashigani.audit.schema import LicenceIntegrityViolationEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        event = LicenceIntegrityViolationEvent(
            module="agents.registry",
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        )
        writer.write(event)
    except Exception:
        pass


def _check_agents_registry_integrity() -> None:
    """
    T3: Self-check registry.py SHA-256 against _integrity.AGENTS_REGISTRY_HASH.
    Sets _agents_registry_integrity_violated = True on mismatch.
    Called from AgentRegistry.__init__ (DG-04: consuming class, not _integrity.py).
    """
    global _agents_registry_integrity_violated
    from yashigani.licensing import _integrity

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    if _integrity.is_agents_registry_hash_placeholder():
        if not is_dev:
            _agents_registry_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: AGENTS_REGISTRY_HASH is still a placeholder "
                "in a non-dev environment; forcing COMMUNITY tier (T3)"
            )
        return

    try:
        digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except Exception as exc:
        logger.warning("License integrity: could not read agents/registry.py for hash check: %s", exc)
        return

    if digest != _integrity.AGENTS_REGISTRY_HASH:
        _agents_registry_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: agents/registry.py has been tampered with "
            "(expected=%s, actual=%s); forcing COMMUNITY tier (T3)",
            _integrity.AGENTS_REGISTRY_HASH[:16],
            digest[:16],
        )
        _emit_agents_registry_integrity_violation_event(
            check_type="self_hash",
            expected_hash=_integrity.AGENTS_REGISTRY_HASH,
            actual_hash=digest,
        )


def get_agents_registry_integrity_status() -> bool:
    """Return True if the agents/registry integrity has been violated."""
    return _agents_registry_integrity_violated

_BCRYPT_COST = 12

# V232-CSCAN-01a: canonical agent-name pattern (must match AgentRegisterRequest.name).
# Any existing registry entry whose name does not match is flagged at startup.
_AGENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


def _record_durable_write_failure(operation: str, kind: str) -> None:
    """YSG-RISK-155: make a swallowed durable-write failure observable.

    The register()/register_nhi() dual-write is intentionally best-effort —
    a Postgres blip must not roll back a successful Redis registration, so the
    exception is caught and logged there. Fail-loud-log alone is easy to miss
    in practice; increment a Prometheus counter too so a dashboard/alert can
    catch a durability drop even if nobody is tailing logs at the moment it
    happens. Import is local + wrapped so a metrics-layer problem can never
    mask or replace the original registration error (mirrors gateway/agent_auth.py).
    """
    try:
        from yashigani.metrics.registry import agent_durable_write_failures_total
        agent_durable_write_failures_total.labels(operation=operation, kind=kind).inc()
    except Exception:
        logger.debug(
            "AgentRegistry: metric increment failed for agent_durable_write_failures_total "
            "(operation=%s, kind=%s)", operation, kind, exc_info=True,
        )


class AgentRegistry:
    """
    Thread-safe agent registry backed by Redis db/3.

    Agent IDs use the prefix agnt_ followed by 12 hex chars.
    PSK tokens are 256-bit hex strings (64 chars).
    Token hashes use bcrypt cost 12 — never store plaintext.
    """

    # LAURA-LIMIT-AGENTS-01 + AGENTS-03 (GROUP-4-1): atomic Lua script for
    # agent registration. Replaces the non-atomic count→check→hset→sadd
    # pipeline which had a TOCTOU race:
    #   Thread A: count() = 9 (limit = 10) → passes check
    #   Thread B: count() = 9 (limit = 10) → passes check
    #   Thread A: hset + sadd → active count = 10
    #   Thread B: hset + sadd → active count = 11 → LIMIT BYPASSED
    #
    # The Lua script executes atomically under Redis's single-threaded model.
    # KEYS[1] = agent:index:active
    # KEYS[2] = agent:index:all
    # KEYS[3] = agent:reg:{agent_id}
    # KEYS[4] = agent:token:{agent_id}
    # ARGV[1] = limit (int, -1 = unlimited)
    # ARGV[2] = agent_id
    # ARGV[3] = token_hash
    # ARGV[4..N] = flat key-value pairs for HSET
    _REGISTER_LUA = """
local limit = tonumber(ARGV[1])
local current = tonumber(redis.call("SCARD", KEYS[1]))
if limit ~= -1 and current >= limit then
    return redis.error_reply("LIMIT_EXCEEDED:" .. current .. ":" .. limit)
end
local agent_id = ARGV[2]
local token_hash = ARGV[3]
-- Build HSET mapping from ARGV[4..] (pairs: field, value, field, value, ...)
local hset_args = {}
for i = 4, #ARGV do
    table.insert(hset_args, ARGV[i])
end
redis.call("HSET", KEYS[3], unpack(hset_args))
redis.call("SET", KEYS[4], token_hash)
redis.call("SADD", KEYS[2], agent_id)
redis.call("SADD", KEYS[1], agent_id)
return 1
"""

    def __init__(self, redis_client, durable_store=None) -> None:
        self._r = redis_client
        # ISSUE-AGENT-REG-DURABILITY (Iris, 2026-06-10): optional durable
        # Postgres mirror. When wired, register/update/deactivate dual-write to
        # Postgres so a Redis db/3 wipe (it runs appendonly no / save "") can be
        # reconciled back on startup. None in tests / pre-DB-pool init paths —
        # the registry then behaves exactly as before (Redis-only).
        self._durable = durable_store
        total = self._r.scard("agent:index:all") or 0
        logger.info("AgentRegistry initialised: %d agent(s) in index", total)
        # T3: integrity self-check (DG-04 — called in consuming class, not _integrity.py)
        _check_agents_registry_integrity()
        # V232-CSCAN-01a migration check: warn on names that pre-date the slug constraint.
        # These entries are not deleted (non-breaking), but the gateway will skip their
        # secret-file lookup due to the path-resolution guard in openai_router.py.
        self._warn_non_compliant_names()

    # ── Startup integrity check (V232-CSCAN-01a) ─────────────────────────────

    def _warn_non_compliant_names(self) -> None:
        """Log a structured warning for any existing agent whose name does not satisfy
        the slug pattern '^[a-z][a-z0-9_-]{0,63}$' introduced in v2.23.2.

        Non-compliant entries are NOT deleted — that would break existing deployments.
        They are flagged here and surfaced as ``legacy_name_violation=True`` in list_all()
        so the admin UI can display them as a flagged row.
        """
        try:
            for agent in self.list_all():
                name = agent.get("name", "")
                if not _AGENT_NAME_RE.fullmatch(name):
                    logger.warning(
                        "V232-CSCAN-01a: agent %r (id=%s) has a name %r that does not satisfy "
                        "the slug pattern -- secret-file lookup will be skipped for this agent; "
                        "re-register with a compliant name or remove this entry",
                        name, agent.get("agent_id", "?"), name,
                    )
        except Exception as exc:
            logger.warning("V232-CSCAN-01a name-compliance check failed (non-fatal): %s", exc)

    # ── Registration ─────────────────────────────────────────────────────────

    def register(
        self,
        name: str,
        upstream_url: str,
        groups: list,
        allowed_caller_groups: list,
        allowed_paths: list,
        allowed_cidrs: list | None = None,
        protocol: str = "openai",
        # 4.0 Phase 5 §C + §A.3 (additive — backward-compatible defaults).
        # `kind` distinguishes bundled callee agents ("agent") from NHI instances
        # ("nhi").  `sensitivity_ceiling` caps what sensitivity class the agent may
        # receive in a response (None = unrestricted; "INTERNAL" = hard INTERNAL cap).
        # `allowed_tools` is the NHI-specific explicit tool list (Phase 3 §A.3);
        # stored here as a stub so the registry schema is consistent before Phase 3
        # wires the NHI instantiation endpoint.
        kind: str = "agent",
        sensitivity_ceiling: Optional[str] = None,
        allowed_tools: list | None = None,
    ) -> tuple[str, str]:
        """
        Register a new agent atomically via Lua script.

        The Lua script performs an atomic SCARD → limit check → HSET + SET + SADD
        sequence. This eliminates the TOCTOU race in the previous count → check →
        pipeline pattern (LAURA-LIMIT-AGENTS-01 / AGENTS-03, GROUP-4-1).

        Returns (agent_id, plaintext_token). The plaintext token is never
        stored again — the caller is responsible for delivering it securely.

        Raises LicenseLimitExceeded when the active agent count is at the limit.
        """
        from yashigani.licensing.enforcer import get_license

        lic = get_license()
        limit = lic.max_agents  # -1 = unlimited

        agent_id = f"agnt_{uuid.uuid4().hex[:12]}"
        plaintext_token = secrets.token_bytes(32).hex()

        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")

        now = _now_iso()

        # Flat HSET argv list: field, value, field, value, ...
        hset_pairs: list[str] = [
            "name",                    name,
            "upstream_url",            upstream_url,
            "protocol",                protocol,
            "status",                  "active",
            "created_at",              now,
            "last_seen_at",            "",
            "groups",                  json.dumps(groups),
            "allowed_caller_groups",   json.dumps(allowed_caller_groups),
            "allowed_paths",           json.dumps(allowed_paths),
            "allowed_cidrs",           json.dumps(allowed_cidrs or []),
            # 4.0 Phase 5 / §A.3 (additive fields — older entries simply lack them;
            # _decode_agent() returns defaults for missing keys).
            "kind",                    kind,
            "sensitivity_ceiling",     sensitivity_ceiling or "",
            "allowed_tools",           json.dumps(allowed_tools or []),
        ]

        keys = [
            "agent:index:active",          # KEYS[1]
            "agent:index:all",             # KEYS[2]
            f"agent:reg:{agent_id}",       # KEYS[3]
            f"agent:token:{agent_id}",     # KEYS[4]
        ]
        argv = [
            str(limit),                    # ARGV[1]
            agent_id,                      # ARGV[2]
            token_hash,                    # ARGV[3]
        ] + hset_pairs                     # ARGV[4..]

        try:
            self._r.eval(self._REGISTER_LUA, len(keys), *keys, *argv)
        except Exception as exc:
            err_str = str(exc)
            if "LIMIT_EXCEEDED" in err_str:
                # Parse "LIMIT_EXCEEDED:current:max" from Redis error reply
                try:
                    parts = err_str.split(":")
                    current = int(parts[1])
                    max_val = int(parts[2])
                except (IndexError, ValueError):
                    current = self.count("active")
                    max_val = limit
                raise LicenseLimitExceeded(
                    limit_name="max_agents",
                    current=current,
                    max_val=max_val,
                ) from exc
            raise

        logger.info("AgentRegistry: registered %s (%s)", agent_id, name)

        # ISSUE-AGENT-REG-DURABILITY: dual-write to the durable Postgres mirror
        # (including the bcrypt token_hash) so this registration survives a Redis
        # db/3 wipe. The Redis write above is the request-time source; Postgres
        # is the durability anchor reconciled on startup. Best-effort: a durable
        # write failure must NOT roll back a successful Redis registration (the
        # agent still works right now), but it IS logged loudly so the operator
        # can re-trigger before the next redis recreate.
        if self._durable is not None:
            try:
                # YSG-RISK-155: use the freshly-decoded Redis record (via get())
                # rather than a hand-built partial dict, so kind/sensitivity_ceiling/
                # allowed_tools (4.0 Phase 5 / §A.3 — set via the kind=/sensitivity_
                # ceiling=/allowed_tools= kwargs above) round-trip to Postgres instead
                # of silently defaulting on restore.
                full = self.get(agent_id)
                if full is not None:
                    self._durable.upsert(full, token_hash=token_hash)
            except Exception as exc:
                logger.error(
                    "AgentRegistry: DURABLE write failed for %s (%s) — agent is live in "
                    "Redis but will NOT survive a redis recreate until re-registered: %s",
                    agent_id, name, exc,
                )
                _record_durable_write_failure("register", kind)

        return agent_id, plaintext_token

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get(self, agent_id: str) -> Optional[dict]:
        """Return agent dict or None if not found."""
        reg_key = f"agent:reg:{agent_id}"
        raw = self._r.hgetall(reg_key)
        if not raw:
            return None
        return self._decode_agent(agent_id, raw)

    def list_all(self) -> list[dict]:
        """Return all agents (active and inactive)."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:all")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    def list_active(self) -> list[dict]:
        """Return active agents only."""
        agent_ids = [
            aid.decode("utf-8") if isinstance(aid, bytes) else aid
            for aid in self._r.smembers("agent:index:active")
        ]
        result = []
        for aid in sorted(agent_ids):
            agent = self.get(aid)
            if agent is not None:
                result.append(agent)
        return result

    # ── Mutations ─────────────────────────────────────────────────────────────

    def update(self, agent_id: str, **fields) -> None:
        """
        Update mutable fields: name, upstream_url, groups,
        allowed_caller_groups, allowed_paths.
        """
        allowed_fields = {
            "name", "upstream_url", "groups",
            "allowed_caller_groups", "allowed_paths", "allowed_cidrs",
            # 4.0 Phase 5 / §A.3 additions (additive)
            "kind", "sensitivity_ceiling", "allowed_tools",
            # 4.0 Phase 3: persist minted SPIFFE ID after approve_svid
            "spiffe_id",
        }
        reg_key = f"agent:reg:{agent_id}"
        mapping = {}
        for k, v in fields.items():
            if k not in allowed_fields:
                logger.warning("AgentRegistry.update: ignoring unknown field %r", k)
                continue
            if isinstance(v, (list, dict)):
                mapping[k.encode("utf-8")] = json.dumps(v).encode("utf-8")
            else:
                mapping[k.encode("utf-8")] = str(v).encode("utf-8")
        if mapping:
            self._r.hset(reg_key, mapping=mapping)
            logger.info("AgentRegistry: updated %s fields=%s", agent_id, list(fields.keys()))
            # ISSUE-AGENT-REG-DURABILITY: mirror the metadata update into Postgres
            # (token_hash unchanged → None). Read the full post-update hash back so
            # the durable row reflects every field, not just the changed ones.
            if self._durable is not None:
                agent = None
                try:
                    agent = self.get(agent_id)
                    if agent is not None:
                        self._durable.upsert(agent, token_hash=None)
                except Exception as exc:
                    logger.error(
                        "AgentRegistry: DURABLE update failed for %s — Postgres mirror "
                        "stale until next mutation: %s", agent_id, exc,
                    )
                    _record_durable_write_failure("update", (agent or {}).get("kind") or "agent")

    def deactivate(self, agent_id: str) -> None:
        """Set status=inactive, remove from active indexes, AND revoke the PSK.

        v4.1 Phase 1a (GAP-4 adjacency): NHIs must ALSO leave
        ``nhi:index:active`` — ``get_nhi_token_map()`` reads that index, so a
        deactivated NHI whose id lingered there kept a live gateway token.

        FIND-0813-013 / SEC-001 (Nico, 2026-08-13): pre-fix, this method only
        flipped ``status`` + index membership. ``verify_token()`` looks up
        ``agent:token:{agent_id}`` directly and never consulted ``status`` or
        ``agent:index:active`` — so a "deactivated" agent's bcrypt-hashed PSK
        kept authenticating forever. This is the ONLY documented manual
        remediation an operator has for an orphaned/duplicate-name row
        (migration 0017 deliberately drops agent-NAME uniqueness — MUST-FIX-2,
        Iris 2026-06-10 — so a re-registration under a colliding name does
        not itself revoke the superseded row's credential; agent_id stays the
        real key). Deleting the token material here — not just flipping a
        flag — is what makes deactivate() actually revoke access. The grace
        key (``agent:token:grace:{agent_id}``, token_rotation.py's rotation
        grace window) is deleted too: it is the same credential family and
        would otherwise remain a live fallback secret past a deliberate
        deactivate.
        """
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"status", b"inactive")
        self._r.srem("agent:index:active", agent_id.encode("utf-8"))
        self._r.srem("nhi:index:active", agent_id.encode("utf-8"))
        # FIND-0813-013: revoke the credential material itself.
        self._r.delete(f"agent:token:{agent_id}")
        self._r.delete(f"agent:token:grace:{agent_id}")
        logger.info("AgentRegistry: deactivated %s (token material revoked)", agent_id)
        # ISSUE-AGENT-REG-DURABILITY: mirror the status change into Postgres.
        if self._durable is not None:
            try:
                self._durable.set_status(agent_id, "inactive")
            except Exception as exc:
                logger.error(
                    "AgentRegistry: DURABLE deactivate failed for %s — Postgres mirror "
                    "stale until next mutation: %s", agent_id, exc,
                )

    # ── Reconcile (ISSUE-AGENT-REG-DURABILITY) ─────────────────────────────────

    def restore_from_durable(self, agent: dict, token_hash: Optional[str]) -> None:
        """Re-materialise one durable agent row into Redis db/3 (idempotent).

        Called by the startup reconciler (AgentReconciler) when Redis db/3 has
        been wiped but Postgres still holds the registration. Writes the agent
        hash, the bcrypt token_hash, and the index-set memberships WITHOUT going
        through register() — register() would mint a NEW agent_id and a NEW token,
        breaking every caller's stored PSK. We restore the EXACT stored hash so
        existing agent tokens keep working.

        YSG-RISK-155 — ``kind == "nhi"`` is handled differently:
          * An NHI's bearer token lives PLAINTEXT in ``nhi:token:{nhi_id}``, not
            bcrypt-hashed in ``agent:token:{agent_id}`` — and it is a one-time
            secret that ``register_nhi()`` deliberately never re-persists to
            Postgres (``token_hash`` is always NULL for an NHI's durable row).
            So there is nothing durable to restore into either token key:
            ``token_hash`` is expected to be ``None`` here for an NHI, and this
            method does NOT touch ``agent:token:*``/``nhi:token:*`` at all.
          * What IS restored is the NHI's full registration metadata (kind,
            template_id, owner_identity_id, allowed_tools/models,
            sensitivity_ceiling, budget_cap, svid_issued, pids_limit,
            memory_mb, spiffe_id, scope_hash) plus its index memberships
            (``agent:index:all``/``active``, ``nhi:index:active`` when it was
            durably active + SVID-approved) — so the NHI comes back as an NHI
            (visible to admin UI, RBAC/identity-dispatch code, GAP-2 scope_hash
            comparisons) rather than either vanishing or restoring as a plain
            "agent" with none of its fields. The NHI's caller-presented bearer
            token will not validate again until it is re-provisioned (rotate /
            re-approve) — this is called out at WARNING by the caller
            (AgentReconciler) so it is an operator-visible follow-up, not a
            silent gap.

        Does not enforce the licence limit: this is a restore of already-licensed
        registrations, not a new registration. Idempotent — re-running overwrites
        with identical data.
        """
        agent_id = agent["agent_id"]
        reg_key = f"agent:reg:{agent_id}"
        token_key = f"agent:token:{agent_id}"
        status = agent.get("status") or "active"
        kind = agent.get("kind") or "agent"

        mapping = {
            b"name": str(agent.get("name", "")).encode("utf-8"),
            b"upstream_url": str(agent.get("upstream_url", "")).encode("utf-8"),
            b"protocol": str(agent.get("protocol") or "openai").encode("utf-8"),
            b"status": status.encode("utf-8"),
            b"created_at": str(agent.get("created_at", "") or _now_iso()).encode("utf-8"),
            b"last_seen_at": str(agent.get("last_seen_at", "")).encode("utf-8"),
            b"groups": json.dumps(agent.get("groups", [])).encode("utf-8"),
            b"allowed_caller_groups": json.dumps(agent.get("allowed_caller_groups", [])).encode("utf-8"),
            b"allowed_paths": json.dumps(agent.get("allowed_paths", [])).encode("utf-8"),
            b"allowed_cidrs": json.dumps(agent.get("allowed_cidrs", [])).encode("utf-8"),
            # 4.0 Phase 5 / §A.3: additive fields restored from durable store.
            # Pre-4.0 durable rows lack these; default to "agent" / "" / [].
            b"kind": kind.encode("utf-8"),
            b"sensitivity_ceiling": str(agent.get("sensitivity_ceiling") or "").encode("utf-8"),
            b"allowed_tools": json.dumps(agent.get("allowed_tools") or []).encode("utf-8"),
        }
        if kind == "nhi":
            mapping.update({
                b"template_id":         str(agent.get("template_id", "")).encode("utf-8"),
                b"owner_identity_id":   str(agent.get("owner_identity_id", "")).encode("utf-8"),
                b"allowed_tools":       json.dumps(agent.get("allowed_tools", [])).encode("utf-8"),
                b"allowed_models":      json.dumps(agent.get("allowed_models", [])).encode("utf-8"),
                b"sensitivity_ceiling": str(agent.get("sensitivity_ceiling", "PUBLIC")).encode("utf-8"),
                b"budget_cap":          json.dumps(agent.get("budget_cap", {})).encode("utf-8"),
                b"svid_issued":         b"1" if agent.get("svid_issued") else b"0",
                b"pids_limit":          str(agent.get("pids_limit", 64)).encode("utf-8"),
                b"memory_mb":           str(agent.get("memory_mb", 512)).encode("utf-8"),
                b"spiffe_id":           str(agent.get("spiffe_id", "")).encode("utf-8"),
                b"scope_hash":          str(agent.get("scope_hash", "")).encode("utf-8"),
            })

        pipe = self._r.pipeline()
        pipe.hset(reg_key, mapping=mapping)
        pipe.sadd("agent:index:all", agent_id.encode("utf-8"))

        if kind == "nhi":
            # No durable token to restore (see docstring) — index membership
            # only. An NHI only ever entered nhi:index:active via approve_svid,
            # so mirror that invariant: active + svid_issued => nhi:index:active.
            if status == "active":
                pipe.sadd("agent:index:active", agent_id.encode("utf-8"))
                if agent.get("svid_issued"):
                    pipe.sadd("nhi:index:active", agent_id.encode("utf-8"))
                else:
                    pipe.srem("nhi:index:active", agent_id.encode("utf-8"))
            else:
                pipe.srem("agent:index:active", agent_id.encode("utf-8"))
                pipe.srem("nhi:index:active", agent_id.encode("utf-8"))
        else:
            # FIND-0813-013 (Nico, 2026-08-13): do NOT unconditionally restore
            # the token key. AgentDurableStore.set_status() (called by
            # deactivate()) updates status/is_active in Postgres but
            # deliberately RETAINS the historical token_hash column
            # (audit/rotation trail) -- deactivate() itself deletes the LIVE
            # Redis token key, not the Postgres column. If this reconciler
            # blindly restored token_hash for every row regardless of status, a
            # Redis db/3 wipe (appendonly no / save "") followed by a reconcile
            # would silently RESURRECT a deliberately-revoked agent's PSK --
            # the exact "manual deactivate doesn't actually revoke" gap this
            # fix closes, reopened one layer down. Only live/active agents get
            # their token key restored; an inactive row's token key is
            # explicitly deleted (idempotent — restore_from_durable() only runs
            # when the key is already absent, but this keeps the invariant
            # explicit rather than implicit).
            #
            # 5.0 reintegration (2026-08-24): the token_hash guard stays, but
            # only on the path that actually consumes it — an inactive non-NHI
            # row is now deleted rather than restored, so it no longer needs a
            # hash to reconcile.
            if status == "active":
                if token_hash is None:
                    raise ValueError(
                        f"restore_from_durable: token_hash is required for non-NHI agent {agent_id!r}"
                    )
                pipe.set(token_key, token_hash.encode("utf-8"))
                pipe.sadd("agent:index:active", agent_id.encode("utf-8"))
            else:
                pipe.delete(token_key)
                pipe.srem("agent:index:active", agent_id.encode("utf-8"))

        pipe.execute()
        logger.info(
            "AgentRegistry: restored %s (%s, kind=%s) into Redis db/3 from durable store",
            agent_id, agent.get("name", ""), kind,
        )

    def get_token_hash(self, agent_id: str) -> Optional[str]:
        """Return the stored bcrypt token_hash for an agent, or None.

        Used by the durability back-fill (ISSUE-AGENT-REG-DURABILITY) to seed the
        durable Postgres store from agents that already exist in Redis db/3 but
        pre-date the dual-write (e.g. the letta/langflow agents registered at
        install before this fix landed). NEVER returns plaintext — only the
        bcrypt hash, exactly as stored.
        """
        token_key = f"agent:token:{agent_id}"
        stored = self._r.get(token_key)
        if not stored:
            return None
        return stored.decode("utf-8") if isinstance(stored, bytes) else stored

    # ── Token operations ──────────────────────────────────────────────────────

    def verify_token(self, agent_id: str, plaintext_token: str) -> bool:
        """
        Verify a plaintext PSK against the stored bcrypt hash.
        Calls _update_last_seen on success.
        Always returns False on any error (fail-closed).
        """
        try:
            token_key = f"agent:token:{agent_id}"
            stored = self._r.get(token_key)
            if not stored:
                return False
            stored_hash = stored if isinstance(stored, bytes) else stored.encode("utf-8")
            candidate = plaintext_token.encode("utf-8")
            ok = bcrypt.checkpw(candidate, stored_hash)
            if ok:
                self._update_last_seen(agent_id)
            return ok
        except Exception as exc:
            logger.error("AgentRegistry.verify_token error for %s: %s", agent_id, exc)
            return False

    def rotate_token(self, agent_id: str) -> str:
        """
        Generate a new 256-bit token, hash and store it, return the plaintext.
        """
        plaintext_token = secrets.token_bytes(32).hex()
        token_hash = bcrypt.hashpw(
            plaintext_token.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_COST)
        ).decode("utf-8")
        token_key = f"agent:token:{agent_id}"
        self._r.set(token_key, token_hash.encode("utf-8"))
        logger.info("AgentRegistry: token rotated for %s", agent_id)
        # ISSUE-AGENT-REG-DURABILITY: persist the new token_hash to Postgres so a
        # post-rotation redis recreate reconciles the ROTATED hash, not the old
        # one (which would leave the agent's current token rejected).
        if self._durable is not None:
            try:
                agent = self.get(agent_id)
                if agent is not None:
                    self._durable.upsert(agent, token_hash=token_hash)
            except Exception as exc:
                logger.error(
                    "AgentRegistry: DURABLE token-rotation write failed for %s — durable "
                    "store holds the OLD hash; rotate again after fixing Postgres: %s",
                    agent_id, exc,
                )
        return plaintext_token

    # ── NHI registration (4.0 Phase 3 — RISK-097) ───────────────────────────

    def register_nhi(
        self,
        *,
        name: str,
        owner_identity_id: str,
        template_id: str,
        allowed_tools: list[str],
        allowed_paths: list[str],
        allowed_models: list[str],
        sensitivity_ceiling: str,
        budget_cap: dict,
        pids_limit: int = 64,
        memory_mb: int = 512,
        spiffe_id: str = "",
        scope_hash: str = "",
    ) -> tuple[str, str]:
        """Register a new Non-Human Identity (NHI) entry.

        NHI IDs use the ``nhi_`` prefix (not ``agnt_``) so identity-dispatch
        code can distinguish them without a kind lookup.

        The plaintext bearer token is stored in ``nhi:token:{nhi_id}`` (NOT a
        bcrypt hash) for fast per-request hmac.compare_digest by the gateway.
        The gateway's ``_state.token_role_map`` is refreshed by calling
        ``get_nhi_token_map()`` after each NHI registration.

        ``svid_issued`` is ``False`` at creation — admin approval (``approve_svid``)
        transitions it to ``True``.  All gateway invocations of an NHI where
        ``svid_issued=False`` return 403 ``NHI_PENDING_APPROVAL``.

        Returns (nhi_id, plaintext_token).  The plaintext token is passed to the
        NHI container as ``YASHIGANI_NHI_TOKEN`` and stored in the secret mount.
        It is NEVER stored again after this call — treat it like a one-time secret.

        Does not enforce the licence agent-count limit (NHIs are governed by a
        separate NHI-instance limit that defaults to the licence's max_agents cap).
        """
        nhi_id = f"nhi_{uuid.uuid4().hex[:12]}"
        plaintext_token = secrets.token_bytes(32).hex()
        now = _now_iso()

        hset_pairs = {
            "name":                    name,
            "upstream_url":            "",          # populated by PoolManager at container start
            "protocol":                "openai",
            "status":                  "active",
            "kind":                    "nhi",
            "template_id":             template_id,
            "owner_identity_id":       owner_identity_id,
            "allowed_tools":           json.dumps(allowed_tools),
            "allowed_paths":           json.dumps(allowed_paths),
            "allowed_models":          json.dumps(allowed_models),
            "sensitivity_ceiling":     sensitivity_ceiling,
            "budget_cap":              json.dumps(budget_cap),
            "pids_limit":              str(pids_limit),
            "memory_mb":               str(memory_mb),
            "spiffe_id":               spiffe_id,
            "scope_hash":              scope_hash,
            "svid_issued":             "0",
            "created_at":              now,
            "last_seen_at":            "",
            "groups":                  json.dumps([]),
            "allowed_caller_groups":   json.dumps([]),
            "allowed_cidrs":           json.dumps([]),
        }

        reg_key = f"agent:reg:{nhi_id}"
        token_key = f"nhi:token:{nhi_id}"

        pipe = self._r.pipeline()
        pipe.hset(reg_key, mapping={
            k.encode("utf-8"): v.encode("utf-8") for k, v in hset_pairs.items()
        })
        # Plaintext token — fast gateway lookup (NOT bcrypt)
        pipe.set(token_key, plaintext_token.encode("utf-8"))
        pipe.sadd("agent:index:all", nhi_id.encode("utf-8"))
        # NHI is NOT in agent:index:active until svid_issued=1
        pipe.execute()

        logger.info(
            "AgentRegistry: NHI registered nhi_id=%s name=%r owner=%r svid_issued=False",
            nhi_id, name, owner_identity_id,
        )

        if self._durable is not None:
            try:
                # YSG-RISK-155: use the freshly-decoded Redis record (via get())
                # instead of a hand-built partial dict. get() decodes kind="nhi"
                # and includes ALL NHI fields (template_id, owner_identity_id,
                # allowed_models, budget_cap, svid_issued, pids_limit, memory_mb,
                # spiffe_id, scope_hash) — the previous partial dict carried only
                # agent_id/name/upstream_url/protocol/status/groups/allowed_*,
                # silently dropping every NHI-specific field even when the
                # underlying upsert() bug (dead UPDATE-only branch on a brand-new
                # row) is fixed. token_hash stays None — an NHI's plaintext
                # bearer token is a one-time secret and is NEVER durably
                # persisted (see this method's docstring); durable_store.upsert()
                # now permits a NULL token_hash for kind="nhi" rows (migration
                # 0030) so the INSERT still succeeds.
                full = self.get(nhi_id)
                if full is not None:
                    self._durable.upsert(full, token_hash=None)
            except Exception as exc:
                logger.error(
                    "AgentRegistry: DURABLE write failed for NHI %s — the NHI is live in "
                    "Redis but will NOT survive a redis recreate until re-registered: %s",
                    nhi_id, exc,
                )
                _record_durable_write_failure("register_nhi", "nhi")

        return nhi_id, plaintext_token

    def approve_svid(self, nhi_id: str) -> None:
        """Set ``svid_issued=1`` and add the NHI to the active index.

        Called by the admin-approval endpoint after the PKI leaf cert is issued.
        Post-call: the gateway's ``_state.token_role_map`` must be refreshed
        (call ``get_nhi_token_map()`` and reload) so the NHI token is recognised.

        Raises ``KeyError`` if ``nhi_id`` does not exist or is not an NHI.
        """
        reg_key = f"agent:reg:{nhi_id}"
        raw = self._r.hgetall(reg_key)
        if not raw:
            raise KeyError(f"NHI {nhi_id!r} not found in registry")

        kind_raw = raw.get(b"kind", b"")
        kind = kind_raw.decode("utf-8") if isinstance(kind_raw, bytes) else kind_raw
        if kind != "nhi":
            raise KeyError(f"{nhi_id!r} is not an NHI entry (kind={kind!r})")

        pipe = self._r.pipeline()
        # BUG-4.0-LANGFLOW-TOKEN-PERMS / consistent mapping form:
        # Use mapping= kwarg (redis-py v4+ canonical; compatible with all
        # fakeredis versions). The old positional pipe.hset(key, field, val)
        # form is incompatible with some fakeredis pipeline implementations.
        pipe.hset(reg_key, mapping={b"svid_issued": b"1"})
        pipe.sadd("agent:index:active", nhi_id.encode("utf-8"))
        pipe.sadd("nhi:index:active", nhi_id.encode("utf-8"))
        pipe.execute()
        logger.info("AgentRegistry: NHI %s SVID approved — now executable", nhi_id)

        # YSG-RISK-155: mirror svid_issued=True into the durable store. Without
        # this, an NHI approved via this method restores from a redis wipe with
        # svid_issued=False (its durable row would still show the pre-approval
        # state) — i.e. an already-executable NHI would come back as
        # pending-approval, contradicting "restore an NHI with its NHI fields
        # intact". Best-effort/logged, same as every other durable dual-write —
        # the approval itself already succeeded in Redis and must not roll back.
        if self._durable is not None:
            try:
                full = self.get(nhi_id)
                if full is not None:
                    self._durable.upsert(full, token_hash=None)
            except Exception as exc:
                logger.error(
                    "AgentRegistry: DURABLE svid-approval write failed for NHI %s — Postgres "
                    "mirror stale (would restore as pending-approval) until next mutation: %s",
                    nhi_id, exc,
                )
                _record_durable_write_failure("approve_svid", "nhi")

    def get_nhi_token_map(self) -> dict[str, str]:
        """Return {plaintext_token: nhi_id} for all active NHIs (svid_issued=1).

        Called at gateway startup (and after NHI approval) to populate
        ``_state.token_role_map`` for fast hmac.compare_digest on every request.

        Only NHIs with ``svid_issued=1`` are included — pending-approval NHIs are
        not resolvable and their tokens are not distributed yet (still in secrets/).
        """
        active_nhis: set[str] = {
            v.decode("utf-8") if isinstance(v, bytes) else v
            for v in self._r.smembers("nhi:index:active")
        }
        result: dict[str, str] = {}
        for nhi_id in active_nhis:
            token_key = f"nhi:token:{nhi_id}"
            raw = self._r.get(token_key)
            if raw:
                token = raw.decode("utf-8") if isinstance(raw, bytes) else raw
                result[token] = nhi_id
        return result

    # ── Counts ────────────────────────────────────────────────────────────────

    def count(self, status: str = "active") -> int:
        """Return count of agents by status ('active' or 'inactive' or 'all')."""
        if status == "active":
            return self._r.scard("agent:index:active") or 0
        if status == "all":
            return self._r.scard("agent:index:all") or 0
        # inactive = all - active
        total = self._r.scard("agent:index:all") or 0
        active = self._r.scard("agent:index:active") or 0
        return max(0, total - active)

    # ── Internal ─────────────────────────────────────────────────────────────

    def _update_last_seen(self, agent_id: str) -> None:
        reg_key = f"agent:reg:{agent_id}"
        self._r.hset(reg_key, b"last_seen_at", _now_iso().encode("utf-8"))

    @staticmethod
    def _decode_agent(agent_id: str, raw: dict) -> dict:
        """Decode a Redis HGETALL hash into a Python dict.

        FIND-IRIS-DUP-AGENT (2026-08-04): this used to look up ``raw`` with
        bytes-literal keys only (``raw.get(b"name", b"")``), which silently
        returned the empty-string default for EVERY field whenever the
        redis-py client was constructed with ``decode_responses=True`` (that
        client returns str keys/values from HGETALL, so a bytes-key lookup
        never matches). install.sh's inline agent-bootstrap script used
        exactly such a client to call ``AgentRegistry(...).list_all()`` for
        its "already registered by name?" idempotency check — every existing
        agent decoded with ``name=""``, so the name-membership check always
        missed and ``--upgrade`` re-registered langflow/letta with a brand
        new agent_id + fresh token on every run (2 -> 4 -> 6 ... active rows,
        old tokens never revoked). Root-caused live via
        ``docker/secrets/{langflow,letta}_token`` sha256 diffs across an
        upgrade. Fixed here (not in the decode_responses=True call site)
        so every caller of this registry is correct regardless of which
        redis-py decode_responses setting it happens to use — normalise
        ``raw``'s keys to str up front, tolerating both bytes-keyed
        (decode_responses=False, the historical/majority convention) and
        str-keyed (decode_responses=True) hashes transparently.
        """
        _norm: dict = {
            (k.decode("utf-8") if isinstance(k, bytes) else k): v
            for k, v in raw.items()
        }

        def _b(key: bytes) -> str:
            name = key.decode("utf-8") if isinstance(key, bytes) else key
            val = _norm.get(name, "")
            return val.decode("utf-8") if isinstance(val, bytes) else val

        def _j(key: bytes) -> list:
            try:
                return json.loads(_b(key))
            except Exception:
                return []

        upstream_url = _b(b"upstream_url")
        # v2.4.1 — pool_image: derived from upstream_url when it uses pool:// scheme.
        # Stored as pool://<image>; surfaced as a separate convenience field so
        # callers can distinguish pool-managed from externally-deployed agents.
        pool_image = upstream_url[len("pool://"):] if upstream_url.startswith("pool://") else None

        # NHI fields (4.0 Phase 3 — RISK-097). Present only when kind="nhi";
        # empty/default values for legacy bundled-agent entries.
        kind = _b(b"kind") or "agent"

        # 4.0 Phase 5 / §A.3: sensitivity_ceiling — stored as empty string when None;
        # surface as None so callers can use `if agent["sensitivity_ceiling"]`.
        _raw_ceiling = _b(b"sensitivity_ceiling")
        _sensitivity_ceiling: Optional[str] = _raw_ceiling if _raw_ceiling else None

        result: dict = {
            "agent_id": agent_id,
            "name": _b(b"name"),
            "upstream_url": upstream_url,
            "protocol": _b(b"protocol") or "openai",
            # YSG-RISK/TD-2026-07-25-02: every OTHER field with real semantic
            # weight here (kind, protocol) already falls back with `or` when
            # the Redis hash field is empty/absent — "status" was the one
            # exception, decoding to "" (never "active") for any record whose
            # status field was never explicitly HSET. An agent/nhi identity
            # is active by construction unless explicitly deactivated (which
            # DOES write status=b"inactive" — see deactivate()); "" is not a
            # real state and must not be distinguishable from "active" by any
            # downstream status=="active" gate (ASVS V4.1.3 default-secure).
            "status": _b(b"status") or "active",
            "kind": kind,
            "created_at": _b(b"created_at"),
            "last_seen_at": _b(b"last_seen_at"),
            "groups": _j(b"groups"),
            "allowed_caller_groups": _j(b"allowed_caller_groups"),
            "allowed_paths": _j(b"allowed_paths"),
            "allowed_cidrs": _j(b"allowed_cidrs"),
            # v0.9.0 — token rotation fields (F-09)
            "token_last_rotated": _b(b"token_last_rotated"),
            "token_rotation_schedule": _b(b"token_rotation_schedule"),
            # v2.4.1 — pool_image (None for externally-deployed agents)
            "pool_image": pool_image,
            # 4.0 Phase 5 / §A.3 — NHI + callee agent metadata (additive; absent in
            # pre-4.0 entries → default values applied here for backward compat).
            "sensitivity_ceiling": _sensitivity_ceiling,
            "allowed_tools": _j(b"allowed_tools"),
        }

        if kind == "nhi":
            result.update({
                "template_id":         _b(b"template_id"),
                "owner_identity_id":   _b(b"owner_identity_id"),
                "allowed_tools":       _j(b"allowed_tools"),
                "allowed_models":      _j(b"allowed_models"),
                "sensitivity_ceiling": _b(b"sensitivity_ceiling") or "PUBLIC",
                "budget_cap":          _j(b"budget_cap") or {},
                "svid_issued":         _b(b"svid_issued") == "1",
                "scope_hash":          _b(b"scope_hash"),
                "image_digest":        _b(b"image_digest"),
                "pids_limit":          int(_b(b"pids_limit") or "64"),
                "memory_mb":           int(_b(b"memory_mb") or "512"),
                "spiffe_id":           _b(b"spiffe_id"),
            })

        return result
