"""
Feature gate enforcement.

The active license is loaded once at startup and cached in module state.
All gate functions are synchronous — called from FastAPI route handlers.
"""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from yashigani.licensing.model import COMMUNITY_LICENSE, LicenseState, LicenseTier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level license state
# ---------------------------------------------------------------------------

_license: LicenseState = COMMUNITY_LICENSE

# Module-level integrity state (T1)
_enforcer_integrity_violated = False


def _emit_licence_integrity_violation_event(
    module: str,
    check_type: str,
    expected_hash: str,
    actual_hash: str,
    classification: str = "unknown",
) -> None:
    """Emit a typed LicenceIntegrityViolationEvent (defence-in-depth — never raises)."""
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
            module=module,
            check_type=check_type,
            expected_hash=expected_hash[:16],
            actual_hash=actual_hash[:16],
        )
        event._internal_classification = classification
        writer.write(event)
    except Exception:
        pass


def _check_enforcer_integrity() -> None:
    """
    T1: Self-check enforcer.py SHA-256 against _integrity.ENFORCER_HASH.
    Also cross-checks verifier.py against _integrity.VERIFIER_HASH.
    Sets _enforcer_integrity_violated = True on any mismatch.
    Called at module load (DG-04: consuming module, not _integrity.py).
    """
    global _enforcer_integrity_violated
    from yashigani.licensing import _integrity

    is_dev = os.environ.get("YASHIGANI_ENV") == "dev"

    # Self-check
    if _integrity.is_enforcer_hash_placeholder():
        if not is_dev:
            _enforcer_integrity_violated = True
            logger.critical(
                "LICENSE INTEGRITY VIOLATION: ENFORCER_HASH is still a placeholder "
                "in a non-dev environment; forcing COMMUNITY tier (T1)"
            )
        return

    try:
        digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except Exception as exc:
        logger.warning("License integrity: could not read enforcer.py for hash check: %s", exc)
        return

    if digest != _integrity.ENFORCER_HASH:
        _enforcer_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: enforcer.py has been tampered with "
            "(expected=%s, actual=%s); forcing COMMUNITY tier (T1)",
            _integrity.ENFORCER_HASH[:16],
            digest[:16],
        )
        _emit_licence_integrity_violation_event(
            module="enforcer",
            check_type="self_hash",
            expected_hash=_integrity.ENFORCER_HASH,
            actual_hash=digest,
        )

    # Cross-check verifier.py
    if _integrity.is_verifier_hash_placeholder():
        return  # already handled by verifier's own check

    try:
        verifier_path = Path(__file__).parent / "verifier.py"
        v_digest = hashlib.sha256(verifier_path.read_bytes()).hexdigest()
    except Exception as exc:
        logger.warning("License integrity: could not read verifier.py for cross-check: %s", exc)
        return

    if v_digest != _integrity.VERIFIER_HASH:
        _enforcer_integrity_violated = True
        logger.critical(
            "LICENSE INTEGRITY VIOLATION: verifier.py cross-check failed from enforcer "
            "(expected=%s, actual=%s); forcing COMMUNITY tier (T1)",
            _integrity.VERIFIER_HASH[:16],
            v_digest[:16],
        )
        _emit_licence_integrity_violation_event(
            module="enforcer",
            check_type="cross_hash",
            expected_hash=_integrity.VERIFIER_HASH,
            actual_hash=v_digest,
        )


def get_enforcer_integrity_status() -> bool:
    """Return True if the enforcer integrity has been violated."""
    return _enforcer_integrity_violated


def _emit_set_license_audit(lic: LicenseState) -> None:
    """Emit a LicenceStateSetEvent on every set_license() call (T8)."""
    try:
        import inspect
        from yashigani.audit.schema import LicenceStateSetEvent
        try:
            from yashigani.backoffice.state import backoffice_state
            writer = getattr(backoffice_state, "audit_writer", None)
        except Exception:
            writer = None
        if writer is None:
            return
        frame = inspect.stack()[2] if len(inspect.stack()) > 2 else None
        caller = frame.filename.split("/")[-1].replace(".py", "") if frame else "unknown"
        event = LicenceStateSetEvent(
            tier=lic.tier.value,
            org_domain=lic.org_domain,
            license_id=lic.license_id or "",
            caller_module=caller,
        )
        writer.write(event)
    except Exception:
        pass


def set_license(lic: LicenseState) -> None:
    """Set the active license. Called once at startup. Emits a LicenceStateSetEvent (T8)."""
    global _license
    _license = lic
    _emit_set_license_audit(lic)


def get_license() -> LicenseState:
    """
    Return the currently active license.

    T5: Checks ALL five integrity flags (verifier, enforcer, loader,
    agents_registry, identity_registry). If ANY flag is True → returns
    COMMUNITY_LICENSE. Lazy imports to avoid circular dependencies.
    """
    # Verifier integrity (lazy import — circular-safe)
    try:
        from yashigani.licensing.verifier import get_integrity_status as _v_status
        if _v_status():
            return COMMUNITY_LICENSE
    except Exception:
        pass  # verifier unavailable — conservative: don't block

    if _enforcer_integrity_violated:
        return COMMUNITY_LICENSE

    try:
        from yashigani.licensing.loader import get_loader_integrity_status as _l_status
        if _l_status():
            return COMMUNITY_LICENSE
    except Exception:
        pass

    try:
        from yashigani.agents.registry import get_agents_registry_integrity_status as _a_status
        if _a_status():
            return COMMUNITY_LICENSE
    except Exception as _exc_agents:
        # IMPL-03: import failure of an integrity module is treated as a
        # violation — an attacker who can cause the import to fail while
        # having patched agents/registry.py would otherwise bypass this check.
        # Log critical and fail to Community rather than silently pass.
        logger.critical(
            "License gate: failed to import agents.registry integrity check — "
            "treating as integrity violation and restraining to Community (IMPL-03): %s",
            _exc_agents,
        )
        return COMMUNITY_LICENSE

    try:
        from yashigani.identity.registry import get_identity_registry_integrity_status as _id_status
        if _id_status():
            return COMMUNITY_LICENSE
    except Exception as _exc_identity:
        # IMPL-03: same treatment as agents.registry — import failure → Community.
        logger.critical(
            "License gate: failed to import identity.registry integrity check — "
            "treating as integrity violation and restraining to Community (IMPL-03): %s",
            _exc_identity,
        )
        return COMMUNITY_LICENSE

    return _license


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class LicenseFeatureGated(Exception):
    def __init__(self, feature: str, tier: LicenseTier) -> None:
        self.feature = feature
        self.tier = tier
        super().__init__(f"Feature '{feature}' is not available on {tier.value} tier")


class LicenseLimitExceeded(Exception):
    def __init__(self, limit_name: str, current: int, max_val: int) -> None:
        self.limit_name = limit_name
        self.current = current
        self.max_val = max_val
        super().__init__(
            f"License limit exceeded: {limit_name} ({current}/{max_val})"
        )


# ---------------------------------------------------------------------------
# Features that are always available regardless of tier (ENT-001, 2026-06-14)
# ---------------------------------------------------------------------------
# PII detection (LOG / REDACT / BLOCK) is available on every tier including
# Community/free.  This aligns with README §8 Feature Matrix (only OIDC/SAML/SCIM
# are tier-gated) and the product narrative "PII filtering runs on all traffic,
# by default".  The LicenseFeature enum values are kept for back-compat with
# license payloads issued under v2.2 that carry pii_log/pii_redact in their
# features claim — but those claims are never *required* at gate time.

_ALWAYS_AVAILABLE_FEATURES: frozenset[str] = frozenset({"pii_log", "pii_redact"})


# ---------------------------------------------------------------------------
# Gate functions
# ---------------------------------------------------------------------------

def require_feature(feature: str) -> None:
    """Raise LicenseFeatureGated if feature not in active license.

    Features listed in _ALWAYS_AVAILABLE_FEATURES are unconditionally permitted
    regardless of tier or what the license payload carries.
    """
    if feature in _ALWAYS_AVAILABLE_FEATURES:
        return  # ENT-001: PII is always available
    if not _license.has_feature(feature):
        raise LicenseFeatureGated(feature=feature, tier=_license.tier)


def check_agent_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_agents (and max != -1)."""
    if _license.max_agents == -1:
        return
    if current_count >= _license.max_agents:
        raise LicenseLimitExceeded(
            limit_name="max_agents",
            current=current_count,
            max_val=_license.max_agents,
        )


def check_end_user_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_end_users (and max != -1)."""
    if _license.max_end_users == -1:
        return
    if current_count >= _license.max_end_users:
        raise LicenseLimitExceeded(
            limit_name="max_end_users",
            current=current_count,
            max_val=_license.max_end_users,
        )


def check_admin_seat_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_admin_seats (and max != -1)."""
    if _license.max_admin_seats == -1:
        return
    if current_count >= _license.max_admin_seats:
        raise LicenseLimitExceeded(
            limit_name="max_admin_seats",
            current=current_count,
            max_val=_license.max_admin_seats,
        )


def check_org_limit(current_count: int) -> None:
    """Raise LicenseLimitExceeded if current_count >= max_orgs (and max != -1)."""
    if _license.max_orgs == -1:
        return
    if current_count >= _license.max_orgs:
        raise LicenseLimitExceeded(
            limit_name="max_orgs",
            current=current_count,
            max_val=_license.max_orgs,
        )


# ---------------------------------------------------------------------------
# Canonical end-user count (GROUP-2-3 / v2.23.2)
# ---------------------------------------------------------------------------

def count_canonical_end_users() -> int:
    """
    Return the canonical end-user count as the union of three pools,
    deduplicated by lowercase email address.

    Pools:
      1. auth_service — Postgres users table (non-admin accounts)
      2. IdentityRegistry — Redis identity:index:kind:human members
      3. RBAC store — all group members via RBACStore.list_groups()

    Design note (2026-05-05): canonical count = union(auth_service users,
    IdentityRegistry HUMAN, RBAC users), deduped by lowercase email.

    Async caveat: auth_service uses async Postgres. When called from within a
    running asyncio event loop (FastAPI route handlers) we cannot use
    run_until_complete(). In that context the auth_service pool is skipped
    and only the synchronous Redis pools (identity_registry + RBAC) are counted.
    The caller (check_end_user_limit) is still called with the result; the count
    may be an undercount in that context but it is never zero for a non-empty
    deployment, and the atomicity of the Lua scripts in IdentityRegistry/
    AgentRegistry provides the primary enforcement barrier.

    Never raises — returns 0 on any error (fail-open for count, fail-closed for
    limit enforcement in the Lua scripts).
    """
    try:
        from yashigani.backoffice.state import backoffice_state
    except Exception:
        return 0

    emails: set[str] = set()

    # Pool 1: IdentityRegistry HUMAN members (synchronous Redis SMEMBERS)
    try:
        registry = getattr(backoffice_state, "identity_registry", None)
        if registry is not None:
            r = getattr(registry, "_r", None)
            if r is not None:
                members = r.smembers("identity:index:kind:human")
                for identity_id_raw in (members or []):
                    identity_id = (
                        identity_id_raw.decode("utf-8")
                        if isinstance(identity_id_raw, bytes)
                        else identity_id_raw
                    )
                    # Slug is not the email; use name as proxy or identity_id as fallback.
                    # We need the email field from the hash — not always present for
                    # HUMAN identities provisioned via SSO (email only in audit logs).
                    # Fall back to identity_id as a unique key — prevents double-counting
                    # entries without email fields.
                    try:
                        email_raw = r.hget(f"identity:reg:{identity_id}", "email")
                        if email_raw:
                            email = (
                                email_raw.decode("utf-8")
                                if isinstance(email_raw, bytes)
                                else email_raw
                            )
                            emails.add(email.strip().lower())
                        else:
                            # No email field — use identity_id as surrogate key
                            emails.add(f"__idnt__{identity_id}")
                    except Exception:
                        emails.add(f"__idnt__{identity_id}")
    except Exception as exc:
        logger.debug("count_canonical_end_users: identity_registry pool error: %s", exc)

    # Pool 2: RBAC store group members
    try:
        rbac = getattr(backoffice_state, "rbac_store", None)
        if rbac is not None:
            groups = rbac.list_groups()
            for group in (groups or []):
                for member_raw in (group.members if hasattr(group, "members") else []):
                    member = member_raw.strip().lower() if isinstance(member_raw, str) else ""
                    if member:
                        emails.add(member)
    except Exception as exc:
        logger.debug("count_canonical_end_users: rbac_store pool error: %s", exc)

    # Pool 3: auth_service (async — use Redis cache when event loop is running) (T13)
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if not loop.is_running():
            auth = getattr(backoffice_state, "auth_service", None)
            if auth is not None:
                count = loop.run_until_complete(auth.total_user_count())
                for i in range(count):
                    emails.add(f"__auth__{i}")
        else:
            # Event loop running (FastAPI context) — use Redis-cached count (T13)
            try:
                registry = getattr(backoffice_state, "identity_registry", None)
                if registry is not None:
                    r = getattr(registry, "_r", None)
                    if r is not None:
                        cached = r.get("license:count:auth_users")
                        if cached is not None:
                            count = int(
                                cached if isinstance(cached, int)
                                else (cached.decode("utf-8") if isinstance(cached, bytes) else cached)
                            )
                            for i in range(count):
                                emails.add(f"__auth__{i}")
            except Exception as exc:
                logger.debug("count_canonical_end_users: auth_cache pool error: %s", exc)
    except Exception as exc:
        logger.debug("count_canonical_end_users: auth_service pool error: %s", exc)

    return len(emails)


async def _sync_auth_user_count() -> None:
    """
    Background job: sync auth_service user count to Redis (T13).

    Wired into APScheduler in app.py as a 60s interval job.
    """
    try:
        from yashigani.backoffice.state import backoffice_state
        auth = getattr(backoffice_state, "auth_service", None)
        if auth is None:
            return
        count = await auth.total_user_count()
        registry = getattr(backoffice_state, "identity_registry", None)
        if registry is None:
            return
        r = getattr(registry, "_r", None)
        if r is None:
            return
        r.set("license:count:auth_users", str(count))
    except Exception as exc:
        logger.debug("_sync_auth_user_count: %s", exc)


# ---------------------------------------------------------------------------
# FastAPI exception handler helpers
# ---------------------------------------------------------------------------

# Which tier unlocks each feature — used in upgrade messages.
# ENT-001 (2026-06-14): pii_log/pii_redact removed — PII is always available
# and will never reach this lookup via license_feature_gated_response().
_FEATURE_UPGRADE_TIER: dict[str, str] = {
    "oidc":  "Starter",
    "saml":  "Professional",
    "scim":  "Professional",
}


def license_feature_gated_response(exc: LicenseFeatureGated) -> dict:
    upgrade_tier = _FEATURE_UPGRADE_TIER.get(exc.feature, "Professional")
    return {
        "error": "LICENSE_FEATURE_GATED",
        "feature": exc.feature,
        "tier": exc.tier.value,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": f"{exc.feature.upper()} requires {upgrade_tier} or higher",
    }


def license_limit_exceeded_response(exc: LicenseLimitExceeded) -> dict:
    tier = _license.tier.value
    limit_label = {
        "max_agents":      "Agent",
        "max_end_users":   "End user",
        "max_admin_seats": "Admin seat",
        "max_orgs":        "Organization",
    }.get(exc.limit_name, exc.limit_name)
    return {
        "error": "LICENSE_LIMIT_EXCEEDED",
        "limit": exc.limit_name,
        "current": exc.current,
        "maximum": exc.max_val,
        "tier": tier,
        "upgrade_url": "https://agnosticsec.com/pricing",
        "message": (
            f"{limit_label} limit reached ({exc.current}/{exc.max_val}). "
            f"Upgrade your license at yashigani.io/pricing."
        ),
    }


# Run integrity check at module load (T1 / DG-04)
_check_enforcer_integrity()
