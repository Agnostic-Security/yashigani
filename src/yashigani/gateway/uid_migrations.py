"""
Yashigani 3.1 UID unification — startup migrations.

migrate_rbac_to_identity_id
    Re-keys RBAC user membership from email/slug → identity_id.
    Must run before any request is served after the 3.1 deploy.

migrate_perm_grants_to_identity_id
    Re-keys permission grants from perm:grant:*:user:{email-or-slug}:*
    to perm:grant:*:user:{identity_id}:*.
    Also migrates perm:browser_cap:user:{} and perm:idx:*:user:{}.

Both functions are IDEMPOTENT (safe to run again if interrupted):
    - Already-migrated keys (scope_id starts with "idnt_") are skipped.
    - Unmapped email entries are logged at CRITICAL and treated fail-closed
      (removed from the store; those users lose group/grant access until an
      operator re-adds them with the correct identity_id via the admin API).
    - Leaving an unmapped DENY grant as-is would make it inert (the reader
      now queries by identity_id → key miss → the DENY silently becomes ALLOW).
      Removal is the safe fail-closed posture for both migrations.

Ordering: run in lifespan startup AFTER identity_registry is connected
and BEFORE the first request is served.  Both are synchronous (Redis calls)
and expected to complete in < 1 second on a fresh install.

3.1 UID unification — Iris spec §5.
"""
from __future__ import annotations

import logging

_KEY_USER = "rbac:user:{}"   # mirrored from rbac/store.py

logger = logging.getLogger(__name__)


def migrate_rbac_to_identity_id(rbac_store, identity_registry) -> None:
    """
    Re-key RBAC user membership from email → identity_id.

    Scans every RBACGroup.members set.  For each member that is NOT already
    an identity_id (does not start with "idnt_"), resolves via the identity
    registry (get_by_email, then get_by_slug as fallback).  Re-keys the
    Redis user→group index from the old key to the new identity_id key.

    Unmapped members are REMOVED from the group and logged at CRITICAL.
    The group JSON is rewritten with the identity_id member set.

    Fail-closed: unmapped members lose group access (never silently allowed).
    Idempotent: running a second time on an already-migrated store is safe.
    """
    log = logging.getLogger("yashigani.migration.rbac_uid")
    unmapped: list[tuple[str, str]] = []

    for group in rbac_store.list_groups():
        old_members: set[str] = set(group.members)
        new_members: set[str] = set()

        for member in old_members:
            if member.startswith("idnt_") or member.startswith("agnt_"):
                # Already an identity_id — carry forward unchanged.
                new_members.add(member)
                continue

            identity = None
            try:
                if "@" in member:
                    identity = identity_registry.get_by_email(member)
                if identity is None:
                    # Try slug lookup (covers test envs where email=slug was stored)
                    identity = identity_registry.get_by_slug(member)
            except Exception as exc:
                log.error(
                    "rbac migration: registry lookup failed for %r in group %r: %s",
                    member, group.id, exc,
                )

            if identity is not None:
                iid = (
                    identity.get("identity_id")
                    if isinstance(identity, dict)
                    else getattr(identity, "identity_id", None)
                )
                if iid:
                    new_members.add(iid)
                    log.info(
                        "rbac migration: %r → %r (group %r)", member, iid, group.id
                    )
                else:
                    unmapped.append((group.id, member))
                    log.error(
                        "rbac migration: identity for %r in group %r has no identity_id "
                        "field — REMOVED from group",
                        member, group.id,
                    )
            else:
                unmapped.append((group.id, member))
                log.error(
                    "rbac migration: %r in group %r has NO registered identity — "
                    "REMOVED from group",
                    member, group.id,
                )

        # Delete old email-keyed Redis index entries
        for member in old_members:
            if not (member.startswith("idnt_") or member.startswith("agnt_")):
                try:
                    rbac_store._redis.srem(_KEY_USER.format(member), group.id)
                    rbac_store._redis.delete(_KEY_USER.format(member))
                except Exception as exc:
                    log.warning(
                        "rbac migration: failed to clean up old key for %r: %s",
                        member, exc,
                    )

        # Overwrite group with identity_id members + rebuild index
        group.members = new_members
        try:
            rbac_store.add_group(group)
        except Exception as exc:
            log.error(
                "rbac migration: failed to rewrite group %r: %s", group.id, exc
            )

    if unmapped:
        log.critical(
            "rbac migration INCOMPLETE: %d member(s) could not be mapped to "
            "identity_ids: %s. "
            "These users have been REMOVED from their groups. Review immediately.",
            len(unmapped), unmapped,
        )
        # Do NOT abort startup — alert loudly. Those users are now group-less
        # (fail-closed for group-tier narrowing).
    else:
        log.info("rbac migration: completed — all members re-keyed to identity_id")


def migrate_perm_grants_to_identity_id(perm_store, identity_registry) -> None:
    """
    Re-key permission grants from perm:grant:*:user:{email-or-slug}:*
    to perm:grant:*:user:{identity_id}:*.

    Also migrates:
      perm:browser_cap:user:{email-or-slug}
      perm:idx:{resource_type}:user:{email-or-slug}

    Keys whose scope_id already starts with "idnt_" are skipped (idempotent).
    Unmapped scope_ids (no registry match) are DELETED and logged at CRITICAL —
    fail-closed, matching the rbac migration. Leaving an old email-keyed DENY
    grant in place would make it silently inert (the reader now keys on
    identity_id), i.e. a DENY that stops denying; an unmapped scope_id also means
    the principal cannot authenticate, so removal is safe. The CRITICAL log lets
    an operator re-issue the grant against the correct identity_id.

    Idempotent: safe to run multiple times.
    """
    log = logging.getLogger("yashigani.migration.perm_uid")

    patterns = [
        "perm:grant:*:user:*",
        "perm:browser_cap:user:*",
        "perm:idx:*:user:*",
    ]

    for pattern in patterns:
        cursor = 0
        while True:
            try:
                cursor, keys = perm_store._redis.scan(
                    cursor, match=pattern, count=200
                )
            except Exception as exc:
                log.error(
                    "perm migration: Redis scan failed for pattern %r: %s", pattern, exc
                )
                break

            for raw_key in keys:
                key = raw_key.decode() if isinstance(raw_key, bytes) else raw_key
                parts = key.split(":")

                # Identify scope_id field position by key prefix
                if key.startswith("perm:grant:"):
                    # perm:grant:{resource_type}:user:{scope_id}:{resource_id}
                    # idx:  0    1      2         3     4           5
                    if len(parts) < 6 or parts[3] != "user":
                        continue
                    scope_id = parts[4]
                elif key.startswith("perm:browser_cap:user:"):
                    # perm:browser_cap:user:{scope_id}
                    # idx:  0    1          2    3
                    if len(parts) < 4:
                        continue
                    scope_id = parts[3]
                elif key.startswith("perm:idx:"):
                    # perm:idx:{resource_type}:user:{scope_id}
                    # idx:  0   1    2         3     4
                    if len(parts) < 5 or parts[3] != "user":
                        continue
                    scope_id = parts[4]
                else:
                    continue

                # Already identity_id — skip
                if scope_id.startswith("idnt_") or scope_id.startswith("agnt_"):
                    continue

                # Resolve scope_id to identity_id
                identity = None
                try:
                    if "@" in scope_id:
                        identity = identity_registry.get_by_email(scope_id)
                    if identity is None:
                        identity = identity_registry.get_by_slug(scope_id)
                except Exception as exc:
                    log.warning(
                        "perm migration: registry lookup failed for %r: %s", scope_id, exc
                    )

                if identity is not None:
                    new_scope_id = (
                        identity.get("identity_id")
                        if isinstance(identity, dict)
                        else getattr(identity, "identity_id", None)
                    )
                    if new_scope_id and new_scope_id != scope_id:
                        new_key = key.replace(
                            f":user:{scope_id}", f":user:{new_scope_id}", 1
                        )
                        try:
                            val = perm_store._redis.get(raw_key)
                            if val is not None:
                                perm_store._redis.set(new_key, val)
                            perm_store._redis.delete(raw_key)
                            log.info("perm migration: %s → %s", key, new_key)
                        except Exception as exc:
                            log.error(
                                "perm migration: failed to re-key %s → %s: %s",
                                key, new_key, exc,
                            )
                    # else: scope_id is already identity_id or same value
                else:
                    # GAP-3 fix: unmapped scope_id → CRITICAL + DELETE.
                    # Leaving the key at the old email/slug address is UNSAFE:
                    # the reader now queries by identity_id (idnt_*), so the
                    # old key is never matched — a DENY grant silently becomes
                    # ALLOW (fail-open). Remove the key and log at CRITICAL so
                    # an operator can re-add it via PUT /admin/api/grants once
                    # the identity is registered. Consistent with
                    # migrate_rbac_to_identity_id which REMOVES unmapped members.
                    log.critical(
                        "perm migration: scope_id %r has no registered identity — "
                        "grant REMOVED to prevent inert DENY silently becoming ALLOW. "
                        "Re-add via PUT /admin/api/grants once the identity is "
                        "registered (GET /admin/api/identities for identity_id).",
                        scope_id,
                    )
                    try:
                        perm_store._redis.delete(raw_key)
                    except Exception as _del_exc:
                        log.error(
                            "perm migration: failed to remove orphaned key %s: %s",
                            key, _del_exc,
                        )

            if cursor == 0:
                break

    log.info("perm migration: completed")
