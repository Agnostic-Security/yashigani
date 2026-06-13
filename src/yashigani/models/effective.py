"""
Yashigani Models — Effective allowed-models resolution (Track B1).

THE ENFORCEMENT CORE. Given a caller identity, the live allocation store and the
alias store, compute the EFFECTIVE set of models the caller may use:

    effective = identity.allowed_models
              ∪ aliases allocated to the identity's org
              ∪ aliases allocated to each of the identity's groups
              ∪ aliases allocated to the user directly

Each allocated *alias* is expanded so the effective set carries BOTH the alias
name (e.g. ``smart``) AND the concrete model behind it (e.g. ``claude-sonnet-4-6``).
This matters because:
  • the caller may request a model by ALIAS (``body.model == "smart"``), and
  • the optimisation engine resolves aliases and returns the CONCRETE model
    name in ``RoutingDecision.model`` — which is what OPA's ``model_allowed``
    rule checks against ``input.identity.allowed_models``.
Carrying both forms guarantees the OPA check and the optimiser-binding check
agree regardless of which form reaches them.

DENY-BY-DEFAULT / EMPTY-SCOPE SEMANTICS (load-bearing, fail-closed):
  • A caller with a non-empty effective set is restricted to EXACTLY that set
    (OPA ``model_allowed`` Flow 1 only opens up on an EMPTY list, so a non-empty
    effective set is a true allowlist).
  • ``has_restriction`` is True when the caller's own ``allowed_models`` is
    non-empty OR any allocation applies to one of the caller's scopes (even an
    allocation whose alias fails to resolve). When ``has_restriction`` is True
    but the effective set is empty (e.g. every allocated alias is dangling), the
    caller can call NOTHING — fail-closed, never fail-open.
  • A caller with NO own allowed_models and NO applicable allocation is
    unrestricted (effective set empty, ``has_restriction`` False) — preserving
    the pre-existing "empty allowed_models == all models" behaviour for
    deployments that have configured no model RBAC at all.

The resolver NEVER raises on a store blip: on any internal error it returns a
fail-closed result (``has_restriction=True`` with whatever was resolved) so a
transient fault cannot silently grant unrestricted access.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class EffectiveModels:
    """Result of effective-allowed-models resolution for one caller."""

    # The allowlist fed to OPA input.identity.allowed_models. Carries alias
    # names AND concrete model names. Empty + has_restriction=False means
    # "unrestricted" (legacy empty-allowlist == all).
    allowed: set[str] = field(default_factory=set)
    # True iff a restriction applies (own allowed_models non-empty OR any
    # allocation touches one of the caller's scopes). When True and allowed is
    # empty, the caller may call nothing.
    has_restriction: bool = False
    # Aliases that were allocated to the caller's scopes (for audit/debug).
    allocated_aliases: set[str] = field(default_factory=set)
    # GLOBAL gating set: every model (alias name + concrete) that is allocated to
    # SOME scope. Once a model is allocation-gated, a caller who is not allocated
    # it must be DENIED that specific model — even if otherwise unrestricted.
    # This is what makes "a user NOT in group G is denied model X (allocated only
    # to G)" hold, while non-gated models stay open for unrestricted callers.
    gated: set[str] = field(default_factory=set)

    def is_model_denied(self, model: str) -> bool:
        """True iff *model* must be denied to this caller.

        Deny when:
          • a restriction applies and the model is not in the allowlist, OR
          • the model is allocation-gated globally and not in this caller's
            allowed set (gated-but-not-allocated → denied even for unrestricted
            callers).
        """
        if not model:
            return False
        if self.has_restriction and model not in self.allowed:
            return True
        if model in self.gated and model not in self.allowed:
            return True
        return False

    def pick_allowed_local_default(
        self, alias_store, global_default: str
    ) -> str | None:
        """LAURA-B1-OBS-1 — the LOCAL model this caller may be served as the
        optimiser's local fallback, or None when the global default is fine.

        The optimiser substitutes the global ``default_local`` (e.g. ``qwen2.5:3b``)
        in every local-route rule.  When that global default would be DENIED to
        this caller (``is_model_denied(global_default)``) but the caller IS
        allocated some OTHER local model, the optimiser must fall back to a model
        the caller can actually use — not the denied global default.

        Returns:
          • None when ``global_default`` is NOT denied (unrestricted/entitled
            caller, or no restriction) — the optimiser keeps legacy behaviour.
          • A concrete LOCAL model name from the caller's effective allowed set
            when the global default is denied AND such a local model exists.
          • None when the global default is denied and NO allowed local model
            exists — the optimiser keeps substituting the (denied) global default
            so the downstream alloc-bind re-check DENIES the truly-unallocated
            request (deny-by-default preserved; we never over-grant).

        "Local" means: an allowed entry whose alias resolves with provider
        ``ollama`` (or ``force_local``), OR a bare concrete model with no ``/``
        provider prefix and no resolvable cloud alias.  Cloud models are never
        offered here — substituting a cloud model for a local-route decision would
        violate the P1/P2/P3 data-residency guarantees.
        """
        if not self.is_model_denied(global_default):
            return None

        # First pass: resolve every allowed alias and partition the concrete
        # models behind them into LOCAL vs CLOUD.  A concrete model behind a CLOUD
        # alias (e.g. claude-sonnet-4-6 behind `smart`) is carried in `allowed`
        # too — we must NOT later mistake that bare name for a local model.
        cloud_concretes: set[str] = set()
        local_alias_models: list[str] = []  # concrete models behind LOCAL aliases
        alias_names: set[str] = set()
        for name in sorted(self.allowed):
            cfg = None
            if alias_store is not None:
                try:
                    cfg = alias_store.get(name)
                except Exception:  # noqa: BLE001 — store blip, treat as non-alias
                    cfg = None
            if cfg is None:
                continue
            alias_names.add(name)
            provider = (getattr(cfg, "provider", "") or "").strip().lower()
            concrete = (getattr(cfg, "model", "") or "").strip()
            if provider == "ollama" or getattr(cfg, "force_local", False):
                if concrete:
                    local_alias_models.append(concrete)
            else:
                # Cloud alias — never offer for a local-route fallback, and record
                # its concrete model so the bare-name pass below excludes it.
                if concrete:
                    cloud_concretes.add(concrete)

        # Prefer a concrete LOCAL model behind an allocated LOCAL alias.
        for concrete in local_alias_models:
            if not self.is_model_denied(concrete):
                return concrete

        # Then a bare concrete model name (no alias, no "/" provider prefix →
        # treated as a local Ollama model, matching engine._resolve_alias) — but
        # NEVER one that is the concrete behind a cloud alias (would route cloud
        # on a local-route decision, breaking P1/P2/P3 data residency).
        for name in sorted(self.allowed):
            if name in alias_names or name in cloud_concretes:
                continue
            if "/" not in name and not self.is_model_denied(name):
                return name

        return None

    def to_opa_allowed_models(self) -> list[str] | None:
        """The list to place in OPA input.identity.allowed_models.

        Returns None when the caller is fully unrestricted AND no model is
        globally gated — preserving the legacy "empty allowed_models == all"
        behaviour (caller's own list flows through unchanged).

        Otherwise returns a concrete allowlist. When a restriction applies but
        nothing resolved, returns a single non-matchable sentinel so OPA's
        ``model_allowed`` Flow 1 (empty == all) does NOT fire and every real
        model is denied (fail-closed).

        NOTE: OPA enforces the caller's positive allowlist; the GLOBAL gating of
        a model the caller isn't allocated is enforced in the gateway via
        ``is_model_denied`` (OPA's allowlist cannot express "deny X unless
        allocated" for an otherwise-unrestricted caller without the full model
        universe). The two together are belt-and-braces.
        """
        if self.allowed:
            return sorted(self.allowed)
        if self.has_restriction:
            return ["__yashigani_no_model_allocated__"]
        return None


def model_denied_for_caller(
    identity: Optional[dict],
    model: str,
    alloc_store,
    alias_store,
    *,
    brain_leg: bool = False,
) -> tuple[bool, "EffectiveModels"]:
    """THE SINGLE MODEL-RBAC AUTHORITY (Track B1 — seed/catalog/hop unification).

    One function every model-selection path consults to decide whether a
    (caller, concrete-or-alias model) pair must be DENIED.  It resolves the
    caller's EFFECTIVE allocation (own allowed_models ∪ org/group/user
    allocations, alias-expanded) and applies ``EffectiveModels.is_model_denied``
    — the same deny-by-default / fail-closed authority the chat egress uses.

    THE BRAIN/INTERNAL EXEMPTION (server-minted ONLY):
      ``brain_leg`` is the caller-computed, SERVER-MINTED brain-reasoning-leg
      marker (``is_brain_reasoning_leg`` — process-local round-trip counter +
      internal-bearer identity + the configured brain model).  It is NOT derived
      from any client header or letta-controllable input.  When True, the model
      is NEVER denied — the internal cognition leg (which holds no allocation and
      would otherwise be denied the gated brain model) must complete.

      CRITICALLY: a principal-bearing orchestration self-call (a model/agent tool
      hop) is NOT exempt here — it carries the REAL caller's identity and
      allocations, so the real caller's allocation is enforced on the hop.  Only
      the genuine internal-identity brain-reasoning leg passes ``brain_leg=True``.

    Returns ``(denied, effective)`` so callers can log the effective set without
    re-resolving.  Never raises (the resolver is fail-closed internally).
    """
    effective = resolve_effective_allowed_models(identity, alloc_store, alias_store)
    if brain_leg:
        return False, effective
    return effective.is_model_denied(model), effective


def _scope_aliases(alloc_store, target_type: str, target_id: str) -> tuple[set[str], bool]:
    """Aliases allocated to one scope + whether the scope has ANY allocation."""
    if not target_id:
        return set(), False
    try:
        aliases = alloc_store.aliases_for_scope(target_type, target_id)
        has = bool(aliases) or alloc_store.scope_has_allocation(target_type, target_id)
        return set(aliases), has
    except Exception as exc:  # store blip — fail-closed (treat as restricted)
        logger.warning(
            "effective-models: scope lookup failed (%s:%s): %s — fail-closed",
            target_type, target_id, exc,
        )
        return set(), True


def resolve_effective_allowed_models(
    identity: Optional[dict],
    alloc_store,
    alias_store,
) -> EffectiveModels:
    """Compute the EffectiveModels for *identity*.

    Args:
        identity:    resolved identity dict (may carry allowed_models, groups,
                     org_id, identity_id, slug, _owui_email).
        alloc_store: ModelAllocationStore (or None — then only own
                     allowed_models apply).
        alias_store: ModelAliasStore (or None — alias expansion to concrete
                     models is skipped; alias names are still carried).
    """
    if identity is None:
        return EffectiveModels()

    own = {str(m) for m in (identity.get("allowed_models") or [])}
    result = EffectiveModels(allowed=set(own), has_restriction=bool(own))

    if alloc_store is None:
        return result

    # Build the caller's scope identifiers.
    org_id = str(identity.get("org_id") or "")
    groups = [str(g) for g in (identity.get("groups") or [])]
    # A user may be addressed by identity_id, slug, or forwarded email — match
    # an allocation targeting ANY of these so the admin can allocate by whichever
    # handle they used in the UI.
    user_ids = [
        str(identity.get("identity_id") or ""),
        str(identity.get("slug") or ""),
        str(identity.get("_owui_email") or ""),
    ]

    allocated: set[str] = set()
    restricted = result.has_restriction

    try:
        a, h = _scope_aliases(alloc_store, "org", org_id)
        allocated |= a
        restricted = restricted or h
        for gid in groups:
            a, h = _scope_aliases(alloc_store, "group", gid)
            allocated |= a
            restricted = restricted or h
        for uid in user_ids:
            if not uid:
                continue
            a, h = _scope_aliases(alloc_store, "user", uid)
            allocated |= a
            restricted = restricted or h
    except Exception as exc:  # defensive — fail-closed
        logger.warning("effective-models: allocation resolution failed: %s — fail-closed", exc)
        restricted = True

    result.allocated_aliases = set(allocated)
    result.has_restriction = restricted

    def _expand(alias_name: str) -> set[str]:
        """{alias name, concrete model} for an alias (concrete only if resolvable)."""
        out = {alias_name}
        if alias_store is not None:
            try:
                cfg = alias_store.get(alias_name)
            except Exception as exc:
                logger.warning("effective-models: alias lookup failed for %r: %s", alias_name, exc)
                cfg = None
            if cfg is not None and getattr(cfg, "model", None):
                out.add(str(cfg.model))
        return out

    # Expand each allocated alias -> {alias name, concrete model} into allowed.
    for alias_name in allocated:
        result.allowed |= _expand(alias_name)

    # GLOBAL gated set: every alias allocated ANYWHERE, expanded to concrete.
    try:
        global_aliases = alloc_store.all_allocated_aliases()
    except Exception as exc:
        logger.warning("effective-models: global gated lookup failed (%s) — fail-closed", exc)
        # Fail-closed: if we cannot read the global set, gate on what we know is
        # allocated to the caller's own scopes at minimum (no widening).
        global_aliases = set(allocated)
    for alias_name in global_aliases:
        result.gated |= _expand(alias_name)

    return result
