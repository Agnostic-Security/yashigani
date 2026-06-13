"""
Yashigani Optimization — Sensitivity taxonomy store.

R14/R15 (v2.25.5): per-tenant number→{label, colour_class} map.
Enforcement (OPA ceiling comparisons) uses the numeric level directly —
this store is display-only metadata.  If the DB is unavailable, the store
falls back to DEFAULT_TAXONOMY silently (not fail-closed, by design).

Table: sensitivity_taxonomy (created by migration 0021).
  tenant_id    TEXT
  level_number INTEGER (1–N)
  label        TEXT
  colour_class TEXT  (one of sens-level-1 .. sens-level-5)
  created_at   TIMESTAMPTZ
  updated_at   TIMESTAMPTZ
  PK (tenant_id, level_number)

Last updated: 2026-06-13T00:00:00+00:00
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical colour classes (CSS classes in dashboard.css)
# ---------------------------------------------------------------------------
VALID_COLOUR_CLASSES = frozenset({
    "sens-level-1",
    "sens-level-2",
    "sens-level-3",
    "sens-level-4",
    "sens-level-5",
})

# ---------------------------------------------------------------------------
# Default 5-level taxonomy — used when no DB rows exist for a tenant and as
# the canonical fallback if the DB is unavailable.
#
# Level number → {label, colour_class}
# Labels intentionally differ from old enum names to signal the new model.
# ---------------------------------------------------------------------------
DEFAULT_TAXONOMY: dict[int, dict] = {
    1: {"label": "Info",         "colour_class": "sens-level-1"},  # blue — lowest
    2: {"label": "Public",       "colour_class": "sens-level-2"},  # green
    3: {"label": "Internal",     "colour_class": "sens-level-3"},  # yellow
    4: {"label": "Confidential", "colour_class": "sens-level-4"},  # orange
    5: {"label": "Sensitive",    "colour_class": "sens-level-5"},  # red — highest
}


def _get_pool():
    """Lazy import of the asyncpg pool so TaxonomyStore can be imported at
    module level without requiring the pool to be initialised yet."""
    try:
        from yashigani.db.postgres import get_pool
        return get_pool()
    except Exception:
        return None


class TaxonomyStore:
    """Per-tenant sensitivity taxonomy CRUD.

    Enforcement comparisons use the integer level directly — never call the
    taxonomy store in the enforcement path (OPA, classify, ceiling checks).
    This store is display metadata only.

    DB access uses asyncpg via yashigani.db.get_pool().  If the pool is
    unavailable (DB down, pool not initialised), every method falls back
    to DEFAULT_TAXONOMY silently.
    """

    # Class-level default taxonomy (also accessible as a class attribute)
    DEFAULT_TAXONOMY = DEFAULT_TAXONOMY

    # ------------------------------------------------------------------ #
    # Read operations                                                       #
    # ------------------------------------------------------------------ #

    async def get_taxonomy(self, tenant_id: str = "default") -> dict[int, dict]:
        """Return the taxonomy for tenant_id as {level_number: {label, colour_class}}.

        Falls back to DEFAULT_TAXONOMY when no rows exist or DB is unavailable.
        """
        pool = _get_pool()
        if pool is None:
            return dict(DEFAULT_TAXONOMY)
        try:
            rows = await pool.fetch(
                "SELECT level_number, label, colour_class FROM sensitivity_taxonomy "
                "WHERE tenant_id = $1 ORDER BY level_number",
                tenant_id,
            )
            if not rows:
                return dict(DEFAULT_TAXONOMY)
            return {row["level_number"]: {"label": row["label"], "colour_class": row["colour_class"]}
                    for row in rows}
        except Exception as exc:
            logger.warning("TaxonomyStore.get_taxonomy failed (tenant=%s): %s", tenant_id, exc)
            return dict(DEFAULT_TAXONOMY)

    async def get_level_count(self, tenant_id: str = "default") -> int:
        """Return the number of levels configured for tenant_id."""
        pool = _get_pool()
        if pool is None:
            return len(DEFAULT_TAXONOMY)
        try:
            row = await pool.fetchrow(
                "SELECT COUNT(*) AS cnt FROM sensitivity_taxonomy WHERE tenant_id = $1",
                tenant_id,
            )
            count = row["cnt"] if row else 0
            return int(count) if count else len(DEFAULT_TAXONOMY)
        except Exception as exc:
            logger.warning("TaxonomyStore.get_level_count failed (tenant=%s): %s", tenant_id, exc)
            return len(DEFAULT_TAXONOMY)

    async def level_to_label(self, tenant_id: str, level_number: int) -> str:
        """Return the label for a given level, falling back to DEFAULT_TAXONOMY."""
        taxonomy = await self.get_taxonomy(tenant_id)
        entry = taxonomy.get(level_number)
        if entry:
            return entry["label"]
        # Last-resort fallback: DEFAULT_TAXONOMY
        default_entry = DEFAULT_TAXONOMY.get(level_number)
        if default_entry:
            return default_entry["label"]
        return str(level_number)

    # ------------------------------------------------------------------ #
    # Write operations                                                      #
    # ------------------------------------------------------------------ #

    async def set_level(
        self,
        tenant_id: str,
        level_number: int,
        label: str,
        colour_class: str,
    ) -> None:
        """Upsert a level entry.

        Raises ValueError if colour_class is not in VALID_COLOUR_CLASSES.
        Falls back silently (logs warning) if DB is unavailable.
        """
        if colour_class not in VALID_COLOUR_CLASSES:
            raise ValueError(
                f"Invalid colour_class {colour_class!r}. "
                f"Must be one of: {sorted(VALID_COLOUR_CLASSES)}"
            )
        pool = _get_pool()
        if pool is None:
            logger.warning("TaxonomyStore.set_level: DB pool unavailable — skipping write")
            return
        try:
            await pool.execute(
                """
                INSERT INTO sensitivity_taxonomy (tenant_id, level_number, label, colour_class)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (tenant_id, level_number)
                DO UPDATE SET label = EXCLUDED.label,
                              colour_class = EXCLUDED.colour_class,
                              updated_at = NOW()
                """,
                tenant_id,
                level_number,
                label,
                colour_class,
            )
        except Exception as exc:
            logger.warning(
                "TaxonomyStore.set_level failed (tenant=%s level=%d): %s",
                tenant_id, level_number, exc,
            )
            raise

    async def delete_level(self, tenant_id: str, level_number: int) -> None:
        """Delete a level entry.

        Raises ValueError if trying to delete level 1 or the current max level.
        Falls back silently if DB is unavailable.
        """
        # Safety: cannot delete the lowest level
        if level_number == 1:
            raise ValueError("Cannot delete level 1 (lowest level must always exist).")
        # Safety: cannot delete the current max level
        taxonomy = await self.get_taxonomy(tenant_id)
        if taxonomy:
            current_max = max(taxonomy.keys())
            if level_number == current_max:
                raise ValueError(
                    f"Cannot delete level {level_number} (current max level). "
                    "Add a higher level first or delete from the top."
                )
        pool = _get_pool()
        if pool is None:
            logger.warning("TaxonomyStore.delete_level: DB pool unavailable — skipping delete")
            return
        try:
            await pool.execute(
                "DELETE FROM sensitivity_taxonomy WHERE tenant_id = $1 AND level_number = $2",
                tenant_id,
                level_number,
            )
        except Exception as exc:
            logger.warning(
                "TaxonomyStore.delete_level failed (tenant=%s level=%d): %s",
                tenant_id, level_number, exc,
            )
            raise

    # ------------------------------------------------------------------ #
    # Validation                                                            #
    # ------------------------------------------------------------------ #

    async def validate_taxonomy(self, taxonomy: dict[int, dict]) -> None:
        """Validate that taxonomy has contiguous levels 1..N with N in [2, 10].

        Raises ValueError describing the first validation failure found.
        """
        if not taxonomy:
            raise ValueError("Taxonomy must have at least 2 levels.")
        levels = sorted(taxonomy.keys())
        n = len(levels)
        if n < 2:
            raise ValueError(f"Taxonomy must have at least 2 levels, got {n}.")
        if n > 10:
            raise ValueError(f"Taxonomy must have at most 10 levels, got {n}.")
        # Check contiguous 1..N
        expected = list(range(1, n + 1))
        if levels != expected:
            gaps = [e for e in expected if e not in levels]
            raise ValueError(
                f"Taxonomy levels must be contiguous 1..{n}. "
                f"Missing: {gaps}. Got: {levels}."
            )
        # Check each entry has required fields
        for lvl, entry in taxonomy.items():
            if not isinstance(entry, dict):
                raise ValueError(f"Level {lvl} entry must be a dict, got {type(entry).__name__}.")
            label = entry.get("label", "")
            if not label or not isinstance(label, str):
                raise ValueError(f"Level {lvl} must have a non-empty label string.")
            colour = entry.get("colour_class", "")
            if colour and colour not in VALID_COLOUR_CLASSES:
                raise ValueError(
                    f"Level {lvl} has invalid colour_class {colour!r}. "
                    f"Must be one of: {sorted(VALID_COLOUR_CLASSES)}."
                )
