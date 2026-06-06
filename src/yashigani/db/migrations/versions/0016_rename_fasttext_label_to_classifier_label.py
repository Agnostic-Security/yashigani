"""v2.25.3 — rename pattern_type value fasttext_label → classifier_label.

Revision ID: 0016
Revises: 0015
Create Date: 2026-06-06

Rationale:
    The `pattern_type` column in `sensitivity_patterns` has a CHECK constraint
    that includes the value 'fasttext_label'. This was added in migration 0005
    when the first-pass classifier was fasttext-wheel. In v2.23.3 the engine
    was replaced with scikit-learn; in v2.25.3 all public identifiers are
    renamed to the engine-agnostic name 'classifier'.

    This migration:
      1. Updates any existing rows with pattern_type='fasttext_label' to
         pattern_type='classifier_label' (data migration — defensive; there are
         no seeded rows with fasttext_label, but live installs may have them).
      2. Drops and recreates the CHECK constraint with the new value name.

    Note: Postgres TEXT CHECK constraints cannot be renamed in place; they must
    be dropped and re-added. The constraint is named to allow targeted DROP.

Downgrade:
    Reverses the data migration and restores the original constraint.
"""
from alembic import op


# revision identifiers, used by Alembic.
revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Data migration: rename existing fasttext_label rows
    op.execute(
        "UPDATE sensitivity_patterns "
        "SET pattern_type = 'classifier_label' "
        "WHERE pattern_type = 'fasttext_label'"
    )

    # 2. Drop the old CHECK constraint (Postgres requires dropping by name).
    #    The constraint was created inline in migration 0005 without an explicit
    #    name, so Postgres assigns a generated name of the form
    #    sensitivity_patterns_pattern_type_check.
    op.execute(
        "ALTER TABLE sensitivity_patterns "
        "DROP CONSTRAINT IF EXISTS sensitivity_patterns_pattern_type_check"
    )

    # 3. Re-add the constraint with the new value set.
    op.execute(
        "ALTER TABLE sensitivity_patterns "
        "ADD CONSTRAINT sensitivity_patterns_pattern_type_check "
        "CHECK (pattern_type IN ('regex', 'keyword', 'classifier_label'))"
    )


def downgrade() -> None:
    # 1. Restore old constraint name and value set.
    op.execute(
        "ALTER TABLE sensitivity_patterns "
        "DROP CONSTRAINT IF EXISTS sensitivity_patterns_pattern_type_check"
    )
    op.execute(
        "ALTER TABLE sensitivity_patterns "
        "ADD CONSTRAINT sensitivity_patterns_pattern_type_check "
        "CHECK (pattern_type IN ('regex', 'keyword', 'fasttext_label'))"
    )

    # 2. Reverse the data migration.
    op.execute(
        "UPDATE sensitivity_patterns "
        "SET pattern_type = 'fasttext_label' "
        "WHERE pattern_type = 'classifier_label'"
    )
