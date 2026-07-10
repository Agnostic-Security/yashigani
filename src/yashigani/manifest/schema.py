"""
Yashigani Manifest — JSON-Schema validator (M8).

Uses ``jsonschema>=4.17.3,<5.0`` with external ``$ref`` resolution DISABLED
(P10 / M8 / Laura TM-URF-026).  The schema bundle is loaded from the local
``schemas/`` directory inside this package — never from the network.

Last updated: 2026-05-28T00:00:00+00:00
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jsonschema
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

# Package-relative path to the bundled schema.
_SCHEMA_FILENAME = "agent-manifest-v1alpha1.schema.json"


def _load_schema() -> dict:
    """
    Load the bundled JSON-Schema from this package's ``schemas/`` directory.

    External ``$ref`` resolution is disabled at the validator level (P10 / M8).
    """
    schema_dir = Path(__file__).parent / "schemas"
    schema_path = schema_dir / _SCHEMA_FILENAME
    if not schema_path.is_file():
        raise RuntimeError(
            "Bundled manifest schema not found at %s — packaging error" % schema_path
        )
    with schema_path.open("r", encoding="utf-8") as fh:
        schema = json.load(fh)
    return schema


# Module-level singleton — loaded once, never re-fetched.
_SCHEMA: dict | None = None


def _get_schema() -> dict:
    global _SCHEMA
    if _SCHEMA is None:
        _SCHEMA = _load_schema()
    return _SCHEMA


# ---------------------------------------------------------------------------
# External-$ref-disabled resolver (P10 / M8)
#
# jsonschema >=4.18 prefers the `referencing` library; we use it when
# available to avoid the DeprecationWarning on RefResolver.  The legacy
# RefResolver path is kept as a fallback for environments where
# `referencing` is not installed (< 4.18).
# ---------------------------------------------------------------------------


def _make_validator(schema: dict) -> Draft202012Validator:
    """
    Build a Draft2020-12 validator with external ``$ref`` resolution disabled.

    Strategy:
    - Modern path (jsonschema >= 4.18, referencing installed): create a
      ``Registry`` that contains only the bundled schema.  Any URI not in
      the registry raises ``referencing.exceptions.Unresolvable`` — the
      library's natural "no external fetch" behaviour.
    - Fallback (older jsonschema / no referencing): use the legacy
      ``RefResolver`` subclass that overrides ``resolve_remote`` to raise.

    In both cases no network call is made.  Closes: Laura TM-URF-026 / P10 / M8.
    """
    try:
        from referencing import Registry  # noqa: PLC0415
        from referencing.jsonschema import DRAFT202012  # noqa: PLC0415

        # Build a self-contained registry with only the bundled schema.
        # Any external $ref will raise referencing.exceptions.Unresolvable
        # because the URI is not in this registry (no crawl, no network).
        resource = DRAFT202012.create_resource(schema)
        registry = Registry().with_resource(schema.get("$id", ""), resource)
        validator = Draft202012Validator(schema, registry=registry)

    except ImportError:
        # Fallback: legacy RefResolver for environments without referencing.
        import warnings  # noqa: PLC0415

        class _NoExternalRefResolver(jsonschema.RefResolver):  # type: ignore[misc]
            def resolve_remote(self, uri: str) -> Any:  # type: ignore[override]
                raise SchemaError(
                    "External $ref resolution is disabled in yashigani validate "
                    "(M8/P10). Attempted URI: %s" % uri
                )

        schema_id = schema.get("$id", "")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = _NoExternalRefResolver(base_uri=schema_id, referrer=schema)
        validator = Draft202012Validator(schema, resolver=resolver)  # type: ignore[call-arg]

    return validator


# ---------------------------------------------------------------------------
# Public validation API
# ---------------------------------------------------------------------------


class ManifestSchemaError(ValueError):
    """Raised when a manifest fails JSON-Schema validation (M8)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Manifest schema validation failed:\n" + "\n".join(errors))


def validate_schema(parsed: dict) -> list[str]:
    """
    Validate a parsed manifest dict against the bundled JSON-Schema.

    Returns a list of human-readable error strings (empty = valid).
    Does NOT raise; callers decide whether to raise ManifestSchemaError.
    """
    schema = _get_schema()
    validator = _make_validator(schema)
    errors = sorted(validator.iter_errors(parsed), key=lambda e: list(e.path))
    messages: list[str] = []
    for error in errors:
        path = " -> ".join(str(p) for p in error.absolute_path) or "(root)"
        messages.append("  %s: %s" % (path, error.message))
    return messages


def assert_schema_valid(parsed: dict) -> None:
    """
    Validate and raise ManifestSchemaError if invalid.
    """
    errors = validate_schema(parsed)
    if errors:
        raise ManifestSchemaError(errors)
