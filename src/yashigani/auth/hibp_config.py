"""
Yashigani Auth — HIBP API key resolution and masking.

Resolution priority (highest → lowest):
  1. Admin-panel key (from auth_settings table, encrypted at rest) — takes
     effect immediately on next HIBP call; no container restart required.
  2. Env var YASHIGANI_HIBP_API_KEY — fallback for operators who prefer
     env-based configuration or have not yet configured via admin panel.
  3. None (anonymous range request) — final fallback; the free k-Anonymity
     endpoint works without a key and is the default for most deployments.

The key is only injected when non-empty. An empty admin-panel value falls
through to env var; an empty (or absent) env var falls through to anon.

Security invariants:
  - The key is NEVER logged at any level (not even DEBUG).
  - API responses only return a masked value (first 3 + last 3 chars, middle
    replaced with '…') so the admin panel can confirm a key is configured
    without exposing the full value.
  - The masked value is always None when no key is configured.

Last updated: 2026-05-07T00:00:00+01:00
"""
from __future__ import annotations

import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

_HIBP_KEY_ENV = "YASHIGANI_HIBP_API_KEY"
_SETTINGS_KEY = "hibp_api_key"

# HIBP API keys are UUID-shaped (e.g. hex with optional hyphens, 32–36 chars).
# We validate loosely: at least 8 non-whitespace chars to catch obvious junk,
# but don't enforce UUID format exactly to allow future HIBP key format changes.
_MIN_KEY_LENGTH = 8
_MAX_KEY_LENGTH = 128
_KEY_RE = re.compile(r"^[A-Za-z0-9\-]{8,128}$")


def mask_hibp_key(key: str) -> Optional[str]:
    """
    Return a masked representation of *key* safe for admin UI display.

    Pattern: first 3 chars + '…' + last 3 chars.
    For keys shorter than 7 chars: '***' (should not occur in practice).
    Returns None if key is empty.

    The masked value is the ONLY form of the key ever sent to a client.
    The full key value is never returned by any API endpoint.
    """
    if not key:
        return None
    if len(key) < 7:
        return "***"
    return key[:3] + "…" + key[-3:]


def validate_hibp_key_format(key: str) -> None:
    """
    Validate key format. HIBP keys are UUID-shaped.

    Raises:
        ValueError: if the key is outside acceptable length/charset bounds.
    """
    if not key:
        # Empty = "clear the key" — valid
        return
    if len(key) < _MIN_KEY_LENGTH or len(key) > _MAX_KEY_LENGTH:
        raise ValueError(
            f"HIBP API key must be between {_MIN_KEY_LENGTH} and {_MAX_KEY_LENGTH} characters"
        )
    if not _KEY_RE.match(key):
        raise ValueError(
            "HIBP API key must contain only alphanumeric characters and hyphens"
        )


async def resolve_hibp_api_key(settings_store=None) -> Optional[str]:
    """
    Resolve the HIBP API key using the priority chain:
      1. Admin-panel key (from AuthSettingsStore, encrypted at rest)
      2. Env var YASHIGANI_HIBP_API_KEY
      3. None (anonymous request)

    Returns the key string if one is configured, or None for anon.
    The key is NEVER logged.

    Args:
        settings_store: AuthSettingsStore instance, or None to skip DB lookup
                        (env-var + anon only). Pass None for tests or when DB
                        is not available.
    """
    # --- Priority 1: admin-panel key ---
    if settings_store is not None:
        try:
            db_key = await settings_store.get_setting(_SETTINGS_KEY)
            if db_key:
                logger.debug("HIBP key source: admin_panel")
                return db_key
        except Exception as exc:
            logger.warning(
                "HIBP key: admin_panel lookup failed (%s) — falling back to env var",
                type(exc).__name__,
            )

    # --- Priority 2: env var ---
    env_key = os.environ.get(_HIBP_KEY_ENV, "").strip()
    if env_key:
        logger.debug("HIBP key source: env_var")
        return env_key

    # --- Priority 3: anon ---
    logger.debug("HIBP key source: none (anonymous request)")
    return None


async def get_hibp_key_status(settings_store=None) -> dict:
    """
    Return the status dict for GET /api/v1/admin/auth/hibp/status.

    Dict keys:
      configured (bool)   — True if any key is set (admin-panel OR env var)
      source (str)        — "admin_panel" | "env_var" | "none"
      masked_value (str|None) — first 3 + '…' + last 3, or None
      updated_at (str|None)   — ISO-8601 or None (only for admin_panel source)
      updated_by (str|None)   — admin username or None (only for admin_panel source)

    Does NOT return the full key value.
    """
    # Check admin-panel first
    if settings_store is not None:
        try:
            db_key = await settings_store.get_setting(_SETTINGS_KEY)
            if db_key:
                meta = await settings_store.get_metadata(_SETTINGS_KEY)
                return {
                    "configured": True,
                    "source": "admin_panel",
                    "masked_value": mask_hibp_key(db_key),
                    "updated_at": meta["updated_at"] if meta else None,
                    "updated_by": meta["updated_by"] if meta else None,
                }
        except Exception as exc:
            logger.warning(
                "HIBP status: admin_panel lookup failed (%s)",
                type(exc).__name__,
            )

    # Check env var
    env_key = os.environ.get(_HIBP_KEY_ENV, "").strip()
    if env_key:
        return {
            "configured": True,
            "source": "env_var",
            "masked_value": mask_hibp_key(env_key),
            "updated_at": None,
            "updated_by": None,
        }

    return {
        "configured": False,
        "source": "none",
        "masked_value": None,
        "updated_at": None,
        "updated_by": None,
    }
