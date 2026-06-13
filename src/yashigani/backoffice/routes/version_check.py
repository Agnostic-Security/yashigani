"""
Yashigani Backoffice — Version check endpoint (R26).

Last updated: 2026-06-13T00:00:00+01:00

Routes:
  GET /admin/version          — running version vs latest published (opt-in egress)

R26 design:
  - Returns running version always.
  - Latest-version check against GitHub releases is OPT-IN via the
    YASHIGANI_VERSION_CHECK_ENABLED env var (default: false).
  - When disabled or unreachable: returns gracefully with check_skipped=true.
  - Classifies available updates: major / minor / patch / security.
  - Zero telemetry: the request is a plain unauthenticated GET to the GitHub
    releases API — no payload, no identifying headers sent.
  - Caddy egress note: if Caddy's egress allowlist is locked, the outbound
    request to api.github.com will be blocked at the network layer. The
    endpoint handles this gracefully (check_skipped=true, reason="network_error").
    Operator action: add `api.github.com` to the Caddy egress allowlist
    (YASHIGANI_EGRESS_ALLOW_HOSTS env var or caddy/egress-policy config).

Auth: admin session required.
"""
from __future__ import annotations

import logging
import os

from fastapi import APIRouter

from yashigani.backoffice.middleware import AdminSession

logger = logging.getLogger(__name__)

router = APIRouter()

# Environment variable that opts the deployment into egress version checks.
_VERSION_CHECK_ENV = "YASHIGANI_VERSION_CHECK_ENABLED"

# GitHub releases API endpoint. No authentication needed for public repos.
# The client sends a plain GET with only a User-Agent header — no telemetry.
_GITHUB_RELEASES_URL = (
    "https://api.github.com/repos/agnosticsec/yashigani/releases/latest"
)

# Timeout for the outbound check. Keep short so the endpoint stays snappy.
_CHECK_TIMEOUT_SECONDS = 5


def _parse_semver(version: str) -> tuple[int, int, int]:
    """
    Parse a semver string into (major, minor, patch).
    Returns (0,0,0) on parse failure — safe fallback.
    """
    v = version.lstrip("vV").split("-")[0]  # strip 'v' prefix and pre-release suffix
    parts = v.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return major, minor, patch
    except (ValueError, IndexError):
        return 0, 0, 0


def _classify_update(
    running: str,
    latest: str,
    is_security: bool,
) -> str:
    """
    Classify the update type.

    Returns one of: "none", "security", "major", "minor", "patch".
    "security" takes priority over structural classification when the
    release is flagged as a security release.
    """
    rv = _parse_semver(running)
    lv = _parse_semver(latest)

    if lv <= rv:
        return "none"

    if is_security:
        return "security"

    if lv[0] > rv[0]:
        return "major"
    if lv[1] > rv[1]:
        return "minor"
    return "patch"


async def _fetch_latest_release() -> dict:
    """
    Fetch the latest release from GitHub.

    Returns a dict with keys:
      tag_name: str
      is_security: bool   — True if 'security' appears in release name/body
      html_url: str
      published_at: str

    Raises: OSError / httpx.RequestError on network failure.
    """
    try:
        import httpx
    except ImportError:
        raise OSError("httpx not installed — cannot perform version check")

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "Yashigani-Version-Check/1.0",
        # No Authorization header — public endpoint, zero-telemetry
    }
    async with httpx.AsyncClient(timeout=_CHECK_TIMEOUT_SECONDS) as client:
        resp = await client.get(_GITHUB_RELEASES_URL, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    tag = data.get("tag_name", "")
    name = (data.get("name") or "").lower()
    body = (data.get("body") or "").lower()
    is_security = "security" in name or "security" in body or "cve" in body

    return {
        "tag_name": tag,
        "is_security": is_security,
        "html_url": data.get("html_url", ""),
        "published_at": data.get("published_at", ""),
    }


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------

@router.get(
    "",
    summary="R26: Running version vs latest published",
    tags=["version"],
)
async def get_version_check(session: AdminSession):
    """
    GET /admin/version

    Returns the running Yashigani version and, if version-check egress is
    enabled (YASHIGANI_VERSION_CHECK_ENABLED=true), compares it to the
    latest published release on GitHub.

    Response fields:
      running_version   — version currently deployed
      check_enabled     — whether outbound version check is enabled
      check_skipped     — true when check is disabled or network was unreachable
      skip_reason       — human-readable reason when check_skipped=true
      latest_version    — latest published tag (null when skipped)
      update_available  — true when latest > running (null when skipped)
      update_type       — "none"|"patch"|"minor"|"major"|"security" (null when skipped)
      release_url       — GitHub release URL (null when skipped)
      published_at      — ISO-8601 release date (null when skipped)

    Opt-in egress note:
      Set YASHIGANI_VERSION_CHECK_ENABLED=true to enable outbound checks.
      The request goes to api.github.com — ensure this host is in the Caddy
      egress allowlist (YASHIGANI_EGRESS_ALLOW_HOSTS or caddy/egress-policy).
      When egress is blocked the endpoint returns gracefully with
      check_skipped=true, reason="network_error" — it never errors out.

    Zero telemetry: only a plain GET with a User-Agent header is sent.
    No identifying payload, no installation ID, no usage data.
    """
    from yashigani import __version__ as running_version

    check_enabled = os.environ.get(_VERSION_CHECK_ENV, "false").lower() in (
        "1", "true", "yes"
    )

    base = {
        "running_version": running_version,
        "check_enabled": check_enabled,
    }

    if not check_enabled:
        return {
            **base,
            "check_skipped": True,
            "skip_reason": (
                f"Version check is disabled. Set {_VERSION_CHECK_ENV}=true to enable. "
                "Requires api.github.com in the Caddy egress allowlist."
            ),
            "latest_version": None,
            "update_available": None,
            "update_type": None,
            "release_url": None,
            "published_at": None,
        }

    # Egress is enabled — attempt the check.
    try:
        release = await _fetch_latest_release()
    except Exception as exc:
        logger.info(
            "Version check skipped — network error reaching %s: %s",
            _GITHUB_RELEASES_URL,
            exc,
        )
        return {
            **base,
            "check_skipped": True,
            "skip_reason": (
                "Could not reach GitHub releases API. "
                "Check that api.github.com is in the Caddy egress allowlist."
            ),
            "latest_version": None,
            "update_available": None,
            "update_type": None,
            "release_url": None,
            "published_at": None,
        }

    latest_version = release["tag_name"].lstrip("vV")
    update_type = _classify_update(
        running=running_version,
        latest=latest_version,
        is_security=release["is_security"],
    )
    update_available = update_type != "none"

    return {
        **base,
        "check_skipped": False,
        "skip_reason": None,
        "latest_version": latest_version,
        "update_available": update_available,
        "update_type": update_type,
        "release_url": release["html_url"],
        "published_at": release["published_at"],
    }
