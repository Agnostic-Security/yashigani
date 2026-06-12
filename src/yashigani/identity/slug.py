"""
Yashigani — canonical email-to-slug derivation.

B5 (2.25.5): The auth-side and OWUI-resolver side previously used different
slug derivation rules:
  - auth.py/_auth_email_to_slug: full email → replace [^a-z0-9-] with "-"
    → dana.lee@example.com → dana-lee-example-com
  - openai_router.py/_resolve_owui_forwarded_user: local part only, kept "." and "_"
    → dana.lee@example.com → dana.lee  (WRONG — never registered)

This module is the SINGLE SOURCE OF TRUTH for slug derivation.
Every call site that converts an email to a registry slug MUST import and
call ``email_to_slug`` from here.  Never implement the rule inline again.

Rule: lower the whole address, take local + "-" + domain, replace every
character outside [a-z0-9-] with "-", strip leading/trailing "-", truncate
to 64 characters (the IdentityRegistry slug limit).

Examples:
  dana.lee@example.com     → dana-lee-example-com
  alice+test@corp.co.uk    → alice-test-corp-co-uk
  BOB_SMITH@EXAMPLE.COM    → bob-smith-example-com
  user@localhost           → user-localhost
"""

from __future__ import annotations

import re

_SLUG_RE = re.compile(r"[^a-z0-9\-]")
_SLUG_MAXLEN = 64


def email_to_slug(email: str) -> str:
    """Derive a stable registry slug from an email address.

    Canonical rule used by ALL slug-derivation sites in the codebase:
      1. Lower-case the entire email.
      2. Combine local + "-" + domain (replaces "@").
      3. Replace every character not in [a-z0-9-] with "-".
      4. Strip leading/trailing "-".
      5. Truncate to 64 characters.

    This is deterministic, reversible to a human-readable form, and
    uniquely identifies an email address for slug lookup purposes.

    Raises ValueError if *email* is empty or contains no "@".
    """
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("email_to_slug: empty email")
    local, sep, domain = email.partition("@")
    if not sep:
        raise ValueError(f"email_to_slug: no '@' in {email!r}")
    raw = f"{local}-{domain}"
    slug = _SLUG_RE.sub("-", raw).strip("-")
    return slug[:_SLUG_MAXLEN]
