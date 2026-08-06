"""
Rego package-declaration extraction + namespace-scope enforcement.

YSG-RISK-141 (HIGH — OPA policy-save cross-namespace injection):

Policy-save endpoints (POST /admin/policies/save, PUT
/admin/policies/custom/{name}/rego, POST /admin/opa-assistant/apply-rego)
accepted the module id / policy slug from the request (e.g. `name` /
`policy_name`) and stored the Rego at OPA path `clients/<name>` — but never
verified that the `package` statement DECLARED INSIDE the submitted Rego
source actually matched `clients.<name>`.

OPA keys evaluated data documents by the `package` declaration inside the
module, NOT by the REST module id used in the PUT path. A caller could
therefore submit `name="my_own_policy"` (passing the id-based namespace
checks) while the Rego body declared `package clients.some_other_tenant`
(or even a core namespace such as `yashigani`/`rbac`), silently overriding
or merging into another tenant's decision document, or the load-bearing core
policy namespace, despite the id-level reserved-name and per-tenant checks
looking clean.

This module is the single source of truth for extracting the declared
package and asserting it matches the caller's authorized namespace BEFORE
the Rego is persisted to OPA (whether via PUT or the sandbox compile check).
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import HTTPException

# Matches the first top-level `package <dotted.path>` statement. Rego package
# names are dotted identifiers (letters/digits/underscore segments).
_PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z_][A-Za-z0-9_.]*)")


def extract_rego_package(rego: str) -> Optional[str]:
    """Return the declared `package <path>` value, or None if not present."""
    m = _PACKAGE_RE.search(rego)
    if not m:
        return None
    return m.group(1).strip()


def assert_client_package_scope(rego: str, expected_name: str) -> None:
    """Reject Rego whose package is not EXACTLY `clients.<expected_name>`.

    Used by every endpoint that persists a client-scoped policy under a
    caller-chosen name (save / edit / apply-rego / duplicate). Raises
    HTTPException(400) on a missing or mismatched package declaration —
    fail closed, never silently accept a cross-namespace package.
    """
    expected = f"clients.{expected_name}"
    pkg = extract_rego_package(rego)
    if pkg is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_package", "message": "policy must declare a package"},
        )
    if pkg != expected:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "package_namespace_mismatch",
                "message": (
                    f"Rego package {pkg!r} does not match the authorized namespace "
                    f"{expected!r} for policy name {expected_name!r}. Cross-namespace "
                    f"package declarations are rejected — the module must declare "
                    f"exactly 'package {expected}'."
                ),
            },
        )


def assert_core_package_scope(rego: str, core_root: str = "yashigani") -> None:
    """Reject core-policy edits whose package escapes the core namespace tree.

    Core policy modules (yashigani / rbac / mcp / agents / v1_routing module
    ids) legitimately share/extend the `yashigani` package tree (e.g.
    `yashigani`, `yashigani.mcp`, `yashigani.v1`). An edit through the core
    policy endpoint that declares a DIFFERENT package (e.g. `clients.*`)
    would silently write into a different namespace than the module id
    implies — reject it.
    """
    pkg = extract_rego_package(rego)
    if pkg is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_package", "message": "policy must declare a package"},
        )
    if pkg != core_root and not pkg.startswith(core_root + "."):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "package_namespace_mismatch",
                "message": (
                    f"Rego package {pkg!r} escapes the core policy namespace "
                    f"({core_root!r}). Core policy edits must stay within the "
                    f"'{core_root}' package tree."
                ),
            },
        )
