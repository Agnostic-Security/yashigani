"""YSG-RISK-201 regression — legacy WebAuthn revoke must require step-up.

ASVS V6.8.4. Two surfaces existed for one privileged operation:

    DELETE /admin/settings/webauthn/credentials/{id}   -> AdminSession        (legacy, UNHARDENED)
    DELETE /api/v1/admin/webauthn/credentials/{id}     -> StepUpAdminSession  (v1, hardened)

An attacker with a hijacked-but-not-step-upped admin session could strip a
target's passkeys via the legacy route — removing their strongest authenticator
— then fall back to password+TOTP. YTF Tier-B proved it live on BOTH runtimes:
"WA-REVOKE-04 FAIL: DELETE without step-up returned 200, expected 401".

This test asserts the DEPENDENCY, not a live HTTP round trip, so it runs in
Tier-A (no stack) and fails immediately if anyone reverts the annotation or adds
a third unhardened surface.
"""
from __future__ import annotations

import ast
import pathlib

_ROUTES = pathlib.Path(__file__).resolve().parents[3] / "yashigani" / "backoffice" / "routes"


def _revoke_handlers():
    """Every handler whose route path deletes a webauthn credential."""
    found = []
    for f in ("webauthn.py", "webauthn_v1.py"):
        tree = ast.parse((_ROUTES / f).read_text())
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                src = ast.unparse(dec)
                if "delete" in src and "webauthn/credentials" in src:
                    args = {a.arg: ast.unparse(a.annotation) if a.annotation else ""
                            for a in node.args.args}
                    found.append((f, node.name, args.get("session", "")))
    return found


def test_every_webauthn_revoke_surface_requires_stepup():
    handlers = _revoke_handlers()
    assert handlers, "no webauthn credential-delete handlers found — test is blind"
    unhardened = [(f, n, s) for f, n, s in handlers if "StepUp" not in s]
    assert not unhardened, (
        "WebAuthn credential revocation reachable WITHOUT step-up (ASVS V6.8.4): "
        f"{unhardened}. Every surface that revokes an authenticator must take "
        "StepUpAdminSession — see YSG-RISK-201."
    )


def test_both_known_surfaces_are_covered_by_this_test():
    """Guard against the test silently going blind if a file is renamed."""
    names = {n for _, n, _ in _revoke_handlers()}
    assert {"delete_credential", "revoke_credential"} <= names, names
