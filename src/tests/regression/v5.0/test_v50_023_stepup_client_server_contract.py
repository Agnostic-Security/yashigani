# Last updated: 2026-07-29T00:00:00+00:00
"""
Regression — V50-023 (CRITICAL, release-blocker; proven by Ava's live UI e2e)
and its sibling client/server payload-contract mismatches found during the
class audit that followed.

Root cause (V50-023):
  src/yashigani/backoffice/static/ui4/core/api-client.js's built-in step-up
  interceptor POSTed ``{totp: code}`` to ``/auth/stepup``.  The server's
  ``StepUpRequest`` (routes/auth.py) requires the field ``totp_code``, not
  ``totp``.  FastAPI/Pydantic 422'd on every step-up attempt BEFORE the TOTP
  check ever ran — so the TOTP pipeline itself was correct, but no admin
  could complete ANY step-up-gated write through the UI (RBAC create/
  delete/member, SCIM writes, MCP import/re-approve, admin/user create/
  delete/reset, NHI SVID approve, cloud-key set, model RBAC — every module
  that routes through ApiClient.mutate()'s server-driven step-up
  interceptor). Present since 835c235d8 (2026-06-27); the shared ui4 client
  means 4.1.x carries the same bug and needs the same fix propagated there
  separately (out of scope for this worktree — flagged in the release
  report).

Class audit (every ui4 JS payload cross-checked against its route's Pydantic
request model) turned up THREE more sites of the same failure class, all
fixed alongside V50-023:

  1. admin/modules/_iam.js `elevate()` — a SECOND, independent /auth/stepup
     POST (used to client-gate RBAC group/member + SCIM writes that carry a
     plain AdminSession server-side) had the identical `{totp: code}` bug.
  2. admin/modules/mcp.js `_importServer()` — passed an ALREADY-stringified
     JSON body into ApiClient.mutate(), which JSON.stringifies its `body`
     argument internally (api-client.js §2.6). Double-encoding meant FastAPI
     received a JSON string literal instead of an object and 422'd
     ImportMcpServerRequest on every MCP import attempt.
  3. admin/modules/agent-policies.js `_applyTemplate()` / `_revokeGrant()` —
     called `this.api.mutate('POST', path, body)`, a 3-positional-argument
     call that does not match ApiClient.mutate(path, opts). `path` silently
     became the literal string 'POST', `opts` became the real path
     (destructured as {method,body,...} off a string yields all defaults),
     and the body was dropped entirely — Apply Template / Revoke Grant
     (StepUp-gated agent-policy writes) never reached the real endpoint.
  4. admin/modules/budget-models.js `_approveOverride()` — POSTed no body at
     all to /admin/cloud-override/approve, whose ApproveRequest requires
     `confirming_fingerprint` (SOD-1 swap-attack guard). Always 422'd.

This suite is static/contract-only (no live stack, no network) per the
coordinator's brief: it parses the shipped JS source with a regex extractor
(the client is JS, not Python — there is no AST to import) and asserts the
extracted payload key(s) equal the Pydantic model's required field name(s).
Any future regression that reintroduces a client/server key mismatch on
these routes fails this suite BEFORE Ava has to catch it live.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).parent.parent.parent.parent / "yashigani"
UI4 = SRC / "backoffice" / "static" / "ui4"
ROUTES_DIR = SRC / "backoffice" / "routes"

API_CLIENT_JS = UI4 / "core" / "api-client.js"
IAM_JS = UI4 / "admin" / "modules" / "_iam.js"
MCP_JS = UI4 / "admin" / "modules" / "mcp.js"
AGENT_POLICIES_JS = UI4 / "admin" / "modules" / "agent-policies.js"
BUDGET_MODELS_JS = UI4 / "admin" / "modules" / "budget-models.js"
AUTH_PY = ROUTES_DIR / "auth.py"
MCP_SERVERS_PY = ROUTES_DIR / "mcp_servers.py"
CLOUD_OVERRIDE_PY = ROUTES_DIR / "cloud_override.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    assert path.is_file(), f"expected file missing: {path}"
    return path.read_text(encoding="utf-8")


def _pydantic_field_names(source: str, class_name: str) -> set[str]:
    """
    Extract top-level field names declared directly on a Pydantic BaseModel
    class body (regex-based — good enough for our flat request models, all
    of which declare `field_name: type = ...` lines with no nested classes).
    """
    m = re.search(rf"class {re.escape(class_name)}\(.*?\):\n(.*?)(?=\nclass |\Z)", source, re.S)
    assert m, f"could not locate class {class_name} in source"
    body = m.group(1)
    fields = set()
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith('"""'):
            continue
        field_m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*", stripped)
        if field_m:
            fields.add(field_m.group(1))
        # Stop at the first method/validator — field declarations only appear
        # before any `def`.
        if stripped.startswith("def ") or stripped.startswith("@"):
            break
    return fields


def _strip_js_line_comments(js_source: str) -> str:
    """Strip `// ...` line comments so prose mentions of '/auth/stepup' in
    docstring-style comments don't get mistaken for real call sites."""
    return re.sub(r"//[^\n]*", "", js_source)


def _extract_fetch_stepup_totp_key(js_source: str) -> str:
    """
    Find the fetch(..., {...}) call targeting '/auth/stepup' (either a direct
    string literal or via this._url('/auth/stepup')) and extract the JSON key
    used for the TOTP code in its body, e.g.
    `body: JSON.stringify({ totp_code: code })` -> 'totp_code'.
    """
    no_comments = _strip_js_line_comments(js_source)
    m = re.search(
        r"fetch\([^;]*?/auth/stepup[^;]*?body:\s*JSON\.stringify\(\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:",
        no_comments,
        re.S,
    )
    assert m, "could not find a fetch(..., {...}) call targeting /auth/stepup with a JSON.stringify({key: ...}) body"
    return m.group(1)


def _has_real_stepup_fetch_call(js_source: str) -> bool:
    """True if the file contains an ACTUAL fetch(...) call targeting
    /auth/stepup (as opposed to just a prose comment mentioning the path)."""
    no_comments = _strip_js_line_comments(js_source)
    return re.search(r"fetch\([^;]*?/auth/stepup", no_comments, re.S) is not None


# ---------------------------------------------------------------------------
# V50-023 — /auth/stepup payload key vs StepUpRequest.totp_code
# ---------------------------------------------------------------------------

class TestStepUpPayloadContract:
    """
    Static contract test: every client site that POSTs to /auth/stepup must
    send the TOTP code under the same JSON key the server's StepUpRequest
    requires. This is the exact test that would have caught V50-023 before
    Ava had to catch it live.
    """

    def _server_field(self) -> str:
        source = _read(AUTH_PY)
        fields = _pydantic_field_names(source, "StepUpRequest")
        assert fields, "StepUpRequest has no fields — route model missing/renamed?"
        # StepUpRequest has exactly one field (the TOTP code).
        assert len(fields) == 1, f"StepUpRequest field set changed unexpectedly: {fields}"
        return next(iter(fields))

    def test_server_field_is_totp_code(self):
        """Pin the server contract itself — fails loudly if StepUpRequest is renamed."""
        assert self._server_field() == "totp_code"

    def test_api_client_stepup_body_key_matches_server_field(self):
        """api-client.js's built-in step-up interceptor (ApiClient.mutate)."""
        server_field = self._server_field()
        client_key = _extract_fetch_stepup_totp_key(_read(API_CLIENT_JS))
        assert client_key == server_field, (
            f"V50-023 regression: api-client.js sends {{{client_key!r}: code}} to "
            f"/auth/stepup but StepUpRequest requires {{{server_field!r}: ...}} — "
            "every step-up-gated admin write would 422 before the TOTP check runs."
        )

    def test_iam_elevate_stepup_body_key_matches_server_field(self):
        """_iam.js's second, independent /auth/stepup POST (elevate())."""
        server_field = self._server_field()
        client_key = _extract_fetch_stepup_totp_key(_read(IAM_JS))
        assert client_key == server_field, (
            f"V50-023 sibling regression: _iam.js elevate() sends "
            f"{{{client_key!r}: code}} to /auth/stepup but StepUpRequest requires "
            f"{{{server_field!r}: ...}} — RBAC group/member + SCIM writes gated "
            "through elevate() would never step up."
        )

    def test_no_other_stepup_totp_payload_sites_exist_undetected(self):
        """
        Enumerate every ui4 JS file that references '/auth/stepup' at all and
        confirm we've accounted for both fetch() call sites above. If a THIRD
        site is added later without a matching test, this fails loud instead
        of shipping silently broken.
        """
        hits = []
        for js_file in UI4.rglob("*.js"):
            text = js_file.read_text(encoding="utf-8")
            if _has_real_stepup_fetch_call(text):
                hits.append(js_file)
        known = {API_CLIENT_JS.resolve(), IAM_JS.resolve()}
        unexpected = {f.resolve() for f in hits} - known
        assert not unexpected, (
            "New /auth/stepup call site(s) found that this contract test does not "
            f"cover — audit and extend: {sorted(str(p) for p in unexpected)}"
        )


# ---------------------------------------------------------------------------
# Sibling #2 — mcp.js import: double JSON.stringify
# ---------------------------------------------------------------------------

class TestMcpImportBodyNotDoubleEncoded:
    def test_import_call_does_not_json_stringify_body(self):
        """
        ApiClient.mutate() JSON.stringifies `body` internally. mcp.js's
        _importServer() must pass the plain object, not a pre-stringified
        string, or the server receives a JSON string literal instead of an
        object and 422s ImportMcpServerRequest.
        """
        source = _read(MCP_JS)
        m = re.search(r"await this\.api\.mutate\(`\$\{SERVERS_BASE\}/import`,\s*\{(.*?)\}\s*\)\s*;", source, re.S)
        assert m, "could not find the /admin/mcp/servers/import mutate() call"
        call_opts = m.group(1)
        assert "JSON.stringify(body)" not in call_opts, (
            "V50-023 sibling regression: mcp.js _importServer() double-encodes "
            "the body (ApiClient.mutate already JSON.stringifies it) — "
            "ImportMcpServerRequest would 422 on every MCP import."
        )
        assert re.search(r"\bbody\b\s*,?\s*$", call_opts.strip()) or "body:" in call_opts, (
            "mutate() call for MCP import no longer passes a body at all"
        )

    def test_import_request_model_still_expects_object_fields(self):
        """Pin server contract: ImportMcpServerRequest is an object model (not a raw string)."""
        fields = _pydantic_field_names(_read(MCP_SERVERS_PY), "ImportMcpServerRequest")
        assert {"server_id", "upstream_url", "topology", "egress_posture"} <= fields


# ---------------------------------------------------------------------------
# Sibling #3 — agent-policies.js: wrong mutate() call signature
# ---------------------------------------------------------------------------

class TestAgentPoliciesMutateCallSignature:
    """
    ApiClient.mutate(path, opts) — never mutate(method, path, body). A
    positional-args call silently sends the request to the wrong URL with no
    body and no real HTTP method override.
    """

    def test_apply_template_uses_correct_mutate_signature(self):
        source = _read(AGENT_POLICIES_JS)
        assert "this.api.mutate(\n        'POST'," not in source
        assert re.search(r"this\.api\.mutate\(\s*['\"]POST['\"]\s*,", source) is None, (
            "V50-023 sibling regression: agent-policies.js calls "
            "mutate('POST', path, body) — a broken 3-positional-arg call that "
            "never reaches the real endpoint. Use mutate(path, {method, body})."
        )

    def test_revoke_grant_uses_correct_mutate_signature(self):
        source = _read(AGENT_POLICIES_JS)
        assert re.search(r"this\.api\.mutate\(\s*['\"]DELETE['\"]\s*,", source) is None, (
            "V50-023 sibling regression: agent-policies.js calls "
            "mutate('DELETE', path, null) — a broken 3-positional-arg call. "
            "Use mutate(path, {method: 'DELETE'})."
        )

    def test_apply_and_revoke_check_result_ok_before_reporting_success(self):
        """
        The pre-fix code unconditionally set _actionResult = {ok: true, ...}
        after the mutate() call, regardless of whether the write actually
        succeeded (mutate() never throws on HTTP error responses). Confirm
        the fixed code branches on res.ok.
        """
        source = _read(AGENT_POLICIES_JS)
        apply_fn = re.search(r"async _applyTemplate\(\) \{(.*?)\n  \}", source, re.S)
        assert apply_fn, "_applyTemplate() not found"
        assert "if (!res.ok)" in apply_fn.group(1), (
            "_applyTemplate() must branch on res.ok before reporting success"
        )


# ---------------------------------------------------------------------------
# Sibling #4 — budget-models.js: cloud-override approve missing required field
# ---------------------------------------------------------------------------

class TestCloudOverrideApproveBody:
    def test_server_approve_request_requires_confirming_fingerprint(self):
        fields = _pydantic_field_names(_read(CLOUD_OVERRIDE_PY), "ApproveRequest")
        assert fields == {"confirming_fingerprint"}

    def test_client_approve_call_sends_confirming_fingerprint(self):
        source = _read(BUDGET_MODELS_JS)
        m = re.search(r"async _approveOverride\(\) \{(.*?)\n  \}", source, re.S)
        assert m, "_approveOverride() not found"
        body = m.group(1)
        assert "confirming_fingerprint" in body, (
            "V50-023 sibling regression: budget-models.js _approveOverride() "
            "sends no confirming_fingerprint — ApproveRequest requires it "
            "(SOD-1 swap-attack guard) and the call would always 422."
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
