#!/usr/bin/env python3
"""
Generate customer-facing API reference markdown from live OpenAPI schemas.

Outputs three files under docs/api/:
  gateway-api.md  — operator/agent-facing Gateway API
  admin-api.md    — admin-panel Backoffice API
  auth-api.md     — shared auth endpoints

Run manually:
  python scripts/gen_api_docs.py

CI drift gate (ci.yml):
  python scripts/gen_api_docs.py && git diff --exit-code docs/api/

No HTTP server is required — schemas are extracted directly from the app
factories using FastAPI's .openapi() method.

Last updated: 2026-05-17T00:00:00+01:00
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# ── repo root on sys.path ──────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_OUT = _REPO_ROOT / "docs" / "api"
_OUT.mkdir(parents=True, exist_ok=True)

# Tags that belong to the auth domain — extracted to auth-api.md
_AUTH_TAGS = frozenset({"auth", "sso"})
# Tags that are internal-only (not included in customer-facing docs)
_INTERNAL_TAGS = frozenset({"csp", "services"})

# Path prefixes excluded from the customer-facing Gateway API doc.
# These are infrastructure/internal endpoints that customers should not call.
_GATEWAY_INTERNAL_PATHS = frozenset({
    "/healthz",
    "/internal/metrics",
    "/docs",
    "/openapi.json",
})


# ── Schema loading helpers ─────────────────────────────────────────────────

def _load_backoffice_schema() -> dict:
    """Load backoffice OpenAPI schema without starting a server."""
    from yashigani.backoffice.app import create_backoffice_app
    app = create_backoffice_app()
    return app.openapi()


def _load_gateway_schema() -> dict:
    """Load gateway OpenAPI schema without starting a server.

    Includes the openai_router (which provides /v1/chat/completions and
    /v1/models) as extra_routers, matching the real entrypoint wiring.
    """
    from yashigani.gateway.proxy import create_gateway_app, GatewayConfig
    from yashigani.gateway.openai_router import router as openai_router

    mock_pipeline = MagicMock()
    mock_pipeline.inspect.return_value = MagicMock(
        action="ALLOW", sanitized_content=None
    )
    cfg = GatewayConfig(
        upstream_base_url="http://mcp:8080",
        opa_url="http://policy:8181",
    )
    app = create_gateway_app(
        config=cfg,
        inspection_pipeline=mock_pipeline,
        chs=MagicMock(),
        audit_writer=MagicMock(),
        rate_limiter=None,
        rbac_store=None,
        agent_registry=None,
        extra_routers=[openai_router],
    )
    return app.openapi()


# ── Markdown rendering helpers ─────────────────────────────────────────────

def _schema_fields(schema_ref: str | None, components: dict) -> list[dict]:
    """Resolve a $ref or inline schema to a flat field list."""
    if schema_ref is None:
        return []
    if schema_ref.startswith("#/components/schemas/"):
        name = schema_ref.split("/")[-1]
        schema = components.get("schemas", {}).get(name, {})
    else:
        schema = {}
    fields = []
    for prop, prop_schema in schema.get("properties", {}).items():
        required = prop in schema.get("required", [])
        fields.append({
            "name": prop,
            "type": _type_str(prop_schema),
            "required": required,
            "description": prop_schema.get("description", ""),
        })
    return fields


def _type_str(prop_schema: dict) -> str:
    if "$ref" in prop_schema:
        return prop_schema["$ref"].split("/")[-1]
    t = prop_schema.get("type", "any")
    fmt = prop_schema.get("format", "")
    if fmt:
        return f"{t} ({fmt})"
    if t == "array":
        items = prop_schema.get("items", {})
        return f"array[{_type_str(items)}]"
    return t


def _fields_table(fields: list[dict]) -> str:
    if not fields:
        return ""
    lines = ["| Field | Type | Required | Description |",
             "|-------|------|----------|-------------|"]
    for f in fields:
        req = "Yes" if f["required"] else "No"
        desc = f["description"].replace("|", "\\|")
        lines.append(f"| `{f['name']}` | `{f['type']}` | {req} | {desc} |")
    return "\n".join(lines)


def _curl_example(method: str, path: str, auth_header: str, body_fields: list[dict]) -> str:
    method = method.upper()
    if method in ("POST", "PUT", "PATCH") and body_fields:
        body_example = {f["name"]: f"<{f['type']}>" for f in body_fields if f["required"]}
        body_str = json.dumps(body_example, indent=2)
        body_arg = f" \\\n  -H 'Content-Type: application/json' \\\n  -d '{body_str}'"
    else:
        body_arg = ""
    return textwrap.dedent(f"""\
        ```bash
        curl -X {method} https://<gateway-host>{path} \\
          -H '{auth_header}'{body_arg}
        ```""")


def _render_endpoint(
    method: str,
    path: str,
    operation: dict,
    components: dict,
    auth_header: str,
) -> str:
    summary = operation.get("summary", "")
    description = operation.get("description", "")

    # Request body schema
    req_fields: list[dict] = []
    req_body = operation.get("requestBody", {})
    if req_body:
        content = req_body.get("content", {})
        json_content = content.get("application/json", {})
        ref = json_content.get("schema", {}).get("$ref")
        req_fields = _schema_fields(ref, components)

    # Response schema (200 or first success code)
    resp_fields: list[dict] = []
    responses = operation.get("responses", {})
    for code in ["200", "201"]:
        if code in responses:
            resp_content = responses[code].get("content", {})
            json_resp = resp_content.get("application/json", {})
            ref = json_resp.get("schema", {}).get("$ref")
            resp_fields = _schema_fields(ref, components)
            break

    lines = [
        f"### `{method.upper()} {path}`",
        "",
    ]
    if summary:
        lines += [f"**{summary}**", ""]
    if description:
        lines += [description.strip(), ""]

    lines += [f"**Auth required:** {auth_header}", ""]

    if req_fields:
        lines += ["**Request body:**", "", _fields_table(req_fields), ""]
    if resp_fields:
        lines += ["**Response (200):**", "", _fields_table(resp_fields), ""]

    lines += [
        "**Example:**",
        "",
        _curl_example(method, path, auth_header, req_fields),
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def _filter_paths(
    paths: dict,
    include_tags: set[str] | None = None,
    exclude_tags: set[str] | None = None,
) -> dict:
    """Return filtered paths dict."""
    result = {}
    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if method not in ("get", "post", "put", "patch", "delete", "head"):
                continue
            op_tags = set(operation.get("tags", []))
            if include_tags is not None and not op_tags.intersection(include_tags):
                continue
            if exclude_tags is not None and op_tags.intersection(exclude_tags):
                continue
            result.setdefault(path, {})[method] = operation
    return result


# ── Document writers ───────────────────────────────────────────────────────

def _write_gateway_api(schema: dict) -> None:
    components = schema.get("components", {})
    all_paths = schema.get("paths", {})

    # Exclude internal-only and auth-domain paths from the customer doc
    paths = _filter_paths(
        all_paths,
        exclude_tags=_INTERNAL_TAGS | _AUTH_TAGS,
    )
    # Also exclude known infrastructure paths and the catch-all proxy route
    paths = {
        p: ops for p, ops in paths.items()
        if p not in _GATEWAY_INTERNAL_PATHS
        and not p.startswith("/{")  # filter catch-all /{path:path} variants
    }

    auth_header = "Authorization: Bearer <api-key>"
    sections: list[str] = []
    for path in sorted(paths):
        for method, operation in sorted(paths[path].items()):
            sections.append(_render_endpoint(method, path, operation, components, auth_header))

    content = textwrap.dedent("""\
        # Yashigani Gateway API Reference

        The Gateway API is the AI traffic control plane. All LLM requests and
        MCP protocol traffic passes through this endpoint.

        ## Authentication

        All requests require a valid API key issued by your administrator via
        the Backoffice.

        ```
        Authorization: Bearer <api-key>
        ```

        Alternatively, if your operator has configured SSO, the Gateway accepts
        an `X-Forwarded-User` header injected by the Caddy reverse proxy after
        a successful SSO login.

        ## Transport

        The Gateway listens on HTTPS only. Mutual TLS (mTLS) is enforced by
        the Caddy edge layer for agent-to-gateway connections. API key holders
        connect over standard HTTPS.

        ## Endpoints

    """) + "\n".join(sections) if sections else textwrap.dedent("""\
        # Yashigani Gateway API Reference

        No public endpoints detected in schema.
    """)

    (_OUT / "gateway-api.md").write_text(content, encoding="utf-8")
    print(f"[gen_api_docs] wrote {_OUT / 'gateway-api.md'} ({len(sections)} endpoints)")


def _write_admin_api(schema: dict) -> None:
    components = schema.get("components", {})
    all_paths = schema.get("paths", {})

    # Exclude auth-domain paths (they go in auth-api.md)
    # Exclude known internal-only tags
    paths = _filter_paths(
        all_paths,
        exclude_tags=_AUTH_TAGS | _INTERNAL_TAGS,
    )

    auth_header = "Cookie: __Host-yashigani_admin_session=<token>"
    sections: list[str] = []
    for path in sorted(paths):
        for method, operation in sorted(paths[path].items()):
            sections.append(_render_endpoint(method, path, operation, components, auth_header))

    content = textwrap.dedent("""\
        # Yashigani Backoffice API Reference

        The Backoffice API is the operator management plane. It controls users,
        agents, policies, audit sinks, rate limits, RBAC, PKI, and licensing.

        ## Authentication

        All endpoints require a valid admin session cookie obtained via
        `POST /auth/login` followed by TOTP step-up where required.

        ```
        Cookie: __Host-yashigani_admin_session=<session-token>
        ```

        High-value endpoints (key rotation, user deletion, PKI operations)
        additionally require a step-up TOTP confirmation via `POST /auth/stepup`
        before the request is accepted.

        ## Base URL

        The Backoffice is isolated on port 8443 (TLS only). The Swagger UI is
        available at `/admin/api-docs` after logging in.

        ## Endpoints

    """) + "\n".join(sections) if sections else textwrap.dedent("""\
        # Yashigani Backoffice API Reference

        No admin endpoints detected in schema.
    """)

    (_OUT / "admin-api.md").write_text(content, encoding="utf-8")
    print(f"[gen_api_docs] wrote {_OUT / 'admin-api.md'} ({len(sections)} endpoints)")


def _write_auth_api(schema: dict) -> None:
    components = schema.get("components", {})
    all_paths = schema.get("paths", {})

    # Only auth-tagged paths
    paths = _filter_paths(all_paths, include_tags=_AUTH_TAGS)

    auth_header = "Cookie: __Host-yashigani_admin_session=<token> (or unauthenticated for login)"
    sections: list[str] = []
    for path in sorted(paths):
        for method, operation in sorted(paths[path].items()):
            sections.append(_render_endpoint(method, path, operation, components, auth_header))

    content = textwrap.dedent("""\
        # Yashigani Auth API Reference

        Authentication endpoints shared by the Backoffice admin portal and
        user login flow.

        ## Login flow

        1. `POST /auth/login` — submit username + password
        2. `POST /auth/stepup` — submit TOTP code (required for privileged ops)
        3. Use the returned session cookie on subsequent requests

        ## Endpoints

    """) + "\n".join(sections) if sections else textwrap.dedent("""\
        # Yashigani Auth API Reference

        No auth endpoints detected in schema.
    """)

    (_OUT / "auth-api.md").write_text(content, encoding="utf-8")
    print(f"[gen_api_docs] wrote {_OUT / 'auth-api.md'} ({len(sections)} endpoints)")


def _write_index() -> None:
    content = textwrap.dedent("""\
        # Yashigani API Reference

        | Document | Audience | Description |
        |----------|----------|-------------|
        | [Gateway API](gateway-api.md) | Operators, AI agents | LLM proxy + MCP traffic control |
        | [Admin API](admin-api.md) | Operators | Backoffice management plane |
        | [Auth API](auth-api.md) | All | Login, step-up, session management |

        ## Quick start

        1. Log in via the Backoffice at `https://<host>:8443/admin/login`
        2. Create an API key for your agent identity under **Agents**
        3. Use `Authorization: Bearer <key>` on all Gateway API requests

        ## Interactive docs

        Once logged in, the interactive Swagger UI is available at:

        - Backoffice: `https://<host>:8443/admin/api-docs`
        - Backoffice (ReDoc): `https://<host>:8443/admin/api-redoc`
        - Gateway: `https://<host>/docs` (requires valid Bearer token)

        Last updated: 2026-05-17
    """)
    (_OUT / "README.md").write_text(content, encoding="utf-8")
    print(f"[gen_api_docs] wrote {_OUT / 'README.md'}")


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> int:
    print("[gen_api_docs] loading backoffice schema ...")
    try:
        bo_schema = _load_backoffice_schema()
    except Exception as exc:
        print(f"[gen_api_docs] ERROR loading backoffice schema: {exc}", file=sys.stderr)
        return 1

    print("[gen_api_docs] loading gateway schema ...")
    try:
        gw_schema = _load_gateway_schema()
    except Exception as exc:
        print(f"[gen_api_docs] ERROR loading gateway schema: {exc}", file=sys.stderr)
        return 1

    _write_gateway_api(gw_schema)
    _write_admin_api(bo_schema)
    _write_auth_api(bo_schema)
    _write_index()

    print("[gen_api_docs] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
