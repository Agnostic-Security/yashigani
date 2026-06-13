"""
Yashigani — CSP-clean API documentation HTML helpers (N2 fix, 2.25.5).

FastAPI's built-in get_swagger_ui_html() and get_redoc_html() emit inline
<script> and <style> blocks that are blocked by the strict CSP
(script-src 'self'; style-src 'self'; no 'unsafe-inline').  These helpers
produce equivalent HTML with:

  - No inline <script> — init logic lives in /static/swagger-ui/swagger-ui-init.js
    (served same-origin, always permitted by script-src 'self').
  - No inline <style> — body reset moved to swagger-ui.css (already served from
    /static/swagger-ui/swagger-ui.css).
  - Redoc: the <redoc spec-url="..."> web-component attribute replaces the
    inline init call; no additional inline script is needed.  The HTML carries
    a 'Content-Security-Policy' response header that adds 'worker-src blob:
    child-src blob:' because Redoc spawns a Web Worker via blob: URL.  This
    header is set on the response in Python so Caddy's per-route CSP is
    already correct (the Caddyfile also adds worker-src blob: child-src blob:
    for /admin/api-redoc and /redoc).

Usage:
    from yashigani.api_docs import swagger_ui_html, redoc_html
    return HTMLResponse(swagger_ui_html(openapi_url="/admin/openapi.json", title="..."))
    return redoc_html(openapi_url="/admin/openapi.json", title="...")   # returns HTMLResponse
"""

from __future__ import annotations

import html as _html

from fastapi.responses import HTMLResponse

# CSP additions needed for Redoc's blob: Web Worker.
# Scoped to the two redoc routes only; all other routes keep the strict default.
_REDOC_EXTRA_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "  # Redoc injects runtime inline styles via Shadow DOM
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "worker-src blob:; "
    "child-src blob:; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "report-uri /admin/csp-report; "
    "report-to default"
)


def swagger_ui_html(
    *,
    openapi_url: str,
    title: str,
    swagger_js_url: str = "/static/swagger-ui/swagger-ui-bundle.js",
    swagger_css_url: str = "/static/swagger-ui/swagger-ui.css",
    swagger_init_js_url: str = "/static/swagger-ui/swagger-ui-init.js",
    favicon_url: str = "/static/swagger-ui/favicon.png",
) -> str:
    """Return CSP-clean Swagger UI HTML.

    The openapi_url is passed to the init script via a data attribute on
    #swagger-ui — no inline script required.  All assets are same-origin.
    """
    safe_title = _html.escape(title)
    safe_openapi = _html.escape(openapi_url, quote=True)
    safe_js = _html.escape(swagger_js_url, quote=True)
    safe_css = _html.escape(swagger_css_url, quote=True)
    safe_init = _html.escape(swagger_init_js_url, quote=True)
    safe_favicon = _html.escape(favicon_url, quote=True)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="stylesheet" type="text/css" href="{safe_css}">
<link rel="shortcut icon" href="{safe_favicon}">
<title>{safe_title}</title>
</head>
<body>
<div id="swagger-ui" data-openapi-url="{safe_openapi}"></div>
<script src="{safe_js}"></script>
<script src="{safe_init}"></script>
</body>
</html>"""


def redoc_html(
    *,
    openapi_url: str,
    title: str,
    redoc_js_url: str = "/static/swagger-ui/redoc.standalone.js",
    favicon_url: str = "/static/swagger-ui/favicon.png",
) -> HTMLResponse:
    """Return a CSP-clean ReDoc HTMLResponse.

    The <redoc spec-url="..."> web component attribute is used instead of an
    inline SwaggerUIBundle() call — no inline script required.

    The response carries an explicit Content-Security-Policy header that adds
    'worker-src blob: child-src blob:' because Redoc spawns a Web Worker via
    blob: URL internally.  This header overrides the upstream Caddy strict CSP
    for these two routes only (Caddy is also configured with a per-route
    override for /admin/api-redoc and /redoc).
    """
    safe_title = _html.escape(title)
    safe_openapi = _html.escape(openapi_url, quote=True)
    safe_js = _html.escape(redoc_js_url, quote=True)
    safe_favicon = _html.escape(favicon_url, quote=True)

    body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="shortcut icon" href="{safe_favicon}">
<title>{safe_title}</title>
</head>
<body>
<redoc spec-url="{safe_openapi}"></redoc>
<script src="{safe_js}"></script>
</body>
</html>"""

    return HTMLResponse(
        content=body,
        headers={"Content-Security-Policy": _REDOC_EXTRA_CSP},
    )
