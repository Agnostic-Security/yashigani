/* Yashigani — Swagger UI externalised initialiser (N2 CSP fix, 2.25.5)
 *
 * Replaces the inline <script>const ui = SwaggerUIBundle({...})</script>
 * that FastAPI's get_swagger_ui_html() emits.  Inline scripts are blocked by
 * the strict CSP (script-src 'self'; no 'unsafe-inline').  This file is served
 * from /static/swagger-ui/ (same-origin) so it is always permitted.
 *
 * openapi_url is injected by the HTML template via a data attribute on the
 * <div id="swagger-ui"> element to avoid any inline script.
 */
(function () {
  var container = document.getElementById("swagger-ui");
  var openapiUrl = container ? container.getAttribute("data-openapi-url") : null;
  if (!openapiUrl) {
    console.error("swagger-ui-init.js: missing data-openapi-url on #swagger-ui");
    return;
  }
  /* global SwaggerUIBundle */
  SwaggerUIBundle({
    url: openapiUrl,
    dom_id: "#swagger-ui",
    layout: "BaseLayout",
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIBundle.SwaggerUIStandalonePreset,
    ],
  });
}());
