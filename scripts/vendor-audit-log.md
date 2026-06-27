# Vendor Audit Log

Pre-vendoring audit results for all third-party JS/CSS bundles under `static/vendor/`.
Every library must have an entry here before it may be added to `vendor-integrity.lock`
and referenced in HTML templates.

---

## Lit 3.3.3 — 2026-06-27

- **Audit result:** PASS
- **eval-audit.sh output:** PASS — no eval/Function/setTimeout-string/setInterval-string/document.write patterns
- **DOMPurify TrustedHTML compat check:** N/A (Lit does not use DOMPurify)
- **Source of download:** esbuild bundle from `https://registry.npmjs.org/lit/-/lit-3.3.3.tgz`
  Built with: `npx esbuild lit-bundle-entry.js --bundle --format=esm --minify --target=es2020`
  Entry point exports: lit, lit/decorators.js, lit/directives/{repeat,when,class-map,style-map,if-defined,cache,ref,live,unsafe-html,map,until}
- **Bundle notes:** esbuild@0.28.1 (installed via npx); output: ESM, no eval source-map,
  no dynamic imports. sourceMappingURL absent in output.
- **SHA-384:** sha384-cBzrHZ8u4IIGOvDAM8EvZTPl/pjhSl5VSC5gtkUvAi10eJbxv8gLfqW6Z7E8EceE
  (matches `scripts/vendor-integrity.lock`)
- **File:** `static/vendor/lit/lit-all-3.3.3.min.js` (28,356 bytes)
- **License:** BSD-3-Clause (Google LLC) — `static/vendor/lit/LICENSE`
- **Auditor:** Su / 2026-06-27

---

## DOMPurify 3.4.11 — 2026-06-27

- **Audit result:** PASS
- **eval-audit.sh output:** PASS — no eval-class patterns found
- **DOMPurify TrustedHTML compat check:** PASS — version 3.4.11 >= 2.4.0;
  `RETURN_TRUSTED_TYPE: true` is supported (requires DOMPurify >= 2.4.0 per spec §3.7).
  The `createHTML` callback in `yashigani-render` policy uses this option.
- **Source of download:** `https://registry.npmjs.org/dompurify/-/dompurify-3.4.11.tgz`
  Extracted: `package/dist/purify.min.js` (official pre-built minified UMD bundle)
- **Bundle notes:** sourceMappingURL comment stripped (spec §3.1: no .map files shipped).
  Pre-built by Cure53 using their standard release pipeline.
- **SHA-384:** sha384-L4fiZZO0ovDfQmTlw6xSYZzb9ehmGvwXbpu/e+rKu7UFhn2E3NbfiHVAKXw3AqnI
  (matches `scripts/vendor-integrity.lock`)
- **File:** `static/vendor/dompurify/purify-3.4.11.min.js` (28,438 bytes)
- **License:** Apache-2.0 (Cure53 and other contributors) — `static/vendor/dompurify/LICENSE`
- **Auditor:** Su / 2026-06-27

---

## marked 18.0.5 — 2026-06-27

- **Audit result:** PASS
- **eval-audit.sh output:** PASS — no eval-class patterns found
- **DOMPurify TrustedHTML compat check:** N/A (marked is the parser; DOMPurify
  sanitizes its output in the `yashigani-render` TT policy)
- **Source of download:** `https://registry.npmjs.org/marked/-/marked-18.0.5.tgz`
  Extracted: `package/lib/marked.umd.js` (UMD production build)
- **Bundle notes:** marked 18.x ships a UMD production build only (no pre-minified .min.js).
  The UMD build is the official production artifact used in browser contexts.
  sourceMappingURL comment stripped (spec §3.1: no .map files shipped).
  Named `marked-18.0.5.min.js` per the version-in-filename convention (spec §3.1).
- **SHA-384:** sha384-uoUU9Qe/2pBp2tX+Izn5kp+Z7J0TjfXlyVEAZY/AQ+NiiaftxNni6grS8JufpRjQ
  (matches `scripts/vendor-integrity.lock`)
- **File:** `static/vendor/marked/marked-18.0.5.min.js` (42,921 bytes)
- **License:** MIT (MarkedJS, 2018-2026) — `static/vendor/marked/LICENSE`
- **Auditor:** Su / 2026-06-27

---

## Drawflow 0.0.60 — 2026-06-27

- **Audit result:** PASS (source UMD) — see TT decision below
- **eval-audit.sh output:** PASS — no eval/Function/setTimeout-string/setInterval-string/document.write
  patterns found in `package/dist/drawflow.min.js` (webpack 4, UMD production build).
- **DOMPurify TrustedHTML compat check:** N/A for the source UMD directly. The ESM shim imports
  `purify.es.mjs` (already vendored/audited at 3.4.11) and uses its zero-allowlist mode for
  the `drawflow-label` TT policy output. DOMPurify >= 2.4.0 confirmed.
- **Source of download:** `https://registry.npmjs.org/drawflow/-/drawflow-0.0.60.tgz`
  Extracted: `package/dist/drawflow.min.js` (UMD, no sourceMappingURL) +
             `package/dist/drawflow.min.css` (1910 bytes, no sourceMappingURL)
- **No ESM build in package** — Drawflow 0.0.60 ships UMD only (`main: dist/drawflow.min.js`,
  no `module` field). ESM shim built by wrapping with Python block-scope capture of
  module/exports (same pattern as Phase 1 Lit shim).

**TT compatibility audit (RISK-096) — innerHTML call inventory:**

Drawflow 0.0.60 contains 8 `innerHTML` assignments:

| # | Pattern | Type | Decision |
|---|---------|------|----------|
| 1 | `t.innerHTML="x"` | Literal string (delete icon) | → `t.textContent="x"` |
| 2 | `h.innerHTML=""` | Empty string (node init) | → `h.textContent=""` |
| 3 | `_.innerHTML=c` | `html` param when `typenode===false` | → `_.innerHTML=__df_tt(c)` |
| 4 | `i.innerHTML=""` | Empty string (import node init) | → `i.textContent=""` |
| 5 | `c.innerHTML=e.html` | `html` field on import when `typenode===false` | → `c.innerHTML=__df_tt(e.html)` |
| 6–8 | `this.precanvas.innerHTML=""` (×3) | Canvas clear | → `this.precanvas.textContent=""` |

Patches 1,2,4,6,7,8 (6 safe literal/empty assignments): replaced with `textContent`
equivalents — no TT policy needed, no semantic change.

Patches 3 and 5 (2 variable assignments): `__df_tt()` wrapper injected into the ESM
shim. `__df_tt()` runs DOMPurify with `ALLOWED_TAGS:[], ALLOWED_ATTR:[]` (zero-allowlist
— strips ALL HTML, labels are plain-text identifiers per R11), then routes through the
`drawflow-label` TT policy registered in `ui4/core/drawflow-safe.js`.

**TT policy decision (spec §2.4, RECONCILIATION R1 conditional):**
R1 specifies: "drawflow-label not created unless a later Drawflow audit proves textContent
impossible." Audit finding: Drawflow's internal `innerHTML=variable` calls (patches 3+5)
cannot be replaced with textContent without forking the library's rendering logic (they
assign node HTML templates, not identifiers). The conditional in R1 is met. `drawflow-label`
TT policy IS registered (in `ui4/core/drawflow-safe.js`), added to the `trusted-types`
directive in `docker/Caddyfile.csp` (alongside `yashigani-render dompurify lit-html`).

When `typenode=true` (MANDATORY in the agent builder — enforced by `mountDrawflowSafe()`),
Drawflow takes the `cloneNode(!0)` path (not innerHTML) for node content. The `__df_tt()`
wrappers then receive developer-authored template strings (or empty strings during import)
and sanitize them to plain text. User-supplied labels are assigned via `textContent` by the
builder UI layer — never through Drawflow's `html` parameter.

- **SHA-384 (ESM shim):**
  `sha384-8u9QSHa0NpNzUh7hK3NiCiTkf7Uduk/Nhhwh/tw9mG0YnBEOVlEYwpZHsHpyFQxw`
  (matches `scripts/vendor-integrity.lock`)
- **SHA-384 (CSS):**
  `sha384-IFh+Q6zh+LRcTjqVmAKetdGY59dT485vtvWT5DAKQy8iv5+fYWHXisHP7mFKcFqV`
  (matches `scripts/vendor-integrity.lock`)
- **Files:**
  `static/vendor/drawflow/drawflow.esm.js` (50,731 bytes — patched ESM shim)
  `static/vendor/drawflow/drawflow.min.css` (1,910 bytes)
  `static/vendor/drawflow/LICENSE` (MIT)
- **License:** MIT (Jero Soler / jerosoler/Drawflow)
- **Auditor:** Su / 2026-06-27

---

## swagger-ui-bundle.js — KNOWN FAIL (existing, not yet remediated)

- **Audit result:** KNOWN FAIL (RISK-115 / SC-NEW-004)
- **eval-audit.sh output:** FAIL — webpack eval source-maps present in existing bundle
- **Notes:** The existing `static/swagger-ui/swagger-ui-bundle.js` was NOT vendored
  through this audit process (predates the integrity gate). It contains `eval` calls
  from webpack's `devtool: eval-source-map` mode. Remediation: rebuild from source
  with `devtool: false`. See spec §3.6 for the full remediation procedure.
  Serving under `/docs` route which has `@strict_legacy` CSP (`script-src 'self'`,
  no 'unsafe-eval') — verify no CSP console violations from swagger-ui before Phase 1
  ships. If eval violations appear, scope to a dedicated `@swagger_ui` matcher.
- **File:** `static/swagger-ui/swagger-ui-bundle.js` (unversioned, NOT in lock)
- **Scheduled for remediation:** Phase 1 swagger-ui production rebuild

---

## redoc.standalone.js — PENDING (existing, not yet audited)

- **Audit result:** NOT YET RUN
- **eval-audit.sh output:** NOT RUN — must run before SRI is added to template
- **Notes:** Existing `static/swagger-ui/redoc.standalone.js`. Run
  `scripts/audit-vendor-eval.sh` against it and record result here.
  If PASS: add version to filename, add to lock, add integrity= to redoc template.
  If FAIL: scope to dedicated matcher with documented justification.
- **File:** `static/swagger-ui/redoc.standalone.js` (unversioned, NOT in lock)
