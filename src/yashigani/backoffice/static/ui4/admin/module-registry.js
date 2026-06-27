// Yashigani 4.0 admin shell — module-registration contract (Wave-1 PINNED).
//
// This is the STABLE seam Wave-2 module groups build to. Keep it small and
// additive: never break an existing field; add new optional fields only.
//
// ── The contract ────────────────────────────────────────────────────────────
// A module group registers ONE descriptor per admin section by calling
// `registerAdminModule(descriptor)` at module-evaluation time (i.e. as a
// side-effect of being imported by admin-app.js). The descriptor shape:
//
//   registerAdminModule({
//     id:    'rbac',            // REQUIRED. Unique, stable, URL-safe slug. Drives
//                               //   the nav entry and the location.hash route
//                               //   (#rbac). Re-registering an id is ignored
//                               //   (first registration wins) so a double-import
//                               //   can never duplicate a nav entry.
//     label: 'Access control',  // REQUIRED. Nav text. TRUSTED-CHROME — rendered
//                               //   via Lit textContent, never the §3 markdown
//                               //   sink. Author-supplied, never user input.
//     icon:  'lock',            // OPTIONAL. Short glyph/emoji string shown in the
//                               //   nav. TRUSTED-CHROME (textContent). Defaults
//                               //   to '•'.
//     order: 30,                // OPTIONAL. Sort weight (asc). Default 100; ties
//                               //   break on label. Dashboard pins itself at 0.
//     render: (ctx) => html`…`, // REQUIRED. Pure function returning a Lit
//                               //   TemplateResult for the content area. Called
//                               //   on every shell re-render of the active
//                               //   module — keep it cheap; do data-loading in
//                               //   your own LitElement's lifecycle, not here.
//   });
//
// ── The context (ctx) passed to render() ─────────────────────────────────────
//   ctx.api    The ONE shared ApiClient({sessionKind:'admin'}) — RISK-100: never
//              construct your own, never share with the user plane. Step-up is
//              already wired (ctx.api honours the server's step_up_required tag
//              via the shared TOTP modal). Use ctx.api.get / .mutate / .stream.
//   ctx.app    The <ys-admin-app> root, for cross-cutting chrome only:
//                ctx.app.toast(message, kind)  — transient notice via <ys-toast>
//                                                  (kind: 'info'|'error'|'success')
//              Do NOT reach into app private state; the contract is toast() only.
//
// ── Authoring pattern (what a Wave-2 module file looks like) ──────────────────
//   1. Define a LitElement, e.g. <ys-admin-rbac>, that takes `.api` as a
//      property and owns its own fetch/render (mirror modules/dashboard.js).
//   2. Register a thin descriptor whose render() just mounts that element and
//      forwards ctx.api:
//        import { registerAdminModule } from '../module-registry.js';
//        import { html } from '/static/vendor/lit/lit-core.min.js';
//        import './rbac-element.js';            // defines <ys-admin-rbac>
//        registerAdminModule({
//          id: 'rbac', label: 'Access control', icon: 'lock', order: 30,
//          render: (ctx) => html`<ys-admin-rbac .api=${ctx.api}
//                                  .app=${ctx.app}></ys-admin-rbac>`,
//        });
//   3. Add a single side-effect import of your module file to admin-app.js's
//      MODULE import block. That is the only edit to the shell.
//
// This file has NO dependency on Lit or the DOM — it is a pure registry — so the
// contract stays trivially testable and stable across the rebuild.

/** @typedef {{api: import('../core/api-client.js').ApiClient, app: any}} AdminModuleCtx */
/**
 * @typedef {Object} AdminModule
 * @property {string} id                          unique stable slug (nav + #hash)
 * @property {string} label                       nav text (trusted chrome)
 * @property {string} [icon]                       short glyph (trusted chrome)
 * @property {number} [order]                      sort weight (asc, default 100)
 * @property {(ctx: AdminModuleCtx) => unknown} render  → Lit TemplateResult
 */

/** @type {Map<string, AdminModule>} insertion-ordered, deduped by id. */
const _modules = new Map();

/**
 * Register an admin module descriptor (idempotent per id; first wins).
 * Validates the required fields and fails LOUD on a malformed descriptor so a
 * broken Wave-2 module is caught at load, not silently dropped from the nav.
 *
 * @param {AdminModule} mod
 * @returns {boolean} true if registered, false if a duplicate id was ignored
 */
export function registerAdminModule(mod) {
  if (!mod || typeof mod !== 'object') {
    throw new Error('registerAdminModule: descriptor must be an object');
  }
  const { id, label, render } = mod;
  if (typeof id !== 'string' || !id.trim()) {
    throw new Error('registerAdminModule: `id` must be a non-empty string');
  }
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(id)) {
    throw new Error(`registerAdminModule: \`id\` must be a URL-safe slug (got ${JSON.stringify(id)})`);
  }
  if (typeof label !== 'string' || !label.trim()) {
    throw new Error(`registerAdminModule(${id}): \`label\` must be a non-empty string`);
  }
  if (typeof render !== 'function') {
    throw new Error(`registerAdminModule(${id}): \`render\` must be a function`);
  }
  if (_modules.has(id)) {
    return false; // first registration wins; double-import is a no-op.
  }
  _modules.set(id, Object.freeze({
    id,
    label,
    icon: typeof mod.icon === 'string' && mod.icon ? mod.icon : '•',
    order: Number.isFinite(mod.order) ? Number(mod.order) : 100,
    render,
  }));
  return true;
}

/**
 * Return all registered modules, sorted by `order` then `label`. The returned
 * array is a fresh copy — callers cannot mutate the registry.
 * @returns {AdminModule[]}
 */
export function getAdminModules() {
  return [..._modules.values()].sort(
    (a, b) => (a.order - b.order) || a.label.localeCompare(b.label),
  );
}

/** Look up a single module by id (or null). */
export function getAdminModule(id) {
  return _modules.get(id) || null;
}

// Test-only: clear the registry (never called by the shell). Lets unit tests
// register/inspect in isolation without module-cache bleed.
export function _resetAdminModules() {
  _modules.clear();
}
