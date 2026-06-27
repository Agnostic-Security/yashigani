// Yashigani 4.0 admin app — <ys-admin-app> (root shell, 3.0 dashboard.js
// replacement). Wave 1: the shell + framework + the Dashboard reference module.
// Module groups (RBAC, audit, KMS, policies, …) plug in next (Wave 2) against
// the PINNED contract in module-registry.js — adding a module is one side-effect
// import in the MODULES block below, nothing else here changes.
//
// Same hardened stack as the user UI (truly identical): the audited core layer
// (ApiClient + Trusted-Types + safe-render + widgets), classes-only CSS, ES
// modules only, no inline script/style. The admin client is its OWN per-plane
// ApiClient({sessionKind:'admin'}) — NEVER shared with the user plane (RISK-100)
// — which selects the admin route group, the /admin/login redirect on 401, and
// honours the server's step_up_required tag via the shared TOTP modal.
//
// Load order (spec §1): installTrustedTypes() runs first so the named TT policy
// is registered before any sink (importing the core barrel triggers it
// transitively; the explicit call honours the contract and is idempotent).
import { ApiClient, installTrustedTypes, widgets } from '../core/index.js';
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';
import './admin-topbar.js';
import './admin-nav.js';
import { getAdminModules, getAdminModule } from './module-registry.js';

// ── MODULES (Wave-2 plug-in point) ───────────────────────────────────────────
// Each side-effect import self-registers via registerAdminModule(). Wave 2 adds
// one line per module group here; the shell discovers them through the registry.
import './modules/dashboard.js';
// Identity & Access module group (feat/4.0-admin-iam): accounts/users, RBAC+SCIM,
// SSO/JWT federation, passkeys/HIBP/rate-limit.
import './modules/accounts.js';
import './modules/rbac.js';
import './modules/sso.js';
import './modules/security-auth.js';

// Register the named TT policy before any sink runs (spec §1). `widgets` is
// referenced so its side-effect import (ys-* custom elements incl. ys-toast /
// ys-modal for step-up) is retained.
installTrustedTypes();
void widgets;

export class YsAdminApp extends LitElement {
  static properties = {
    _modules: { state: true },
    _activeId: { state: true },
    _username: { state: true },
  };

  constructor() {
    super();
    this._modules = getAdminModules();
    this._username = '';
    // Active module: from the URL hash if it names a registered module, else the
    // first registered module (Dashboard, order:0).
    this._activeId = this._resolveInitialActive();

    // ONE per-plane client. sessionKind:'admin' → admin route group + the
    // /admin/login redirect on 401. onStepUp wires the shared TOTP modal so any
    // module's mutate() that the server tags step_up_required transparently
    // prompts, posts /auth/stepup, and retries once (api-client.js §2.6).
    this.api = new ApiClient({
      sessionKind: 'admin',
      onStepUp: (spec) => widgets.promptStepUp(spec),
    });

    this._onHashChange = () => {
      const id = this._idFromHash();
      if (id && getAdminModule(id)) this._activeId = id;
    };
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    window.addEventListener('hashchange', this._onHashChange);
    // Normalise the hash so a deep-link / refresh stays on the active module.
    if (this._activeId && window.location.hash !== `#${this._activeId}`) {
      try { window.history.replaceState(null, '', `#${this._activeId}`); } catch { /* noop */ }
    }
  }

  disconnectedCallback() {
    window.removeEventListener('hashchange', this._onHashChange);
    super.disconnectedCallback();
  }

  _idFromHash() {
    const h = (window.location.hash || '').replace(/^#/, '').trim();
    return h || '';
  }

  _resolveInitialActive() {
    const fromHash = this._idFromHash();
    if (fromHash && getAdminModule(fromHash)) return fromHash;
    return this._modules.length ? this._modules[0].id : '';
  }

  _onNavSelect(e) {
    const id = e.detail && e.detail.id;
    if (id && getAdminModule(id)) this._activeId = id;
  }

  /**
   * Cross-cutting chrome handle exposed to modules via ctx.app (module-registry
   * contract). Transient notice through the shared <ys-toast>.
   * @param {string} message server/system-authored text (trusted chrome)
   * @param {'info'|'error'|'success'} [kind]
   */
  toast(message, kind = 'info') {
    const t = this.querySelector('ys-toast');
    if (t && typeof t.show === 'function') t.show(message, kind);
  }

  _renderActive() {
    const mod = getAdminModule(this._activeId);
    if (!mod) {
      return html`<div class="ys-admin-content-pad">
        <div class="ys-txt-note">No admin module selected.</div>
      </div>`;
    }
    // The PINNED context handed to every module's render() (see module-registry).
    const ctx = { api: this.api, app: this };
    return mod.render(ctx);
  }

  render() {
    const active = getAdminModule(this._activeId);
    return html`
      <div class="ys-admin-app"
           @ys-admin-nav-select=${(e) => this._onNavSelect(e)}>
        <ys-admin-topbar
          .username=${this._username}
          .sectionLabel=${active ? active.label : ''}></ys-admin-topbar>
        <div class="ys-admin-body">
          <ys-admin-nav
            .modules=${this._modules}
            .active=${this._activeId}></ys-admin-nav>
          <main class="ys-admin-content">
            ${this._renderActive()}
          </main>
        </div>
        <ys-toast></ys-toast>
      </div>`;
  }
}

customElements.define('ys-admin-app', YsAdminApp);
