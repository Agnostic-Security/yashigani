// Yashigani 4.0 admin shell — <ys-admin-nav> (left navigation, TRUSTED-CHROME).
//
// Renders one entry per registered admin module (module-registry.js). Entries
// are hash links (#<id>) so navigation stays inside the /admin4/ SPA, requires
// no server round-trip, and is CSP-clean (no inline handlers — Lit @click only,
// and the href carries the canonical route for middle-click/bookmarking).
//
// `modules` and `active` arrive already-typed from the root app. label/icon are
// author-supplied trusted chrome rendered via Lit textContent (spec §3.3) — a
// module id is a slug, never user input.
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';

export class YsAdminNav extends LitElement {
  static properties = {
    // [{id, label, icon, order, render}] from getAdminModules().
    modules: { type: Array },
    // id of the active module (highlights the entry).
    active: { type: String },
  };

  constructor() {
    super();
    this.modules = [];
    this.active = '';
  }

  createRenderRoot() { return this; }

  _select(id, e) {
    // Let the browser update the hash via the href; we also emit an intent event
    // so the app can react synchronously without waiting for hashchange.
    if (e) e.preventDefault();
    if (window.location.hash !== `#${id}`) {
      window.location.hash = `#${id}`;
    }
    this.dispatchEvent(new CustomEvent('ys-admin-nav-select', {
      detail: { id }, bubbles: true, composed: true,
    }));
  }

  render() {
    const mods = Array.isArray(this.modules) ? this.modules : [];
    return html`
      <nav class="ys-admin-nav" aria-label="Admin sections">
        ${mods.length === 0
          ? html`<div class="ys-txt-note ys-admin-nav-empty">No modules registered.</div>`
          : mods.map((m) => html`
              <a class="ys-admin-nav-link ${m.id === this.active ? 'ys-admin-nav-active' : ''}"
                 href="#${m.id}"
                 aria-current=${m.id === this.active ? 'page' : 'false'}
                 @click=${(e) => this._select(m.id, e)}
                 @keydown=${(e) => { if (e.key === 'Enter' || e.key === ' ') this._select(m.id, e); }}>
                <span class="ys-admin-nav-icon" aria-hidden="true">${m.icon}</span>
                <span class="ys-admin-nav-label">${m.label}</span>
              </a>`)}
      </nav>`;
  }
}

customElements.define('ys-admin-nav', YsAdminNav);
