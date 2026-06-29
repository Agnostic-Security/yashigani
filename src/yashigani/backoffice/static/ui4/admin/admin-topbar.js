// Yashigani 4.0 admin shell — <ys-admin-topbar> (TRUSTED-CHROME).
//
// Brand + active-section title + signed-in identity + sign-out. All text is
// system/server-authored and rendered via Lit auto-escaping (textContent) —
// never through the §3 markdown sink. Sign-out navigates to the admin
// single-logout redirect which clears the admin session cookie and returns to
// /admin/login (mirrors the user-plane <ys-session-header> pattern).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsAdminTopbar extends LitElement {
  static properties = {
    // Display name for the signed-in admin (server-authored). Absent → neutral.
    username: { type: String },
    // Label of the active module (trusted chrome) shown as the page title.
    sectionLabel: { type: String },
  };

  constructor() {
    super();
    this.username = '';
    this.sectionLabel = '';
  }

  createRenderRoot() { return this; }

  render() {
    return html`
      <header class="ys-admin-topbar">
        <div class="ys-admin-brand">
          <span class="ys-admin-brand-mark">Yashigani</span>
          <span class="ys-admin-brand-tag">Admin</span>
          ${this.sectionLabel
            ? html`<span class="ys-admin-section-title">${this.sectionLabel}</span>`
            : nothing}
        </div>
        <div class="ys-admin-session">
          <span class="ys-admin-user">${this.username ? this.username : 'Signed in'}</span>
          <a class="ys-btn ys-btn-secondary" href="/auth/logout-redirect">Sign out</a>
        </div>
      </header>`;
  }
}

customElements.define('ys-admin-topbar', YsAdminTopbar);
