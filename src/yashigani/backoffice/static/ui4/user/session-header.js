// Yashigani 4.0 user app — <ys-session-header> (user-tier session view).
//
// TRUSTED-CHROME. Brand + signed-in identity + logout. All text is
// system/server-authored and rendered via Lit auto-escaping (textContent) —
// never through the §3 markdown sink. Logout navigates to the browser-navigable
// single-logout redirect (/auth/logout-redirect) which clears the user session
// cookie (__Host-yashigani_session) and returns to /login.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsSessionHeader extends LitElement {
  static properties = {
    // Optional display name for the signed-in user (server-authored). When
    // absent we show a neutral "Signed in" — we never invent an identity.
    username: { type: String },
  };

  constructor() {
    super();
    this.username = '';
  }

  createRenderRoot() { return this; }

  render() {
    return html`
      <header class="ys-app-header">
        <div class="ys-app-brand">
          <span class="ys-app-brand-mark">Yashigani</span>
        </div>
        <div class="ys-app-session">
          <span class="ys-app-user">${this.username ? this.username : 'Signed in'}</span>
          <a class="ys-btn ys-btn-secondary" href="/auth/logout-redirect">Sign out</a>
        </div>
      </header>`;
  }
}

customElements.define('ys-session-header', YsSessionHeader);
