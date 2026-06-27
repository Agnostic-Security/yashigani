// Yashigani 4.0 user app — <ys-session-header> (user-tier session view).
//
// TRUSTED-CHROME. Brand + signed-in identity + logout. All text is
// system/server-authored and rendered via Lit auto-escaping (textContent) —
// never through the §3 markdown sink. Logout navigates to the browser-navigable
// single-logout redirect (/auth/logout-redirect) which clears the user session
// cookie (__Host-yashigani_session) and returns to /login.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

// Top-level user-plane surfaces. Plain server-side navigations (no client
// router): each is its own SPA entry point sharing this header. `active` is a
// system-authored key, never user input.
const NAV = [
  { key: 'chat', href: '/chat', label: 'Chat' },
  { key: 'agents', href: '/agents', label: 'Agents' },
  { key: 'builder', href: '/builder', label: 'Builder' },
  { key: 'workflows', href: '/workflows', label: 'Workflows' },
];

export class YsSessionHeader extends LitElement {
  static properties = {
    // Optional display name for the signed-in user (server-authored). When
    // absent we show a neutral "Signed in" — we never invent an identity.
    username: { type: String },
    // Which surface is current ('chat' | 'agents' | 'builder' | 'workflows');
    // highlights nav.
    active: { type: String },
    // When true, the Settings button is shown (only the chat surface owns the
    // settings panel). Other surfaces omit it.
    showSettings: { type: Boolean },
  };

  constructor() {
    super();
    this.username = '';
    this.active = '';
    this.showSettings = false;
  }

  createRenderRoot() { return this; }

  _openSettings() {
    this.dispatchEvent(new CustomEvent('ys-open-settings', { bubbles: true, composed: true }));
  }

  render() {
    return html`
      <header class="ys-app-header">
        <div class="ys-app-brand">
          <span class="ys-app-brand-mark">Yashigani</span>
          <nav class="ys-app-nav">
            ${NAV.map((n) => html`
              <a class="ys-nav-link ${n.key === this.active ? 'ys-nav-active' : ''}"
                 href=${n.href}>${n.label}</a>`)}
          </nav>
        </div>
        <div class="ys-app-session">
          <span class="ys-app-user">${this.username ? this.username : 'Signed in'}</span>
          ${this.showSettings
            ? html`<button class="ys-btn ys-btn-secondary ys-settings-open"
                    @click=${() => this._openSettings()}>Settings</button>`
            : nothing}
          <a class="ys-btn ys-btn-secondary" href="/auth/logout-redirect">Sign out</a>
        </div>
      </header>`;
  }
}

customElements.define('ys-session-header', YsSessionHeader);
