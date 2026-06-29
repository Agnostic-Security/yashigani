// Yashigani 4.0 shared layer — <ys-toast> (spec §5, TRUSTED-CHROME).
//
// Transient notices/errors. Replaces 3.0 _showAuthzError() (dashboard.js:651).
// All text is server/system-authored and rendered via Lit auto-escaping
// (textContent) — never through the §3 markdown sink.
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';

export class YsToast extends LitElement {
  static properties = { _items: { state: true } };

  constructor() {
    super();
    this._items = [];
    this._seq = 0;
  }

  createRenderRoot() { return this; }

  /** Show a toast. kind: 'info' | 'error' | 'success'. Auto-dismisses. */
  show(message, kind = 'info', ttlMs = 5000) {
    const id = ++this._seq;
    this._items = [...this._items, { id, message: String(message == null ? '' : message), kind }];
    if (ttlMs > 0) setTimeout(() => this.dismiss(id), ttlMs);
    return id;
  }

  dismiss(id) {
    this._items = this._items.filter((it) => it.id !== id);
  }

  render() {
    return html`
      <div class="ys-toast-stack">
        ${this._items.map((it) => html`
          <div class="ys-toast ys-toast-${it.kind}" role="status"
               @click=${() => this.dismiss(it.id)}>${it.message}</div>`)}
      </div>`;
  }
}

customElements.define('ys-toast', YsToast);
