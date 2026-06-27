// Yashigani 4.0 user app — <ys-mention-menu> (@-mention autocomplete popup).
//
// Presentational only: the chat composer (<ys-chat-view>) owns the fetch+cache
// of GET /user/mentions, the typed filter, the active index, and the textarea
// insertion. This widget just renders the already-filtered list and emits intent
// events. handle/display are UNTRUSTED (per-user agent/persona names): they reach
// the DOM ONLY through Lit text bindings (textContent-equivalent, auto-escaped) —
// never innerHTML, never the §3 markdown sink. CSP/Trusted-Types clean: no inline
// styles, no raw HTML.
//
// Events (bubbles+composed):
//   - ys-mention-pick   {item}  — user chose an entry (click / Enter / Tab)
//   - ys-mention-active {index} — pointer hover moved the highlight
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsMentionMenu extends LitElement {
  static properties = {
    items: { attribute: false },  // [{handle, kind, display, id}] (already filtered)
    active: { type: Number },     // highlighted index
  };

  constructor() {
    super();
    this.items = [];
    this.active = 0;
  }

  createRenderRoot() { return this; }

  _pick(item) {
    this.dispatchEvent(new CustomEvent('ys-mention-pick', {
      detail: { item }, bubbles: true, composed: true,
    }));
  }

  _hover(index) {
    this.dispatchEvent(new CustomEvent('ys-mention-active', {
      detail: { index }, bubbles: true, composed: true,
    }));
  }

  render() {
    const items = Array.isArray(this.items) ? this.items : [];
    if (!items.length) return nothing;
    return html`
      <div class="ys-mention-menu" role="listbox" aria-label="Mentionable agents and personas">
        ${items.map((it, i) => {
          // String(...) keeps untrusted values as plain text; Lit escapes the
          // interpolation into element content (no markup is ever parsed here).
          const handle = String((it && it.handle) ?? '');
          const display = String((it && it.display) ?? handle);
          const kind = (it && it.kind) === 'persona' ? 'persona' : 'agent';
          return html`
            <div class="ys-mention-item ${i === this.active ? 'ys-mention-active' : ''}"
                 role="option" aria-selected=${i === this.active}
                 @mousedown=${(e) => { e.preventDefault(); this._pick(it); }}
                 @mouseenter=${() => this._hover(i)}>
              <span class="ys-mention-display">${display}</span>
              <span class="ys-mention-handle">@${handle}</span>
              <span class="ys-mention-kind">${kind}</span>
            </div>`;
        })}
      </div>`;
  }
}

customElements.define('ys-mention-menu', YsMentionMenu);
