// Yashigani 4.0 user app — <ys-mention-menu> (@-mention autocomplete popup).
//
// Presentational only: the host composer (<ys-chat-view>, <ys-workflow-composer-app>)
// owns the fetch+cache of GET /user/mentions, the typed filter, the active index,
// and the textarea insertion. This widget just renders the already-filtered list
// and emits intent events. handle/display are UNTRUSTED (per-user agent/persona/
// MCP/API names): they reach the DOM ONLY through Lit text bindings
// (textContent-equivalent, auto-escaped) — never innerHTML, never the §3 markdown
// sink. CSP/Trusted-Types clean: no inline styles, no raw HTML.
//
// kind ∈ {agent, persona, mcp, api} — the workflow composer addresses all four;
// the chat composer typically yields agent/persona. Any unknown kind falls back
// to 'agent' for the label (the value itself is never trusted).
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
      <div class="ys-mention-menu" role="listbox" aria-label="Mentionable agents, personas, MCPs and APIs">
        ${items.map((it, i) => {
          // String(...) keeps untrusted values as plain text; Lit escapes the
          // interpolation into element content (no markup is ever parsed here).
          const handle = String((it && it.handle) ?? '');
          const display = String((it && it.display) ?? handle);
          const k = it && it.kind;
          const kind = (k === 'persona' || k === 'mcp' || k === 'api') ? k : 'agent';
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
