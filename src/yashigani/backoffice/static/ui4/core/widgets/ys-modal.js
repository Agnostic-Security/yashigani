// Yashigani 4.0 shared layer — <ys-modal> (spec §5, TRUSTED-CHROME).
//
// Generic modal + a step-up (TOTP) helper. Replaces 3.0 _showStepUpModal()
// (dashboard.js:680). All content is system-authored; declaratively-nested
// children are re-homed into the card by <ys-modal> itself (no <slot> — see
// the PROJECTION FIX comment on connectedCallback() below). The step-up flow
// is wired into ApiClient via the onStepUp callback.
import { LitElement, html, nothing, createRef, ref } from '/static/vendor/lit/lit-core.min.js';

export class YsModal extends LitElement {
  static properties = {
    open: { type: Boolean, reflect: true },
    heading: { type: String },
  };

  constructor() {
    super();
    this.open = false;
    this.heading = '';
    // Captured once in connectedCallback(), before this element's own render()
    // ever runs — see PROJECTION FIX (V50-030) below.
    this._projected = null;
    this._bodyRef = createRef();
    this._footerRef = createRef();
  }

  createRenderRoot() { return this; }

  // PROJECTION FIX (V50-030): <ys-modal> renders in LIGHT DOM (createRenderRoot
  // returns `this`, matching every other ui4 widget — see ys-markdown.js — so
  // the global design-system.css classes apply without a per-component shadow
  // stylesheet). <slot>/<slot name="footer"> ONLY project content in SHADOW
  // DOM; in light DOM they render empty, so the consumer's declaratively
  // nested children (e.g. ys-settings-panel's Default-model/Theme/API-keys
  // fields + Cancel/Save footer buttons — the only current consumer of the
  // <ys-modal> element itself) were left as untouched siblings of the
  // backdrop/card this component renders — sitting OUTSIDE the card and
  // underneath the full-screen backdrop, which then intercepts every pointer
  // event aimed at them. (The 6 admin modules that reuse the ys-modal-* CSS
  // classnames — backup.js, agents.js, mcp.js, agent-templates.js,
  // policies-opa.js, _iam.js's step-up caller — build their own backdrop/card
  // markup inline in their own Lit templates and never instantiate the
  // <ys-modal> element or its slots, so they were never affected by this bug.)
  // Same root cause already fixed below for the standalone step-up modal
  // (promptStepUp), which sidesteps it by building real DOM nodes with no
  // <slot> at all. Same remedy applied here: capture the consumer's actual
  // light-DOM children ONCE, on connect (before Lit's own render ever touches
  // `this`), then re-home them into the rendered card's body/footer
  // containers on every update via ref() — no <slot> anywhere, so this can
  // never regress silently.
  connectedCallback() {
    if (this._projected === null) {
      this._projected = Array.from(this.childNodes);
      for (const n of this._projected) n.remove();
    }
    super.connectedCallback();
  }

  close() {
    this.open = false;
    this.dispatchEvent(new CustomEvent('ys-close'));
  }

  updated(changed) {
    super.updated(changed);
    if (!this.open || !this._projected) return;
    const body = this._bodyRef.value;
    const footer = this._footerRef.value;
    if (!body || !footer) return;
    for (const n of this._projected) {
      const toFooter = n.nodeType === Node.ELEMENT_NODE && n.getAttribute('slot') === 'footer';
      (toFooter ? footer : body).appendChild(n);
    }
  }

  render() {
    if (!this.open) return nothing;
    return html`
      <div class="ys-modal-backdrop" @click=${(e) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          ${this.heading ? html`<div class="ys-modal-header">${this.heading}</div>` : nothing}
          <div class="ys-modal-body" ${ref(this._bodyRef)}></div>
          <div class="ys-modal-footer" ${ref(this._footerRef)}></div>
        </div>
      </div>`;
  }
}

customElements.define('ys-modal', YsModal);

/**
 * Promise-based TOTP step-up prompt for ApiClient's onStepUp. Resolves with the
 * 6-digit code, or null on cancel. Attaches to <body>.
 *
 * IMPLEMENTATION NOTE (4.0 step-up fix, predates V50-030): the modal markup is
 * built directly here rather than via the <ys-modal> custom element. At the
 * time this was written, <ys-modal> rendered in LIGHT DOM (createRenderRoot()
 * returns `this`) but projected content through <slot> / <slot name="footer">
 * — slots only project in SHADOW DOM, so light-DOM slotted children rendered
 * OUTSIDE the modal card and were covered by the full-screen backdrop, making
 * the TOTP input + Verify button unclickable. That broke EVERY step-up path in
 * the admin SPA (NHI SVID approve, cloud-key set, model RBAC writes, MCP
 * re-approval). Building the backdrop→card→body/footer tree as real DOM nodes
 * (createElement + textContent — CSP-clean, no innerHTML, no slots) sidesteps
 * the projection bug entirely and keeps the same onStepUp contract. <ys-modal>
 * itself now uses the same "no <slot>" remedy (V50-030, see connectedCallback()
 * above) so this standalone build-up is kept only for parity/isolation, not
 * because <ys-modal> is unsafe to use — but there is no need to migrate it.
 *
 * @param {object} [spec] server-provided step-up spec (e.g. {action})
 * @returns {Promise<string|null>}
 */
export function promptStepUp(spec) {
  return new Promise((resolve) => {
    const mk = (tag, cls, text) => {
      const el = document.createElement(tag);
      if (cls) el.className = cls;
      if (text != null) el.textContent = text; // textContent — never markdown/innerHTML
      return el;
    };

    const backdrop = mk('div', 'ys-modal-backdrop');
    const card = mk('div', 'ys-modal');
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');

    const header = mk('div', 'ys-modal-header', 'Step-up verification required');

    const body = mk('div', 'ys-modal-body');
    const label = mk('div', 'ys-label',
      (spec && spec.message)
        || 'Enter your authenticator code (6 or 8 digits) to authorise this action.');
    const input = mk('input', 'ys-input');
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('autocomplete', 'one-time-code');
    input.setAttribute('pattern', '[0-9]{6,8}');
    input.maxLength = 8;
    body.appendChild(label);
    body.appendChild(input);

    const footer = mk('div', 'ys-modal-footer');
    const cancelBtn = mk('button', 'ys-btn ys-btn-secondary', 'Cancel');
    const okBtn = mk('button', 'ys-btn', 'Verify');
    footer.appendChild(cancelBtn);
    footer.appendChild(okBtn);

    card.appendChild(header);
    card.appendChild(body);
    card.appendChild(footer);
    backdrop.appendChild(card);

    const cleanup = (val) => {
      backdrop.remove();
      resolve(val);
    };
    backdrop.addEventListener('click', (e) => { if (e.target === backdrop) cleanup(null); });
    cancelBtn.addEventListener('click', () => cleanup(null));
    okBtn.addEventListener('click', () => {
      const v = input.value.trim();
      cleanup(/^\d{6,8}$/.test(v) ? v : null);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') okBtn.click();
      else if (e.key === 'Escape') cleanup(null);
    });

    document.body.appendChild(backdrop);
    requestAnimationFrame(() => input.focus());
  });
}
