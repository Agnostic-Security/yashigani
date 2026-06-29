// Yashigani 4.0 shared layer — <ys-modal> (spec §5, TRUSTED-CHROME).
//
// Generic modal + a step-up (TOTP) helper. Replaces 3.0 _showStepUpModal()
// (dashboard.js:680). All content is system-authored; slotted children render
// via Lit. The step-up flow is wired into ApiClient via the onStepUp callback.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

export class YsModal extends LitElement {
  static properties = {
    open: { type: Boolean, reflect: true },
    heading: { type: String },
  };

  constructor() {
    super();
    this.open = false;
    this.heading = '';
  }

  createRenderRoot() { return this; }

  close() {
    this.open = false;
    this.dispatchEvent(new CustomEvent('ys-close'));
  }

  render() {
    if (!this.open) return nothing;
    return html`
      <div class="ys-modal-backdrop" @click=${(e) => { if (e.target === e.currentTarget) this.close(); }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          ${this.heading ? html`<div class="ys-modal-header">${this.heading}</div>` : nothing}
          <div class="ys-modal-body"><slot></slot></div>
          <div class="ys-modal-footer"><slot name="footer"></slot></div>
        </div>
      </div>`;
  }
}

customElements.define('ys-modal', YsModal);

/**
 * Promise-based TOTP step-up prompt for ApiClient's onStepUp. Resolves with the
 * 6-digit code, or null on cancel. Attaches to <body>.
 *
 * IMPLEMENTATION NOTE (4.0 step-up fix): the modal markup is built directly here
 * rather than via the <ys-modal> custom element. <ys-modal> renders in LIGHT DOM
 * (createRenderRoot() returns `this`) but projects content through <slot> /
 * <slot name="footer"> — slots only project in SHADOW DOM, so light-DOM slotted
 * children render OUTSIDE the modal card and are covered by the full-screen
 * backdrop, making the TOTP input + Verify button unclickable. That broke EVERY
 * step-up path in the admin SPA (NHI SVID approve, cloud-key set, model RBAC
 * writes, MCP re-approval). Building the backdrop→card→body/footer tree as real
 * DOM nodes (createElement + textContent — CSP-clean, no innerHTML, no slots)
 * sidesteps the projection bug entirely and keeps the same onStepUp contract.
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
        || 'Enter your 6-digit authenticator code to authorise this action.');
    const input = mk('input', 'ys-input');
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('autocomplete', 'one-time-code');
    input.maxLength = 6;
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
      cleanup(/^\d{6}$/.test(v) ? v : null);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') okBtn.click();
      else if (e.key === 'Escape') cleanup(null);
    });

    document.body.appendChild(backdrop);
    requestAnimationFrame(() => input.focus());
  });
}
