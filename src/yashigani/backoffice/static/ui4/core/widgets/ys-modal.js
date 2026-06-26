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
 * Promise-based TOTP step-up prompt for ApiClient's onStepUp. Renders a modal,
 * resolves with the 6-digit code, or null on cancel. Attaches to <body>.
 *
 * @param {object} [spec] server-provided step-up spec (e.g. {action})
 * @returns {Promise<string|null>}
 */
export function promptStepUp(spec) {
  return new Promise((resolve) => {
    const modal = document.createElement('ys-modal');
    modal.heading = 'Step-up verification required';
    const body = document.createElement('div');
    const label = document.createElement('div');
    label.className = 'ys-label';
    // textContent — server-authored, never markdown.
    label.textContent = (spec && spec.message)
      || 'Enter your 6-digit authenticator code to authorise this action.';
    const input = document.createElement('input');
    input.className = 'ys-input';
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('autocomplete', 'one-time-code');
    input.maxLength = 6;
    body.appendChild(label);
    body.appendChild(input);
    modal.appendChild(body);

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'ys-btn ys-btn-secondary';
    cancelBtn.setAttribute('slot', 'footer');
    cancelBtn.textContent = 'Cancel';
    const okBtn = document.createElement('button');
    okBtn.className = 'ys-btn';
    okBtn.setAttribute('slot', 'footer');
    okBtn.textContent = 'Verify';
    modal.appendChild(cancelBtn);
    modal.appendChild(okBtn);

    const cleanup = (val) => {
      modal.remove();
      resolve(val);
    };
    cancelBtn.addEventListener('click', () => cleanup(null));
    modal.addEventListener('ys-close', () => cleanup(null));
    okBtn.addEventListener('click', () => {
      const v = input.value.trim();
      cleanup(/^\d{6}$/.test(v) ? v : null);
    });

    document.body.appendChild(modal);
    modal.open = true;
    requestAnimationFrame(() => input.focus());
  });
}
