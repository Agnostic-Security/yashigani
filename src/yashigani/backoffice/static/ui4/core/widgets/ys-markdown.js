// Yashigani 4.0 shared layer — <ys-markdown> (spec §5, UNTRUSTED-CONTENT).
//
// The ONLY TrustedHTML sink in the whole layer. Renders model/agent/document/
// markdown text fed EXCLUSIVELY through the §3 safe-render pipeline. Visually
// distinct container (.ys-md) per FIND-AVA-001.3 so it can't masquerade as
// system chrome.
//
// Lit vendor seam (Su, /static/vendor/lit/). We render into LIGHT DOM
// (createRenderRoot → this) so the global design-system.css classes apply and
// there are no inline styles (CSP-clean).
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';
import { renderMarkdown } from '../safe-render.js';

export class YsMarkdown extends LitElement {
  static properties = { content: { type: String } };

  constructor() {
    super();
    this.content = '';
  }

  // Light DOM so global classes apply.
  createRenderRoot() { return this; }

  render() {
    // Lit renders the trusted container chrome; the untrusted content is
    // injected in updated() via the single sanctioned sink below.
    return html`<div class="ys-md" part="md"></div>`;
  }

  updated() {
    const host = this.querySelector('.ys-md');
    if (!host) return;
    // SINGLE TrustedHTML sink of the entire layer. The value MUST come from
    // renderMarkdown() (marked → DOMPurify → TT policy). Assigning a bare
    // string here would throw under require-trusted-types-for 'script'.
    host.innerHTML = renderMarkdown(this.content);
  }
}

customElements.define('ys-markdown', YsMarkdown);
