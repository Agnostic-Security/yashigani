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
import { copyText } from '../clipboard.js';

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
    // After the sole sink has run, decorate fenced code blocks with a copy
    // button. This is TRUSTED-CHROME added imperatively (createElement +
    // textContent + addEventListener) — it NEVER re-enters innerHTML and reads
    // only the already-sanitised text via .innerText, so the §3 contract holds.
    this._decorateCodeBlocks(host);
  }

  _decorateCodeBlocks(host) {
    const pres = host.querySelectorAll('pre');
    pres.forEach((pre) => {
      // innerHTML was just reassigned, so wrappers from a prior render are gone;
      // the guard keeps this idempotent if updated() ever runs without a reset.
      if (pre.parentElement && pre.parentElement.classList.contains('ys-code-wrap')) return;
      const wrap = document.createElement('div');
      wrap.className = 'ys-code-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'ys-btn ys-btn-ghost ys-code-copy';
      btn.textContent = 'Copy';
      btn.addEventListener('click', async () => {
        const ok = await copyText(pre.innerText);
        btn.textContent = ok ? 'Copied' : 'Copy failed';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      });
      wrap.appendChild(btn);
    });
  }
}

customElements.define('ys-markdown', YsMarkdown);
