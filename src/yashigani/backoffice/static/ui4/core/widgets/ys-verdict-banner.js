// Yashigani 4.0 shared layer — <ys-verdict-banner> (spec §5.1, RISK-105 HARD).
//
// TRUSTED-CHROME. Renders the [BLOCKED BY YASHIGANI] sentinel + coded tuple +
// human message from STRUCTURED fields ONLY (decodeVerdict output). It:
//   - accepts NO free text to parse and has NO markdown sink;
//   - shows the sentinel ONLY when the structured `sentinel` flag is true,
//     never by string-matching message text (FIND-AVA-001.2);
//   - renders via Lit auto-escaping (textContent), positioned OUTSIDE any
//     ys-markdown/ys-chat-stream region with a system-only visual treatment
//     (.ys-system-chrome) so an LLM cannot forge it (FIND-AVA-001.3).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';

const SENTINEL_TEXT = '[BLOCKED BY YASHIGANI]';

export class YsVerdictBanner extends LitElement {
  static properties = {
    // Structured object from ApiClient.decode(): {sentinel, codes[], userMessage, policyId}
    verdict: { type: Object },
  };

  constructor() {
    super();
    this.verdict = null;
  }

  createRenderRoot() { return this; }

  render() {
    const v = this.verdict;
    if (!v || v.sentinel !== true) return nothing;

    const codes = Array.isArray(v.codes) ? v.codes : [];
    // All interpolations below go through Lit auto-escaping → textContent.
    return html`
      <div class="ys-system-chrome" role="alert">
        <div class="ys-system-chrome-sentinel">${SENTINEL_TEXT}</div>
        ${v.userMessage
          ? html`<div class="ys-system-chrome-msg">${v.userMessage}</div>`
          : nothing}
        ${codes.map((c) => html`
          <div class="ys-system-chrome-code">
            <span>${c.code}</span>
            ${c.reasonLabel ? html` — <span>${c.reasonLabel}</span>` : nothing}
          </div>`)}
        ${v.policyId
          ? html`<div class="ys-system-chrome-policy">policy: ${v.policyId}</div>`
          : nothing}
      </div>`;
  }
}

customElements.define('ys-verdict-banner', YsVerdictBanner);
