// Yashigani 4.0 shared layer — <ys-chat-stream> (spec §5, mixed trust).
//
// Streaming chat bubble. While streaming, raw tokens are shown via textContent
// ONLY (no parse, no XSS — RISK-106). On completion the COMPLETE accumulated
// string is rendered ONCE through <ys-markdown> (→ §3 pipeline). A verdict (if
// any) renders via <ys-verdict-banner> from the STRUCTURED tail, OUTSIDE the
// content region (RISK-105).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import './ys-markdown.js';
import './ys-verdict-banner.js';

export class YsChatStream extends LitElement {
  static properties = {
    streaming: { type: Boolean },
    _buffer: { state: true },
    _done: { state: true },
    _verdict: { state: true },
  };

  constructor() {
    super();
    this.streaming = false;
    this._buffer = '';
    this._done = false;
    this._verdict = null;
  }

  createRenderRoot() { return this; }

  /** Append a raw token delta (shown as textContent only). */
  appendToken(delta) {
    this._buffer += String(delta == null ? '' : delta);
    this.streaming = true;
    this._done = false;
  }

  /**
   * Mark the message complete. `fullText` is the complete accumulated string
   * (re-rendered ONCE via ys-markdown). `verdict` is the decoded structured
   * verdict (or null) for the trusted banner.
   */
  finish(fullText, verdict) {
    if (typeof fullText === 'string') this._buffer = fullText;
    this._verdict = verdict || null;
    this.streaming = false;
    this._done = true;
  }

  reset() {
    this._buffer = '';
    this._done = false;
    this._verdict = null;
    this.streaming = false;
  }

  render() {
    return html`
      <div class="ys-chat-bubble">
        ${this._verdict
          ? html`<ys-verdict-banner .verdict=${this._verdict}></ys-verdict-banner>`
          : nothing}
        ${this._done
          ? html`<ys-markdown .content=${this._buffer}></ys-markdown>`
          : html`<div class="ys-chat-streaming">${this._buffer}</div>`}
      </div>`;
  }
}

customElements.define('ys-chat-stream', YsChatStream);
