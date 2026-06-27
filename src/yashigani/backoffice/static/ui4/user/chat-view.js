// Yashigani 4.0 user app — <ys-chat-view> (SSE streaming chat).
//
// Streams a chat completion over the gateway's OpenAI-compatible SSE endpoint
// (/v1/chat/completions) under the user's session, via the shared
// ApiClient.stream() → sse.js. Composes the shared <ys-chat-stream> bubble:
//   - streaming tokens are shown as textContent ONLY (no parse, RISK-106);
//   - on completion the COMPLETE string is rendered ONCE through <ys-markdown>
//     (the §3 marked→DOMPurify→TT pipeline) — never per chunk;
//   - a verdict (block/decision codes) arrives as a STRUCTURED tail and is
//     decoded via ApiClient.decode() into <ys-verdict-banner> as TRUSTED-CHROME
//     OUTSIDE the message region (RISK-105) — the stream text is NEVER scanned
//     for [BLOCKED BY YASHIGANI].
//
// The chat log is managed imperatively (createElement + property/textContent
// assignment — never innerHTML) so streaming does not fight Lit reconciliation;
// the Lit template owns only the static frame + the dynamic target line.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import '/static/ui4/core/widgets/ys-chat-stream.js';

const CHAT_PATH = '/v1/chat/completions';

export class YsChatView extends LitElement {
  static properties = {
    api: { attribute: false },
    activeAgentId: { type: String },
    activeAgentName: { type: String },
    _sending: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.activeAgentId = '';
    this.activeAgentName = '';
    this._sending = false;
    this._history = [];     // OpenAI-compatible messages array
    this._log = null;       // imperatively-managed log container
    this._input = null;
    this._cancel = null;    // active stream canceller
  }

  createRenderRoot() { return this; }

  firstUpdated() {
    this._log = this.querySelector('.ys-chat-log');
    this._input = this.querySelector('.ys-chat-input');
    this._renderEmptyState();
  }

  _renderEmptyState() {
    if (!this._log || this._history.length) return;
    if (this._log.querySelector('.ys-chat-empty')) return;
    const empty = document.createElement('div');
    empty.className = 'ys-chat-empty';
    empty.textContent = 'Start a conversation. Every turn is policy-adjudicated by Yashigani.';
    this._log.appendChild(empty);
  }

  _clearEmptyState() {
    const e = this._log && this._log.querySelector('.ys-chat-empty');
    if (e) e.remove();
  }

  _scrollToEnd() {
    if (this._log) this._log.scrollTop = this._log.scrollHeight;
  }

  _appendUserBubble(text) {
    const row = document.createElement('div');
    row.className = 'ys-chat-row ys-chat-row-user';
    const bubble = document.createElement('div');
    bubble.className = 'ys-chat-user-bubble';
    bubble.textContent = text; // textContent — never innerHTML
    row.appendChild(bubble);
    this._log.appendChild(row);
  }

  _appendAssistantBubble() {
    const row = document.createElement('div');
    row.className = 'ys-chat-row ys-chat-row-assistant';
    const wrap = document.createElement('div');
    wrap.className = 'ys-chat-assistant-wrap';
    const stream = document.createElement('ys-chat-stream');
    wrap.appendChild(stream);
    row.appendChild(wrap);
    this._log.appendChild(row);
    return stream;
  }

  _onKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      this._send();
    }
  }

  _send() {
    if (!this.api || this._sending) return;
    const text = (this._input && this._input.value || '').trim();
    if (!text) return;

    this._clearEmptyState();
    this._appendUserBubble(text);
    this._history = [...this._history, { role: 'user', content: text }];
    if (this._input) this._input.value = '';
    this._scrollToEnd();

    const bubble = this._appendAssistantBubble();
    this._sending = true;
    this._scrollToEnd();

    const model = this.activeAgentId || 'default';
    const handle = this.api.stream(CHAT_PATH, {
      body: { model, messages: this._history },
      onToken: (delta) => {
        bubble.appendToken(delta);
        this._scrollToEnd();
      },
      onMessageDone: (full, tail) => {
        // Verdict decoded from the STRUCTURED tail ONLY (RISK-105).
        const verdict = tail ? this.api.decode(tail) : null;
        bubble.finish(full, verdict);
        this._history = [...this._history, { role: 'assistant', content: full }];
        this._sending = false;
        this._cancel = null;
        this._scrollToEnd();
      },
      onBlocked: (structured) => {
        // Pre-stream block (e.g. HTTP 403): the gateway rejected before the SSE
        // opened, so the verdict arrives as the error body's STRUCTURED fields,
        // not an in-stream event. Decode via the audited path into the trusted
        // <ys-verdict-banner> — content stays empty and NO error text is ever
        // promoted to chrome (RISK-105 anti-spoofing). The blocked turn is not
        // added to history (no assistant reply was produced).
        const verdict = this.api.decode(structured || { blocked: true });
        bubble.finish('', verdict);
        this._sending = false;
        this._cancel = null;
        this._scrollToEnd();
      },
      onError: (err) => {
        bubble.finish(`_(stream error: ${err && err.message ? err.message : 'unknown'})_`, null);
        this._sending = false;
        this._cancel = null;
      },
    });
    this._cancel = handle && handle.cancel;
  }

  _stop() {
    if (this._cancel) this._cancel();
    this._sending = false;
    this._cancel = null;
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._cancel) this._cancel();
  }

  render() {
    const target = this.activeAgentName || this.activeAgentId;
    return html`
      <div class="ys-app-main">
        <!-- log is managed imperatively; no Lit bindings inside it -->
        <div class="ys-chat-log"></div>
        <div class="ys-chat-composer">
          <div class="ys-chat-input-col">
            ${target
              ? html`<div class="ys-chat-target">Talking to: ${target}</div>`
              : nothing}
            <textarea class="ys-chat-input" rows="1"
                      placeholder="Send a message…"
                      @keydown=${(e) => this._onKeydown(e)}></textarea>
          </div>
          ${this._sending
            ? html`<button class="ys-btn ys-btn-secondary" @click=${() => this._stop()}>Stop</button>`
            : html`<button class="ys-btn" @click=${() => this._send()}>Send</button>`}
        </div>
      </div>`;
  }
}

customElements.define('ys-chat-view', YsChatView);
