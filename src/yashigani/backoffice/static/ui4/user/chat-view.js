// Yashigani 4.0 user app — <ys-chat-view> (SSE streaming chat + OWUI parity).
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
// OWUI-parity features added on this same discipline:
//   - resume a past conversation (GET /user/conversations/{id} → rebuild log);
//   - persist new turns to the active conversation (conversation auto-created via
//     POST /user/conversations on first send; conversation_id sent with the chat);
//   - in-composer model/agent selector (GET /user/models, app-owned);
//   - stop the in-flight stream; regenerate the last answer; edit a prior user
//     message and re-run from that point; copy an assistant message.
//
// The chat log is managed imperatively (createElement + property/textContent
// assignment — never innerHTML) so streaming does not fight Lit reconciliation;
// the Lit template owns only the static frame + the composer.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import '/static/ui4/core/widgets/ys-chat-stream.js';
import { copyText } from '/static/ui4/core/clipboard.js';

const CHAT_PATH = '/v1/chat/completions';

export class YsChatView extends LitElement {
  static properties = {
    api: { attribute: false },
    activeAgentId: { type: String },
    activeAgentName: { type: String },
    models: { type: Array },
    selectedModel: { type: String },
    conversationId: { type: String },
    _sending: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.activeAgentId = '';
    this.activeAgentName = '';
    this.models = [];
    this.selectedModel = '';
    this.conversationId = '';
    this._sending = false;
    this._history = [];     // [{role, content, verdict?}] — verdict is local chrome
    this._log = null;       // imperatively-managed log container
    this._input = null;
    this._cancel = null;    // active stream canceller
    this._loadedConversationId = null; // guards updated() against self-set ids
  }

  createRenderRoot() { return this; }

  firstUpdated() {
    this._log = this.querySelector('.ys-chat-log');
    this._input = this.querySelector('.ys-chat-input');
    this._renderEmptyState();
  }

  updated(changed) {
    // Resume a conversation when the app selects a DIFFERENT id than the one we
    // last loaded (or self-created). Self-created ids set _loadedConversationId
    // first so this does not clobber the just-typed turn.
    if (changed.has('conversationId')
        && this.conversationId !== this._loadedConversationId) {
      this._loadConversation(this.conversationId);
    }
  }

  // ── conversation load ──────────────────────────────────────
  _coerceMessages(payload) {
    let arr = [];
    if (Array.isArray(payload)) arr = payload;
    else if (payload && typeof payload === 'object') {
      if (Array.isArray(payload.messages)) arr = payload.messages;
      else if (Array.isArray(payload.items)) arr = payload.items;
      else if (Array.isArray(payload.data)) arr = payload.data;
    }
    return arr
      .map((m) => ({
        role: m.role === 'assistant' ? 'assistant' : 'user',
        content: String(m.content ?? m.text ?? ''),
      }))
      .filter((m) => m.content.length || m.role === 'assistant');
  }

  async _loadConversation(id) {
    this._loadedConversationId = id;
    if (this._cancel) { this._cancel(); this._cancel = null; }
    this._sending = false;
    this._history = [];
    if (!this._log) return;
    if (!id || !this.api) { this._rebuildLog(); return; }
    const data = await this.api.get(`/user/conversations/${encodeURIComponent(id)}`);
    this._history = this._coerceMessages(data);
    this._rebuildLog();
    this._scrollToEnd();
  }

  // ── log primitives (imperative; never innerHTML) ───────────
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

  _ghostBtn(label, onClick, extraClass) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = `ys-btn ys-btn-ghost ys-msg-act${extraClass ? ' ' + extraClass : ''}`;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  _appendUserBubble(text, index) {
    const row = document.createElement('div');
    row.className = 'ys-chat-row ys-chat-row-user';
    const col = document.createElement('div');
    col.className = 'ys-chat-user-col';
    const bubble = document.createElement('div');
    bubble.className = 'ys-chat-user-bubble';
    bubble.textContent = text; // textContent — never innerHTML
    col.appendChild(bubble);
    const tools = document.createElement('div');
    tools.className = 'ys-msg-tools';
    tools.appendChild(this._ghostBtn('Edit', () => this._editUser(index), 'ys-msg-edit'));
    col.appendChild(tools);
    row.appendChild(col);
    this._log.appendChild(row);
  }

  _appendUserEditor(index, content) {
    const row = document.createElement('div');
    row.className = 'ys-chat-row ys-chat-row-user';
    const col = document.createElement('div');
    col.className = 'ys-chat-user-col ys-chat-user-editing';
    const ta = document.createElement('textarea');
    ta.className = 'ys-textarea ys-edit-input';
    ta.value = content;
    ta.rows = Math.min(8, Math.max(2, content.split('\n').length));
    col.appendChild(ta);
    const tools = document.createElement('div');
    tools.className = 'ys-msg-tools';
    tools.appendChild(this._ghostBtn('Save & submit', () => {
      const v = (ta.value || '').trim();
      if (!v) return;
      // Truncate to BEFORE this turn, append the edited user message, re-run.
      this._history = [...this._history.slice(0, index), { role: 'user', content: v }];
      this._rebuildLog();
      this._streamAssistant();
    }, 'ys-edit-save'));
    tools.appendChild(this._ghostBtn('Cancel', () => this._rebuildLog(), 'ys-edit-cancel'));
    col.appendChild(tools);
    row.appendChild(col);
    this._log.appendChild(row);
    ta.focus();
  }

  _appendAssistantFinished(msg, index, isLast) {
    const row = document.createElement('div');
    row.className = 'ys-chat-row ys-chat-row-assistant';
    const wrap = document.createElement('div');
    wrap.className = 'ys-chat-assistant-wrap';
    const stream = document.createElement('ys-chat-stream');
    wrap.appendChild(stream);
    // finish() re-renders the COMPLETE string once via ys-markdown (§3) and the
    // verdict (if any) via ys-verdict-banner from the STRUCTURED decoded object.
    stream.finish(msg.content, msg.verdict || null);
    const tools = document.createElement('div');
    tools.className = 'ys-msg-tools';
    const copyBtn = this._ghostBtn('Copy', () => this._copy(msg.content, copyBtn), 'ys-msg-copy');
    tools.appendChild(copyBtn);
    if (isLast) {
      tools.appendChild(this._ghostBtn('Regenerate', () => {
        // Drop this assistant turn (and anything after), re-run from the user turn.
        this._history = this._history.slice(0, index);
        this._rebuildLog();
        this._streamAssistant();
      }, 'ys-msg-regen'));
    }
    wrap.appendChild(tools);
    row.appendChild(wrap);
    this._log.appendChild(row);
  }

  _appendAssistantStreaming() {
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

  // Full rebuild from _history (used on load / regenerate / edit / completion).
  _rebuildLog() {
    if (!this._log) return;
    this._log.replaceChildren();
    if (!this._history.length) { this._renderEmptyState(); return; }
    let lastAssistant = -1;
    this._history.forEach((m, i) => { if (m.role === 'assistant') lastAssistant = i; });
    this._history.forEach((m, i) => {
      if (m.role === 'assistant') this._appendAssistantFinished(m, i, i === lastAssistant);
      else this._appendUserBubble(m.content, i);
    });
    this._scrollToEnd();
  }

  async _copy(text, btn) {
    const ok = await copyText(text);
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = ok ? 'Copied' : 'Copy failed';
      setTimeout(() => { btn.textContent = prev; }, 1500);
    }
  }

  _editUser(index) {
    const content = (this._history[index] && this._history[index].content) || '';
    // Re-render with that single row replaced by an editor.
    this._log.replaceChildren();
    if (!this._history.length) { this._renderEmptyState(); return; }
    let lastAssistant = -1;
    this._history.forEach((m, i) => { if (m.role === 'assistant') lastAssistant = i; });
    this._history.forEach((m, i) => {
      if (i === index && m.role === 'user') this._appendUserEditor(index, content);
      else if (m.role === 'assistant') this._appendAssistantFinished(m, i, i === lastAssistant);
      else this._appendUserBubble(m.content, i);
    });
  }

  // ── send / stream ──────────────────────────────────────────
  _apiMessages() {
    return this._history.map((m) => ({ role: m.role, content: m.content }));
  }

  _currentModel() {
    return this.selectedModel || this.activeAgentId || 'default';
  }

  async _ensureConversation() {
    if (this.conversationId) return this.conversationId;
    if (!this.api) return '';
    const res = await this.api.mutate('/user/conversations', { method: 'POST', body: {} });
    if (res && res.ok && res.data) {
      const id = String(res.data.id ?? res.data.conversation_id ?? res.data.uuid ?? '');
      if (id) {
        this._loadedConversationId = id; // prevent updated() from reloading
        this.conversationId = id;
        this.dispatchEvent(new CustomEvent('ys-conversation-created', {
          detail: { id }, bubbles: true, composed: true,
        }));
      }
      return id;
    }
    return '';
  }

  _streamAssistant() {
    if (!this.api) return;
    const stream = this._appendAssistantStreaming();
    this._sending = true;
    this._scrollToEnd();

    const body = { model: this._currentModel(), messages: this._apiMessages() };
    if (this.conversationId) body.conversation_id = this.conversationId;

    const handle = this.api.stream(CHAT_PATH, {
      body,
      onToken: (delta) => {
        stream.appendToken(delta); // textContent only while streaming (RISK-106)
        this._scrollToEnd();
      },
      onMessageDone: (full, tail) => {
        // Verdict decoded from the STRUCTURED tail ONLY (RISK-105).
        const verdict = tail ? this.api.decode(tail) : null;
        this._sending = false;
        this._cancel = null;
        if (full && full.trim()) {
          this._history = [...this._history, { role: 'assistant', content: full, verdict }];
          this._rebuildLog(); // promotes the finished turn to a toolbar'd bubble
        } else {
          // Nothing to persist (empty completion); finalise the transient bubble.
          stream.finish(full || '', verdict);
        }
        this._scrollToEnd();
      },
      onBlocked: (structured) => {
        // Pre-stream block (e.g. HTTP 403): the gateway rejected before the SSE
        // opened, so the verdict arrives as the error body's STRUCTURED fields.
        // Decode via the audited path into the trusted <ys-verdict-banner> —
        // content stays empty and NO error text is promoted to chrome (RISK-105).
        // The blocked turn is NOT added to history (no assistant reply existed).
        const verdict = this.api.decode(structured || { blocked: true });
        stream.finish('', verdict);
        this._sending = false;
        this._cancel = null;
        this._scrollToEnd();
      },
      onError: (err) => {
        stream.finish(`_(stream error: ${err && err.message ? err.message : 'unknown'})_`, null);
        this._sending = false;
        this._cancel = null;
      },
    });
    this._cancel = handle && handle.cancel;
  }

  async _send() {
    if (!this.api || this._sending) return;
    const text = (this._input && this._input.value || '').trim();
    if (!text) return;

    this._clearEmptyState();
    this._history = [...this._history, { role: 'user', content: text }];
    this._appendUserBubble(text, this._history.length - 1);
    if (this._input) this._input.value = '';
    this._scrollToEnd();

    await this._ensureConversation(); // persist subsequent turns server-side
    this._streamAssistant();
  }

  _stop() {
    if (this._cancel) this._cancel();
    this._sending = false;
    this._cancel = null;
  }

  _onKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      this._send();
    }
  }

  _onModelChange(e) {
    const model = e.target.value;
    this.selectedModel = model; // optimistic; app echoes it back as the prop
    this.dispatchEvent(new CustomEvent('ys-model-select', {
      detail: { model }, bubbles: true, composed: true,
    }));
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    if (this._cancel) this._cancel();
  }

  _modelOptions() {
    const models = Array.isArray(this.models) ? this.models : [];
    const sel = this._currentModel();
    return models.map((m) => {
      const id = String(m.id ?? m.model ?? m.name ?? '');
      const label = String(m.name ?? m.id ?? m.model ?? id);
      return html`<option value=${id} ?selected=${id === sel}>${label}</option>`;
    });
  }

  render() {
    const models = Array.isArray(this.models) ? this.models : [];
    return html`
      <div class="ys-app-main">
        <!-- log is managed imperatively; no Lit bindings inside it -->
        <div class="ys-chat-log"></div>
        <div class="ys-chat-composer">
          <div class="ys-chat-input-col">
            <div class="ys-composer-bar">
              <label class="ys-composer-model">
                <span class="ys-composer-model-label">Model</span>
                ${models.length
                  ? html`<select class="ys-select ys-model-select"
                                 @change=${(e) => this._onModelChange(e)}>
                      ${this._modelOptions()}
                    </select>`
                  : html`<span class="ys-chat-target">${this.activeAgentName || this.activeAgentId || 'default'}</span>`}
              </label>
            </div>
            <textarea class="ys-chat-input" rows="1"
                      placeholder="Send a message…"
                      @keydown=${(e) => this._onKeydown(e)}></textarea>
          </div>
          ${this._sending
            ? html`<button class="ys-btn ys-btn-secondary ys-chat-stop" @click=${() => this._stop()}>Stop</button>`
            : html`<button class="ys-btn ys-chat-send" @click=${() => this._send()}>Send</button>`}
        </div>
      </div>`;
  }
}

customElements.define('ys-chat-view', YsChatView);
