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
import './mention-menu.js';
import { copyText } from '/static/ui4/core/clipboard.js';

// FIND-4.0-CHAT-001: route through the backoffice trusted-forwarder proxy
// instead of hitting /v1/chat/completions directly.  Direct access 401s
// because the gateway requires Authorization: Bearer which must not be
// exposed in the browser.  The proxy (UserSession-gated) adds the internal
// bearer + X-OpenWebUI-User-Email server-side and streams SSE back unchanged.
const CHAT_PATH = '/user/chat/completions';
const MENTIONS_PATH = '/user/mentions';

// Escape a handle for safe use inside a RegExp (handles are untrusted).
function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export class YsChatView extends LitElement {
  static properties = {
    api: { attribute: false },
    activeAgentId: { type: String },
    activeAgentName: { type: String },
    models: { type: Array },
    selectedModel: { type: String },
    conversationId: { type: String },
    _sending: { state: true },
    _mentionOpen: { state: true },
    _mentionFiltered: { state: true },
    _mentionActive: { state: true },
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
    // @-mention state. _mentions is the per-session cache of GET /user/mentions
    // (null = not yet fetched); _mentionsPromise de-dupes concurrent fetches so
    // fast typing can't fire the request twice or race an empty result.
    this._mentions = null;
    this._mentionsPromise = null;
    this._mentionStart = 0;       // index of the '@' in the textarea value
    this._mentionOpen = false;
    this._mentionFiltered = [];
    this._mentionActive = 0;
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

  // ── @-mention autocomplete ─────────────────────────────────
  // Fetch the caller's addressable agents+personas once per session (cache).
  _ensureMentions() {
    if (!this._mentionsPromise) {
      this._mentionsPromise = (async () => {
        if (!this.api) return [];
        const data = await this.api.get(MENTIONS_PATH);
        // YSG-RISK-175 (live-verified, browser-gate probe 2026-07-30):
        // GET /user/mentions actually responds `{"mentions": [...]}`
        // (user_agents.py::list_user_mentions, "Response shape:
        // {"mentions": [...]}") — this coercion never checked `data.mentions`,
        // only `data.items`/`data.data`, so `list` was ALWAYS `[]` regardless
        // of the fetch timing. This made every @-mention resolution silently
        // no-op (this._mentions stayed `[]` forever, never null, so the
        // race-ordering fix above alone could never have caught it) —
        // _targetModel() always fell through to _currentModel()'s fallback
        // for EVERY send, including explicit "@letta"/"@openclaw"/
        // "@agent_langflow" turns, confirmed via a raw Playwright
        // request-body capture showing model:"smart" sent for an
        // "@letta ..." message. Checking `data.mentions` first fixes the
        // actual payload shape without touching the generic items/data
        // fallbacks other callers may still rely on.
        const list = Array.isArray(data)
          ? data
          : (data && Array.isArray(data.mentions) ? data.mentions
            : (data && Array.isArray(data.items) ? data.items
              : (data && Array.isArray(data.data) ? data.data : [])));
        this._mentions = list; // sync mirror for _resolveMentionTarget()
        return list;
      })();
    }
    return this._mentionsPromise;
  }

  // Detect an active "@token" immediately left of the caret and open/refilter
  // the menu. Called on every textarea input.
  async _syncMention() {
    const ta = this._input;
    if (!ta) return;
    const caret = ta.selectionStart;
    const left = ta.value.slice(0, caret);
    // The @token starts at line-start or after whitespace; no spaces/@ inside it.
    const m = /(?:^|\s)@([^\s@]*)$/.exec(left);
    if (!m) { this._closeMention(); return; }
    this._mentionStart = caret - m[1].length - 1; // position of the '@'
    const q = m[1].toLowerCase();
    const items = await this._ensureMentions();
    // The caret may have moved away from the @token while the fetch was in
    // flight; re-validate before opening so we don't pop a stale menu.
    if (!/(?:^|\s)@[^\s@]*$/.test(ta.value.slice(0, ta.selectionStart))) {
      this._closeMention();
      return;
    }
    this._mentionFiltered = items.filter((it) => {
      const h = String((it && it.handle) ?? '').toLowerCase();
      const d = String((it && it.display) ?? '').toLowerCase();
      return !q || h.includes(q) || d.includes(q);
    });
    this._mentionActive = 0;
    this._mentionOpen = this._mentionFiltered.length > 0;
  }

  _closeMention() {
    this._mentionOpen = false;
    this._mentionFiltered = [];
    this._mentionActive = 0;
  }

  // Insert "@handle " over the active @token and close the menu.
  _pickMention(item) {
    const ta = this._input;
    if (!ta || !item) return;
    const handle = String(item.handle ?? '');
    const before = ta.value.slice(0, this._mentionStart);
    const after = ta.value.slice(ta.selectionStart);
    const insert = `@${handle} `;
    ta.value = `${before}${insert}${after}`;
    const pos = before.length + insert.length;
    ta.setSelectionRange(pos, pos);
    this._closeMention();
    ta.focus();
  }

  // ── send / stream ──────────────────────────────────────────
  _apiMessages() {
    return this._history.map((m) => ({ role: m.role, content: m.content }));
  }

  // The model/target used when no @mention addresses the turn explicitly.
  // YSG-RISK-175: this MUST NEVER be the raw internal agent id
  // (`activeAgentId`, format `agnt_{12hex}` from AgentRegistry.agent_id).
  // The gateway's model-string charset validator rejects the underscore in
  // that id and returns 422 model_not_found (LAURA-411-002) — so a bare
  // "chat with the active agent, no @mention" turn always 422'd before this
  // fix. Resolve the active agent through its @-handle (the SAME catalog
  // the mention menu autocompletes from — see _resolveActiveAgentTarget)
  // instead, and only then fall back to a known model alias/name. The raw
  // id is never returned.
  _currentModel() {
    if (this.selectedModel) return this.selectedModel;
    const handle = this._resolveActiveAgentTarget();
    if (handle) return handle;
    const models = Array.isArray(this.models) ? this.models : [];
    if (models.length) {
      const m = models[0] || {};
      const fallback = String(m.alias ?? m.id ?? m.model ?? m.name ?? '');
      if (fallback) return fallback;
    }
    return 'default';
  }

  // Resolve this.activeAgentId to the "@handle" the same agent is
  // addressable by in the mention catalog (GET /user/mentions). Matches by
  // id first; falls back to matching by display name in case /user/models
  // and /user/mentions ever disagree on id shape. Returns '' (never the raw
  // internal id) when nothing matches, or when _mentions has not been
  // fetched yet (see _ensureMentions/_send ordering fix).
  _resolveActiveAgentTarget() {
    const id = this.activeAgentId;
    if (!id) return '';
    const items = Array.isArray(this._mentions) ? this._mentions : [];
    const byId = items.find((it) => it && String(it.id ?? '') === String(id));
    if (byId && byId.handle) return `@${byId.handle}`;
    const name = this.activeAgentName;
    if (name) {
      const byName = items.find((it) => it && String(it.display ?? '') === String(name));
      if (byName && byName.handle) return `@${byName.handle}`;
    }
    return '';
  }

  // If the text addresses a KNOWN @handle, return "@handle" as the chat target
  // (the gateway resolves it per-user). Only handles we actually fetched count,
  // so arbitrary "@foo" text is never treated as a route.
  _resolveMentionTarget(text) {
    const items = Array.isArray(this._mentions) ? this._mentions : [];
    const s = String(text || '');
    for (const it of items) {
      const h = String((it && it.handle) ?? '');
      if (!h) continue;
      const re = new RegExp(`(?:^|\\s)@${escapeRegExp(h)}(?=\\s|$)`);
      if (re.test(s)) return `@${h}`;
    }
    return '';
  }

  // The model/target for the next request: an addressed @handle in the latest
  // user turn wins over the composer's model selector.
  _targetModel() {
    let lastUser = '';
    for (let i = this._history.length - 1; i >= 0; i -= 1) {
      if (this._history[i].role === 'user') { lastUser = this._history[i].content; break; }
    }
    return this._resolveMentionTarget(lastUser) || this._currentModel();
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

    const body = { model: this._targetModel(), messages: this._apiMessages() };
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

    // YSG-RISK-175: resolve @-mentions BEFORE streaming starts. Previously
    // this._mentions was populated only by the async _ensureMentions() fired
    // from the textarea's `input` handler (_syncMention) — a fast
    // type-then-Enter (or any send whose text was set programmatically,
    // never firing `input`) could reach _streamAssistant() → _targetModel()
    // before that fetch resolved. this._mentions was then still null,
    // _resolveMentionTarget() silently returned '' for an explicitly
    // "@handle"-addressed turn, and _currentModel() took over — see
    // _currentModel()'s own fix for why THAT fallback was unsafe too.
    // Awaiting _ensureMentions() here (idempotent/cached, so this is a
    // no-op fetch if _syncMention already kicked it off) makes mention
    // resolution deterministic instead of a race.
    await Promise.all([this._ensureMentions(), this._ensureConversation()]);
    this._streamAssistant();
  }

  _stop() {
    if (this._cancel) this._cancel();
    this._sending = false;
    this._cancel = null;
  }

  _onKeydown(e) {
    // While the mention menu is open it captures navigation/commit keys.
    if (this._mentionOpen && this._mentionFiltered.length) {
      const n = this._mentionFiltered.length;
      if (e.key === 'ArrowDown') { e.preventDefault(); this._mentionActive = (this._mentionActive + 1) % n; return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); this._mentionActive = (this._mentionActive - 1 + n) % n; return; }
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); this._pickMention(this._mentionFiltered[this._mentionActive]); return; }
      if (e.key === 'Escape') { e.preventDefault(); this._closeMention(); return; }
    }
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
            ${this._mentionOpen
              ? html`<ys-mention-menu
                       .items=${this._mentionFiltered}
                       .active=${this._mentionActive}
                       @ys-mention-pick=${(e) => this._pickMention(e.detail.item)}
                       @ys-mention-active=${(e) => { this._mentionActive = e.detail.index; }}></ys-mention-menu>`
              : nothing}
            <textarea class="ys-chat-input" rows="1"
                      placeholder="Send a message… (type @ to address an agent)"
                      @keydown=${(e) => this._onKeydown(e)}
                      @input=${() => this._syncMention()}
                      @blur=${() => this._closeMention()}></textarea>
          </div>
          ${this._sending
            ? html`<button class="ys-btn ys-btn-secondary ys-chat-stop" @click=${() => this._stop()}>Stop</button>`
            : html`<button class="ys-btn ys-chat-send" @click=${() => this._send()}>Send</button>`}
        </div>
      </div>`;
  }
}

customElements.define('ys-chat-view', YsChatView);
