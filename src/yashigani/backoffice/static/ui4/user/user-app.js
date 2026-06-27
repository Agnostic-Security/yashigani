// Yashigani 4.0 user app — <ys-user-app> (root, OpenWebUI replacement).
//
// Thin composition over the Phase-1 shared layer (spec §5.2): it imports the
// audited core, constructs ONE ApiClient({sessionKind:'user'}) (NEVER shared
// across planes — RISK-100), fetches the user's constructs through it, and
// passes already-typed data to the widgets via reactive properties. The app
// itself does NOT fetch raw, parse errors, or touch any DOM sink — every
// untrusted string reaches the DOM only through <ys-markdown> (the §3 pipeline),
// and every verdict only through <ys-verdict-banner> from structured fields.
//
// The app is the single owner of cross-component state: the conversation list,
// the active conversation, the model list + selection, and the (client-local)
// preferences. Child components dispatch intent events; the app performs the
// one server mutation and re-reads, so there is exactly one source of truth.
//
// Load order (spec §1): installTrustedTypes() runs first so the named TT policy
// is registered before any sink. (Importing the core barrel already triggers it
// transitively via safe-render.js; we call it explicitly to honour the contract.)
import { ApiClient, installTrustedTypes, widgets } from '/static/ui4/core/index.js';
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';
import './session-header.js';
import './user-sidebar.js';
import './chat-view.js';
import './settings-panel.js';

// Register the named TT policy before any sink runs (spec §1). Importing the
// core barrel already triggers this transitively; the explicit call honours the
// contract and is idempotent. `widgets` is referenced so the side-effect import
// that registers the ys-* custom elements is retained.
installTrustedTypes();
void widgets;

const PREFS_KEY = 'ys-user-prefs';

export class YsUserApp extends LitElement {
  static properties = {
    _agents: { state: true },
    _budget: { state: true },
    _memory: { state: true },
    _activeAgentId: { state: true },
    _activeAgentName: { state: true },
    _username: { state: true },
    _conversations: { state: true },
    _activeConversationId: { state: true },
    _models: { state: true },
    _selectedModel: { state: true },
    _settingsOpen: { state: true },
    _theme: { state: true },
    _defaultModel: { state: true },
    _convBusy: { state: true },
  };

  constructor() {
    super();
    this._agents = [];
    this._budget = null;
    this._memory = [];
    this._activeAgentId = '';
    this._activeAgentName = '';
    this._username = '';
    this._conversations = [];
    this._activeConversationId = '';
    this._models = [];
    this._selectedModel = '';
    this._settingsOpen = false;
    this._convBusy = false;

    const prefs = this._loadPrefs();
    this._theme = prefs.theme || 'light';
    this._defaultModel = prefs.defaultModel || '';
    this._selectedModel = this._defaultModel;

    // ONE per-plane client. sessionKind:'user' selects the user route group and
    // the user login redirect (/login). onStepUp wires the shared TOTP modal.
    this.api = new ApiClient({
      sessionKind: 'user',
      onStepUp: (spec) => widgets.promptStepUp(spec),
    });
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._applyTheme(this._theme);
    this._loadConstructs();
  }

  // ── preferences (client-local) ─────────────────────────────
  _loadPrefs() {
    try {
      const raw = window.localStorage.getItem(PREFS_KEY);
      const obj = raw ? JSON.parse(raw) : {};
      return (obj && typeof obj === 'object') ? obj : {};
    } catch { return {}; }
  }

  _savePrefs() {
    try {
      window.localStorage.setItem(PREFS_KEY, JSON.stringify({
        theme: this._theme, defaultModel: this._defaultModel,
      }));
    } catch { /* storage unavailable — preferences stay in-memory only */ }
  }

  _applyTheme(theme) {
    // Programmatic class toggle on <body> (NOT an inline style attribute) —
    // CSP-clean. The dark palette overrides live in user.css under .ys-theme-dark.
    const dark = theme === 'dark';
    document.body.classList.toggle('ys-theme-dark', dark);
  }

  // ── data load ──────────────────────────────────────────────
  async _loadConstructs() {
    const [agents, budget, memory, conversations, models] = await Promise.all([
      this.api.get('/user/agents'),
      this.api.get('/user/budget'),
      this.api.get('/user/memory'),
      this.api.get('/user/conversations'),
      this.api.get('/user/models'),
    ]);
    this._agents = this._coerceList(agents, 'agents');
    this._budget = (budget && typeof budget === 'object') ? (budget.budget ?? budget) : null;
    this._memory = this._coerceList(memory, 'memory');
    this._conversations = this._coerceList(conversations, 'conversations');
    this._models = this._coerceList(models, 'models');

    if (!this._activeAgentId && this._agents.length) {
      const a = this._agents[0];
      this._activeAgentId = a.id ?? a.agent_id ?? a.model ?? a.name ?? '';
      this._activeAgentName = a.name ?? this._activeAgentId;
    }
    // Resume the most-recent conversation if one exists and none is active.
    if (!this._activeConversationId && this._conversations.length) {
      const c = this._conversations[0];
      this._activeConversationId = String(c.id ?? c.conversation_id ?? c.uuid ?? '');
    }
  }

  async _refreshConversations() {
    const data = await this.api.get('/user/conversations');
    this._conversations = this._coerceList(data, 'conversations');
  }

  // Tolerate both a bare array and an envelope ({agents:[...]}, {items:[...]},
  // and the OpenAI /v1/models {data:[...]} shape).
  _coerceList(payload, key) {
    if (Array.isArray(payload)) return payload;
    if (payload && typeof payload === 'object') {
      if (Array.isArray(payload[key])) return payload[key];
      if (Array.isArray(payload.items)) return payload.items;
      if (Array.isArray(payload.data)) return payload.data;
    }
    return [];
  }

  // ── agent / model selection ────────────────────────────────
  _onAgentSelect(e) {
    const a = e.detail && e.detail.agent;
    if (!a) return;
    this._activeAgentId = a.id ?? a.agent_id ?? a.model ?? a.name ?? '';
    this._activeAgentName = a.name ?? this._activeAgentId;
  }

  _onModelSelect(e) {
    if (e.detail && typeof e.detail.model === 'string') this._selectedModel = e.detail.model;
  }

  // ── conversation CRUD (app owns the list) ──────────────────
  async _onConvNew() {
    if (this._convBusy) return;
    this._convBusy = true;
    try {
      const res = await this.api.mutate('/user/conversations', { method: 'POST', body: {} });
      if (res && res.ok && res.data) {
        const id = String(res.data.id ?? res.data.conversation_id ?? res.data.uuid ?? '');
        await this._refreshConversations();
        if (id) this._activeConversationId = id;
      }
    } finally {
      this._convBusy = false;
    }
  }

  _onConvSelect(e) {
    const id = e.detail && e.detail.id;
    if (id) this._activeConversationId = String(id);
  }

  _onConvCreated(e) {
    // chat-view auto-created a conversation on first send; sync app state + list.
    const id = e.detail && e.detail.id;
    if (id) this._activeConversationId = String(id);
    this._refreshConversations();
  }

  async _onConvRename(e) {
    const { id, title } = (e.detail || {});
    if (!id || !title) return;
    const res = await this.api.mutate(`/user/conversations/${encodeURIComponent(id)}`, {
      method: 'PATCH', body: { title },
    });
    if (res && res.ok) await this._refreshConversations();
  }

  async _onConvDelete(e) {
    const id = e.detail && e.detail.id;
    if (!id) return;
    const res = await this.api.mutate(`/user/conversations/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (res && res.ok) {
      await this._refreshConversations();
      if (String(id) === this._activeConversationId) {
        // Active chat was deleted — fall back to the newest remaining, else clear.
        const next = this._conversations[0];
        this._activeConversationId = next
          ? String(next.id ?? next.conversation_id ?? next.uuid ?? '')
          : '';
      }
    }
  }

  // ── settings / preferences ─────────────────────────────────
  _onOpenSettings() { this._settingsOpen = true; }
  _onCloseSettings() { this._settingsOpen = false; }

  _onPrefsChange(e) {
    const d = e.detail || {};
    this._theme = d.theme === 'dark' ? 'dark' : 'light';
    this._defaultModel = String(d.defaultModel || '');
    if (this._defaultModel) this._selectedModel = this._defaultModel;
    this._applyTheme(this._theme);
    this._savePrefs();
    this._settingsOpen = false;
  }

  render() {
    return html`
      <div class="ys-app"
           @ys-agent-select=${(e) => this._onAgentSelect(e)}
           @ys-model-select=${(e) => this._onModelSelect(e)}
           @ys-conversation-new=${() => this._onConvNew()}
           @ys-conversation-select=${(e) => this._onConvSelect(e)}
           @ys-conversation-created=${(e) => this._onConvCreated(e)}
           @ys-conversation-rename=${(e) => this._onConvRename(e)}
           @ys-conversation-delete=${(e) => this._onConvDelete(e)}
           @ys-open-settings=${() => this._onOpenSettings()}
           @ys-prefs-change=${(e) => this._onPrefsChange(e)}>
        <ys-session-header .username=${this._username}></ys-session-header>
        <div class="ys-app-body">
          <ys-user-sidebar
            .api=${this.api}
            .agents=${this._agents}
            .budget=${this._budget}
            .memory=${this._memory}
            .conversations=${this._conversations}
            .activeConversationId=${this._activeConversationId}
            .convBusy=${this._convBusy}
            .activeAgentId=${this._activeAgentId}></ys-user-sidebar>
          <ys-chat-view
            .api=${this.api}
            .models=${this._models}
            .selectedModel=${this._selectedModel}
            .conversationId=${this._activeConversationId}
            .activeAgentId=${this._activeAgentId}
            .activeAgentName=${this._activeAgentName}></ys-chat-view>
        </div>
        <ys-settings-panel
          .open=${this._settingsOpen}
          .models=${this._models}
          .defaultModel=${this._defaultModel}
          .theme=${this._theme}
          @ys-close=${() => this._onCloseSettings()}></ys-settings-panel>
      </div>`;
  }
}

customElements.define('ys-user-app', YsUserApp);
