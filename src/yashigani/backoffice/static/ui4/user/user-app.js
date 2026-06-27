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
// Load order (spec §1): installTrustedTypes() runs first so the named TT policy
// is registered before any sink. (Importing the core barrel already triggers it
// transitively via safe-render.js; we call it explicitly to honour the contract.)
import { ApiClient, installTrustedTypes, widgets } from '/static/ui4/core/index.js';
import { LitElement, html } from '/static/vendor/lit/lit-core.min.js';
import './session-header.js';
import './user-sidebar.js';
import './chat-view.js';

// Register the named TT policy before any sink runs (spec §1). Importing the
// core barrel already triggers this transitively; the explicit call honours the
// contract and is idempotent. `widgets` is referenced so the side-effect import
// that registers the ys-* custom elements is retained.
installTrustedTypes();
void widgets;

export class YsUserApp extends LitElement {
  static properties = {
    _agents: { state: true },
    _budget: { state: true },
    _memory: { state: true },
    _activeAgentId: { state: true },
    _activeAgentName: { state: true },
    _username: { state: true },
  };

  constructor() {
    super();
    this._agents = [];
    this._budget = null;
    this._memory = [];
    this._activeAgentId = '';
    this._activeAgentName = '';
    this._username = '';

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
    this._loadConstructs();
  }

  async _loadConstructs() {
    // Pinned contract: GET /user/agents, /user/budget, /user/memory (read via
    // the shared ApiClient; null on error/unauth — get() redirects to /login on
    // 401, so a null here is a soft "no data", not an auth failure).
    const [agents, budget, memory] = await Promise.all([
      this.api.get('/user/agents'),
      this.api.get('/user/budget'),
      this.api.get('/user/memory'),
    ]);
    this._agents = this._coerceList(agents, 'agents');
    this._budget = (budget && typeof budget === 'object') ? (budget.budget ?? budget) : null;
    this._memory = this._coerceList(memory, 'memory');

    // Default the chat target to the first agent if one exists.
    if (!this._activeAgentId && this._agents.length) {
      const a = this._agents[0];
      this._activeAgentId = a.id ?? a.agent_id ?? a.model ?? a.name ?? '';
      this._activeAgentName = a.name ?? this._activeAgentId;
    }
  }

  // Tolerate both a bare array and an envelope ({agents:[...]}, {items:[...]}).
  _coerceList(payload, key) {
    if (Array.isArray(payload)) return payload;
    if (payload && typeof payload === 'object') {
      if (Array.isArray(payload[key])) return payload[key];
      if (Array.isArray(payload.items)) return payload.items;
      if (Array.isArray(payload.data)) return payload.data;
    }
    return [];
  }

  _onAgentSelect(e) {
    const a = e.detail && e.detail.agent;
    if (!a) return;
    this._activeAgentId = a.id ?? a.agent_id ?? a.model ?? a.name ?? '';
    this._activeAgentName = a.name ?? this._activeAgentId;
  }

  render() {
    return html`
      <div class="ys-app">
        <ys-session-header .username=${this._username}></ys-session-header>
        <div class="ys-app-body" @ys-agent-select=${(e) => this._onAgentSelect(e)}>
          <ys-user-sidebar
            .api=${this.api}
            .agents=${this._agents}
            .budget=${this._budget}
            .memory=${this._memory}
            .activeAgentId=${this._activeAgentId}></ys-user-sidebar>
          <ys-chat-view
            .api=${this.api}
            .activeAgentId=${this._activeAgentId}
            .activeAgentName=${this._activeAgentName}></ys-chat-view>
        </div>
      </div>`;
  }
}

customElements.define('ys-user-app', YsUserApp);
