// Yashigani 4.0 user app — <ys-user-sidebar> (our constructs).
//
// TRUSTED-CHROME. Renders the user's agents, budget summary, per-identity
// memory, and the doc-OPA upload control. Data arrives already-typed from the
// shared ApiClient (sessionKind:'user') via the root app; this component does
// NOT fetch raw, does NOT parse errors, does NOT sanitise. Every interpolation
// goes through Lit auto-escaping (textContent) — agent names / memory / policy
// ids are identifiers, never markdown (spec §3.3).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import './doc-upload.js';

export class YsUserSidebar extends LitElement {
  static properties = {
    agents: { type: Array },
    budget: { type: Object },
    memory: { type: Array },
    activeAgentId: { type: String },
    // shared ApiClient instance (for the doc-upload child).
    api: { attribute: false },
  };

  constructor() {
    super();
    this.agents = [];
    this.budget = null;
    this.memory = [];
    this.activeAgentId = '';
    this.api = null;
  }

  createRenderRoot() { return this; }

  _selectAgent(a) {
    this.dispatchEvent(new CustomEvent('ys-agent-select', {
      detail: { agent: a }, bubbles: true, composed: true,
    }));
  }

  _renderAgents() {
    const agents = Array.isArray(this.agents) ? this.agents : [];
    return html`
      <div class="ys-section">
        <div class="ys-section-title">Agents</div>
        ${agents.length === 0
          ? html`<div class="ys-txt-note">No agents available.</div>`
          : html`<div class="ys-agent-list">
              ${agents.map((a) => {
                const id = a.id ?? a.agent_id ?? a.model ?? a.name;
                const active = id === this.activeAgentId;
                return html`
                  <div class="ys-agent ${active ? 'ys-agent-active' : ''}"
                       role="button" tabindex="0"
                       @click=${() => this._selectAgent(a)}
                       @keydown=${(e) => { if (e.key === 'Enter') this._selectAgent(a); }}>
                    <span class="ys-agent-name">${a.name ?? id}</span>
                    ${a.description
                      ? html`<span class="ys-agent-meta">${a.description}</span>`
                      : nothing}
                  </div>`;
              })}
            </div>`}
      </div>`;
  }

  _renderBudget() {
    const b = this.budget;
    if (!b) {
      return html`
        <div class="ys-section">
          <div class="ys-section-title">Budget</div>
          <div class="ys-txt-note">No budget data.</div>
        </div>`;
    }
    // Tolerate a few field-name shapes from the pinned /user/budget contract.
    const used = Number(b.used ?? b.spent ?? b.used_usd ?? 0);
    const limit = Number(b.limit ?? b.cap ?? b.limit_usd ?? 0);
    const unit = b.unit ?? b.currency ?? 'USD';
    const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0;
    const over = limit > 0 && used > limit;
    const fmt = (n) => (Number.isFinite(n) ? n.toLocaleString(undefined, { maximumFractionDigits: 2 }) : '—');
    return html`
      <div class="ys-section">
        <div class="ys-section-title">Budget</div>
        <div class="ys-budget-line"><span>Used</span><span>${fmt(used)} ${unit}</span></div>
        <div class="ys-budget-line"><span>Limit</span><span>${limit > 0 ? `${fmt(limit)} ${unit}` : 'unlimited'}</span></div>
        ${limit > 0
          ? html`<div class="ys-budget-bar">
              <div class="ys-budget-bar-fill ${over ? 'ys-over' : ''}" data-pct=${pct}></div>
            </div>
            <div class="ys-txt-note">${pct}% of limit${over ? ' — over budget' : ''}</div>`
          : nothing}
      </div>`;
  }

  _renderMemory() {
    const mem = Array.isArray(this.memory) ? this.memory : [];
    return html`
      <div class="ys-section">
        <div class="ys-section-title">Memory</div>
        ${mem.length === 0
          ? html`<div class="ys-txt-note">No stored memory for your identity.</div>`
          : html`<div class="ys-memory-list">
              ${mem.map((m) => html`
                <div class="ys-memory-item">
                  ${m.key ?? m.id ? html`<div class="ys-memory-key">${m.key ?? m.id}</div>` : nothing}
                  <div>${m.value ?? m.text ?? m.content ?? String(m)}</div>
                </div>`)}
            </div>`}
      </div>`;
  }

  // The budget bar width is CSP-clean: we cannot use inline style=, so the
  // fill width is applied via a CSS custom property set from updated() (a
  // property assignment, not an inline style attribute string).
  updated() {
    const fill = this.querySelector('.ys-budget-bar-fill');
    if (fill) {
      const pct = Number(fill.getAttribute('data-pct') || 0);
      fill.style.width = `${pct}%`;
    }
  }

  render() {
    return html`
      <aside class="ys-app-sidebar">
        ${this._renderAgents()}
        ${this._renderBudget()}
        ${this._renderMemory()}
        <div class="ys-section">
          <div class="ys-section-title">Document check (doc-OPA)</div>
          <ys-doc-upload .api=${this.api}></ys-doc-upload>
        </div>
      </aside>`;
  }
}

customElements.define('ys-user-sidebar', YsUserSidebar);
