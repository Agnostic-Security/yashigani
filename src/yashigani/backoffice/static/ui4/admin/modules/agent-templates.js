// Yashigani 4.0 admin shell — Agent Template pool oversight (NEW 4.0 surface).
//
// Users build their own agents through the no-code builder and Langflow visual
// flows (routes/user_agents.py). Each committed flow registers a GOVERNED
// Langflow callee in the agent registry (kind="agent", group "user_agent_callee",
// protocol "langflow", carrying owner_identity_id + template_id lineage). This
// module gives admins oversight of that user-created pool: list, inspect, and
// disable (deactivate the governed callee → the gateway can no longer route to
// the flow). The gateway still OPA-adjudicates every callee invocation; this is
// the human governance surface on top.
//
// Endpoints:
//   GET    /admin/agents             — filtered to governed callees (group=user_agent_callee)
//   GET    /admin/agents/{id}        — full record for the inspect panel
//   DELETE /admin/agents/{id}        — disable (deactivate) — StepUpAdminSession
//
// TRUSTED-CHROME: all values are server-authored registry fields via Lit
// textContent. No markdown sink, no innerHTML.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const CALLEE_GROUP = 'user_agent_callee';

export class YsAdminAgentTemplates extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _callees: { state: true },
    _inspect: { state: true },   // full record being inspected, or null
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._callees = [];
    this._inspect = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const agents = await this.api.get('/admin/agents');
    this._callees = (Array.isArray(agents) ? agents : []).filter(
      (a) => (a.groups || []).includes(CALLEE_GROUP) || a.kind === 'persona' || a.protocol === 'langflow',
    );
    this._loading = false;
  }

  async _inspectOne(a) {
    const full = await this.api.get(`/admin/agents/${encodeURIComponent(a.agent_id)}`);
    this._inspect = full || a;
  }

  async _disable(a) {
    const res = await this.api.mutate(`/admin/agents/${encodeURIComponent(a.agent_id)}`, {
      method: 'DELETE', body: { reason: 'admin template-pool disable' },
    });
    if (res.ok) {
      this.app && this.app.toast(`Template agent “${a.name}” disabled.`, 'success');
      await this._load();
    } else {
      this.app && this.app.toast((res.error && res.error.message) || 'Disable failed.', 'error');
    }
  }

  _renderInspect() {
    if (!this._inspect) return nothing;
    const a = this._inspect;
    const rowsKv = [
      ['Agent ID', a.agent_id],
      ['Name', a.name],
      ['Owner', a.owner_identity_id || '—'],
      ['Template', a.template_id || '—'],
      ['Protocol', a.protocol || '—'],
      ['Upstream (flow)', a.upstream_url || '—'],
      ['Status', a.status || '—'],
      ['Groups', (a.groups || []).join(', ') || '—'],
      ['Allowed caller groups', (a.allowed_caller_groups || []).join(', ') || '—'],
      ['Allowed paths', (a.allowed_paths || []).join(', ') || '—'],
    ];
    return html`
      <div class="ys-modal-backdrop" @click=${(ev) => { if (ev.target === ev.currentTarget) this._inspect = null; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Inspect — ${a.name}</div>
          <div class="ys-modal-body">
            <table class="ys-table">
              <tbody>
                ${rowsKv.map(([k, v]) => html`<tr><td>${k}</td><td>${v}</td></tr>`)}
              </tbody>
            </table>
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn" @click=${() => { this._inspect = null; }}>Close</button>
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading template pool…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-panel">
          <div class="ys-panel-header">User-created agent templates (${this._callees.length})</div>
          <div class="ys-panel-body">
            <div class="ys-txt-note">
              Governed Langflow callees and personas built by users in the no-code builder.
              Every invocation is still OPA-adjudicated at the gateway; disable removes the
              registry route entirely.
            </div>
            <table class="ys-table">
              <thead><tr><th>Name</th><th>Owner</th><th>Template</th><th>Status</th><th>Actions</th></tr></thead>
              <tbody>
                ${this._callees.length === 0
                  ? html`<tr><td class="ys-table-empty" colspan="5">No user-created agent templates.</td></tr>`
                  : this._callees.map((a) => html`
                      <tr>
                        <td>${a.name}</td>
                        <td>${a.owner_identity_id || '—'}</td>
                        <td>${a.template_id || '—'}</td>
                        <td>${a.status}</td>
                        <td>
                          <button class="ys-btn ys-btn-ghost" data-act="inspect" @click=${() => this._inspectOne(a)}>Inspect</button>
                          <button class="ys-btn ys-btn-danger" data-act="disable" @click=${() => this._disable(a)}>Disable</button>
                        </td>
                      </tr>`)}
              </tbody>
            </table>
          </div>
        </div>
        ${this._renderInspect()}
      </div>`;
  }
}

customElements.define('ys-admin-agent-templates', YsAdminAgentTemplates);

registerAdminModule({
  id: 'agent-templates',
  label: 'Agent Templates',
  icon: '⌬',
  order: 24,
  render: (ctx) => html`<ys-admin-agent-templates .api=${ctx.api} .app=${ctx.app}></ys-admin-agent-templates>`,
});
