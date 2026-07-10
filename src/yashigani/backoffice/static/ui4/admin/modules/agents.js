// Yashigani 4.0 admin shell — Agents module (group: Agents, NHI & Resources).
//
// Rebuilds the 3.0 Agents page on the hardened ui4 stack and surfaces the
// previously-dark GAPs (AG-07 quickstart, AG-08 identities) plus the NEW 4.0
// per-agent SVID/cert status column (registry kind / svid_issued / spiffe_id,
// now carried on AgentResponse).
//
// SCOPE: service/machine agents only (kind="agent" that are NOT user-created
// governed Langflow callees — those live in the Agent Templates module, keyed
// by the "user_agent_callee" group). NHIs (kind="nhi") live in NHI Approvals.
//
// Endpoints (routes/agents.py + agent_bundles.py):
//   GET    /admin/agents                       list (PRESENT, rebuilt)
//   POST   /admin/agents                       register — StepUpAdminSession (server-tagged)
//   PUT    /admin/agents/{id}                   edit    — StepUpAdminSession
//   DELETE /admin/agents/{id}                   deactivate — StepUpAdminSession
//   GET    /admin/agents/{id}/quickstart        GAP AG-07 — integration snippets
//   GET    /admin/identities                    GAP AG-08 — principal inventory
//   GET    /admin/agent-bundles                 GAP AB — opt-in bundle catalogue
//
// TRUSTED-CHROME: every value rendered here is server-authored status text shown
// via Lit textContent auto-escape (no §3 markdown sink, no innerHTML). Step-up
// is transparent: ctx.api.mutate() honours the server's step_up_required tag via
// the shared TOTP modal (RISK-103).
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const CALLEE_GROUP = 'user_agent_callee';

/** Split a comma/newline list into a trimmed, de-duped string array. */
function csvToList(v) {
  if (!v) return [];
  return [...new Set(String(v).split(/[\n,]/).map((s) => s.trim()).filter(Boolean))];
}
function listToCsv(v) {
  return Array.isArray(v) ? v.join(', ') : '';
}

export class YsAdminAgents extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _agents: { state: true },
    _identities: { state: true },
    _bundles: { state: true },
    _disclaimer: { state: true },
    _showRegister: { state: true },
    _edit: { state: true },        // agent being edited (draft), or null
    _result: { state: true },      // {title, token?, quick_start?} post-action modal
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._agents = [];
    this._identities = [];
    this._bundles = [];
    this._disclaimer = '';
    this._showRegister = false;
    this._edit = null;
    this._result = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [agents, identities, bundles] = await Promise.all([
      this.api.get('/admin/agents'),
      this.api.get('/admin/identities'),
      this.api.get('/admin/agent-bundles/'),
    ]);
    this._agents = Array.isArray(agents) ? agents : [];
    this._identities = Array.isArray(identities) ? identities : [];
    this._bundles = (bundles && Array.isArray(bundles.bundles)) ? bundles.bundles : [];
    this._disclaimer = (bundles && bundles.disclaimer) || '';
    this._loading = false;
  }

  // Service/machine agents = kind "agent" excluding user-created governed callees.
  _serviceAgents() {
    return this._agents.filter(
      (a) => (a.kind || 'agent') === 'agent' && !(a.groups || []).includes(CALLEE_GROUP),
    );
  }

  _toast(res, okMsg) {
    if (res && res.ok) this.app && this.app.toast(okMsg, 'success');
    else this.app && this.app.toast((res && res.error && res.error.message) || 'Action failed.', 'error');
  }

  // ── Register ───────────────────────────────────────────────────────────────
  async _onRegister(values) {
    const body = {
      name: (values.name || '').trim(),
      upstream_url: (values.upstream_url || '').trim(),
      protocol: values.protocol || 'openai',
      groups: csvToList(values.groups),
      allowed_caller_groups: csvToList(values.allowed_caller_groups),
      allowed_paths: csvToList(values.allowed_paths),
      allowed_cidrs: csvToList(values.allowed_cidrs),
    };
    const res = await this.api.mutate('/admin/agents', { method: 'POST', body });
    if (res.ok) {
      this._showRegister = false;
      this._result = {
        title: `Agent “${res.data.name}” registered`,
        token: res.data.token,
        quick_start: res.data.quick_start,
      };
      await this._load();
    } else {
      this._toast(res);
    }
  }

  // ── Edit ─────────────────────────────────────────────────────────────────
  _openEdit(a) {
    this._edit = {
      agent_id: a.agent_id,
      name: a.name,
      upstream_url: a.upstream_url,
      groups: listToCsv(a.groups),
      allowed_caller_groups: listToCsv(a.allowed_caller_groups),
      allowed_paths: listToCsv(a.allowed_paths),
      allowed_cidrs: listToCsv(a.allowed_cidrs),
    };
  }
  _editField(k, v) { this._edit = { ...this._edit, [k]: v }; }
  async _saveEdit() {
    const e = this._edit;
    const body = {
      name: e.name,
      upstream_url: e.upstream_url,
      groups: csvToList(e.groups),
      allowed_caller_groups: csvToList(e.allowed_caller_groups),
      allowed_paths: csvToList(e.allowed_paths),
      allowed_cidrs: csvToList(e.allowed_cidrs),
    };
    const res = await this.api.mutate(`/admin/agents/${encodeURIComponent(e.agent_id)}`, { method: 'PUT', body });
    this._toast(res, 'Agent updated.');
    if (res.ok) { this._edit = null; await this._load(); }
  }

  async _deactivate(a) {
    const res = await this.api.mutate(`/admin/agents/${encodeURIComponent(a.agent_id)}`, {
      method: 'DELETE', body: { reason: 'admin UI deactivate' },
    });
    this._toast(res, 'Agent deactivated.');
    if (res.ok) await this._load();
  }

  async _quickstart(a) {
    const data = await this.api.get(`/admin/agents/${encodeURIComponent(a.agent_id)}/quickstart`);
    if (data && data.quick_start) {
      this._result = { title: `Quickstart — ${a.name}`, quick_start: data.quick_start };
    } else {
      this.app && this.app.toast('Quickstart unavailable.', 'error');
    }
  }

  _svidCell(a) {
    if (a.spiffe_id) return `✓ ${a.spiffe_id}`;
    if (a.svid_issued === true) return 'approved';
    if (a.svid_issued === false) return 'pending';
    return 'n/a';
  }

  _renderAgentsPanel() {
    const rows = this._serviceAgents();
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Service &amp; machine agents (${rows.length})
          <button class="ys-btn ys-btn-ghost" data-act="register"
                  @click=${() => { this._showRegister = !this._showRegister; }}>
            ${this._showRegister ? 'Close' : '+ Register agent'}
          </button>
        </div>
        <div class="ys-panel-body">
          ${this._showRegister ? this._renderRegisterForm() : nothing}
          <table class="ys-table">
            <thead><tr>
              <th>Name</th><th>Upstream</th><th>Status</th><th>SVID / cert</th><th>Groups</th><th>Actions</th>
            </tr></thead>
            <tbody>
              ${rows.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="6">No agents registered.</td></tr>`
                : rows.map((a) => html`
                    <tr>
                      <td>${a.name}</td>
                      <td>${a.upstream_url}</td>
                      <td>${a.status}</td>
                      <td>${this._svidCell(a)}</td>
                      <td>${listToCsv(a.groups)}</td>
                      <td>
                        <button class="ys-btn ys-btn-ghost" data-act="edit" @click=${() => this._openEdit(a)}>Edit</button>
                        <button class="ys-btn ys-btn-ghost" data-act="quickstart" @click=${() => this._quickstart(a)}>Quickstart</button>
                        <button class="ys-btn ys-btn-danger" data-act="deactivate" @click=${() => this._deactivate(a)}>Deactivate</button>
                      </td>
                    </tr>`)}
            </tbody>
          </table>
        </div>
      </div>`;
  }

  _renderRegisterForm() {
    return html`
      <div class="ys-panel">
        <ys-form
          .fields=${[
            { name: 'name', label: 'Name (slug)', required: true, placeholder: 'my-agent' },
            { name: 'upstream_url', label: 'Upstream URL', required: true, placeholder: 'https://agent.example.com' },
            { name: 'protocol', label: 'Protocol', type: 'select',
              options: [{ value: 'openai', label: 'openai' }, { value: 'letta', label: 'letta' }, { value: 'langflow', label: 'langflow' }] },
            { name: 'groups', label: 'Groups (comma-separated)', placeholder: 'group-a, group-b' },
            { name: 'allowed_caller_groups', label: 'Allowed caller groups', placeholder: 'user' },
            { name: 'allowed_paths', label: 'Allowed paths', placeholder: '/mcp' },
            { name: 'allowed_cidrs', label: 'Allowed CIDRs', placeholder: '10.0.0.0/8' },
          ]}
          submitLabel="Register"
          @ys-submit=${(e) => this._onRegister(e.detail)}></ys-form>
      </div>`;
  }

  _renderIdentitiesPanel() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Identities — principal inventory (${this._identities.length})</div>
        <div class="ys-panel-body">
          <ys-table
            .columns=${[
              { key: 'name', label: 'Name', sortable: true },
              { key: 'kind', label: 'Kind', sortable: true },
              { key: 'slug', label: 'Slug' },
              { key: 'status', label: 'Status', sortable: true },
              { key: 'last_seen_at', label: 'Last seen' },
            ]}
            .rows=${this._identities}
            emptyText="No identities (community tier or none registered)."></ys-table>
        </div>
      </div>`;
  }

  _renderBundlesPanel() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Optional agent bundles</div>
        <div class="ys-panel-body">
          ${this._disclaimer ? html`<div class="ys-txt-note">${this._disclaimer}</div>` : nothing}
          <ys-table
            .columns=${[
              { key: 'name', label: 'Bundle', sortable: true },
              { key: 'image', label: 'Image' },
              { key: 'license', label: 'License' },
              { key: 'integration', label: 'Integration' },
            ]}
            .rows=${this._bundles}
            emptyText="No bundles available."></ys-table>
        </div>
      </div>`;
  }

  _renderEditModal() {
    if (!this._edit) return nothing;
    const e = this._edit;
    const field = (k, label) => html`
      <div class="ys-field">
        <label class="ys-label">${label}</label>
        <input class="ys-input" .value=${e[k] ?? ''} @input=${(ev) => this._editField(k, ev.target.value)}>
      </div>`;
    return html`
      <div class="ys-modal-backdrop" @click=${(ev) => { if (ev.target === ev.currentTarget) this._edit = null; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">Edit agent — ${e.name}</div>
          <div class="ys-modal-body">
            ${field('name', 'Name')}
            ${field('upstream_url', 'Upstream URL')}
            ${field('groups', 'Groups (comma-separated)')}
            ${field('allowed_caller_groups', 'Allowed caller groups')}
            ${field('allowed_paths', 'Allowed paths')}
            ${field('allowed_cidrs', 'Allowed CIDRs')}
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn ys-btn-secondary" @click=${() => { this._edit = null; }}>Cancel</button>
            <button class="ys-btn" data-act="save-edit" @click=${() => this._saveEdit()}>Save</button>
          </div>
        </div>
      </div>`;
  }

  _renderResultModal() {
    if (!this._result) return nothing;
    const r = this._result;
    const qs = r.quick_start || {};
    return html`
      <div class="ys-modal-backdrop" @click=${(ev) => { if (ev.target === ev.currentTarget) this._result = null; }}>
        <div class="ys-modal" role="dialog" aria-modal="true">
          <div class="ys-modal-header">${r.title}</div>
          <div class="ys-modal-body">
            ${r.token ? html`
              <div class="ys-field">
                <label class="ys-label">Token — shown once, store it now</label>
                <div class="ys-code-wrap"><code class="ys-system-chrome-code">${r.token}</code></div>
              </div>` : nothing}
            ${qs.curl ? html`<div class="ys-field"><label class="ys-label">curl</label>
              <div class="ys-code-wrap"><code class="ys-system-chrome-code">${qs.curl}</code></div></div>` : nothing}
            ${qs.python_httpx ? html`<div class="ys-field"><label class="ys-label">Python (httpx)</label>
              <div class="ys-code-wrap"><code class="ys-system-chrome-code">${qs.python_httpx}</code></div></div>` : nothing}
            ${qs.note ? html`<div class="ys-txt-note">${qs.note}</div>` : nothing}
          </div>
          <div class="ys-modal-footer">
            <button class="ys-btn" @click=${() => { this._result = null; }}>Done</button>
          </div>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading agents…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderAgentsPanel()}
        <div class="ys-admin-2col">
          ${this._renderIdentitiesPanel()}
          ${this._renderBundlesPanel()}
        </div>
        ${this._renderEditModal()}
        ${this._renderResultModal()}
      </div>`;
  }
}

customElements.define('ys-admin-agents', YsAdminAgents);

registerAdminModule({
  id: 'agents',
  label: 'Agents',
  icon: '⬡',
  order: 0,
  group: 'agents',
  render: (ctx) => html`<ys-admin-agents .api=${ctx.api} .app=${ctx.app}></ys-admin-agents>`,
});
