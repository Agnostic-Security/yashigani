// Yashigani 4.0 admin shell — NHI SVID Approvals (NEW 4.0 surface, no UI in 3.0).
//
// The admin-approval gate (RISK-097) that a user-created agent must clear before
// it can run: a non-human identity (NHI) is registered with svid_issued=false
// and the gateway returns 403 NHI_PENDING_APPROVAL on every invocation until an
// admin approves its SVID here. Approval mints the PKI leaf cert and flips the
// NHI into the active index.
//
// Endpoints:
//   GET  /admin/agents                 — NHIs are kind="nhi" in the registry; the
//                                        4.0 AgentResponse now carries kind /
//                                        svid_issued / spiffe_id / owner_identity_id.
//   POST /admin/nhi/{nhi_id}/approve   — StepUpAdminSession (ASVS V6.8.4). The
//                                        server tags step_up_required → the shared
//                                        TOTP modal fires via ctx.api (RISK-103).
//
// TRUSTED-CHROME: all rendered values are server-authored identity fields shown
// via Lit textContent. No markdown sink, no innerHTML.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

export class YsAdminNhiApprovals extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _nhis: { state: true },
    _busy: { state: true },   // nhi_id currently being approved
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._nhis = [];
    this._busy = '';
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
    this._nhis = (Array.isArray(agents) ? agents : []).filter((a) => a.kind === 'nhi');
    this._loading = false;
  }

  _pending() { return this._nhis.filter((n) => n.svid_issued === false); }
  _approved() { return this._nhis.filter((n) => n.svid_issued === true); }

  async _approve(nhi) {
    this._busy = nhi.agent_id;
    // Step-up is server-driven: approve_nhi_svid requires StepUpAdminSession, so
    // mutate() receives 401 step_up_required and the shared TOTP modal prompts,
    // posts /auth/stepup and retries once.
    const res = await this.api.mutate(`/admin/nhi/${encodeURIComponent(nhi.agent_id)}/approve`, { method: 'POST' });
    this._busy = '';
    if (res.ok) {
      this.app && this.app.toast(`NHI “${nhi.name}” SVID approved.`, 'success');
      await this._load();
    } else {
      this.app && this.app.toast((res.error && res.error.message) || 'Approval failed.', 'error');
    }
  }

  _renderPending() {
    const rows = this._pending();
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Pending SVID approval (${rows.length})
          ${rows.length ? html`<span class="ys-badge ys-badge-amber">action required</span>` : nothing}
        </div>
        <div class="ys-panel-body">
          ${rows.length === 0
            ? html`<div class="ys-txt-note">No NHIs awaiting approval — all clear.</div>`
            : html`<table class="ys-table">
                <thead><tr><th>Name</th><th>Owner</th><th>Template</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                  ${rows.map((n) => html`
                    <tr>
                      <td>${n.name}</td>
                      <td>${n.owner_identity_id || '—'}</td>
                      <td>${n.template_id || '—'}</td>
                      <td><span class="ys-badge ys-badge-amber">pending</span></td>
                      <td>
                        <button class="ys-btn" data-act="approve"
                                ?disabled=${this._busy === n.agent_id}
                                @click=${() => this._approve(n)}>
                          ${this._busy === n.agent_id ? 'Approving…' : 'Approve SVID'}
                        </button>
                      </td>
                    </tr>`)}
                </tbody>
              </table>`}
        </div>
      </div>`;
  }

  _renderApproved() {
    const rows = this._approved();
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Approved NHIs (${rows.length})</div>
        <div class="ys-panel-body">
          <table class="ys-table">
            <thead><tr><th>Name</th><th>SPIFFE ID</th><th>Owner</th><th>Status</th></tr></thead>
            <tbody>
              ${rows.length === 0
                ? html`<tr><td class="ys-table-empty" colspan="4">No approved NHIs yet.</td></tr>`
                : rows.map((n) => html`
                    <tr>
                      <td>${n.name}</td>
                      <td>${n.spiffe_id || '—'}</td>
                      <td>${n.owner_identity_id || '—'}</td>
                      <td><span class="ys-badge ys-badge-green">active</span></td>
                    </tr>`)}
            </tbody>
          </table>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading NHIs…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-txt-note">
          Non-human identities must be admin-approved before the gateway will run them
          (RISK-097). Approval mints the PKI leaf cert and requires step-up TOTP.
        </div>
        ${this._renderPending()}
        ${this._renderApproved()}
      </div>`;
  }
}

customElements.define('ys-admin-nhi-approvals', YsAdminNhiApprovals);

registerAdminModule({
  id: 'nhi-approvals',
  label: 'NHI Approvals',
  icon: '◆',
  order: 10,
  group: 'agents',
  render: (ctx) => html`<ys-admin-nhi-approvals .api=${ctx.api} .app=${ctx.app}></ys-admin-nhi-approvals>`,
});
