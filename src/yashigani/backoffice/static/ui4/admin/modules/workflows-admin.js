// Yashigani 4.0 admin shell — Workflow oversight module (NEW 4.0 admin surface).
//
// Admin read + disable for user-authored no-code workflows and the scheduler's
// run history, surfacing the per-step governance trail (ingress/egress OPA +
// inspection verdict) the scheduler records for every governed step:
//   GET   /user/workflows                       → workflow list
//   GET   /user/workflows/{id}                  → full spec (steps + schedule)
//   GET   /user/workflows/{id}/runs             → scheduler run history
//   GET   /user/workflows/{id}/runs/{run_id}    → per-step detail
//   PATCH /user/workflows/{id} {enabled:false}  → admin disable
//
// ⚠ BACKEND GAP (flagged): these routes are user_workflows_router endpoints gated
// by UserSession and BOLA-scoped to the *calling* identity (account_id ==
// owner). There is NO admin-plane / cross-user oversight endpoint yet, so an
// admin ApiClient (sessionKind:'admin') cannot enumerate OTHER users' workflows
// through them — it would 401 (UserSession) or only ever see its own. This module
// is the UI half of the contract; it needs a backend admin-oversight route
// (e.g. GET /admin/workflows + /admin/workflows/{id}/runs with admin auth) to be
// fully functional. Until then it renders the empty/locked state honestly.
//
// SAFE-RENDER: workflow names/descriptions + step output are user-authored. All
// fields render via Lit auto-escape (ys-table / ${value} / <pre> textContent) —
// never innerHTML, never the markdown sink. XSS-inert.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets;

const STEP_VERDICT_BADGE = (s) => {
  if (s === 'completed') return 'ys-badge-green';
  if (s === 'denied' || s === 'blocked') return 'ys-badge-red';
  return 'ys-badge-amber';
};

export class YsAdminWorkflows extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _workflows: { state: true },
    _unavailable: { state: true },
    _selected: { state: true },     // workflow_id whose runs are shown
    _runs: { state: true },
    _runDetail: { state: true },    // expanded run
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._workflows = [];
    this._unavailable = false;
    this._selected = null;
    this._runs = [];
    this._runDetail = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    this._loading = true;
    const res = await this.api.get('/user/workflows');
    if (res == null) {
      // null = read failed / not authorised on the admin plane (the backend gap).
      this._unavailable = true;
      this._workflows = [];
    } else {
      this._unavailable = false;
      this._workflows = Array.isArray(res.workflows) ? res.workflows : [];
    }
    this._loading = false;
  }

  async _viewRuns(wfId) {
    this._selected = wfId;
    this._runDetail = null;
    const res = await this.api.get(`/user/workflows/${encodeURIComponent(wfId)}/runs?limit=50`);
    this._runs = (res && Array.isArray(res.runs)) ? res.runs : [];
  }

  async _disable(wfId) {
    const res = await this.api.mutate(`/user/workflows/${encodeURIComponent(wfId)}`, {
      method: 'PATCH', body: { enabled: false },
    });
    if (res.ok) { this.app && this.app.toast('Workflow disabled.', 'success'); this._load(); }
    else { this.app && this.app.toast(res.error ? res.error.message : 'Failed.', 'error'); }
  }

  _toggleRunDetail(run) {
    this._runDetail = (this._runDetail && this._runDetail.run_id === run.run_id) ? null : run;
  }

  _renderGapBanner() {
    return html`
      <div class="ys-system-chrome" role="note">
        <div class="ys-system-chrome-sentinel">Admin oversight — backend route required</div>
        <div class="ys-system-chrome-msg">
          The workflow + run-history routes are user-plane (UserSession, BOLA-scoped
          to the owner). Cross-user admin oversight needs a dedicated admin endpoint
          (e.g. GET /admin/workflows). This panel is the UI half; wire the backend to
          enumerate all owners.
        </div>
      </div>`;
  }

  _renderWorkflows() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">User workflows (${this._workflows.length})</div>
        <div class="ys-panel-body">
          ${this._unavailable ? this._renderGapBanner() : nothing}
          ${this._workflows.length === 0
            ? html`<div class="ys-txt-note">No workflows visible to this session.</div>`
            : this._workflows.map((w) => html`
                <div class="ys-svc-card">
                  <span class="ys-badge ${w.enabled ? 'ys-badge-green' : 'ys-badge-red'}">${w.enabled ? 'enabled' : 'disabled'}</span>
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${w.name || w.workflow_id}</div>
                    <div class="ys-txt-note">owner: ${w.owner_identity_id || '—'} · ${w.description || ''}</div>
                  </div>
                  <button class="ys-btn ys-btn-ghost" @click=${() => this._viewRuns(w.workflow_id)}>Runs</button>
                  ${w.enabled
                    ? html`<button class="ys-btn ys-btn-danger" @click=${() => this._disable(w.workflow_id)}>Disable</button>`
                    : nothing}
                </div>`)}
        </div>
      </div>`;
  }

  _renderRuns() {
    if (!this._selected) {
      return html`<div class="ys-panel"><div class="ys-panel-header">Run history</div>
        <div class="ys-panel-body"><div class="ys-txt-note">Select a workflow to see scheduler runs.</div></div></div>`;
    }
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Run history — ${this._selected}</div>
        <div class="ys-panel-body">
          ${this._runs.length === 0
            ? html`<div class="ys-txt-note">No runs recorded.</div>`
            : this._runs.map((run) => html`
                <div class="ys-svc-card" @click=${() => this._toggleRunDetail(run)}>
                  <span class="ys-badge ${STEP_VERDICT_BADGE(run.status)}">${run.status}</span>
                  <div class="ys-svc-meta">
                    <div class="ys-svc-name">${run.run_id}</div>
                    <div class="ys-txt-note">${run.trigger_kind} · ${run.started_at || ''}</div>
                  </div>
                </div>
                ${this._runDetail && this._runDetail.run_id === run.run_id
                  ? this._renderSteps(run)
                  : nothing}`)}
        </div>
      </div>`;
  }

  _renderSteps(run) {
    const steps = Array.isArray(run.steps) ? run.steps : [];
    return html`
      <div class="ys-panel-body">
        ${steps.map((s) => html`
          <div class="ys-svc-card">
            <span class="ys-badge ${STEP_VERDICT_BADGE(s.status)}">${s.status}</span>
            <div class="ys-svc-meta">
              <div class="ys-svc-name">#${s.step_index} ${s.actor} → ${s.action}</div>
              <div class="ys-txt-note">
                ingress-OPA: ${s.ingress_opa || '—'} · egress-OPA: ${s.egress_opa || '—'}
                · inspection: ${s.inspection_verdict || '—'}${s.block_source ? ` · blocked-by: ${s.block_source}` : ''}
              </div>
            </div>
          </div>`)}
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading workflows…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <div class="ys-admin-2col">
          ${this._renderWorkflows()}
          ${this._renderRuns()}
        </div>
      </div>`;
  }
}

customElements.define('ys-admin-workflows', YsAdminWorkflows);

registerAdminModule({
  id: 'workflows',
  label: 'Workflow oversight',
  icon: '⛓',
  order: 35,
  render: (ctx) => html`<ys-admin-workflows .api=${ctx.api} .app=${ctx.app}></ys-admin-workflows>`,
});
