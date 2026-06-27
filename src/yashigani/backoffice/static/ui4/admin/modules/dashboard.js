// Yashigani 4.0 admin shell — Dashboard module (REFERENCE, fully built).
//
// The worked example every Wave-2 module group copies. It demonstrates the
// whole contract end-to-end:
//   • a self-contained LitElement (<ys-admin-dashboard>) that owns its own data
//     load + render lifecycle and takes the shared ApiClient as `.api`,
//   • a thin registerAdminModule() descriptor (bottom of file) that mounts the
//     element and forwards ctx.api/ctx.app — the ONLY shell-visible surface.
//
// TRUSTED-CHROME: every field rendered here is a server-authored status string
// (component health, counts, priorities) shown via Lit auto-escaping
// (textContent). No model/agent/document output reaches this surface, so the §3
// markdown sink is not used. Data arrives through the shared ApiClient
// (sessionKind:'admin'); this component never fetches raw or parses errors.
//
// Wired to the real 3.0 dashboard endpoints (routes/dashboard.py + accounts.py +
// agents.py), replicating what the old dashboard.js dashboard page shows:
//   GET /dashboard/services-health   → per-service semaphores + roll-up
//   GET /dashboard/security-metrics  → active alerts by priority (P1–P5)
//   GET /dashboard/budget-summary    → spend gauge
//   GET /dashboard/traffic-metrics   → request/agent/MCP activity
//   GET /admin/accounts/enforcement  → admin account counts (active/total)
//   GET /admin/agents                → registered service/machine agent count
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';           // registers ys-table etc.
import { registerAdminModule } from '../module-registry.js';

void widgets; // retain the side-effect import (ys-* custom elements).

// Map a backend status string to a semaphore severity class (3.0 R25 palette).
function semaphoreClass(status) {
  if (status === 'ok' || status === 'community' || status === 'not_configured') {
    return 'ys-semaphore--ok';
  }
  if (status === 'degraded' || status === 'warning' || status === 'stopped') {
    return 'ys-semaphore--degraded';
  }
  return 'ys-semaphore--critical';
}

function rollupClass(rollup) {
  if (rollup === 'ok') return 'ys-semaphore--ok';
  if (rollup === 'degraded') return 'ys-semaphore--degraded';
  return 'ys-semaphore--critical';
}

export class YsAdminDashboard extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _rollup: { state: true },
    _services: { state: true },
    _alerts: { state: true },     // {P1..P5}
    _budget: { state: true },
    _traffic: { state: true },
    _admins: { state: true },     // {total, active, below_active_minimum}
    _agentCount: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._rollup = 'unknown';
    this._services = [];
    this._alerts = {};
    this._budget = null;
    this._traffic = null;
    this._admins = null;
    this._agentCount = null;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    // Parallel fan-out (mirrors 3.0 loadDashboard()'s Promise.all). Every read
    // is null-tolerant: a missing/410 subsystem renders an empty card, never a
    // hard error (community-tier deploys omit several subsystems).
    const [svc, sec, budget, traffic, enforcement, agents] = await Promise.all([
      this.api.get('/dashboard/services-health'),
      this.api.get('/dashboard/security-metrics'),
      this.api.get('/dashboard/budget-summary'),
      this.api.get('/dashboard/traffic-metrics'),
      this.api.get('/admin/accounts/enforcement'),
      this.api.get('/admin/agents'),
    ]);

    this._rollup = (svc && svc.rollup) || 'unknown';
    this._services = (svc && Array.isArray(svc.services)) ? svc.services : [];
    this._alerts = (sec && sec.recent_alerts_by_priority) || {};
    this._budget = (budget && typeof budget === 'object') ? budget : null;
    this._traffic = (traffic && typeof traffic === 'object') ? traffic : null;
    this._admins = (enforcement && typeof enforcement === 'object') ? enforcement : null;
    this._agentCount = Array.isArray(agents)
      ? agents.length
      : (agents && Array.isArray(agents.agents) ? agents.agents.length : null);

    this._loading = false;
  }

  _alertTotal() {
    const c = this._alerts || {};
    return (c.P1 || 0) + (c.P2 || 0) + (c.P3 || 0) + (c.P4 || 0) + (c.P5 || 0);
  }

  _budgetLine() {
    const b = this._budget;
    if (!b) return '—';
    const used = Number(b.used ?? b.spent ?? b.total_used ?? 0);
    const cap = Number(b.cap ?? b.limit ?? b.total_cap ?? 0);
    const unit = b.unit ?? b.currency ?? 'USD';
    const fmt = (n) => (Number.isFinite(n) ? n.toLocaleString(undefined, { maximumFractionDigits: 2 }) : '—');
    return cap > 0 ? `${fmt(used)} / ${fmt(cap)} ${unit}` : `${fmt(used)} ${unit}`;
  }

  _renderStatCards() {
    const admins = this._admins;
    const adminVal = admins
      ? `${admins.active ?? '—'} / ${admins.total ?? '—'}`
      : '—';
    const adminWarn = admins && admins.below_active_minimum;
    return html`
      <div class="ys-stat-grid">
        <div class="ys-stat-card">
          <div class="ys-stat-num ${adminWarn ? 'ys-stat-num--warn' : ''}">${adminVal}</div>
          <div class="ys-stat-label">Admins (active / total)${adminWarn ? ' — below minimum' : ''}</div>
        </div>
        <div class="ys-stat-card">
          <div class="ys-stat-num">${this._agentCount == null ? '—' : this._agentCount}</div>
          <div class="ys-stat-label">Registered agents</div>
        </div>
        <div class="ys-stat-card">
          <div class="ys-stat-num">${this._alertTotal()}</div>
          <div class="ys-stat-label">Active alerts (buffer)</div>
        </div>
        <div class="ys-stat-card">
          <div class="ys-stat-num ys-stat-num--sm">${this._budgetLine()}</div>
          <div class="ys-stat-label">Budget used</div>
        </div>
      </div>`;
  }

  _renderHealthRollup() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          <span class="ys-semaphore ${rollupClass(this._rollup)}" title=${this._rollup}></span>
          System health — ${this._rollup}
        </div>
        <div class="ys-panel-body">
          ${this._services.length === 0
            ? html`<div class="ys-txt-note">No service-health data.</div>`
            : html`<div class="ys-svc-grid">
                ${this._services.map((s) => html`
                  <div class="ys-svc-card">
                    <span class="ys-semaphore ${semaphoreClass(s.status)}" title=${s.status}></span>
                    <div class="ys-svc-meta">
                      <div class="ys-svc-name">${s.name}</div>
                      <div class="ys-txt-note">${s.detail || s.status}</div>
                    </div>
                    ${s.criticality
                      ? html`<span class="ys-badge ys-badge-amber">critical</span>`
                      : html`<span class="ys-badge ys-badge-blue">non-critical</span>`}
                  </div>`)}
              </div>`}
        </div>
      </div>`;
  }

  _renderAlerts() {
    const c = this._alerts || {};
    const rows = [
      { key: 'P1', label: 'P1 Critical' },
      { key: 'P2', label: 'P2 High' },
      { key: 'P3', label: 'P3 Medium' },
      { key: 'P4', label: 'P4 Low' },
      { key: 'P5', label: 'P5 Informational' },
    ];
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Active alerts</div>
        <div class="ys-panel-body">
          <ul class="ys-alert-list">
            ${rows.map((r) => {
              const n = c[r.key] || 0;
              return html`
                <li class="ys-alert-item">
                  <span class="ys-semaphore ys-semaphore--${r.key.toLowerCase()}"></span>
                  <span class="ys-alert-label">${r.label}</span>
                  <span class="ys-alert-count ${n === 0 ? 'ys-alert-count--zero' : ''}">${n}</span>
                </li>`;
            })}
          </ul>
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading dashboard…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        ${this._renderStatCards()}
        ${this._renderHealthRollup()}
        <div class="ys-admin-2col">
          ${this._renderAlerts()}
          <div class="ys-panel">
            <div class="ys-panel-header">Services</div>
            <div class="ys-panel-body">
              <ys-table
                .columns=${[
                  { key: 'name', label: 'Service', sortable: true },
                  { key: 'status', label: 'Status', sortable: true },
                  { key: 'criticality', label: 'Criticality', render: (r) => (r.criticality ? 'critical' : 'non-critical') },
                  { key: 'detail', label: 'Detail' },
                ]}
                .rows=${this._services}
                emptyText="No services reporting."></ys-table>
            </div>
          </div>
        </div>
        ${this._traffic && (this._traffic.requests_total != null || this._traffic.request_rate != null)
          ? html`<div class="ys-panel">
              <div class="ys-panel-header">Traffic</div>
              <div class="ys-panel-body ys-txt-note">
                Requests: ${this._traffic.requests_total ?? this._traffic.request_rate ?? '—'}
              </div>
            </div>`
          : nothing}
      </div>`;
  }
}

customElements.define('ys-admin-dashboard', YsAdminDashboard);

// ── Registration: the thin descriptor Wave-2 modules copy ────────────────────
// id pins the #dashboard route; order:0 keeps it first in the nav. render()
// mounts the element and forwards the shared client + app handle — nothing else.
registerAdminModule({
  id: 'dashboard',
  label: 'Dashboard',
  icon: '◧',
  order: 0,
  render: (ctx) => html`
    <ys-admin-dashboard .api=${ctx.api} .app=${ctx.app}></ys-admin-dashboard>`,
});
