// Yashigani 4.0 admin shell — Infrastructure module ("Ops & Crypto" group).
//
// Surfaces the ops/infrastructure routers the 3.0 SPA never wired (parity-matrix
// GAPs IF-01..04, SV-01/02, CA-01..04):
//   GET  /admin/infrastructure/topology            → AZ topology + warnings
//   PUT  /admin/infrastructure/topology            → spread policy update
//   GET  /admin/infrastructure/autoscaling         → KEDA config per workload
//   PUT  /admin/infrastructure/autoscaling/{wl}    → per-workload scaling update
//   GET  /admin/services                           → optional-service inventory
//   POST /admin/services/{id}                       → manage (deploy-time; STEP-UP)
//   GET  /admin/cache                               → per-tenant response-cache cfg
//   PUT  /admin/cache/{tenant}                      → set cache cfg
//   DELETE /admin/cache/{tenant}                    → flush cache (operational)
//
// TRUSTED-CHROME: every value rendered is a server-authored status/config string
// shown via Lit auto-escape (textContent). No model/agent/document output reaches
// this surface, so the §3 markdown sink is never used. Reads/writes go through the
// shared admin ApiClient (sessionKind:'admin'); ctx.api.mutate already honours the
// server's step_up_required tag (RISK-103) — POST /admin/services/{id} is
// StepUpAdminSession, so a service-manage action transparently prompts for TOTP.
import { LitElement, html, nothing } from '/static/vendor/lit/lit-core.min.js';
import { widgets } from '../../core/index.js';
import { registerAdminModule } from '../module-registry.js';

void widgets; // retain ys-* custom elements (ys-table, ys-toast).

export class YsAdminInfrastructure extends LitElement {
  static properties = {
    api: { attribute: false },
    app: { attribute: false },
    _loading: { state: true },
    _topology: { state: true },
    _autoscaling: { state: true },
    _services: { state: true },
    _cache: { state: true },
    // edit buffers
    _topoZones: { state: true },
    _topoPolicy: { state: true },
    _topoSkew: { state: true },
    _wlEdit: { state: true },     // {workload, min, max, cpu, mem} | null
    _cacheTenant: { state: true },
    _cacheEnabled: { state: true },
    _cacheTtl: { state: true },
  };

  constructor() {
    super();
    this.api = null;
    this.app = null;
    this._loading = true;
    this._topology = null;
    this._autoscaling = null;
    this._services = [];
    this._cache = null;
    this._topoZones = '';
    this._topoPolicy = 'ScheduleAnyway';
    this._topoSkew = 1;
    this._wlEdit = null;
    this._cacheTenant = '';
    this._cacheEnabled = false;
    this._cacheTtl = 300;
  }

  createRenderRoot() { return this; }

  connectedCallback() {
    super.connectedCallback();
    this._load();
  }

  async _load() {
    if (!this.api) return;
    this._loading = true;
    const [topo, scaling, services, cache] = await Promise.all([
      this.api.get('/admin/infrastructure/topology'),
      this.api.get('/admin/infrastructure/autoscaling'),
      this.api.get('/admin/services'),
      this.api.get('/admin/cache'),
    ]);
    this._topology = topo || null;
    this._topoPolicy = (topo && topo.spread_policy) || 'ScheduleAnyway';
    this._autoscaling = scaling || null;
    this._services = (services && Array.isArray(services.services)) ? services.services : [];
    this._cache = cache || null;
    this._loading = false;
  }

  _toast(msg, kind) { if (this.app && this.app.toast) this.app.toast(msg, kind); }

  /** Route a mutate through the step-up-aware client and toast the outcome. */
  async _mutate(path, opts, okMsg) {
    const res = await this.api.mutate(path, opts);
    if (res.ok) {
      this._toast(okMsg, 'success');
      await this._load();
    } else {
      this._toast((res.error && res.error.message) || 'Request failed.', 'error');
    }
    return res;
  }

  // ── Topology ───────────────────────────────────────────────────────────────
  _saveTopology() {
    const zones = this._topoZones.split(',').map((z) => z.trim()).filter(Boolean);
    if (zones.length === 0) { this._toast('Enter at least one zone.', 'error'); return; }
    this._mutate('/admin/infrastructure/topology', {
      method: 'PUT',
      body: { zones, spread_policy: this._topoPolicy, max_skew: Number(this._topoSkew) || 1 },
    }, 'Topology updated.');
  }

  _renderTopology() {
    const t = this._topology;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Availability-zone topology</div>
        <div class="ys-panel-body">
          ${!t ? html`<div class="ys-txt-note">Topology data unavailable.</div>` : html`
            <div class="ys-stat-grid">
              <div class="ys-stat-card">
                <div class="ys-stat-num ${t.az_count < 2 ? 'ys-stat-num--warn' : ''}">${t.az_count ?? '—'}</div>
                <div class="ys-stat-label">Availability zones</div>
              </div>
              <div class="ys-stat-card">
                <div class="ys-stat-num ys-stat-num--sm">${t.spread_policy || '—'}</div>
                <div class="ys-stat-label">Spread policy</div>
              </div>
            </div>
            ${(t.warnings && t.warnings.length)
              ? html`<ul class="ys-alert-list">${t.warnings.map((w) => html`
                  <li class="ys-alert-item">
                    <span class="ys-semaphore ys-semaphore--degraded"></span>
                    <span class="ys-alert-label">${w}</span>
                  </li>`)}</ul>`
              : nothing}
            <div class="ys-field">
              <label class="ys-label">Zones (comma-separated)</label>
              <input class="ys-input" .value=${this._topoZones}
                     placeholder="us-east-1a, us-east-1b"
                     @input=${(e) => { this._topoZones = e.target.value; }}>
            </div>
            <div class="ys-field">
              <label class="ys-label">Spread policy</label>
              <select class="ys-select" .value=${this._topoPolicy}
                      @change=${(e) => { this._topoPolicy = e.target.value; }}>
                <option value="ScheduleAnyway">ScheduleAnyway</option>
                <option value="DoNotSchedule">DoNotSchedule (requires ≥2 zones)</option>
              </select>
            </div>
            <div class="ys-field">
              <label class="ys-label">Max skew</label>
              <input class="ys-input" type="number" min="1" max="5" .value=${String(this._topoSkew)}
                     @input=${(e) => { this._topoSkew = e.target.value; }}>
            </div>
            <button class="ys-btn" @click=${() => this._saveTopology()}>Save topology</button>
          `}
        </div>
      </div>`;
  }

  // ── Autoscaling ──────────────────────────────────────────────────────────────
  _wlRows() {
    const a = this._autoscaling;
    if (!a || !a.workloads) return [];
    return Object.keys(a.workloads).map((k) => ({ workload: k, ...a.workloads[k] }));
  }

  _startWlEdit(row) {
    this._wlEdit = {
      workload: row.workload,
      min: row.min_replicas ?? 1,
      max: row.max_replicas ?? 1,
      cpu: row.cpu_threshold ?? 70,
      mem: row.memory_threshold ?? 80,
    };
  }

  _saveWl() {
    const e = this._wlEdit;
    if (!e) return;
    this._mutate(`/admin/infrastructure/autoscaling/${encodeURIComponent(e.workload)}`, {
      method: 'PUT',
      body: {
        min_replicas: Number(e.min), max_replicas: Number(e.max),
        cpu_threshold: Number(e.cpu), memory_threshold: Number(e.mem),
      },
    }, `Autoscaling updated for ${e.workload}.`).then((r) => { if (r.ok) this._wlEdit = null; });
  }

  _renderAutoscaling() {
    const rows = this._wlRows();
    const e = this._wlEdit;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Autoscaling (KEDA)
          ${this._autoscaling
            ? html`<span class="ys-badge ${this._autoscaling.keda_enabled ? 'ys-badge-green' : 'ys-badge-amber'}">${this._autoscaling.keda_enabled ? 'enabled' : 'disabled'}</span>`
            : nothing}
        </div>
        <div class="ys-panel-body">
          <ys-table
            .columns=${[
              { key: 'workload', label: 'Workload', sortable: true },
              { key: 'min_replicas', label: 'Min' },
              { key: 'max_replicas', label: 'Max' },
              { key: 'cpu_threshold', label: 'CPU %', render: (r) => (r.cpu_threshold ?? '—') },
              { key: 'memory_threshold', label: 'Mem %', render: (r) => (r.memory_threshold ?? '—') },
            ]}
            .rows=${rows}
            emptyText="No workloads reporting."></ys-table>
          <div class="ys-field">
            <label class="ys-label">Edit workload</label>
            <select class="ys-select" .value=${e ? e.workload : ''}
                    @change=${(ev) => { const r = rows.find((x) => x.workload === ev.target.value); if (r) this._startWlEdit(r); else this._wlEdit = null; }}>
              <option value="">— select workload —</option>
              ${rows.map((r) => html`<option value=${r.workload}>${r.workload}</option>`)}
            </select>
          </div>
          ${e ? html`
            <div class="ys-field"><label class="ys-label">Min replicas</label>
              <input class="ys-input" type="number" min="1" max="20" .value=${String(e.min)}
                     @input=${(ev) => { this._wlEdit = { ...e, min: ev.target.value }; }}></div>
            <div class="ys-field"><label class="ys-label">Max replicas</label>
              <input class="ys-input" type="number" min="1" max="100" .value=${String(e.max)}
                     @input=${(ev) => { this._wlEdit = { ...e, max: ev.target.value }; }}></div>
            <div class="ys-field"><label class="ys-label">CPU threshold %</label>
              <input class="ys-input" type="number" min="10" max="100" .value=${String(e.cpu)}
                     @input=${(ev) => { this._wlEdit = { ...e, cpu: ev.target.value }; }}></div>
            <div class="ys-field"><label class="ys-label">Memory threshold %</label>
              <input class="ys-input" type="number" min="10" max="100" .value=${String(e.mem)}
                     @input=${(ev) => { this._wlEdit = { ...e, mem: ev.target.value }; }}></div>
            <button class="ys-btn" @click=${() => this._saveWl()}>Apply scaling</button>
          ` : nothing}
        </div>
      </div>`;
  }

  // ── Optional services ────────────────────────────────────────────────────────
  _manageService(id, action) {
    // POST /admin/services/{id} is StepUpAdminSession → mutate prompts for TOTP.
    this._mutate(`/admin/services/${encodeURIComponent(id)}`, {
      method: 'POST', body: { action },
    }, 'Service request submitted (deploy-time managed).').then((r) => {
      if (r.ok && r.data && r.data.message) this._toast(r.data.message, 'info');
    });
  }

  _renderServices() {
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">Optional services</div>
        <div class="ys-panel-body">
          ${this._services.length === 0
            ? html`<div class="ys-txt-note">No optional services reported.</div>`
            : html`<div class="ys-svc-grid">
                ${this._services.map((s) => html`
                  <div class="ys-svc-card">
                    <span class="ys-semaphore ${s.status === 'running' ? 'ys-semaphore--ok' : 'ys-semaphore--degraded'}"
                          title=${s.status}></span>
                    <div class="ys-svc-meta">
                      <div class="ys-svc-name">${s.name}</div>
                      <div class="ys-txt-note">${s.description || s.profile}</div>
                    </div>
                    ${s.status === 'running'
                      ? html`<button class="ys-btn ys-btn-secondary"
                               @click=${() => this._manageService(s.id, 'disable')}>Manage…</button>`
                      : html`<button class="ys-btn ys-btn-secondary"
                               @click=${() => this._manageService(s.id, 'enable')}>Manage…</button>`}
                  </div>`)}
              </div>`}
          <div class="ys-txt-note">Optional services are a deploy-time / IaC choice; "Manage" requires step-up and returns installer guidance (no runtime toggle).</div>
        </div>
      </div>`;
  }

  // ── Response cache ────────────────────────────────────────────────────────────
  _cacheRows() {
    return (this._cache && Array.isArray(this._cache.tenants)) ? this._cache.tenants : [];
  }

  _saveCache() {
    const t = this._cacheTenant.trim();
    if (!t) { this._toast('Enter a tenant id.', 'error'); return; }
    this._mutate(`/admin/cache/${encodeURIComponent(t)}`, {
      method: 'PUT',
      body: { enabled: !!this._cacheEnabled, ttl_seconds: Number(this._cacheTtl) || 300 },
    }, `Cache config saved for ${t}.`);
  }

  _flushCache(tenant) {
    // Operational flush — confirm before destructive cache invalidation.
    if (!window.confirm(`Flush all cached entries for tenant "${tenant}"?`)) return;
    this._mutate(`/admin/cache/${encodeURIComponent(tenant)}`, { method: 'DELETE' },
      `Cache flushed for ${tenant}.`);
  }

  _renderCache() {
    const available = !this._cache || this._cache.cache_available !== false;
    return html`
      <div class="ys-panel">
        <div class="ys-panel-header">
          Response cache
          ${available ? nothing : html`<span class="ys-badge ys-badge-amber">unavailable</span>`}
        </div>
        <div class="ys-panel-body">
          <ys-table
            .columns=${[
              { key: 'tenant_id', label: 'Tenant', sortable: true },
              { key: 'enabled', label: 'Enabled', render: (r) => (r.enabled ? 'yes' : 'no') },
              { key: 'ttl_seconds', label: 'TTL (s)' },
            ]}
            .rows=${this._cacheRows()}
            emptyText="No per-tenant cache configuration."></ys-table>
          <div class="ys-field"><label class="ys-label">Tenant id</label>
            <input class="ys-input" .value=${this._cacheTenant}
                   @input=${(e) => { this._cacheTenant = e.target.value; }}></div>
          <div class="ys-field"><label class="ys-label">Enabled</label>
            <select class="ys-select" .value=${this._cacheEnabled ? 'true' : 'false'}
                    @change=${(e) => { this._cacheEnabled = e.target.value === 'true'; }}>
              <option value="false">false</option>
              <option value="true">true</option>
            </select></div>
          <div class="ys-field"><label class="ys-label">TTL seconds (1–3600)</label>
            <input class="ys-input" type="number" min="1" max="3600" .value=${String(this._cacheTtl)}
                   @input=${(e) => { this._cacheTtl = e.target.value; }}></div>
          <button class="ys-btn" @click=${() => this._saveCache()}>Save cache config</button>
          ${this._cacheRows().length ? html`
            <div class="ys-field"><label class="ys-label">Flush tenant cache</label>
              <select class="ys-select" id="ys-cache-flush"
                      @change=${(e) => { if (e.target.value) { this._flushCache(e.target.value); e.target.value = ''; } }}>
                <option value="">— select tenant to flush —</option>
                ${this._cacheRows().map((r) => html`<option value=${r.tenant_id}>${r.tenant_id}</option>`)}
              </select></div>` : nothing}
        </div>
      </div>`;
  }

  render() {
    if (this._loading) {
      return html`<div class="ys-admin-content-pad"><div class="ys-txt-note">Loading infrastructure…</div></div>`;
    }
    return html`
      <div class="ys-admin-content-pad">
        <h2 class="ys-admin-section-title">Infrastructure</h2>
        ${this._renderTopology()}
        ${this._renderAutoscaling()}
        <div class="ys-admin-2col">
          ${this._renderServices()}
          ${this._renderCache()}
        </div>
      </div>`;
  }
}

customElements.define('ys-admin-infrastructure', YsAdminInfrastructure);

registerAdminModule({
  id: 'infrastructure',
  label: 'Infrastructure',
  icon: '🏗',
  order: 60,
  render: (ctx) => html`
    <ys-admin-infrastructure .api=${ctx.api} .app=${ctx.app}></ys-admin-infrastructure>`,
});
